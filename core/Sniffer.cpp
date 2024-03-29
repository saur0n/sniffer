/*******************************************************************************
 *  Advanced network sniffer
 *  Main module
 *  
 *  © 2013—2021, Sauron
 ******************************************************************************/

#include <arpa/inet.h>
#include <cassert>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <map>
#include <netdb.h>
#include <set>
#include <sstream>
#include <sys/poll.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>
#include <vector>
#include "Sniffer.hpp"
#include "StreamConnection.hpp"

using std::cerr;
using std::cout;
using std::endl;
using std::map;
using std::ostream;
using std::ostringstream;
using std::pair;
using std::set;
using std::string;
using std::vector;

namespace posix {
    int socket(int family, int type, int protocol) {
        int result=::socket(family, type, protocol);
        if (result<0)
            Error::raise("creating socket");
        return result;
    }
    
    int accept(int socket, struct sockaddr * addr, socklen_t * len) {
        int result=::accept(socket, addr, len);
        if (result<0)
            Error::raise("accepting a connection");
        return result;
    }
    
    void bind(int socket, const struct sockaddr * addr, socklen_t len) {
        if (::bind(socket, addr, len)<0)
            Error::raise("binding to port");
    }
    
    void listen(int socket, int backlog) {
        if (::listen(socket, backlog)<0)
            Error::raise("listening to port");
    }
    
    int poll(struct pollfd * fds, nfds_t nfds, int timeout) {
        int retval=::poll(fds, nfds, timeout);
        if (retval<0)
            Error::raise("poll()");
        return retval;
    }
    
    template <class T>
    void setsockopt(int socket, int level, int option, T value) {
        if (::setsockopt(socket, level, option, &value, sizeof(T))<0)
            Error::raise("setting socket option");
    }
    
    ssize_t read(int fd, void * buffer, size_t length) {
        ssize_t retval=::read(fd, buffer, length);
        if (retval<0)
            Error::raise("reading from network");
        return retval;
    }
    
    ssize_t write(int fd, const void * buffer, size_t length) {
        ssize_t retval=::write(fd, buffer, length);
        if (retval<0)
            Error::raise("writing to network");
        return retval;
    }
}

/** Listen at the specified port at all local interfaces **/
int listenAt(uint16_t port, int family=AF_INET, bool reuseAddress=true) {
    int listener=posix::socket(family, SOCK_STREAM, 0);
    struct sockaddr_in endpoint;
    memset(&endpoint, 0, sizeof(endpoint));
    endpoint.sin_family=family;
    endpoint.sin_port=htons(port);
    endpoint.sin_addr.s_addr=htonl(INADDR_ANY);
    posix::setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, int(reuseAddress));
    posix::bind(listener, (struct sockaddr *)&endpoint, sizeof(endpoint));
    posix::listen(listener, 50);
    return listener;
}

/** Bind to the specified port **/
int bindTo(uint16_t port, int family=AF_INET, bool reuseAddress=true) {
    int listener=posix::socket(family, SOCK_DGRAM, 0);
    struct sockaddr_in endpoint;
    memset(&endpoint, 0, sizeof(endpoint));
    endpoint.sin_family=family;
    endpoint.sin_port=htons(port);
    endpoint.sin_addr.s_addr=htonl(INADDR_ANY);
    posix::setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, int(reuseAddress));
    posix::bind(listener, (struct sockaddr *)&endpoint, sizeof(endpoint));
    return listener;
}

/** Dump byte array to text stream **/
ostream &operator <<(ostream &stream, const vector<uint8_t> &data) {
    //stream << "DUMP (len=" << data.size() << ")\n";
    if (data.empty())
        stream << "EMPTY\n";
    else {
        char buffer[4];
        size_t length=data.size();
        string hex, ascii;
        for (size_t i=0; i<=length; i++) {
            if (i<length) {
                uint8_t b=data[i];
                sprintf(buffer, "%02x ", b);
                hex+=buffer;
                if (i%8==7)
                    hex+=' ';
                ascii+=((b>=32&&b<127)?(char)b:'.');
            }
            if ((i%16==15)||(i==length)) {
                for (unsigned i=hex.length(); i<50; i++)
                    hex+=' ';
                stream << hex << ascii << endl;
                hex=string();
                ascii=string();
            }
        }
    }
    return stream;
}

ostream &operator <<(ostream &stream, const Error &error) {
    stream << error.getStage() << ": " << error.getError();
    return stream;
}

/**/
void readFully(int stream, void * _buffer, size_t length) {
    uint8_t * buffer=reinterpret_cast<uint8_t *>(_buffer);
    while (length>0) {
        ssize_t retval=posix::read(stream, buffer, length);
        if (retval==0)
            throw Reader::End();
        length-=retval;
        buffer+=retval;
    }
}

/** Read one byte from stream **/
static uint8_t readByte(int stream) {
    uint8_t result;
    if (read(stream, &result, sizeof(result))!=sizeof(result))
        Error::raise("reading byte");
    return result;
}

/** Write one byte to stream **/
static void writeByte(int stream, uint8_t value) {
    posix::write(stream, &value, sizeof(uint8_t));
}

/** Read a word from stream **/
static uint16_t readWord(int stream) {
    uint16_t result;
    readFully(stream, &result, sizeof(result));
    return ntohs(result);
}

/** Write a word to stream **/
static void writeWord(int stream, uint16_t value) {
    value=htons(value);
    posix::write(stream, &value, sizeof(value));
}

/** Read a long integer from stream **/
static uint32_t readLong(int stream) {
    uint32_t result;
    readFully(stream, &result, sizeof(result));
    return ntohl(result);
}

/** Write a long integer to stream **/
static void writeLong(int stream, uint32_t value) {
    value=htonl(value);
    posix::write(stream, &value, sizeof(value));
}

/** Read a zero-terminated string from stream **/
static string readStringZ(int stream) {
    string result;
    char ch=0;
    do {
        readFully(stream, &ch, 1);
        if (ch)
            result.push_back(ch);
    } while (ch);
    return result;
}

/** Read a string with prefixed length from stream **/
static string readString(int stream) {
    string result(readByte(stream), '\0');
    readFully(stream, &result[0], result.length());
    return result;
}

/******************************************************************************/

OptionsImpl::OptionsImpl(const char * optarg) {
    string key, value;
    enum { KEY, VALUE, DONE } state=KEY;
    for (const char * oc=optarg; *oc; oc++) {
        if (state==KEY) {
            if (*oc=='=')
                state=VALUE;
            else if (*oc==',')
                state=DONE;
            else
                key.push_back(*oc);
        }
        else if (state==VALUE) {
            if (*oc==',')
                state=DONE;
            else
                value.push_back(*oc);
        }
        if (state==DONE) {
            if (!key.empty())
                options[key]=value;
            key=value=string();
            state=KEY;
        }
    }
    if (!key.empty())
        options[key]=value;
}

const string &OptionsImpl::get(const char * option) const {
    static const string EMPTY;
    const auto &iter=options.find(option);
    return iter==options.end()?EMPTY:iter->second;
}

/******************************************************************************/

const Plugin &Registry::operator [](const char * name) {
    for (auto i=begin(); i!=end(); i++)
        if (!strcasecmp(name, i->name))
            return *i;
    throw PluginNotFoundException(name);
}

Registry &Registry::instance() {
    static Registry * localInstance=0;
    if (localInstance==0)
        localInstance=new Registry();
    return *localInstance;
}

void Protocol::add(const char * name, const char * description, int version,
        unsigned flags, Protocol::Factory factory) {
    const Plugin plugin={name, description, version, flags, factory};
    Registry::instance().push_back(plugin);
}

/******************************************************************************/

Error::Error(const char * stage) : stage(stage), error(errno) {}

const char * Error::getError() const { return strerror(error); }

void Error::raise(const char * stage) {
    if (errno==EINTR)
        throw Interrupt();
    else
        throw Error(stage);
}

/******************************************************************************/

Sniffer::Sniffer(const Plugin &plugin, const OptionsImpl &options,
    ostream &output) : plugin(plugin), options(options), output(output),
    alive(true), pollThread(&Sniffer::pollThreadFunc, this) {}

Sniffer::~Sniffer() {
    alive=false;
    if (pollThread.joinable()) {
        pthread_kill(pollThread.native_handle(), SIGTERM);
        pollThread.join();
    }
}

void Sniffer::add(Connection * connection) {
    std::unique_lock<std::mutex> lock(gcMutex);
    if (connection) {
        for (auto i=connections.begin(); i!=connections.end(); ++i) {
            if (!*i) {
                *i=connection;
                return;
            }
        }
        connections.push_back(connection);
    }
}

void Sniffer::pollThreadFunc() {
    try {
        while (alive) {
            vector<pollfd> pollfds;
            vector<std::reference_wrapper<Channel>> channels;
            {
                std::unique_lock<std::mutex> lock(gcMutex);
                for (size_t i=0; i<connections.size(); i++) {
                    ConnectionPtr connection=connections[i];
                    if (connection) {
                        for (unsigned j=0; j<2; j++) {
                            Channel &channel=connection->getChannel(bool(j));
                            if (channel.isAlive()) {
                                channels.emplace_back(channel);
                                pollfds.push_back(pollfd{channel.getDescriptor(), POLLIN, 0});
                            }
                        }
                    }
                }
                // TODO: do not rebuild database each time
            }
            
            int retval=posix::poll(pollfds.data(), pollfds.size(), 5000);
            if (retval)
                for (size_t i=0; i<pollfds.size(); i++)
                    if (pollfds[i].revents)
                        channels[i].get().notify();
            
            // Delete connections which are not alive
            std::unique_lock<std::mutex> lock(gcMutex);
            for (auto i=connections.begin(); i!=connections.end(); ++i) {
                ConnectionPtr connection=*i;
                if (connection&&!connection->isAlive()) {
                    delete connection;
                    *i=nullptr;
                }
            }
        }
    }
    catch (const Interrupt &e) {
        cerr << "pollThread: program was terminated" << endl;
    }
    catch (const Error &e) {
        cerr << "pollThread: " << e << endl;
    }
    catch (...) {
        cerr << "pollThread: unknown error" << endl;
    }
}

/******************************************************************************/

Connection::Connection(Sniffer &sniffer) : sniffer(sniffer),
        instanceId(++maxInstanceId),
        protocol(sniffer.newProtocol()) {
    if (!protocol)
        throw "failed to instantiate protocol plugin";
}

Connection::~Connection() {
    if (c2sThread.joinable())
        c2sThread.join();
    if (s2cThread.joinable())
        s2cThread.join();
    delete protocol;
}

bool Connection::isAlive() {
    Channel &incoming=getChannel(true), &outgoing=getChannel(false);
    bool incomingAlive=incoming.isAlive(), outgoingAlive=outgoing.isAlive();
    return incomingAlive&&outgoingAlive;
    //return getChannel(true).isAlive()&&getChannel(false).isAlive();
}

void Connection::dump(ostream &log, bool incoming, Reader &reader) {
    string dumpText;
    try {
        dumpText=protocol->dump(incoming, reader);
    }
    catch (Reader::End) {
        throw;
    }
    catch (...) {
        dumpText="UNHANDLED EXCEPTION";
    }
    
    std::lock_guard<std::mutex> logLock(logMutex);
    ostringstream header;
    time_t now=time(0);
    const char * timestamp=ctime(&now);
    header << "==[" << instanceId << " " << (incoming?"▼":"▲") << "]==[";
    header << string(timestamp, strchrnul(timestamp, '\n')-timestamp) << "]==";
    string headerStr=header.str();
    log << headerStr;
    for (unsigned i=headerStr.length(); i<80; i++)
        log << '=';
    log << endl << dumpText << endl;
}

void Connection::start(Sniffer &sniffer) {
    c2sThread=std::thread(&Connection::_threadFunc, this, std::ref(sniffer), false);
    s2cThread=std::thread(&Connection::_threadFunc, this, std::ref(sniffer), true);
}

ostream &Connection::error() const {
    return cerr << "Connection #" << getInstanceId() << ": ";
}

unsigned Connection::maxInstanceId=0;

void Connection::_threadFunc(Sniffer &sniffer, bool incoming) {
    try {
        threadFunc(sniffer.getStream(), incoming);
    }
    catch (Reader::End) {
        error() << "disconnected from " << (incoming?"server":"client") << endl;
    }
    catch (const Error &e) {
        error() << e << endl;
    }
    catch (...) {
        error() << "unknown exception was thrown by the plugin" << endl;
    }
}

std::mutex Connection::logMutex;

/******************************************************************************/

int StreamConnection::acceptSocksConnection(int client) {
    uint8_t version=readByte(client);
    if (version==4) {
        // Process SOCKS4 request
        struct Socks4Request {
            uint8_t command;
            uint16_t port;
            uint32_t address;
        } __attribute__((packed)) rq;
        readFully(client, &rq, sizeof(rq));
        string username=readStringZ(client);
        
        uint8_t status=0x5a;
        if (rq.command!=1) {
            error() << "SOCKSv4: unknown command " << int(rq.command) << endl;
            status=0x5b;
        }
        char addressBuf[32];
        if (!inet_ntop(AF_INET, &(rq.address), addressBuf, 32)) {
            error() << "SOCKSv4: inet_pton() failed" << endl;
            status=0x5b;
        }
        if (!username.empty())
            error() << "SOCKSv4: client sent username: " << username << endl;
        
        // Send SOCKS4 response
        struct Socks4Response {
            uint8_t null;
            uint8_t status;
            uint8_t reserved[6];
        } __attribute__((packed)) rs;
        memset(&rs, 0, sizeof(rs));
        rs.status=status;
        posix::write(client, &rs, sizeof(rs));
        if (rs.status!=0x5a)
            throw Error("SOCKSv4 connection", EPROTO);
        
        return initialize({addressBuf, ntohs(rq.port)});
    }
    else if (version==5) {
        // Process initial SOCKS5 request
        string authMethods=readString(client);
        uint8_t preferredMethod=authMethods.find('\0')==string::npos?0xff:0x00;
        error() << "SOCKSv5: authentication methods: ";
        for (size_t i=0; i<authMethods.size(); i++) {
            if (i>0)
                cerr << ", ";
            cerr << unsigned(authMethods[i]);
        }
        cerr << endl;
        
        // Send response about authentication method
        writeByte(client, 5);
        writeByte(client, preferredMethod);
        
        // Process SOCKS5 connection request
        readByte(client);
        uint8_t command=readByte(client), status=0x00;
        if (command!=1) {
            error() << "SOCKSv5: unknown command " << int(command) << endl;
            status=0x07;
        }
        readByte(client);
        uint8_t addressType=readByte(client);
        HostAddress remote;
        if (addressType==1) {
            char buffer[32];
            uint32_t address=htonl(readLong(client));
            if (!inet_ntop(AF_INET, &address, buffer, 32)) {
                error() << "SOCKSv5: inet_pton() failed" << endl;
                status=0x04;
            }
            remote.first=buffer;
        }
        else if (addressType==3) {
            remote.first=readString(client);
        }
        else {
            error() << "SOCKSv5: unknown address type " << int(addressType) << endl;
            status=0x08;
        }
        remote.second=readWord(client);
        
        if (status==0) {
            // Connect to the target server
            int result=initialize(remote);
            
            // Send SOCKS5 connection response
            writeByte(client, 5);
            writeByte(client, status);
            writeByte(client, 0);
            writeByte(client, 1);
            writeLong(client, 0x7f000001);
            writeWord(client, remote.second);
            // TODO: send NACK in case of bad connection
            return result;
        }
        else {
            writeByte(client, 5);
            writeByte(client, status);
            throw Error("SOCKSv5 connection", EPROTO);
        }
    }
    else {
        error() << "SOCKSv" << (int)version << " is not supported" << endl;
        throw Error("SOCKS version mismatch", EPROTO);
    }
}

/******************************************************************************/

static sig_atomic_t working=1;

template <typename ... T>
int mainLoop(const char * program, Sniffer &sniffer, int listener, T ... args) {
    while (working) {
        // Accept connection from client
        int client=-1;
        try {
            client=posix::accept(listener, 0, 0);
            cerr << "New connection from client" << endl; // TODO print ip:port
            sniffer.add<StreamConnection>(client, args...);
        }
        catch (const Interrupt &e) {
            cerr << endl << program << ": shutting down..." << endl;
        }
        catch (const Error &e) {
            if (e.getErrno()!=EINTR) {
                cerr << program << ": " << e << endl;
                if (client>=0)
                    close(client);
            }
        }
    }
    close(listener);
    return 0;
}

int mainLoopTcp(const char * program, Sniffer &sniffer, int listener, HostAddress remote) {
    return mainLoop(program, sniffer, listener, remote);
}

int mainLoopSocks(const char * program, Sniffer &sniffer, int listener) {
    return mainLoop(program, sniffer, listener);
}

void sighandler(int sigNo) {
    working=0;
}
