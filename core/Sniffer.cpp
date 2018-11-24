/*******************************************************************************
 *  Advanced network sniffer
 *  Main module
 *  
 *  © 2013—2018, Sauron
 ******************************************************************************/

#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>
#include <netdb.h>
#include <set>
#include <sstream>
#include <sys/types.h>
#include <unistd.h>
#include <utility>
#include <vector>
#include "Sniffer.hpp"

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

/** Listen at specified port at all local interfaces **/
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

/** Bind to specified port **/
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
    return stream;
}

/** Print error message to stream **/
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
            throw true;
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

/******************************************************************************/

void Sniffer::add(Connection * sniffer) {
    std::unique_lock<std::mutex> lock(gcMutex);
    if (sniffer)
        sniffers.insert({sniffer, Alive});
}

void Sniffer::remove(Connection * sniffer) {
    std::unique_lock<std::mutex> lock(gcMutex);
    if (sniffer)
        sniffers.erase(sniffer);
}

void Sniffer::mark(Connection * sniffer) {
    std::unique_lock<std::mutex> lock(gcMutex);
    if (sniffer) {
        auto i=sniffers.find(sniffer);
        if (i!=sniffers.end())
            sniffers[sniffer]=Marked;
    }
    gc.notify_all();
}

void Sniffer::gcThreadFunc() {
    while (alive) {
        set<Connection *> toBeDeleted;
        {
            std::unique_lock<std::mutex> lock(gcMutex);
            gc.wait(lock);
            for (auto i=sniffers.begin(); i!=sniffers.end(); i++)
                if (i->second==Marked)
                    toBeDeleted.insert(i->first);
        }
        
        for (auto i=toBeDeleted.begin(); i!=toBeDeleted.end(); ++i)
            delete *i;
    }
}

Sniffer::~Sniffer() {
    alive=false;
    mark(nullptr);
    gcThread.join();
    for (auto i=sniffers.begin(); i!=sniffers.end(); i++)
        delete i->first;
}

/******************************************************************************/

Connection::Connection(Sniffer &controller) : controller(controller),
        instanceId(++controller.maxInstanceId),
        protocol(controller.newProtocol()) {
    controller.add(this);
    if (!protocol)
        throw "failed to instantiate protocol plugin";
}

Connection::~Connection() {
    controller.remove(this);
    if (c2sThread.joinable())
        c2sThread.join();
    if (s2cThread.joinable())
        s2cThread.join();
    delete protocol;
}

void Connection::dump(ostream &log, bool incoming, Reader &reader) {
    string dumpText=protocol->dump(incoming, reader);
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

void Connection::start(Sniffer &controller) {
    c2sThread=std::thread(&Connection::_threadFunc, this, std::ref(controller), false);
    s2cThread=std::thread(&Connection::_threadFunc, this, std::ref(controller), true);
}

ostream &Connection::error() const {
    return cerr << "Connection #" << getInstanceId() << ": ";
}

void Connection::_threadFunc(Sniffer &controller, bool incoming) {
    try {
        threadFunc(controller.getStream(), incoming);
    }
    catch (bool) {
        error() << "disconnected from " << (incoming?"server":"client") << endl;
    }
    catch (const Error &e) {
        error() << e << endl;
    }
    catch (...) {
        error() << "unknown exception caught" << endl;
    }
    
    controller.mark(this);
}

std::mutex Connection::logMutex;

/******************************************************************************/

/** Stream protocol sniffer **/
class StreamSniffer : public Connection, private Reader {
public:
    /** Create TCP sniffer working as a forwarder **/
    StreamSniffer(Sniffer &controller, int client, HostAddress remote);
    /** Create TCP sniffer working as SOCKS proxy **/
    StreamSniffer(Sniffer &controller, int client);
    /** Close connections **/
    ~StreamSniffer();
    
private:
    /** Read portion of raw data **/
    virtual void read(void * buffer, size_t length);
    
private:
    /** Client socket descriptor **/
    int client;
    /** Server socket descriptor **/
    int server;
    /** Outgoing thread ID **/
    std::thread::id c2s;
    /** Connect to server **/
    void initialize(HostAddress remote);
    /** Thread function **/
    void threadFunc(ostream &log, bool incoming);
};

StreamSniffer::StreamSniffer(Sniffer &controller, int client,
        HostAddress remote) : Connection(controller), client(client), c2s(0) {
    initialize(remote);
    start(controller);
}

StreamSniffer::StreamSniffer(Sniffer &controller, int client) :
        Connection(controller), client(client), c2s(0) {
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
        
        initialize({addressBuf, ntohs(rq.port)});
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
            initialize(remote);
            
            // Send SOCKS5 connection response
            writeByte(client, 5);
            writeByte(client, status);
            writeByte(client, 0);
            writeByte(client, 1);
            writeLong(client, 0x7f000001);
            writeWord(client, remote.second);
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
    
    start(controller);
}

StreamSniffer::~StreamSniffer() {
    if (client>=0)
        close(client);
    if (server>=0)
        close(server);
}

void StreamSniffer::read(void * buffer, size_t length) {
    bool incoming=c2s!=std::this_thread::get_id();
    readFully(incoming?server:client, buffer, length);
    posix::write(incoming?client:server, buffer, length);
}

void StreamSniffer::initialize(HostAddress remote) {
    // Get server network address
    char service[16];
    sprintf(service, "%d", remote.second);
    struct addrinfo hints, * result;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family=AF_INET; /* IPv4 only */
    hints.ai_socktype=SOCK_STREAM; /* TCP */
    int ret=getaddrinfo(remote.first.c_str(), service, &hints, &result);
    if (ret!=0)
        throw Error("connecting", EHOSTUNREACH);
    
    // Connect to server
    error() << "connecting to " << remote.first << ':' << remote.second << "…" << endl;
    server=socket(AF_INET, SOCK_STREAM, 0);
    if (server<0)
        Error::raise("creating socket");
    if (connect(server, result->ai_addr, result->ai_addrlen)<0)
        Error::raise("connecting to host");
    freeaddrinfo(result);
}

void StreamSniffer::threadFunc(ostream &log, bool incoming) {
    if (!incoming)
        c2s=std::this_thread::get_id();
    
    while (true)
        dump(log, incoming, *this);
}

/******************************************************************************/

/** Datagram-based protocol (UDP, UDPLITE, DCCP) sniffer **/
class DatagramConnection : public Connection {
public:
    /** Initialize UDP sniffer **/
    DatagramConnection(Sniffer &controller, ostream &log, uint16_t localPort,
        HostAddress remote);
    
private:
    /** Client socket **/
    
    /****/
    
};

DatagramConnection::DatagramConnection(Sniffer &sniffer, ostream &log,
        uint16_t localPort, HostAddress remote) : Connection(sniffer) {
    log << "Datagram sniffer log" << endl;
    log << "Date: <DATE HERE>" << endl;
    log << "Port: <PORT>" << endl;
    throw "NOT IMPLEMENTED YET";
}

/******************************************************************************/

/** Sequential packet sniffer (not supported) **/
class SeqpacketConnection : public Connection {};

/** Reliable datagram sniffer (not supported) **/
class ReliableDatagramConnection : public Connection {};

/******************************************************************************/

static sig_atomic_t working=1;

template <typename ... T>
int mainLoop(const char * program, Sniffer &controller, int listener, T ... args) {
    while (working) {
        // Accept connection from client
        int client=-1;
        try {
            client=posix::accept(listener, 0, 0);
            cerr << "New connection from client" << endl; // TODO print ip:port
            new StreamSniffer(controller, client, args...);
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
    cerr << "Exited from infinite loop." << endl;
    return 0;
}

int mainLoopTcp(const char * program, Sniffer &controller, int listener, HostAddress remote) {
    return mainLoop(program, controller, listener, remote);
}

int mainLoopSocks(const char * program, Sniffer &controller, int listener) {
    return mainLoop(program, controller, listener);
}

void sighandler(int sigNo) {
    working=0;
}
