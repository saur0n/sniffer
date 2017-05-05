/*******************************************************************************
 *  Advanced network sniffer
 *  Main module
 *  
 *  © 2013—2016, Sauron
 ******************************************************************************/

#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <map>
#include <mutex>
#include <netdb.h>
#include <sstream>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>
#include "sniffer.hpp"

using std::cerr;
using std::cout;
using std::endl;
using std::map;
using std::ostream;
using std::ostringstream;
using std::pair;
using std::string;
using std::vector;

namespace posix {
    int socket(int family, int type, int protocol) {
        int result=::socket(family, type, protocol);
        if (result<0)
            Error::raise("creating socket");
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
    
    ssize_t write(int fd, void * buffer, size_t length) {
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

/** Parse HOST:PORT string **/
HostAddress parseHostAddress(char * address) {
    char * colon=strchr(address, ':');
    if (!colon)
        throw "invalid argument format";
    uint16_t remotePort=atoi(colon+1); // TODO: C++11
    if (remotePort==0)
        throw "invalid remote port number";
    *colon='\0';
    return HostAddress(address, remotePort);
}

/** Read one byte from stream **/
uint8_t readByte(int stream) {
    uint8_t result;
    if (read(stream, &result, sizeof(result))!=sizeof(result))
        Error::raise("reading byte");
    return result;
}

/******************************************************************************/

/**/
struct Plugin {
    const char * name;
    const char * description;
    int version;
    Protocol::Factory factory;
    Protocol::Initializer initializer;
};

/** Plugin registry **/
class Registry : public vector<Plugin> {
public:
    /** Thrown on attempt to access non-existent plugin **/
    class PluginNotFoundException {};
    /** Find plugin by name **/
    const Plugin &operator [](const char * name) {
        for (auto i=begin(); i!=end(); i++)
            if (!strcasecmp(name, i->name))
                return *i;
        throw PluginNotFoundException();
    }
    /** Global plugin registry **/
    static Registry &instance() {
        static Registry * localInstance=0;
        if (localInstance==0)
            localInstance=new Registry();
        return *localInstance;
    }
};

/** Add protocol to the protocol registry **/
void Protocol::add(const char * name, const char * description, int version,
        Protocol::Factory factory, Protocol::Initializer initializer) {
    ///fprintf(stderr, "Adding protocol %s...\n", name);
    const Plugin plugin={name, description, version, factory, initializer};
    Registry::instance().push_back(plugin);
}

/******************************************************************************/

Error::Error(const char * stage) : stage(stage), error(errno) {}

const char * Error::getError() const { return strerror(error); }

/******************************************************************************/

/** Abstract protocol sniffer **/
class Sniffer {
public:
    /**/
    explicit Sniffer(const Plugin &plugin);
    /** Close connection and destroy plugin **/
    virtual ~Sniffer();
    /** Returns unique instance identifier **/
    unsigned getInstanceId() const { return instanceId; }
    
protected:
    /** Dump next packet **/
    void dump(ostream &log, bool incoming, Reader &reader);
    
private:
    int client;
    /** Unique instance ID **/
    unsigned instanceId;
    /** Protocol plugin instance **/
    Protocol * protocol;
    /**/
    std::mutex logMutex;
};

Sniffer::Sniffer(const Plugin &plugin) {
    static unsigned maxInstanceId=1;
    instanceId=maxInstanceId++;
    protocol=plugin.factory();
    if (!protocol)
        throw "failed to instantiate protocol plugin";
}

Sniffer::~Sniffer() {
    delete protocol;
}

void Sniffer::dump(ostream &log, bool incoming, Reader &reader) {
    string dumpText=protocol->dump(incoming, reader);
    std::unique_lock<std::mutex> logLock(logMutex);
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

/******************************************************************************/

/** Stream protocol sniffer **/
class StreamSniffer : public Sniffer, private Reader {
public:
    /** Create TCP sniffer **/
    StreamSniffer(const Plugin &plugin, ostream &log, int client,
        HostAddress remote);
    /** Create TCP sniffer working as SOCKS proxy **/
    StreamSniffer(const Plugin &plugin, ostream &log, int client);
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
    void initialize(ostream &log, HostAddress remote);
    /** Thread function **/
    void threadFunc(ostream &log, bool incoming);
};

StreamSniffer::StreamSniffer(const Plugin &plugin, ostream &log, int client,
        HostAddress remote) : Sniffer(plugin), client(client), c2s(0) {
    initialize(log, remote);
}

StreamSniffer::StreamSniffer(const Plugin &plugin, ostream &log, int client) :
        Sniffer(plugin), client(client), c2s(0) {
    char addressBuf[32];
    
    struct SocksRequest {
        uint8_t command;
        uint16_t port;
        uint32_t address;
    } __attribute__((packed)) rq;
    struct SocksResponse {
        uint8_t null;
        uint8_t status;
        uint8_t reserved[6];
    } __attribute__((packed)) rs;
    memset(&rs, 0, sizeof(rs));
    rs.status=0x5a;
    
    // Process SOCKS request
    uint8_t version=0;
    readFully(client, &version, 1);
    if (version!=4) {
        cerr << "SOCKSv" << (int)version << " is not supported" << endl;
        throw Error("SOCKS version mismatch", EPROTO);
    }
    
    readFully(client, &rq, sizeof(rq));
    string username;
    char ch=0;
    do {
        readFully(client, &ch, 1);
        if (ch)
            username.push_back(ch);
    } while (ch);
    
    if (rq.command!=1) {
        cerr << "Command " << rq.command << " is not implemented" << endl;
        rs.status=0x5b;
    }
    if (!inet_ntop(AF_INET, &(rq.address), addressBuf, 32)) {
        cerr << "inet_pton() failed\n";
        rs.status=0x5b;
    }
    if (!username.empty())
        cerr << "SOCKS client sent username: " << username << endl;
    
    // Send response
    posix::write(client, &rs, sizeof(rs));
    if (rs.status!=0x5a)
        throw Error("SOCKSv4 connection", EPROTO);
    
    initialize(log, HostAddress(addressBuf, ntohs(rq.port)));
}

StreamSniffer::~StreamSniffer() {
    close(client);
    close(server);
}

void StreamSniffer::read(void * buffer, size_t length) {
    bool incoming=c2s!=std::this_thread::get_id();
    readFully(incoming?server:client, buffer, length);
    posix::write(incoming?client:server, buffer, length);
}

void StreamSniffer::initialize(ostream &log, HostAddress remote) {
    // Get server network address
    char service[16];
    sprintf(service, "%d", remote.second);
    struct addrinfo hints, * result;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family=AF_INET; /* IPv4 only */
    hints.ai_socktype=SOCK_STREAM; /* TCP */
    int ret=getaddrinfo(remote.first, service, &hints, &result);
    if (ret!=0)
        throw Error(remote.first, EHOSTUNREACH);
    
    // Connect to server
    cerr << "Connecting to " << remote.first << ':' << remote.second << "…" << endl;
    server=socket(AF_INET, SOCK_STREAM, 0);
    if (server<0)
        Error::raise("creating socket");
    if (connect(server, result->ai_addr, result->ai_addrlen)<0)
        Error::raise("connecting to host");
    freeaddrinfo(result);
    
    // Statr client-to-server thread
    std::thread c2sThread(&StreamSniffer::threadFunc, this, std::ref(log), false);
    c2sThread.detach();
    
    // Start server-to-client thread
    std::thread s2cThread(&StreamSniffer::threadFunc, this, std::ref(log), true);
    s2cThread.detach();
}

void StreamSniffer::threadFunc(ostream &log, bool incoming) {
    try {
        if (!incoming)
            c2s=std::this_thread::get_id();
        
        while (true)
            dump(log, incoming, *this);
    }
    catch (bool) {
        cerr << "Connection #" << getInstanceId() << ": disconnected from "
            << (incoming?"server":"client") << endl;
    }
    catch (const Error &e) {
        cerr << "Connection #" << getInstanceId() << ": " << e << endl;
    }
}

/******************************************************************************/

/** Datagram-based protocol (UDP, UDPLITE, DCCP) sniffer **/
class DatagramSniffer : public Sniffer {
public:
    /** Initialize UDP sniffer **/
    DatagramSniffer(const Plugin &plugin, ostream &log, uint16_t localPort,
        HostAddress remote);
    
private:
    /** Client socket **/
    
    /****/
    
};

DatagramSniffer::DatagramSniffer(const Plugin &plugin, ostream &log,
        uint16_t localPort, HostAddress remote) : Sniffer(plugin) {
    log << "Datagram sniffer log" << endl;
    log << "Date: <DATE HERE>" << endl;
    log << "Port: <PORT>" << endl;
    throw "NOT IMPLEMENTED YET";
}

/******************************************************************************/

/** Sequential packet sniffer (not supported) **/
class SeqpacketSniffer : public Sniffer {};

/** Reliable datagram sniffer (not supported) **/
class ReliableDatagramSniffer : public Sniffer {};

/******************************************************************************/

/** Show help and supported protocols (always returns 0) **/
int help(const char * program) {
    cout << "Usage: " << program << " [OPTIONS]" << endl;
    cout << "\t--append                 Append to FILE" << endl;
    cout << "\t--daemon                 Daemonize process" << endl;
    cout << "\t--help                   *Show this help" << endl;
    cout << "\t--options=OPTIONS        Pass OPTIONS to protocol plugin" << endl;
    cout << "\t--output=FILE            Output dump to FILE" << endl;
    cout << "\t--port=PORT              Listen at specified PORT" << endl;
    cout << "\t--protocol=PROTOCOL      Use specified PROTOCOL" << endl;
    cout << "\t--socks-server           *Act as a SOCKS5 proxy" << endl;
    cout << "\t--tcp-server=HOST:PORT   *Route connections to HOST" << endl;
    cout << "\t--udp-server=HOST:PORT   *Route datagrams to HOST" << endl;
    cout << "One and only one option marked with * SHOULD be used." << endl;
    cout << endl;
    cout << "Supported PROTOCOLs:" << endl;
    Registry &registry=Registry::instance();
    ///cout << "Total " << registry.size() << endl;
    for (auto i=registry.begin(); i!=registry.end(); ++i) {
        cout << "\e[0;34m" << i->name << "\e[0m (v. " << i->version << ")" << endl;
        cout << "\t" << i->description << endl;
    }
    return 0;
}

template <typename ... T>
int mainLoop(const char * program, const Plugin &plugin, int listener, T ... args) {
    while (true) {
        // Accept connection from client
        int client=accept(listener, 0, 0);
        cerr << "New connection from client" << endl; // TODO print ip:port
        try {
            new StreamSniffer(plugin, cout, client, args...);
        }
        catch (const Error &e) {
            cerr << program << ": " << e << endl;
            close(client);
        }
    }
    cerr << "Exited from infinite loop." << endl;
    return 0;
}

#define SETTYPE(s) \
    if (options.type!=UNSPECIFIED) \
        throw "invalid combination of options"; \
    options.type=s;

int main(int argc, char ** argv) {
    try {
        // Set default locale
        setlocale(LC_ALL, "");
        
        // Get rid of fucking SIGPIPE
        signal(SIGPIPE, SIG_IGN);
        
        // Parse command line arguments
        int help=0, append=0, daemonize=0, c;
        const char * protocol="raw", * output=0;
        //StringMap options;//TODO
        static struct option OPTIONS[]={
            {   "append",       no_argument,        &append,    1   },
            {   "daemon",       no_argument,        &daemonize, 1   },
            {   "help",         no_argument,        &help,      1   },
            {   "options",      optional_argument,  0,          '*' },
            {   "output",       required_argument,  0,          'o' },
            {   "port",         required_argument,  0,          'p' },
            {   "protocol",     required_argument,  0,          '_' },
            {   "socks-server", no_argument,        0,          's' },
            {   "tcp-server",   required_argument,  0,          't' },
            {   "udp-server",   required_argument,  0,          'u' },
            {   0                                                   }
        };
        
        const Protocol::Options::Type UNSPECIFIED=Protocol::Options::Type(-1);
        Protocol::Options options={UNSPECIFIED, 0, HostAddress(0, 0), 0};
        
        do {
            c=getopt_long(argc, argv, "", OPTIONS, 0);
            if (c=='*') {
                // TODO: parse optarg
                options.aux=optarg;
            }
            else if (c=='o') {
                if (output)
                    throw "--output is already set";
                output=optarg;
            }
            else if (c=='p') {
                options.localPort=atoi(optarg);
                if (options.localPort==0)
                    throw "invalid local --port";
            }
            else if (c=='s') {
                SETTYPE(Protocol::Options::SOCKS);
            }
            else if (c=='t') {
                SETTYPE(Protocol::Options::TCP);
                options.remote=parseHostAddress(optarg);
            }
            else if (c=='u') {
                SETTYPE(Protocol::Options::UDP);
                options.remote=parseHostAddress(optarg);
            }
            else if (c=='_')
                protocol=optarg;
            else if (c=='?')
                return 2;
        } while (c!=-1);
        
        if (help)
            return ::help(argv[0]);
        else if (options.type==UNSPECIFIED)
            throw "missing --tcp-server, --udp-server, --socks-server or --help option";
        else {
            // Find protocol by name
            const Plugin &plugin=Registry::instance()[protocol];
            
            // Call plugin initialization routine
            if (!plugin.initializer(options))
                throw "transport protocol is not supported by plugin";
            
            // Open log
            std::filebuf buf;
            if (output) {
                using namespace std;
                buf.open(output, ios::out|(append?ios::app:ios::trunc));
                cout.rdbuf(&buf);
            }
            
            // Daemonize sniffer
            if (daemonize) {
                cerr << "Daemonizing sniffer" << endl;
                daemon(1, 1);
            }
            
            if (options.type==Protocol::Options::TCP) {
                if (options.localPort==0)
                    options.localPort=options.remote.second;
                int listener=listenAt(options.localPort);
                return mainLoop(argv[0], plugin, listener, options.remote);
            }
            else if (options.type==Protocol::Options::UDP) {
                if (options.localPort==0)
                    options.localPort=options.remote.second;
                throw "UDP is not implemented yet";
            }
            else if (options.type==Protocol::Options::SOCKS) {
                if (options.localPort==0)
                    throw "--port must be specified";
                int listener=listenAt(options.localPort);
                return mainLoop(argv[0], plugin, listener);
            }
            else
                throw "this cannot happens";
        }
    }
    catch (const Registry::PluginNotFoundException &e) {
        cerr << "Protocol with specified name was not found.\n";
        cerr << "See " << argv[0] << " --help" << endl;
        return 2;
    }
    catch (const Error &e) {
        cerr << argv[0] << ": " << e << endl;
        return 1;
    }
    catch (const char * e) {
        cerr << argv[0] << ": " << e << endl;
        return 1;
    }
}
