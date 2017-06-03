/*******************************************************************************
 *  Advanced network sniffer
 *  Main module
 *  
 *  © 2013—2017, Sauron
 ******************************************************************************/

#include <arpa/inet.h>
#include <cerrno>
#include <condition_variable>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <map>
#include <mutex>
#include <netdb.h>
#include <set>
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

/** Parse HOST:PORT string **/
static HostAddress parseHostAddress(const char * address) {
    const char * colon=strchr(address, ':');
    if (!colon)
        throw "invalid argument format";
    uint16_t remotePort=atoi(colon+1); // TODO: C++11
    if (remotePort==0)
        throw "invalid remote port number";
    return HostAddress(string(address, colon-address), remotePort);
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
    class PluginNotFoundException {
    public:
        PluginNotFoundException(const char * name) : name(name) {}
        const char * getName() const { return name; }
        
    private:
        const char * name;
    };
    /** Find plugin by name **/
    const Plugin &operator [](const char * name) {
        for (auto i=begin(); i!=end(); i++)
            if (!strcasecmp(name, i->name))
                return *i;
        throw PluginNotFoundException(name);
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
    const Plugin plugin={name, description, version, factory, initializer};
    Registry::instance().push_back(plugin);
}

/******************************************************************************/

Error::Error(const char * stage) : stage(stage), error(errno) {}

const char * Error::getError() const { return strerror(error); }

/******************************************************************************/

class SnifferBase {
public:
    SnifferBase(class SnifferController &controller);
    virtual ~SnifferBase();
    /** Returns unique instance identifier **/
    unsigned getInstanceId() const { return instanceId; }
    
protected:
    SnifferController &controller;
    unsigned instanceId;
};

/** Object for controlling life cycle of sniffers **/
class SnifferController {
    friend class SnifferBase;
public:
    /**/
    SnifferController(const Plugin &plugin, ostream &output) : 
        maxInstanceId(0), plugin(plugin), output(output), alive(true),
        gcThread(&SnifferController::gcThreadFunc, this) {}
    /**/
    ~SnifferController();
    /** Returns stream where sniffers should write to **/
    ostream &getStream() const { return output; }
    /** Create protocol plugin instance **/
    Protocol * newProtocol() const { return plugin.factory(); }
    /** Called by sniffer to inform that it should be destroyed **/
    void mark(SnifferBase * sniffer);
    
private:
    enum State { Alive, Marked, Deleted };
    
    SnifferController(const SnifferController &)=delete;
    SnifferController &operator =(const SnifferController &)=delete;
    unsigned maxInstanceId;
    const Plugin &plugin;
    ostream &output;
    bool alive;
    std::mutex gcMutex;
    std::thread gcThread;
    std::condition_variable gc;
    map<SnifferBase *, State> sniffers;
    void gcThreadFunc();
    
    /** Called by sniffer to inform that it was created **/
    void add(SnifferBase * sniffer);
    /** Called by sniffer to inform that it was deleted **/
    void remove(SnifferBase * sniffer);
};

SnifferBase::SnifferBase(class SnifferController &controller) :
        controller(controller), instanceId(++controller.maxInstanceId) {
    controller.add(this);
}

SnifferBase::~SnifferBase() {
    controller.remove(this);
}

void SnifferController::add(SnifferBase * sniffer) {
    std::unique_lock<std::mutex> lock(gcMutex);
    if (sniffer)
        sniffers.insert({sniffer, Alive});
}

void SnifferController::remove(SnifferBase * sniffer) {
    std::unique_lock<std::mutex> lock(gcMutex);
    if (sniffer)
        sniffers.erase(sniffer);
}

void SnifferController::mark(SnifferBase * sniffer) {
    std::unique_lock<std::mutex> lock(gcMutex);
    if (sniffer) {
        auto i=sniffers.find(sniffer);
        if (i!=sniffers.end())
            sniffers[sniffer]=Marked;
    }
    gc.notify_all();
}

void SnifferController::gcThreadFunc() {
    while (alive) {
        set<SnifferBase *> toBeDeleted;
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

SnifferController::~SnifferController() {
    alive=false;
    mark(nullptr);
    gcThread.join();
    for (auto i=sniffers.begin(); i!=sniffers.end(); i++)
        delete i->first;
}

/******************************************************************************/

/** Abstract protocol sniffer **/
class Sniffer : public SnifferBase {
public:
    /**/
    explicit Sniffer(SnifferController &controller);
    /** Close connection and destroy plugin **/
    virtual ~Sniffer();
    
protected:
    /** Dump next packet **/
    void dump(ostream &log, bool incoming, Reader &reader);
    /** Start incoming and outgoing threads **/
    void start(SnifferController &controller);
    /** Output beginning of message to cerr and return it **/
    ostream &error() const;
    /** This function should be overridden by subclasses **/
    virtual void threadFunc(ostream &log, bool incoming)=0;
    
private:
    /** Protocol plugin instance **/
    Protocol * protocol;
    /** Mutex for synchronization of access to output log **/
    static std::mutex logMutex;
    /** Thread for interception outgoing data **/
    std::thread c2sThread;
    /** Thread for interception incoming data **/
    std::thread s2cThread;
    /** Private thread function **/
    void _threadFunc(SnifferController &controller, bool incoming);
};

Sniffer::Sniffer(SnifferController &controller) : SnifferBase(controller), protocol(controller.newProtocol()) {
    if (!protocol)
        throw "failed to instantiate protocol plugin";
}

Sniffer::~Sniffer() {
    if (c2sThread.joinable())
        c2sThread.join();
    if (s2cThread.joinable())
        s2cThread.join();
    delete protocol;
}

void Sniffer::dump(ostream &log, bool incoming, Reader &reader) {
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

void Sniffer::start(SnifferController &controller) {
    c2sThread=std::thread(&Sniffer::_threadFunc, this, std::ref(controller), false);
    s2cThread=std::thread(&Sniffer::_threadFunc, this, std::ref(controller), true);
}

ostream &Sniffer::error() const {
    return cerr << "Connection #" << getInstanceId() << ": ";
}

void Sniffer::_threadFunc(SnifferController &controller, bool incoming) {
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

std::mutex Sniffer::logMutex;

/******************************************************************************/

/** Stream protocol sniffer **/
class StreamSniffer : public Sniffer, private Reader {
public:
    /** Create TCP sniffer **/
    StreamSniffer(SnifferController &controller, int client, HostAddress remote);
    /** Create TCP sniffer working as SOCKS proxy **/
    StreamSniffer(SnifferController &controller, int client);
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

StreamSniffer::StreamSniffer(SnifferController &controller, int client,
        HostAddress remote) : Sniffer(controller), client(client), c2s(0) {
    initialize(remote);
    start(controller);
}

StreamSniffer::StreamSniffer(SnifferController &controller, int client) :
        Sniffer(controller), client(client), c2s(0) {
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
class DatagramSniffer : public Sniffer {
public:
    /** Initialize UDP sniffer **/
    DatagramSniffer(SnifferController &controller, ostream &log, uint16_t localPort,
        HostAddress remote);
    
private:
    /** Client socket **/
    
    /****/
    
};

DatagramSniffer::DatagramSniffer(SnifferController &controller, ostream &log,
        uint16_t localPort, HostAddress remote) : Sniffer(controller) {
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
    for (auto i=registry.begin(); i!=registry.end(); ++i) {
        cout << "\e[0;34m" << i->name << "\e[0m (v. " << i->version << ")" << endl;
        cout << "\t" << i->description << endl;
    }
    return 0;
}

template <typename ... T>
int mainLoop(const char * program, SnifferController &controller, int listener, T ... args) {
    while (true) {
        // Accept connection from client
        int client=accept(listener, 0, 0);
        cerr << "New connection from client" << endl; // TODO print ip:port
        try {
            new StreamSniffer(controller, client, args...);
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
        const char * protocol="raw", * output=nullptr;
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
        Protocol::Options options={UNSPECIFIED, 0, HostAddress(string(), 0), 0};
        
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
            
            SnifferController controller(plugin, cout);
            
            // Daemonize sniffer
            if (daemonize) {
                cerr << "Daemonizing sniffer" << endl;
                daemon(1, 1);
            }
            
            if (options.type==Protocol::Options::TCP) {
                if (options.localPort==0)
                    options.localPort=options.remote.second;
                int listener=listenAt(options.localPort);
                return mainLoop(argv[0], controller, listener, options.remote);
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
                return mainLoop(argv[0], controller, listener);
            }
            else
                throw "this cannot happens";
        }
    }
    catch (const Registry::PluginNotFoundException &e) {
        cerr << "Protocol with name «" << e.getName() << "» was not found.\n";
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
    catch (...) {
        cerr << argv[0] << ": unknown exception caught" << endl;
        return 1;
    }
}
