/*******************************************************************************
 *  Advanced protocol sniffer
 *  Main module
 *  
 *  © 2013—2015, Sauron
 ******************************************************************************/

#include <arpa/inet.h>
#include <csignal>
#include <cstdint>
#include <getopt.h>
#include <map>
#include <netdb.h>
#include <sys/types.h>
#include <unistd.h>
#include "sniffer.hpp"

using std::cerr;
using std::cout;
using std::endl;
using std::map;
using std::ostream;
using std::string;
using std::vector;

/** Global plugin list **/
vector<Plugin *> Plugin::plugins;

/** Dump byte array to text stream **/
ostream &operator <<(ostream &stream, const vector<uint8_t> &data) {
    //stream << "DUMP (len=" << data.size() << ")\n";
    char buffer[4];
    size_t length=data.size();
    string hex,ascii;
    for (size_t i=0; i<=length; i++) {
        if (i<length) {
            uint8_t b=data[i];
            sprintf(buffer,"%02x ",b);
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

/** Listen at specified port at all local interfaces **/
int listenAt(uint16_t port, int family=AF_INET, bool reuseAddress=true) {
    int listener=socket(family,SOCK_STREAM,0);
    if (listener<0)
        Error::raise("creating socket");
    struct sockaddr_in endpoint;
    bzero(&endpoint,sizeof(endpoint));
    endpoint.sin_family=family;
    endpoint.sin_port=htons(port);
    endpoint.sin_addr.s_addr=htonl(INADDR_ANY);
    if (reuseAddress) {
        int n=1;
        setsockopt(listener,SOL_SOCKET,SO_REUSEADDR,&n,sizeof(int));
    }
    if (bind(listener,(struct sockaddr *)&endpoint,sizeof(endpoint))<0)
        Error::raise("binding to port");
    if (listen(listener,50)<0)
        Error::raise("starting listener");
    return listener;
}

/**/
void readFully(int stream, void * _buffer, size_t length) {
    uint8_t * buffer=reinterpret_cast<uint8_t *>(_buffer);
    while (length>0) {
        ssize_t retval=::read(stream,buffer,length);
        if (retval<0)
            Error::raise("reading from net");
        else if (retval==0)
            throw true;
        length-=retval;
        buffer+=retval;
    }
}

/**/
void writeFully(int stream, void * _buffer, size_t length) {
    ssize_t retval=::write(stream,_buffer,length);
    if (retval<0)
        Error::raise("writing to net");
}

/******************************************************************************/

Sniffer::~Sniffer() {
    close(client);
    close(server);
}

void Sniffer::start(unsigned id, ostream &log) {
    connectionId=id;
    
    // Client-to-server thread
    std::thread c2s(threadFunc,std::ref(*this),std::ref(log),OUTGOING);
    c2s.detach();
    
    // Server-to-client thread
    std::thread s2c(threadFunc,std::ref(*this),std::ref(log),INCOMING);
    s2c.detach();
}

Sniffer::Direction Sniffer::getDirection() const {
    return std::this_thread::get_id()==c2s?OUTGOING:INCOMING;
}

void Sniffer::read(void * buffer, size_t length) {
    bool outgoing=getDirection()==OUTGOING;
    readFully(outgoing?client:server,buffer,length);
    writeFully(outgoing?server:client,buffer,length);
}

vector<uint8_t> Sniffer::read(size_t length) {
    vector<uint8_t> result(length,0);
    read(&result[0],length);
    return result;
}

void Sniffer::threadFunc(Sniffer &sniffer, ostream &log, Direction direction) {
    try {
        if (direction==OUTGOING)
            sniffer.c2s=std::this_thread::get_id();
        while (true) {
            string dump=sniffer.dumpPacket();
            log << makeHeader(sniffer.connectionId,direction) << endl << dump << endl;
        }
    }
    catch (bool) {
        cerr << "Connection #" << sniffer.connectionId << ": disconnected from "
            << (direction==OUTGOING?"client":"server") << endl;
    }
    catch (Error e) {
        cerr << "Connection #" << sniffer.connectionId << ": " << e << endl;
    }
}

string Sniffer::makeHeader(unsigned connectionId, Direction direction) {
    char connectionIdStr[16];
    sprintf(connectionIdStr,"%d",connectionId);
    time_t now=time(0);
    const char * timestamp=ctime(&now);
    string result=string("==[")+connectionIdStr+' '+
        (direction==INCOMING?"▼":"▲")+"]====["+
        string(timestamp,strchrnul(timestamp,'\n')-timestamp)+"]";
    while (result.length()<82)
        result.push_back('=');
    return result;
}

/** Read one byte from stream **/
uint8_t readByte(int stream) {
    uint8_t result;
    if (read(stream,&result,sizeof(result))!=sizeof(result))
        Error::raise("reading byte");
    return result;
}

/** Start sniffer instance **/
Sniffer * startSniffer(const Plugin * plugin, int client,
        const char * remoteHost, uint16_t remotePort) {
    char addressBuf[32];
    
    // Socks
    if (remoteHost==0) {
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
        memset(&rs,0,sizeof(rs));
        rs.status=0x5a;
        
        // Process SOCKS request
        uint8_t version=0;
        readFully(client,&version,1);
        if (version!=4) {
            cerr << "SOCKSv" << (int)version << " is not supported" << endl;
            throw Error("SOCKS version mismatch",EPROTO);
        }
        
        readFully(client,&rq,sizeof(rq));
        string username;
        char ch=0;
        do {
            readFully(client,&ch,1);
            if (ch)
                username.push_back(ch);
        } while (ch);
        
        if (rq.command!=1) {
            cerr << "Command " << rq.command << " is not implemented" << endl;
            rs.status=0x5b;
        }
        if (!inet_ntop(AF_INET,&(rq.address),addressBuf,32)) {
            cerr << "inet_pton() failed\n";
            rs.status=0x5b;
        }
        if (!username.empty())
            cerr << "SOCKS client sent username: " << username << endl;
        remoteHost=addressBuf;
        remotePort=ntohs(rq.port);
        
        // Send response
        writeFully(client,&rs,sizeof(rs));
        if (rs.status!=0x5a)
            throw Error("SOCKSv4 connection",EPROTO);
    }
    
    // Get server network address
    char service[16];
    sprintf(service,"%d",remotePort);
    struct addrinfo hints,* result;
    memset(&hints,0,sizeof(struct addrinfo));
    hints.ai_family=AF_INET; /* IPv4 only */
    hints.ai_socktype=SOCK_STREAM; /* TCP */
    int ret=getaddrinfo(remoteHost,service,&hints,&result);
    if (ret!=0)
        throw Error(remoteHost,EHOSTUNREACH);
    
    // Connect to server
    cerr << "Connecting to " << remoteHost << ':' << remotePort << "…" << endl;
    int server=socket(AF_INET,SOCK_STREAM,0);
    if (server<0)
        Error::raise("creating socket");
    if (connect(server,result->ai_addr,result->ai_addrlen)<0)
        Error::raise("connecting to host");
    freeaddrinfo(result);
    
    // Create sniffer instance
    static unsigned counter=1;
    Sniffer * sniffer=plugin->create(client,server);
    sniffer->start(counter++,cout);
    return sniffer;
}

/** Show help **/
void help(const char * appName) {
    cout << "Usage: " << appName << " [OPTIONS]" << endl;
    cout << "\t--help               Show this help" << endl;
    cout << "\t--host=HOST:PORT     Route connections to HOST" << endl;
    cout << "\t--list               Show list of protocol plugins" << endl;
    cout << "\t--options=OPTIONS    Pass OPTIONS to protocol plugin" << endl;
    cout << "\t--output=FILE        Output dump to FILE" << endl;
    cout << "\t--port=PORT          Listen at specified PORT" << endl;
    cout << "\t--protocol=PROTOCOL  Use specified PROTOCOL" << endl;
    cout << "\t--socks              Act as SOCKS5 proxy" << endl;
}

/** Show list of plugins **/
void listPlugins() {
    for (unsigned i=0; i<Plugin::plugins.size(); i++) {
        const Plugin * plugin=Plugin::plugins[i];
        cout << plugin->name << endl << "\t" << plugin->description << endl;
    }
}

int main(int argc, char ** argv) {
    try {
        // Set locale
        setlocale(LC_ALL,"");
        
        // Get rid of fucking SIGPIPE
        signal(SIGPIPE,SIG_IGN);
        
        // Parse command line arguments
        int mode=0, c;
        uint16_t localPort=0, remotePort=0;
        const char * protocol="raw", * remoteHost=0, * options=0; //217.69.141.242
        static const char * SOCKS="socks";
        //StringMap options;
        static struct option OPTIONS[]={
            {   "help",         no_argument,        &mode,  1   },
            {   "host",         required_argument,  0,      'h' },
            {   "list",         no_argument,        &mode,  2   },
            {   "options",      optional_argument,  0,      '*' },
            {   "output",       required_argument,  0,      'o' },
            {   "port",         required_argument,  0,      'p' },
            {   "protocol",     required_argument,  0,      '_' },
            {   "socks",        no_argument,        0,      's' },
            {   0                                               }
        };
        
        do {
            c=getopt_long(argc,argv,"",OPTIONS,0);
            if (c=='*')
                options=optarg;
            else if (c=='h') {
                if (remoteHost==SOCKS)
                    throw "cannot use both --host and --socks";
                char * colon=strchr(optarg,':');
                if (!colon)
                    throw "invalid --host argument format";
                remotePort=atoi(colon+1);
                if (remotePort==0)
                    throw "invalid remote port";
                *colon='\0';
                remoteHost=optarg;
            }
            else if (c=='o')
                throw "--output is not implemented yet";
            else if (c=='p') {
                localPort=atoi(optarg);
                if (localPort==0)
                    throw "invalid local --port";
            }
            else if (c=='s') {
                if (remoteHost&&(remoteHost!=SOCKS))
                    throw "cannot use both --socks and --host";
                remoteHost=SOCKS;
                remotePort=0;
            }
            else if (c=='_')
                protocol=optarg;
            else if (c=='?')
                return 2;
        } while (c!=-1);
        
        if (mode==0) {
            if (!remoteHost)
                throw "--host or --socks must be specified";
            
            if (localPort==0) {
                if (remoteHost==SOCKS)
                    throw "--port must be specified when --socks used";
                else
                    localPort=remotePort;
            }
            
            // Find protocol by name
            const Plugin * plugin=0;
            for (unsigned i=0; i<Plugin::plugins.size(); i++)
                if (!strcmp(Plugin::plugins[i]->name,protocol))
                    plugin=Plugin::plugins[i];
            if (!plugin) {
                cerr << "Protocol " << protocol << " not found.\n";
                cerr << "See " << argv[0] << " --list" << endl;
                return 2;
            }
            if (!plugin->create) {
                cerr << "Plugin " << protocol << " must declare its " <<
                    "create() function" << endl;
                return 2;
            }
            
            // Call `prepare()` function
            if (plugin->prepare)
                plugin->prepare(localPort,remoteHost,remotePort);
            
            // Start listening
            int listener=listenAt(localPort);
            while (true) {
                // Accept connection from client
                int client=accept(listener,0,0);
                cerr << "New connection from client" << endl; // TODO print ip:port
                try {
                    startSniffer(plugin,client,remoteHost==SOCKS?0:remoteHost,
                        remotePort);
                }
                catch (Error e) {
                    cerr << argv[0] << ": " << e << endl;
                    close(client);
                }
            }
            cerr << "Exited from infinite loop" << endl;
        }
        else if (mode==1)
            help(argv[0]);
        else if (mode==2)
            listPlugins();
        else
            cout << options << endl; //###
        /*int localPort=2042, remotePort=2042;
        const char * remoteHost="217.69.141.242";
        MMPSniffer::start(localPort,remoteHost,remotePort);*/
        
        return 0;
    }
    catch (Error e) {
        cerr << argv[0] << ": " << e << endl;
        return 1;
    }
    catch (const char * e) {
        cerr << argv[0] << ": " << e << endl;
        return 1;
    }
}