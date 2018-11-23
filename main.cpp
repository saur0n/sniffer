#include <arpa/inet.h>
#include <clocale>
#include <csignal>
#include <cstring>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <streambuf>
#include <unistd.h>
#include "core/Sniffer.hpp"

using std::cerr;
using std::cout;
using std::endl;
using std::ostream;
using std::string;

#define SETMODE(s) \
    if (options.type!=Options::UNSPECIFIED) \
        throw "invalid combination of options"; \
    options.type=s;

void sighandler(int sigNo);

/** Show help and supported protocols (always returns 0) **/
static int help(const char * program) {
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
    cout << endl;
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

int listenAt(uint16_t port, int family, bool reuseAddress);
int mainLoopTcp(const char * program, SnifferController &controller, int listener, HostAddress remote);
int mainLoopSocks(const char * program, SnifferController &controller, int listener);
ostream &operator <<(ostream &stream, const Error &error);

int main(int argc, char ** argv) {
    try {
        // Set default locale
        setlocale(LC_ALL, "");
        
        // Set signal behaviour
        signal(SIGPIPE, SIG_IGN);
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler=sighandler;
        sigaction(SIGHUP, &sa, nullptr);
        sigaction(SIGINT, &sa, nullptr);
        sigaction(SIGTERM, &sa, nullptr);
        
        // Parse command line arguments
        int help=0, append=0, daemonize=0, c;
        const char * protocol="raw", * output=nullptr;
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
        
        struct Options {
            Options() : type(UNSPECIFIED), reuseAddress(false) {}
            enum Type { UNSPECIFIED, TCP, UDP, SOCKS, UDPLITE } type;
            HostAddress remote;
            uint16_t localPort;
            bool reuseAddress;
            OptionsImpl aux;
        } options;
        
        do {
            c=getopt_long(argc, argv, "", OPTIONS, 0);
            if (c=='*') {
                options.aux=OptionsImpl(optarg);
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
                SETMODE(Options::SOCKS);
            }
            else if (c=='t') {
                SETMODE(Options::TCP);
                options.remote=parseHostAddress(optarg);
            }
            else if (c=='u') {
                SETMODE(Options::UDP);
                options.remote=parseHostAddress(optarg);
            }
            else if (c=='_')
                protocol=optarg;
            else if (c=='?')
                return 2;
        } while (c!=-1);
        
        if (help)
            return ::help(argv[0]);
        else if (options.type==Options::UNSPECIFIED)
            throw "mandatory option is missing, see --help";
        else {
            // Find protocol by name
            const Plugin &plugin=Registry::instance()[protocol];
            
            // Open log
            std::filebuf buf;
            if (output) {
                using namespace std;
                buf.open(output, ios::out|(append?ios::app:ios::trunc));
                cout.rdbuf(&buf);
            }
            
            SnifferController controller(plugin, options.aux, cout);
            
            // Daemonize sniffer
            if (daemonize) {
                cerr << "Daemonizing sniffer" << endl;
                daemon(1, 1);
            }
            
            if (options.type==Options::TCP) {
                if (!(plugin.flags&Protocol::STREAM))
                    throw "plugin does not support stream connections";
                if (options.localPort==0)
                    options.localPort=options.remote.second;
                int listener=listenAt(options.localPort, AF_INET, options.reuseAddress);
                return mainLoopTcp(argv[0], controller, listener, options.remote);
            }
            else if (options.type==Options::UDP) {
                if (!(plugin.flags&Protocol::DATAGRAM))
                    throw "plugin does not support datagram connections";
                if (options.localPort==0)
                    options.localPort=options.remote.second;
                throw "UDP is not implemented yet";
            }
            else if (options.type==Options::SOCKS) {
                if (!(plugin.flags&Protocol::STREAM))
                    throw "plugin does not support stream connections";
                if (options.localPort==0)
                    throw "--port must be specified";
                int listener=listenAt(options.localPort, AF_INET, options.reuseAddress);
                return mainLoopSocks(argv[0], controller, listener);
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
