/*******************************************************************************
 *  Advanced protocol sniffer
 *  Mail.Ru Agent protocol plugin
 *  
 *  © 2013—2015, Sauron
 ******************************************************************************/

#include <arpa/inet.h>
#include <sstream>
#include <unistd.h>
#include "sniffer.hpp"

using std::cerr;
using std::cout;
using std::endl;
using std::ostream;
using std::ostringstream;
using std::string;
using std::thread;
using std::vector;

extern int listenAt(uint16_t port, int family=AF_INET, bool reuseAddress=true);
extern ostream &operator <<(ostream &stream, const vector<uint8_t> &data);

/** Mail.Ru Agent protocol sniffer **/
class MMPSniffer : public Sniffer {
public:
    /** Start fake load balancer **/
    static void prepare(uint16_t &localPort, const char * &host, uint16_t &port) {
        uint16_t mmpPort=localPort^1;
        thread fakeBalancer(MMPSniffer::startFakeBalancer,localPort,mmpPort);
        fakeBalancer.detach();
        localPort=mmpPort;
    }
    /** Returns new sniffer instance **/
    static Sniffer * create(int client, int server) {
        return new MMPSniffer(client,server);
    }
    
protected:
    /** Construct sniffer **/
    MMPSniffer(int client, int server) : Sniffer(client,server) {}
    /** Dump MMP packet **/
    virtual string dumpPacket() {
        ostringstream out;
        uint32_t magic=read<uint32_t>();
        uint32_t version=read<uint32_t>();
        uint32_t sequence=read<uint32_t>();
        uint32_t type=read<uint32_t>();
        uint32_t length=read<uint32_t>();
        uint32_t from=read<uint32_t>();
        uint32_t fromport=read<uint32_t>();
        read<uint64_t>();read<uint64_t>();
        vector<uint8_t> payload=read(length);
        out << "[" << std::hex << type << std::dec << "] v=" << (version>>16)
            << '.' << (version&0xffff) << "; s=" << sequence;
        if (magic!=0xDEADBEEF)
            out << "; magic=0x" << std::hex << magic << std::dec;
        if (from!=0)
            out << "; from=" << std::hex << from << std::dec;
        if (fromport!=0)
            out << "; fromport=" << fromport;
        out << endl << payload;
        return out.str();
    }
    
private:
    /** Fake balancer thread function **/
    static void startFakeBalancer(uint16_t port, uint16_t mmpPort) {
        cerr << "Starting fake balancer at 0.0.0.0:" << port << endl;
        const char * serverAddress=getenv("MRIM_SERVER");
        if (!serverAddress)
            serverAddress="127.0.0.1";
        try {
            int listener=listenAt(port), client;
            char buffer[64];
            while (true) {
                client=accept(listener,0,0);
                cerr << "New connection to balancer" << endl;
                sprintf(buffer,"%s:%d\n",serverAddress,mmpPort);
                write(client,buffer,strlen(buffer));
                close(client);
            }
        }
        catch (Error e) {
            cerr << "Fake balancer: " << e.getStage() << ": " << e.getError() << endl;
        }
    }
};

static Plugin MMP_PLUGIN={
    "mmp",
    "Mail.Ru Agent protocol",
    MMPSniffer::prepare,
    MMPSniffer::create
};
DECLARE_PLUGIN(MMP_PLUGIN);