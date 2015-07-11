/*******************************************************************************
 *  Advanced protocol sniffer
 *  Raw traffic sniffer plugin, suitable for reversing unknown protocols
 *  
 *  © 2013—2015, Sauron
 ******************************************************************************/

#include <mutex>
#include <sstream>
#include "sniffer.hpp"

using std::mutex;
using std::ostream;
using std::ostringstream;
using std::string;
using std::vector;

/** Raw traffic sniffer **/
class RawSniffer : public Sniffer {
public:
    /** Create instance of raw sniffer **/
    static Sniffer * create(int client, int server) {
        return new RawSniffer(client,server);
    }
    
protected:
    /** Construct raw sniffer **/
    RawSniffer(int client, int server) : Sniffer(client,server),
        writingThread(std::this_thread::get_id()),
        mainThread(std::this_thread::get_id()) {}
    /** Dump chunk of data **/
    virtual string dumpPacket();
    
private:
    std::thread::id writingThread,mainThread;
    mutex l;
    vector<uint8_t> cBuffer,sBuffer;
};

string RawSniffer::dumpPacket() {
    extern ostream &operator <<(ostream &stream, const vector<uint8_t> &data);
    vector<uint8_t> &buffer=getDirection()==INCOMING?sBuffer:cBuffer;
    vector<uint8_t> tmpBuffer;
    std::thread::id threadId=std::this_thread::get_id();
    
    try {
        bool exit=false;
        while (!exit) {
            uint8_t b=read<uint8_t>();
            l.lock();
            if ((writingThread!=threadId)&&(writingThread!=mainThread)) {
                exit=true;
                tmpBuffer=buffer;
                buffer.clear();
            }
            writingThread=threadId;
            l.unlock();
            buffer.push_back(b);
        }
    }
    catch (bool) {
        tmpBuffer=buffer;
        buffer.clear();
    }
    
    if (buffer.empty()&&tmpBuffer.empty())
        throw true;
    
    ostringstream result;
    result << tmpBuffer;
    return result.str();
}

static Plugin RAW_PLUGIN={
    "raw",
    "Raw traffic sniffer [default]",
    0,
    RawSniffer::create
};
DECLARE_PLUGIN(RAW_PLUGIN);