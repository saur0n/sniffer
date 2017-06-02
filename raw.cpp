/*******************************************************************************
 *  Advanced network sniffer
 *  Plugin for any binary protocol
 *  
 *  © 2017, Sauron
 ******************************************************************************/

#include <cstdio>
#include <sstream>
#include <vector>
#include "sniffer.hpp"

using std::ostream;
using std::ostringstream;
using std::string;
using std::vector;

extern ostream &operator <<(ostream &stream, const vector<uint8_t> &data);

class RawSniffer : public Protocol {
public:
    /** Initialize plugin **/
    RawSniffer() : lastWriter(LW_NONE) {}
    /** Dump Raw packet **/
    string dump(bool incoming, Reader &input);
    /** Initialize plugin **/
    static bool init(Protocol::Options &options);
    
private:
    enum Writer { LW_NONE, LW_INCOMING, LW_OUTGOING } lastWriter;
    vector<uint8_t> buffer;
};

string RawSniffer::dump(bool incoming, Reader &input) {
    Writer opposite=incoming?LW_OUTGOING:LW_INCOMING;
    uint8_t byte;
    vector<uint8_t> packet;
    do {
        try {
            byte=uint8_t(input);
            if (lastWriter==opposite)
                packet.swap(buffer);
            buffer.push_back(byte);
            lastWriter=incoming?LW_INCOMING:LW_OUTGOING;
        }
        catch (bool) {
            if (buffer.empty())
                throw;
            else
                packet.swap(buffer);
        }
    } while (packet.empty());
    
    ostringstream out;
    out << packet;
    return out.str();
}

bool RawSniffer::init(Protocol::Options &options) {
    return options.type==Options::TCP||options.type==Options::SOCKS;
}

REGISTER_PROTOCOL(
    RawSniffer,
    "raw",
    "Universal raw sniffer",
    1
);
 
