/*******************************************************************************
 *  Advanced network sniffer
 *  Sniffer for SSL/TLS protocols (without decryption)
 *  
 *  © 2020, Sauron
 ******************************************************************************/

#include <sstream>
#include <vector>
#include "../sniffer.hpp"

using std::ostream;
using std::string;
using std::vector;

static struct {
    uint8_t type;
    const char * name;
} TLS_RECORD_TYPES[]={
    {0, "HELLO_REQUEST"},
    {1, "CLIENT_HELLO"},
    {2, "SERVER_HELLO"},
    {11, "CERTIFICATE"},
    {12, "SERVER_KEY_EXCHANGE"},
    {13, "CERTIFICATE_REQUEST"},
    {14, "SERVER_HELLO_DONE"},
    {15, "CERTIFICATE_VERIFY"},
    {16, "CLIENT_KEY_EXCHANGE"},
    {20, "CHANGE_CYPHER_SPEC"},
    {22, "HANDSHAKE"},
    {23, "DATA"},
    {32, "FINISHED"},
    {33, "CERTIFICATE_URL"},
    {34, "CERTIFICATE_STATS"}
};

class TLSSniffer : public Protocol {
public:
    /**/
    TLSSniffer(const Options &options) {}
    /**/
    string dump(bool incoming, Reader &input) {
        extern ostream &operator <<(ostream &, const vector<uint8_t> &);
        
        uint8_t type=uint8_t(input);
        uint8_t major=uint8_t(input), minor=uint8_t(input);
        uint16_t length=__builtin_bswap16(uint16_t(input));
        vector<uint8_t> data(length);
        input.readFully(data.data(), length);
        
        std::ostringstream os;
        const char * recordType=getTLSRecordType(type);
        if (recordType)
            os << recordType;
        else
            os << "UNKNOWN (" << unsigned(type) << ")";
        os << " [" << unsigned(major) << "." << unsigned(minor) << "]\n";
        os << data;
        return os.str();
    }
    
private:
    static const char * getTLSRecordType(uint8_t type) {
        for (size_t i=0; i<sizeof(TLS_RECORD_TYPES)/sizeof(TLS_RECORD_TYPES[0]); i++)
            if (TLS_RECORD_TYPES[i].type==type)
                return TLS_RECORD_TYPES[i].name;
        return nullptr;
    }
};

REGISTER_PROTOCOL(
    TLSSniffer,
    "tls",
    "SSL/TLS sniffer",
    1,
    Protocol::STREAM
);
