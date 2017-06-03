/*******************************************************************************
 *  Advanced network sniffer
 *  Bubuta mobile chat protocol sniffer
 *  
 *  © 2014—2017, Sauron
 ******************************************************************************/

#include <arpa/inet.h>
#include <cstdio> //DEBUUG
#include <cstring>
#include <iomanip>
#include <sstream>
#include <vector>
#include <zlib.h>
#include "sniffer.hpp"

#define SHORT_BINARY

using std::endl;
using std::ostream;
using std::ostringstream;
using std::string;
using std::vector;

class ZlibException {};

static int uncompressGzip(Bytef * dest, uLongf * destLen, const Bytef * source, uLong sourceLen) {
    z_stream stream;

    stream.next_in = (z_const Bytef *)source;
    stream.avail_in = (uInt)sourceLen;
    /* Check for source > 64K on 16-bit machine: */
    if ((uLong)stream.avail_in != sourceLen)
        return Z_BUF_ERROR;

    stream.next_out = dest;
    stream.avail_out = (uInt)*destLen;
    if ((uLong)stream.avail_out != *destLen)
        return Z_BUF_ERROR;

    stream.zalloc = (alloc_func)0;
    stream.zfree = (free_func)0;

    int err = inflateInit2(&stream, 16+MAX_WBITS);
    if (err != Z_OK)
        return err;

    err = inflate(&stream, Z_FINISH);
    if (err != Z_STREAM_END) {
        inflateEnd(&stream);
        if (err == Z_NEED_DICT || (err == Z_BUF_ERROR && stream.avail_in == 0))
            return Z_DATA_ERROR;
        return err;
    }
    *destLen = stream.total_out;

    return inflateEnd(&stream);
}

vector<uint8_t> uncompress(const vector<uint8_t> &data) {
    uLong uncDataLength=data.size();
    vector<uint8_t> uncData(uncDataLength);
    int retval=Z_OK;
    do {
        retval=uncompressGzip(&uncData[0], &uncDataLength, &data[0], data.size());
        if (retval==Z_BUF_ERROR)
            uncData.resize(uncDataLength=uncData.size()*2+1);
    } while (retval==Z_BUF_ERROR);
    if (retval!=Z_OK)
        throw ZlibException();
    return vector<uint8_t>(uncData.begin(), uncData.begin()+uncDataLength);
}

static void printByte(ostream &stream, uint8_t byte) {
    static const char * XDIGITS="0123456789abcdef";
    stream << XDIGITS[byte>>4] << XDIGITS[byte&0x0f];
}

class BubutaReader : public Reader {
public:
    /** Initialize reader with other reader **/
    BubutaReader(Reader &reader, const vector<uint8_t> &key) :
        reader(reader), key(key), shift(0) {}
    /** Read arbitrary number of bytes **/
    void read(void * buffer, size_t length);
    
private:
    Reader &reader;
    const vector<uint8_t> &key;
    size_t shift;
};

void BubutaReader::read(void * buffer, size_t length) {
    reader.read(buffer, length);
    if (!key.empty()) {
        uint8_t * plaintext=static_cast<uint8_t *>(buffer);
        for (size_t i=0; i<length; i++, shift++)
            plaintext[i]^=key[shift%key.size()];
    }
}

class BubutaSniffer : public Protocol {
public:
    /** Initialize counters **/
    BubutaSniffer(const std::map<string, string> &options) {}
    /** Dump Bubuta packet **/
    string dump(bool incoming, Reader &input);
    
private:
    enum DumpException { PREMATURE_EOF, UNKNOWN_TYPE };
    static void dump(const vector<uint8_t> &frame, ostream &stream);
    vector<uint8_t> key;
};

string BubutaSniffer::dump(bool incoming, Reader &rawInput) {
    extern ostream &operator <<(ostream &, const vector<uint8_t> &);
    
    BubutaReader input(rawInput, key);
    uint32_t length=ntohl(uint32_t(input));
    //((length>>24)&0xff)+((length>>16)&0xff+((length>>8)&0xff)+length&0xff;
    uint8_t checksum=uint8_t(input);
    (void)checksum;
    
    ostringstream output;
    /*output << "length=0x" << std::hex << std::setw(8) << std::setfill('0') <<
        length << ", cksum=0x" << std::setw(2) << std::setfill('0') <<
        int(checksum) << std::dec << endl;*/
    
    if (length>=4&&length<0x40000) {
        uint8_t foodgroup=uint8_t(input), type=uint8_t(input);
        output << "--[" << int(foodgroup) << "/" << int(type);
        
        uint8_t flags=uint8_t(input);
        if (flags)
            output << ", flags=" << std::hex << int(flags) << std::dec;
        
        vector<uint8_t> payload(length-4);
        input.read(&payload[0], payload.size());
        
        output << "]--\n";
        try {
            if (flags&1)
                payload=uncompress(payload);
            dump(payload, output);
            output << "\n";
            output << payload << "\n";
        }
        catch (ZlibException ze) {
            output << "\n[!] Could not uncompress packet. Raw dump:\n" << payload;
        }
        catch (DumpException de) {
            output << "\n[!] Could not decode packet. Raw dump:\n" << payload;
        }
        
        if (foodgroup==0) {
            if (type==0) {
                static const struct Key {
                    uint8_t length;
                    const char * key;
                } KEYS[]={
                    {5, "\x98\x82\x51\xb0\x59"},
                    {0, nullptr},
                    {0, nullptr},
                    {0, nullptr},
                    {5, "\x0f\xd6\x76\x90\x1c"}
                };
                uint8_t keyId=payload[6];
                if (keyId<=4&&KEYS[keyId].key) {
                    const Key * $key=KEYS+keyId;
                    key=vector<uint8_t>($key->length);
                    for (size_t i=0; i<key.size(); i++)
                        key[i]=payload[20+i]^uint8_t($key->key[i%key.size()]);
                    
#if 0
                    output << "Timestamp & key: `";
                    for (size_t i=10; i<payload.size(); i++)
                        printByte(output, payload[i]^uint8_t($key->key[i%key.size()]));
                    output << "`\n";
#endif
                }
            }
            else if (type==1) {
                key=vector<uint8_t>(payload.size()-11);
                memcpy(&key[0], &payload[11], key.size());
            }
        }
    }
    else
        output << "\nBad frame length.\n";
    
    return output.str();
}

void BubutaSniffer::dump(const vector<uint8_t> &frame, ostream &stream) {
    class DumpStream {
    public:
        DumpStream(const vector<uint8_t> &frame) : frame(frame), offset(0) {}
        void dumpTo(ostream &stream) {
            uint8_t type=read();
            if (type==0)
                dumpBinaryTo(stream);
            else if (type==1)
                dumpStringTo(stream);
            else if (type==3)
                stream << read(4);
            else if (type==4)
                dumpArrayTo(stream);
            else if (type==5)
                dumpObjectTo(stream);
            else
                throw UNKNOWN_TYPE;
        }
        void dumpBinaryTo(ostream &stream) {
            size_t length=read(3);
            stream << '`';
            for (size_t i=0; i<length; i++)
                printByte(stream, read());
            stream << '`';
        }
        void dumpStringTo(ostream &stream) {
            size_t length=read(2);
            stream << '"';
            for (size_t i=0; i<length; i++)
                dumpCharacterTo(stream);
            stream << '"';
        }
        void dumpArrayTo(ostream &stream) {
            size_t length=read(2);
            stream << '[';
            for (size_t i=0; i<length; i++) {
                if (i!=0)
                    stream << ',';
                dumpTo(stream);
            }
            stream << ']';
        }
        void dumpObjectTo(ostream &stream) {
            size_t length=read(2);
            stream << '{';
            for (size_t i=0; i<length; i++) {
                if (i!=0)
                    stream << ',';
                dumpTo(stream);
                stream << ':';
                dumpTo(stream);
            }
            stream << '}';
        }
        
    private:
        const vector<uint8_t> &frame;
        size_t offset;
        inline int read(unsigned octets=1) {
            if (offset+octets>frame.size())
                throw PREMATURE_EOF;
            int result=0;
            for (unsigned i=0; i<octets; i++)
                result=(result<<8)|frame[offset++];
            return result;
        }
        void dumpCharacterTo(ostream &stream) {
            uint8_t c=read();
            if (c<32) {
                const char * ESCAPED="0------abtnv-r------------------";
                char esc=ESCAPED[c];
                if (esc!='-')
                    stream << esc;
                else {
                    stream << "\\x";
                    printByte(stream, c);
                }
            }
            else {
                if (c=='\\'||c=='\"')
                    stream << '\\';
                stream << char(c);
            }
        }
    };
    
    DumpStream ds(frame);
    ds.dumpArrayTo(stream);
}

REGISTER_PROTOCOL(
    BubutaSniffer,
    "bubuta",
    "Bubuta chat protocol sniffer",
    1,
    Protocol::STREAM
);
