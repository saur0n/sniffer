/*******************************************************************************
 *  Advanced network sniffer
 *  Utility class for reading compressed streams
 *  
 *  © 2020, Sauron
 ******************************************************************************/

#ifndef __UTILS_INFLATEREADER_HPP
#define __UTILS_INFLATEREADER_HPP

#include <vector>
#include <zlib.h>
#include "../sniffer.hpp"

/**/
class ZLibException {
public:
    explicit ZLibException(int error) : error(error) {}
    const char * what() const;
    
private:
    int error;
};

/**/
class InflateReader : public Reader {
public:
    /** End of stream marker **/
    class End : public Reader::End {};
    /**/
    explicit InflateReader(Reader &in);
    /**/
    InflateReader(Reader &in, int windowBits);
    /**/
    ~InflateReader();
    /** Returns the underlying input stream **/
    Reader &getInput() const { return in; }
    /**/
    size_t read(void * buffer, size_t length) override;
    /** Reset the stream state **/
    void reset();
    /** Reset the stream state **/
    void reset(int windowBits);
    /**/
    void resetKeep();
    /**/
    void sync();
    /**/
    size_t availIn() const {
        return stream.avail_in;
    }
    /**/
    bool isAtEnd() const { return atEnd; }

protected:
    std::vector<uint8_t> getRest(size_t maxLength);
    
private:
    InflateReader(const InflateReader &other)=delete;
    InflateReader &operator =(const InflateReader &other)=delete;
    
    z_stream stream;
    Reader &in;
    std::vector<uint8_t> internalBuffer;
    bool atEnd;
};

#endif
