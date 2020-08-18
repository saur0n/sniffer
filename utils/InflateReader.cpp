/*******************************************************************************
 *  Advanced network sniffer
 *  Utility class for reading compressed streams
 *  
 *  © 2020, Sauron
 ******************************************************************************/

#include <cstring>
#include "InflateReader.hpp"

using std::vector;

static void check(int x) {
    if (x!=Z_OK)
        throw ZLibException(x);
}

const char * ZLibException::what() const {
    return zError(error);
}

InflateReader::InflateReader(Reader &in) : in(in), internalBuffer(1), atEnd(false) {
    memset(&stream, 0, sizeof(stream));
    check(inflateInit(&stream));
}

InflateReader::InflateReader(Reader &in, int windowBits) : in(in), internalBuffer(1), atEnd(false) {
    memset(&stream, 0, sizeof(stream));
    check(inflateInit2(&stream, windowBits));
}

InflateReader::~InflateReader() {
    inflateEnd(&stream);
}

size_t InflateReader::read(void * buffer, size_t length) {
    stream.next_out=static_cast<Bytef *>(buffer);
    stream.avail_out=length;
    while ((stream.avail_out>0)&&!atEnd) {
        //cerr << "loop\n";
        if (stream.avail_in==0) {
            in.read(&internalBuffer[0], internalBuffer.size());
            stream.next_in=&internalBuffer[0];
            stream.avail_in=internalBuffer.size();
        }
        int zres=inflate(&stream, Z_FULL_FLUSH);
        if (zres==Z_STREAM_END)
            atEnd=true;
        else
            check(zres);
    }
    return length-stream.avail_out;
}

void InflateReader::reset() {
    check(inflateReset(&stream));
    atEnd=false;
}

void InflateReader::reset(int windowBits) {
    check(inflateReset2(&stream, windowBits));
    atEnd=false;
}

void InflateReader::resetKeep() {
    check(inflateResetKeep(&stream));
    atEnd=false; //?
}

void InflateReader::sync() {
    check(inflateSync(&stream));
}

vector<uint8_t> InflateReader::getRest(size_t maxLength) {
    vector<uint8_t> result(stream.avail_in>maxLength?maxLength:stream.avail_in);
    for (size_t i=0; i<result.size(); i++) {
        stream.avail_in--;
        result[i]=*(stream.next_in++);
    }
    return result;
}
