/*******************************************************************************
 *  Advanced network sniffer
 *  Utility class for reading compressed streams
 *  
 *  © 2020, Sauron
 ******************************************************************************/

#include <cstdio>
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

InflateReader::InflateReader(Reader &in) : in(in), internalBuffer(256), atEnd(false) {
    memset(&stream, 0, sizeof(stream));
    check(inflateInit(&stream));
}

InflateReader::InflateReader(Reader &in, int windowBits) : in(in), internalBuffer(256), atEnd(false) {
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
            size_t nRead=in.read(&internalBuffer[0], internalBuffer.size());
            if (nRead==0) {
                fprintf(stderr, "[.] FUCK: zero occurred\n");
                throw End();
            }
            fprintf(stderr, "[.] buffer populated, nRead=%zu\n", nRead);
            stream.next_in=&internalBuffer[0];
            stream.avail_in=nRead;
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

size_t InflateReader::getRest(void * buffer, size_t maxLength) {
    uint8_t * byteBuffer=reinterpret_cast<uint8_t *>(buffer);
    if (stream.avail_in<maxLength)
        maxLength=stream.avail_in;
    memcpy(byteBuffer, stream.next_in, maxLength);
    stream.next_in+=maxLength;
    stream.avail_in-=maxLength;
    return maxLength;
}
