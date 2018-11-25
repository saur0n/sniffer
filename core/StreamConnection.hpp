#ifndef __CORE_STREAMCONNECTION_HPP
#define __CORE_STREAMCONNECTION_HPP

#include "Sniffer.hpp"

class StreamReader : public Reader, public Handler {
public:
    StreamReader(int fd, StreamReader &destination) : fd(fd), destination(destination) {}
    ~StreamReader() {
        close(fd);
        fd=-1;
        cv.notify_all();
    }
    int getDescriptor() const { return fd; }
    void notify();
    
private:
    StreamReader(const StreamReader &)=delete;
    StreamReader &operator =(const StreamReader &)=delete;
    void read(void * destination, size_t length) {
        std::unique_lock<std::mutex> lock(mutex);
        while ((fd>=0)&&(buffer.size()<length))
            cv.wait(lock);
        if (fd<0)
            throw true;
        memcpy(destination, buffer.data(), length);
        buffer.erase(0, length);
    }
    
    int fd;
    StreamReader &destination;
    std::string buffer;
    std::mutex mutex;
    std::condition_variable cv;
};

/** Stream protocol sniffer **/
class StreamConnection : public Connection {
public:
    /** Create TCP sniffer working as a forwarder **/
    StreamConnection(Sniffer &controller, int client, HostAddress remote);
    /** Create TCP sniffer working as SOCKS proxy **/
    StreamConnection(Sniffer &controller, int client);
    /** Close connections **/
    ~StreamConnection();
    /** Returns the interface for using in the polling function **/
    Handler &getHandler(unsigned no) { return no?client:server; }
    
private:
    /** Client to server reader **/
    StreamReader client;
    /** Server socket descriptor **/
    StreamReader server;
    /** Connect to server **/
    int initialize(HostAddress remote);
    /** Accept SOCKS connection and connect to the target server **/
    int acceptSocksConnection(int client);
    /** Thread function **/
    void threadFunc(std::ostream &log, bool incoming);
};

#endif
