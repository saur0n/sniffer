/*******************************************************************************
 *  Advanced network sniffer
 *  Sniffer for stream-based connection (SOCK_STREAM)
 *  
 *  © 2013—2021, Sauron
 ******************************************************************************/

#ifndef __CORE_STREAMCONNECTION_HPP
#define __CORE_STREAMCONNECTION_HPP

#include "Sniffer.hpp"

class StreamReader : public Reader, public Channel {
public:
    /**/
    StreamReader(int fd, StreamReader &destination);
    ~StreamReader();
    bool isAlive() const { return fd>=0; }
    int getDescriptor() const { return fd; }
    void notify();
    
private:
    StreamReader(const StreamReader &)=delete;
    StreamReader &operator =(const StreamReader &)=delete;
    size_t read(void * destination, size_t length);
    void close();
    
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
    Channel &getChannel(bool incoming) { return incoming?server:client; }
    
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
