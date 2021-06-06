/*******************************************************************************
 *  Advanced network sniffer
 *  Sniffer for stream-based connection (SOCK_STREAM)
 *  
 *  © 2013—2021, Sauron
 ******************************************************************************/

#include <cstdio>
#include <cstring>
#include <iostream>
#include <netdb.h>
#include <unistd.h>
#include "StreamConnection.hpp"

using std::endl;
using std::ostream;

#define BUFFER_SIZE 4096

// TODO: move to Utils.hpp
namespace posix {
    ssize_t read(int fd, void * buffer, size_t length);
    ssize_t write(int fd, const void * buffer, size_t length);
}

/******************************************************************************/

StreamReader::StreamReader(int fd, StreamReader &destination) : fd(fd), destination(destination) {}

StreamReader::~StreamReader() {
    close(fd);
    fd=-1;
    cv.notify_all();
}

void StreamReader::notify() {
    if (isAlive()) {
        char tempBuffer[BUFFER_SIZE];
        auto retval=posix::read(fd, tempBuffer, sizeof(tempBuffer));
        if (retval>0) {
            {
                std::unique_lock<std::mutex> lock(mutex);
                buffer.append(tempBuffer, retval);
            }
            posix::write(destination.getDescriptor(), tempBuffer, retval);
        }
        else {
            close(fd);
            fd=-1;
        }
    }
    cv.notify_all();
}

size_t StreamReader::read(void * destination, size_t length) {
    size_t result=0;
    if (length>0) {
        std::unique_lock<std::mutex> lock(mutex);
        if (buffer.length()<length) {
            do {
                cv.wait(lock);
            } while (isAlive()&&(buffer.length()==0));
        }
        if (isAlive()) {
            if (buffer.length()<=length) {
                memcpy(destination, buffer.data(), buffer.length());
                result=buffer.length();
                buffer.clear();
            }
            else {
                memcpy(destination, buffer.data(), length);
                buffer.erase(0, length);
                result=length;
            }
        }
    }
    return result;
}

/******************************************************************************/

StreamConnection::StreamConnection(Sniffer &sniffer, int clientfd,
        HostAddress remote) : Connection(sniffer), client(clientfd, server),
        server(initialize(remote), client) {
    start(sniffer);
}

StreamConnection::StreamConnection(Sniffer &sniffer, int clientfd) :
        Connection(sniffer), client(clientfd, server),
        server(acceptSocksConnection(clientfd), client) {
    start(sniffer);
}

StreamConnection::~StreamConnection() {}

int StreamConnection::initialize(HostAddress remote) {
    // Get server network address
    char service[16];
    sprintf(service, "%d", remote.second);
    struct addrinfo hints, * ai;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family=AF_INET; /* IPv4 only */
    hints.ai_socktype=SOCK_STREAM; /* TCP */
    int ret=getaddrinfo(remote.first.c_str(), service, &hints, &ai);
    if (ret!=0)
        throw Error("connecting", EHOSTUNREACH);
    
    // Connect to server
    error() << "connecting to " << remote.first << ':' << remote.second << "…" << endl;
    int result=socket(AF_INET, SOCK_STREAM, 0);
    if (result<0)
        Error::raise("creating socket");
    if (connect(result, ai->ai_addr, ai->ai_addrlen)<0)
        Error::raise("connecting to host");
    freeaddrinfo(ai);
    
    return result;
}

void StreamConnection::threadFunc(ostream &log, bool incoming) {
    while (true)
        dump(log, incoming, incoming?server:client);
}
