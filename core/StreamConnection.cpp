#include <cstdio>
#include <cstring>
#include <unistd.h>
#include "StreamConnection.hpp"

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
