/*******************************************************************************
 *  Advanced protocol sniffer
 *  Plugin SDK
 *  
 *  © 2013—2015, Sauron
 ******************************************************************************/

#ifndef __SNIFFER_HPP
#define __SNIFFER_HPP

#include <cerrno>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

/** Sniffer error **/
class Error {
public:
    /** Create exception **/
    Error(const char * stage) : stage(stage), error(errno) {}
    /** Create exception and specify error code **/
    Error(const char * stage, int error) : stage(stage), error(error) {}
    /** Returns stage name **/
    const char * getStage() const { return stage; }
    /** Returns error code **/
    int getErrno() const { return error; }
    /** Returns error description **/
    const char * getError() const { return strerror(error); }
    /** Create exception and throw it **/
    static void raise(const char * stage) { throw Error(stage); }
    
private:
    const char * stage;
    int error;
};

/** Abstract protocol sniffer **/
class Sniffer {
public:
    /** Packet direction **/
    enum Direction {
        /** Client-to-server **/
        OUTGOING,
        /** Server-to-client **/
        INCOMING
    };
    /** Construct sniffer **/
    Sniffer(int client, int server) : client(client), server(server) {}
    /** Close connections **/
    virtual ~Sniffer();
    /** Call this after constructing sniffer **/
    void start(unsigned id, std::ostream &log);
    
protected:
    /** Returns data direction **/
    Direction getDirection() const;
    /** Read portion of raw data **/
    void read(void * buffer, size_t length);
    /** Read byte array **/
    std::vector<uint8_t> read(size_t length);
    /** Read primitive value **/
    template <typename T>
    T read() {
        T result;
        read(&result,sizeof(result));
        return result;
    }
    /** Dump packet **/
    virtual std::string dumpPacket()=0;
    
private:
    /** Client socket descriptor **/
    int client;
    /** Server socket descriptor **/
    int server;
    /** Logging stream lock **/
    //TODO
    /** Outgoing thread ID **/
    std::thread::id c2s;
    /** Unique connection ID **/
    unsigned connectionId;
    /** Thread function **/
    static void threadFunc(Sniffer &sniffer, std::ostream &log, Direction dir);
    /** Format header for packet dump **/
    static std::string makeHeader(unsigned connectionId, Direction dir);
};

/** Plugin description **/
struct Plugin {
    /** Plugin name (lowercase, 3-16 chars) **/
    const char * name;
    /** Plugin description **/
    const char * description;
    /** Called after parsing arguments **/
    void (* prepare)(uint16_t &localPort, const char * &host, uint16_t &port);
    /** Create new Sniffer instance **/
    Sniffer * (* create)(int client, int server);
    /** Global plugin list **/
    static std::vector<Plugin *> plugins;
};

#define DECLARE_PLUGIN(plugin) \
    __attribute__((constructor)) \
    static void init_##plugin() { \
        Plugin::plugins.push_back(&plugin); \
    }

#endif