/*******************************************************************************
 *  Advanced network sniffer
 *  Main module
 *  
 *  © 2013—2018, Sauron
 ******************************************************************************/

#ifndef __CORE_SNIFFER_HPP
#define __CORE_SNIFFER_HPP

#include <condition_variable>
#include <mutex>
#include <thread>
#include <vector>
#include "../sniffer.hpp"

/**/
struct Plugin {
    const char * name;
    const char * description;
    int version;
    unsigned flags;
    Protocol::Factory factory;
};

/** Plugin registry **/
class Registry : public std::vector<Plugin> {
public:
    /** Thrown on attempt to access non-existent plugin **/
    class PluginNotFoundException {
    public:
        PluginNotFoundException(const char * name) : name(name) {}
        const char * getName() const { return name; }
        
    private:
        const char * name;
    };
    /** Find plugin by name **/
    const Plugin &operator [](const char * name);
    /** Global plugin registry **/
    static Registry &instance();
};

class OptionsImpl : public Options {
public:
    OptionsImpl() {}
    OptionsImpl(const char * optarg);
    const std::string &get(const char * option) const;
    
private:
    std::map<std::string, std::string> options;
};

/**/
class Handler {
public:
    virtual void notify()=0;
};

/** Abstract protocol sniffer **/
class Connection {
public:
    /**/
    explicit Connection(class Sniffer &controller);
    /** Close connection and destroy plugin **/
    virtual ~Connection();
    /** Returns unique instance identifier **/
    unsigned getInstanceId() const { return instanceId; }
    /**/
    bool isAlive() const { return alive; }
    
protected:
    /** Dump next packet **/
    void dump(std::ostream &log, bool incoming, Reader &reader);
    /** Start incoming and outgoing threads **/
    void start(Sniffer &controller);
    /** Output beginning of message to cerr and return it **/
    std::ostream &error() const;
    /** This function should be overridden by subclasses **/
    virtual void threadFunc(std::ostream &log, bool incoming)=0;
    /**/
    bool alive;
    
private:
    Sniffer &controller;
    unsigned instanceId;
    /** Protocol plugin instance **/
    Protocol * protocol;
    /** Mutex for synchronization of access to output log **/
    static std::mutex logMutex;
    /** Thread for interception outgoing data **/
    std::thread c2sThread;
    /** Thread for interception incoming data **/
    std::thread s2cThread;
    
    /** Private thread function **/
    void _threadFunc(Sniffer &controller, bool incoming);
};

/** Object for controlling life cycle of sniffers **/
class Sniffer {
    friend class Connection;
public:
    /**/
    Sniffer(const Plugin &plugin, const OptionsImpl &options,
        std::ostream &output) : maxInstanceId(0), plugin(plugin), options(options),
        output(output), alive(true), gcThread(&Sniffer::gcThreadFunc,
        this) {}
    /**/
    ~Sniffer();
    /** Returns stream where sniffers should write to **/
    std::ostream &getStream() const { return output; }
    /** Create protocol plugin instance **/
    Protocol * newProtocol() const { return plugin.factory(options); }
    /** Called by a connection to inform that it should be destroyed **/
    void mark(Connection * connection);
    
private:
    enum State { Alive, Marked, Deleted };
    
    Sniffer(const Sniffer &)=delete;
    Sniffer &operator =(const Sniffer &)=delete;
    unsigned maxInstanceId;
    const Plugin &plugin;
    OptionsImpl options;
    std::ostream &output;
    bool alive;
    std::mutex gcMutex;
    std::thread gcThread;
    std::condition_variable gc;
    std::map<Connection *, State> sniffers;
    void gcThreadFunc();
    
    /** Called by sniffer to inform that it was created **/
    void add(Connection * connection);
    /** Called by sniffer to inform that it was deleted **/
    void remove(Connection * connection);
};

#endif
