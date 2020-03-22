/*******************************************************************************
 *  Advanced network sniffer
 *  Main module
 *  
 *  © 2013—2020, Sauron
 ******************************************************************************/

#ifndef __CORE_SNIFFER_HPP
#define __CORE_SNIFFER_HPP

#include <condition_variable>
#include <mutex>
#include <set>
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
class Channel {
public:
    virtual bool isAlive() const=0;
    virtual int getDescriptor() const=0;
    virtual void notify()=0;
};

/** Abstract protocol sniffer **/
class Connection {
public:
    /** Create a sniffer connection and protocol handler instance **/
    explicit Connection(class Sniffer &controller);
    /** Close connection and destroy protocol handler instance **/
    virtual ~Connection();
    /** Returns unique instance identifier **/
    unsigned getInstanceId() const { return instanceId; }
    /** Returns whether at least one connection is alive **/
    bool isAlive();
    /** Returns server-to-client handler **/
    virtual Channel &getChannel(bool incoming)=0;
    
protected:
    /** Dump next packet **/
    void dump(std::ostream &log, bool incoming, Reader &reader);
    /** Start incoming and outgoing threads **/
    void start(Sniffer &sniffer);
    /** Output beginning of message to cerr and return it **/
    std::ostream &error() const;
    /** This function should be overridden by subclasses **/
    virtual void threadFunc(std::ostream &log, bool incoming)=0;
    
private:
    Sniffer &sniffer;
    static unsigned maxInstanceId;
    unsigned instanceId;
    /** Protocol handler instance **/
    Protocol * protocol;
    /** Mutex for synchronization of access to output log **/
    static std::mutex logMutex;
    /** Thread for interception outgoing data **/
    std::thread c2sThread;
    /** Thread for interception incoming data **/
    std::thread s2cThread;
    
    /** Private thread function **/
    void _threadFunc(Sniffer &sniffer, bool incoming);
};

/** Object for controlling life cycle of sniffed connections **/
class Sniffer {
public:
    /**/
    Sniffer(const Plugin &plugin, const OptionsImpl &options, std::ostream &output);
    /**/
    ~Sniffer();
    /** Returns stream where sniffers should write to **/
    std::ostream &getStream() const { return output; }
    /** Create protocol plugin instance **/
    Protocol * newProtocol() const { return plugin.factory(options); }
    /** Add a new connection **/
    template <class T, class... A>
    void add(A... args) {
        Connection * connection=new T(*this, args...);
        add(connection);
    }
    
private:
    typedef Connection * ConnectionPtr;
    const Plugin &plugin;
    OptionsImpl options;
    std::ostream &output;
    bool alive;
    std::mutex gcMutex;
    std::thread pollThread;
    std::vector<ConnectionPtr> connections;
    
    Sniffer(const Sniffer &)=delete;
    Sniffer &operator =(const Sniffer &)=delete;
    /** Called by sniffer to inform that it was created **/
    void add(Connection * connection);
    /** Polling thread worker **/
    void pollThreadFunc();
};

#endif
