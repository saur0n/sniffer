/*******************************************************************************
 *  Advanced network sniffer
 *  Plugin SDK
 *  
 *  © 2013—2017, Sauron
 ******************************************************************************/

#ifndef __SNIFFER_HPP
#define __SNIFFER_HPP

#include <string>
#include <utility>

typedef std::pair<std::string, uint16_t> HostAddress;

/** Sniffer error **/
class Error {
public:
    /** Create exception **/
    explicit Error(const char * stage);
    /** Create exception and specify error code **/
    Error(const char * stage, int error) : stage(stage), error(error) {}
    /** Returns stage name **/
    const char * getStage() const { return stage; }
    /** Returns error code **/
    int getErrno() const { return error; }
    /** Returns error description **/
    const char * getError() const;
    /** Create exception and throw it **/
    static void raise(const char * stage) { throw Error(stage); }
    
private:
    const char * stage;
    int error;
};

/** Abstract data source **/
class Reader {
public:
    /** Read specified number of bytes to buffer **/
    virtual void read(void * buffer, size_t length)=0;
    /** Read primitive value **/
    template <typename T>
    explicit operator T() {
        T result;
        read(&result, sizeof(result));
        return result;
    }
};

/** Abstract plugin class (one instance per connection is created) **/
class Protocol {
public:
    /** Options specified by user **/
    struct Options {
        /** Sniffer modes **/
        enum Type {
            /** Works as fake TCP server **/
            TCP=0,
            /** Works as fake UDP server **/
            UDP=1,
            /** Works as SOCKS5 server **/
            SOCKS=2
        } type;
        /** Local port sniffer listening at **/
        uint16_t localPort;
        /** [not for proxy] Remote host and port **/
        HostAddress remote;
        /** Additional data passed by user **/
        const char * aux;
    };
    /** Factory returns new plugin instance **/
    typedef Protocol * (&Factory)();
    /** Function allows plugin to check/modify parameters passed by user **/
    typedef bool (&Initializer)(Options &options);
    /** Register plugin in the global registry **/
    static void add(const char * name, const char * description, int version,
        Factory create, Initializer initializer);
    /**/
    virtual ~Protocol() {}
    /** [abstract] Dump next packet to string **/
    virtual std::string dump(bool incoming, Reader &input)=0;
};

#define REGISTER_PROTOCOL(class, name, description, version) \
    Protocol * class##Factory() { \
        return new class(); \
    } \
    __attribute__((constructor)) \
    void class##Initialize() { \
        return Protocol::add(name, description, version, class##Factory, class::init); \
    }

#endif
