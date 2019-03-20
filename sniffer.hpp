/*******************************************************************************
 *  Advanced network sniffer
 *  Plugin SDK
 *  
 *  © 2013—2017, Sauron
 ******************************************************************************/

#ifndef __SNIFFER_HPP
#define __SNIFFER_HPP

#include <map>
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
    static void raise(const char * stage);
    
private:
    const char * stage;
    int error;
};

/** A system call was interrupted **/
class Interrupt {};

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

/** Abstract option provider **/
class Options {
public:
    /** Get an option value **/
    virtual const std::string &get(const char * option) const=0;
};

/** Abstract plugin class (one instance per connection is created) **/
class Protocol {
public:
    /** Various plugin flags **/
    enum PluginFlags {
        /** Can be used on a stream connection **/
        STREAM=1,
        /** Can be used on a datagram connection **/
        DATAGRAM=2
    };
    /** Factory returns new plugin instance **/
    typedef Protocol * (&Factory)(const Options &options);
    /** Register plugin in the global registry **/
    static void add(const char * name, const char * description, int version,
        unsigned flags, Factory create);
    /**/
    virtual ~Protocol() {}
    /** [abstract] Dump next packet to string **/
    virtual std::string dump(bool incoming, Reader &input)=0;
};

#define REGISTER_PROTOCOL(class, name, description, version, flags) \
    Protocol * class##Factory(const Options &options) { \
        return new class(options); \
    } \
    __attribute__((constructor)) \
    void class##Initialize() { \
        return Protocol::add(name, description, version, flags, class##Factory); \
    }

#endif
