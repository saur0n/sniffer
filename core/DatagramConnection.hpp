#ifndef __CORE_DATAGRAMCONNECTION_HPP
#define __CORE_DATAGRAMCONNECTION_HPP

#include "Sniffer.hpp"

/** Datagram-based protocol (UDP, UDPLITE, DCCP) sniffer **/
class DatagramConnection : public Connection {
public:
    /** Initialize UDP sniffer **/
    DatagramConnection(Sniffer &sniffer, std::ostream &log,
        uint16_t localPort, HostAddress remote);
    
private:
    /** Client socket **/
    
    /****/
    
};

#endif
