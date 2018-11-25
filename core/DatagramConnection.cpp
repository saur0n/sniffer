#include <iostream>
#include "DatagramConnection.hpp"

using std::endl;
using std::ostream;

DatagramConnection::DatagramConnection(Sniffer &sniffer, ostream &log,
        uint16_t localPort, HostAddress remote) : Connection(sniffer) {
    log << "Datagram sniffer log" << endl;
    log << "Date: <DATE HERE>" << endl;
    log << "Port: <PORT>" << endl;
    throw "NOT IMPLEMENTED YET";
}
