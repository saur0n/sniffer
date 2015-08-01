# Sauron Advanced Network Sniffer

This program is capable to sniff following protocols:

* ``mmp`` — Mail.Ru Messaging Protocol
* ``raw`` — arbitrary protocol, packet headers will not be parsed

Sniffer currently runs only under Linux.

## Sniffing Mail.Ru Agent protocol

* Add following line to your /etc/hosts: ``127.0.0.1 mrim.mail.ru``.
* Start sniffer: ``./sniffer --host=217.69.141.242:2042 --proto=mmp``.
* Run Mail.Ru Agent. Note if you using Agent v5.8 or later it will encrypt connection with TLS and sniffer will not intercept encrypted packets.

## Sniffing other protocols

(TODO)

## Sniffing other protocols as SOCKS server

(TODO)

## Writing your own protocol plugin

(TODO)