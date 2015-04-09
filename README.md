# Overview

bttools is a set of Python tools for experimenting with the BitTorrent
protocol. It current consists of two tools: utptrace and btparser.

## utptrace

uTP (uTorrent Transport Protocol, also known as the Micro Transport
Protocol) is a reliable transport protocol implemented over UDP. It is
used by some BitTorrent clients for file transfer. See [BEP 29][1] for
more information.

utptrace is a library for tracing uTP streams. It can be used as a
script and fed a PCAP file to trace all uTP streams in it and write
them to disk, or it can be fed packets incrementally and receive
stream segments in callbacks.

## tcptrace

This module is very similar to utptrace, only it works for TCP. Not
strictly BitTorrent related but may come handy.

## btparser

btparser parses BitTorrent streams. An output file of utptrace can be
passed to btparser as an argument. btparser then prints out what it
finds in the given stream. Like utptrace, btparser can also be used as
a library.

# Dependencies

scapy and bencode are needed in order to use any of the above
mentioned libraries. You can get the dependencies by simply running
`make` (you'll need pip and virtualenv, in addition to make).

The code has been tested with Python 2.7.6.

[1]: http://www.bittorrent.org/beps/bep_0029.html
