# Overview

bttools is a set of Python tools for experimenting with the BitTorrent
protocol. It current consists of two tools: utptrace and btparser.

# utptrace

uTP (uTorrent Transport Protocol, also known as the Micro Transport
Protocol) is a reliable transport protocol implemented over UDP. It is
used by some BitTorrent clients for file transfer. See [BEP 29][1] for
more information.

py-utptrace is a Python library for tracing uTP streams. At the moment
it works as a simple script that receives a PCAP file, traces it and
writes the assembled streams to disk.

# btparser

btparser parses the BitTorrent streams. The output of utptrace can be
passed to btparser as an argument. btparser then prints out what it
finds in the given stream.

[1]: http://www.bittorrent.org/beps/bep_0029.html
