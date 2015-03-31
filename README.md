# Overview

uTP (uTorrent Transport Protocol, also known as the Micro Transport
Protocol) is a reliable transport protocol implemented over UDP. It is
used by some BitTorrent clients for file transfer. See [BEP 29][1] for
more information.

py-utptrace is a Python library for tracing uTP streams. At the moment
it works as a simple script that receives a PCAP file and traces it
(the reassembled stream is not really written anywhere!). This will
hopefully change very soon.

[1]: http://www.bittorrent.org/beps/bep_0029.html
