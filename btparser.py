#!/usr/bin/env python

import bencode

import sys
import struct
from socket import ntohl, ntohs

message_parsers = {}
extended_message_parsers = {}

# maps extended message numbers to their names
extended_message_associtions = {}

def register_message(n):
    def decorator(f):
        def wrapper(*args, **kwargs):
            f(*args, **kwargs)
        message_parsers[n] = f
        return wrapper
    return decorator

def register_extended_message(n):
    def decorator(f):
        def wrapper(*args, **kwargs):
            f(*args, **kwargs)
        extended_message_parsers[n] = f
        return wrapper
    return decorator

@register_message(0)
def parse_message_choke(stream, n, length):
    print 'CHOKE'

@register_message(1)
def parse_message_choke(stream, n, length):
    print 'UNCHOKE'

@register_message(2)
def parse_message_choke(stream, n, length):
    print 'INTERESTED'

@register_message(3)
def parse_message_choke(stream, n, length):
    print 'NOT INTERESTED'

@register_message(4)
def parse_message_choke(stream, n, length):
    index = ntohl(struct.unpack('I', stream[n+5:n+9])[0])
    print 'HAVE:', index

@register_message(5)
def parse_message_choke(stream, n, length):
    print 'BITFIELD:', ''.join(bin(ord(i))[2:] for i in stream[n+5:n+length])

@register_message(6)
def parse_message_choke(stream, n, length):
    if n + 17 >= len(stream):
        print 'Unexpected end of stream.'
        exit(1)
    index = ntohl(struct.unpack('I', stream[n+5:n+9])[0])
    begin = ntohl(struct.unpack('I', stream[n+9:n+13])[0])
    length = ntohl(struct.unpack('I', stream[n+13:n+17])[0])
    print 'REQUEST: index={} begin={} length={}'.format(index, begin, length)

@register_message(7)
def parse_message_piece(stream, n, length):
    index = ntohl(struct.unpack('I', stream[n+5:n+9])[0])
    begin = ntohl(struct.unpack('I', stream[n+9:n+13])[0])
    print 'PIECE: index={} begin={} block_size={}'.format(index, begin, length - 1 - 8)

@register_message(8)
def parse_message_choke(stream, n, length):
    index = ntohl(struct.unpack('I', stream[n+5:n+9])[0])
    begin = ntohl(struct.unpack('I', stream[n+9:n+13])[0])
    length = ntohl(struct.unpack('I', stream[n+13:n+17])[0])
    print 'CANCEL: index={} begin={} length={}'.format(index, begin, length)

@register_message(9)
def parse_message_port(stream, n, length):
    port = ntohs(struct.unpack('H', stream[n+5:n+7])[0])
    print 'DHT Port:', port

@register_message(0x0d)
def parse_message_suggest_piece(stream, n, length):
    index = ntohl(struct.unpack('I', stream[n+5:n+9])[0])
    print 'SUGGEST PIECE:', index

@register_message(0x0e)
def parse_message_have_all(stream, n, length):
    print 'HAVE ALL'

@register_message(0x0f)
def parse_message_have_none(stream, n, length):
    print 'HAVE NONE'

@register_message(0x10)
def parse_message_reject(stream, n, length):
    index = ntohl(struct.unpack('I', stream[n+5:n+9])[0])
    begin = ntohl(struct.unpack('I', stream[n+9:n+13])[0])
    length = ntohl(struct.unpack('I', stream[n+13:n+17])[0])
    print 'REJECT:', index, begin, length

@register_message(0x11)
def parse_message_allowed_fast(stream, n, length):
    index = ntohl(struct.unpack('I', stream[n+5:n+9])[0])
    print 'ALLOWED FAST:', index

@register_message(20)
def parser_message_extended(stream, n, length):
    n += 5
    id = ord(stream[n])
    n += 1
    if id == 0:
        handshake = stream[n:n + (length - 2)]
        handshake = bencode.bdecode(handshake)
        print 'EXTENDED: Handshake:', handshake

        for name, number in handshake['m'].items():
            if number == 0:
                # disable this extension
                extended_message_associations = {
                    k: v for k, v in extended_message_associtions.items()
                    if v != name}
            else:
                # add this extension
                extended_message_associtions[number] = name
    elif id in extended_message_associtions:
        name = extended_message_associtions[id]
        if name not in extended_message_parsers:
            print 'EXTENDED: UNKNOWN EXTENSION PROTOCOL:', name
            return
        extended_message_parsers[name](stream, n - 6, length)
    else:
        print 'EXTENDED: UNKNOWN MESSAGE ID:', id
        return

@register_extended_message('lt_tex')
def parse_message_foo(stream, n, length):
    lt_tex = bencode.bdecode(stream[n+6:n+length+4])
    print 'lt_tex: announced {} tracker(s).'.format(len(lt_tex['added']))

@register_extended_message('ut_pex')
def parse_message_foo(stream, n, length):
    ut_pex = bencode.bdecode(stream[n+6:n+length+4])
    added = ut_pex['added']
    prefer_encryption = len([i for i in ut_pex['added.f'] if ord(i) & 0x01 == 1])
    seeders = len([i for i in ut_pex['added.f'] if ord(i) & 0x02 == 1])
    print 'ut_pex: added {} peers ({} prefer(s) encryption; {} is/are seeder(s)). dropped {}.'.format(len(added), prefer_encryption, seeders, len(ut_pex['dropped']))

    if all(k in ut_pex for k in ['added6', 'added6.f', 'dropped6']) and \
       (len(ut_pex['added6']) > 0 or len(ut_pex['dropped6']) > 0):
        added = ut_pex['added6']
        prefer_encryption = len([i for i in ut_pex['added6.f'] if ord(i) & 0x01 == 1])
        seeders = len([i for i in ut_pex['added6.f'] if ord(i) & 0x02 == 1])
        print '        also added {} IPv6 peers ({} prefer(s) encryption; {} is/are seeder(s)). dropped {}.'.format(len(added), prefer_encryption, seeders, len(ut_pex['dropped6']))

@register_extended_message('upload_only')
def parse_message_foo(stream, n, length):
    payload = stream[n+6:n+length+4]
    print 'upload_only: turned', 'off' if payload[0] == '\x00' else 'on'

def parse_message(stream, n):
    length = ntohl(struct.unpack('I', stream[n:n + 4])[0])
    if length == 0:
        return n + 4

    id = ord(stream[n + 4])

    try:
        message_parsers[id](stream, n, length)
    except KeyError as e:
        print 'UNKNOWN MESSAGE ID:', id

    return n + length + 4

def parse_stream(stream):
    pstrlen = ord(stream[0])
    pstr = stream[1:pstrlen + 1]

    if pstr != 'BitTorrent protocol':
        print 'Stream does not contain BitTorrent data.'
        exit(1)

    print 'pstr:', pstr

    n = 1 + pstrlen
    reserved = stream[n:n + 8]
    print 'reserved:', `reserved`
    n += 8

    infohash = stream[n:n + 20]
    print 'infohash:', `infohash`
    n += 20

    peerid = stream[n:n + 20]
    print 'peerid:', `peerid`
    n += 20

    while n < len(stream):
        n = parse_message(stream, n)

def main():
    filename = sys.argv[1]
    with open(filename) as f:
        stream = f.read()

    parse_stream(stream)

if __name__ == '__main__':
    main()
