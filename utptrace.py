# suppress scapy warnings
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import RawPcapReader, Ether, IP, UDP
from random import randint

ST_DATA = 0x0
ST_FIN = 0x1
ST_STATE = 0x2
ST_RESET = 0x3
ST_SYN = 0x4

CS_HANDSHAKE = 0x1
CS_SYN_ACKED = 0x2
CS_CONNECTED = 0x3
CS_HALF_CLOSED = 0x4
CS_PENDING = 0x5

total = 0

class UtpFlow(object):
    def __init__(self, connid, seq):
        self.connid = connid
        self.seq = seq + 1
        self.state = CS_HANDSHAKE
        self.pending = []

    def __repr__(self):
        return '<UtpFlow connid={}>'.format(self.connid)

class UtpTracer(object):
    def __init__(self):
        self.flows = {}
        self.no_incomplete_flows = True

    def trace(self, pkt):
        assert isinstance(pkt[0], Ether) and \
            isinstance(pkt[1], IP) and \
            isinstance(pkt[2], UDP)

        payload = str(pkt[3])
        if len(payload) < 20:
            print 'Payload smaller than 20 bytes. Not a UTP packet.'
            return

        version = ord(payload[0]) & 0x0f
        if version != 1:
            print 'Invalid version. Not a UTP packet.'
            return

        type = (ord(payload[0]) & 0xf0) >> 4
        if type > 4:
            print 'Invalid type. Not a UTP packet.'
            return

        connid = (ord(payload[2]) << 8) | ord(payload[3])

        src = pkt[1].src
        dst = pkt[1].dst
        sport = pkt[2].sport
        dport = pkt[2].dport

        seq = (ord(payload[16]) << 8) | \
              (ord(payload[17]) << 0)

        if (src, sport, dst, dport) in self.flows:
            flow = self.flows[src, sport, dst, dport]

            if type != ST_SYN and flow.state == CS_SYN_ACKED:
                flow.connid += 1

            if connid + 1 != flow.connid and type == ST_RESET:
                print 'Invalid connid.'
                return
            elif connid != flow.connid and type != ST_RESET:
                print 'Invalid connid.'
                return

            if type == ST_DATA:
                if flow.state != CS_CONNECTED:
                    if flow.state == CS_HANDSHAKE:
                        del self.flows[src, sport, dst, dport]
                        print 'SYN not acked. Removed flow.'
                        return
                    flow.state = CS_CONNECTED
                    print 'put connection to connected mode'

                    r_flow = self.flows.get((dst, dport, src, sport), None)
                    if not r_flow:
                        del self.flows[src, sport, dst, dport]
                        print 'No reverse flow. Something is wrong.'
                        return
                    r_flow.state = CS_CONNECTED
                    print 'put reverse to connected mode'

                if seq == flow.seq:
                    self.add_data(payload[20:], flow)
                elif seq > flow.seq:
                    flow.pending.append((payload[20:], seq))
                    print 'Out of order packet. Added to pending list.'
                else: # seq < flow.seq
                    print 'Duplicate packet. Ignored.'
                    return
            elif type == ST_RESET:
                print 'RST received. Flows reset.'
                del self.flows[src, sport, dst, dport]
                if (dst, dport, src, sport) in self.flows:
                    del self.flows[dst, dport, src, sport]
            elif type == ST_FIN:
                print 'FIN received. Closing flows.'
                if len(flow.pending) == 0:
                    del self.flows[src, sport, dst, dport]
                    print 'Flow closed (side 1).'

                    # Put the other side in half closed state.
                    if (dst, dport, src, sport) in self.flows:
                        self.flows[dst, dport, src, sport].state = CS_HALF_CLOSED
                else:
                    print 'Waiting for pending packets before closing the flows.'
                    flow.state = CS_PENDING
                    if (dst, dport, src, sport) in self.flows:
                        self.flows[dst, dport, src, sport].state = CS_PENDING
            elif type == ST_STATE:
                if flow.state == CS_HALF_CLOSED:
                    del self.flows[src, sport, dst, dport]
                    print 'Flow closed (side 2).'
                else:
                    print 'Normal ACK received.'
        else:
            if self.no_incomplete_flows:
                if type in (ST_DATA, ST_FIN):
                    print 'Incomplete flow. Ignored.'
                    return
                if type == ST_RESET:
                    print 'Lone RESET received. Ignored.'
                    return

            if type == ST_SYN:
                flow = UtpFlow(connid, seq)

                r_flow = self.flows.get((dst, dport, src, sport), None)
                if r_flow:
                    if r_flow.state == CS_HANDSHAKE:
                        print 'Two peers trying simultaneously to initiate a connection. Letting the second one win.'
                        del self.flows[dst, dport, src, sport]
                    else:
                        print 'SYN in the middle of connection. Ignored.'
                        return

                self.flows[src, sport, dst, dport] = flow
                print 'New flow.'
            elif type == ST_STATE:
                r_src, r_sport, r_dst, r_dport = dst, dport, src, sport
                r_flow = self.flows.get((r_src, r_sport, r_dst, r_dport), None)
                if not r_flow:
                    print 'ACK for a non-existent flow. Ignored.'
                    return
                if connid != r_flow.connid:
                    print 'Connedtion IDs do not match.'
                    return
                flow = UtpFlow(connid, seq)
                self.flows[src, sport, dst, dport] = flow
                r_flow.state = CS_SYN_ACKED
                print 'SYN acknowledged.'
            else:
                print 'We should not have reached here. Something is seriously wrong!'
                return

    def add_data(self, piece, flow):
        print 'PIECE:', len(piece), 'byte(s) received.'
        flow.seq = (flow.seq + 1) % 0xffff

        global total
        total += len(piece)

        added_some = True
        while added_some:
            added_some = False
            for payload, seq in flow.pending:
                if seq == flow.seq:
                    print 'PIECE (WAS PENDING): Added', len(payload), 'byte(s)'
                    flow.seq = (flow.seq + 1) % 0xffff
                    added_some = True

import sys
tracer = UtpTracer()
reader = RawPcapReader(sys.argv[1])
i = 1
for pkt_data in reader:
    print i
    i += 1
    p = Ether(pkt_data[0])
    if isinstance(p[1], IP) and isinstance(p[2], UDP):
        tracer.trace(p)

print 'Remaining Flow:', len(tracer.flows)
print 'Total Bytes:', total
