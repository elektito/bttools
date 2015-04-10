# suppress scapy warnings
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import RawPcapReader, Ether, IP, TCP
import os

FG_FIN = 0x01
FG_SYN = 0x02
FG_RST = 0x04
FG_ACK = 0x10

CS_INIT = 1
CS_INITIATOR_SENT_SYN = 2
CS_SYN_ACKED = 3
CS_CONNECTED = 4
CS_INITIATOR_SENT_FIN = 5
CS_ACCEPTER_SENT_FIN = 6
CS_INITIATOR_FIN_ACKED = 7
CS_ACCEPTER_FIN_ACKED = 8
CS_BOTH_SENT_FIN = 9
CS_BOTH_SENT_FIN_INITIATOR_ACKED = 10
CS_BOTH_SENT_FIN_ACCEPTER_ACKED = 11
CS_PENDING_CLOSE = 12

class TcpFlow(object):
    def __init__(self,
                 initiator_ip, initiator_port,
                 accepter_ip, accepter_port,
                 seq0):
        self.initiator_ip = initiator_ip
        self.initiator_port = initiator_port
        self.accepter_ip = accepter_ip
        self.accepter_port = accepter_port
        self.tup = (initiator_ip, initiator_port, accepter_ip, accepter_port)
        self.seq0 = seq0
        self.seq1 = 0
        self.state = CS_INITIATOR_SENT_SYN
        self.pending = []

    def __repr__(self):
        return '<TcpFlow {}>'.format(str(self))

    def __str__(self):
        return '{}:{} => {}:{}'.format(
            self.initiator_ip,
            self.initiator_port,
            self.accepter_ip,
            self.accepter_port)

state_machine = {}

def on_state(state):
    def decorator(f):
        state_machine[state] = f
        return f
    return decorator

class TcpTracer(object):
    def __init__(self):
        self.flows = {}
        self.logger = logging.getLogger('tcptrace')
        self.logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler(sys.stdout)
        self.logger.addHandler(handler)

    @on_state(CS_INIT)
    def action(self, flow, payload, src, sport, dst, dport, flags, seq):
        if not flags & FG_SYN:
            self.logger.warning('Packet from incomplete flow. Ignored.')
            return
        flow = TcpFlow(src, sport, dst, dport, (seq + 1) % 0xffffffff)
        flow.state = CS_INITIATOR_SENT_SYN
        self.flows[src, sport, dst, dport] = flow
        self.new_flow(flow)

    @on_state(CS_INITIATOR_SENT_SYN)
    def actin(self, flow, payload, src, sport, dst, dport, flags, seq):
        if flow.tup == (dst, dport, src, sport):
            if flags & FG_SYN and flags & FG_ACK:
                flow.state = CS_SYN_ACKED
                flow.seq1 = (seq + 1) % 0xffffffff
                self.logger.debug('SYN ACKED')
            else:
                self.logger.debug('Expected SYN ACK. Ignored.')

    @on_state(CS_SYN_ACKED)
    def action(self, flow, payload, src, sport, dst, dport, flags, seq):
        if flow.tup == (src, sport, dst, dport):
            if flags & FG_ACK:
                flow.state = CS_CONNECTED
                self.logger.debug('Connection established.')

                if len(payload) > 0:
                    self.add_segment(flow, 0, payload, seq)

    @on_state(CS_CONNECTED)
    def action(self, flow, payload, src, sport, dst, dport, flags, seq):
        if flags & FG_RST:
            self.flow_closed(flow)
            del self.flows[flow.tup]
            self.logger.warning('Connection RESET.')
            return

        if flags & FG_FIN:
            if (src, sport, dst, dport) == flow.tup:
                flow.state = CS_INITIATOR_SENT_FIN
                flow.seq0 = (flow.seq0 + 1) % 0xffffffff
                self.logger.debug('Initiator sent FIN.')
            else:
                flow.state = CS_ACCEPTER_SENT_FIN
                flow.seq1 = (flow.seq1 + 1) % 0xffffffff
                self.logger.debug('Accepter sent FIN.')
            return

        if (src, sport, dst, dport) == flow.tup:
            self.add_segment(flow, 0, payload, seq)
        elif (dst, dport, src, sport) == flow.tup:
            self.add_segment(flow, 1, payload, seq)
        else:
            self.logger.warning('Something bad has happened!')

    @on_state(CS_INITIATOR_SENT_FIN)
    def action(self, flow, payload, src, sport, dst, dport, flags, seq):
        if flow.tup == (dst, dport, src, sport) and flags & FG_ACK:
            if flags & FG_FIN:
                flow.state = CS_BOTH_SENT_FIN_INITIATOR_ACKED
                flow.seq1 = (flow.seq1 + 1) % 0xffffffff
                self.logger.debug('Both sent FIN and initiator\'s was acked.')
            else:
                flow.state = CS_INITIATOR_FIN_ACKED
                self.logger.debug('Initiator FIN acked.')

    @on_state(CS_ACCEPTER_SENT_FIN)
    def action(self, flow, payload, src, sport, dst, dport, flags, seq):
        if flow.tup == (src, sport, dst, dport) and flags & FG_ACK:
            if flags & FG_FIN:
                flow.state = CS_BOTH_SENT_FIN_ACCEPTER_ACKED
                flow.seq0 = (flow.seq0 + 1) % 0xffffffff
                self.logger.debug('Both sent FIN and accepter\'s was acked.')
            else:
                flow.state = CS_ACCEPTER_FIN_ACKED
                self.logger.debug('Accepter FIN acked.')

    @on_state(CS_INITIATOR_FIN_ACKED)
    def action(self, flow, payload, src, sport, dst, dport, seq):
        if flow.tup == (dst, dport, src, sport) and flags & FG_FIN:
            flow.state = CS_BOTH_SENT_FIN_INITIATOR_ACKED
            flow.seq1 = (flow.seq1 + 1) % 0xffffffff
            self.logger.debug('Both sent FIN and initiator\'s was acked.')

    @on_state(CS_ACCEPTER_FIN_ACKED)
    def action(self, flow, payload, src, sport, dst, dport, flags, seq):
        if flow.tup == (src, sport, dst, dport):
            flow.state = CS_BOTH_SENT_FIN_ACCEPTER_ACKED
            flow.seq0 = (flow.seq0 + 1) % 0xffffffff
            self.logger.debug('Both sent FIN and accepter\'s was acked.')

    @on_state(CS_BOTH_SENT_FIN_INITIATOR_ACKED)
    def action(self, flow, payload, src, sport, dst, dport, flags, seq):
        if (dst, dport, src, sport) != flow.tup:
            return

        if not flags & FG_ACK:
            return

        if seq != flow.seq1:
            return

        if len(flow.pending) > 0:
            flow.state = CS_PENDING_CLOSE
        else:
            self.flow_closed(flow)
            del self.flows[flow.tup]
            self.logger.info('Flow closed.')

    @on_state(CS_INITIATOR_SENT_FIN)
    def action(self, flow, payload, src, sport, dst, dport, flags, seq):
        if (dst, dport, src, sport) == flow.tup and flags & FG_FIN:
            flow.state = CS_BOTH_SENT_FIN
            flow.seq1 = (flow.seq1 + 1) % 0xffffffff
            self.logger.debug('Both sent FIN.')

    @on_state(CS_BOTH_SENT_FIN)
    def action(self, flow, payload, src, sport, dst, dport, flags, seq):
        if not flags & FG_ACK:
            return

        if (src, sport, dst, dport) == flow.tup:
            flow.state = CS_BOTH_SENT_FIN_INITIATOR_ACKED
            self.logger.error('Both sent FIN and initiator\'s was acked.')
        elif (dst, dport, src, sport) == flow.tup:
            flow.state = CS_BOTH_SENT_FIN_ACCEPTER_ACKED
            self.logger.error('Both sent FIN and accepter\'s was acked.')
        else:
            self.logger.error('Something wicked has happened!')

    @on_state(CS_BOTH_SENT_FIN_ACCEPTER_ACKED)
    def action(self, flow, payload, src, sport, dst, dport, flags, seq):
        if (src, sport, dst, dport) != flow.tup:
            return

        if not flags & FG_ACK:
            return

        if seq != flow.seq0:
            return

        if len(flow.pending) > 0:
            flow.state = CS_PENDING_CLOSE
        else:
            self.flow_closed(flow)
            del self.flows[flow.tup]
            self.logger.info('Flow closed.')

    @on_state(CS_PENDING_CLOSE)
    def action(self, flow, payload, src, sport, dst, dport, flags, seq):
        if (src, sport, dst, dport) == flow.tup:
            self.add_segment(flow, 0, payload, seq)
        elif (dst, dport, src, sport) == flow.tup:
            self.add_segment(flow, 1, payload, seq)
        if len(flow.pending) == 0:
            self.flow_closed(flow)
            del self.flows[flow.tup]
            self.logger.info('Flow closed.')

    def trace(self, pkt):
        assert isinstance(pkt[0], Ether) and \
            isinstance(pkt[1], IP) and \
            isinstance(pkt[2], TCP)

        src = pkt[1].src
        dst = pkt[1].dst
        sport = pkt[2].sport
        dport = pkt[2].dport
        try:
            payload = str(pkt[3])
        except IndexError:
            payload = ''

        seq = pkt[2].seq
        flags = pkt[2].flags

        flow = self.flows.get((src, sport, dst, dport), None)
        if not flow:
            flow = self.flows.get((dst, dport, src, sport), None)

        try:
            if flow:
                state_machine[flow.state](
                    self, flow, payload, src, sport, dst, dport, flags, seq)
            else:
                state_machine[CS_INIT](
                    self, flow, payload, src, sport, dst, dport, flags, seq)
        except KeyError as e:
            self.logger.debug(
                'State not found in the state machine: state={} flags={} existing={}'.format(
                    flow.state if flow else CS_INIT, flags, flow != None))

    def add_segment(self, flow, direction, payload, seq):
        if len(payload) == 0:
            return

        fseq = flow.seq0 if direction == 0 else flow.seq1
        if seq == fseq:
            self.new_segment(flow, direction, payload)

            if direction == 0:
                flow.seq0 = (flow.seq0 + len(payload)) % 0xffffffff
            else:
                flow.seq1 = (flow.seq1 + len(payload)) % 0xffffffff

            self.logger.info('New segment arrived from the {}.'.format(
                'initiator' if direction == 0 else 'accepter'))
        elif seq > fseq:
            flow.pending.append((payload, seq, direction))
            self.logger.debug('Out of order packet. Added to pending list.')
            print seq, fseq
        else: # seq < fseq
            self.logger.debug('Duplicate packet. Ignored.')

        added_some = True
        removed = []
        while added_some:
            added_some = False
            i = 0
            for payload, seq, direction in flow.pending:
                if direction == 0:
                    if seq == flow.seq0:
                        self.new_segment(flow, direction, payload)
                        self.logger.info('Pending segment added: {} byte(s)'.format(len(payload)))
                        flow.seq0 = (flow.seq0 + len(payload)) % 0xffffffff
                        added_some = True
                        removed.append(i)
                else:
                    if seq == flow.seq1:
                        self.new_segment(flow, direction, payload)
                        self.logger.info('Pending segment added: {} byte(s)'.format(len(payload)))
                        flow.seq1 = (flow.seq1 + len(payload)) % 0xffffffff
                        added_some = True
                        removed.append(i)
                i += 1

        flow.pending = [i for j, i in enumerate(flow.pending) if j not in flow.pending]

    def trace_pcap(self, pcap_file):
        reader = RawPcapReader(pcap_file)
        i = 1
        for pkt_data in reader:
            self.logger.info('{}'.format(i))
            i += 1
            p = Ether(pkt_data[0])
            if isinstance(p[1], IP) and isinstance(p[2], TCP):
                tracer.trace(p)

class MyTcpTracer(TcpTracer):
    def __init__(self):
        TcpTracer.__init__(self)

        self.added = 0
        self.closed = 0
        self.segments = 0
        self.data = 0

        self.filenames = {}

    def new_flow(self, flow):
        self.logger.info('New flow.')
        self.added += 1

    def new_segment(self, flow, direction, segment):
        self.segments += 1
        self.data += len(segment)
        self.logger.info('{} byte(s) received.'.format(len(segment)))

        if (flow.tup, direction) in self.filenames:
            filename = self.filenames[flow.tup, direction]
            first_segment = False
        else:
            filename = 'stream-{}-{}-{}-{}-{}'.format(
                direction,
                flow.initiator_ip, flow.initiator_port,
                flow.accepter_ip, flow.accepter_port)
            ext = ''
            n = 1
            while os.path.exists(filename + ext):
                ext = '.{}'.format(n)
                n += 1
            filename += ext
            self.filenames[flow.tup, direction] = filename
            first_segment = True

        with open(filename, 'w' if first_segment else 'a') as f:
            f.write(segment)

    def flow_closed(self, flow):
        self.closed += 1

if __name__ == '__main__':
    import sys

    tracer = MyTcpTracer()
    tracer.trace_pcap(sys.argv[1])
    print 'Added flows:', tracer.added
    print 'Closed flows:', tracer.closed
    print 'Remaining flows:', tracer.added - tracer.closed
    print 'Segments arrived:', tracer.segments
    print 'Total bytes:', tracer.data
    print 'Pending packets:', sum(len(f.pending) for f in tracer.flows.values())
