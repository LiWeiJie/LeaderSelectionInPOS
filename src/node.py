import Queue
import argparse
import logging
import random
import sys
import json
from collections import defaultdict
from base64 import b64encode, b64decode

from twisted.internet import reactor, task, error
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol
from twisted.internet.protocol import Factory
from typing import Dict, Tuple

import src.messages.messages_pb2 as pb
from src.protobufreceiver import ProtobufReceiver

from chain.client import Client as ChainRunner
from src.utils.network_utils import Replay, Handled, set_logging, my_err_back, call_later, stop_reactor
from src.discovery import Discovery, got_discovery

from src.chain.config import chain_config

from src.utils.hash_utils import hash_once

class MyProto(ProtobufReceiver):
    """
    Main protocol that handles the Byzantine consensus, one instance is created for each connection
    """
    def __init__(self, factory):
        # type: (MyFactory) -> None
        self.factory = factory
        self.config = factory.config
        self.vk = factory.vk
        self.peers = factory.peers
        self.remote_vk = None
        self.state = 'SERVER'

    def connection_lost(self, reason):
        """
        We don't try to test churn for this experiment, so there's no reason to continue running the node when some.
        If a node is deleted, it means either some error occurred, or the experiment is completed.
        Thus we stop the current reactor too.
        :param reason: 
        :return: 
        """
        peer = "<None>" if self.remote_vk is None else b64encode(self.remote_vk)

        if not self.factory.first_disconnect_logged:
            logging.info("NODE: deleting peer {}, reason {}".format(peer, reason))
            self.factory.first_disconnect_logged = True
        else:
            logging.debug("NODE: deleting peer {}, reason {}".format(peer, reason))

        try:
            del self.peers[self.remote_vk]
        except KeyError:
            logging.warning("NODE: peer {} already deleted".format(b64encode(self.remote_vk)))

        stop_reactor()

    def obj_received(self, obj):
        """
        first we handle the items in the queue
        then we handle the received message
        :param obj:
        :return:
        """

        # TODO do something like handler registry

        if isinstance(obj, pb.Ping):
            self.handle_ping(obj)

        elif isinstance(obj, pb.Pong):
            self.handle_pong(obj)

        elif isinstance(obj, pb.DirectorCompetition):
            self.factory.chain_runner.handle_director_competition(obj, self.remote_vk)

        elif isinstance(obj, pb.TransactionSummit):
            self.factory.chain_runner.handle_transaction_summit(obj, self.remote_vk)

        elif isinstance(obj, pb.ConsensusReq):
            # TODO: should delay to consensus machine
            self.factory.chain_runner.handle_consensus_result(pb.ConsensusResult(block=obj.block), self.remote_vk)

        elif isinstance(obj, pb.SenateSignature):
            self.factory.chain_runner.handle_senate_signature(obj, self.remote_vk)

        # elif isinstance(obj, pb.DirectorShowTime):
        #     self.factory.chain_runner.handle_director_show_time(obj, self.remote_vk)

        elif isinstance(obj, pb.Block):
            self.factory.chain_runner.handle_block(obj, self.remote_vk)

        elif isinstance(obj, pb.Gossip):
            self.handle_gossip(obj)

        # old

        # elif isinstance(obj, pb.ACS):
        #     if self.factory.config.failure != 'omission':
        #         res = self.factory.acs.handle(obj, self.remote_vk)
        #         self.process_acs_res(res, obj)
        #
        # elif isinstance(obj, pb.TxReq):
        #     self.factory.tc_runner.handle_tx_req(obj, self.remote_vk)
        #
        # elif isinstance(obj, pb.TxResp):
        #     self.factory.tc_runner.handle_tx_resp(obj, self.remote_vk)
        #
        # elif isinstance(obj, pb.ValidationReq):
        #     self.factory.tc_runner.handle_validation_req(obj, self.remote_vk)
        #
        # elif isinstance(obj, pb.ValidationResp):
        #     self.factory.tc_runner.handle_validation_resp(obj, self.remote_vk)
        #
        # elif isinstance(obj, pb.SigWithRound):
        #     self.factory.tc_runner.handle_sig(obj, self.remote_vk)
        #
        # elif isinstance(obj, pb.CpBlock):
        #     self.factory.tc_runner.handle_cp(obj, self.remote_vk)
        #
        # elif isinstance(obj, pb.Cons):
        #     self.factory.tc_runner.handle_cons(obj, self.remote_vk)
        #
        # elif isinstance(obj, pb.AskCons):
        #     self.factory.tc_runner.handle_ask_cons(obj, self.remote_vk)

        # NOTE messages below are for testing, bracha/mo14 is normally handled by acs


        elif isinstance(obj, pb.Dummy):
            logging.info("NODE: got dummy message from {}".format(b64encode(self.remote_vk)))

        else:
            raise AssertionError("invalid message type {}".format(obj))

        self.factory.recv_message_log[obj.__class__.__name__] += obj.ByteSize()

    def send_obj(self, obj):
        """
        Wrapper around ProtobufReceiver.send_obj for logging
        :param obj:
        :return:
        """
        ProtobufReceiver.send_obj(self, obj)
        self.factory.sent_message_log[obj.__class__.__name__] += obj.ByteSize()

    # def process_acs_res(self, o, m):
    #     """
    #     This function checks whether the result is Replay or Handled.
    #     If it's the former, the message is placed into factory.q and then we replay it (factory.process_queue).
    #     :param o: the object we're processing
    #     :param m: the original message
    #     :return:
    #     """
    #     assert o is not None

    #     if isinstance(o, Replay):
    #         logging.debug("NODE: putting {} into msg queue".format(m))
    #         self.factory.q.put((self.remote_vk, m))
    #     elif isinstance(o, Handled):
    #         if self.factory.config.test == 'acs':
    #             logging.debug("NODE: testing ACS, not handling the result")
    #             return
    #         if o.m is not None:
    #             logging.debug("NODE: attempting to handle ACS result")
    #             self.factory.tc_runner.handle_cons_from_acs(o.m)
    #     else:
    #         raise AssertionError("instance is not Replay or Handled")

    def send_ping(self):
        self.send_obj(pb.Ping(vk=self.vk, port=self.config.port))
        logging.debug("NODE: sent ping")
        self.state = 'CLIENT'

    def handle_ping(self, msg):
        # type: (pb.Ping) -> None
        logging.debug("NODE: got ping, vk:{}".format(b64encode(msg.vk)))
        assert (self.state == 'SERVER')
        if msg.vk in self.peers.keys():
            logging.debug("NODE: ping found myself in peers.keys")
        self.peers[msg.vk] = (self.transport.getPeer().host, msg.port, self)
        self.remote_vk = msg.vk
        self.send_obj(pb.Pong(vk=self.vk, port=self.config.port))
        logging.debug("sent pong")

    def handle_pong(self, msg):
        # type: (pb.Pong) -> None
        logging.debug("NODE: got pong, vk:{}".format(b64encode(msg.vk)))
        assert (self.state == 'CLIENT')
        if msg.vk in self.peers.keys():
            logging.debug("NODE: pong: found myself in peers.keys")
            # self.transport.loseConnection()
        self.peers[msg.vk] = (self.transport.getPeer().host, msg.port, self)
        self.remote_vk = msg.vk
        logging.debug("NODE: done pong")

    def handle_gossip(self, msg):
        logging.debug("NODE: got gossip")
        assert isinstance(msg, pb.Gossip)
        true_msg = msg.body
        hv = hash_once(true_msg)
        if self.factory.gossip_dict[hv] == 0:
            self.factory.gossip_dict[hv] = 1
            obj = self.unpack_string(true_msg)
            assert not isinstance(obj, pb.Gossip)
            self.stringReceived(true_msg)
            self.factory.gossip_except(self.vk, msg)
        else:
            logging.info("Node: already handle gossip")

class MyFactory(Factory):
    """
    The Twisted Factory with a broadcast functionality, should be singleton
    """
    def __init__(self, config):
        # type: (Config) -> None
        self.peers = {}  # type: Dict[str, Tuple[str, int, MyProto]]
        self.promoters = []
        self.config = config

        # self.tc_runner = TrustChainRunner(self)
        self.chain_runner = ChainRunner(factory=self, senates_number=config.n, blocks_path=config.chain)
        self.vk = self.chain_runner.member.verify_key_str
        self.q = Queue.Queue()  # (str, msg)
        self.first_disconnect_logged = False

        self._neighbour = None
        self._sorted_peer_keys = None

        # start looping call on the queue
        self.lc = task.LoopingCall(self.process_queue)
        self.lc.start(1).addErrback(my_err_back)

        # logging message size
        self.recv_message_log = defaultdict(long)
        self.sent_message_log = defaultdict(long)

        # Gossip dict
        self.gossip_dict = defaultdict(int)

        # TODO output this at the end of every round
        task.LoopingCall(self.log_communication_costs).start(5, False).addErrback(my_err_back)

    def log_communication_costs(self, heading="NODE:"):
        logging.info('{} messages info {{ "sent": {}, "recv": {} }}'
                     .format(heading, json.dumps(self.sent_message_log), json.dumps(self.recv_message_log)))

    def process_queue(self):
        # we use counter to stop this routine from running forever,
        # because self.json_received can put item back into the queue
        logging.debug("NODE: processing queue, size {}".format(self.q.qsize()))
        qsize = self.q.qsize()
        ctr = 0
        while ctr < qsize:
            ctr += 1
            node, m = self.q.get()
            self.peers[node][2].obj_received(m)

    def buildProtocol(self, addr):
        return MyProto(self)

    def new_connection_if_not_exist(self, nodes):
        # logging.info("NODE: peers {}".format(self.peers.items()))
        for _vk, addr in nodes.iteritems():
            vk = b64decode(_vk)
            if vk not in self.peers.keys() and vk != self.vk:
                host, port = addr.split(":")
                self.make_new_connection(host, int(port))
            else:
                logging.debug("NODE: client {},{} already exist".format(b64encode(vk), addr))

    def make_new_connection(self, host, port):
        logging.debug("NODE: making client connection {}:{}".format(host, port))
        point = TCP4ClientEndpoint(reactor, host, port, timeout=90)
        proto = MyProto(self)
        d = connectProtocol(point, proto)
        d.addCallback(got_protocol).addErrback(my_err_back)

    def change_member(self, member):
        logging.warn("NODE: changing member id")
        # port = self.peers[self.vk][1]
        self.peers.clear()
        self.chain_runner.change_member(member)
        self.vk = self.chain_runner.member.verify_key_str

        # # connect to myself
        # point = TCP4ClientEndpoint(reactor, "localhost", self.config.port, timeout=90)
        # d = connectProtocol(point, MyProto(self))
        # d.addCallback(got_protocol).addErrback(my_err_back)

    def bcast(self, msg):
        """
        Broadcast a message to all nodes in self.peers, the list should include myself
        :param msg:
        :return:
        """
        for k, v in self.peers.iteritems():
            proto = v[2]
            proto.send_obj(msg)

    def promoter_cast(self, msg):
        for promoter in self.promoters:
            self.send(promoter, msg)

    def promoter_cast_t(self, msg):
        for promoter in random.sample(self.promoters, self.config.t + 1):
            self.send(promoter, msg)

    def non_promoter_cast(self, msg):
        for node in set(self.peers.keys()) - set(self.promoters):
            self.send(node, msg)

    def _gossip(self, nodes, gossip_obj):
        assert isinstance(gossip_obj, pb.Gossip)
        for node in nodes:
            self.send(node, gossip_obj)

    def gossip(self, msg):
        """
        Receivers of the gossiped currently needs to manually decide whether it wants to forward it.
        TODO create a special gossip message type and do the gossiping/forwarding on the base class.
        :param msg: 
        :return: 
        """
        fan_out = min(self.config.fan_out, len(self.peers.keys()))
        gossip_obj = msg
        if not isinstance(msg, pb.Gossip):
            msg = ProtobufReceiver.pack_obj(msg)
            gossip_obj = pb.Gossip(body=msg)
        nodes = random.sample(self.peers.keys(), fan_out)
        self._gossip(nodes=nodes, gossip_obj=gossip_obj)

    def gossip_except(self, exception, msg):
        new_set = set(self.peers.keys()) - set(exception)
        fan_out = min(self.config.fan_out, len(new_set))
        nodes = random.sample(new_set, fan_out)
        gossip_obj = msg
        if not isinstance(msg, pb.Gossip):
            msg = ProtobufReceiver.pack_obj(msg)
            gossip_obj = pb.Gossip(body=msg)
        self._gossip(nodes=nodes, gossip_obj=gossip_obj)

    def multicast(self, nodes, msg):
        for node in nodes:
            self.send(node, msg)

    def send(self, node, msg):
        proto = self.peers[node][2]
        proto.send_obj(msg)

    def send_gossip(self, node, msg):
        proto = self.peers[node][2]
        proto.send_gossip(msg)

    @property
    def random_node(self):
        node = random.choice(self.peers.keys())
        while node == self.vk:
            node = random.choice(self.peers.keys())
        return node

    @property
    def neighbour(self):
        """
        Expect all peers to be connected, return the verification key of the node that's after me, or loop back
        :return: 
        """
        if self._neighbour is None:
            my_idx = self.sorted_peer_keys.index(self.vk)
            self._neighbour = self.sorted_peer_keys[(my_idx + 1) % len(self.sorted_peer_keys)]
        return self._neighbour

    def get_n_neighbour(self, n):
        my_idx = self.sorted_peer_keys.index(self.vk)
        double_sorted_peer_keys = None
        if hasattr(self, '_double_sorted_peer_keys'):
            double_sorted_peer_keys = self._double_sorted_peer_keys
        if double_sorted_peer_keys is None:
            double_sorted_peer_keys = []
            double_sorted_peer_keys.extend(self.sorted_peer_keys)
            double_sorted_peer_keys.extend(self.sorted_peer_keys)
            self._double_sorted_peer_keys = double_sorted_peer_keys
        my_idx += 1
        return double_sorted_peer_keys[my_idx:my_idx+n]


    @property
    def sorted_peer_keys(self):
        if self._sorted_peer_keys is None:
            self._sorted_peer_keys = sorted(self.peers.keys())
        return self._sorted_peer_keys

    def handle_instruction(self, msg):
        """
        The msg.delay need to be long enough such that the ping/pong messages are finished
        :param msg: 
        :return: 
        """
        assert isinstance(msg, pb.Instruction)
        logging.info("NODE: handling instruction - {}".format(msg).replace('\n', ','))
        self.config.from_instruction = True

        call_later(msg.delay, self.chain_runner.start)

        if msg.instruction == 'bootstrap-only':
            self.chain_runner.make_tx(True)

        elif msg.instruction == 'tx-rate':
            rate = float(msg.param)
            interval = 1.0 / rate
            call_later(msg.delay, self.chain_runner.make_tx, interval, 1, False)

        elif msg.instruction == 'tx-rate-random':
            rate = float(msg.param)
            interval = 1.0 / rate
            call_later(msg.delay, self.chain_runner.make_tx, interval, 1, True)

        elif msg.instruction == 'tx-n-outputs':
            outputs = int(msg.param)
            interval = self.chain_runner.prepare_timeout-0.5
            call_later(msg.delay, self.chain_runner.make_tx, interval, outputs, False)

        # elif msg.instruction == 'tx-n-outputs-random':
        #     outputs = int(msg.param)
        #     interval = self.chain_runner.prepare_timeout-0.5
        #     call_later(msg.delay, self.chain_runner.make_tx, interval, outputs, True)

        else:
            raise AssertionError("Invalid instruction msg {}".format(msg))


def got_protocol(p):
    # this needs to be lower than the deferLater in `run`
    call_later(1, p.send_ping)


class Config(object):
    """
    All the static settings, used in Factory
    Should be singleton
    """
    def __init__(self, port, n, t, population, fan_out, 
                 ignore_promoter, chain, output_dir):
        """
        This only stores the config necessary at runtime, so not necessarily all the information from argparse
        :param port:
        :param n:
        :param t:
        :param population:
        """
        self.port = port
        self.n = n
        self.t = t

        self.chain = chain

        self.fan_out = fan_out

        self.ignore_promoter = ignore_promoter

        self.from_instruction = False

        self.population = population

        self.output_dir = output_dir


def simple_run(member = None, n=4, t=0, population=0, port = 0):
    set_logging(logging.DEBUG)

    # logging.basicConfig(level=logging.DEBUG,
    #                 format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
    #                 datefmt='%a, %d %b %Y %H:%M:%S',
    #                 filename='log/default.log',
    #                 filemode='w')
    
    discovery = 'localhost'
    fan_out = 10
    ignore_promoter = False
    return run(Config(port, n, t, population,
                fan_out, ignore_promoter, chain_config.chain_genic_path, 'log'),
           discovery)

def run(config, discovery_addr):
    f = MyFactory(config)

    try:
        port = reactor.listenTCP(config.port, f)
        config.port = port.getHost().port
    except error.CannotListenError:
        logging.error("cannot listen on {}".format(config.port))
        sys.exit(1)

    # connect to discovery server
    point = TCP4ClientEndpoint(reactor, discovery_addr, 8123, timeout=90)
    d = connectProtocol(point, Discovery({}, f))
    d.addCallback(got_discovery, b64encode(f.vk), config.port).addErrback(my_err_back)

    # # connect to myself
    # point = TCP4ClientEndpoint(reactor, "localhost", config.port, timeout=90)
    # d = connectProtocol(point, MyProto(f))
    # d.addCallback(got_protocol).addErrback(my_err_back)

    # connect to myself
    # def connect_to_myself():
    #     point = TCP4ClientEndpoint(reactor, "localhost", config.port, timeout=90)
    #     d = connectProtocol(point, MyProto(f))
    #     d.addCallback(got_protocol).addErrback(my_err_back)
    # connect_to_myself()
    # call_later(1, connect_to_myself)

    logging.info("NODE: reactor starting on port {}".format(config.port))
    reactor.run()
    return f

# python -m src.node 0 10 3 10 -d --fan-out 10 --ignore-promoter
# python -m src.node 0 $n $t $GUMBY_das4_instances_to_run -d --discovery $(hostname) --fan-out 10 --ignore-promoter $profile"
if __name__ == '__main__':
    # simple_run()
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'port',
        type=int,
        help='the listener port'
    )
    parser.add_argument(
        'n',
        type=int,
        help='the total number of promoters'
    )
    parser.add_argument(
        't',
        type=int,
        help='the total number of malicious nodes'
    )
    parser.add_argument(
        'population',
        type=int,
        help='the population size',
    )
    parser.add_argument(
        '-d', '--debug',
        help="log at debug level",
        action="store_const", dest="loglevel", const=logging.DEBUG,
        default=logging.WARNING
    )
    parser.add_argument(
        '-v', '--verbose',
        help="log at info level",
        action="store_const", dest="loglevel", const=logging.INFO
    )
    parser.add_argument(
        "-o", "--output",
        type=argparse.FileType('w'),
        metavar='NAME',

        help="location for the output file"
    )
    parser.add_argument(
        '--discovery',
        metavar='ADDR',
        default='localhost',
        help='address of the discovery server on port 8123'
    )
    parser.add_argument(
        '--fan-out',
        type=int,
        default=10,
        help='fan-out parameter for gossiping'
    )
    parser.add_argument(
        '--ignore-promoter',
        action='store_true',
        help='do not transact with promoters'
    )
    parser.add_argument(
        '--profile',
        metavar='NAME',
        help='run the node with cProfile'
    )
    parser.add_argument(
        '--timeout',
        help='force exit after timeout, 0 means continue forever',
        default=0,
        type=int
    )
    parser.add_argument(
        '--chain',
        help='the initial chain path',
        default='genic',
        dest='chain'
    )
    parser.add_argument(
        '--output_dir',
        help='output dir',
        default='log',
        dest='output_dir',
    )
    args = parser.parse_args()

    if args.chain == 'genic':
        args.chain = chain_config.chain_genic_path
    elif args.chain=='10_rich_man':
        args.chain = chain_config.chain_10_rich_man_path
    elif args.chain == '100_rich_man':
        args.chain = chain_config.chain_100_rich_man_path

    set_logging(args.loglevel, args.output)

    def _run():
        run(Config(args.port, args.n, args.t, args.population,
                   args.fan_out,  args.ignore_promoter, args.chain, args.output_dir),
            args.discovery)

    if args.timeout != 0:
        call_later(args.timeout, stop_reactor)

    if args.profile:
        import cProfile
        cProfile.run('_run()', args.profile)
    else:
        _run()

