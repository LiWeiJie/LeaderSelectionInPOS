import argparse
import logging
import sys

import random

from twisted.internet import reactor, task
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol
from twisted.internet.protocol import Factory
from typing import Union, Dict

import src.messages.messages_pb2 as pb
from src.protobufreceiver import ProtobufReceiver
from src.utils.network_utils import set_logging, my_err_back, call_later

from collections import defaultdict

from src.chain.config import chain_config
from base64 import b64encode, b64decode


return_code = 0


class Discovery(ProtobufReceiver):
    """
    this is a discovery server
    """

    def __init__(self, nodes, factory):
        self.nodes = nodes  # type: Dict[str, str]
        self.vk = None
        self.addr = None
        self.state = 'SERVER'
        self.factory = factory  

    def connection_lost(self, reason):
        if self.vk in self.nodes:
            if self.vk in self.factory.member_determined:
                self.factory.member_determined[self.vk] = False
            del self.nodes[self.vk]
            logging.debug("Discovery: deleted {}".format(self.vk))
        
        if self.state == 'CLIENT':
            logging.debug("stop reactor")
            reactor.stop()

    def obj_received(self, obj):
        """
        type: (Union[pb.Discover, pb.DiscoverReply]) -> None

        we don't bother with decoding vk here, since we don't use vk in any crypto functions
        :param obj:
        :return:
        """

        logging.debug("Discovery : received msg {} from {}"
                      .format(obj, self.transport.getPeer().host).replace('\n', ','))

        if self.state == 'SERVER':

            if isinstance(obj, pb.Discover):

                # dreply = pb.DiscoverReply()
                id = self.nodes.__len__()
                # dreply.nodes.extend(self.factory.make_nodes_dict())

                self.vk = obj.vk  # NOTE storing base64 form as is
                self.addr = self.transport.getPeer().host + ":" + str(obj.port)

                member = None

                if self.nodes.__len__() < self.factory.load_member:
                    idx = self.nodes.__len__()
                    # member = self.factory.pre_members[idx]
                    member = chain_config.get_member_by_idx(idx)
                    vk = b64encode(member.verify_key_str)
                    if self.factory.member_determined[vk] is False:
                        logging.info("Discovery: set a member {}".format(idx))
                        self.factory.member_determined[vk] = True
                        self.vk = vk
                        # self.send_obj(member.pb)
                        # dreply.member.CopyFrom(member.pb)

                    # self.factory.lc = task.LoopingCall(self.factory.send_instruction_when_ready)
                    # self.factory.lc.start(5).addErrback(my_err_back)

                # TODO check addr to be in the form host:port
                if self.vk not in self.nodes:
                    logging.debug("Discovery: added node {} {}".format(self.vk, self.addr))
                    self.nodes[self.vk] = (self.addr, self)
                    logging.debug("Discovery: connected nodes {}".format(self.nodes.__len__()))

                assert isinstance(self.factory, DiscoveryFactory)
                # dreply.nodes = self.factory.make_nodes_dict()
                self.send_obj(pb.DiscoverReply(nodes=self.factory.make_nodes_dict(), id=id, member=member.pb))

            else:
                raise AssertionError("Discovery: invalid payload type on SERVER")

        elif self.state == 'CLIENT':
            if isinstance(obj, pb.DiscoverReply):
                

                from src.utils.encode_utils import b64e
                logger = logging.getLogger()
                log_path = self.factory.config.output_dir + '/' + str(obj.id)  +'.log'
                fh = logging.FileHandler(log_path, "w")
                formatter = logging.Formatter('%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s')  
                fh.setFormatter(formatter)  
                logger.addHandler(fh)  

                logging.debug("Discovery: making new clients...")
                logging.debug("peers: {}".format([ b64encode(s[0]) for s in self.factory.peers.items()]))
                logging.debug("received peers: {}".format([ (s[0]) for s in obj.nodes.items()]))

                if obj.member.sk_str != "":
                    self.factory.change_member(obj.member)

                point = TCP4ClientEndpoint(reactor, "localhost", self.factory.config.port, timeout=90)
                from src.node import MyProto
                d = connectProtocol(point, MyProto(self.factory))
                from src.node import got_protocol
                d.addCallback(got_protocol).addErrback(my_err_back)

                self.factory.new_connection_if_not_exist(obj.nodes)

            elif isinstance(obj, pb.Instruction):
                self.factory.handle_instruction(obj)

            elif isinstance(obj, pb.Member):
                self.factory.change_member(obj)

            else:
                raise AssertionError("Discovery: invalid payload type on CLIENT")

    def say_hello(self, vk, port):
        self.state = 'CLIENT'
        self.send_obj(pb.Discover(vk=vk, port=port))
        logging.debug("Discovery: discovery sent {} {}".format(vk, port))


class DiscoveryFactory(Factory):
    def __init__(self, n, t, m, inst, load_member, fan_out=0):
        self.nodes = {}  # key = vk, val = addr
        self.timeout_called = False
        self.load_member = load_member
        self.member_determined = defaultdict(bool)
        self.fan_out = fan_out
        # self.pre_members = chain_config.get_members(load_member)

        import time
        logging.debug("Create a discoveryFactory at {}".format(time.time()))

        def has_sufficient_instruction_params():
            return n is not None and \
                   t is not None and \
                   m is not None and \
                   inst is not None and \
                   len(inst) >= 2

        if has_sufficient_instruction_params():
            logging.info("Sufficient params to send instructions")
            self.n = n
            self.t = t
            self.m = m

            self.inst_delay = int(inst[0])
            self.inst_inst = inst[1]
            self.inst_param = None if len(inst) < 3 else inst[2]

            self.lc = task.LoopingCall(self.send_instruction_when_ready)
            self.lc.start(5).addErrback(my_err_back)

            self.sent = False

        else:
            logging.info("Insufficient params to send instructions")

    def make_nodes_dict(self):
        if self.fan_out==0:
            msg = {k: v[0] for k, v in self.nodes.iteritems()}
            return msg

        else:
            fan_out = min(self.fan_out, len(self.nodes.keys()))
            msg = random.sample(self.nodes.keys(), fan_out)
            msg = {k: self.nodes[k][0] for k in msg}
            return msg

    def send_instruction_when_ready(self):

        # if at least 1 node started, then all should start within 120 seconds
        # otherwise exit 1
        if len(self.nodes) > 0:
            def stop_and_ret():
                if not self.sent:
                    global return_code
                    return_code = 1
                    reactor.stop()
            if not self.timeout_called:
                logging.info("Timeout start")
                call_later(120, stop_and_ret)
                self.timeout_called = True

        if len(self.nodes) >= self.m:
            msg = pb.Instruction(instruction=self.inst_inst, delay=self.inst_delay, param=self.inst_param)
            logging.debug("Broadcasting instruction - {}".format(msg).replace('\n', ','))
            self.bcast(msg)
            self.lc.stop()
            self.sent = True
        else:
            logging.debug("Instruction not ready ({} / {})...".format(len(self.nodes), self.m))

    def buildProtocol(self, addr):
        return Discovery(self.nodes, self)

    def bcast(self, msg):
        for k, v in self.nodes.iteritems():
            proto = v[1]
            proto.send_obj(msg)


def got_discovery(p, id, port):
    p.say_hello(id, port)


def run(port, n, t, m, inst, load_member, fan_out):
    f = DiscoveryFactory(n, t, m, inst, load_member, fan_out)
    reactor.listenTCP(port, f)
    logging.info("Discovery server running on {}".format(port))
    reactor.run()
    return f


# def run_in_terminal(port=8123, n=10, t=2, m=10, inst=[2, 'boostrap-only', 2], load_member=10):
#     return run(port, n, t, m, inst, load_member)

# python -m src.discovery -n $n -t $t -m $GUMBY_das4_instances_to_run --inst $delay $experiment $param"
if __name__ == '__main__':
    set_logging(logging.DEBUG)

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--port',
        type=int, help='the listener port, default 8123',
        default=8123,
    )
    parser.add_argument(
        '-n',
        type=int, help='the total number of senates',
        nargs='?'
    )
    parser.add_argument(
        '-t',
        type=int, help='the total number of malicious nodes, to be implemented',
        nargs='?'
    )
    parser.add_argument(
        '-m',
        type=int, help='the total number of nodes',
        nargs='?'
    )
    parser.add_argument(
        '--inst',
        metavar='INST',
        help='the instruction to send after all nodes are connected',
        nargs='*'
    )
    parser.add_argument(
        '-l', '--load_member',
        type=int,
        help="the first n node will load the member file",
        default=0,
    )
    parser.add_argument(
        '--output_dir',
        help='output dir',
        default='log',
        dest='output_dir',
    )
    parser.add_argument(
        '--fan-out',
        type=int,
        default=0,
        help='fan-out parameter for gossiping'
    )
    args = parser.parse_args()

    if args.output_dir:
        # logging.basicConfig(level=logging.DEBUG,
        #                     format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
        #                     datefmt='%a, %d %b %Y %H:%M:%S',
        #                     filename= args.output_dir + '/discovery.log',
        #                     filemode='w')
        logger = logging.getLogger()
        log_path = args.output_dir + '/discovery.log'
        fh = logging.FileHandler(log_path, "w")
        formatter = logging.Formatter('%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s')
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    logging.info("sys argv: {}".format(sys.argv))



    # NOTE: n, t, m and inst must be all or nothing
    run(args.port, args.n, args.t, args.m, args.inst, args.load_member, args.fan_out)
    sys.exit(return_code)
