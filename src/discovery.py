import argparse
import logging
import sys

from twisted.internet import reactor, task
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
    this is both a discovery server and a coin server, the latter is not implemented yet
    """

    def __init__(self, nodes, factory):
        self.nodes = nodes  # type: Dict[str, str]
        self.vk = None
        self.addr = None
        self.state = 'SERVER'
        self.factory = factory  # this changes depending on whether it's a server or client

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
        # type: (Union[pb.Discover, pb.DiscoverReply]) -> None
        """
        we don't bother with decoding vk here, since we don't use vk in any crypto functions
        :param obj:
        :return:
        """

        logging.debug("Discovery : received msg {} from {}"
                      .format(obj, self.transport.getPeer().host).replace('\n', ','))


        if self.state == 'SERVER':

            if isinstance(obj, pb.Discover):
                self.vk = obj.vk  # NOTE storing base64 form as is
                self.addr = self.transport.getPeer().host + ":" + str(obj.port)

                if self.nodes.__len__() < self.factory.load_member:
                    idx = self.nodes.__len__()
                    member = self.factory.pre_members[idx]
                    vk = b64encode(member.verify_key_str)
                    if self.factory.member_determined[vk] is False:
                        logging.info("Discovery: set a member {}".format(idx))
                        self.factory.member_determined[vk] = True
                        self.vk = vk
                        self.send_obj(member.pb)

                # TODO check addr to be in the form host:port
                if self.vk not in self.nodes:
                    logging.debug("Discovery: added node {} {}".format(self.vk, self.addr))
                    self.nodes[self.vk] = (self.addr, self)
                    logging.debug("Discovery: connected nodes {}".format(self.nodes.__len__()))

                    # self.factory.lc = task.LoopingCall(self.factory.send_instruction_when_ready)
                    # self.factory.lc.start(5).addErrback(my_err_back)

                assert isinstance(self.factory, DiscoveryFactory)
                self.send_obj(pb.DiscoverReply(nodes=self.factory.make_nodes_dict()))

            else:
                raise AssertionError("Discovery: invalid payload type on SERVER")

        elif self.state == 'CLIENT':
            if isinstance(obj, pb.DiscoverReply):
                idx = obj.nodes.__len__()
                # logging.basicConfig(level=logging.DEBUG,
                #     format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                #     datefmt='%a, %d %b %Y %H:%M:%S',
                #     filename='log/'+str(idx)+'.log',
                #     filemode='w')
                logger = logging.getLogger()
                fh = logging.FileHandler('log/'+str(idx)+'.log', "w")
                formatter = logging.Formatter('%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s')  
                fh.setFormatter(formatter)  
                logger.addHandler(fh)  

                logging.debug("Discovery: making new clients...")
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
    def __init__(self, n, t, m, inst, load_member):
        self.nodes = {}  # key = vk, val = addr
        self.timeout_called = False
        self.load_member = load_member
        self.member_determined = defaultdict(bool)
        self.pre_members = chain_config.get_members(load_member)

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
        msg = {k: v[0] for k, v in self.nodes.iteritems()}
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


def run(port, n, t, m, inst, load_member):
    f = DiscoveryFactory(n, t, m, inst, load_member)
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
        type=int, help='the total number of promoters',
        nargs='?'
    )
    parser.add_argument(
        '-t',
        type=int, help='the total number of malicious nodes',
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
    args = parser.parse_args()

    print sys.argv

    # NOTE: n, t, m and inst must be all or nothing
    run(args.port, args.n, args.t, args.m, args.inst, args.load_member)
    sys.exit(return_code)
