#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# client.py ---
#
# @Filename: client.py
# @Description: 
# @Author: Weijie Li
# @Created time: 2018-02-20 15:26:00
# @Last Modified by: 
# @Last Modified time: 

import time
import enum

# Network
import json

# logger system
import logging
import logging.handlers

# public crypto Library
from collections import defaultdict
from ecdsa import SigningKey
from ecdsa import VerifyingKey

# payload
from payload import payload_base

# Model
from .model import member_model
from .model import block_model
from .model import transaction_model
from .model import chain_model
from src.chain.model.transaction_model import TxoIndex

from src.utils import message
from src.utils import hash_utils, random_utils
import src.messages.messages_pb2 as pb

from src.chain.model.member_model import verify

from twisted.internet import task

from src.utils.network_utils import my_err_back, call_later
# from src.utils import set_logging, my_err_back, call_later
from src.chain.config import chain_config
from src.utils.script_utils import script_to_verify_key

from base64 import b64encode


class Client(object):
    ClientStatus = enum.Enum("ClientStatus",
                             ('Sleeping', "Wait4Senates", 'Wait4TxsAndDirector', 'Wait4Consensus', 'Wait4Block'))

    @property
    def status(self):
        return self._status

    @property
    def timestamp(self):
        return self._timestamp

    @property
    def member(self):
        return self._member

    @property
    def leader_serial_number(self):
        # decide who is the senate leader
        return self._leader_serial_number

    @property
    def senates(self):
        return self.chain.senates

    @property
    def senates_leader(self):
        if self._senates_leader is None:
            senates = self.chain.senates
            for senate in senates:
                if self.leader_serial_number in senates[senate]:
                    self._senates_leader = senate
        return self._senates_leader

    @property
    def chain(self):
        return self._chain

    @property
    def rounds(self):
        return self._rounds

    @property
    def last_block(self):
        return self.chain.last_block

    @property
    def pending_transactions(self):
        """ 
        pending_transactions = {
            tx_hash: Transaction,
            ...
        }
        """
        return self._pending_transactions

    @property
    def pend_to_summit_transactions(self):
        """
        {
            tx_hash: Transaction,
            ...
        }
        """
        return self._pend_to_summit_transactions

    @property
    def locking_txo(self):
        return self._locking_txo

    @property
    def my_satoshi(self):
        """
        my_satoshi = {
            (transaction_hash, transaction_idx): Transaction.Output,
            ...
        }
        """
        return self._m_satoshi

    @property
    def my_satoshi_total(self):
        return self._m_satoshi_total

    @property
    def cooking_food(self):
        return self._cooking_food

    @property
    def is_senate(self):
        ledger = self.chain
        senates = ledger.senates
        return self.member.verify_key_str in senates

    @property
    def is_senate_leader(self):
        # senates = self.chain.senates
        # mvs = self.member.verify_key_str
        # if mvs in senates:
        #     if self._leader_serial_number in senates[mvs]:
        #         return True
        # return False
        return self.senates_leader == self.member.verify_key_str

    def __init__(self,
                 member=None,
                 blocks_path=None,
                 consensus_timeout=10,
                 prepare_timeout=5,
                 factory=None,
                 senates_number=chain_config.senates_number,
                 failure_boundary=0):
        """

        :param member: MemberModel or member_path , if None , will generate a random member
        :param blocks_path:
        """

        self.consensus_timeout = consensus_timeout
        self.prepare_timeout = prepare_timeout
        logging.info("prepare time for txs and director in a round: {} secs".format(prepare_timeout))
        logging.info("consensus_timeout for a round: {} secs".format(consensus_timeout))
        self._senates_leader = None

        self.factory = factory
        self.consensus_reached = {}

        self._timestamp = 0
        # decide which senate be the leader
        self._leader_serial_number = 0
        self._status = None
        self.set_client_status(self.ClientStatus.Sleeping)
        self._cooking_food = {}
        self._locking_txo = defaultdict(bool)

        self._chain = chain_model.Chain.new(senates_number=senates_number, failure_boundary=failure_boundary)

        # the pending transactions from others
        self._pending_transactions = {}

        # summit_transaction -> pending_transaction -> block
        self._pend_to_summit_transactions = {}

        if not member:
            member = member_model.MemberModel.new(genkey=True)
        else:
            if not isinstance(member, member_model.MemberModel):
                member_path = member
                member = member_model.MemberModel.new(key_path=member_path)
        assert isinstance(member, member_model.MemberModel), type(member)

        self._member = member

        self._m_satoshi = {}
        self._m_satoshi_total = 0
        if blocks_path:
            bs = block_model.load_blocks(blocks_path)
            chain = self.chain
            chain.set_ledger(bs, None)
            self.listen_block_change(None)

        self._rounds = self.chain.blocks.__len__()

        # logger
        # self._logger = create_logger(member.mid[-5:])

        # init models

        self.initiate_protocol_handler()

    def listen_block_change(self, block):
        if block:
            self.update_pending_transactions(block)
        self.update_my_satoshi()
        self._cooking_food = {}
        self._senates_leader = None
        self._leader_serial_number = 0
        self.pend_to_summit_transactions.clear()
        self.reset_lock_list()

    def reset_lock_list(self):
        print "reset lock list"
        self.locking_txo.clear()

    def lock_txo(self, tx_hash, tx_idx):
        # logging.info("chain_runner: lock transaction output {}:{}".format(b64encode(txo.transaction_hash), txo.transaction_idx))
        self.locking_txo[(tx_hash, tx_idx)] = True

    def lock_txos(self, txos):
        for txo in txos:
            self.lock_txo(txo.transaction_hash, txo.transaction_idx)

    def is_lock(self, tx_hash, tx_idx):
        # print txo
        locking_txo = self.locking_txo
        # print locking_txo
        return locking_txo[(tx_hash, tx_idx)]

    def update_my_satoshi(self):
        """check the satoshi client have"""
        utxos = self.chain.utxos
        member = self.member
        m_satoshi = {}
        m_satoshi_total = 0
        for (key, transaction_output) in utxos.items():
            # print ("trans {}".format(transaction_output.script))
            # vkd = transaction_output.script.body[0].data
            # print ("trans vk {}".format(.))
            # print ("member {}".format(member.verify_key_str))
            if transaction_output.script.body[0].data == member.verify_key_str:
                m_satoshi[key] = transaction_output
                m_satoshi_total += transaction_output.value
        self._m_satoshi = m_satoshi
        self._m_satoshi_total = m_satoshi_total

    def add_director(self, block=None, director=None):
        if not block:
            block = self.get_cooking_block()
        if not block:
            return None
        if not director:
            if self.cooking_food.has_key("director_competition"):
                sorted_list = sorted(self.cooking_food["director_competition"])
                if sorted_list.__len__():
                    director = sorted_list[0][1]
                else:
                    return None
            else:
                return None
        block.set_director(director)
        return block

    def add_senate_signature(self, block_hash, signatory, signature):
        block = self.get_cooking_block()
        sign_source = block.get_senate_sign_data_source()
        if block_hash == sign_source and self.chain.verify_senate_signature(signatory, sign_source, signature):
            block.add_senate_signature(signatory, signature)
            return True
        else:
            return False

    def add_block(self, block):
        chain = self.chain
        if chain.add_block(block):
            self.listen_block_change(block)
            return True
        else:
            logging.warn("Invalid block")
            return False

    def set_round(self, rounds):
        self._rounds = rounds

    def set_cooking_block(self, block):
        self.cooking_food['cooking_block'] = block

    def set_client_status(self, status):
        assert (status in self.ClientStatus)
        logging.info("client status from {} to {}".format(self.status, status))
        self._status = status

    def change_member(self, pbo):
        assert (isinstance(pbo, pb.Member)), type(pbo)
        self._member = member_model.MemberModel(pbo)
        self.update_my_satoshi()

    def next_senate_leader(self):
        self._senates_leader = None
        self._leader_serial_number += 1

    def create_inputs(self, transaction_info):
        """
        @transaction_info list of tuples (transaction_hash, transaction_idx)
        """
        ips = []
        for (transaction_hash, transaction_idx) in transaction_info:
            ips.append(transaction_model.Transaction.Input.new(transaction_hash, transaction_idx))
        return ips

    def create_outputs(self, transaction_info):
        """
        @transaction_info list of tuples (value, script, address)
        """
        ops = []
        for (value, script) in transaction_info:
            ops.append(transaction_model.Transaction.Output.new(value=value, script=script))
        return ops

    def create_transaction(self, inputs, outputs, add_to_summit_list=False):
        tx = transaction_model.Transaction()
        tx.add_inputs(inputs)
        tx.add_outputs(outputs)
        source = tx.get_transaction_sign_source()
        # MARK: deprecated in future
        for i in range(inputs.__len__()):
            tx.add_input_script(i, pb.Script(body=[pb.ScriptUnit(type=pb.SCRIPT_DATA, data=self.member.sign(source))]))
        if add_to_summit_list:
            self.pend_to_summit_transactions[tx.hash] = tx
        return tx

    def create_block(self, transactions=None):
        """create by accepted transactions"""
        last_block = self.last_block
        block = block_model.Block.new(last_block.hash)
        if not transactions:
            transactions = self.pending_transactions.values()
        block.add_transactions(transactions)
        self.add_director(block)
        return block

    def update_pending_transactions(self, block):
        """
        after add a new block, there are some transaction had been committed
        maybe reset, clean all transaction is a good idea?
        """
        # ----- method 1 -----
        # check committed transactions
        # 
        # transactions = block.transactions
        # committed_hashes = [ transaction.hash for transaction in transactions ]
        # pending_transactions = self.pending_transactions
        # new_pending = {}
        # for committed_hash in committed_hashes:
        #     if committed_hash in pending_transactions:
        #         pending_transactions.pop(committed_hash)
        # ----- method 2 ----
        self._pending_transactions = {}

    def receive_transactions(self, transactions):
        """collect transactions"""
        for transaction in transactions:
            if isinstance(transaction, pb.Transaction):
                transaction = transaction_model.Transaction(transaction)
            check = True
            pend_to_lock = []
            for ip in transaction.inputs:
                txo = TxoIndex(transaction_hash=ip.transaction_hash,
                               transaction_idx=ip.transaction_idx)
                pend_to_lock.append(txo)
            sam = pend_to_lock[0]
            # print "lock or not ", self.is_lock(sam), " {}:{}".format(b64encode(sam.transaction_hash), sam.transaction_idx)
            # print self.locking_txo
            for txo in pend_to_lock:
                if self.is_lock(txo.transaction_hash, txo.transaction_idx):
                    check = False
                    logging.warn(
                        "txo {}:{} already locked".format(b64encode(txo.transaction_hash), txo.transaction_idx))
                    break
            if check:
                # print "lock or not ", self.is_lock(sam), " {}:{}".format(b64encode(sam.transaction_hash), sam.transaction_idx)
                self.lock_txos(pend_to_lock)
                # print "lock or not ", self.is_lock(sam), " {}:{}".format(b64encode(sam.transaction_hash), sam.transaction_idx)
                self.pending_transactions[transaction.hash] = transaction

    def receive_director_competition(self, signature, txo_idx):
        ret = self.verify_director_competition_signature(signature, txo_idx)
        if ret:
            if self.cooking_food.has_key("director_competition"):
                self.cooking_food["director_competition"].append((signature, ret))
            else:
                self.cooking_food["director_competition"] = [(signature, ret)]
        return False

    def get_cooking_block(self):
        cooking_food = self.cooking_food
        if cooking_food.has_key('cooking_block'):
            return cooking_food['cooking_block']
        else:
            return None

    def get_director_competition_signature(self, transaction_hash, transaction_idx):
        """return (signature, txo_idx),
        signature = sign_owner( hash(prev_hash+q+merkle_root + transacntion out index ) )
        """
        utxo_idx = (transaction_hash, transaction_idx)
        if (transaction_hash, transaction_idx) in self.my_satoshi:
            ret = self.chain.get_director_competition_signature_source(transaction_hash, transaction_idx)
            if ret:
                source, txo_idx, __output = ret
                data = self.member.sign(source)
                return data, txo_idx
        return None

    def senate_sign(self, block):
        # todo: (return hash, vk, signature)
        if self.is_senate:
            ledger = self.chain
            if ledger.verify_transactions(block) != None:
                data = block.get_senate_sign_data_source()
                member = self.member
                return (data, member.verify_key_str, member.sign(data))
            else:
                logging.info("senate_sign fail")
        return False

    def director_sign(self, block):
        if block.director == self.member.verify_key_str:
            chain = self.chain
            block.director_sign(self.member, chain.last_block.q)
            if chain.verify_block(block):
                return block
            else:
                block._q = None
                block._signature = None
        return None

    def verify_director_competition_signature(self, signature, txo_idx):
        """return the owner member"""
        ret = self.chain.get_director_competition_signature_source(txo_idx.transaction_hash, txo_idx.transaction_idx)
        if ret:
            source, __txo_idx, op = ret
            verify_key_str = op.address
            if verify(signer=verify_key_str, signature=signature, data=source):
                return verify_key_str
        return False

    def initiate_protocol_handler(self):
        messages = {
            "senate_broadcast": message.Message(handler=self.on_senate_broadcast,
                                                payload_class=payload_base.PayloadBase),
            # "blocks_broadcast": message.Message(handler=on_blocks_broadcast)
        }
        self._meta_messages = messages

    def start(self, rounds=0):
        """set the status and timestamp """
        #  TODO: timeout , different role
        logging.critical("Start Round: {}".format(rounds))
        role = "nothing!"
        if self.is_senate_leader:
            role = "senate leader!!!"
        elif self.is_senate:
            role = "senate!!"
        logging.critical("I am : {}".format(role))
        # logging.critical("senates: {}".format(self.senates))
        logging.critical("satoshi {}".format(self.my_satoshi_total))

        self.set_round(rounds)
        self.consensus_reached[rounds] = False
        status = self.ClientStatus.Wait4TxsAndDirector
        self.set_client_status(status)
        self.send_director_competition()
        self.send_pend_to_summit_txs()

        if self.is_senate:
            # todo: broadcast existence
            if self.is_senate_leader:
                # set timeout for collect and create block

                # self.factory.lc = task.LoopingCall(self.send_senate_block_when_ready)
                # self.factory.lc.start(self.prepare_timeout).addErrback(my_err_back)
                call_later(self.prepare_timeout, self.send_senate_block_when_ready)
            else:
                call_later(self.prepare_timeout, self.consensus_phase_when_ready)
        else:
            status = self.ClientStatus.Wait4Block
            self.set_client_status(status)

    def send_director_competition(self):
        my_satoshi = self.my_satoshi
        one = random_utils.rand_one(my_satoshi)
        if one:
            ret = self.get_director_competition_signature(one[0][0], one[0][1])
            if ret:
                self.send_to_senates(pb.DirectorCompetition(signature=pb.Signature(signer=self.member.verify_key_str,
                                                                                   signature=ret[0]),
                                                            transaction_hash=ret[1].transaction_hash,
                                                            transaction_idx=ret[1].transaction_idx))

    def send_pend_to_summit_txs(self):
        if self.status is self.ClientStatus.Wait4TxsAndDirector:
            if self.pend_to_summit_transactions.__len__() > 0:
                logging.info("chain runner: send {} txs".format(self.pend_to_summit_transactions.__len__()))
                pb_txs = [tx.pb for tx in self.pend_to_summit_transactions.values()]
                tran_summit = pb.TransactionSummit(rounds=self.rounds,
                                                   txs=pb_txs)
                self.send_to_senates(tran_summit)
                self.pend_to_summit_transactions.clear()

    def consensus_phase_when_ready(self):
        logging.info("consensus_phase_when_ready")
        if self.pending_transactions.__len__() > 0 and self.cooking_food.has_key("director_competition"):
            def stop_and_restart(r):
                if not self.consensus_reached[r]:
                    self.next_senate_leader()
                    self.start(self.rounds)
                else:
                    del self.consensus_reached[r]

            call_later(self.consensus_timeout, stop_and_restart, self.rounds)
            if self.status == self.ClientStatus.Wait4TxsAndDirector:
                self.set_client_status(self.ClientStatus.Wait4Consensus)
        else:
            next_call = 2
            logging.info("senate: no transaction or director, check {} seconds later".format(next_call))
            self.send_pend_to_summit_txs()
            call_later(next_call, self.consensus_phase_when_ready)

    def send_senate_block_when_ready(self):
        logging.info("senate leader time to send block")
        if self.pending_transactions.__len__() > 0 and self.cooking_food.has_key("director_competition"):
            def stop_and_restart(r):
                if not self.consensus_reached[r]:
                    self.factory.lc.stop()
                    self.next_senate_leader()
                    self.start(self.rounds)
                else:
                    del self.consensus_reached[r]

            call_later(self.consensus_timeout, stop_and_restart, self.rounds)

            block = self.create_block()
            self.set_client_status(self.ClientStatus.Wait4Consensus)
            for senate in self.senates:
                self.send(senate, pb.ConsensusReq(block=block.pb))
            self.set_cooking_block(block)
            self.factory.lc = task.LoopingCall(self.check_enough_senate_signature)
            start_repeat_call = 2
            self.factory.lc.start(start_repeat_call).addErrback(my_err_back)
            # logging.info("Timeout start")
            # call_later(self.consensus_timeout, stop_and_restart)
            # self.timeout_called = True
        else:
            next_call = 2
            logging.info("senate leader: no transaction, check {} seconds later".format(next_call))
            self.send_pend_to_summit_txs()
            call_later(next_call, self.send_senate_block_when_ready)

    def check_enough_senate_signature(self):
        block = self.get_cooking_block()
        received_signature = block.senates
        ct = 0
        for senate_signature in received_signature:
            ct += self.senates[senate_signature.signer].__len__()
        failure_boundary = self.chain.failure_boundary
        logging.info("received {}/{}/{} signature".format(ct, failure_boundary, self.chain.senates_number))
        if ct >= failure_boundary:
            block = self.get_cooking_block()
            self.factory.lc.stop()
            # self.broadcast(block.pb)
            self.send(block.director, pb.DirectorShowTime(block=block.pb))
            self.set_client_status(self.ClientStatus.Wait4Block)
            logging.info("wait4block")

    def send_senate_broadcast(self):
        logger = logging
        meta_messages = self._meta_messages
        protocol_name = "senate_broadcast"

        logger.info("send " + protocol_name)
        # logger.info("member ", self.member)

        dest = member_model.BroadcastMember()
        message = meta_messages[protocol_name].payload_class(
            sender=self.member,
            destination=dest,
            signature=None,
            timestamp=self.timestamp
        )
        message.add_signature()
        #  (destination, protoco_name, message)
        return json.dumps([dest.mid]), protocol_name, json.dumps(message, default=payload_base.PayloadBase.obj2dict)

    def handle_protocols(self, dests, protocol_name, data):
        meta_messages = self._meta_messages
        logger = logging
        dest_mids = json.loads(dests)
        if dest_mids:
            if dest_mids[0] == None or self.member.mid in dest_mids:
                if protocol_name in meta_messages:
                    # return meta_messages[protocol_name].handler(data)
                    ret = meta_messages[protocol_name].handler(
                        json.loads(data, object_hook=meta_messages[protocol_name].payload_class.dict2obj))
                    return ret
                else:
                    logger.warn("unknown protocol: %s", protocol_name)
        return (None, (None, None, None))

    def handle_director_competition(self, obj, remote_vk_str):
        assert (isinstance(obj, pb.DirectorCompetition)), type(obj)
        client_status = self.ClientStatus
        if self.status in [client_status.Wait4TxsAndDirector]:
            self.receive_director_competition(signature=obj.signature.signature,
                                              txo_idx=transaction_model.TxoIndex(transaction_hash=obj.transaction_hash,
                                                                                 transaction_idx=obj.transaction_idx))
        else:
            logging.critical("chain_runner: "
                             "handle_director_competition in error statue {} from".format(self.status,
                                                                                          b64encode(remote_vk_str)))

    def handle_transaction_summit(self, obj, remote_vk_str):
        assert (isinstance(obj, pb.TransactionSummit)), type(obj)
        client_status = self.ClientStatus
        if self.status in [client_status.Wait4TxsAndDirector]:
            if obj.rounds == self.rounds and self.is_senate:
                self.receive_transactions(obj.txs)
        else:
            logging.critical("chain_runner: "
                             "handle_transaction_summit in error statue {} from {}".format(self.status,
                                                                                           b64encode(remote_vk_str)))


    def handle_senate_signature(self, obj, remote_vk_str):
        assert (isinstance(obj, pb.SenateSignature)), type(obj)
        client_status = self.ClientStatus
        if self.status in [client_status.Wait4Consensus]:
            self.add_senate_signature(obj.signed_block_hash, obj.senate_signature.signer, obj.senate_signature.signature)
        else:
            logging.critical("chain_runner: "
                             "handle_senate_signature in error statue {} from {}".format(self.status,
                                                                                         b64encode(remote_vk_str)))

    def handle_consensus_result(self, obj, remote_vk_str):
        assert (isinstance(obj, pb.ConsensusResult)), type(obj)
        # self.consensus_reached = True
        if self.status in [self.ClientStatus.Wait4Consensus, self.ClientStatus.Wait4TxsAndDirector]:
            block = block_model.Block(obj.block)
            ret = self.senate_sign(block)
            if ret:
                # cli.set_cooking_block(copy.copy(block))
                self.send(self.senates_leader, pb.SenateSignature(signed_block_hash=ret[0],
                                                                  senate_signature=pb.Signature(signer=ret[1],
                                                                                                signature=ret[2])))
                if not self.is_senate_leader:
                    self.set_client_status(self.ClientStatus.Wait4Block)
        else:
            logging.critical("chain_runner: "
                             "handle_consensus_result in error statue {} from {}".format(self.status,
                                                                                         b64encode(remote_vk_str)))

    def handle_block(self, obj, remote_vk_str):
        assert (isinstance(obj, pb.Block)), type(obj)
        if obj.prev_hash != self.last_block.hash:
            logging.critical("client: prev hash in equal")
            return
        client_status = self.ClientStatus
        if self.status == client_status.Wait4Block:
            if self.add_block(obj):
                self.consensus_reached[self.rounds] = True
                logging.info("add block: {} Bytes".format(obj.ByteSize()))
                self.start(self.rounds + 1)
        else:
            # raise Exception("chain_runner: handle block in invalid status: {}".format(self.status))
            logging.critical("chain_runner: "
                             "handle_block in error statue {} from {}".format(self.status,
                                                                              b64encode(remote_vk_str)))

    def handle_director_show_time(self, obj, remote_vk_str):
        assert (isinstance(obj, pb.DirectorShowTime)), type(obj)
        client_status = self.ClientStatus
        if self.status == client_status.Wait4Block:
            block = block_model.Block(obj.block)
            signed = self.director_sign(block)
            logging.info("I am director")
            if signed:
                self.broadcast(signed.pb)
        else:
            logging.critical("chain_runner: "
                             "handle_director_show_time in error statue {} from {}".format(self.status,
                                                                                           b64encode(remote_vk_str)))

    def send(self, remote_vk, obj):
        if remote_vk in self.factory.peers:
            self.factory.send(remote_vk, obj)
        else:
            logging.error("chain runner: remote_vk not exist {}".format(b64encode(remote_vk)))
            # raise Exception()

    def send_to_senates(self, obj):
        senates = self.senates
        for senate in senates:
            # print(senate)
            self.send(senate, obj)

    def broadcast(self, obj):
        self.factory.bcast(obj)

    # def on_blocks_broadcast..

    def on_senate_broadcast(self, payload):
        logger = self._logger
        timestamp = self.timestamp
        status = self.status
        logger.info("handle senate broadcast")

        # payload = json.loads(data, object_hook=payload_base.PayloadBase.dict2obj)
        sender = None

        if payload.verify():
            authentication = payload.authentication
            sender = authentication.sender.verify_key_str
            if self.is_senate:
                logger.info("senate broadcast from %s", authentication.sender.mid)
                if status == Client.ClientStatus.Wait4Senates and payload.timestamp >= timestamp:
                    return (sender, (None, None, None))
                else:
                    logger.warn("status invalid: %s" % status.name)
        else:
            logger.warn("payload verify fail")
        # sender, (destination, protoco_name, message)
        ret = (sender, (None, None, None))
        return ret

    ######## FOR SIMULATOR #############
    def make_tx(self, interval=0, output_number=1, random_node=False):
        if random_node:
            dests = []
            for _i in range(output_number):
                dests.append(self.factory.random_node)
            lc = task.LoopingCall(lambda: self._make_tx(dests))
        else:
            # node = self.factory.neighbour
            dests = self.factory.get_n_neighbour(output_number)
            lc = task.LoopingCall(self._make_tx, dests)
        lc.start(interval).addErrback(my_err_back)

    def _make_tx(self, dests):
        if self.status == self.ClientStatus.Wait4TxsAndDirector:
            m_satoshi = self.my_satoshi
            rand_one = random_utils.rand_one(m_satoshi)
            if rand_one:
                utx_header, output = rand_one
                if dests is not None and not self.is_lock(utx_header[0], utx_header[1]):
                    if not self.is_senate:
                        self.lock_txo(utx_header[0], utx_header[1])
                    cli_inputs = self.create_inputs([utx_header])
                    rand_remains_amount = output.value
                    collector = []
                    for dest in dests:
                        rand_out_amount = rand_remains_amount * random_utils.rand_percent()
                        import math
                        rand_out_amount = int(math.floor(rand_out_amount))
                        if rand_out_amount > 0:
                            logging.info("send {} to dest: {}".format(rand_out_amount, b64encode(dest)))
                            script_to_dest = script_to_verify_key(dest)
                            collector.append((rand_out_amount, script_to_dest))
                        rand_remains_amount = rand_remains_amount - rand_out_amount
                        if rand_remains_amount <= 0:
                            break
                    if rand_remains_amount:
                        logging.info(
                            "send {} to myself: {}".format(rand_out_amount, b64encode(self.member.verify_key_str)))
                        script_to_myself = script_to_verify_key(self.member.verify_key_str)
                        collector.append((rand_remains_amount, script_to_myself))
                    if collector.__len__() > 0:
                        cli_outputs = self.create_outputs(collector)
                        self.create_transaction(cli_inputs, cli_outputs, True)

#
# if __name__ == "__main__":
#     c = Client()
#     addr = c.get_first_peer_address()
#     c.gossip_existence(addr)
#     c.request_peers(addr)
#     c.run()


def gen_some_member(path, number=10):
    import os
    for no in range(number):
        detail_path = os.path.join(path, no.__str__())
        member = member_model.MemberModel(True)
        member.write_to_path(detail_path)


def gen_genic_block(path, owner_path):
    member = member_model.MemberModel(key_path=owner_path)
    tx = transaction_model.Transaction()
    op = transaction_model.Transaction.Output.new(1000, pb.SCRIPT_TYPE_VK, member.verify_key_str)
    tx.add_outputs([op])
    b = block_model.Block.new(None, hash_utils.hash_std("genic block"))
    b.add_transactions([tx])
    b.director_sign(member)
    block_model.dump_blocks([b], path)


def create_logger(log_name='batch'):
    handler = logging.handlers.RotatingFileHandler(filename='log/' + str(log_name) + '.log', maxBytes=1024 * 1024 * 500,
                                                   backupCount=5)
    # handler = logging.FileHandler(str(log_name) + '.log', maxBytes = 1024 * 1024 * 500, backupCount = 5)
    # fmt = '%(asctime)s - %(filename)s:%(lineno)s - %(name)s - %(message)s'
    # fmt = "[%(asctime)s]\t[%(levelname)s]\t[%(thread)d]\t[%(pathname)s:%(lineno)d]\t%(message)s"
    fmt = "[%(asctime)s]\t[%(levelname)s]\t[%(name)s]\t[%(pathname)s:%(lineno)d]\t%(message)s"
    formatter = logging.Formatter(fmt)
    handler.setFormatter(formatter)
    logger = logging.getLogger(str(log_name))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger


def get_logger(log_name):
    logger = logging.getLogger(log_name)
    logger.setLevel(logging.INFO)
    hdlr = logging.FileHandler(log_name + '.log')
    hdlr.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "[%(asctime)s]\t[%(levelname)s]\t[%(thread)d]\t[%(pathname)s:%(lineno)d]\t%(message)s")
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    return logger
