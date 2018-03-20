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
from src.utils import hash_utils
import src.messages.messages_pb2 as pb

from src.chain.model.member_model import verify


class Client(object):

    STATUS = enum.Enum("client_status" , ('Sleeping', "Wait4Senates"))
    
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
    def chain(self):
        return self._chain

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
        senates = self.chain.senates
        mvs = self.member.verify_key_str
        if mvs in senates:
            if self._leader_serial_number in senates[mvs]:
                return True
        return False

    def __init__(self, member=None, blocks_path=None):
        """

        :param member: MemberModel or member_path , if None , will generate a random member
        :param blocks_path:
        """

        self._timestamp = 0
        self._leader_serial_number = 0
        self._status = Client.STATUS.Sleeping
        self._cooking_food = {}
        self._locking_txo = defaultdict(bool)

        self._chain = chain_model.Chain.new()
        
        # the pending transactions 
        self._pending_transactions = {}

        if not member:
            member = member_model.MemberModel(genkey=True)
        else:
            if not isinstance(member, member_model.MemberModel):
                member_path = member
                member = member_model.MemberModel()
                member.new(key_path=member_path)
        assert isinstance(member, member_model.MemberModel), type(member)

        self._member = member

        self._m_satoshi = {}  
        self._m_satoshi_total = 0
        if blocks_path:
            bs = block_model.load_blocks(blocks_path)
            chain = self.chain
            chain.set_ledger(bs, None)
            self.listen_block_change(None)

        # logger
        self._logger = create_logger(member.mid[-5:])
        
        # init models

        self.initiate_protocol_handler();

    def listen_block_change(self, block):
        if block:
            self.update_pending_transactions(block)
        self.update_my_satoshi()
        self._cooking_food = {}
        self.reset_lock_list()

    def reset_lock_list(self):
        self.locking_txo.clear()

    def lock_txo(self, txo):
        self.locking_txo[txo] = True

    def lock_txos(self, txos):
        for txo in txos:
            self.locking_txo[txo] = True

    def is_lock(self, txo):
        return self.locking_txo[txo]

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
                m_satoshi[ key ] = transaction_output
                m_satoshi_total += transaction_output.value
        self._m_satoshi = m_satoshi
        self._m_satoshi_total = m_satoshi_total
       
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

    def create_transaction(self, inputs, outputs):
        tx = transaction_model.Transaction()
        tx.add_inputs(inputs)
        tx.add_outputs(outputs)
        source = tx.get_transaction_sign_source()
        # MARK: deprecated in future
        for i in range(inputs.__len__()):
            tx.add_input_script(i, pb.Script(body=[pb.ScriptUnit(type=pb.SCRIPT_DATA, data=self.member.sign(source))]))
        return tx

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
            check = True
            pend_to_lock = []
            for ip in transaction.inputs:
                txo = TxoIndex(transaction_hash=ip.transaction_hash,
                               transaction_idx=ip.transaction_idx)
                pend_to_lock.append(txo)
            for txo in pend_to_lock:
                if self.is_lock(txo):
                    check = False
                    break
            if check:
                self.lock_txos(pend_to_lock)
            self.pending_transactions[transaction.hash] = transaction       

    def receive_director_competition(self, signature, txo_idx):
        ret = self.verify_director_competition_signature(signature, txo_idx)
        if ret:
            if self.cooking_food.has_key("director_competition"):
                self.cooking_food["director_competition"].append((signature, ret))
            else:
                self.cooking_food["director_competition"] = [ (signature, ret) ]
        return False

    def create_block(self, transactions=None):
        """create by accepted transactions"""
        last_block = self.last_block
        block = block_model.Block.new(last_block.hash)
        if not transactions:
            transactions = self.pending_transactions.values()
        block.add_transactions(transactions)
        self.add_director(block)
        
        return block
    
    def set_cooking_block(self, block):
        self.cooking_food['cooking_block'] = block
    
    def get_cooking_block(self):
        cooking_food = self.cooking_food
        if cooking_food.has_key('cooking_block'):
            return cooking_food['cooking_block']
        else:
            return None

    def senate_sign(self, block):
        if self.is_senate:
            ledger = self.chain
            if ledger.verify_transactions(block)!=None:
                data = block.get_senate_sign_data_source()
                member = self.member
                return (member.verify_key_str, member.sign(data))
            else :
                logging.info("senate_sign fail")                
        return False

    def director_sign(self, block):
        if block.director == self.member.verify_key_str:
            ledger = self.chain
            block.director_sign(self.member, ledger.last_block.q)
            if ledger.verify_block(block) :
                return block
            else:
                block._q = None
                block._signature = None
        return None

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

    def add_senate_signature(self, signatory, signature):
        block = self.get_cooking_block()
        sign_source = block.get_senate_sign_data_source()
        if self.chain.verify_senate_signature(signatory, sign_source, signature):
            block.add_senate_signature(signatory, signature)

    def get_director_competition_signature(self, transaction_hash, transaction_idx):
        """return (signature, txo_idx),  signature = sign_owner( hash(prev_hash+q+merkle_root + transacntion out index ) ) """
        utxo_idx = (transaction_hash, transaction_idx)
        if (transaction_hash, transaction_idx) in self.my_satoshi:
            ret = self.chain.get_director_competition_signature_source(transaction_hash, transaction_idx)
            if ret:
                source, txo_idx, __output = ret
                data = self.member.sign(source)
                return data, txo_idx
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

    def add_block(self, block):
        chain = self.chain
        if chain.add_block(block):
            self.listen_block_change(block)
        else:
            logging.warn("Invalid block")

    def initiate_protocol_handler(self):
        messages = {
            "senate_broadcast": message.Message(handler=self.on_senate_broadcast,
                                                payload_class=payload_base.PayloadBase ),
            # "blocks_broadcast": message.Message(handler=on_blocks_broadcast)
        }
        self._meta_messages = messages

    def start(self, status=STATUS.Wait4Senates, timestamp = 0):
        """set the status and timestamp """
        self._timestamp = timestamp
        self._status = status

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
                if (status == Client.STATUS.Wait4Senates and payload.timestamp >= timestamp):
                    return (sender, (None, None, None))
                else:
                    logger.warn("status invalid: %s"%status.name)
        else:
            logger.warn("payload verify fail")
        # sender, (destination, protoco_name, message)
        ret = (sender, (None, None, None))
        return ret

    def send_senate_broadcast(self):
        logger = self._logger
        meta_messages = self._meta_messages
        protocol_name = "senate_broadcast"

        logger.info("send " + protocol_name)
        # logger.info("member ", self.member)

        dest = member_model.BroadcastMember()
        message = meta_messages[protocol_name].payload_class(
            sender = self.member,
            destination= dest,
            signature=None,
            timestamp=self.timestamp
        )
        message.add_signature()
        #  (destination, protoco_name, message)
        return (json.dumps([dest.mid]), protocol_name, json.dumps(message, default=payload_base.PayloadBase.obj2dict))

    def handle_protocols(self, dests, protocol_name, data):
        meta_messages = self._meta_messages
        logger = self._logger
        dest_mids = json.loads(dests)
        if dest_mids:
            if dest_mids[0]==None or self.member.mid in dest_mids:
                if protocol_name in meta_messages:
                    # return meta_messages[protocol_name].handler(data)
                    ret = meta_messages[protocol_name].handler(json.loads(data, object_hook=meta_messages[protocol_name].payload_class.dict2obj)  )
                    return ret
                else:
                    logger.warn("unknown protocol: %s", protocol_name)
        return (None, (None, None, None))

    
if __name__ == "__main__":
    c = Client()
    addr = c.get_first_peer_address()
    c.gossip_existence(addr)
    c.request_peers(addr)
    c.run()

def gen_some_member(path, number=10):
    import os
    for no in range(number):
        detail_path= os.path.join(path, no.__str__())
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

def create_logger(log_name = 'batch'):
    handler = logging.handlers.RotatingFileHandler(filename = 'log/' + str(log_name) + '.log', maxBytes = 1024 * 1024 * 500, backupCount = 5)
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
    formatter = logging.Formatter("[%(asctime)s]\t[%(levelname)s]\t[%(thread)d]\t[%(pathname)s:%(lineno)d]\t%(message)s")
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    return logger