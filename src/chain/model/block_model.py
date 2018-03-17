#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# block.py ---
#
# @Filename: block.py
# @Description: 
# @Author: Weijie Li
# @Created time: 2018-02-26 10:58:30
# @Last Modified by: 
# @Last Modified time: 

import json

from . import transaction_model
from src.chain.model.transaction_model import Transaction
from . import member_model
from src.utils import hash_utils
from src.protobufwrapper import ProtobufWrapper
import src.messages.messages_pb2 as pb
from src.chain.model.member_model import verify

from base64 import urlsafe_b64decode as b64d
from base64 import urlsafe_b64encode as b64e

def load_blocks(path):
    with open(path, 'r') as f:
        # b = json.load(f, object_hook=Block.dict2obj)
        b = json.load(f, object_hook=Block.dict2obj)
        return b

def loads_blocks(bls):
    b = json.load(bls, object_hook=Block.dict2obj)
    return b

def dump_blocks(blocks, path):
    with open(path, 'w') as f:
        json.dump(blocks, f, default=Block.obj2dict)

def dumps_blocks(blocks):
    return json.dumps(blocks, default=Block.obj2dict)

class Block(ProtobufWrapper):

    def __init__(self, pbo):
        assert(isinstance(pbo, pb.Block)), type(pbo)
        super(Block, self).__init__(pbo)
        self._prev_hash = pbo.prev_hash
        self._q = pbo.q
        self._merkle_root = pbo.merkle_root
        self._txs = [Transaction(tx) for tx in pbo.txs]

        self._senates_signature = pbo.senates_signature
        self._director_signature = pbo.director_signature

        self._merkle_tree = None

    @classmethod
    def new(cls, prev_hash, q=""):
        obj = cls(pb.Block(
            prev_hash=prev_hash,
            q=q
        ))
        return obj


    # MARK: Not needed: blocks write and load is needed, not block
    # @classmethod
    # def from_json_path(cls, json_path):
    #     with open(path, 'r') as f:
    #         # b = json.load(f, object_hook=Block.dict2obj)
    #         b = json.load(f)
    #         return b

    # def write_to_path(self, path):
    #     with open(path, 'w') as f:
    #         json.dump(self, f, default=Block.obj2dict)

    @property
    def n_txs(self):
        return self._txs.__len__()

    @property
    def q(self):
        return self._q
    
    @property
    def merkle_root(self):
        if not self._merkle_root:
            self._merkle_root = self.merkle_tree[-1]
        return self._merkle_root

    @property
    def merkle_tree(self):
        if not self._merkle_tree:
            self.completion_merkle_tree()
        return self._merkle_tree

    # @property
    # def hash(self):
    #     if not self._hash:
    #         self.cal_hash()
    #     return self._hash

    @property
    def prev_hash(self):
        return self._prev_hash
    
    @property
    def transactions(self):
        return self._txs

    @property
    def director_signature(self):
        return self._director_signature

    @property
    def senates(self):
        return self._senates_signature

    @property
    def director(self):
        """director's verify_key"""
        return self._director_signature.signer
    
    def on_change(self):
        super(Block, self).on_change()
        self._merkle_root = ""
        self._merkle_tree = None
    
    def add_transactions(self, txs):
        pbs = [t.pb for t in txs]
        self.pb.txs.extend(pbs)
        n = pbs.__len__()
        last_pbs = self.pb.txs[-n:]
        new_txs = [Transaction(tx) for tx in last_pbs ]
        self._txs.extend(new_txs)
        self.on_change()

    def add_senate_signature(self, senate, senate_signature):
        """
        must verify the senate's real identity in outside
        @senate_verify_key_str  pem format
        """
        self.pb.senates_signature.add(signer=senate, signature=senate_signature)
        # self._senates_signature = self.pb.senates_signature
        self.on_change()

    def set_q(self, new_q):
        self._q = new_q
        self.pb.q = new_q
        # self._q = new_q.encode('utf-8')
        self.on_change()

    def set_director_signature(self, signer, signature):
        self.pb.director_signature.signer = signer
        self.pb.director_signature.signature = signature
        # self._director_signature = self.pb.director_signature
        self.on_change()

    def director_sign(self, member, prev_q):
        """add director, signature, q"""
        self.set_q(member.sign(hash_utils.hash_std(prev_q)))
        data = self.get_director_sign_data_source()
        self.set_director_signature(signer=member.verify_key_str, signature=member.sign(data))

    def director_verify(self, prev_q):
        """including:
        signature of the block hash value by director
        q
        """
        if not self.director_signature or not self.director or not self.q:
            return False
        director = self.director
        prev_q = hash_utils.hash_std(prev_q)
        data = self.get_director_sign_data_source()
        return verify(signer=director, data=prev_q, signature=self.q) and verify(signer=director, data=data, signature=self.director_signature.signature)

    def get_senate_sign_data_source(self):
        """including director_verify_key_str, transaction merkle_root"""
        director = self.director
        assert isinstance(director, member_model.MemberModel), type(director)
        director_str = director.verify_key_str
        return director_str + self.merkle_root

    def get_director_competition_data_source(self):
        """the data of b*, including the prev_block, the q, the transactions merkle root, director"""
        header = self.prev_hash + self.q + self.merkle_root + self.director
        hv = hash_utils.hash_std(header)
        return hv
    
    def get_director_sign_data_source(self):
        header = self.prev_hash + self.q + self.merkle_root + self.director + self.merkle_root
        for s in self.senates:
            header += s.director_signature.signature
        hv = hash_utils.hash_std(header)
        return hv

    def get_transaction(self, idx):
        if idx<=self.n_txs:
            return self.transactions[idx]
        else:
            return None

    def clean_transaction(self):
        self._txs = None
        self._merkle_root = None
        self.on_change()


    def completion_merkle_tree(self):
        n = self.n_txs
        merkle_tree = []
        for tx in self.transactions:
            merkle_tree.append(tx.hash)
        pos = 0
        last = n
        while n>1:
            second_pos = pos + 1
            a = merkle_tree[pos]
            if second_pos<last:
                a += merkle_tree[second_pos]
                pos += 2
            else:
                a += a
                pos += 1
            hv = hash_utils.hash_std(a)
            merkle_tree.append(hv)

            if pos >= last:
                last = merkle_tree.__len__()
                n = last - pos

        self._merkle_tree = merkle_tree

    # def cal_hash(self):
    #     verify_key_str = None
    #     if self.director:
    #         verify_key_str = self.director.verify_key_str
    #     header = [self.prev_hash, self.q, self.merkle_root, verify_key_str]
    #     header.extend(self.senates)
    #     head_data = json.dumps(header, sort_keys=True)
    #     hv = hash_utils.hash_std(head_data)
    #     self._hash = hv

    @classmethod
    def obj2dict(cls, obj):
        return {
            "prev_hash": obj.prev_hash,
            "q":obj.q,
            "txs": json.dumps(obj.transactions, default=transaction_model.Transaction.obj2dict),
            "director_signature": (b64e(obj.director_signature.signer), b64e(obj.director_signature.signature)),
            "senates_signature": [(b64e(s.signer), b64e(s.signature)) for s in obj.senates],
            # "n_txs":obj.n_txs,
            "merkle_root": obj.merkle_root
        }

    @classmethod
    def dict2obj(cls, dic):
        prev_hash = dic['prev_hash']
        q = dic['q']
        # import logging
        # logging.info("{}".format(type(prev_hash)))
        b = Block.new(prev_hash, q)

        # FUTURE: Optimization
        b.add_transactions(json.loads(dic['txs'], object_hook=transaction_model.Transaction.dict2obj))

        b.set_director_signature(signer=b64d(dic['director_signature'][0]),
                                 signature=b64d(dic['director_signature'][1]))
        for signature in dic['senates_signature']:
            b.add_senate_signature(senate=b64d(signature[0]),
                                   signature=b64d(signature[1]))

        b.pb.merkle_root = dic["merkle_root"]
        b._merkle_root = b.pb.merkle_root
        return b
        






        

    
