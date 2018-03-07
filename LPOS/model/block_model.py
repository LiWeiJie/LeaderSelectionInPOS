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
from . import member_model
from ..utils import hash_utils

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
class Block(object):

    def __init__(self, prev_hash, q = None):
        self._prev_hash = None
        self._q = None
        self._merkle_root = None
        self._n_txs = 0

        self._txs = []
        self._hash = None
        self._merkle_tree = None
        self._signature = None

        self._director = None
        self._senates = []
        if prev_hash:
            # print prev_hash, " type ", type(prev_hash)
            self._prev_hash = prev_hash.encode('utf-8')

        if q:
            self._q = q.encode('utf-8')

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
        return self._n_txs

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

    @property
    def hash(self):
        if not self._hash:
            self.cal_hash()
        return self._hash

    @property
    def prev_hash(self):
        return self._prev_hash
    
    @property
    def transactions(self):
        return self._txs

    @property
    def signature(self):
        return self._signature

    @property
    def senates(self):
        return self._senates

    @property
    def director(self):
        """director's verify_key"""
        return self._director

    def set_director(self, director):
        self._director = director

    def director_sign(self, member, prev_q):
        """add director, signature, q"""
        self.set_director(member)
        self._q = member.sign(hash_utils.hash_std(prev_q))
        self._signature = member.sign(self.hash)

    def director_verify(self, prev_q):
        """including:
        signature of the block hash value by director
        q
        """
        if not self.signature or not self.director or not self.q:
            return False
        director = self.director
        prev_q = hash_utils.hash_std(prev_q)
        return director.verify(prev_q, self.q) and director.verify(self.hash, self.signature)

    def add_senate_signature(self, senate_verify_key_str, senate_signature):
        """
        must verify the senate's real identity in outside
        @senate_verify_key_str  pem format
        """
        self._senates.append((senate_verify_key_str, senate_signature))

    def get_senate_sign_source(self):
        """including director_verify_key_str, transaction merkle_root"""
        director = self.director
        assert isinstance(director, member_model.MemberModel), type(director)
        director_str = director.verify_key_str
        return director_str + self.merkle_root

    def get_block_star_info_source(self):
        """the data of b*, including the prev_block, the q, the transactions merkle root"""
        prev_hash = self.prev_hash
        if not prev_hash:
            prev_hash = ""
        data = prev_hash + self.q + self.merkle_root
        return data
    
    def set_q(self, new_q):
        self._q = new_q.encode('utf-8')

    def add_transactions(self, txs):
        for tx in txs:
            assert isinstance(tx, transaction_model.Transaction), type(tx)
            self._txs.append(tx)
            self._n_txs += 1
        self.on_change()

    def get_transaction(self, idx):
        if idx<=self.n_txs:
            return self.transactions[idx]
        else:
            return None

    def clean_transaction(self):
        self._n_txs = 0
        self._txs = None
        self._merkle_root = None
        self.on_change()

    def on_change(self):
        self._merkle_root = None
        self._merkle_tree = None
        self._hash = None

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

    def cal_hash(self):
        verify_key_str = None
        if self.director:
            verify_key_str = self.director.verify_key_str
        header = [self.prev_hash, self.q, self.merkle_root, verify_key_str]
        header.extend(self.senates)
        head_data = json.dumps(header, sort_keys=True)
        hv = hash_utils.hash_std(head_data)
        self._hash = hv

    @classmethod
    def obj2dict(cls, obj):
        return {
            "prev_hash": obj.prev_hash,
            "q":obj.q,
            "n_txs":obj.n_txs,
            "txs": json.dumps(obj.transactions, default=transaction_model.Transaction.obj2dict),
            "signature": obj.signature,
            "director": json.dumps(obj.director, default=member_model.MemberModel.obj2dict),
            "senates": obj.senates
        }

    @classmethod
    def dict2obj(cls, dic):
        prev_hash = dic['prev_hash']
        q = dic['q']
        b = Block(prev_hash, q)
        b._n_txs = dic['n_txs']

        b._txs = json.loads(dic['txs'], object_hook=transaction_model.Transaction.dict2obj)
        b._signature = dic['signature']

        b._director = json.loads(dic['director'], object_hook=member_model.MemberModel.dict2obj)
        b._senates = dic['senates']
        return b
        






        

    
