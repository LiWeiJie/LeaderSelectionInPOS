#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# transaction_output_index.py ---
#
# @Filename: transaction_output_index.py
# @Description: Transaction Output index
# @Author: Weijie Li
# @Created time: 2018-03-05 17:04:09
# @Last Modified by: 
# @Last Modified time: 

class TxoIndex(object):

    def __init__(self, transaction_hash, transaction_idx):
        self._transaction_hash = transaction_hash
        self._transaction_idx = transaction_idx
    
    def to_str(self):
        return self.transaction_hash+str(self.transaction_idx)
    
    @property
    def transaction_hash(self):
        return self._transaction_hash
    
    @property
    def transaction_idx(self):
        return self._transaction_idx

    @classmethod
    def obj2dict(cls, obj):
        return {
            "transaction_hash": self.transaction_hash,
            "transaction_idx": self.transaction_idx
        }

    @classmethod
    def dict2obj(cls, dic):
        return cls(dic['transaction_hash'], dic['transaction_idx'])