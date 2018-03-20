#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# chain_model.py ---
#
# @Filename: chain_model.py
# @Description: 
# @Author: Weijie Li
# @Created time: 2018-02-27 14:42:00
# @Last Modified by: 
# @Last Modified time: 

import logging

from . import block_model
from . import member_model
from transaction_model import TxoIndex

from ..config import config_loader
from src.chain.config import chain_config
from src.utils import hash_utils
import src.messages.messages_pb2 as pb
from src.protobufwrapper import ProtobufWrapper
from src.chain.model.member_model import verify

class Chain(ProtobufWrapper):

    def __init__(self, pbo):
        assert(isinstance(pbo, pb.Chain)), type(pbo)
        super(Chain, self).__init__(pbo)
        self._blocks = [ block_model.Block(bl) for bl in self.pb.blocks ]
        # self._blocks = []
        self._utxos = {}
        self._utxos_tot = 0
        self._senates = None

        if self._blocks.__len__() > 0:
            genic_block = self._blocks[0]
            self.update_utxo(block=genic_block, verify_prev_block=False)
            rest_blocks = self._blocks[1:]
            # be careful
            self.update_utxo(block=rest_blocks, verify_prev_block=True)
        # self._senates_number = senates_number
        # self._senates_boundary = senates_number*3/4

        # self._director_competition_boundary = director_competition_boundary

    @classmethod
    def new(cls,
            senates_number=chain_config.senates_number,
            failure_boundary=0):
        if failure_boundary == 0:
            import math
            max_fail_node = int(math.floor(senates_number-1)/3)
            failure_boundary = senates_number-max_fail_node

        chain = cls(pb.Chain(
            senates_number=senates_number,
            failure_boundary=failure_boundary
        ))
        # self._blocks = []
        # self._utxos = {}
        # self._utxos_tot = 0
        # self._senates = None
        # self._senates_number = senates_number
        # self._failure_boundary = failure_boundary
        # self._director_competition_boundary = director_competition_timeout_in_secs
        return chain

    def set_ledger(self, blocks, utxos):
        """set the blocks and utxos without check"""
        # self.pb = pb.Chain()
        del self.pb.blocks[:]
        self._blocks = []
        for bl in blocks:
            self.pb.blocks.add()
            self.pb.blocks[-1].CopyFrom(bl.pb)
            self._blocks.append(block_model.Block(self.pb.blocks[-1]))
        if utxos and isinstance(utxos, dict) and utxos.__len__() != 0:
            self._utxos = utxos
            self.recount_utxos_tot()
        else:
            self._utxos = {}
            self._utxos_tot = 0
            self._senates = None
            self.update_utxos(blocks, verify_prev_block=False)

    @property
    def senates_number(self):
        return self.pb.senates_number

    @property
    def failure_boundary(self):
        return self.pb.failure_boundary

    @property
    def blocks(self):
        return self._blocks

    @property
    def last_block(self):
        return self.blocks[-1]

    @property
    def utxos(self):
        """utxos = {
            (transaction_hash, transaction_idx): transaction.output,
            ...
        }
        """
        return self._utxos

    @property
    def senates(self):
        """ senates = {}
            utxo.address: [0, 1, 2],   #(senate serial number, for example)
            ...
        }
        """
        if not self._senates:
            self.cal_senates()
        return self._senates

    def verify_transactions(self, block):
        """verify_transactions, and return a new utxo pool if success, otherwise return None
        checklist:
        * transaction input whether exist in utxo
        * verify transaction input signature
        * income >= outcome
        """
        import copy
        utxos_copy = copy.copy(self.utxos)
        total_in = 0
        total_out = 0
        counter = 0
        for tx in block.transactions:
            counter += 1
            satoshi_income = 0
            satoshi_outcome = 0
            prev_out = []
            for ip in tx.inputs:
                utxo_header = (ip.transaction_hash, ip.transaction_idx)
                if utxo_header in utxos_copy:
                    prev_out.append(utxos_copy[utxo_header])
                    satoshi_income += utxos_copy[utxo_header].value
                    utxos_copy.pop(utxo_header)
                else:
                    # print ip, "not in utxo"
                    return None

            for idx, op in enumerate(tx.outputs):
                satoshi_outcome += op.value
                utxo_header = (tx.hash, idx)
                utxos_copy[utxo_header] = op

            # FUTURE:
            # FEATURE:INCENTIVE
            if satoshi_income==0 and counter==block.transactions.__len__():
                # transaction fee transaction
                total_different= total_in-total_out
                if total_different<satoshi_outcome:
                    return None
            else:
                if not tx.verify_sig_in_inputs(prev_out):
                    logging.info("tx.verify_sig_in_inputs fail")
                    return None
                if satoshi_income<satoshi_outcome:
                    return None
            total_in += satoshi_income
            total_out += satoshi_outcome
        return utxos_copy
        
    def verify_block(self, block, update=False, verbose=False):
        """ 
        @update whether update utxo if success
        check list:
        prev hash
        check q 
        the director signature
        the senates signature
        verify_transaction
        """
        last_block = self.last_block
        if last_block.hash != block.prev_hash:
            print("last_block.hash != block.prev_hash")
            return False

        # director signature
        if not block.director_verify(last_block.q):
            print("director_verify fail")
            return False
        # senate signature
        failure_boundary = self.failure_boundary
    
        senate_sign_source = block.get_senate_sign_data_source()
        senates_signed_data = block.senates
        signed_ct = 0
        for senate_signature in senates_signed_data:
            verify_key_str = senate_signature.signer
            signature = senate_signature.signature
            if not self.verify_senate_signature(verify_key_str, senate_sign_source, signature):
                print("verify_senate_signature fail")
                return False
            signed_ct += self.senates[verify_key_str].__len__()
        if signed_ct < failure_boundary:
            print("signed_ct not enough %d/%d/%d"%(signed_ct, failure_boundary, self.senates_number))
            return False

        utxos_copy = self.verify_transactions(block)
        if utxos_copy==None:
            # print "utxos_copy ", utxos_copy
            print("verify_transactions fail")
            return False
        if update:
            if verbose:
                print utxos_copy            
            self._utxos = utxos_copy
            self.recount_utxos_tot()
        return True

    def verify_senate_signature(self, senate_verify_key_str, data, senate_signature):
        senates = self.senates
        if senate_verify_key_str not in senates:
                return False
        return verify(signer=senate_verify_key_str, signature=senate_signature, data=data)

    def update_utxo(self, block, update_satoshi_tot=True, verify_prev_block=True):
        """
        @verify_prev_block should be always True except the genic block
        """
        if verify_prev_block:
            ret = self.verify_transactions(block=block)
            if ret!=None:
                self._utxos = ret
            if update_satoshi_tot:
                self.recount_utxos_tot()
        else:
            # dont use this except the genic block
            inputs = []
            pending_utxos = []
            # i = 0
            for tx in block.transactions:
                # print i,"transaction hash", tx.hash
                # i += 1
                inputs.extend(tx.inputs)
                for index, output in enumerate(tx.outputs):
                    pending_utxos.append(((tx.hash, index), output))

            remove_items = [ (x.transaction_hash, x.transaction_idx) for x in inputs ]
            import copy
            utxos_copy = copy.copy(self._utxos)
            for remove_item in remove_items:
                if utxos_copy.has_key(remove_item):
                    utxos_copy.pop(remove_item)
                else:
                    print remove_item
                    raise Exception("update_utxo: not exist utxo")
            utxos_copy.update(pending_utxos)
            self._utxos = utxos_copy
            if update_satoshi_tot:
                self.recount_utxos_tot()

    def update_utxos(self, blocks, verify_prev_block=True):
        for block in blocks:
            self.update_utxo(block, update_satoshi_tot=False, verify_prev_block=verify_prev_block)
        self.recount_utxos_tot()

    def add_block(self, block):
        """add block with verify"""
        assert isinstance(block, (block_model.Block, pb.Block)), type(block)
        if isinstance(block, pb.Block):
            block = block_model.Block(block)
        if self.verify_block(block, update=True):
            self._senates = None
            self.pb.blocks.extend([block.pb])
            self.blocks.append(block_model.Block(self.pb.blocks[-1]))
            return True
        else:
            logging.warn("block verify fail")
            return False

    def add_blocks(self, blocks):
        """add blocks with verify"""
        for b in blocks:
            self.add_block(b)

    def recount_utxos_tot(self):
        tot = 0
        utxos = self.utxos
        for op in utxos.itervalues():
            tot += op.value
        self._utxos_tot = tot

    def get_director_competition_signature_source(self, transaction_hash, transaction_idx):
        """return source, txo_idx, Transaction.Output"""
        prev_block_star = self.last_block.get_director_competition_data_source()
        utxo_header = (transaction_hash, transaction_idx)
        if utxo_header in self.utxos:
            txo_idx = TxoIndex(transaction_hash, transaction_idx)
            data = prev_block_star + txo_idx.to_str()
            data = hash_utils.hash_std(data)
            return data, txo_idx, self.utxos[utxo_header]
        else:
            return None

    def dump_blocks(self, path):
        """store in path"""
        return block_model.dump_blocks(self.blocks, path)

    def dumps_blocks(self):
        """to str"""
        return block_model.dumps_blocks(self.blocks)

    def cal_senates(self, verbose=False):
        # sort by hash of transaction, then chose the satoshi owner by  prev_transaction.q
        # transaction equal and
        sorted_utxos = sorted(self._utxos.items(), key=lambda x:x[0])

        q = self.last_block.q
        senates_number = self.senates_number
        senates_owner_satoshi = []
        utxos_tot = self._utxos_tot

        def cal_satoshi_with_sha256(hv, tot_satoshi):
            """
            @hv hash value by sha256
            @tot_satoshi
            """
            import binascii
            hexhv = binascii.hexlify(hv)
            hi = int(hexhv, 16) * tot_satoshi
            const_tot_sha256 = 1<<256
            return hi / const_tot_sha256

        for i in range(senates_number):
            q = hash_utils.hash_std(q)
            satoshi = cal_satoshi_with_sha256(q, utxos_tot*1.0)
            senates_owner_satoshi.append( (i, satoshi))
        senates_owner_satoshi.sort(key=lambda x:x[1])

        if verbose:
            print "cal_senates():  ", senates_owner_satoshi

        satoshi_ct = 0
        result = {}
        utxo_iter = iter(sorted_utxos)
        current_utxo =  utxo_iter.next()
        current_op = current_utxo[1]
        satoshi_ct = current_op.value
        for senate in senates_owner_satoshi:
            while satoshi_ct<senate[1]:
                if verbose:
                    print("satoshi_ct: %d / senate: %d"%(satoshi_ct,senate[1]))
                current_utxo =  utxo_iter.next()
                current_op = current_utxo[1]
                satoshi_ct += current_op.value
            
            if result.has_key(current_op.address):
                # record the No. of senate
                result[current_op.address].append(senate[0])
            else:
                result[current_op.address] = [senate[0]]
        if verbose:            
            print "cal_senates():  ", result
            print "cal_senates():  sorted_utxo", sorted_utxos
        self._senates = result
       
            


