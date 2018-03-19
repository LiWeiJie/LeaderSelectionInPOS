#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# model_test.py ---
#
# @Filename: model_test.py
# @Description: 
# @Author: Weijie Li
# @Created time: 2018-02-26 09:33:06
# @Last Modified by: 
# @Last Modified time: 

import unittest
import json
import os

from ..model import member_model
from .unittest_config import unittest_chain_config
from .. import config
from src.utils import hash_utils
import src.messages.messages_pb2 as pb

def get_member():
    return member_model.MemberModel.new(genkey=True)

def get_random_hash():
    return hash_utils.hash_std("sad")

class TestMember(unittest.TestCase):

    def test_member_init(self):
        a = get_member()
        self.assertIsNotNone(a.signing_key, 'signing_key is none')
        self.assertIsNotNone(a.verify_key, 'verify_key is none')
        self.assertIsNotNone(a.mid, 'mid is none')

    def test_member_from_verify_key(self):
        m = get_member()
        vk = m.verify_key
        n = member_model.MemberModel.get_verify_member(vk)
        msg1 = "msg1"
        msg2 = "msg2"
        self.assertTrue(n.verify(msg1, m.sign(msg1)))
        self.assertFalse(n.verify(msg1, m.sign(msg2)))
        vk = m.verify_key_str
        n = member_model.MemberModel.get_verify_member(vk)
        self.assertTrue(n.verify(msg1, m.sign(msg1)))
        self.assertFalse(n.verify(msg1, m.sign(msg2)))

    def test_member_model(self):
        a = get_member()
        b = json.dumps(a, default=member_model.MemberModel.obj2dict_without_signingkey)
        c = json.loads(b, object_hook=member_model.MemberModel.dict2obj)
        msg = "1234"
        self.assertTrue(c.verify(msg, a.sign(msg)))
        self.assertFalse( c.verify(msg, a.sign("dasd")))
        b = a
        a = c
        c = b
        # c.verify(msg, a.sign(msg))
        path = os.path.join(unittest_chain_config.tmp_output_dir, "member_config.txt")
        c.write_to_path(path, except_signing_key=False)
        c = a
        a = member_model.MemberModel.new(False, path)
        self.assertTrue(c.verify(msg, a.sign(msg)))
        a = member_model.MemberModel.new(True)
        self.assertFalse(c.verify(msg, a.sign(msg)))
        os.remove(path)

from ..model import transaction_model

def get_input():
    ip = transaction_model.Transaction.Input.new(transaction_hash="transaction_hash", transaction_idx=0, script=pb.Script())
    return ip

def get_output():
    op = transaction_model.Transaction.Output.new(1, pb.Script())
    return op

def get_tx():
    tx = transaction_model.Transaction()
    tx.add_inputs([get_input()])
    tx.add_outputs([get_output()])
    return tx
    
class TestTransaction(unittest.TestCase):

    def test_txs_dump_load(self):
        tx = get_tx()
        tx_str = json.dumps(tx, default=tx.obj2dict)
        t2 = json.loads(tx_str, object_hook=tx.dict2obj)
        tx2_str = json.dumps(t2, default=t2.obj2dict)
        self.assertEqual(tx.hash, t2.hash)

    def test_transaction_init(self):
        ip = get_input()
        op = get_output()
        tx = get_tx()
        self.assertIsInstance(tx, transaction_model.Transaction)

    def test_transaction_add_ioput(self):
        ip = get_input()
        op = get_output()
        tx = get_tx()
        tx.add_inputs([ip])
        tx.add_outputs([op])

    def test_output_init(self):
        op = get_output()
        self.assertIsInstance(op, transaction_model.Transaction.Output)

    def test_input_init(self):
        ip = get_input()
        self.assertIsInstance(ip, transaction_model.Transaction.Input)

    def test_get_transaction_sign_source(self):
        pass

    def test_verify_sig_in_inputs(self):
        pass
    
    def test_add_input_script(self):
        pass

    def test_add_outputs(self):
        pass

    def test_complete_transaction(self):
        pass

    
        
def get_block():
    b = block_model.Block.new("prev_hash", "q")
    b.add_transactions([get_tx(), get_tx()])
    member = member_model.MemberModel.new(genkey=True)
    b.director_sign(member, "prev_q")
    return b

from ..model import block_model
class TestBlock(unittest.TestCase):
    
    def test_init(self):
        b = block_model.Block.new("prev_hash","q")

    def test_get_merkle_root(self):
        b = get_block()
        # b.merkle_root
        # assert not b.merkle_root
        self.assertIsNotNone(b.merkle_root)

    def test_get_hash(self):
        b = get_block()
        # b.merkle_root
        # assert not b.merkle_root
        self.assertIsNotNone(b.hash)

    def test_block_json_dumps(self):
        b = get_block()
        bjd = json.dumps(b, default=block_model.Block.obj2dict)
        b2 = json.loads(bjd, object_hook=block_model.Block.dict2obj)
        self.assertEqual( b.hash, b2.hash)

    def test_block_write_down(self):
        path = os.path.join(unittest_chain_config.tmp_output_dir, "0")
        b = get_block()
        block_model.dump_blocks([b], path)

        b2 = block_model.load_blocks(path)
        self.assertEqual(b2[0].hash, b.hash)
        os.remove(path)

    def test_director_sign_verify(self):
        b = get_block()
        m = get_member()
        b.director_sign(m, "prev_q")
        self.assertTrue(b.director_verify("prev_q"))

    def test_get_genic_blocks(self):
        ls = get_genic_blocks()        
        blocks_path = unittest_chain_config.genic_chain_path
        with open(blocks_path, 'r') as f:
            dic = json.load(f)
        # print dic
        dic_obj = [ls[0].dict2obj(x) for x in dic ]
        for i in range(ls.__len__()):
            # ls[i].cal_hash()
            # dic_obj[i].cal_hash()
            self.assertEqual(dic_obj[i].hash, ls[i].hash)

from ..model import chain_model

def get_genic_blocks():
    blocks_path = unittest_chain_config.genic_chain_path
    bs = block_model.load_blocks(blocks_path)
    for b in bs:
        assert isinstance(b, block_model.Block)
    return bs

def get_ledger():
    ledger = chain_model.Chain.new()
    bs = get_genic_blocks()
    ledger.set_ledger(bs, None)
    return ledger

class TestLedger(unittest.TestCase):

    def test_get_ledger(self):
        l = get_ledger()        
        self.assertIsInstance(l, chain_model.Chain)
        b = l.last_block
        self.assertEquals(b.transactions.__len__(), 1)
        tx = b.transactions[-1]
        self.assertEquals(tx.outputs.__len__(), 1)
        # tx = b.txs[]

    def test_cal_senates(self):
        l = get_ledger()
        print l.senates
        # FUTURE: after stable ledger   
        pass

