#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# client_test.py ---
#
# @Filename: client_test.py
# @Description: 
# @Author: Weijie Li
# @Created time: 2018-02-26 17:10:45
# @Last Modified by: 
# @Last Modified time: 

import unittest
import os
import json

from .. import client
from ..payload import payload_base
from ..model import member_model

from .unittest_config import unittest_chain_config

from src.utils import random_utils

import src.messages.messages_pb2 as pb

class TestClient(unittest.TestCase):
    
    def setUp(self):
        members = unittest_chain_config.get_members(10)
        clients = [client.Client(member=member, blocks_path=unittest_chain_config.genic_chain_path) for member in members ]
        self._genic_clients = clients
        self._members = members

        clients = [client.Client(member=member, blocks_path=unittest_chain_config.ten_rich_man_chain_path) for member in members ]
        self._clients = clients

    def tearDown(self):
        pass
    
    def test_load_client_member_path(self):
        clients = [client.Client(member=member) for member in unittest_chain_config.get_members(10) ]
        for cli in clients:
            self.assertIsInstance(cli, client.Client)
            msg = 'abc'
            member = cli.member
            self.assertTrue(member.verify(msg, member.sign(msg)))

    def test_clients_local(self, verbose=False):
        if verbose:
            print("=== test_clients_local ===")
        members = self._members
        clients = self._genic_clients
        leader_client = clients[0]

        # gen transaction
        leader_satoshi = leader_client.my_satoshi
        if verbose:
            print leader_satoshi
        spend_satoshi = leader_satoshi.items()[0]
        spend_token = spend_satoshi[0]
        spend_txo = spend_satoshi[1]
        ips = leader_client.create_inputs( [spend_token])
        ops = leader_client.create_outputs( [(100, pb.SCRIPT_TYPE_VK, client.member.verify_key_str ) for client in clients] )
        c_tx = leader_client.create_transaction(ips, ops)
        sign_source = c_tx.get_transaction_sign_source()
        c_tx.add_input_script(0 , leader_client.member.sign(sign_source), leader_client.member.verify_key_str)
        self.assertTrue(c_tx.verify_sig_in_inputs([spend_txo]))

        # two method create block
        # method 1
        cli_ret = []
        for cli in clients:
            if cli.is_senate_leader:
                cli_ret.append(leader_client.create_block([c_tx]) )
        self.assertEqual(cli_ret.__len__(), 1)
        b1 = cli_ret[0]
        # method 2
        cli_ret = []
        for cli in clients:
            cli.receive_transactions([c_tx])
        for cli in clients:
            if cli.is_senate_leader:
                cli_ret.append(leader_client.create_block() )
        self.assertEqual(cli_ret.__len__(), 1)
        b2 = cli_ret[0]

        self.assertEqual(b1.hash, b2.hash)

        import copy
        for cli in clients:
            cli.set_cooking_block(copy.copy(b2))

        
        # director_competitions = []
        for cli in clients:
            my_satoshi = cli.my_satoshi
            one = random_utils.rand_one(my_satoshi)
            if one:
                print 'one', one
                ret = cli.get_director_competition_signature(one[0][0], one[0][1])
                if ret:
                    for clicli in clients:
                        clicli.receive_director_competition(ret[0], ret[1])
                    # director_competitions.append(ret)
        # print director_competitions
        
        # competition director
        ret = []
        for cli in clients:
            if cli.is_senate_leader:
                ret.append(cli.add_director())
        self.assertEqual(ret.__len__(), 1)
        b2 = ret[0]
                

        # senates sign
        accepted_message = []
        for cli in clients:
            signed = cli.senate_sign(b2)
            if signed:
                accepted_message.append(signed)
        if verbose:
            print accepted_message

        for cli in clients:
            if cli.is_senate_leader:
                for am in accepted_message:
                    cli.add_senate_signature(am[0], am[1])

        b = None
        for cli in clients:
            if cli.is_senate_leader:
                b = cli.get_cooking_block()
        
        # director sign
        director_signed_block = []
        for cli in clients:
            signed = cli.director_sign(b)
            if signed:
                director_signed_block.append(signed)
        self.assertEqual(director_signed_block.__len__(), 1)
        if verbose:
            print "director sign" , director_signed_block

        self.assertTrue(leader_client.ledger.verify_block(b2))

        # add block
        for cli in clients:
            cli.add_block(b)

        self.assertFalse(leader_client.ledger.verify_block(b))        

        for cli in clients:
            self.assertEqual(cli.my_satoshi_total, 100)

        if verbose:
            print ips
            print ops

            i = 0
            for cli in clients:
                print cli.last_block.q
                print i, cli.my_satoshi, cli.ledger.senates
                i += 1
            print("=== test_clients_local ===")
        
        leader_client.ledger.dump_blocks(os.path.join(unittest_chain_config.tmp_output_dir, "clients_local.json"))
        


    def test_load_client(self, verbose=False):
        if verbose:
            print("=== test_load_client ===")        
        members = unittest_chain_config.get_members(10)
        for member in members:
            self.assertIsNotNone(  member.signing_key   )
        clients = [client.Client(member) for member in members ]
        for cli in clients:
            self.assertIsInstance(cli, client.Client)
            self.assertIn( cli.member, members)
        if verbose:
            print("=== test_load_client ===")
        
    
    # def test_client_handle_senate(self, verbose=False):
    #     if verbose:        
    #         print("=== test_client_handle_senate ===")

    #     def send_protocols(cli, dests, protocol, data):
    #         ret = cli.handle_protocols(dests, protocol, data)
    #         return ret

    #     members = unittest_chain_config.get_members(10)
    #     blocks_path = unittest_chain_config.genic_chain_path

    #     clients = [client.Client(member=member, blocks_path= blocks_path) for member in members ]

    #     client0 = clients[0]
    #     client1 = clients[1]
        
    #     member0 = members[0]
    #     member1 = members[1]

    #     a = payload_base.PayloadBase(sender=member0,
    #                                                 destination=member_model.BroadcastMember())
    #     a.add_signature()
    #     a.verify()
    #     # print "38 ", a
    #     dic_a = json.dumps(a, default=payload_base.PayloadBase.obj2dict)
    #     # print "s ", dic_a
    #     print dic_a
    #     b = json.loads(dic_a, object_hook=payload_base.PayloadBase.dict2obj)
    #     # print b


    #     dest, protocol, data = client0.send_senate_broadcast()
    #     # print "f ", data
    #     if dest:
    #         sender, (dest, protocol, data) = ret = send_protocols(client0, dest, protocol, data)
    #         # all None
    #         self.assertEqual(sender, client0.member.verify_key_str)
    #         self.assertEqual(dest, protocol)
    #         self.assertEqual(dest, data)
    #         if verbose:        
    #             print ret
    #     if verbose:        
    #         print("=== test_client_handle_senate ===")
        