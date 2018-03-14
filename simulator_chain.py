#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# simulator.py  ---
#
# @Filename: simulator.py  
# @Description: 
# @Author: Weijie Li
# @Created time: 2018-03-02 14:52:10
# @Last Modified by: 
# @Last Modified time: 

from src.chain  import client

from src.chain.config import config_loader

from src.chain.model import member_model
from src.chain.model import block_model
from src.chain.model import transaction_model
from src.chain.model import ledger_model

from src.chain.utils import hash_utils
from src.chain.utils import random_utils

import os
import time
import line_profiler
import sys

import logging
import sys

def set_logging_stdout():
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    root.addHandler(ch)
set_logging_stdout()

import json
def gen_some_member(member_dir, number=10, in_a_file=True):
    if  in_a_file:
        datas = []
        members = []
        path=os.path.join(member_dir, "members.json")
        for no in range(number):
            member = member_model.MemberModel(True)
            members.append(member)
            datas.append(member.dumps(except_signing_key=False))
        with open(path, "w") as f:
            json.dump(datas, f)

        # check
        datas = None
        with open(path, "r") as f:
            datas = json.load(f)
        ct = 0
        for data in datas:
            m = member_model.MemberModel.loads(data)
            assert(m.mid == members[ct].mid)
            ct += 1
        

    else:
        for no in range(number):
            detail_path= os.path.join(member_dir, no.__str__()+".json")
            member = member_model.MemberModel(True)
            logging.info("{}".format(member))
            member.write_to_path(detail_path, except_signing_key=False)
            # check
            with open(detail_path, "r") as f:
                member2 = member_model.MemberModel.load(f)
                assert(member2.mid == member.mid)

def gen_genic_block(path, owner_path):
    member = member_model.MemberModel(key_path=owner_path)
    tx = transaction_model.Transaction()
    op = transaction_model.Transaction.Output(1000.0, "verifyKeyStr", member.verify_key_str)
    tx.add_outputs([op])
    b = block_model.Block("prev_hash", hash_utils.hash_std("genic block"))
    b.add_transactions([tx])
    b.director_sign(member=member, prev_q="prev_q")
    block_model.dump_blocks([b], path)

# import simulator
# path = "config/blocks2.json"
# member_path = "config/members/0.json"
# simulator.gen_genic_block(path, member_path)

members_notebook = []
def load_predine_members():
    members_dir = config_loader['pre_members_dir']
    members_path = [os.path.join(members_dir, i.__str__()+".json") for i in range(10)]
    total_member_ct = 10
    members = [member_model.MemberModel(False,  key_path=os.path.join(members_dir, i.__str__()+".json")) for i in range(total_member_ct)]
    return members

def load_predine_chains(members):
    blocks_path = config_loader['blocks_path']
    # blocks_path = "config/long_blocks.json"
    clients = [client.Client(member=member, blocks_path=blocks_path) for member in members ]
    return clients


def rreload(module):
    """Recursively reload modules."""
    reload(module)
    for attribute_name in dir(module):
        attribute = getattr(module, attribute_name)
        import types
        if type(attribute) is types.ModuleType:
            rreload(attribute)

def collect_transaction(clients, verbose=False):
    collects = []
    for cli in clients:
        if random_utils.rand_true_false():
            m_satoshi = cli.my_satoshi
            rand_one = random_utils.rand_one(m_satoshi)
            if rand_one:
                utx_header, output = rand_one
                dest = random_utils.rand_one(members_notebook)
                cli_inputs = cli.create_inputs([utx_header])
                rand_out_amount = output.value * random_utils.rand_percent()
                rand_out_amount = round(rand_out_amount)
                rand_remains_amount = output.value-rand_out_amount
                cli_outputs = cli.create_outputs( [(rand_remains_amount, "verifyKeyStr", cli.member.verify_key_str ), (rand_out_amount, "verifyKeyStr", dest.verify_key_str )] )
                cli_tx = cli.create_transaction(cli_inputs, cli_outputs)
                collects.append(cli_tx)
    return collects

def collect_director_competition(clients, verbose=False):
    collects = []
    for cli in clients:
        if random_utils.rand_true_false():
            my_satoshi = cli.my_satoshi
            one = random_utils.rand_one(my_satoshi)
            if one:
                ret = cli.get_director_competition_signature(one[0][0], one[0][1])
                if ret:
                    collects.append(ret)
    return collects

def collect_senate_sign(clients, block, verbose=False):
    collects = []
    for cli in clients:
        if cli.is_senate:
            ret = cli.senate_sign(block)
            if ret:
                import copy
                cli.set_cooking_block(copy.copy(block))
                collects.append(ret)
    return collects

    
def simulation_one_round(clients, verbose=False):
    
    for client in clients:
        if client.member not in members_notebook:
            members_notebook.append(member)

    #  broadcast senate

    # received transactions
    start = time.time()
    message = collect_transaction(clients, verbose=verbose)
    end = time.time()
    print "collect_transaction cost", end-start, "secs"
    print "transactions %d:"%message.__len__()

    # send to clients
    start = time.time()
    for cli in clients:
        cli.receive_transactions(message)
    end = time.time()
    print "receive_transactions cost", end-start, "secs"

    # competite the director
    start = time.time()
    message = collect_director_competition(clients, verbose=verbose)
    end = time.time()
    print "collect_director_competition cost", end-start, "secs"
    print "director competition %d:"%message.__len__(), message

    # send to clients
    start = time.time()
    for cli in clients:
        for (signature, txo_idx) in message:
            cli.receive_director_competition(signature, txo_idx)
    end = time.time()
    print "receive_director_competition cost", end-start, "secs"
    
    # senates with other clients

    # leader gen prototype
    start = time.time()
    block = None
    for cli in clients:
        if cli.is_senate_leader:
            block = cli.create_block()
            cli.set_cooking_block(block)
            # print cli.get_cooking_block().director
    end = time.time()
    print "create block cost", end-start, "secs"
            
    # send to senates, will using pbft in remote mode
    start = time.time()
    responses = collect_senate_sign(clients=clients, block=block, verbose=verbose)
    end = time.time()
    print "collect_senate_sign cost", end-start, "secs"
    print "senate's signatures %d:"%responses.__len__(), responses

    # response to senate leader
    start = time.time()
    for cli in clients:
        if cli.is_senate_leader:
            for (signatory, signature) in responses:
                cli.add_senate_signature(signatory, signature)
    end = time.time()
    print "add_senate_signature cost", end-start, "secs"
    
    start = time.time()
    # get final block
    block = None
    for cli in clients:
        if cli.is_senate_leader:
            block = cli.get_cooking_block()
    end = time.time()
    print "get_cooking_block cost", end-start, "secs"

    # sent to director
    start = time.time()
    message = []
    for cli in clients:
            signed = cli.director_sign(block)
            if signed:
                message.append(signed)
    end = time.time()
    print "director_sign cost", end-start, "secs"
    print "director sign %d:"%message.__len__(), message

    start = time.time()
    block = message[0]
    for cli in clients:
        cli.add_block(block)
    end = time.time()
    print "add_block cost", end-start, "secs"

    for cli in clients:
        print "satoshi %d:"%cli.my_satoshi_total, cli.my_satoshi    
    
if __name__=="__main__":
    # prof = line_profiler.LineProfiler()
    # prof.add_function(simulation_one_round)
    # prof.add_module(ledger_model.Ledger.add_block)
    # prof.add_module(ledger_model.Ledger.add_blocks)
    # line_profiler.LineProfiler()
    # prof.enable()  # 开始性能分析

    members = load_predine_members()
    clients = load_predine_chains(members)
    simulation_one_round(clients, verbose=False)
    # prof.disable()  # 停止性能分析
    # prof.print_stats(sys.stdout)
    # with open("analysis.log", 'w') as f:
        # prof.print_stats(f)
    # import simulator