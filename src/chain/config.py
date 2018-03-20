#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# config.py ---
#
# @Filename: config.py
# @Description: 
# @Author: Weijie Li
# @Created time: 2018-02-27 15:21:36
# @Last Modified by: 
# @Last Modified time: 

import json
import os

from .model import member_model

default_config_path = 'config/config.json'

# default parameter
config_loader = {
    "senates_number": 10
}

if os.path.exists(default_config_path):
    with open(default_config_path, 'r') as f:
        j = json.load(f)
        for k, v in j.iteritems():
            config_loader[k] = v

class chain_config(object):

    senates_number = int(config_loader["senates_number"])
    pre_members_dir = config_loader["pre_members_dir"]
    pre_members_path = config_loader["pre_members_path"]
    blocks_path = config_loader["blocks_path"]
    genic_chain_path = config_loader["genic_chain_path"]
    ten_rich_man_chain_path = config_loader["10_rich_man_chain"]

    @classmethod
    def get_members(cls, number=10):
        pre_members = []
        pre_members_path = cls.pre_members_path
        ct = 1
        if number == 0:
            return []
        if pre_members_path and os.path.exists(pre_members_path):
            with open(pre_members_path, 'r') as f:
                j = json.load(f)
                for m in j:
                    pre_members.append( member_model.MemberModel.loads(m) )
                    ct += 1
                    if number and ct > number:
                        return pre_members
                    
        return pre_members

    @classmethod
    def get_member_by_idx(cls, idx):
        """start from 0, up to 299"""
        assert(idx>=0 and idx <300)
        pre_member = None
        pre_members_path = cls.pre_members_path
        if pre_members_path and os.path.exists(pre_members_path):
            with open(pre_members_path, 'r') as f:
                j = json.load(f)
                pre_member = member_model.MemberModel.loads( j[idx] )
        return pre_member 

        # @classmethod
        # def get_genic_chain(cls):
        #     genic_chain = cls.genic_chain
        #     if genic_chain and os.path.exists(genic_chain):
        #     with open(genic_chain, 'r') as f:
        #         j = json.load(f)
        #         pre_member = member_model.MemberModel.loads( j[idx] )
        # return pre_member 

