#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# script_utils.py ---
#
# @Filename: script_utils.py
# @Description: 
# @Author: Weijie Li
# @Created time: 2018-03-18 17:35:59
# @Last Modified by: 
# @Last Modified time: 

import src.messages.messages_pb2 as pb

def script_to_verify_key(vk): 
    return pb.Script(body=[pb.ScriptUnit(type=pb.SCRIPT_DATA, data=vk),
                           pb.ScriptUnit(type=pb.SCRIPT_CHECK_SIG)])

def script_to_member(member):
    return script_to_verify_key(member.verify_key_str)

def script_to_sig(member, data):
    signature = member.sign(data)
    return pb.Script(body= [pb.ScriptUnit(type=pb.SCRIPT_DATA, data=signature)])