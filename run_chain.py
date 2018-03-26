#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# run.py ---
#
# @Filename: run.py
# @Description: 
# @Author: Weijie Li
# @Created time: 
# @Last Modified by: 
# @Last Modified time: 

from src.chain.config import config_loader
from src.chain import client
import os.path

if __name__=="__main__":
    senates_number = config_loader["senates_number"]
    pre_members_dir = config_loader["pre_members_dir"]
    member_path = os.path.join(pre_members_dir, "0.json")
    blocks_path = config_loader["blocks_path"]
    client = client.Client(member=member_path, blocks_path=blocks_path)
    print client.chain.dumps_blocks()