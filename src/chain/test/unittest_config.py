#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# unittest_config ---
#
# @Filename: unittest_config
# @Description: 
# @Author: Weijie Li
# @Created time: 2018-02-27 11:29:22
# @Last Modified by: 
# @Last Modified time: 

import os


tmp_output_dir = 'tmp'
# config_dir = 'config'
test_data_dir = "src/chain/test/data"

members_dir = os.path.join(test_data_dir,  'members')
blocks_path = os.path.join(test_data_dir,  'blocks.json')
genic_block_path = os.path.join(test_data_dir, "genic_blocks.json")

test_block_path = os.path.join(test_data_dir, "test_blocks.json")

