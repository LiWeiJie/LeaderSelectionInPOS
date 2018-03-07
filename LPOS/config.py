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