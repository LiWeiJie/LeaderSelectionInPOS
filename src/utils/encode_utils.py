#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# encode_utils.py ---
#
# @Filename: encode_utils.py
# @Description: 
# @Author: Weijie Li
# @Created time: 2018-03-18 14:54:50
# @Last Modified by: 
# @Last Modified time: 

from base64 import urlsafe_b64encode as b64e
from base64 import urlsafe_b64decode as b64d

def json_bytes_dumps(bytes_data):
    return b64e(bytes_data)

def json_bytes_loads(bytes_unicode_data):
    return b64d(bytes_unicode_data.encode('utf-8'))

