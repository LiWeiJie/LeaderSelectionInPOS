#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# hash_utils.py ---
#
# @Filename: hash_utils.py
# @Description: 
# @Author: Weijie Li
# @Created time: 2018-02-26 13:13:34
# @Last Modified by: 
# @Last Modified time: 

import hashlib

def hash_once(data):
    """hash once by sha256"""
    return hashlib.sha256(data).digest()

def hash_twice(data):
    """hash twice by sha256"""
    return hash_once(hash_once(data))

def hash_std(data):
    """standard hash, hash twice"""
    return hash_twice(data)

class HashCase(object):

    def __init__():
        self._h = hashlib.sha256()
    
    def update(data):
        self._h.update(data)

    def hexdigest(data):
        return self._h.hexdigest()