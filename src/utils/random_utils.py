#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# random_utils.py ---
#
# @Filename: random_utils.py
# @Description: 
# @Author: Weijie Li
# @Created time: 2018-02-28 11:03:22
# @Last Modified by: 
# @Last Modified time: 

import random
import time

random.seed(time.time())

def rand_int(a, b):
    """return a integer N that a <= N < B"""
    return random.randint(a, b-1)

def rand_percent():
    """Return the next random floating point number in the range [0.0, 1.0)."""
    return random.random()

def rand_true_false():
    if rand_int(0,2):
        return True
    else:
        return False

def rand_one(object_list):
    """return one from the list randomly"""
    if isinstance(object_list, list):
        s = object_list
    elif isinstance(object_list, dict):
        s = object_list.items()
    else:
        s = None
    if s and s.__len__()>0:
        idx = rand_int(0, s.__len__())
        return s[idx]
    return None
