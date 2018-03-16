#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# protobufwrapper.py ---
#
# @Filename: protobufwrapper.py
# @Description: 
# @Author: Weijie Li
# @Created time: 2018-03-16 13:27:07
# @Last Modified by: 
# @Last Modified time:

from utils import hash_utils

class ProtobufWrapper(object):
    def __init__(self, x):
        """
        The argument `x`, or `self.pb`, is the only data that gets serialized.
        :param x: 
        """
        self.pb = x
        self._str = None
        self._hash = None

    # def to_str(self):
    #     """ToString() == self.pb.SerializeToString()"""
    #     return self.pb.SerializeToString()

    # def __eq__(self, other):
    #     pass

    # def __ne__(self, other):
    #     return not self.__eq__(other)

    # def __hash__(self):
    #     return hash(self.SerializeToString())

    def on_change(self):
        self._str = None
        self._hash = None

    def SerializeToString(self):
        if self._str is None:
            self._str = self.pb.SerializeToString()
        return self._str
    
    def __str__(self):
        return str(self.pb)

    @property
    def hash(self):
        # type: () -> str
        # return hash(self.SerializeToString())
        if self._hash is None:
            self._hash = hash_utils.hash_std(self.SerializeToString())
        return self._hash