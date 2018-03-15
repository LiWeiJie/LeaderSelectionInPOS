#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# payload_base.py ---
#
# @Filename: payload_base.py
# @Description: 
# @Author: Weijie Li
# @Created time: 2018-02-21 15:20:37
# @Last Modified by: 
# @Last Modified time: 

from ..model import member_model

import json
import binascii
import logging

from ..utils import hash_utils

class PayloadBase(object):

    def __init__(self, sender, destination, signature=None, payload_name="PayloadBase", timestamp=0, msg="simple message"):
        self._payload_name = payload_name.encode('utf-8')
        self._authentication = self.Authentication(sender, signature)
        self._destination = destination
        self._timestamp = 0
        self._msg = msg.encode('utf-8')
    
    @property
    def payload_name(self):
        return self._payload_name

    class Authentication(object):
        
        def __init__(self, sender, signature=None):
            assert isinstance(sender, member_model.MemberModel), type(sender)
            self._sender = sender
            self._signature = signature

        @property
        def sender(self):
            return self._sender
        
        @property
        def signature(self):
            return self._signature

        def add_signature(self, signature):
            self._signature = signature

        def sign(self, data):
            sign_data = self.sender.sign(data)
            # logging.info("data: %s"%data)
            # logging.info("signed_data: %s, type%s"%(sign_data, type(sign_data)))
            return sign_data
        
        def verify(self, data):
            verify_data = self.signature
            # logging.info("data: %s"%data)
            # logging.info("verify_data: %s"%verify_data)
            return self.sender.verify(data, verify_data)

        @classmethod
        def obj2dict(cls, obj):
            return {
                "sender": json.dumps(obj.sender, default=member_model.MemberModel.obj2dict),
                "signature": obj.signature
            }
    
        @classmethod
        def dict2obj(cls, dic):
            sender = json.loads(dic['sender'], object_hook=member_model.MemberModel.dict2obj)
            signature = dic["signature"]
            return cls(sender, signature)

    @property
    def authentication(self):
        return self._authentication

    @property
    def destination(self):
        return self._destination
    
    @property
    def timestamp(self):
        return self._timestamp

    @property
    def msg(self):
        return self._msg

    def raw_data(self):
        """without the authentication and the function is for sign"""
        raw_dict = self.obj2dict(self)
        raw_dict["authentication"] = None
        raw_dict = json.dumps(raw_dict)
        return hash_utils.hash_std(raw_dict)
    
    def add_signature(self):
        raw_data = self.raw_data()
        signature = self.authentication.sign(raw_data)
        self.authentication.add_signature(signature)

    def verify(self):
        if self.authentication.signature:
            raw_data = self.raw_data()
            return self.authentication.verify(raw_data)
        return False 

    @classmethod
    def obj2dict(cls, payload):
        dest = payload.destination
        if isinstance(dest, member_model.BroadcastMember):
            dest = None
        else:
            dest = json.dumps(dest, default=member_model.MemberModel.obj2dict_without_signingkey)
        return {
            "payload_name": payload.payload_name,
            "authentication": json.dumps(payload.authentication, default=cls.Authentication.obj2dict),
            # "authentication": payload.authentication.authentication2dict(payload.authentication),
            "destination": dest,
            # "destination": [member_model.MemberModel.member2dict_without_signingkey(dest) for dest in payload.destination],
            "timestamp": payload.timestamp,
            "msg": payload.msg
        }
    
    @classmethod
    def dict2obj(cls, dic):
        assert dic.has_key("payload_name")
        payload_name = dic["payload_name"]
        authentication = json.loads(dic["authentication"], object_hook=cls.Authentication.dict2obj)
        destination = None
        if dic["destination"]:
            print dic["destination"]
            destination = json.loads(dic["destination"], object_hook=member_model.MemberModel.dict2obj) 
        else:
            destination = member_model.BroadcastMember()
        timestamp = dic["timestamp"]
        msg = dic["msg"]
        return cls( payload_name=payload_name,
                            sender=authentication.sender,
                            destination=destination,
                            signature=authentication.signature,
                            timestamp=timestamp,
                            msg=msg)



if __name__=="__main__":
    print("%s test"%__package__)
    member_a = member_model.MemberModel(True)
    member_b = member_model.MemberModel(True)
    a = PayloadBase(member_a, [member_b])
    print("Test add signature and verify: ")
    assert not a.verify()
    a.add_signature()
    assert a.verify()
    print("PASS")    
    print("Test dict to obj and invert: ")
    b = PayloadBase.dict2obj(PayloadBase.obj2dict(a))
    catch = False
    try:
        b.add_signature()
    except RuntimeError:
        catch = True
    finally:
        assert catch
    b.verify()
    print("PASS")

    

    