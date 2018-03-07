#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# message.py ---
#
# @Filename: message.py
# @Description: 
# @Author: Weijie Li
# @Created time: 2018-02-22 10:49:18
# @Last Modified by: 
# @Last Modified time: 

import json

class Message(object):
    def __init__(self, handler, payload_class, id=None):
        self.handler = handler
        self.payload_class = payload_class
        self.id = id
    
    def get_payload(self, payload=()):
        return self.payload_class(*payload)

    def get_payload_by_dict(self, payload_dict):
        payload = json.loads(payload_dict, object_hook=self.payload_class.dict2payload)
        assert isinstance(payload, self.payload_class), type(payload)
        return payload

if __name__=="__main__":
    from ..payload import payload_base
    print("%s test"%__package__)
    ms = Message(None, None, "MS")
    meta_messages = {
        "a":Message(ms.handler_print, Message, "a"),
        "b":Message(ms.handler_print, Message, "b"),
    }
    protocol = 'a'
    if protocol in meta_messages:
        meta_messages[protocol].handler()
        meta_messages[protocol].payload_class(1,2,3).handler_print()
    message = meta_messages['a']
    print message
    print("PASS")

    