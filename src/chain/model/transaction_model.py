#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# transaction_model.py ---
#
# @Filename: transaction_model.py
# @Description: 
# @Author: Weijie Li
# @Created time: 2018-02-23 12:01:27
# @Last Modified by: 
# @Last Modified time: 

import json
from src.utils import hash_utils
import src.messages.messages_pb2 as pb
from src.protobufwrapper import ProtobufWrapper
import logging

TransactionOutputScriptOP = [
    "verifyKeyStr",    # 0
]

class Transaction(ProtobufWrapper):


    def __init__(self):
        self._inputs = []
        self._outputs = []
        # self._version = None
        # self._locktime = None
        self._hash = None

    def on_change(self):
        self.clean_hash()

    def add_inputs(self, inputs):
        order_list = []
        order = self._inputs.__len__()
        for input in inputs:
            assert isinstance(input, Transaction.Input), type(input)
            self._inputs.append(input)
            order_list.append(order)
            order += 1
        self.on_change()
        return order_list

    def add_input_script(self, input_idx, signature, signatory):
        """
        script =  signature + " " + signatory
        """
        script = signature + " " + signatory
        self.inputs[input_idx].set_script(script)
        self.on_change()

    def add_outputs(self, outputs):
        for output in outputs:
            assert isinstance(output, Transaction.Output), type(output)
            self._outputs.append(output)
        self.on_change()

    def get_transaction_sign_source(self):
        data = []
        for ip in self.inputs:
            data.append((ip.transaction_hash, ip.transaction_idx))
        
        for op in self.outputs:
            data.append((op.value, op.script, op.addresses))
        
        return json.dumps(data)
        
    def verify_sig_in_inputs(self, prev_outputs):
        """
        @prev_outputs corresponding to the inputs
        and check the inputs satoshi >= outputs
        """
        data = self.get_transaction_sign_source()
        inputs = self.inputs
        if inputs.__len__() != prev_outputs.__len__():
            logging.info("len not equal {}/{}".format(inputs.__len__(), prev_outputs.__len__()))
            return False
        sz = prev_outputs.__len__()
        input_satoshi = 0
        for i in range(sz):
            ip = inputs[i]
            op = prev_outputs[i]
            
            # FUTURE: find a better way
            ip_script = ip.script.split()
            # verify_pem_start_pos = ip_script.find('-----BEGIN')
            # ip_sig = ip_script[:verify_pem_start_pos-1]
            # ip_verify_key = ip_script[verify_pem_start_pos:]
            ip_sig=ip_script[0]
            ip_verify_key = ip_script[1]

            input_satoshi += op.value

            op_script = op.script
            op_addresses = op.addresses
            result = True
            if op_script in TransactionOutputScriptOP:
                # verifyKey
                if TransactionOutputScriptOP.index(op_script)==0:
                    if op_addresses!=ip_verify_key:
                        logging.info("verify_key fail")
                        result = False
                    from . import member_model
                    member = member_model.MemberModel.get_verify_member(ip_verify_key)
                    if not member.verify(data, ip_sig):
                        logging.info("member fail")
                        result = False 
                else:
                    # FUTURE:
                    pass
            else:
                logging.info("script type fail")
                result = False
            if not result:
                return result

        for op in self.outputs:
            input_satoshi -= op.value
        
        if input_satoshi>=0:
            return True
        else:
            logging.info("satoshi {}".format(input_satoshi))
            # for i in range(sz):
            #     print "in:",prev_outputs[i].value
            # for op in self.outputs:
            #     print "out:", op.value
            return False

    def clean_hash(self):
        self._hash = None

    @property
    def hash(self):
        if not self._hash:
            self.cal_hash()
        return self._hash

    @property
    def inputs(self):
        """inputs = [
            input = {
                transaction_hash,
                transaction_idx,
                script=None
                hash // cal by itself
            }
            ...
        ]
        """
        return self._inputs
    
    @property
    def outputs(self):
        """outputs = [
            output = {
                value,
                script,
                addresses
                hash // cal by itself
            }
            ...
        ]
        """
        return self._outputs

    @property
    def n_inputs(self):
        return self.inputs.__len__()

    @property
    def n_outputs(self):
        return self.outputs.__len__()

    def cal_hash(self):
        # header = []

        # inputs = self._inputs
        # outputs = self._outputs

        # for input in inputs:
        #     header.append(input.hash)
        # for output in outputs:
        #     header.append(output.hash)

        # head_data = json.dumps(header, sort_keys=True)

        head_data = ""
        for input in self.inputs:
            head_data += input.hash
        for output in self.outputs:
            head_data += output.hash

        self._hash = hash_utils.hash_std( head_data)

    def get_input(self, idx):
        if idx<=self.n_inputs:
            return self._inputs[idx]
        else:
            return None
            
    def get_output(self, idx):
        if idx<=self.n_outputs:
            return self._outputs[idx]
        else:
            return None

    @classmethod
    def obj2dict(cls, obj):
        return {
            "inputs": json.dumps(obj.inputs, default=Transaction.Input.obj2dict),
            "outputs": json.dumps(obj.outputs, default=Transaction.Output.obj2dict),

        }

    @classmethod
    def dict2obj(cls, dic):
        t = Transaction()
        t.add_inputs(json.loads(dic['inputs'], object_hook=Transaction.Input.dict2obj))
        t.add_outputs(json.loads(dic['outputs'], object_hook=Transaction.Output.dict2obj))

        return t

    class Input(object):
        """Represents a transaction input"""

        def __init__(self, transaction_hash, transaction_idx, script=None):
            self._transaction_hash = transaction_hash
            self._transaction_idx = transaction_idx
            self._script = script
            self._hash = None

        def __repr__(self):
            return "Input(%s,%d,%s)" % (self.transaction_hash, self.transaction_idx, self.script)

        @property
        def transaction_hash(self):
            """Returns the hash of the transaction containing the output
            redeemed by this input"""
            return self._transaction_hash

        @property
        def transaction_idx(self):
            """Returns the index of the output inside the transaction that is
            redeemed by this input"""
            return self._transaction_idx

        @property
        def script(self):
            """Returns a Script object representing the redeem script"""
            return self._script

        @property
        def hash(self):
            if not self._hash:
                self.cal_hash()
            return self._hash      

        def set_script(self, script):
            self._script = script
            self._hash = None

        def cal_hash(self):
            # header = [self.transaction_hash, self.transaction_idx, self.script]
            # head_data = json.dumps(header, sort_keys=True)
            head_data = self.transaction_hash + str(self.transaction_idx) + self.script
            self._hash = hash_utils.hash_std(head_data)

        @classmethod
        def obj2dict(cls, obj):
            return {
                "transaction_hash": obj.transaction_hash,
                "transaction_idx": obj.transaction_idx,
                "script": obj.script
            }


        @classmethod
        def dict2obj(cls, dic):
            ip = Transaction.Input( dic['transaction_hash'], 
                                    dic['transaction_idx'],
                                    dic['script'])
            return ip
       

    class Output(object):
        """Represents a Transaction output"""

        def __init__(self, value, script, address):
            """
            @value float or int
            @script in TransactionOutputScriptOP
            @address verify_key_str
            """
            self._value = value
            assert(script in TransactionOutputScriptOP)
            self._script = script
            self._addresses = address
            self._hash = None

        def __repr__(self):
            return "Output(satoshis=%d)" % self.value

        def __cmp__(self, other):
            return cmp(self.hash, other.hash)

        @property
        def value(self):
            """Returns the value of the output exprimed in satoshis"""
            return self._value

        @property
        def script(self):
            return self._script

        @property
        def addresses(self):
            """Returns a list containing all the addresses mentionned
            in the output's script
            """
            return self._addresses

        @property
        def hash(self):
            if not self._hash:
                self.cal_hash()
            return self._hash
           
        def cal_hash(self):
            # header = [self.value, self.script, self.addresses]
            # head_data = json.dumps(header, sort_keys=True)
            head_data = str(self.value) + self.script + self.addresses
            self._hash = hash_utils.hash_std(head_data)

        @classmethod
        def obj2dict(cls, obj):
            return {
                "value": obj.value,
                "script": obj.script,
                "addresses": obj.addresses
            }

        @classmethod
        def dict2obj(cls, dic):
            op = Transaction.Output(dic['value'], 
                                    dic['script'],
                                    dic['addresses'])
            return op

class TxoIndex(object):

    def __init__(self, transaction_hash, transaction_idx):
        self._transaction_hash = transaction_hash
        self._transaction_idx = transaction_idx
    
    def to_str(self):
        return self.transaction_hash+str(self.transaction_idx)
    
    @property
    def transaction_hash(self):
        return self._transaction_hash
    
    @property
    def transaction_idx(self):
        return self._transaction_idx

    @classmethod
    def obj2dict(cls, obj):
        return {
            "transaction_hash": self.transaction_hash,
            "transaction_idx": self.transaction_idx
        }

    @classmethod
    def dict2obj(cls, dic):
        return cls(dic['transaction_hash'], dic['transaction_idx'])