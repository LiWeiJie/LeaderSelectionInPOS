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

# TransactionOutputScriptOP = [
#     "verifyKeyStr",  # 0
# ]


class Transaction(ProtobufWrapper):

    def __init__(self, pbo=None):
        if pbo == None:
            pbo = pb.Transaction()
        assert (isinstance(pbo, pb.Transaction)), type(pbo)
        super(self.__class__, self).__init__(pbo)
        self._inputs = [Transaction.Input(x) for x in pbo.inputs]
        self._outputs = [Transaction.Output(x) for x in pbo.outputs]
        # self._version = None
        # self._locktime = None

    def on_change(self):
        super(self.__class__, self).on_change()

    def add_inputs(self, inputs):
        # order_list = []
        # order = self._inputs.__len__()
        for input in inputs:
            assert isinstance(input, Transaction.Input), type(input)
            self.pb.inputs.extend([input.pb])
            last_pb = self.pb.inputs[-1]
            self._inputs.append(Transaction.Input(last_pb))
            # order_list.append(order)
            # order += 1
        self.on_change()
        # return order_list

    def add_input_script(self, input_idx, signature, signatory):
        """
        script =  signature + " " + signatory
        """
        script = signature + " " + signatory
        target = self.inputs[input_idx]
        target.set_script(script)
        self.on_change()

    def add_outputs(self, outputs):
        for output in outputs:
            assert isinstance(output, Transaction.Output), type(output)
            self.pb.outputs.extend([output.pb])
            last_pb = self.pb.outputs[-1]
            self._outputs.append(Transaction.Output(last_pb))
        self.on_change()

    def get_transaction_sign_source(self):
        data_str = ""
        for ip in self.inputs:
            ip.pb.script = ""
            data_str += ip.pb.SerializeToString()
            ip.pb.script = ip.script

        for op in self.outputs:
            data_str += op.hash

        return data_str

    def verify_sig_in_inputs(self, prev_outputs):
        """
        @prev_outputs corresponding to the inputs
        and check the inputs satoshi >= outputs
        """
        data = self.get_transaction_sign_source()
        inputs = self.inputs
        if inputs.__len__() != prev_outputs.__len__():
            logging.info("TX: len not equal {}/{}".format(inputs.__len__(), prev_outputs.__len__()))
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
            ip_sig = ip_script[0]
            ip_verify_key = ip_script[1]

            input_satoshi += op.value
            op_script = op.script
            op_addresses = op.address
            result = True
            # verifyKey
            if op_script == pb.SCRIPT_TYPE_VK:
                if op_addresses != ip_verify_key:
                    logging.info("TX: verify_key fail")
                    result = False
                from . import member_model
                member = member_model.MemberModel.get_verify_member(ip_verify_key)
                if not member.verify(data, ip_sig):
                    logging.info("TX: member fail")
                    result = False
            else:
                # FUTURE:
                pass

            if not result:
                return result

        for op in self.outputs:
            input_satoshi -= op.value

        if input_satoshi >= 0:
            return True
        else:
            logging.info("TX: satoshi {}".format(input_satoshi))
            # for i in range(sz):
            #     print "in:",prev_outputs[i].value
            # for op in self.outputs:
            #     print "out:", op.value
            return False

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
                address
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

    # def cal_hash(self):
    #     # header = []
    #
    #     # inputs = self._inputs
    #     # outputs = self._outputs
    #
    #     # for input in inputs:
    #     #     header.append(input.hash)
    #     # for output in outputs:
    #     #     header.append(output.hash)
    #
    #     # head_data = json.dumps(header, sort_keys=True)
    #
    #     head_data = ""
    #     for input in self.inputs:
    #         head_data += input.hash
    #     for output in self.outputs:
    #         head_data += output.hash

        # self._hash = hash_utils.hash_std(head_data)

    def get_input(self, idx):
        if idx <= self.n_inputs:
            return self._inputs[idx]
        else:
            return None

    def get_output(self, idx):
        if idx <= self.n_outputs:
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

    class Input(ProtobufWrapper):
        """Represents a transaction input"""

        def __init__(self, pbo):
            assert (isinstance(pbo, pb.TxInput)), type(pbo)
            super(self.__class__, self).__init__(pbo)
            self._transaction_hash = pbo.transaction_hash
            self._transaction_idx = pbo.transaction_idx
            self._script = pbo.script

        @classmethod
        def new(cls, transaction_hash, transaction_idx, script=""):
            pbti = pb.TxInput(transaction_hash=transaction_hash,
                              transaction_idx=transaction_idx,
                              script=script)
            return cls(pbti)

        # def __repr__(self):
        #     return "Input(%s,%d,%s)" % (self.transaction_hash, self.transaction_idx, self.script)

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

        def on_change(self):
            super(self.__class__, self).on_change()

        def set_script(self, script):
            self._script = script
            self.pb.script = script
            self.on_change()

        @classmethod
        def obj2dict(cls, obj):
            return {
                "transaction_hash": obj.transaction_hash,
                "transaction_idx": obj.transaction_idx,
                "script": obj.script
            }

        @classmethod
        def dict2obj(cls, dic):
            ip = Transaction.Input.new(transaction_hash=dic['transaction_hash'],
                                       transaction_idx=dic['transaction_idx'],
                                       script=dic['script'])
            return ip

    class Output(ProtobufWrapper):
        """Represents a Transaction output"""

        def __init__(self, pbo):
            """
            @value float or int
            @script in TransactionOutputScriptOP
            @address verify_key_str
            """
            assert(isinstance(pbo, pb.TxOutput)), type(pbo)
            super(self.__class__, self).__init__(pbo)
            self._value = pbo.value
            self._script = pbo.script
            self._address = pbo.address

        @classmethod
        def new(cls, value, script, address):
            return cls(pb.TxOutput(value=value,
                                   script=script,
                                   address=address))

        # def __repr__(self):
        #     return "Output(satoshis=%d)" % self.value

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
        def address(self):
            """Returns a list containing all the address mentionned
            in the output's script
            """
            return self._address

        # @property
        # def hash(self):
        #     if not self._hash:
        #         self.cal_hash()
        #     return self._hash
        #
        # def cal_hash(self):
        #     # header = [self.value, self.script, self.address]
        #     # head_data = json.dumps(header, sort_keys=True)
        #     head_data = str(self.value) + self.script + self.address
        #     self._hash = hash_utils.hash_std(head_data)

        @classmethod
        def obj2dict(cls, obj):
            return {
                "value": obj.value,
                "script": obj.script,
                "address": obj.address
            }

        @classmethod
        def dict2obj(cls, dic):
            op = Transaction.Output.new(
                value=dic['value'],
                script=dic['script'],
                address=dic['address'])
            return op


class TxoIndex(object):

    def __init__(self, transaction_hash, transaction_idx):
        self._transaction_hash = transaction_hash
        self._transaction_idx = transaction_idx

    def to_str(self):
        return self.transaction_hash + str(self.transaction_idx)

    @property
    def transaction_hash(self):
        return self._transaction_hash

    @property
    def transaction_idx(self):
        return self._transaction_idx

    @classmethod
    def obj2dict(cls, obj):
        return {
            "transaction_hash": cls.transaction_hash,
            "transaction_idx": cls.transaction_idx
        }

    @classmethod
    def dict2obj(cls, dic):
        return cls(dic['transaction_hash'], dic['transaction_idx'])
