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
from src.chain.model.member_model import verify

from src.utils.encode_utils import json_bytes_dumps, json_bytes_loads

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
        # MARK: Consider a more efficient method
        for ip in inputs:
            assert isinstance(ip, Transaction.Input), type(ip)
            self.pb.inputs.extend([ip.pb])
            last_pb = self.pb.inputs[-1]
            self._inputs.append(Transaction.Input(last_pb))
            # order_list.append(order)
            # order += 1
        self.on_change()
        # return order_list

    def add_input_script(self, input_idx, script):
        """
        """
        target = self.inputs[input_idx]
        target.set_script(script)
        self.on_change()

    def add_outputs(self, outputs):
        # MARK: Consider a more efficient method
        for output in outputs:
            assert isinstance(output, Transaction.Output), type(output)
            self.pb.outputs.extend([output.pb])
            last_pb = self.pb.outputs[-1]
            self._outputs.append(Transaction.Output(last_pb))
        self.on_change()

    def get_transaction_sign_source(self):
        data_str = ""
        for ip in self.inputs:
            cp = pb.TxInput()
            cp.CopyFrom(ip.pb)
            cp.script.Clear()
            data_str += cp.SerializeToString()

        for op in self.outputs:
            data_str += op.pb.SerializeToString()

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
        # handle inputs
        for i in range(sz):
            ip = inputs[i]
            op = prev_outputs[i]

            input_satoshi += op.value
            result = True
            stack = [script_unit for script_unit in ip.script.body]
            for item in op.script.body:
                if item.type == pb.SCRIPT_DATA:
                    stack.append(item)
                elif item.type == pb.SCRIPT_CHECK_SIG:
                    verify_key = stack.pop().data
                    signature = stack.pop().data
                    if not verify(signer=verify_key,
                                  signature=signature,
                                  data=data):
                        logging.info("TX: signature invalid")
                        result = False
                if not result:
                    return result
            if stack.__len__() != 0:
                logging.info("TX: script invalid")
                return False

        # handle outputs
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
    #
    #     self._hash = hash_utils.hash_std(head_data)

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
        # logging.info("tx: obj2dict {}".format(obj.inputs))
        # logging.info("tx: obj2dict {}".format(obj.outputs))
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
            # self._transaction_hash = pbo.transaction_hash
            # self._transaction_idx = pbo.transaction_idx
            # self._script = pbo.script

        @classmethod
        def new(cls, transaction_hash, transaction_idx, script=None):
            if not script:
                script = pb.Script()
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
            return self.pb.transaction_hash

        @property
        def transaction_idx(self):
            """Returns the index of the output inside the transaction that is
            redeemed by this input"""
            return self.pb.transaction_idx

        @property
        def script(self):
            """Returns a Script object representing the redeem script"""
            return self.pb.script

        def on_change(self):
            super(self.__class__, self).on_change()

        def set_script(self, script):
            self.pb.script.CopyFrom(script)
            self.on_change()

        @classmethod
        def obj2dict(cls, obj):
            return {
                "transaction_hash": json_bytes_dumps(obj.transaction_hash),
                "transaction_idx": obj.transaction_idx,
                "script": json_bytes_dumps(obj.script.SerializeToString())
            }

        @classmethod
        def dict2obj(cls, dic):
            ip = Transaction.Input.new(transaction_hash=json_bytes_loads(dic['transaction_hash']),
                                       transaction_idx=dic['transaction_idx'],
                                       script=pb.Script.FromString(json_bytes_loads(dic['script'])))
            return ip

    class Output(ProtobufWrapper):
        """Represents a Transaction output"""

        def __init__(self, pbo):
            """
            @value float or int
            @script in TransactionOutputScriptOP
            @address verify_key_str
            """
            assert (isinstance(pbo, pb.TxOutput)), type(pbo)
            super(self.__class__, self).__init__(pbo)
            # self._value = pbo.value
            # self._script = pbo.script
            # self._address = pbo.address

        @classmethod
        def new(cls, value, script):
            return cls(pb.TxOutput(value=value,
                                   script=script
                                   ))

        # def __repr__(self):
        #     return "Output(satoshis=%d)" % self.value

        def __cmp__(self, other):
            return cmp(self.hash, other.hash)

        @property
        def value(self):
            """Returns the value of the output exprimed in satoshis"""
            return self.pb.value

        @property
        def script(self):
            return self.pb.script

        @property
        def address(self):
            return self.script.body[0].data

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
            from base64 import urlsafe_b64encode as json_bytes_dumps

            return {
                "value": obj.value,
                "script": json_bytes_dumps(obj.script.SerializeToString()),
            }

        @classmethod
        def dict2obj(cls, dic):
            from base64 import urlsafe_b64decode as json_bytes_loads
            op = Transaction.Output.new(
                value=dic['value'],
                script=pb.Script.FromString(json_bytes_loads(dic['script'].encode('utf-8'))))
            return op


from base64 import  b64encode

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
