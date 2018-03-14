#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# member_model.py ---
#
# @Filename: member_model.py
# @Description: 
# @Author: Weijie Li
# @Created time: 2018-02-20 15:13:04
# @Last Modified by: 
# @Last Modified time: 2018-02-20 16:48:48

import json
from base64 import urlsafe_b64encode as b64e
from base64 import urlsafe_b64decode as b64d
# from base64 import b64encode as b64e
# from base64 import b64decode as b64d


from ecdsa import SigningKey, VerifyingKey, BadSignatureError
from os.path import exists
import binascii

import logging

def signingkey_to_str(signing_key):
    """signingkey_to_str, using urlsafe_base64 encode"""
    assert(isinstance(signing_key, SigningKey)), type(signing_key)
    sks = signing_key.to_string()
    sks = b64e(sks)
    return sks

def str_to_signingkey(sk_str):
    """str_to_signingkey, str from signingkey_to_str"""
    signing_key_str = b64d(sk_str)
    signing_key = SigningKey.from_string(signing_key_str)
    assert(isinstance(signing_key, SigningKey)), type(signing_key)
    return signing_key

def verifykey_to_str(verify_key):
    """verifykey_to_str

    convert verifykey to str. encode verify_key_str using base64 then decode it using utf-8

    Args:
        verify_key: verify_key.

    Returns:
        verify_key in str format.

    """
    assert(isinstance(verify_key, VerifyingKey)), type(verify_key)
    vks = verify_key.to_string()
    vks = b64e(vks)
    return vks

def str_to_verifykey(vk_str):
    """str_to_verifykey, str from verifykey_to_str"""
    verify_key_str = b64d(vk_str)
    verify_key = VerifyingKey.from_string(verify_key_str)
    assert(isinstance(verify_key, VerifyingKey)), type(verify_key)
    return verify_key

class MemberModel(object):
    """Summary of class here.

    MemberModel

    Attributes:
        signing_key: A SigningKey class indicating signing key.
        verify_key: A VerifyKey class indicating verify key.
    """

    @property
    def signing_key(self):
        return self._signing_key

    @property
    def verify_key(self):
        return self._verify_key

    @property
    def mid(self):
        """member id"""
        if not self._mid:
            if self.verify_key_str:
                self._mid = self.verify_key_str
        return self._mid

    @property
    def verify_key_str(self):
        if not self._verify_key_str:
            if self.verify_key:
                self._verify_key_str = verifykey_to_str(self.verify_key)
        return self._verify_key_str

    @property
    def signing_key_str(self):
        if not self._signing_key_str:
            if self.signing_key:
                self._signing_key_str = signingkey_to_str(self.signing_key)
        return self._signing_key_str

    @classmethod
    def get_verify_member(cls, verify_key):
        member = None
        if isinstance(verify_key, VerifyingKey):
            member = MemberModel(key_pair=(verify_key, None))
        else:
            vk = str_to_verifykey(verify_key)
            member = MemberModel(key_pair=(vk, None))
        return member

    def __init__(self, genkey=False, key_path=None, key_pair=None):
        """if genkey == True, then will generate a new key pair, otherwise depends on the key_path or key_pair
        @key_pair key_pair = (verify_key, signing_key)
        """
        self._signing_key = self._verify_key = self._mid = self._signing_key_str = self._verify_key_str = None 
        
        verify_key = signing_key = None
        
        if key_pair:
            (verify_key, signing_key) = key_pair
        if genkey:
            # TODO: curve=ecdsa.generator_secp256k1
            self._signing_key = SigningKey.generate()
            self._verify_key = self._signing_key.get_verifying_key()
        if key_path:
            self.load_key_from_path(key_path)
        if verify_key:
            if not isinstance(verify_key, VerifyingKey):
                verify_key = str_to_verifykey(verify_key)
            assert(isinstance(verify_key, VerifyingKey)), type(verify_key)
            self._verify_key = verify_key            
        if signing_key:
            if not isinstance(signing_key, SigningKey):
                signing_key = str_to_signingkey(signing_key)
            assert(isinstance(signing_key, SigningKey)), type(signing_key)            
            self._signing_key = signing_key


    def set_key(self, verify_key, signing_key=None):
        """set verifykey and secrekey"""
        if isinstance(verify_key, VerifyingKey):
            self._verify_key = verify_key
            # self._signing_key = signing_key
        else:
            self._verify_key = str_to_verifykey(verify_key)
        assert(isinstance(self._verify_key, VerifyingKey)), type(self._verify_key)

        self._verify_key = None
        if self._verify_key:
            if isinstance(verify_key, VerifyingKey):
                self._verify_key = verify_key
            else:
                self._verify_key = str_to_verifykey(verify_key)
            assert(isinstance(self.verify_key, VerifyingKey)), type(self.verify_key)    

    def load_key_from_path(self, path):
        """load key from the path.
        
        the file should be json format

        Args:
            path: path to file in json format

        Returns:
            successful then return True,
            otherwises return False

        Raises:
            IOError: An error occurred accessing the file.
        """
        if path and exists(path):
            # TODO: catch the open exception
            with open(path, "r") as key_file:
                obj = json.load(key_file, object_hook=self.dict2obj)
                self._signing_key = obj._signing_key
                self._verify_key = obj._verify_key
                self._mid = obj._mid
        else:
            logging.warn("path or path file not exists, path: %s"%path)

    def write_to_path(self, path, except_signing_key=True):
        """write signing key and verify key to the path, in json format"""
        if path:
            # TODO: catch the open exception
            with open(path, "w") as key_file:
                # key_dict = { 
                #     "_signing_key": self.signingkey_to_str(signing_key),                
                #     "_verify_key": self.verifykey_to_str(verify_key)
                # }
                # json.dump(key_dict, key_file)
                self.dump(key_file, except_signing_key=except_signing_key)
                logging.info("successful write_to_path")
                return True
        else:
            logging.warn("path is None")
            return False

    def sign(self, data, offset=0, length=0):
        """
        Returns the signature of data, starting at offset up to length bytes.

        Will raise a ValueError when len(data) < offset + length
        Will raise a RuntimeError when this we do not have the private key.
        """
        assert isinstance(data, str), type(data)
        assert isinstance(offset, (int, long)), type(offset)
        assert isinstance(length, (int, long)), type(length)

        if length == 0:
            length = len(data) - offset
        elif len(data) < offset + length:
            # DATA is to small, we expect len(DATA[OFFSET:OFFSET+LENGTH]) to be LENGTH
            raise ValueError("LENGTH is larger than the available DATA")

        if self._signing_key:
            return binascii.hexlify(self._signing_key.sign(data[offset:offset + length])).encode('utf-8')
        else:
            raise RuntimeError("unable to sign data without the signing key")

    def verify(self, data, signature, offset=0, length=0):
        """
        Verify that DATA, starting at OFFSET up to LENGTH bytes, was signed by this member and
        matches SIGNATURE.

        DATA is the signed data and the signature concatenated.
        OFFSET is the offset for the signed data.
        LENGTH is the number of bytes, starting at OFFSET, to be verified.  When this value is 0 it
               is set to len(data) - OFFSET.

        Returns True or False.
        """
        assert isinstance(data, str), type(data)
        assert isinstance(signature, unicode) or isinstance(signature, str), type(signature)
        assert isinstance(offset, (int, long)), type(offset)
        assert isinstance(length, (int, long)), type(length)

        if length == 0:
            # default LENGTH is len(DATA[OFFSET:])
            length = len(data) - offset

        elif len(data) < offset + length:
            # DATA is to small, we expect len(DATA[OFFSET:OFFSET+LENGTH]) to be LENGTH
            return False

        if self._verify_key:
            try:
                return self._verify_key.verify(binascii.unhexlify(signature), data[offset:offset + length])
            except BadSignatureError:
                logging.warn("BAD SIGNATURE")
        
        return False

    def __hash__(self):
        """Allows MemberModel classes to be used as keys in a dictionary."""
        return self.mid

    def __str__(self):
        """Returns a human readable string representing the member."""
        return "<%s %s>" % (self.__class__.__name__, self.mid)

    @classmethod
    def obj2dict_without_signingkey(cls, member):
        assert isinstance(member, cls), type(member)
        verify_key_str = None
        if member._verify_key:
            verify_key_str = member.verify_key_str
        return {
            # "_signing_key": None,   # do not give signing key to others
            "_verify_key": verify_key_str,
            # "_mid": member.mid
        }

    @classmethod
    def obj2dict(cls, member):
        """obj2dict_without_signingkey"""
        return cls.obj2dict_without_signingkey(member)

    @classmethod
    def obj2dict_with_signingkey(cls, member):
        assert isinstance(member, cls), type(member)
        signing_key_str = member.signing_key_str
        m_dict = cls.obj2dict_without_signingkey(member)
        m_dict['_signing_key'] = signing_key_str
        return m_dict

    @classmethod
    def dict2obj(self, key_dict):
        assert isinstance(key_dict, dict), type(key_dict)
        assert key_dict.has_key("_verify_key")
        if key_dict.has_key("_signing_key"):
            signing_key = key_dict["_signing_key"].encode("utf-8")
        verify_key = key_dict["_verify_key"].encode("utf-8")
        return MemberModel(key_pair=(verify_key, signing_key))

    def dump(self, opened_file, except_signing_key=True):
        if except_signing_key:
            json.dump(self, opened_file, default=self.obj2dict_without_signingkey)
        else:
            json.dump(self, opened_file, default=self.obj2dict_with_signingkey)
        return True
    
    def dumps(self, except_signing_key=True):
        if except_signing_key:
            return json.dumps(self, default=self.obj2dict_without_signingkey)
        else:
            return json.dumps(self, default=self.obj2dict_with_signingkey)

    @classmethod
    def load(cls, opened_file):
        obj = json.load(opened_file, object_hook=cls.dict2obj)
        assert(isinstance(obj, cls)), type(obj)
        return obj

    @classmethod
    def loads(cls, data):
        obj = json.loads(data, object_hook=cls.dict2obj)
        assert(isinstance(obj, cls)), type(obj)
        return obj

class BroadcastMember(MemberModel):
    def __init__(self):
        super(BroadcastMember, self).__init__()
        