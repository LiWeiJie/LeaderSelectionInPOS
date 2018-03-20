# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: messages.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='messages.proto',
  package='',
  syntax='proto3',
  serialized_pb=_b('\n\x0emessages.proto\"\x12\n\x05\x44ummy\x12\t\n\x01m\x18\x01 \x01(\t\"$\n\x08\x44iscover\x12\n\n\x02vk\x18\x01 \x01(\x0c\x12\x0c\n\x04port\x18\x02 \x01(\x05\"g\n\rDiscoverReply\x12(\n\x05nodes\x18\x01 \x03(\x0b\x32\x19.DiscoverReply.NodesEntry\x1a,\n\nNodesEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"@\n\x0bInstruction\x12\x13\n\x0binstruction\x18\x01 \x01(\t\x12\r\n\x05\x64\x65lay\x18\x02 \x01(\x05\x12\r\n\x05param\x18\x03 \x01(\t\" \n\x04Ping\x12\n\n\x02vk\x18\x01 \x01(\x0c\x12\x0c\n\x04port\x18\x02 \x01(\x05\" \n\x04Pong\x12\n\n\x02vk\x18\x01 \x01(\x0c\x12\x0c\n\x04port\x18\x02 \x01(\x05\".\n\tSignature\x12\x0e\n\x06signer\x18\x01 \x01(\x0c\x12\x11\n\tsignature\x18\x02 \x01(\x0c\"(\n\x06Member\x12\x0e\n\x06vk_str\x18\x01 \x01(\x0c\x12\x0e\n\x06sk_str\x18\x02 \x01(\x0c\"U\n\x07TxInput\x12\x18\n\x10transaction_hash\x18\x01 \x01(\x0c\x12\x17\n\x0ftransaction_idx\x18\x02 \x01(\x05\x12\x17\n\x06script\x18\x03 \x01(\x0b\x32\x07.Script\"9\n\nScriptUnit\x12\x1d\n\x04type\x18\x01 \x01(\x0e\x32\x0f.ScriptUnitType\x12\x0c\n\x04\x64\x61ta\x18\x02 \x01(\x0c\"#\n\x06Script\x12\x19\n\x04\x62ody\x18\x01 \x03(\x0b\x32\x0b.ScriptUnit\"2\n\x08TxOutput\x12\r\n\x05value\x18\x01 \x01(\x05\x12\x17\n\x06script\x18\x02 \x01(\x0b\x32\x07.Script\"C\n\x0bTransaction\x12\x18\n\x06inputs\x18\x01 \x03(\x0b\x32\x08.TxInput\x12\x1a\n\x07outputs\x18\x02 \x03(\x0b\x32\t.TxOutput\"\xa4\x01\n\x05\x42lock\x12\x11\n\tprev_hash\x18\x01 \x01(\x0c\x12\t\n\x01q\x18\x02 \x01(\x0c\x12\x13\n\x0bmerkle_root\x18\x03 \x01(\x0c\x12\x19\n\x03txs\x18\x04 \x03(\x0b\x32\x0c.Transaction\x12%\n\x11senates_signature\x18\x05 \x03(\x0b\x32\n.Signature\x12&\n\x12\x64irector_signature\x18\x06 \x01(\x0b\x32\n.Signature\"Q\n\x05\x43hain\x12\x16\n\x06\x62locks\x18\x01 \x03(\x0b\x32\x06.Block\x12\x16\n\x0esenates_number\x18\x02 \x01(\x05\x12\x18\n\x10\x66\x61ilure_boundary\x18\x03 \x01(\x05\"g\n\x13\x44irectorCompetition\x12\x1d\n\tsignature\x18\x01 \x01(\x0b\x32\n.Signature\x12\x18\n\x10transaction_hash\x18\x02 \x01(\x0c\x12\x17\n\x0ftransaction_idx\x18\x03 \x01(\x05\">\n\x11TransactionSummit\x12\x0e\n\x06rounds\x18\x01 \x01(\x05\x12\x19\n\x03txs\x18\x02 \x03(\x0b\x32\x0c.Transaction\"%\n\x0c\x43onsensusReq\x12\x15\n\x05\x62lock\x18\x01 \x01(\x0b\x32\x06.Block\"(\n\x0f\x43onsensusResult\x12\x15\n\x05\x62lock\x18\x01 \x01(\x0b\x32\x06.Block\"R\n\x0fSenateSignature\x12\x19\n\x11signed_block_hash\x18\x01 \x01(\x0c\x12$\n\x10senate_signature\x18\x02 \x01(\x0b\x32\n.Signature\")\n\x10\x44irectorShowTime\x12\x15\n\x05\x62lock\x18\x01 \x01(\x0b\x32\x06.Block*7\n\x0eScriptUnitType\x12\x0f\n\x0bSCRIPT_DATA\x10\x00\x12\x14\n\x10SCRIPT_CHECK_SIG\x10\x01\x62\x06proto3')
)

_SCRIPTUNITTYPE = _descriptor.EnumDescriptor(
  name='ScriptUnitType',
  full_name='ScriptUnitType',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='SCRIPT_DATA', index=0, number=0,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SCRIPT_CHECK_SIG', index=1, number=1,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=1336,
  serialized_end=1391,
)
_sym_db.RegisterEnumDescriptor(_SCRIPTUNITTYPE)

ScriptUnitType = enum_type_wrapper.EnumTypeWrapper(_SCRIPTUNITTYPE)
SCRIPT_DATA = 0
SCRIPT_CHECK_SIG = 1



_DUMMY = _descriptor.Descriptor(
  name='Dummy',
  full_name='Dummy',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='m', full_name='Dummy.m', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=18,
  serialized_end=36,
)


_DISCOVER = _descriptor.Descriptor(
  name='Discover',
  full_name='Discover',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='vk', full_name='Discover.vk', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='port', full_name='Discover.port', index=1,
      number=2, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=38,
  serialized_end=74,
)


_DISCOVERREPLY_NODESENTRY = _descriptor.Descriptor(
  name='NodesEntry',
  full_name='DiscoverReply.NodesEntry',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='key', full_name='DiscoverReply.NodesEntry.key', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='value', full_name='DiscoverReply.NodesEntry.value', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=_descriptor._ParseOptions(descriptor_pb2.MessageOptions(), _b('8\001')),
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=135,
  serialized_end=179,
)

_DISCOVERREPLY = _descriptor.Descriptor(
  name='DiscoverReply',
  full_name='DiscoverReply',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='nodes', full_name='DiscoverReply.nodes', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[_DISCOVERREPLY_NODESENTRY, ],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=76,
  serialized_end=179,
)


_INSTRUCTION = _descriptor.Descriptor(
  name='Instruction',
  full_name='Instruction',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='instruction', full_name='Instruction.instruction', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='delay', full_name='Instruction.delay', index=1,
      number=2, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='param', full_name='Instruction.param', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=181,
  serialized_end=245,
)


_PING = _descriptor.Descriptor(
  name='Ping',
  full_name='Ping',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='vk', full_name='Ping.vk', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='port', full_name='Ping.port', index=1,
      number=2, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=247,
  serialized_end=279,
)


_PONG = _descriptor.Descriptor(
  name='Pong',
  full_name='Pong',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='vk', full_name='Pong.vk', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='port', full_name='Pong.port', index=1,
      number=2, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=281,
  serialized_end=313,
)


_SIGNATURE = _descriptor.Descriptor(
  name='Signature',
  full_name='Signature',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='signer', full_name='Signature.signer', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='signature', full_name='Signature.signature', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=315,
  serialized_end=361,
)


_MEMBER = _descriptor.Descriptor(
  name='Member',
  full_name='Member',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='vk_str', full_name='Member.vk_str', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='sk_str', full_name='Member.sk_str', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=363,
  serialized_end=403,
)


_TXINPUT = _descriptor.Descriptor(
  name='TxInput',
  full_name='TxInput',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='transaction_hash', full_name='TxInput.transaction_hash', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='transaction_idx', full_name='TxInput.transaction_idx', index=1,
      number=2, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='script', full_name='TxInput.script', index=2,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=405,
  serialized_end=490,
)


_SCRIPTUNIT = _descriptor.Descriptor(
  name='ScriptUnit',
  full_name='ScriptUnit',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='type', full_name='ScriptUnit.type', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='data', full_name='ScriptUnit.data', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=492,
  serialized_end=549,
)


_SCRIPT = _descriptor.Descriptor(
  name='Script',
  full_name='Script',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='body', full_name='Script.body', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=551,
  serialized_end=586,
)


_TXOUTPUT = _descriptor.Descriptor(
  name='TxOutput',
  full_name='TxOutput',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='value', full_name='TxOutput.value', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='script', full_name='TxOutput.script', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=588,
  serialized_end=638,
)


_TRANSACTION = _descriptor.Descriptor(
  name='Transaction',
  full_name='Transaction',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='inputs', full_name='Transaction.inputs', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='outputs', full_name='Transaction.outputs', index=1,
      number=2, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=640,
  serialized_end=707,
)


_BLOCK = _descriptor.Descriptor(
  name='Block',
  full_name='Block',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='prev_hash', full_name='Block.prev_hash', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='q', full_name='Block.q', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='merkle_root', full_name='Block.merkle_root', index=2,
      number=3, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='txs', full_name='Block.txs', index=3,
      number=4, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='senates_signature', full_name='Block.senates_signature', index=4,
      number=5, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='director_signature', full_name='Block.director_signature', index=5,
      number=6, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=710,
  serialized_end=874,
)


_CHAIN = _descriptor.Descriptor(
  name='Chain',
  full_name='Chain',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='blocks', full_name='Chain.blocks', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='senates_number', full_name='Chain.senates_number', index=1,
      number=2, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='failure_boundary', full_name='Chain.failure_boundary', index=2,
      number=3, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=876,
  serialized_end=957,
)


_DIRECTORCOMPETITION = _descriptor.Descriptor(
  name='DirectorCompetition',
  full_name='DirectorCompetition',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='signature', full_name='DirectorCompetition.signature', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='transaction_hash', full_name='DirectorCompetition.transaction_hash', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='transaction_idx', full_name='DirectorCompetition.transaction_idx', index=2,
      number=3, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=959,
  serialized_end=1062,
)


_TRANSACTIONSUMMIT = _descriptor.Descriptor(
  name='TransactionSummit',
  full_name='TransactionSummit',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='rounds', full_name='TransactionSummit.rounds', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='txs', full_name='TransactionSummit.txs', index=1,
      number=2, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1064,
  serialized_end=1126,
)


_CONSENSUSREQ = _descriptor.Descriptor(
  name='ConsensusReq',
  full_name='ConsensusReq',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='block', full_name='ConsensusReq.block', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1128,
  serialized_end=1165,
)


_CONSENSUSRESULT = _descriptor.Descriptor(
  name='ConsensusResult',
  full_name='ConsensusResult',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='block', full_name='ConsensusResult.block', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1167,
  serialized_end=1207,
)


_SENATESIGNATURE = _descriptor.Descriptor(
  name='SenateSignature',
  full_name='SenateSignature',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='signed_block_hash', full_name='SenateSignature.signed_block_hash', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='senate_signature', full_name='SenateSignature.senate_signature', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1209,
  serialized_end=1291,
)


_DIRECTORSHOWTIME = _descriptor.Descriptor(
  name='DirectorShowTime',
  full_name='DirectorShowTime',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='block', full_name='DirectorShowTime.block', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1293,
  serialized_end=1334,
)

_DISCOVERREPLY_NODESENTRY.containing_type = _DISCOVERREPLY
_DISCOVERREPLY.fields_by_name['nodes'].message_type = _DISCOVERREPLY_NODESENTRY
_TXINPUT.fields_by_name['script'].message_type = _SCRIPT
_SCRIPTUNIT.fields_by_name['type'].enum_type = _SCRIPTUNITTYPE
_SCRIPT.fields_by_name['body'].message_type = _SCRIPTUNIT
_TXOUTPUT.fields_by_name['script'].message_type = _SCRIPT
_TRANSACTION.fields_by_name['inputs'].message_type = _TXINPUT
_TRANSACTION.fields_by_name['outputs'].message_type = _TXOUTPUT
_BLOCK.fields_by_name['txs'].message_type = _TRANSACTION
_BLOCK.fields_by_name['senates_signature'].message_type = _SIGNATURE
_BLOCK.fields_by_name['director_signature'].message_type = _SIGNATURE
_CHAIN.fields_by_name['blocks'].message_type = _BLOCK
_DIRECTORCOMPETITION.fields_by_name['signature'].message_type = _SIGNATURE
_TRANSACTIONSUMMIT.fields_by_name['txs'].message_type = _TRANSACTION
_CONSENSUSREQ.fields_by_name['block'].message_type = _BLOCK
_CONSENSUSRESULT.fields_by_name['block'].message_type = _BLOCK
_SENATESIGNATURE.fields_by_name['senate_signature'].message_type = _SIGNATURE
_DIRECTORSHOWTIME.fields_by_name['block'].message_type = _BLOCK
DESCRIPTOR.message_types_by_name['Dummy'] = _DUMMY
DESCRIPTOR.message_types_by_name['Discover'] = _DISCOVER
DESCRIPTOR.message_types_by_name['DiscoverReply'] = _DISCOVERREPLY
DESCRIPTOR.message_types_by_name['Instruction'] = _INSTRUCTION
DESCRIPTOR.message_types_by_name['Ping'] = _PING
DESCRIPTOR.message_types_by_name['Pong'] = _PONG
DESCRIPTOR.message_types_by_name['Signature'] = _SIGNATURE
DESCRIPTOR.message_types_by_name['Member'] = _MEMBER
DESCRIPTOR.message_types_by_name['TxInput'] = _TXINPUT
DESCRIPTOR.message_types_by_name['ScriptUnit'] = _SCRIPTUNIT
DESCRIPTOR.message_types_by_name['Script'] = _SCRIPT
DESCRIPTOR.message_types_by_name['TxOutput'] = _TXOUTPUT
DESCRIPTOR.message_types_by_name['Transaction'] = _TRANSACTION
DESCRIPTOR.message_types_by_name['Block'] = _BLOCK
DESCRIPTOR.message_types_by_name['Chain'] = _CHAIN
DESCRIPTOR.message_types_by_name['DirectorCompetition'] = _DIRECTORCOMPETITION
DESCRIPTOR.message_types_by_name['TransactionSummit'] = _TRANSACTIONSUMMIT
DESCRIPTOR.message_types_by_name['ConsensusReq'] = _CONSENSUSREQ
DESCRIPTOR.message_types_by_name['ConsensusResult'] = _CONSENSUSRESULT
DESCRIPTOR.message_types_by_name['SenateSignature'] = _SENATESIGNATURE
DESCRIPTOR.message_types_by_name['DirectorShowTime'] = _DIRECTORSHOWTIME
DESCRIPTOR.enum_types_by_name['ScriptUnitType'] = _SCRIPTUNITTYPE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Dummy = _reflection.GeneratedProtocolMessageType('Dummy', (_message.Message,), dict(
  DESCRIPTOR = _DUMMY,
  __module__ = 'messages_pb2'
  # @@protoc_insertion_point(class_scope:Dummy)
  ))
_sym_db.RegisterMessage(Dummy)

Discover = _reflection.GeneratedProtocolMessageType('Discover', (_message.Message,), dict(
  DESCRIPTOR = _DISCOVER,
  __module__ = 'messages_pb2'
  # @@protoc_insertion_point(class_scope:Discover)
  ))
_sym_db.RegisterMessage(Discover)

DiscoverReply = _reflection.GeneratedProtocolMessageType('DiscoverReply', (_message.Message,), dict(

  NodesEntry = _reflection.GeneratedProtocolMessageType('NodesEntry', (_message.Message,), dict(
    DESCRIPTOR = _DISCOVERREPLY_NODESENTRY,
    __module__ = 'messages_pb2'
    # @@protoc_insertion_point(class_scope:DiscoverReply.NodesEntry)
    ))
  ,
  DESCRIPTOR = _DISCOVERREPLY,
  __module__ = 'messages_pb2'
  # @@protoc_insertion_point(class_scope:DiscoverReply)
  ))
_sym_db.RegisterMessage(DiscoverReply)
_sym_db.RegisterMessage(DiscoverReply.NodesEntry)

Instruction = _reflection.GeneratedProtocolMessageType('Instruction', (_message.Message,), dict(
  DESCRIPTOR = _INSTRUCTION,
  __module__ = 'messages_pb2'
  # @@protoc_insertion_point(class_scope:Instruction)
  ))
_sym_db.RegisterMessage(Instruction)

Ping = _reflection.GeneratedProtocolMessageType('Ping', (_message.Message,), dict(
  DESCRIPTOR = _PING,
  __module__ = 'messages_pb2'
  # @@protoc_insertion_point(class_scope:Ping)
  ))
_sym_db.RegisterMessage(Ping)

Pong = _reflection.GeneratedProtocolMessageType('Pong', (_message.Message,), dict(
  DESCRIPTOR = _PONG,
  __module__ = 'messages_pb2'
  # @@protoc_insertion_point(class_scope:Pong)
  ))
_sym_db.RegisterMessage(Pong)

Signature = _reflection.GeneratedProtocolMessageType('Signature', (_message.Message,), dict(
  DESCRIPTOR = _SIGNATURE,
  __module__ = 'messages_pb2'
  # @@protoc_insertion_point(class_scope:Signature)
  ))
_sym_db.RegisterMessage(Signature)

Member = _reflection.GeneratedProtocolMessageType('Member', (_message.Message,), dict(
  DESCRIPTOR = _MEMBER,
  __module__ = 'messages_pb2'
  # @@protoc_insertion_point(class_scope:Member)
  ))
_sym_db.RegisterMessage(Member)

TxInput = _reflection.GeneratedProtocolMessageType('TxInput', (_message.Message,), dict(
  DESCRIPTOR = _TXINPUT,
  __module__ = 'messages_pb2'
  # @@protoc_insertion_point(class_scope:TxInput)
  ))
_sym_db.RegisterMessage(TxInput)

ScriptUnit = _reflection.GeneratedProtocolMessageType('ScriptUnit', (_message.Message,), dict(
  DESCRIPTOR = _SCRIPTUNIT,
  __module__ = 'messages_pb2'
  # @@protoc_insertion_point(class_scope:ScriptUnit)
  ))
_sym_db.RegisterMessage(ScriptUnit)

Script = _reflection.GeneratedProtocolMessageType('Script', (_message.Message,), dict(
  DESCRIPTOR = _SCRIPT,
  __module__ = 'messages_pb2'
  # @@protoc_insertion_point(class_scope:Script)
  ))
_sym_db.RegisterMessage(Script)

TxOutput = _reflection.GeneratedProtocolMessageType('TxOutput', (_message.Message,), dict(
  DESCRIPTOR = _TXOUTPUT,
  __module__ = 'messages_pb2'
  # @@protoc_insertion_point(class_scope:TxOutput)
  ))
_sym_db.RegisterMessage(TxOutput)

Transaction = _reflection.GeneratedProtocolMessageType('Transaction', (_message.Message,), dict(
  DESCRIPTOR = _TRANSACTION,
  __module__ = 'messages_pb2'
  # @@protoc_insertion_point(class_scope:Transaction)
  ))
_sym_db.RegisterMessage(Transaction)

Block = _reflection.GeneratedProtocolMessageType('Block', (_message.Message,), dict(
  DESCRIPTOR = _BLOCK,
  __module__ = 'messages_pb2'
  # @@protoc_insertion_point(class_scope:Block)
  ))
_sym_db.RegisterMessage(Block)

Chain = _reflection.GeneratedProtocolMessageType('Chain', (_message.Message,), dict(
  DESCRIPTOR = _CHAIN,
  __module__ = 'messages_pb2'
  # @@protoc_insertion_point(class_scope:Chain)
  ))
_sym_db.RegisterMessage(Chain)

DirectorCompetition = _reflection.GeneratedProtocolMessageType('DirectorCompetition', (_message.Message,), dict(
  DESCRIPTOR = _DIRECTORCOMPETITION,
  __module__ = 'messages_pb2'
  # @@protoc_insertion_point(class_scope:DirectorCompetition)
  ))
_sym_db.RegisterMessage(DirectorCompetition)

TransactionSummit = _reflection.GeneratedProtocolMessageType('TransactionSummit', (_message.Message,), dict(
  DESCRIPTOR = _TRANSACTIONSUMMIT,
  __module__ = 'messages_pb2'
  # @@protoc_insertion_point(class_scope:TransactionSummit)
  ))
_sym_db.RegisterMessage(TransactionSummit)

ConsensusReq = _reflection.GeneratedProtocolMessageType('ConsensusReq', (_message.Message,), dict(
  DESCRIPTOR = _CONSENSUSREQ,
  __module__ = 'messages_pb2'
  # @@protoc_insertion_point(class_scope:ConsensusReq)
  ))
_sym_db.RegisterMessage(ConsensusReq)

ConsensusResult = _reflection.GeneratedProtocolMessageType('ConsensusResult', (_message.Message,), dict(
  DESCRIPTOR = _CONSENSUSRESULT,
  __module__ = 'messages_pb2'
  # @@protoc_insertion_point(class_scope:ConsensusResult)
  ))
_sym_db.RegisterMessage(ConsensusResult)

SenateSignature = _reflection.GeneratedProtocolMessageType('SenateSignature', (_message.Message,), dict(
  DESCRIPTOR = _SENATESIGNATURE,
  __module__ = 'messages_pb2'
  # @@protoc_insertion_point(class_scope:SenateSignature)
  ))
_sym_db.RegisterMessage(SenateSignature)

DirectorShowTime = _reflection.GeneratedProtocolMessageType('DirectorShowTime', (_message.Message,), dict(
  DESCRIPTOR = _DIRECTORSHOWTIME,
  __module__ = 'messages_pb2'
  # @@protoc_insertion_point(class_scope:DirectorShowTime)
  ))
_sym_db.RegisterMessage(DirectorShowTime)


_DISCOVERREPLY_NODESENTRY.has_options = True
_DISCOVERREPLY_NODESENTRY._options = _descriptor._ParseOptions(descriptor_pb2.MessageOptions(), _b('8\001'))
# @@protoc_insertion_point(module_scope)
