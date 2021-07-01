# Copyright (C) 2020 GrammaTech, Inc.
#
# This code is licensed under the MIT license. See the LICENSE file in
# the project root for license terms.
#
# This project is sponsored by the Office of Naval Research, One Liberty
# Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
# N68335-17-C-0700.  The content of the information does not necessarily
# reflect the position or policy of the Government and no official
# endorsement should be inferred.
#

import pytest
import gtirb
from gtirb_capstone.instructions import (
    GtirbInstructionDecoder,
    AccessType,
)


@pytest.mark.commit
def test_x64_instructions():
    # movzbl 0x200b44(%rip),%eax
    # mov    %al,0x200b2e(%rip)
    bi = gtirb.ByteInterval(
        contents=b"\x0f\xb6\x05\x44\x0b\x20\x00\x88\x05\x2e\x0b\x20\x00"
    )
    b = gtirb.CodeBlock(offset=0, size=13)
    b.byte_interval = bi
    decoder = GtirbInstructionDecoder(gtirb.Module.ISA.X64)
    insns = list(decoder.get_instructions(b))
    assert len(insns) == 2
    assert insns[0].mnemonic == "movzx"
    assert insns[1].mnemonic == "mov"


@pytest.mark.commit
def test_arm_instruction():
    # add r3, pc ,r3
    bi = gtirb.ByteInterval(contents=b"\x03\x30\x8f\xe0")
    b = gtirb.CodeBlock(offset=0, size=4, decode_mode=0)
    b.byte_interval = bi
    decoder = GtirbInstructionDecoder(gtirb.Module.ISA.ARM)
    insns = list(decoder.get_instructions(b))
    assert len(insns) == 1
    assert insns[0].mnemonic == "add"


@pytest.mark.commit
def test_arm_thumb_instruction():
    # add r3, pc
    bi = gtirb.ByteInterval(contents=b"\x7b\x44")
    b = gtirb.CodeBlock(offset=0, size=2, decode_mode=1)
    b.byte_interval = bi
    decoder = GtirbInstructionDecoder(gtirb.Module.ISA.ARM)
    insns = list(decoder.get_instructions(b))
    assert len(insns) == 1
    assert insns[0].mnemonic == "add"


def test_x64_data_access():
    # movzbl 0x200b44(%rip),%eax
    # mov    %al,0x200b2e(%rip)
    bi = gtirb.ByteInterval(
        contents=b"\x0f\xb6\x05\x44\x0b\x20\x00\x88\x05\x2e\x0b\x20\x00"
    )
    b = gtirb.CodeBlock(offset=0, size=13)
    b.byte_interval = bi
    decoder = GtirbInstructionDecoder(gtirb.Module.ISA.X64)
    data_accesses = list(decoder.get_memory_accesses(b))
    assert len(data_accesses) == 2
    assert data_accesses[0].type == AccessType.READ
    assert data_accesses[1].type == AccessType.WRITE
    assert data_accesses[0].op_mem.disp == 0x200B44


def test_arm_thumb_data_access():
    # ldr	r6, [pc, #48]
    bi = gtirb.ByteInterval(contents=b"\x0c\x4e")
    b = gtirb.CodeBlock(offset=0, size=2, decode_mode=1)
    b.byte_interval = bi
    decoder = GtirbInstructionDecoder(gtirb.Module.ISA.ARM)
    data_accesses = list(decoder.get_memory_accesses(b))
    assert len(data_accesses) == 1
    assert data_accesses[0].type == AccessType.READ
    assert data_accesses[0].op_mem.disp == 48


def test_mips32_big_endian():
    m = gtirb.Module(name="test", byte_order=gtirb.Module.ByteOrder.Big)
    s = gtirb.Section(name="")
    s.module = m
    bi = gtirb.ByteInterval(contents=b"\x00\x82\x20\x21")
    bi.section = s
    b = gtirb.CodeBlock(offset=0, size=4, decode_mode=0)
    b.byte_interval = bi

    decoder = GtirbInstructionDecoder(gtirb.Module.ISA.MIPS32)
    insns = list(decoder.get_instructions(b))
    assert len(insns) == 1
    assert insns[0].mnemonic == "addu"


def test_mips32_little_endian():
    m = gtirb.Module(name="test", byte_order=gtirb.Module.ByteOrder.Little)
    s = gtirb.Section(name="")
    s.module = m
    bi = gtirb.ByteInterval(contents=b"\x21\x20\x82\x00")
    bi.section = s
    b = gtirb.CodeBlock(offset=0, size=4, decode_mode=0)
    b.byte_interval = bi

    decoder = GtirbInstructionDecoder(gtirb.Module.ISA.MIPS32)
    insns = list(decoder.get_instructions(b))
    assert len(insns) == 1
    assert insns[0].mnemonic == "addu"
