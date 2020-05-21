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

    # 0f b6 05 44 0b 20 00
    #

    # 447b      	add	r3, pc
    # e08f3003 	add	r3, pc, r3
