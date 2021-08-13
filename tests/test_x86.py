# Copyright (C) 2021 GrammaTech, Inc.
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

import capstone
import mcasm
import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
import gtirb_capstone.x86
import pytest


def assemble_and_decode_one(asm):
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    cs.detail = True

    assembler = mcasm.Assembler("x86_64-unknown-linux-gnu")
    assembler.x86_syntax = mcasm.X86Syntax.INTEL
    for event in assembler.assemble(asm):
        if event["kind"] == "instruction":
            encoding = bytes.fromhex(event["data"])
            (inst,) = cs.disasm(encoding, 0)
            return inst


@pytest.mark.commit
def test_operand_to_string():
    def test_one(asm, operand, expected, *, sym_expr=None, extra_offset=0):
        inst = assemble_and_decode_one(asm)
        op_str = gtirb_capstone.x86.operand_to_str(
            inst,
            inst.operands[operand],
            sym_expr=sym_expr,
            extra_offset=extra_offset,
        )
        assert op_str == expected

    # Memory operands
    test_one("inc qword ptr [RDI]", 0, "qword ptr [rdi]")
    test_one("inc dword ptr [RDI+4]", 0, "dword ptr [rdi + 4]")
    test_one("inc word ptr [R12+rbx*4]", 0, "word ptr [r12 + rbx*4]")
    test_one(
        "inc byte ptr cs:[rax+rax*4+4]", 0, "byte ptr cs:[rax + rax*4 + 4]"
    )
    test_one("inc dword ptr [4096]", 0, "dword ptr [0x1000]")
    test_one("inc dword ptr [rsp+rax*1+0]", 0, "dword ptr [rsp + rax]")
    test_one("inc dword ptr [0]", 0, "dword ptr [0]")
    test_one("inc dword ptr gs:[0]", 0, "dword ptr gs:[0]")
    test_one("inc dword ptr [4096]", 0, "dword ptr [0x1004]", extra_offset=4)
    test_one("inc dword ptr [RSP+4]", 0, "dword ptr [rsp + 8]", extra_offset=4)
    test_one(
        "inc dword ptr cs:[rax+rax*4+4]",
        0,
        "dword ptr cs:[rax + rax*4 + 0xc]",
        extra_offset=8,
    )
    test_one("movdqu xmm0, [4096]", 1, "xmmword ptr [0x1000]")

    sym = gtirb.Symbol("__ImageBase")
    test_one(
        "inc dword ptr [0]",
        0,
        "dword ptr [__ImageBase]",
        sym_expr=gtirb.SymAddrConst(0, sym),
    )
    test_one(
        "inc dword ptr [0]",
        0,
        "dword ptr [__ImageBase + 4]",
        sym_expr=gtirb.SymAddrConst(4, sym),
    )
    test_one(
        "inc dword ptr [0]",
        0,
        "dword ptr [__ImageBase + 12]",
        sym_expr=gtirb.SymAddrConst(4, sym),
        extra_offset=8,
    )

    # Register operands
    test_one("inc R11", 0, "r11")
    test_one("inc AX", 0, "ax")

    # Immediate operands
    test_one("add rax, 42", 1, "0x2a")
    test_one(
        "add rax, 0",
        1,
        "offset __ImageBase",
        sym_expr=gtirb.SymAddrConst(0, sym),
    )
    test_one(
        "add rax, 0",
        1,
        "offset __ImageBase + 4",
        sym_expr=gtirb.SymAddrConst(0, sym),
        extra_offset=4,
    )


@pytest.mark.commit
@pytest.mark.parametrize("bi_addr", (0x1000, None))
def test_operand_symbolic_expression(bi_addr):
    sym = gtirb.Symbol("foo")
    bi = gtirb.ByteInterval(
        address=bi_addr,
        size=21,
        contents=(
            # call foo
            b"\xE8\x00\x00\x00\x00"
            # inc byte ptr [foo+1]
            b"\xFE\x04\x25\x00\x00\x00\x00"
            # inc byte ptr [0]
            b"\xFE\x04\x25\x00\x00\x00\x00"
            # inc eax
            b"\xFF\xC0"
        ),
        symbolic_expressions={
            1: gtirb.SymAddrConst(0, sym),
            8: gtirb.SymAddrConst(1, sym),
        },
    )
    b1 = gtirb.CodeBlock(offset=0, size=5)
    b2 = gtirb.CodeBlock(offset=5, size=7)
    b3 = gtirb.CodeBlock(offset=12, size=7)
    b4 = gtirb.CodeBlock(offset=19, size=2)
    bi.blocks.update((b1, b2, b3, b4))

    decoder = GtirbInstructionDecoder(gtirb.Module.ISA.X64)

    (inst,) = decoder.get_instructions(b1)
    assert gtirb_capstone.x86.operand_symbolic_expression(
        b1, inst, inst.operands[0]
    ) == gtirb.SymAddrConst(0, sym)
    assert gtirb_capstone.x86.operand_symbolic_expression(
        bi, inst, inst.operands[0]
    ) == gtirb.SymAddrConst(0, sym)

    (inst,) = decoder.get_instructions(b2)
    assert gtirb_capstone.x86.operand_symbolic_expression(
        b2, inst, inst.operands[0]
    ) == gtirb.SymAddrConst(1, sym)
    assert gtirb_capstone.x86.operand_symbolic_expression(
        bi, inst, inst.operands[0]
    ) == gtirb.SymAddrConst(1, sym)

    (inst,) = decoder.get_instructions(b3)
    assert not gtirb_capstone.x86.operand_symbolic_expression(
        b3, inst, inst.operands[0]
    )
    assert not gtirb_capstone.x86.operand_symbolic_expression(
        bi, inst, inst.operands[0]
    )

    (inst,) = decoder.get_instructions(b4)
    assert not gtirb_capstone.x86.operand_symbolic_expression(
        b4, inst, inst.operands[0]
    )
    assert not gtirb_capstone.x86.operand_symbolic_expression(
        bi, inst, inst.operands[0]
    )
