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
import gtirb_capstone


@pytest.mark.commit
def test_insert_bytes():
    ir = gtirb.IR()
    m = gtirb.Module(isa=gtirb.Module.ISA.X64)
    m.ir = ir
    s = gtirb.Section(name=".text")
    s.module = m
    bi = gtirb.ByteInterval(
        contents=b"\x00\x01\x02\x03\x04\x05\x06\x07", address=0x1000
    )
    bi.section = s
    b = gtirb.CodeBlock(offset=2, size=2)
    b.byte_interval = bi
    b2 = gtirb.DataBlock(offset=6, size=2)
    b2.byte_interval = bi
    bi.symbolic_expressions[6] = gtirb.SymAddrConst(0, None)
    ctx = gtirb_capstone.RewritingContext(ir)
    ctx.modify_block_insert(m, b, b"\x08\x09", 1)
    assert bi.address == 0x1000
    assert bi.size == 10
    assert bi.contents == b"\x00\x01\x02\x08\x09\x03\x04\x05\x06\x07"
    assert b.offset == 2
    assert b.size == 4
    assert b2.offset == 8
    assert b2.size == 2
    assert 6 not in bi.symbolic_expressions
    assert 8 in bi.symbolic_expressions
