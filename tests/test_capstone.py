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
import unittest
import gtirb
import gtirb_capstone


class CapstoneTest(unittest.TestCase):
    def test_insert_bytes(self):
        ir = gtirb.IR()
        m = gtirb.Module()
        m.ir = ir
        s = gtirb.Section(name=".text")
        s.module = m
        bi = gtirb.ByteInterval(contents=b"\x00\x01\x02\x03\x04\x05\x06\x07")
        bi.section = s
        b = gtirb.CodeBlock(offset=2, size=2)
        b.byte_interval = bi
        b2 = gtirb.DataBlock(offset=6, size=2)
        b2.byte_interval = bi
        bi.symbolic_expressions[6] = gtirb.SymAddrConst(0, None)

        ctx = gtirb_capstone.RewritingContext(ir)
        ctx.modify_block_insert(m, b, b"\x08\x09", 3)

        self.assertEqual(bi.size, 10)
        self.assertEqual(
            bi.contents, b"\x00\x01\x02\x08\x09\x03\x04\x05\x06\x07"
        )
        self.assertEqual(b.offset, 2)
        self.assertEqual(b.size, 4)
        self.assertEqual(b2.offset, 8)
        self.assertEqual(b2.size, 2)
        self.assertNotIn(6, bi.symbolic_expressions)
        self.assertIn(8, bi.symbolic_expressions)
