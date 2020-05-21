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

import gtirb
import capstone
import capstone.x86
from enum import Enum
from typing import Iterator, List, Optional
from dataclasses import dataclass


class AccessType(Enum):
    UNKNOWN = "unknown"
    READ = "read"
    WRITE = "write"
    READ_WRITE = "read_write"


@dataclass
class MemoryAccess:
    addr: int
    type: AccessType
    dest: Optional[int]


class GtirbInstructionDecoder:
    """
    Class to obtain instruction information of gtirb basic blocks.
    """

    GTIRB_ISA_TO_CAPSTONE = {
        gtirb.Module.ISA.ARM: capstone.CS_ARCH_ARM,
        gtirb.Module.ISA.ARM64: capstone.CS_ARCH_ARM64,
        gtirb.Module.ISA.MIPS32: capstone.CS_ARCH_MIPS,
        gtirb.Module.ISA.MIPS64: capstone.CS_ARCH_MIPS,
        gtirb.Module.ISA.PPC32: capstone.CS_ARCH_PPC,
        gtirb.Module.ISA.PPC64: capstone.CS_ARCH_PPC,
        gtirb.Module.ISA.IA32: capstone.CS_ARCH_X86,
        gtirb.Module.ISA.X64: capstone.CS_ARCH_X86,
    }

    GTIRB_ISA_TO_CAPSTONE_MODE = {
        gtirb.Module.ISA.ARM: capstone.CS_MODE_ARM,
        gtirb.Module.ISA.ARM64: capstone.CS_MODE_ARM,
        gtirb.Module.ISA.MIPS32: capstone.CS_MODE_MIPS32,
        gtirb.Module.ISA.MIPS64: capstone.CS_MODE_MIPS64,
        gtirb.Module.ISA.PPC32: capstone.CS_MODE_32,
        gtirb.Module.ISA.PPC64: capstone.CS_MODE_64,
        gtirb.Module.ISA.IA32: capstone.CS_MODE_32,
        gtirb.Module.ISA.X64: capstone.CS_MODE_64,
    }

    def __init__(self, arch: gtirb.Module.ISA):

        self._arch = arch
        self._cs = capstone.Cs(
            self.GTIRB_ISA_TO_CAPSTONE[self._arch],
            self.GTIRB_ISA_TO_CAPSTONE_MODE[self._arch],
        )
        self._cs.detail = True

    def get_instructions(
        self, block: gtirb.CodeBlock
    ) -> Iterator[capstone.CsInsn]:
        """
        Get capstone instructions of a basic block.
        """
        if self._arch == gtirb.Module.ISA.ARM:
            if block.decode_mode == 1:
                self._cs.mode = capstone.CS_MODE_THUMB
            else:
                self._cs.mode = capstone.CS_MODE_ARM
        addr = (
            block.byte_interval.address
            if block.byte_interval.address is not None
            else 0
        )
        return self._cs.disasm(
            block.byte_interval.contents[
                block.offset : block.offset + block.size
            ],
            addr + block.offset,
        )

    def get_memory_accesses(
        self, block: gtirb.CodeBlock
    ) -> List[MemoryAccess]:
        """
        Get memory accesses of a basic block.
        Each memory access has an addr, an access type and
        optionally a destination if the access is done with
        only a hard-coded address (without registers).
        """
        if self._arch not in [gtirb.Module.ISA.X64, gtirb.Module.ISA.IA32]:
            raise NotImplementedError(
                f"Memory accesses not available for ISA {self._arch}"
            )
        memory_accesses = []
        for insn in self.get_instructions(block):
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_MEM:
                    access_type = AccessType.UNKNOWN
                    if op.access == capstone.CS_AC_READ:
                        access_type = AccessType.READ
                    elif op.access == capstone.CS_AC_WRITE:
                        access_type = AccessType.WRITE
                    elif (
                        op.access == capstone.CS_AC_READ | capstone.CS_AC_WRITE
                    ):
                        access_type = AccessType.READ_WRITE

                    if (
                        op.mem.base == 0
                        and op.mem.index == 0
                        and op.mem.segment == 0
                    ):
                        dest = op.mem.disp
                    else:
                        dest = None
                    memory_accesses.append(
                        MemoryAccess(
                            addr=insn.address + insn.disp_offset,
                            type=access_type,
                            dest=dest,
                        )
                    )
        return memory_accesses
