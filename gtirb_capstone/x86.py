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

"""
Utilities for converting Capstone operands to assembly strings.
"""

import capstone_gt
import gtirb
from typing import Optional, Union


def operand_size_to_str(size: int) -> str:
    """
    Gets the assembly operand type for a given size in bytes, in Intel syntax.
    """
    if size == 1:
        return "byte"
    if size == 2:
        return "word"
    if size == 4:
        return "dword"
    if size == 8:
        return "qword"
    if size == 16:
        return "xmmword"
    if size == 32:
        return "ymmword"
    if size == 64:
        return "zmmword"

    raise ValueError(f"unsupported size: {size}")


def _hex_if_needed(value: int) -> str:
    """
    Converts larger integers to hex in order to have more readable assembly.
    """
    if abs(value) >= 10:
        return hex(value)
    return str(value)


def symbolic_expression_to_str(
    expr: gtirb.SymbolicExpression,
    *,
    extra_offset: int = 0,
    syntax: int = capstone_gt.CS_OPT_SYNTAX_INTEL,
) -> str:
    """
    Converts a symbolic expression to an equivalent assembly string.
    :param sym_expr: The symbolic expression.
    :param extra_offset: A value to be added to the expression's offset.
    :param syntax: The assembly syntax to generate for. Only Intel is
           currently supported.
    """
    if syntax != capstone_gt.CS_OPT_SYNTAX_INTEL:
        raise NotImplementedError("only Intel syntax is currently supported")

    # TODO: Deal with symbolic expression attributes
    if expr.attributes:
        raise NotImplementedError(
            "symbolic expression attributes not supported"
        )

    if isinstance(expr, gtirb.SymAddrConst):
        result = expr.symbol.name
        offset = expr.offset + extra_offset
        if offset:
            result += f" + {offset}"
        return result

    elif isinstance(expr, gtirb.SymAddrAddr):
        # TODO: Implement this once gtirb-rewriting supports it
        raise NotImplementedError("SymAddrAddr not supported")

    else:
        # GTIRB only currently has two symbolic expression types, so it
        # shouldn't be possible to hit this -- but if we do hit here we need
        # to raise an exception instead of silently doing nothing.
        raise TypeError("Unsupported symbolic expression type")


def mem_access_to_str(
    inst: capstone_gt.CsInsn,
    mem: capstone_gt.x86.X86OpMem,
    sym_expr: Optional[gtirb.SymbolicExpression],
    *,
    extra_displacement: int = 0,
    syntax: int = capstone_gt.CS_OPT_SYNTAX_INTEL,
) -> str:
    """
    Converts a Capstone memory reference into an equivalent assembly string.
    :param inst: The instruction containing the operand.
    :param mem: The memory operation.
    :param sym_expr: The symbolic expression for the displacement.
    :param extra_displacement: A value to be added to the displacement.
    :param syntax: The assembly syntax to generate for. Only Intel is
           currently supported.
    """
    if syntax != capstone_gt.CS_OPT_SYNTAX_INTEL:
        raise NotImplementedError("only Intel syntax is currently supported")

    fields = []
    if mem.base != capstone_gt.x86.X86_REG_INVALID:
        fields.append(inst.reg_name(mem.base))

    if mem.index != capstone_gt.x86.X86_REG_INVALID:
        index_and_scale = inst.reg_name(mem.index)
        if mem.scale != 1:
            index_and_scale += "*" + str(mem.scale)
        fields.append(index_and_scale)

    if sym_expr:
        fields.append(
            symbolic_expression_to_str(
                sym_expr, extra_offset=extra_displacement, syntax=syntax
            )
        )
    elif mem.disp + extra_displacement:
        fields.append(_hex_if_needed(mem.disp + extra_displacement))
    elif not fields:
        fields.append("0")

    segment = ""
    if mem.segment != capstone_gt.x86.X86_REG_INVALID:
        segment = inst.reg_name(mem.segment) + ":"

    return f"{segment}[" + " + ".join(fields) + "]"


def operand_to_str(
    inst: capstone_gt.CsInsn,
    op: capstone_gt.x86.X86Op,
    sym_expr: Optional[gtirb.SymbolicExpression],
    *,
    extra_offset: int = 0,
    syntax: int = capstone_gt.CS_OPT_SYNTAX_INTEL,
) -> str:
    """
    Converts a Capstone operand into an equivalent assembly string.
    :param inst: The instruction containing the operand.
    :param op: The operand.
    :param sym_expr: The symbolic expression for the operand. Only valid for
           memory and immediate operands.
    :param extra_offset: A value to be added to the displacement or immediate.
           Only valid for memory and immediate operands.
    :param syntax: The assembly syntax to generate for. Only Intel is
           currently supported.
    """
    if op not in inst.operands:
        raise ValueError("operand is not in the instruction")

    if syntax != capstone_gt.CS_OPT_SYNTAX_INTEL:
        raise NotImplementedError("only Intel syntax is currently supported")

    if op.type == capstone_gt.x86.X86_OP_MEM:
        mem = mem_access_to_str(
            inst,
            op.mem,
            sym_expr,
            extra_displacement=extra_offset,
            syntax=syntax,
        )
        size = operand_size_to_str(op.size)
        return f"{size} ptr {mem}"

    if op.type == capstone_gt.x86.X86_OP_REG:
        if extra_offset:
            raise ValueError(
                "extra_offset cannot be used with register operands"
            )
        if sym_expr:
            raise ValueError("sym_expr cannot be used with register operands")

        return inst.reg_name(op.reg)

    if op.type == capstone_gt.x86.X86_OP_IMM:
        if sym_expr:
            expr_str = symbolic_expression_to_str(
                sym_expr, extra_offset=extra_offset
            )
            return f"offset {expr_str}"
        value = op.imm
        if extra_offset:
            value += extra_offset
        return _hex_if_needed(value)

    raise ValueError(f"unsupported operand type: {op.type}")


def operand_symbolic_expression(
    parent: Union[gtirb.CodeBlock, gtirb.ByteInterval],
    inst: capstone_gt.CsInsn,
    op: capstone_gt.x86.X86Op,
) -> Optional[gtirb.SymbolicExpression]:
    """
    Gets the symbolic expression, if any, associated with an operand.
    :param parent: The code block or byte interval containing the instruction.
    :param inst: The instruction containing the operand.
    :param op: The operand.
    """
    if isinstance(parent, gtirb.CodeBlock):
        interval = parent.byte_interval
    elif isinstance(parent, gtirb.ByteInterval):
        interval = parent

    if not interval:
        raise ValueError("parent must be in a byte interval")

    if interval.address:
        inst_offset = inst.address - interval.address
    else:
        inst_offset = inst.address

    if op.type == capstone_gt.x86.X86_OP_MEM:
        return interval.symbolic_expressions.get(
            inst_offset + inst.disp_offset, None
        )

    if op.type == capstone_gt.x86.X86_OP_IMM:
        return interval.symbolic_expressions.get(
            inst_offset + inst.imm_offset, None
        )

    return None
