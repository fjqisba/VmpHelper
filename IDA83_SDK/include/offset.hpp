/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _OFFSET_HPP
#define _OFFSET_HPP

#include <nalt.hpp>
#include <segment.hpp>

/*! \file offset.hpp

  \brief Functions that deal with offsets.

  "Being an offset" is a characteristic of an operand.
  This means that operand or its part represent offset from
  some address in the program. This linear address is called
  "offset base". Some operands may have 2 offsets simultaneously.
  Generally, IDA doesn't handle this except for Motorola outer offsets.
  Thus there may be two offset values in an operand: simple offset and
  outer offset.

  Outer offsets are handled by specifying special operand number:
  it should be ORed with #OPND_OUTER value.

  See bytes.hpp for further explanation of operand numbers.
*/


/// Get default reference type depending on the segment.
/// \return one of ::REF_OFF8, ::REF_OFF16, ::REF_OFF32, ::REF_OFF64

idaman reftype_t ida_export get_default_reftype(ea_t ea);


/// Convert operand to a reference.
/// To delete an offset, use clr_op_type() function.
/// \param ea  linear address.
///            if 'ea' has unexplored bytes, try to convert them to
///              - no segment: fail
///              - 16bit segment: to 16bit word data
///              - 32bit segment: to dword
/// \param n   operand number (may be ORed with #OPND_OUTER)
///              - 0: first
///              - 1: second
///               - ...
///               - 7: eighth operand
///              - #OPND_MASK: all operands
/// \param ri  reference information
/// \return success

idaman bool ida_export op_offset_ex(ea_t ea, int n, const refinfo_t *ri);


/// See op_offset_ex()

idaman bool ida_export op_offset(
        ea_t ea,
        int n,
        uint32 type_and_flags,
        ea_t target=BADADDR,
        ea_t base=0,
        adiff_t tdelta=0);


/// Convert operand to a reference with the default reference type

inline bool op_plain_offset(ea_t ea, int n, ea_t base)
{
  reftype_t reftype = get_default_reftype(ea);
  return op_offset(ea, n, reftype, BADADDR, base) != 0;
}


/// Get offset base value
/// \param ea  linear address
/// \param n   0..#UA_MAXOP-1 operand number
/// \return offset base or #BADADDR

inline ea_t get_offbase(ea_t ea, int n)
{
  refinfo_t ri;
  if ( !get_refinfo(&ri, ea, n) )
    return BADADDR;
  return ri.base;
}


/// Get offset expression (in the form "offset name+displ").
/// This function uses offset translation function (\ph{translate}) if your IDP
/// module has such a function. Translation function is used to map linear
/// addresses in the program (only for offsets).
///
/// Example: suppose we have instruction at linear address 0x00011000:
///              \v{mov     ax, [bx+7422h]}
/// and at ds:7422h:
///     \v{array   dw      ...}
/// We want to represent the second operand with an offset expression, so
/// then we call:
/// \v{
/// get_offset_expresion(0x001100, 1, 0x001102, 0x7422, buf);
///                      |         |  |         |       |
///                      |         |  |         |       +output buffer
///                      |         |  |         +value of offset expression
///                      |         |  +address offset value in the instruction
///                      |         +the second operand
///                      +address of instruction
/// }
/// and the function will return a colored string:
///     \v{offset array}
/// \param buf         output buffer to hold offset expression
/// \param ea          start of instruction or data with the offset expression
/// \param n           operand number (may be ORed with #OPND_OUTER)
///                      - 0: first operand
///                      - 1: second operand
///                      - ...
///                      - 7: eighth operand
/// \param from        linear address of instruction operand or data referring to
///                    the name. This address will be used to get fixup information,
///                    so it should point to exact position of operand in the
///                    instruction.
/// \param offset      value of operand or its part. The function will return
///                    text representation of this value as offset expression.
/// \param getn_flags  combination of:
///                      - #GETN_APPZERO: meaningful only if the name refers to
///                                       a structure. appends the struct field name
///                                       if the field offset is zero
///                      - #GETN_NODUMMY: do not generate dummy names for the expression
///                                       but pretend they already exist
///                                       (useful to verify that the offset expression
///                                       can be represented)
/// \retval 0  can't convert to offset expression
/// \retval 1  ok, a simple offset expression
/// \retval 2  ok, a complex offset expression


idaman int ida_export get_offset_expression(
        qstring *buf,
        ea_t ea,
        int n,
        ea_t from,
        adiff_t offset,
        int getn_flags=0);


/// See get_offset_expression()

idaman int ida_export get_offset_expr(
        qstring *buf,
        ea_t ea,
        int n,
        const refinfo_t &ri,
        ea_t from,
        adiff_t offset,
        int getn_flags=0);


/// Does the specified address contain a valid OFF32 value?.
/// For symbols in special segments the displacement is not taken into account.
/// If yes, then the target address of OFF32 will be returned.
/// If not, then #BADADDR is returned.

idaman ea_t ida_export can_be_off32(ea_t ea);


/// Try to calculate the offset base
/// This function takes into account the fixup information,
/// current ds and cs values.
/// \param ea   the referencing instruction/data address
/// \param n    operand number
///             - 0: first operand
///             - 1: second operand
///             - ...
///             - 7: eighth operand
/// \return output base address or #BADADDR

idaman ea_t ida_export calc_offset_base(ea_t ea, int n);


/// Try to calculate the offset base.
/// 2 bases are checked: current ds and cs.
/// If fails, return #BADADDR

idaman ea_t ida_export calc_probable_base_by_value(ea_t ea, uval_t off);


/// Calculate the target and base addresses of an offset expression.
/// The calculated target and base addresses are returned in the locations
/// pointed by 'base' and 'target'. In case 'ri.base' is #BADADDR, the
/// function calculates the offset base address from the referencing
/// instruction/data address.
/// The target address is copied from ri.target. If ri.target is #BADADDR
/// then the target is calculated using the base address and 'opval'.
/// This function also checks if 'opval' matches the full value of the
/// reference and takes in account the memory-mapping.
/// \param  target  output target address
/// \param  base    output base address
/// \param  from    the referencing instruction/data address
/// \param  ri      reference info block from the database
/// \param  opval   operand value (usually op_t::value or op_t::addr)
/// \return success
idaman bool ida_export calc_reference_data(
        ea_t *target,
        ea_t *base,
        ea_t from,
        const refinfo_t &ri,
        adiff_t opval);


/// Add xrefs for a reference from the given instruction (\insn_t{ea}).
/// This function creates a cross references to the target and the base.
/// insn_t::add_off_drefs() calls this function to create xrefs for
/// 'offset' operand.
/// \param  insn   the referencing instruction
/// \param  from   the referencing instruction/data address
/// \param  ri     reference info block from the database
/// \param  opval  operand value (usually op_t::value or op_t::addr)
/// \param  type   type of xref
/// \param  opoff  offset of the operand from the start of instruction
/// \return the target address of the reference
idaman ea_t ida_export add_refinfo_dref(
        const insn_t &insn,
        ea_t from,
        const refinfo_t &ri,
        adiff_t opval,
        dref_t type,
        int opoff);


/// Calculates the target, using the provided refinfo_t

inline ea_t calc_target(ea_t from, adiff_t opval, const refinfo_t &ri)
{
  ea_t target;
  if ( !calc_reference_data(&target, nullptr, from, ri, opval) )
    return BADADDR;
  return target;
}

/// Retrieves refinfo_t structure and calculates the target

inline ea_t calc_target(ea_t from, ea_t ea, int n, adiff_t opval)
{
  refinfo_t ri;
  return get_refinfo(&ri, ea, n) ? calc_target(from, opval, ri) : BADADDR;
}

/// Calculate the value of the reference base.

inline ea_t calc_basevalue(ea_t target, ea_t base)
{
  return base - get_segm_base(getseg(target));
}

#endif  // _OFFSET_HPP
