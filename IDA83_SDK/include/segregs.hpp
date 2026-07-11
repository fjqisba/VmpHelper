/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _SRAREA_HPP
#define _SRAREA_HPP

#include <range.hpp>
#include <segment.hpp>

/*! \file segregs.hpp

  \brief Functions that deal with the segment registers.

  If your processor doesn't use segment registers, then these functions
  are of no use for you. However, you should define
  two virtual segment registers - CS and DS (for code segment and
  data segment) and specify their internal numbers in the LPH structure
  (processor_t::reg_code_sreg and processor_t::reg_data_sreg).
*/

//-------------------------------------------------------------------------
/// The values of the segment registers are kept as address ranges. The segment
/// register does not change its value within one address range.
/// The processor module finds segment register change points and splits
/// ::sreg_range_t ranges so that a new sreg_range_t range is started at
/// each segment register change point. The kernel deletes sreg_range_t
/// if an instruction is converted back to unexplored bytes.
///
/// So, we have information about a segment register by keeping information
/// about the range of addresses where segment register does not change the value.
///
/// Note that each segment has information about the default values of
/// the segment registers. This information is used if the value of a segment
/// register could not be determined.
struct sreg_range_t : public range_t
{
  sel_t val;                ///< segment register value
  uchar tag;                ///< \ref SR_

/// \defgroup SR_ Segment register range tags
/// Used by sreg_range_t::tag
//@{
#define SR_inherit      1   ///< the value is inherited from the previous range
#define SR_user         2   ///< the value is specified by the user
#define SR_auto         3   ///< the value is determined by IDA
#define SR_autostart    4   ///< used as #SR_auto for segment starting address
//@}
};
DECLARE_TYPE_AS_MOVABLE(sreg_range_t);


/// Get value of a segment register.
/// This function uses segment register range and default segment register
/// values stored in the segment structure.
/// \param ea  linear address in the program
/// \param rg  number of the segment register
/// \return value of the segment register, #BADSEL if value is unknown.

idaman sel_t ida_export get_sreg(ea_t ea, int rg);


/// Create a new segment register range.
/// This function is used when the IDP emulator detects that a segment
/// register changes its value.
/// \param ea      linear address where the segment register will
///                have a new value. if ea==#BADADDR, nothing to do.
/// \param rg      the number of the segment register
/// \param v       the new value of the segment register. If the value is
///                unknown, you should specify #BADSEL.
/// \param tag     the register info tag. see \ref SR_
/// \param silent  if false, display a warning() in the case of failure
/// \return success

idaman bool ida_export split_sreg_range(
        ea_t ea,
        int rg,
        sel_t v,
        uchar tag,
        bool silent=false);


/// Set default value of a segment register for a segment.
/// \param sg     pointer to segment structure
///               if nullptr, then set the register for all segments
/// \param rg     number of segment register
/// \param value  its default value. this value will be used by get_sreg()
///               if value of the register is unknown at the specified address.
/// \return success

idaman bool ida_export set_default_sreg_value(segment_t *sg, int rg, sel_t value);


/// Set the segment register value at the next instruction.
/// This function is designed to be called from idb_event::sgr_changed handler
/// in order to contain the effect of changing a segment
/// register value only until the next instruction.
///
/// It is useful, for example, in the ARM module: the modification
/// of the T register does not affect existing instructions later in the code.
/// \param ea1    address to start to search for an instruction
/// \param ea2    the maximal address
/// \param rg     the segment register number
/// \param value  the segment register value

idaman void ida_export set_sreg_at_next_code(ea_t ea1, ea_t ea2, int rg, sel_t value);


/// Get segment register range by linear address.
/// \param out  segment register range
/// \param ea   any linear address in the program
/// \param rg   the segment register number
/// \return success

idaman bool ida_export get_sreg_range(sreg_range_t *out, ea_t ea, int rg);


/// Get segment register range previous to one with address.
/// \note more efficient then get_sreg_range(reg, ea-1)
/// \param out  segment register range
/// \param ea   any linear address in the program
/// \param rg   the segment register number
/// \return success

idaman bool ida_export get_prev_sreg_range(sreg_range_t *out, ea_t ea, int rg);


/// Set default value of DS register for all segments

idaman void ida_export set_default_dataseg(sel_t ds_sel);


/// Get number of segment register ranges.
/// \param rg  the segment register number

idaman size_t ida_export get_sreg_ranges_qty(int rg);


/// Get segment register range by its number.
/// \param out  segment register range
/// \param rg   the segment register number
/// \param n    number of range (0..qty()-1)
/// \return success

idaman bool ida_export getn_sreg_range(sreg_range_t *out, int rg, int n);


/// Get number of segment register range by address.
/// \param ea  any address in the range
/// \param rg  the segment register number
/// \return -1 if no range occupies the specified address.
///         otherwise returns number of
///         the specified range (0..get_srranges_qty()-1)

idaman int ida_export get_sreg_range_num(ea_t ea, int rg);


/// Delete segment register range started at ea.
/// When a segment register range is deleted,
/// the previous range is extended to cover the empty space.
/// The segment register range at the beginning of a segment cannot be deleted.
/// \param ea  start_ea of the deleted range
/// \param rg  the segment register number
/// \return success

idaman bool ida_export del_sreg_range(ea_t ea, int rg);


/// Duplicate segment register ranges.
/// \param dst_rg        number of destination segment register
/// \param src_rg        copy ranges from
/// \param map_selector  map selectors to linear addresses using sel2ea()

idaman void ida_export copy_sreg_ranges(int dst_rg, int src_rg, bool map_selector=false);


#endif // _SRAREA_HPP
