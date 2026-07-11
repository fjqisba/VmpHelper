/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      Enums and bitfields
 *      Bitfields will be abbreviated as "bf".
 *
 */

#ifndef _ENUM_HPP
#define _ENUM_HPP

#include <nalt.hpp>

/*! \file enum.hpp

   \brief Assembly level enum management

   Enums and bitfields are represented as ::enum_t.
*/

typedef tid_t enum_t;         ///< Enums and bitfields

typedef uval_t bmask_t;       ///< unsigned value that describes a bitmask
                              ///< a bit mask is 32/64 bits.

#define DEFMASK (bmask_t(-1)) ///< default bitmask

typedef uval_t const_t;       ///< members of enums

/// Max number of identical constants allowed for one enum type
const uchar MAX_ENUM_SERIAL = 255;


/// Get number of declared ::enum_t types

idaman size_t ida_export get_enum_qty(void);


/// Get enum by its index in the list of enums (0..get_enum_qty()-1).

idaman enum_t ida_export getn_enum(size_t idx);


/// Get the index in the list of enums

idaman uval_t ida_export get_enum_idx(enum_t id);


/// Get enum by name

idaman enum_t ida_export get_enum(const char *name);


/// Is enum a bitfield?
/// (otherwise - plain enum, no bitmasks except for #DEFMASK are allowed)

idaman bool ida_export is_bf(enum_t id);


/// Is enum collapsed?

idaman bool ida_export is_enum_hidden(enum_t id);


/// Collapse enum

idaman bool ida_export set_enum_hidden(enum_t id, bool hidden);


/// Does enum come from type library?

idaman bool ida_export is_enum_fromtil(enum_t id);


/// Specify that enum comes from a type library

idaman bool ida_export set_enum_fromtil(enum_t id, bool fromtil);


/// Is a ghost copy of a local type?

idaman bool ida_export is_ghost_enum(enum_t id);


/// Specify that enum is a ghost copy of a local type

idaman bool ida_export set_enum_ghost(enum_t id, bool ghost);


/// Get name of enum

idaman ssize_t ida_export get_enum_name(qstring *out, enum_t id);

/// Get name of enum
/// \param[out] out  buffer to hold the name
/// \param id        enum id
/// \param flags     \ref ENFL_

idaman ssize_t ida_export get_enum_name2(qstring *out, enum_t id, int flags=0);

/// \defgroup ENFL_ Enum name flags
/// Passed as 'flags' parameter to get_enum_name()
//@{
#define ENFL_REGEX    0x0001    ///< apply regular expressions to beautify the name
//@}

inline qstring get_enum_name(tid_t id, int flags=0)
{
  qstring name;
  get_enum_name2(&name, id, flags);
  return name;
}


/// Get the width of a enum element
/// allowed values: 0 (unspecified),1,2,4,8,16,32,64

idaman size_t ida_export get_enum_width(enum_t id);


/// See comment for get_enum_width()

idaman bool ida_export set_enum_width(enum_t id, int width);


/// Get enum comment

idaman ssize_t ida_export get_enum_cmt(qstring *buf, enum_t id, bool repeatable);


/// Get the number of the members of the enum

idaman size_t ida_export get_enum_size(enum_t id);


/// Get flags determining the representation of the enum.
/// (currently they define the numeric base: octal, decimal, hex, bin) and signness.

idaman flags64_t ida_export get_enum_flag(enum_t id);


/// Get a reference to an enum member by its name

idaman const_t ida_export get_enum_member_by_name(const char *name);


/// Get value of an enum member

idaman uval_t ida_export get_enum_member_value(const_t id);


/// Get the parent enum of an enum member

idaman enum_t ida_export get_enum_member_enum(const_t id);


/// Get bitmask of an enum member

idaman bmask_t ida_export get_enum_member_bmask(const_t id);


/// Find an enum member by enum, value and bitmask
/// \note if serial -1, return a member with any serial

idaman const_t ida_export get_enum_member(enum_t id, uval_t value, int serial, bmask_t mask);


/// \name Access to all used bitmasks in an enum
//@{

/// Get first bitmask in the enum (bitfield)
/// \param enum_id id of enum (bitfield)
/// \return the smallest bitmask for enum, or DEFMASK
///
idaman bmask_t ida_export get_first_bmask(enum_t enum_id);

/// Get last bitmask in the enum (bitfield)
/// \param enum_id id of enum
/// \return the biggest bitmask for enum, or DEFMASK
idaman bmask_t ida_export get_last_bmask(enum_t enum_id);

/// Get next bitmask in the enum (bitfield)
/// \param enum_id id of enum
/// \param bmask the current bitmask
/// \return value of a bitmask with value higher than the specified value, or DEFMASK
idaman bmask_t ida_export get_next_bmask(enum_t enum_id, bmask_t bmask);

/// Get prev bitmask in the enum (bitfield)
/// \param enum_id id of enum
/// \param bmask the current bitmask
/// \return value of a bitmask with value lower than the specified value, or DEFMASK
idaman bmask_t ida_export get_prev_bmask(enum_t enum_id, bmask_t bmask);
//@}

/// \name Access to all enum members with specified bitmask
/// \note these functions return values, not ::const_t!
//@{
idaman uval_t ida_export get_first_enum_member(enum_t id, bmask_t bmask=DEFMASK);
idaman uval_t ida_export get_last_enum_member(enum_t id, bmask_t bmask=DEFMASK);
idaman uval_t ida_export get_next_enum_member(enum_t id, uval_t value, bmask_t bmask=DEFMASK);
idaman uval_t ida_export get_prev_enum_member(enum_t id, uval_t value, bmask_t bmask=DEFMASK);
//@}


/// Get name of an enum member by const_t

idaman ssize_t ida_export get_enum_member_name(qstring *out, const_t id);


/// Get enum member's comment

idaman ssize_t ida_export get_enum_member_cmt(qstring *buf, const_t id, bool repeatable);


/// \name Access to all enum members with specified value and mask
/// A sample loop looks like this:
/// \code
///   const_t main_cid;
///   uchar serial;
///   for ( const_t cid=main_cid=get_first_serial_enum_member(&serial, id, v, mask);
///         cid != BADNODE;
///         cid = get_next_serial_enum_member(&serial, main_cid) )
///   {
///     ...
///   }
/// \endcode
/// The 'out_serial' argument of get_first_serial_enum_member/get_last_serial_enum_member can be nullptr.
/// The 'in_out_serial' is required for the other functions.
//@{
idaman const_t ida_export get_first_serial_enum_member(uchar *out_serial, enum_t id, uval_t value, bmask_t bmask);
idaman const_t ida_export get_last_serial_enum_member(uchar *out_serial, enum_t id, uval_t value, bmask_t bmask);
idaman const_t ida_export get_next_serial_enum_member(uchar *in_out_serial, const_t first_cid);
idaman const_t ida_export get_prev_serial_enum_member(uchar *in_out_serial, const_t first_cid);
//@}


/// Enum member visitor - see for_all_enum_members().
/// Derive your visitor from this class.
struct enum_member_visitor_t
{
  /// Implements action to take when enum member is visited.
  /// \return nonzero to stop the iteration
  virtual int idaapi visit_enum_member(const_t cid, uval_t value) = 0;
};


/// Visit all members of a given enum

idaman int ida_export for_all_enum_members(enum_t id, enum_member_visitor_t &cv);


/// Get serial number of an enum member

idaman uchar ida_export get_enum_member_serial(const_t cid);


/// Get corresponding type ordinal number

idaman int32 ida_export get_enum_type_ordinal(enum_t id);


/// Set corresponding type ordinal number

idaman void ida_export set_enum_type_ordinal(enum_t id, int32 ord);


//--------------------------------------------------------------------------
// MANIPULATION

/// Add new enum type.
///   - if idx==#BADADDR then add as the last idx
///   - if name==nullptr then generate a unique name "enum_%d"

idaman enum_t ida_export add_enum(size_t idx, const char *name, flags64_t flag);


/// Delete an enum type

idaman void ida_export del_enum(enum_t id);


/// Set serial number of enum.
/// Also see get_enum_idx().

idaman bool ida_export set_enum_idx(enum_t id, size_t idx);


/// Set 'bitfield' bit of enum (i.e. convert it to a bitfield)

idaman bool ida_export set_enum_bf(enum_t id, bool bf);


/// Set name of enum type

idaman bool ida_export set_enum_name(enum_t id, const char *name);


/// Set comment for enum type

idaman bool ida_export set_enum_cmt(enum_t id, const char *cmt, bool repeatable);


/// Set data representation flags

idaman bool ida_export set_enum_flag(enum_t id, flags64_t flag);


/// Add member to enum type.
/// \return 0 if ok, otherwise one of \ref ENUM_MEMBER_

idaman int ida_export add_enum_member(
        enum_t id,
        const char *name,
        uval_t value,
        bmask_t bmask=DEFMASK);


/// \defgroup ENUM_MEMBER_ Add enum member result codes
/// Return values for add_enum_member()
//@{
#define ENUM_MEMBER_ERROR_NAME  1     ///< already have member with this name (bad name)
#define ENUM_MEMBER_ERROR_VALUE 2     ///< already have 256 members with this value
#define ENUM_MEMBER_ERROR_ENUM  3     ///< bad enum id
#define ENUM_MEMBER_ERROR_MASK  4     ///< bad bmask
#define ENUM_MEMBER_ERROR_ILLV  5     ///< bad bmask and value combination (~bmask & value != 0)
//@}


/// Delete member of enum type

idaman bool ida_export del_enum_member(enum_t id, uval_t value, uchar serial, bmask_t bmask);


/// Set name of enum member

idaman bool ida_export set_enum_member_name(const_t id, const char *name);


/// Set comment for enum member

inline bool set_enum_member_cmt(const_t id, const char *cmt, bool repeatable)
{
  return set_enum_cmt(id, cmt, repeatable);
}


///  Is bitmask one bit?

inline THREAD_SAFE bool is_one_bit_mask(bmask_t mask)
{
  return is_pow2(mask);
}


/// \name Work with the bitmask name & comment
//@{
idaman bool    ida_export set_bmask_name(enum_t id, bmask_t bmask, const char *name);
idaman ssize_t ida_export get_bmask_name(qstring *out, enum_t id, bmask_t bmask);

idaman bool    ida_export set_bmask_cmt(enum_t id, bmask_t bmask, const char *cmt, bool repeatable);
idaman ssize_t ida_export get_bmask_cmt(qstring *buf, enum_t id, bmask_t bmask, bool repeatable);
//@}

#endif // _ENUM_HPP
