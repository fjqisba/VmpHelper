/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _ENTRY_HPP
#define _ENTRY_HPP

/*! \file entry.hpp

  \brief Functions that deal with entry points

  Exported functions are considered as entry points as well.

  IDA maintains list of entry points to the program.
  Each entry point:
    - has an address
    - has a name
    - may have an ordinal number
*/

/// Get number of entry points

idaman size_t ida_export get_entry_qty(void);

/// \defgroup AEF_ entry flags
/// Passed as 'flags' parameter to add_entry(ea_t, const char *, int)
//@{
#define AEF_UTF8         0x0    ///< the name is given in UTF-8 (default)
#define AEF_IDBENC       0x1    ///< the name is given in the IDB encoding;
                                ///< non-ASCII bytes will be decoded accordingly.
                                ///< Specifying AEF_IDBENC also implies AEF_NODUMMY
#define AEF_NODUMMY      0x2    ///< automatically prepend the name with '_' if
                                ///< it begins with a dummy suffix. See also AEF_IDBENC
//@}


/// Add an entry point to the list of entry points.
/// \param ord       ordinal number
///                  if ordinal number is equal to 'ea' then ordinal is not used
/// \param ea        linear address
/// \param name      name of entry point. If the specified location already
///                  has a name, the old name will be appended to the regular
///                  comment. If name == nullptr, then the old name will be retained.
/// \param makecode  should the kernel convert bytes at the entry point
///                  to instruction(s)
/// \param flags     See AEF_*
/// \return success (currently always true)

idaman bool ida_export add_entry(uval_t ord, ea_t ea, const char *name, bool makecode, int flags=AEF_UTF8);


/// Get ordinal number of an entry point.
/// \param idx  internal number of entry point. Should be
///             in the range 0..get_entry_qty()-1
/// \return ordinal number or 0.

idaman uval_t ida_export get_entry_ordinal(size_t idx);


/// Get entry point address by its ordinal
/// \param ord  ordinal number of entry point
/// \return address or #BADADDR

idaman ea_t ida_export get_entry(uval_t ord);


/// Get name of the entry point by its ordinal.
/// \param buf      output buffer, may be nullptr
/// \param ord      ordinal number of entry point
/// \return size of entry name or -1

idaman ssize_t ida_export get_entry_name(qstring *buf, uval_t ord);


/// Rename entry point.
/// \param ord      ordinal number of the entry point
/// \param name     name of entry point. If the specified location already
///                 has a name, the old name will be appended to a repeatable
///                 comment.
/// \param flags    See AEF_*
/// \return success

idaman bool ida_export rename_entry(uval_t ord, const char *name, int flags=AEF_UTF8);


/// Set forwarder name for ordinal.
/// \param ord      ordinal number of the entry point
/// \param name     forwarder name for entry point.
/// \param flags    See AEF_*
/// \return success

idaman bool ida_export set_entry_forwarder(uval_t ord, const char *name, int flags=AEF_UTF8);


/// Get forwarder name for the entry point by its ordinal.
/// \param buf      output buffer, may be nullptr
/// \param ord      ordinal number of entry point
/// \return size of entry forwarder name or -1

idaman ssize_t ida_export get_entry_forwarder(qstring *buf, uval_t ord);


#endif // _ENTRY_HPP
