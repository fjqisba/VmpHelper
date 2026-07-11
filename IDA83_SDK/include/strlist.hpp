/*
 *      The Interactive Disassembler (IDA).
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _STRLIST_HPP
#define _STRLIST_HPP

/*! \file strlist.hpp

  \brief Functions that deal with the string list

  While the kernel keeps the string list, it does not update it.
  The string list is not used by the kernel because
  keeping it up-to-date would slow down IDA without any benefit.
  If the string list is not cleared using clear_strlist(), the list will be
  saved to the database and restored on the next startup.

  The users of this list should call build_strlist() if they need an
  up-to-date version.
*/

/// Structure to keep string list parameters
struct strwinsetup_t
{
  bytevec_t strtypes; // set of allowed string types
  sval_t minlen = -1;
  uchar display_only_existing_strings = 0;
  uchar only_7bit = 1;
  uchar ignore_heads = 0;
};

/// Information about one string from the string list
struct string_info_t
{
  ea_t ea;
  int length = 0; // in octets
  int type = 0;
  string_info_t(ea_t _ea=BADADDR) : ea(_ea) {}
  bool operator<(const string_info_t &r) const { return ea < r.ea; }
};
DECLARE_TYPE_AS_MOVABLE(string_info_t);


/// Get the static string list options

idaman const strwinsetup_t *ida_export get_strlist_options();


/// Rebuild the string list.

idaman void ida_export build_strlist();


/// Clear the string list.

idaman void ida_export clear_strlist();


/// Get number of elements in the string list.
/// The list will be loaded from the database (if saved) or
/// built from scratch.

idaman size_t ida_export get_strlist_qty(void);


/// Get nth element of the string list (n=0..get_strlist_qty()-1)

idaman bool ida_export get_strlist_item(string_info_t *si, size_t n);


#endif // _STRLIST_HPP
