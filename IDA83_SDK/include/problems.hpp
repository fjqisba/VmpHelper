/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _PROBLEMS_HPP
#define _PROBLEMS_HPP

/*! \file problems.hpp

  \brief Functions that deal with the list of problems.

  There are several problem lists. An address may be inserted to any list.
  The kernel simply maintains these lists, no additional processing
  is done.

  The problem lists are accessible for the user
  from the View->Subviews->Problems menu item.

  Addresses in the lists are kept sorted. In general IDA just maintains
  these lists without using them during analysis (except PR_ROLLED).

*/

typedef uchar problist_id_t; ///< see \ref PR_

/// \defgroup PR_ Problem types
//@{
const problist_id_t
  PR_NOBASE     =  1, ///< Can't find offset base
  PR_NONAME     =  2, ///< Can't find name
  PR_NOFOP      =  3, ///< Can't find forced op (not used anymore)
  PR_NOCMT      =  4, ///< Can't find comment (not used anymore)
  PR_NOXREFS    =  5, ///< Can't find references
  PR_JUMP       =  6, ///< Jump by table !!!! ignored
  PR_DISASM     =  7, ///< Can't disasm
  PR_HEAD       =  8, ///< Already head
  PR_ILLADDR    =  9, ///< Exec flows beyond limits
  PR_MANYLINES  = 10, ///< Too many lines
  PR_BADSTACK   = 11, ///< Failed to trace the value of the stack pointer
  PR_ATTN       = 12, ///< Attention! Probably erroneous situation.
  PR_FINAL      = 13, ///< Decision to convert to instruction/data is made by IDA
  PR_ROLLED     = 14, ///< The decision made by IDA was wrong and rolled back
  PR_COLLISION  = 15, ///< FLAIR collision: the function with the given name already exists
  PR_DECIMP     = 16, ///< FLAIR match indecision: the patterns matched, but not the function(s) being referenced
  PR_END        = 17; ///< Number of problem types
//@}

/// Get the human-friendly description of the problem,
/// if one was provided to remember_problem.
/// \param buf      a buffer to store the message into.
/// \param t        problem list type.
/// \param ea       linear address.
/// \return the message length or -1 if none

idaman ssize_t ida_export get_problem_desc(qstring *buf, problist_id_t t, ea_t ea);


/// Insert an address to a list of problems.
/// Display a message saying about the problem (except of ::PR_ATTN,::PR_FINAL)
/// ::PR_JUMP is temporarily ignored.
/// \param type  problem list type
/// \param ea    linear address
/// \param msg   a user-friendly message to be displayed instead of
///              the default more generic one associated with
///              the type of problem. Defaults to nullptr.

idaman void ida_export remember_problem(problist_id_t type, ea_t ea, const char *msg = nullptr);


/// Get an address from the specified problem list.
/// The address is not removed from the list.
/// \param type   problem list type
/// \param lowea  the returned address will be higher or equal
///               than the specified address
/// \return linear address or #BADADDR

idaman ea_t ida_export get_problem(problist_id_t type, ea_t lowea);


/// Remove an address from a problem list
/// \param type  problem list type
/// \param ea    linear address
/// \return success

idaman bool ida_export forget_problem(problist_id_t type, ea_t ea);


/// Get problem list description

idaman const char *ida_export get_problem_name(problist_id_t type, bool longname=true);


/// Check if the specified address is present in the problem list

idaman bool ida_export is_problem_present(problist_id_t t, ea_t ea);


inline bool was_ida_decision(ea_t ea) { return is_problem_present(PR_FINAL, ea); }


#endif  //  _PROBLEMS_HPP
