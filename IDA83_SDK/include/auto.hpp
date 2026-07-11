/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _AUTO_HPP
#define _AUTO_HPP
#include <ida.hpp>

/*! \file auto.hpp

  \brief Functions that work with the autoanalyzer queue.

  The autoanalyzer works when IDA is not busy processing
  the user keystrokes. It has several queues, each queue having
  its own priority. The analyzer stops when all queues are empty.

  A queue contains addresses or address ranges.
  The addresses are kept sorted by their values.
  The analyzer will process all addresses from the first queue, then
  switch to the second queue and so on.
  There are no limitations on the size of the queues.

  This file also contains functions that deal with the IDA status
  indicator and the autoanalysis indicator.
  You may use these functions to change the indicator value.
*/

typedef int atype_t; ///< identifies an autoanalysis queue - see \ref AU_

/// \defgroup AU_ Autoanalysis queues
/// Names and priorities of the analyzer queues
//@{
const atype_t
  AU_NONE = 00,         ///< placeholder, not used
  AU_UNK  = 10,         ///<  0: convert to unexplored
  AU_CODE = 20,         ///<  1: convert to instruction
  AU_WEAK = 25,         ///<  2: convert to instruction (ida decision)
  AU_PROC = 30,         ///<  3: convert to procedure start
  AU_TAIL = 35,         ///<  4: add a procedure tail
  AU_FCHUNK=38,         ///<  5: find func chunks
  AU_USED = 40,         ///<  6: reanalyze
  AU_TYPE = 50,         ///<  7: apply type information
  AU_LIBF = 60,         ///<  8: apply signature to address
  AU_LBF2 = 70,         ///<  9: the same, second pass
  AU_LBF3 = 80,         ///< 10: the same, third pass
  AU_CHLB = 90,         ///< 11: load signature file (file name is kept separately)
  AU_FINAL=200;         ///< 12: final pass
//@}


typedef int idastate_t; ///< IDA status indicator - see \ref st_

/// \defgroup st_ Status indicator states
//@{
const idastate_t
                         //                      meaning
  st_Ready   = 0,        ///< READY:             IDA is doing nothing
  st_Think   = 1,        ///< THINKING:          Autoanalysis on, the user may press keys
  st_Waiting = 2,        ///< WAITING:           Waiting for the user input
  st_Work    = 3;        ///< BUSY:              IDA is busy
//@}


/// Get current state of autoanalyzer.
/// If auto_state == ::AU_NONE, IDA is currently not running the analysis
/// (it could be temporarily interrupted to perform the user's requests, for example).

idaman atype_t ida_export get_auto_state(void);


/// Set current state of autoanalyzer.
/// \param new_state  new state of autoanalyzer
/// \return previous state

idaman atype_t ida_export set_auto_state(atype_t new_state);


/// See ::get_auto_display
struct auto_display_t
{
  atype_t type = AU_NONE;
  ea_t ea = BADADDR;
  idastate_t state = st_Ready;
};

/// Get structure which holds the autoanalysis indicator contents

idaman bool ida_export get_auto_display(auto_display_t *auto_display);


/// Change autoanalysis indicator value.
/// \param ea    linear address being analyzed
/// \param type  autoanalysis type (see \ref AU_)

idaman void ida_export show_auto(ea_t ea, atype_t type=AU_NONE);


/// Show an address on the autoanalysis indicator.
/// The address is displayed in the form " @:12345678".
/// \param ea - linear address to display

inline void show_addr(ea_t ea) { show_auto(ea); }


/// Change IDA status indicator value
/// \param st - new indicator status
/// \return old indicator status

idaman idastate_t ida_export set_ida_state(idastate_t st);


/// Is it allowed to create stack variables automatically?.
/// This function should be used by IDP modules before creating stack vars.

inline bool may_create_stkvars(void)
{
  return inf_should_create_stkvars() && get_auto_state() == AU_USED;
}


/// Is it allowed to trace stack pointer automatically?.
/// This function should be used by IDP modules before tracing sp.

inline bool may_trace_sp(void)
{
  if ( inf_should_trace_sp() )
  {
    atype_t auto_state = get_auto_state();
    return auto_state == AU_USED;
  }
  return false;
}


/// Put range of addresses into a queue.
/// 'start' may be higher than 'end', the kernel will swap them in this case.
/// 'end' doesn't belong to the range.

idaman void ida_export auto_mark_range(ea_t start, ea_t end, atype_t type);


/// Put single address into a queue. Queues keep addresses sorted.

inline void auto_mark(ea_t ea, atype_t type)
{
  auto_mark_range(ea, ea+1, type);
}


/// Remove range of addresses from a queue.
/// 'start' may be higher than 'end', the kernel will swap them in this case.
/// 'end' doesn't belong to the range.

idaman void ida_export auto_unmark(ea_t start, ea_t end, atype_t type);

// Convenience functions

/// Plan to perform reanalysis
inline void plan_ea(ea_t ea)
{
  auto_mark(ea, AU_USED);
}
/// Plan to perform reanalysis
inline void plan_range(ea_t sEA, ea_t eEA)
{
  auto_mark_range(sEA, eEA, AU_USED);
}
/// Plan to make code
inline void auto_make_code(ea_t ea)
{
  auto_mark(ea, AU_CODE);
}
/// Plan to make code&function
inline void auto_make_proc(ea_t ea)
{
  auto_make_code(ea);
  auto_mark(ea, AU_PROC);
}

/// Plan to reanalyze callers of the specified address.
/// This function will add to ::AU_USED queue all instructions that
/// call (not jump to) the specified address.
/// \param ea     linear address of callee
/// \param noret  !=0: the callee doesn't return, mark to undefine subsequent
///               instructions in the caller. 0: do nothing.

idaman void ida_export reanalyze_callers(ea_t ea, bool noret);


/// Delete all analysis info that IDA generated for for the given range

idaman void ida_export revert_ida_decisions(ea_t ea1, ea_t ea2);


/// Plan to apply the callee's type to the calling point

idaman void ida_export auto_apply_type(ea_t caller, ea_t callee);

/// Plan to apply the tail_ea chunk to the parent
/// \param tail_ea   linear address of start of tail
/// \param parent_ea linear address within parent.  If BADADDR, automatically
///                  try to find parent via xrefs.

idaman void ida_export auto_apply_tail(ea_t tail_ea, ea_t parent_ea);

/// Analyze the specified range.
/// Try to create instructions where possible.
/// Make the final pass over the specified range if specified.
/// This function doesn't return until the range is analyzed.
/// \retval 1  ok
/// \retval 0  Ctrl-Break was pressed

idaman int ida_export plan_and_wait(ea_t ea1, ea_t ea2, bool final_pass=true);


/// Process everything in the queues and return true.
/// \return false if the user clicked cancel.
///         (the wait box must be displayed by the caller if desired)

idaman bool ida_export auto_wait(void);


/// Process everything in the specified range and return true.
/// \return number of autoanalysis steps made. -1 if the user clicked cancel.
///         (the wait box must be displayed by the caller if desired)

idaman ssize_t ida_export auto_wait_range(ea_t ea1, ea_t ea2);


/// Analyze one address in the specified range and return true.
/// \return if processed anything. false means that there is nothing to
///         process in the specified range.

idaman bool ida_export auto_make_step(ea_t ea1, ea_t ea2);


/// Remove an address range (ea1..ea2) from queues ::AU_CODE, ::AU_PROC, ::AU_USED.
/// To remove an address range from other queues use auto_unmark() function.
/// 'ea1' may be higher than 'ea2', the kernel will swap them in this case.
/// 'ea2' doesn't belong to the range.

idaman void ida_export auto_cancel(ea_t ea1, ea_t ea2);


/// Are all queues empty?
/// (i.e. has autoanalysis finished?).

idaman bool ida_export auto_is_ok(void);


/// Peek into a queue 'type' for an address not lower than 'low_ea'.
/// Do not remove address from the queue.
/// \return the address or #BADADDR

idaman ea_t ida_export peek_auto_queue(ea_t low_ea, atype_t type);


/// Retrieve an address from queues regarding their priority.
/// Returns #BADADDR if no addresses not lower than 'lowEA' and less than
/// 'highEA' are found in the queues.
/// Otherwise *type will have queue type.

idaman ea_t ida_export auto_get(atype_t *type, ea_t lowEA, ea_t highEA);


/// Try to create instruction
/// \param ea     linear address of callee
/// \return the length of the instruction or 0

idaman int ida_export auto_recreate_insn(ea_t ea);


/// Get autoanalyzer state

idaman bool ida_export is_auto_enabled(void);


/// Temporarily enable/disable autoanalyzer. Not user-facing, but rather because
/// IDA sometimes need to turn AA on/off regardless of inf.s_genflags:INFFL_AUTO
/// \return old state

idaman bool ida_export enable_auto(bool enable);



#endif  //  _AUTO_HPP
