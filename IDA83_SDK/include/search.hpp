/*
 *      Interactive disassembler (IDA).
 *      ALL RIGHTS RESERVED.
 *      Copyright (c) 1990-2023 Hex-Rays
 *
 */

#ifndef __SEARCH_HPP
#define __SEARCH_HPP

/*! \file search.hpp

  \brief Middle-level search functions

  They all are controlled by \ref SEARCH_
*/

/// \defgroup SEARCH_ Search flags
//@{
#define SEARCH_UP       0x000           ///< search towards lower addresses
#define SEARCH_DOWN     0x001           ///< search towards higher addresses
#define SEARCH_NEXT     0x002           ///< skip the starting address when searching.
                                        ///< this bit is useful only for search(), bin_search2(), find_reg_access().
                                        ///< find_.. functions skip the starting address automatically.
#define SEARCH_CASE     0x004           ///< case-sensitive search (case-insensitive otherwise)
#define SEARCH_REGEX    0x008           ///< regular expressions in search string (supported only for the text search)
#define SEARCH_NOBRK    0x010           ///< do not test if the user clicked cancel to interrupt the search
#define SEARCH_NOSHOW   0x020           ///< do not display the search progress/refresh screen
#define SEARCH_IDENT    0x080           ///< search for an identifier (text search).
                                        ///< it means that the characters before
                                        ///< and after the match cannot be is_visible_char().
#define SEARCH_BRK      0x100           ///< return #BADADDR if the search was cancelled.
#define SEARCH_USE      0x200           ///< find_reg_access: search for a use (read access)
#define SEARCH_DEF      0x400           ///< find_reg_access: search for a definition (write access)
#define SEARCH_USESEL   0x800           ///< query the UI for a possible current
                                        ///< selection to limit the search to
//@}


/// Is the #SEARCH_DOWN bit set?

inline THREAD_SAFE bool search_down(int sflag)      { return (sflag & SEARCH_DOWN) != 0; }


/// \name find_... functions
/// \param ea          start ea
/// \param sflag       combination of \ref SEARCH_
/// \param[out] opnum  filled with operand number whenever relevant
/// \return first ea at which the search criteria is met
//@{


/// Find next error or problem

idaman ea_t ida_export find_error(ea_t ea, int sflag, int *opnum=nullptr);


/// Find next operand without any type info

idaman ea_t ida_export find_notype(ea_t ea, int sflag, int *opnum=nullptr);


/// Find next unexplored address

idaman ea_t ida_export find_unknown(ea_t ea, int sflag);


/// Find next ea that is the start of an instruction or data

idaman ea_t ida_export find_defined(ea_t ea, int sflag);


/// Find next suspicious operand

idaman ea_t ida_export find_suspop(ea_t ea, int sflag, int *opnum=nullptr);


/// Find next data address

idaman ea_t ida_export find_data(ea_t ea, int sflag);


/// Find next code address

idaman ea_t ida_export find_code(ea_t ea, int sflag);


/// Find next code address that does not belong to a function

idaman ea_t ida_export find_not_func(ea_t ea, int sflag);


/// Find next immediate operand with the given value

idaman ea_t ida_export find_imm(ea_t ea, int sflag, uval_t search_value, int *opnum=nullptr);


/// See search()

idaman ea_t ida_export find_text(ea_t start_ea, int y, int x, const char *ustr, int sflag);


/// Find access to a register.
/// \param out      pointer to the output buffer. must be non-null.
///                 upon success contains info about the found register.
///                 upon failed search for a read access out->range contains
///                 the info about the non-redefined parts of the register.
/// \param start_ea starting address
/// \param end_ea   ending address. BADADDR means that the end limit is missing.
///                 otherwise, if the search direction is SEARCH_UP,
///                 END_EA must be lower than START_EA.
/// \param regname  the register to search for.
/// \param sflag    combination of \ref SEARCH_ bits.
/// \note This function does not care about the control flow and
///       probes all instructions in the specified range, starting from START_EA.
///       Only direct references to registers are detected. Function calls and
///       system traps are ignored.
/// \return the found address. BADADDR if not found or error.
idaman ea_t ida_export find_reg_access(
        struct reg_access_t *out,
        ea_t start_ea,
        ea_t end_ea,
        const char *regname,
        int sflag);

//@}

class place_t;


/// Search for a text substring (low level function).
/// \param ud              line array parameter
/// \param[in,out] start   pointer to starting place:
///                          - start->ea:    starting address
///                          - start->lnnum: starting Y coordinate
/// \param end             pointer to ending place:
///                          - end->ea:       ending address
///                          - end->lnnum:    ending Y coordinate
/// \param[in,out] startx  pointer to starting X coordinate
/// \param str             substring to search for.
/// \param sflag           \ref SEARCH_
/// \retval 0  substring not found
/// \retval 1  substring found. The matching position is returned in:
///              - start->ea:       address
///              - start->lnnum:    Y coordinate
///              - *startx:         X coordinate
/// \retval 2  search was cancelled by ctrl-break.
///            The farthest searched address is
///            returned in the same manner as in the successful return (1).
/// \retval 3  the input regular expression is bad.
///            The error message was displayed.

idaman int ida_export search(
        void *ud,
        place_t *start,
        const place_t *end,
        int *startx,
        const char *str,
        int sflag);


#if !defined(NO_OBSOLETE_FUNCS)
idaman DEPRECATED int ida_export user2bin(uchar *, uchar *, ea_t, const char *, int, bool); // use parse_binpat_str()
idaman DEPRECATED ea_t ida_export find_binary(ea_t, ea_t, const char *, int, int); // use bin_search2()

#endif


#endif // __SEARCH_HPP
