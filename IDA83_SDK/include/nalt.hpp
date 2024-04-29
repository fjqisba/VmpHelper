/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef NALT_HPP
#define NALT_HPP

#include <ida.hpp>
#include <netnode.hpp>

/*! \file nalt.hpp

  \brief Definitions of various information kept in netnodes

  Each address in the program has a corresponding netnode: netnode(ea).

  If we have no information about an address, the corresponding
  netnode is not created.
  Otherwise we will create a netnode and save information in it.
  All variable length information (names, comments, offset information, etc)
  is stored in the netnode.

  Don't forget that some information is already stored in the flags (bytes.hpp)

  \warning
  Many of the functions in this file are very low level (they are marked
  as low level functions). Use them only if you can't find higher level
  function to set/get/del information.

  You can create your own nodes in IDP module and store information
  in them. See ::netnode.
*/

/// \defgroup NALT_ Structure of altvals array
/// Structure of altvals array of netnode(ea).
/// altvals is a virtual array of 32-bit longs attached to a netnode.
/// the size of this array is unlimited. Unused indexes are not kept in the
/// database. We use only first several indexes to this array.
//@{
#define  NALT_ENUM      uval_t(-2) ///< reserved for enums, see enum.hpp
#define  NALT_WIDE      uval_t(-1) ///< 16-bit byte value
#define  NALT_SWITCH    1          ///< switch idiom address (used at jump targets)
//#define  NALT_OBASE1    2        // offset base 2
#define  NALT_STRUCT    3          ///< struct id
//#define  NALT_SEENF     4        // 'seen' flag (used in structures)
//#define  NALT_OOBASE0   5        // outer offset base 1
//#define  NALT_OOBASE1   6        // outer offset base 2
//#define  NALT_XREFPOS   7        // saved xref address in the xrefs window
#define  NALT_AFLAGS    8          ///< additional flags for an item
#define  NALT_LINNUM    9          ///< source line number
#define  NALT_ABSBASE  10          ///< absolute segment location
#define  NALT_ENUM0    11          ///< enum id for the first operand
#define  NALT_ENUM1    12          ///< enum id for the second operand
//#define  NALT_STROFF0  13        // struct offset, struct id for the first operand
//#define  NALT_STROFF1  14        // struct offset, struct id for the second operand
#define  NALT_PURGE    15          ///< number of bytes purged from the stack when a function is called indirectly
#define  NALT_STRTYPE  16          ///< type of string item
#define  NALT_ALIGN    17          ///< alignment value if the item is #FF_ALIGN
                                   ///< (should by equal to power of 2)
//#define  NALT_HIGH0    18        // linear address of byte referenced by
//                                 // high 16 bits of an offset (FF_0HIGH)
//#define  NALT_HIGH1    19        // linear address of byte referenced by
//                                 // high 16 bits of an offset (FF_1HIGH)
#define  NALT_COLOR    20          ///< instruction/data background color
//@}

/// \defgroup NSUP_ Structure of supvals array
/// Structure of supvals array of netnode(ea).
/// Supvals is a virtual array of objects of arbitrary length attached
/// to a netnode (length of one element is limited by #MAXSPECSIZE, though)
/// We use first several indexes to this array:
//@{
#define  NSUP_CMT       0       ///< regular comment
#define  NSUP_REPCMT    1       ///< repeatable comment
#define  NSUP_FOP1      2       ///< forced operand 1
#define  NSUP_FOP2      3       ///< forced operand 2
#define  NSUP_JINFO     4       ///< jump table info
#define  NSUP_ARRAY     5       ///< array parameters
#define  NSUP_OMFGRP    6       ///< OMF: group of segments (not used anymore)
#define  NSUP_FOP3      7       ///< forced operand 3
#define  NSUP_SWITCH    8       ///< switch information
#define  NSUP_REF0      9       ///< complex reference information for operand 1
#define  NSUP_REF1      10      ///< complex reference information for operand 2
#define  NSUP_REF2      11      ///< complex reference information for operand 3
#define  NSUP_OREF0     12      ///< outer complex reference information for operand 1
#define  NSUP_OREF1     13      ///< outer complex reference information for operand 2
#define  NSUP_OREF2     14      ///< outer complex reference information for operand 3
#define  NSUP_STROFF0   15      ///< stroff: struct path for the first operand
#define  NSUP_STROFF1   16      ///< stroff: struct path for the second operand
#define  NSUP_SEGTRANS  17      ///< segment translations
#define  NSUP_FOP4      18      ///< forced operand 4
#define  NSUP_FOP5      19      ///< forced operand 5
#define  NSUP_FOP6      20      ///< forced operand 6
#define  NSUP_REF3      21      ///< complex reference information for operand 4
#define  NSUP_REF4      22      ///< complex reference information for operand 5
#define  NSUP_REF5      23      ///< complex reference information for operand 6
#define  NSUP_OREF3     24      ///< outer complex reference information for operand 4
#define  NSUP_OREF4     25      ///< outer complex reference information for operand 5
#define  NSUP_OREF5     26      ///< outer complex reference information for operand 6
#define  NSUP_XREFPOS   27      ///< saved xref address and type in the xrefs window
#define  NSUP_CUSTDT    28      ///< custom data type id
#define  NSUP_GROUPS    29      ///< SEG_GRP: pack_dd encoded list of selectors
#define  NSUP_ARGEAS    30      ///< instructions that initialize call arguments
#define  NSUP_FOP7      31      ///< forced operand 7
#define  NSUP_FOP8      32      ///< forced operand 8
#define  NSUP_REF6      33      ///< complex reference information for operand 7
#define  NSUP_REF7      34      ///< complex reference information for operand 8
#define  NSUP_OREF6     35      ///< outer complex reference information for operand 7
#define  NSUP_OREF7     36      ///< outer complex reference information for operand 8
#define  NSUP_EX_FLAGS  37      ///< Extended flags

// values E_PREV..E_NEXT+1000 are reserved (1000..2000..3000 decimal)

/// SP change points blob (see funcs.cpp).
/// values NSUP_POINTS..NSUP_POINTS+0x1000 are reserved
#define  NSUP_POINTS    0x1000

/// manual instruction.
/// values NSUP_MANUAL..NSUP_MANUAL+0x1000 are reserved
#define  NSUP_MANUAL    0x2000

/// type information.
/// values NSUP_TYPEINFO..NSUP_TYPEINFO+0x1000 are reserved
#define  NSUP_TYPEINFO  0x3000

/// register variables.
/// values NSUP_REGVAR..NSUP_REGVAR+0x1000 are reserved
#define  NSUP_REGVAR    0x4000

/// local labels.
/// values NSUP_LLABEL..NSUP_LLABEL+0x1000 are reserved
#define  NSUP_LLABEL    0x5000

/// register argument type/name descriptions
/// values NSUP_REGARG..NSUP_REGARG+0x1000 are reserved
#define  NSUP_REGARG    0x6000

/// function tails or tail referers
/// values NSUP_FTAILS..NSUP_FTAILS+0x1000 are reserved
#define  NSUP_FTAILS    0x7000

/// graph group information
/// values NSUP_GROUP..NSUP_GROUP+0x1000 are reserved
#define  NSUP_GROUP     0x8000

/// operand type information.
/// values NSUP_OPTYPES..NSUP_OPTYPES+0x100000 are reserved
#define  NSUP_OPTYPES   0x9000

/// function metadata before lumina information was applied
/// values NSUP_ORIGFMD..NSUP_ORIGFMD+0x1000 are reserved
#define  NSUP_ORIGFMD   0x109000

//@}

/// \defgroup NALT_X Netnode xref tags
/// Tag values to store xrefs (see cref.cpp)
//@{
#define NALT_CREF_TO         'X'     ///< code xref to, idx: target address
#define NALT_CREF_FROM       'x'     ///< code xref from, idx: source address
#define NALT_DREF_TO         'D'     ///< data xref to, idx: target address
#define NALT_DREF_FROM       'd'     ///< data xref from, idx: source address
//@}

/// \defgroup N_TAG Netnode graph tags
/// Tag values to store graph info
//@{
#define NSUP_GR_INFO         'g'     ///< group node info: color, ea, text
#define NALT_GR_LAYX         'p'     ///< group layout ptrs, hash: md5 of 'belongs'
#define NSUP_GR_LAYT         'l'     ///< group layouts, idx: layout pointer
//@}

/// Patch netnode tag
#define PATCH_TAG 'P'

/// \defgroup N_DESK UI desktops
//@{
#define IDB_DESKTOPS_NODE_NAME "$ desktops"
                                     ///< hash indexed by desktop name with dekstop netnode
#define IDB_DESKTOPS_TAG       'S'   ///< tag to store desktop blob & timestamp
#define IDB_DESKTOPS_TIMESTAMP nodeidx_t(-1)
                                     ///< desktop timestamp index
//@}


/// Get netnode for the specified address.

idaman nodeidx_t ida_export ea2node(ea_t ea);
idaman ea_t ida_export node2ea(nodeidx_t ndx);
inline netnode getnode(ea_t ea) { return netnode(ea2node(ea)); }

//--------------------------------------------------------------------------
//      C O N V E N I E N C E   F U N C T I O N S
//--------------------------------------------------------------------------

/// \name Get structure ID
/// Returns the struct id of the struct type at the specified address.
/// Use this function when is_struct()==true
//@{

idaman tid_t ida_export get_strid(ea_t ea);

//@}

/// \name xrefpos
//@{
/// Position of cursor in the window with cross-references to the address.
/// Used by the user-interface.
struct xrefpos_t
{
  ea_t ea;
  uchar type;  // the type of xref (::cref_t & ::dref_t)
  xrefpos_t(ea_t ea_ = BADADDR, uchar type_ = 0) : ea(ea_), type(type_) {}
  bool is_valid() const { return ea != BADADDR; }
};

idaman ssize_t ida_export get_xrefpos(xrefpos_t *out, ea_t ea);
idaman void ida_export set_xrefpos(ea_t ea, const xrefpos_t *in);
inline void idaapi del_xrefpos(ea_t ea) { getnode(ea).supdel(NSUP_XREFPOS); }

//@}

/// \defgroup AFL_ Additional flags for the location
/// All 32-bits of the main flags (bytes.hpp) are used up.
/// Additional flags keep more information about addresses.
/// AFLNOTE: DO NOT use these flags directly unless there is absolutely no way.
/// They are too low level and may corrupt the database.
//@{
#define AFL_LINNUM      0x00000001L     ///< has line number info
#define AFL_USERSP      0x00000002L     ///< user-defined SP value
#define AFL_PUBNAM      0x00000004L     ///< name is public (inter-file linkage)
#define AFL_WEAKNAM     0x00000008L     ///< name is weak
#define AFL_HIDDEN      0x00000010L     ///< the item is hidden completely
#define AFL_MANUAL      0x00000020L     ///< the instruction/data is specified by the user
#define AFL_NOBRD       0x00000040L     ///< the code/data border is hidden
#define AFL_ZSTROFF     0x00000080L     ///< display struct field name at 0 offset when displaying an offset.
                                        ///< example:
                                        ///<   \v{offset somestruct.field_0}
                                        ///< if this flag is clear, then
                                        ///<   \v{offset somestruct}
#define AFL_BNOT0       0x00000100L     ///< the 1st operand is bitwise negated
#define AFL_BNOT1       0x00000200L     ///< the 2nd operand is bitwise negated
#define AFL_LIB         0x00000400L     ///< item from the standard library.
                                        ///< low level flag, is used to set
                                        ///< #FUNC_LIB of ::func_t
#define AFL_TI          0x00000800L     ///< has typeinfo? (#NSUP_TYPEINFO); used only for addresses, not for member_t
#define AFL_TI0         0x00001000L     ///< has typeinfo for operand 0? (#NSUP_OPTYPES)
#define AFL_TI1         0x00002000L     ///< has typeinfo for operand 1? (#NSUP_OPTYPES+1)
#define AFL_LNAME       0x00004000L     ///< has local name too (#FF_NAME should be set)
#define AFL_TILCMT      0x00008000L     ///< has type comment? (such a comment may be changed by IDA)
#define AFL_LZERO0      0x00010000L     ///< toggle leading zeroes for the 1st operand
#define AFL_LZERO1      0x00020000L     ///< toggle leading zeroes for the 2nd operand
#define AFL_COLORED     0x00040000L     ///< has user defined instruction color?
#define AFL_TERSESTR    0x00080000L     ///< terse structure variable display?
#define AFL_SIGN0       0x00100000L     ///< code: toggle sign of the 1st operand
#define AFL_SIGN1       0x00200000L     ///< code: toggle sign of the 2nd operand
#define AFL_NORET       0x00400000L     ///< for imported function pointers: doesn't return.
                                        ///< this flag can also be used for any instruction
                                        ///< which halts or finishes the program execution
#define AFL_FIXEDSPD    0x00800000L     ///< sp delta value is fixed by analysis.
                                        ///< should not be modified by modules
#define AFL_ALIGNFLOW   0x01000000L     ///< the previous insn was created for alignment purposes only
#define AFL_USERTI      0x02000000L     ///< the type information is definitive.
                                        ///< (comes from the user or type library)
                                        ///< if not set see #AFL_TYPE_GUESSED
#define AFL_RETFP       0x04000000L     ///< function returns a floating point value
#define AFL_USEMODSP    0x08000000L     ///< insn modifes SP and uses the modified value;
                                        ///< example: pop [rsp+N]
#define AFL_NOTCODE     0x10000000L     ///< autoanalysis should not create code here
#define AFL_NOTPROC     0x20000000L     ///< autoanalysis should not create proc here
#define AFL_TYPE_GUESSED    0xC2000000L ///< who guessed the type information?
#define AFL_IDA_GUESSED     0x00000000L ///< the type is guessed by IDA
#define AFL_HR_GUESSED_FUNC 0x40000000L ///< the function type is guessed by the decompiler
#define AFL_HR_GUESSED_DATA 0x80000000L ///< the data type is guessed by the decompiler
#define AFL_HR_DETERMINED   0xC0000000L ///< the type is definitely guessed by the decompiler
//@}

/// \name Work with additional location flags
/// See \ref AFL_
//@{
using aflags_t = flags_t;

idaman void     ida_export set_aflags(ea_t ea, aflags_t flags);
idaman void     ida_export upd_abits(ea_t ea, aflags_t clr_bits, aflags_t set_bits);
idaman void     ida_export set_abits(ea_t ea, aflags_t bits);
idaman void     ida_export clr_abits(ea_t ea, aflags_t bits);
idaman aflags_t ida_export get_aflags(ea_t ea);
idaman void     ida_export del_aflags(ea_t ea);

inline bool has_aflag_linnum(aflags_t flags)       { return (flags & AFL_LINNUM)   != 0; }
inline bool is_aflag_usersp(aflags_t flags)        { return (flags & AFL_USERSP)   != 0; }
inline bool is_aflag_public_name(aflags_t flags)   { return (flags & AFL_PUBNAM)   != 0; }
inline bool is_aflag_weak_name(aflags_t flags)     { return (flags & AFL_WEAKNAM)  != 0; }
inline bool is_aflag_hidden_item(aflags_t flags)   { return (flags & AFL_HIDDEN)   != 0; }
inline bool is_aflag_manual_insn(aflags_t flags)   { return (flags & AFL_MANUAL)   != 0; }
inline bool is_aflag_hidden_border(aflags_t flags) { return (flags & AFL_NOBRD)    != 0; }
inline bool is_aflag_zstroff(aflags_t flags)       { return (flags & AFL_ZSTROFF)  != 0; }
inline bool is_aflag__bnot0(aflags_t flags)        { return (flags & AFL_BNOT0)    != 0; }
inline bool is_aflag__bnot1(aflags_t flags)        { return (flags & AFL_BNOT1)    != 0; }
inline bool is_aflag_libitem(aflags_t flags)       { return (flags & AFL_LIB)      != 0; }
inline bool has_aflag_ti(aflags_t flags)           { return (flags & AFL_TI)       != 0; }
inline bool has_aflag_ti0(aflags_t flags)          { return (flags & AFL_TI0)      != 0; }
inline bool has_aflag_ti1(aflags_t flags)          { return (flags & AFL_TI1)      != 0; }
inline bool has_aflag_lname(aflags_t flags)        { return (flags & AFL_LNAME)    != 0; }
inline bool is_aflag_tilcmt(aflags_t flags)        { return (flags & AFL_TILCMT)   != 0; }
inline bool is_aflag_lzero0(aflags_t flags)        { return (flags & AFL_LZERO0)   != 0; }
inline bool is_aflag_lzero1(aflags_t flags)        { return (flags & AFL_LZERO1)   != 0; }
inline bool is_aflag_colored_item(aflags_t flags)  { return (flags & AFL_COLORED)  != 0; }
inline bool is_aflag_terse_struc(aflags_t flags)   { return (flags & AFL_TERSESTR) != 0; }
inline bool is_aflag__invsign0(aflags_t flags)     { return (flags & AFL_SIGN0)    != 0; }
inline bool is_aflag__invsign1(aflags_t flags)     { return (flags & AFL_SIGN1)    != 0; }
inline bool is_aflag_noret(aflags_t flags)         { return (flags & AFL_NORET)    != 0; }
inline bool is_aflag_fixed_spd(aflags_t flags)     { return (flags & AFL_FIXEDSPD) != 0; }
inline bool is_aflag_align_flow(aflags_t flags)    { return (flags & AFL_ALIGNFLOW)!= 0; }
inline bool is_aflag_userti(aflags_t flags)        { return (flags & AFL_USERTI)   != 0; }
inline bool is_aflag_retfp(aflags_t flags)         { return (flags & AFL_RETFP)    != 0; }
inline bool uses_aflag_modsp(aflags_t flags)       { return (flags & AFL_USEMODSP) != 0; }
inline bool is_aflag_notcode(aflags_t flags)       { return (flags & AFL_NOTCODE)  != 0; }
inline bool is_aflag_notproc(aflags_t flags)       { return (flags & AFL_NOTPROC)  != 0; }
inline bool is_aflag_type_guessed_by_ida(aflags_t flags)        { return (flags & AFL_TYPE_GUESSED) == AFL_IDA_GUESSED;     }
inline bool is_aflag_func_guessed_by_hexrays(aflags_t flags)    { return (flags & AFL_TYPE_GUESSED) == AFL_HR_GUESSED_FUNC; }
inline bool is_aflag_data_guessed_by_hexrays(aflags_t flags)    { return (flags & AFL_TYPE_GUESSED) == AFL_HR_GUESSED_DATA; }
inline bool is_aflag_type_determined_by_hexrays(aflags_t flags) { return (flags & AFL_TYPE_GUESSED) == AFL_HR_DETERMINED;   }
inline bool is_aflag_type_guessed_by_hexrays(aflags_t flags)
{
  flags = flags & AFL_TYPE_GUESSED;
  return flags == AFL_HR_GUESSED_FUNC
      || flags == AFL_HR_GUESSED_DATA
      || flags == AFL_HR_DETERMINED;
}

inline bool is_hidden_item(ea_t ea)   { return is_aflag_hidden_item(get_aflags(ea)); }
inline void hide_item(ea_t ea)        { set_abits(ea, AFL_HIDDEN); }
inline void unhide_item(ea_t ea)      { clr_abits(ea, AFL_HIDDEN); }

inline bool is_hidden_border(ea_t ea) { return is_aflag_hidden_border(get_aflags(ea)); }
inline void hide_border(ea_t ea)      { set_abits(ea, AFL_NOBRD); }
inline void unhide_border(ea_t ea)    { clr_abits(ea, AFL_NOBRD); }

inline bool uses_modsp(ea_t ea)       { return uses_aflag_modsp(get_aflags(ea)); }
inline void set_usemodsp(ea_t ea)     { set_abits(ea, AFL_USEMODSP); }
inline void clr_usemodsp(ea_t ea)     { clr_abits(ea, AFL_USEMODSP); }

inline bool is_zstroff(ea_t ea)       { return is_aflag_zstroff(get_aflags(ea)); }
inline void set_zstroff(ea_t ea)      { set_abits(ea, AFL_ZSTROFF); }
inline void clr_zstroff(ea_t ea)      { clr_abits(ea, AFL_ZSTROFF); }

inline bool is__bnot0(ea_t ea)        { return is_aflag__bnot0(get_aflags(ea)); }
inline void set__bnot0(ea_t ea)       { set_abits(ea, AFL_BNOT0); }
inline void clr__bnot0(ea_t ea)       { clr_abits(ea, AFL_BNOT0); }

inline bool is__bnot1(ea_t ea)        { return is_aflag__bnot1(get_aflags(ea)); }
inline void set__bnot1(ea_t ea)       { set_abits(ea, AFL_BNOT1); }
inline void clr__bnot1(ea_t ea)       { clr_abits(ea, AFL_BNOT1); }

inline bool is_libitem(ea_t ea)       { return is_aflag_libitem(get_aflags(ea)); }
inline void set_libitem(ea_t ea)      { set_abits(ea, AFL_LIB); }
inline void clr_libitem(ea_t ea)      { clr_abits(ea, AFL_LIB); }

inline bool has_ti(ea_t ea)           { return has_aflag_ti(get_aflags(ea)); }
inline void set_has_ti(ea_t ea)       { set_abits(ea, AFL_TI); }
inline void clr_has_ti(ea_t ea)       { clr_abits(ea, AFL_TI); }

inline bool has_ti0(ea_t ea)          { return has_aflag_ti0(get_aflags(ea)); }
inline void set_has_ti0(ea_t ea)      { set_abits(ea, AFL_TI0); }
inline void clr_has_ti0(ea_t ea)      { clr_abits(ea, AFL_TI0); }

inline bool has_ti1(ea_t ea)          { return has_aflag_ti1(get_aflags(ea)); }
inline void set_has_ti1(ea_t ea)      { set_abits(ea, AFL_TI1); }
inline void clr_has_ti1(ea_t ea)      { clr_abits(ea, AFL_TI1); }

inline bool has_lname(ea_t ea)        { return has_aflag_lname(get_aflags(ea)); }
inline void set_has_lname(ea_t ea)    { set_abits(ea, AFL_LNAME); }
inline void clr_has_lname(ea_t ea)    { clr_abits(ea, AFL_LNAME); }

inline bool is_tilcmt(ea_t ea)        { return is_aflag_tilcmt(get_aflags(ea)); }
inline void set_tilcmt(ea_t ea)       { set_abits(ea, AFL_TILCMT); }
inline void clr_tilcmt(ea_t ea)       { clr_abits(ea, AFL_TILCMT); }

inline bool is_usersp(ea_t ea)        { return is_aflag_usersp(get_aflags(ea)); }
inline void set_usersp(ea_t ea)       { set_abits(ea, AFL_USERSP); }
inline void clr_usersp(ea_t ea)       { clr_abits(ea, AFL_USERSP); }

inline bool is_lzero0(ea_t ea)        { return is_aflag_lzero0(get_aflags(ea)); }
inline void set_lzero0(ea_t ea)       { set_abits(ea, AFL_LZERO0); }
inline void clr_lzero0(ea_t ea)       { clr_abits(ea, AFL_LZERO0); }

inline bool is_lzero1(ea_t ea)        { return is_aflag_lzero1(get_aflags(ea)); }
inline void set_lzero1(ea_t ea)       { set_abits(ea, AFL_LZERO1); }
inline void clr_lzero1(ea_t ea)       { clr_abits(ea, AFL_LZERO1); }

inline bool is_colored_item(ea_t ea)  { return is_aflag_colored_item(get_aflags(ea)); }
inline void set_colored_item(ea_t ea) { set_abits(ea, AFL_COLORED); } // use set_item_color()
inline void clr_colored_item(ea_t ea) { clr_abits(ea, AFL_COLORED); } // use del_item_color()

inline bool is_terse_struc(ea_t ea)   { return is_aflag_terse_struc(get_aflags(ea)); }
inline void set_terse_struc(ea_t ea)  { set_abits(ea, AFL_TERSESTR); }
inline void clr_terse_struc(ea_t ea)  { clr_abits(ea, AFL_TERSESTR); }

inline bool is__invsign0(ea_t ea)     { return is_aflag__invsign0(get_aflags(ea)); }
inline void set__invsign0(ea_t ea)    { set_abits(ea, AFL_SIGN0); }
inline void clr__invsign0(ea_t ea)    { clr_abits(ea, AFL_SIGN0); }

inline bool is__invsign1(ea_t ea)     { return is_aflag__invsign1(get_aflags(ea)); }
inline void set__invsign1(ea_t ea)    { set_abits(ea, AFL_SIGN1); }
inline void clr__invsign1(ea_t ea)    { clr_abits(ea, AFL_SIGN1); }

inline bool is_noret(ea_t ea)         { return is_aflag_noret(get_aflags(ea)); }
inline void set_noret(ea_t ea)        { set_abits(ea, AFL_NORET); }
inline void clr_noret(ea_t ea)        { clr_abits(ea, AFL_NORET); }

inline bool is_fixed_spd(ea_t ea)     { return is_aflag_fixed_spd(get_aflags(ea)); }
inline void set_fixed_spd(ea_t ea)    { set_abits(ea, AFL_FIXEDSPD); }
inline void clr_fixed_spd(ea_t ea)    { clr_abits(ea, AFL_FIXEDSPD); }

inline bool is_align_flow(ea_t ea)    { return is_aflag_align_flow(get_aflags(ea)); }
inline void set_align_flow(ea_t ea)   { set_abits(ea, AFL_ALIGNFLOW); }
inline void clr_align_flow(ea_t ea)   { clr_abits(ea, AFL_ALIGNFLOW); }

inline bool is_userti(ea_t ea)        { return is_aflag_userti(get_aflags(ea)); }
inline void set_userti(ea_t ea)       { upd_abits(ea, AFL_TYPE_GUESSED, AFL_USERTI); }
inline void clr_userti(ea_t ea)       { clr_abits(ea, AFL_TYPE_GUESSED); } // use set_ida_guessed_type()

inline bool is_retfp(ea_t ea)         { return is_aflag_retfp(get_aflags(ea)); }
inline void set_retfp(ea_t ea)        { set_abits(ea, AFL_RETFP); }
inline void clr_retfp(ea_t ea)        { clr_abits(ea, AFL_RETFP); }

inline bool is_notproc(ea_t ea)       { return is_aflag_notproc(get_aflags(ea)); }
inline void set_notproc(ea_t ea)      { set_abits(ea, AFL_NOTPROC); }
inline void clr_notproc(ea_t ea)      { clr_abits(ea, AFL_NOTPROC); }

inline bool is_type_guessed_by_ida(ea_t ea)        { return is_aflag_type_guessed_by_ida(get_aflags(ea));        }
inline bool is_func_guessed_by_hexrays(ea_t ea)    { return is_aflag_func_guessed_by_hexrays(get_aflags(ea));    }
inline bool is_data_guessed_by_hexrays(ea_t ea)    { return is_aflag_data_guessed_by_hexrays(get_aflags(ea));    }
inline bool is_type_determined_by_hexrays(ea_t ea) { return is_aflag_type_determined_by_hexrays(get_aflags(ea)); }
inline bool is_type_guessed_by_hexrays(ea_t ea)    { return is_aflag_type_guessed_by_hexrays(get_aflags(ea));    }

inline void set_type_guessed_by_ida(ea_t ea)        { upd_abits(ea, AFL_TYPE_GUESSED, AFL_IDA_GUESSED);     }
inline void set_func_guessed_by_hexrays(ea_t ea)    { upd_abits(ea, AFL_TYPE_GUESSED, AFL_HR_GUESSED_FUNC); }
inline void set_data_guessed_by_hexrays(ea_t ea)    { upd_abits(ea, AFL_TYPE_GUESSED, AFL_HR_GUESSED_DATA); }
inline void set_type_determined_by_hexrays(ea_t ea) { upd_abits(ea, AFL_TYPE_GUESSED, AFL_HR_DETERMINED);   }
//@}

/// Mark address so that it cannot be converted to instruction
idaman void ida_export set_notcode(ea_t ea);

/// Clear not-code mark
inline void clr_notcode(ea_t ea) { clr_abits(ea, AFL_NOTCODE); }

/// Is the address marked as not-code?
inline bool is_notcode(ea_t ea) { return is_aflag_notcode(get_aflags(ea)); }


/// Change visibility of item at given ea

inline void set_visible_item(ea_t ea, bool visible)
{
  if ( visible )
    unhide_item(ea);
  else
    hide_item(ea);
}

/// Test visibility of item at given ea

inline bool is_visible_item(ea_t ea) { return !is_hidden_item(ea); }


/// Is instruction visible?

inline bool is_finally_visible_item(ea_t ea)
{
  return (inf_get_cmtflg() & SCF_SHHID_ITEM) != 0 || is_visible_item(ea);
}


/// \name Source line numbers
/// They are sometimes present in object files.
//@{
idaman void   ida_export set_source_linnum(ea_t ea, uval_t lnnum);
idaman uval_t ida_export get_source_linnum(ea_t ea);
idaman void   ida_export del_source_linnum(ea_t ea);
//@}

/// \name Absolute segment base address
/// These functions may be used if necessary (despite of the AFLNOTE above).
//@{
inline ea_t get_absbase(ea_t ea)
{
  ea_t x;
  return getnode(ea).supval(NALT_ABSBASE, &x, sizeof(x), atag) > 0 ? ea_t(x-1) : ea_t(-1);
}
inline void set_absbase(ea_t ea, ea_t x)
{
  x++;
  getnode(ea).supset(NALT_ABSBASE, &x, sizeof(x), atag);
}
inline void del_absbase(ea_t ea) { getnode(ea).supdel(NALT_ABSBASE, atag); }
//@}

/// \name Purged bytes
/// Number of bytes purged from the stack when a function is called indirectly
/// get_ind_purged() may be used if necessary (despite of the AFLNOTE above).
/// Use set_purged() to modify this value (do not use set_ind_purged())
//@{
idaman ea_t ida_export get_ind_purged(ea_t ea);
inline void set_ind_purged(ea_t ea, ea_t x)
{
  x++;
  getnode(ea).supset(NALT_PURGE, &x, sizeof(x), atag);
}
inline void del_ind_purged(ea_t ea) { getnode(ea).supdel(NALT_PURGE, atag); }
//@}

/// \name Get type of string
/// Use higher level function get_opinfo().
//@{
idaman uint32 ida_export get_str_type(ea_t ea);
idaman void   ida_export set_str_type(ea_t ea, uint32 x);
idaman void   ida_export del_str_type(ea_t ea);
//@}

// Number of bytes per "units" in a string. E.g., ASCII, Windows-1252,
// UTF-8 all take up one byte per unit, while UTF-16 variations take 2 and
// UTF-32 variations take 4.
// (Note that an "unit" in this context is not necessarily a character,
// since UTF-8-encoded characters can be encoded in up to 4 bytes,
// and UTF-16-encoded characters can be encoded in up to 2 bytes.)
#define STRWIDTH_1B 0
#define STRWIDTH_2B 1
#define STRWIDTH_4B 2
#define STRWIDTH_MASK 0x03

// The string layout; how the string is laid out in data.
#define STRLYT_TERMCHR 0
#define STRLYT_PASCAL1 1
#define STRLYT_PASCAL2 2
#define STRLYT_PASCAL4 3
#define STRLYT_MASK 0xFC
#define STRLYT_SHIFT 2


/// \defgroup STRTYPE_ String type codes
//@{
///< Character-terminated string. The termination characters are kept in
///< the next bytes of string type.
#define STRTYPE_TERMCHR   (STRWIDTH_1B|STRLYT_TERMCHR<<STRLYT_SHIFT)
///< C-style string.
#define STRTYPE_C         STRTYPE_TERMCHR
///< Zero-terminated 16bit chars
#define STRTYPE_C_16      (STRWIDTH_2B|STRLYT_TERMCHR<<STRLYT_SHIFT)
///< Zero-terminated 32bit chars
#define STRTYPE_C_32      (STRWIDTH_4B|STRLYT_TERMCHR<<STRLYT_SHIFT)
///< Pascal-style, one-byte length prefix
#define STRTYPE_PASCAL    (STRWIDTH_1B|STRLYT_PASCAL1<<STRLYT_SHIFT)
///< Pascal-style, 16bit chars, one-byte length prefix
#define STRTYPE_PASCAL_16 (STRWIDTH_2B|STRLYT_PASCAL1<<STRLYT_SHIFT)
///< Pascal-style, two-byte length prefix
#define STRTYPE_LEN2      (STRWIDTH_1B|STRLYT_PASCAL2<<STRLYT_SHIFT)
///< Pascal-style, 16bit chars, two-byte length prefix
#define STRTYPE_LEN2_16   (STRWIDTH_2B|STRLYT_PASCAL2<<STRLYT_SHIFT)
///< Pascal-style, four-byte length prefix
#define STRTYPE_LEN4      (STRWIDTH_1B|STRLYT_PASCAL4<<STRLYT_SHIFT)
///< Pascal-style, 16bit chars, four-byte length prefix
#define STRTYPE_LEN4_16   (STRWIDTH_2B|STRLYT_PASCAL4<<STRLYT_SHIFT)
//@}

/// \name Work with string type codes
/// See \ref STRTYPE_
//@{
inline THREAD_SAFE uchar idaapi get_str_type_code(int32 strtype) { return uchar(strtype); }
inline THREAD_SAFE char get_str_term1(int32 strtype) { return char(strtype>>8); }
inline THREAD_SAFE char get_str_term2(int32 strtype) { return char(strtype>>16); }
                                // if the second termination character is
                                // '\0', then it doesn't exist.
/// Get index of the string encoding for this string
inline THREAD_SAFE uchar idaapi get_str_encoding_idx(int32 strtype) { return uchar(strtype>>24); }
/// Set index of the string encoding in the string type
inline THREAD_SAFE int32 set_str_encoding_idx(int32 strtype, int encoding_idx)
{
  return (strtype & 0xFFFFFF) | ((uchar)encoding_idx << 24);
}
/// Get string type for a string in the given encoding
inline THREAD_SAFE int32 make_str_type(
        uchar type_code,
        int encoding_idx,
        uchar term1 = 0,
        uchar term2 = 0)
{
  return type_code
       | (term1 << 8)
       | (term2 << 16)
       | ((uchar)encoding_idx << 24);
}


inline THREAD_SAFE bool is_pascal(int32 strtype)
{
  int lyt = get_str_type_code(strtype) >> STRLYT_SHIFT;
  return lyt >= STRLYT_PASCAL1 && lyt <= STRLYT_PASCAL4;
}

inline THREAD_SAFE size_t get_str_type_prefix_length(int32 strtype)
{
  switch ( get_str_type_code(strtype) )
  {
    case STRTYPE_LEN4_16:
    case STRTYPE_LEN4:
      return 4;
    case STRTYPE_LEN2_16:
    case STRTYPE_LEN2:
      return 2;
    case STRTYPE_PASCAL_16:
    case STRTYPE_PASCAL:
      return 1;
  }
  return 0;
}
//@}

#define STRENC_DEFAULT 0x00  ///< use default encoding for this type (see get_default_encoding_idx())
#define STRENC_NONE    0xFF  ///< force no-conversion encoding

/// \name Alignment value
/// (should be power of 2)
/// These functions may be used if necessary (despite of the AFLNOTE above).
//@{
inline uint32 get_alignment(ea_t ea)
{
  uint32 x;
  return getnode(ea).supval(NALT_ALIGN, &x, sizeof(x), atag) > 0 ? uint32(x-1) : uint32(-1);
}
inline void set_alignment(ea_t ea, uint32 x)
{
  x++;
  getnode(ea).supset(NALT_ALIGN, &x, sizeof(x), atag);
}
inline void del_alignment(ea_t ea) { getnode(ea).supdel(NALT_ALIGN, atag); }
//@}


/// \name Instruction/Data background color
//@{
idaman void      ida_export set_item_color(ea_t ea, bgcolor_t color);
idaman bgcolor_t ida_export get_item_color(ea_t ea);      // returns DEFCOLOR if no color
idaman bool      ida_export del_item_color(ea_t ea);
//@}


//-------------------------------------------------------------------------
/// \name Array representation
//@{
/// Describes how to display an array
struct array_parameters_t
{
  int32 flags;
#define AP_ALLOWDUPS    0x00000001L     ///< use 'dup' construct
#define AP_SIGNED       0x00000002L     ///< treats numbers as signed
#define AP_INDEX        0x00000004L     ///< display array element indexes as comments
#define AP_ARRAY        0x00000008L     ///< create as array (this flag is not stored in database)
#define AP_IDXBASEMASK  0x000000F0L     ///< mask for number base of the indexes
#define   AP_IDXDEC     0x00000000L     ///< display indexes in decimal
#define   AP_IDXHEX     0x00000010L     ///< display indexes in hex
#define   AP_IDXOCT     0x00000020L     ///< display indexes in octal
#define   AP_IDXBIN     0x00000030L     ///< display indexes in binary

  int32 lineitems;                      ///< number of items on a line
  int32 alignment;                      ///< -1 - don't align.
                                        ///< 0  - align automatically.
                                        ///< else item width
};
idaman ssize_t ida_export get_array_parameters(array_parameters_t *out, ea_t ea);
idaman void ida_export set_array_parameters(ea_t ea, const array_parameters_t *in);
inline void idaapi del_array_parameters(ea_t ea) { getnode(ea).supdel(NSUP_ARRAY); }
//@}

//--------------------------------------------------------------------------
/// Information about a switch statement
struct switch_info_t
{
  uint32 flags;                    ///< \ref SWI_
/// \defgroup SWI_ Switch info flags
/// Used by switch_info_t::flags
//@{
#define SWI_SPARSE      0x00000001 ///< sparse switch (value table present),
                                   ///< otherwise lowcase present
#define SWI_V32         0x00000002 ///< 32-bit values in table
#define SWI_J32         0x00000004 ///< 32-bit jump offsets
#define SWI_VSPLIT      0x00000008 ///< value table is split (only for 32-bit values)
#define SWI_USER        0x00000010 ///< user specified switch (starting from version 2)
#define SWI_DEF_IN_TBL  0x00000020 ///< default case is an entry in the jump table.
                                   ///< This flag is applicable in 2 cases:
                                   ///< - The sparse indirect switch (i.e. a switch with a values table)
                                   ///<    {jump table size} == {value table size} + 1.
                                   ///<    The default case entry is the last one in the table
                                   ///<    (or the first one in the case of an inversed jump table).
                                   ///< - The switch with insns in the jump table.
                                   ///<   The default case entry is before the first entry of the table. \n
                                   ///< See also the find_defjump_from_table() helper function.
#define SWI_JMP_INV     0x00000040 ///< jumptable is inversed. (last entry is
                                   ///< for first entry in values table)
#define SWI_SHIFT_MASK  0x00000180 ///< use formula (element<<shift) + elbase to find jump targets
#define SWI_ELBASE      0x00000200 ///< elbase is present (otherwise the base of the switch
                                   ///< segment will be used)
#define SWI_JSIZE       0x00000400 ///< jump offset expansion bit
#define SWI_VSIZE       0x00000800 ///< value table element size expansion bit
#define SWI_SEPARATE    0x00001000 ///< create an array of individual elements (otherwise separate items)
#define SWI_SIGNED      0x00002000 ///< jump table entries are signed
#define SWI_CUSTOM      0x00004000 ///< custom jump table.
                                   ///< \ph{create_switch_xrefs} will be called to create code xrefs
                                   ///< for the table. Custom jump table must be created by the
                                   ///< module (see also #SWI_STDTBL)
//#define SWI_EXTENDED  0x00008000 ///< reserved
#define SWI_INDIRECT    0x00010000 ///< value table elements are used as indexes into the jump table
                                   ///< (for sparse switches)
#define SWI_SUBTRACT    0x00020000 ///< table values are subtracted from the elbase instead of being added
#define SWI_HXNOLOWCASE 0x00040000 ///< lowcase value should not be used by the decompiler (internal flag)
#define SWI_STDTBL      0x00080000 ///< custom jump table with standard table formatting.
                                   ///< ATM IDA doesn't use SWI_CUSTOM for switches with standard
                                   ///< table formatting. So this flag can be considered as obsolete.
#define SWI_DEFRET      0x00100000 ///< return in the default case (defjump==BADADDR)
#define SWI_SELFREL     0x00200000 ///< jump address is relative to the element not to ELBASE
#define SWI_JMPINSN     0x00400000 ///< jump table entries are insns. For such entries SHIFT has a
                                   ///< different meaning. It denotes the number of insns in the
                                   ///< entry. For example, 0 - the entry contains the jump to the
                                   ///< case, 1 - the entry contains one insn like a 'mov' and jump
                                   ///< to the end of case, and so on.
#define SWI_VERSION     0x00800000 ///< the structure contains the VERSION member
//@}

  /// See #SWI_SHIFT_MASK.
  /// possible answers: 0..3.
  int get_shift(void) const { return ((flags & SWI_SHIFT_MASK) >> 7); }

  /// See #SWI_SHIFT_MASK
  void set_shift(int shift)
  {
    flags &= ~SWI_SHIFT_MASK;
    flags |= ((shift & 3) << 7);
  }

  int get_jtable_element_size(void) const
  { // this brain damaged logic is needed for compatibility with old versions
    int code = flags & (SWI_J32|SWI_JSIZE);
    if ( code == 0 )
      return 2;
    if ( code == SWI_J32 )
      return 4;
    if ( code == SWI_JSIZE )
      return 1;
    return 8;
  }
  void set_jtable_element_size(int size)
  {
    flags &= ~SWI_J32|SWI_JSIZE;
    switch ( size )
    {
      case 4:
        flags |= SWI_J32;
        break;
      case 1:
        flags |= SWI_JSIZE;
        break;
      case 8:
        flags |= SWI_J32|SWI_JSIZE;
        break;
      case 2:
        break;
      default:
        INTERR(1297);
    }
  }
  int get_vtable_element_size(void) const
  {
    int code = flags & (SWI_V32|SWI_VSIZE);
    if ( code == 0 )
      return 2;
    if ( code == SWI_V32 )
      return 4;
    if ( code == SWI_VSIZE )
      return 1;
    return 8;
  }
  void set_vtable_element_size(int size)
  {
    flags &= ~SWI_V32|SWI_VSIZE;
    switch ( size )
    {
      case 4:
        flags |= SWI_V32;
        break;
      case 1:
        flags |= SWI_VSIZE;
        break;
      case 8:
        flags |= SWI_V32|SWI_VSIZE;
        break;
      case 2:
        break;
      default:
        INTERR(1298);
    }
  }

  bool has_default(void)  const { return defjump != BADADDR;             }
  bool has_elbase(void)   const { return (flags & SWI_ELBASE)      != 0; }
  bool is_sparse(void)    const { return (flags & SWI_SPARSE)      != 0; }
  bool is_custom(void)    const { return (flags & SWI_CUSTOM)      != 0; }
  bool is_indirect(void)  const { return (flags & SWI_INDIRECT)    != 0; }
  bool is_subtract(void)  const { return (flags & SWI_SUBTRACT)    != 0; }
  bool is_nolowcase(void) const { return (flags & SWI_HXNOLOWCASE) != 0; }
  bool use_std_table(void) const { return !is_custom() || (flags & SWI_STDTBL) != 0; }
  bool is_user_defined() const
  {
    return get_version() >= 2 && (flags & SWI_USER) != 0;
  }

  ushort ncases = 0;            ///< number of cases (excluding default)
  ea_t jumps = BADADDR;         ///< jump table start address
  union
  {
    ea_t values;                ///< values table address (if #SWI_SPARSE is set)
    uval_t lowcase;             ///< the lowest value in cases
  };
  ea_t defjump = BADADDR;       ///< default jump address (#BADADDR if no default case)
  ea_t startea = BADADDR;       ///< start of the switch idiom
  int jcases = 0;               ///< number of entries in the jump table (SWI_INDIRECT)

  sval_t ind_lowcase = 0;
  sval_t get_lowcase(void) const { return is_indirect() ? ind_lowcase : lowcase; }
  ea_t elbase = 0;              ///< element base

  int regnum = -1;              ///< the switch expression as a value of the REGNUM register
                                ///< before the instruction at EXPR_EA. -1 means 'unknown'
  op_dtype_t regdtype = 0;      ///< size of the switch expression register as dtype

  int get_jtable_size(void) const { return is_indirect() ? jcases : ncases; }
  void set_jtable_size(int size)
  {
    if ( is_indirect() )
      jcases = size;
    else
      ncases = uint16(size);
  }
  void set_elbase(ea_t base)
  {
    elbase = base;
    flags |= SWI_ELBASE;
  }

  void set_expr(int r, op_dtype_t dt) { regnum = r; regdtype = dt; }

  /// get separate parts of the switch
  bool get_jrange_vrange(range_t *jrange = nullptr, range_t *vrange = nullptr) const
  {
    if ( !use_std_table() )
      return false;
    if ( jrange != nullptr )
    {
      int n = get_jtable_size();
      if ( (flags & SWI_DEF_IN_TBL) != 0 )
        ++n;
      int jsize = get_jtable_element_size();
      *jrange = range_t(jumps, jumps + jsize * n);
    }
    if ( vrange != nullptr && is_sparse() )
    {
      int vsize = get_vtable_element_size();
      *vrange = range_t(values, values + vsize * ncases);
    }
    return true;
  }

  uval_t custom = 0;            ///< information for custom tables (filled and used by modules)

  enum { SWITCH_INFO_VERSION = 2 };
  int version = SWITCH_INFO_VERSION;
  int get_version() const { return (flags & SWI_VERSION) == 0 ? 1 : version; }

  // version 2
  ea_t expr_ea = BADADDR;       ///< the address before that the switch expression is in REGNUM.
                                ///< If BADADDR, then the first insn marked as IM_SWITCH after
                                ///< STARTEA is used.
  eavec_t marks;                ///< the insns marked as IM_SWITCH. They are used to delete the switch.

  switch_info_t() : flags(SWI_VERSION), lowcase(0) {}
  void clear() { *this = switch_info_t(); }
};

/// \name Switch info
/// See ::switch_info_t, xref.hpp for related functions
//@{
idaman ssize_t ida_export get_switch_info(switch_info_t *out, ea_t ea);
idaman void ida_export set_switch_info(ea_t ea, const switch_info_t &in);
idaman void ida_export del_switch_info(ea_t ea);
//@}

/// \name Switch parent
/// Address which holds the switch info (::switch_info_t). Used at the jump targets.
//@{
inline ea_t get_switch_parent(ea_t ea)
{
  ea_t x;
  return getnode(ea).supval(NALT_SWITCH, &x, sizeof(x), atag) > 0 ? ea_t(x-1) : ea_t(-1);
}
inline void set_switch_parent(ea_t ea, ea_t x)
{
  x++;
  getnode(ea).supset(NALT_SWITCH, &x, sizeof(x), atag);
}
inline void del_switch_parent(ea_t ea) { getnode(ea).supdel(NALT_SWITCH, atag); }
//@}

/// \name Custom data types
//@{
/// Information about custom data types
struct custom_data_type_ids_t
{
  int16 dtid;               ///< data type id
  int16 fids[UA_MAXOP];     ///< data format ids

  void set(tid_t tid)
  {
    memset(fids, -1, sizeof(fids));
    dtid = uint16(tid);
    fids[0] = uint16(tid >> 16);
  }
  tid_t get_dtid() const
  {
    return uint16(dtid) | (uint16(-1) << 16);
  }
#ifndef SWIG
  DECLARE_COMPARISONS(custom_data_type_ids_t);
#endif
};
idaman int  ida_export get_custom_data_type_ids(custom_data_type_ids_t *cdis, ea_t ea);
idaman void ida_export set_custom_data_type_ids(ea_t ea, const custom_data_type_ids_t *cdis);
inline void idaapi del_custom_data_type_ids(ea_t ea) { getnode(ea).supdel(NSUP_CUSTDT); }
//@}

typedef uchar reftype_t;  ///< see \ref reftype_
/// \defgroup reftype_ Types of references
/// References are represented in the following form:
///
///         \v{target + tdelta - base}
///
/// If the target is not present, then it will be calculated using
///
///         \v{target = operand_value - tdelta + base}
///
/// The target must be present for LOW and HIGH reference types
//@{
const reftype_t
  V695_REF_OFF8 = 0,      ///< reserved
  REF_OFF16  = 1,         ///< 16bit full offset
  REF_OFF32  = 2,         ///< 32bit full offset
  REF_LOW8   = 3,         ///< low 8bits of 16bit offset
  REF_LOW16  = 4,         ///< low 16bits of 32bit offset
  REF_HIGH8  = 5,         ///< high 8bits of 16bit offset
  REF_HIGH16 = 6,         ///< high 16bits of 32bit offset
  V695_REF_VHIGH  = 7,    ///< obsolete
  V695_REF_VLOW   = 8,    ///< obsolete
  REF_OFF64  = 9,         ///< 64bit full offset
  REF_OFF8   = 10,        ///< 8bit full offset
  REF_LAST = REF_OFF8;
//@}

/// Can the target be calculated using operand value?

inline bool is_reftype_target_optional(reftype_t type);

/// Get REF_... constant from size
/// Supported sizes: 1,2,4,8,16
/// For other sizes returns reftype_t(-1)

idaman reftype_t ida_export get_reftype_by_size(size_t size);

/// Information about a reference
struct refinfo_t
{
  ea_t    target;                 ///< reference target (#BADADDR-none)
  ea_t    base;                   ///< base of reference (may be BADADDR)
  adiff_t tdelta;                 ///< offset from the target
  uint32  flags;                  ///< \ref REFINFO_
/// \defgroup REFINFO_ Reference info flags
/// Used by refinfo_t::flags
//@{
#define REFINFO_TYPE      0x000F  ///< reference type (reftype_t), or custom
                                  ///< reference ID if REFINFO_CUSTOM set
#define REFINFO_RVAOFF    0x0010  ///< based reference (rva);
                                  ///< refinfo_t::base will be forced to get_imagebase();
                                  ///< such a reference is displayed with the \ash{a_rva} keyword
#define REFINFO_PASTEND   0x0020  ///< reference past an item;
                                  ///< it may point to an nonexistent address;
                                  ///< do not destroy alignment dirs
#define REFINFO_CUSTOM    0x0040  ///< a custom reference.
                                  ///< see custom_refinfo_handler_t.
                                  ///< the id of the custom refinfo is
                                  ///< stored under the REFINFO_TYPE mask.
#define REFINFO_NOBASE    0x0080  ///< don't create the base xref;
                                  ///< implies that the base can be any value.
                                  ///< nb: base xrefs are created only if the offset base
                                  ///< points to the middle of a segment
#define REFINFO_SUBTRACT  0x0100  ///< the reference value is subtracted from the base value instead of (as usual) being added to it
#define REFINFO_SIGNEDOP  0x0200  ///< the operand value is sign-extended (only supported for REF_OFF8/16/32/64)
#define REFINFO_NO_ZEROS  0x0400  ///< an opval of 0 will be considered invalid
#define REFINFO_NO_ONES   0x0800  ///< an opval of ~0 will be considered invalid
#define REFINFO_SELFREF   0x1000  ///< the self-based reference;
                                  ///< refinfo_t::base will be forced to the reference address
//@}

  reftype_t type(void) const
  {
    return reftype_t(flags & (REFINFO_TYPE | REFINFO_CUSTOM));
  }

  bool is_target_optional() const ///< \ref is_reftype_target_optional()
  {
    reftype_t rt = flags & (REFINFO_TYPE | REFINFO_CUSTOM);
    return is_reftype_target_optional(rt);
  }

  bool no_base_xref(void) const { return (flags & REFINFO_NOBASE) != 0; }
  bool is_pastend(void)   const { return (flags & REFINFO_PASTEND) != 0; }
  bool is_rvaoff(void)    const { return (flags & REFINFO_RVAOFF) != 0; }
  bool is_custom(void)    const { return (flags & REFINFO_CUSTOM) != 0; }
  bool is_subtract(void)  const { return (flags & REFINFO_SUBTRACT) != 0; }
  bool is_signed(void)    const { return (flags & REFINFO_SIGNEDOP) != 0; }
  bool is_no_zeros(void)   const { return (flags & REFINFO_NO_ZEROS) != 0; }
  bool is_no_ones(void)  const { return (flags & REFINFO_NO_ONES) != 0; }
  bool is_selfref(void)   const { return (flags & REFINFO_SELFREF) != 0; }

  // RT can include REFINFO_CUSTOM bit
  void set_type(reftype_t rt)
  {
    flags &= ~(REFINFO_TYPE | REFINFO_CUSTOM);
    flags |= rt;
  }

  // init the structure with some default values
  // reft_and_flags should be REF_xxx optionally ORed with some REFINFO_xxx flags
  void init(uint32 reft_and_flags, ea_t _base = 0, ea_t _target = BADADDR, adiff_t _tdelta = 0)
  {
    flags = reft_and_flags;
    base = _base;
    target = _target;
    tdelta = _tdelta;
  }

  // internal use
#ifndef SWIG
  ea_t _get_target(adiff_t opval) const;
  ea_t _get_value(ea_t target) const;
  adiff_t _get_opval(adiff_t opval) const;
  bool _require_base() const { return !is_rvaoff() && !is_selfref(); }
  DECLARE_COMPARISONS(refinfo_t);
#endif
};

/// Manage a custom refinfo type
/// Custom refinfos are usually used to handle custom fixups,
/// but can also be used to display non-standard references.
struct custom_refinfo_handler_t
{
  int32 cbsize;                 ///< size of this structure
  const char *name;             ///< Format name, must be unique
  const char *desc;             ///< Refinfo description to use in Ctrl-R dialog
  int props;                    ///< properties (currently 0)
/// \defgroup RHF_ Refinfo handler properties
/// Used by custom_refinfo_handler_t::props
//@{
#define RHF_TGTOPT 0x0001       ///< can the target be calculated using
                                ///< operand value?
//@}

  // this callback prepares the full offset expression in buf and
  // returns 1 if it is a simple expression or 2 if it is a complex one.
  // Or this callback checks the compliance of opval and fullvalue,
  // and possibly updates values of target and fullvalue,
  // and prepares the format,
  // and returns 3 to continue standard processing with updated values.
  // Or this callback just prepares the format and returns 4 to continue.
  // It returns 0 in the case of error.
  // It is guaranteed that before calling this callback, the
  // calc_reference_data() callback is always called.
  int (idaapi *gen_expr)(
        qstring *buf,
        qstring *format,      // buffer for the format (if retcode>=3)
        ea_t ea,
        int opnum,
        const refinfo_t &ri,
        ea_t from,
        adiff_t *opval,       // the output value is not used
        ea_t *target,         // the target prepared by calc_reference_data()
        ea_t *fullvalue,
        int getn_flags);

  // this callback replaces calc_target.
  // It calculates target and base,
  // and calculates an internal variable fullvalue,
  // and checks the compliance of opval and fullvalue,
  // and returns the success flag.
  bool (idaapi *calc_reference_data)(
        ea_t *target,
        ea_t *base,
        ea_t from,
        const refinfo_t &ri,
        adiff_t opval);

  // just custom format
  void (idaapi *get_format)(qstring *format);

#ifndef SWIG
  DECLARE_COMPARISONS(custom_refinfo_handler_t);
#endif
};


/// Register a new custom refinfo type.

idaman int ida_export register_custom_refinfo(const custom_refinfo_handler_t *crh);


/// Unregister a new custom refinfo type.

idaman bool ida_export unregister_custom_refinfo(int crid);


/// Get id of a custom refinfo type.

idaman int ida_export find_custom_refinfo(const char *name);


/// Get definition of a registered custom refinfo type.

idaman const custom_refinfo_handler_t *ida_export get_custom_refinfo(int crid);


/// Get refinfo handler

inline const custom_refinfo_handler_t *idaapi get_custom_refinfo_handler(
        const refinfo_t &ri)
{
  return ri.is_custom() ? get_custom_refinfo(ri.type()) : nullptr;
}

// inline implementaion
inline bool is_reftype_target_optional(reftype_t type)
{
  if ( (type & REFINFO_CUSTOM) != 0 )
  {
    const custom_refinfo_handler_t *cfh = get_custom_refinfo(type);
    if ( cfh == nullptr )
      return false;
    return (cfh->props & RHF_TGTOPT) != 0;
  }
  switch ( type )
  {
    case REF_OFF8:
    case REF_OFF16:
    case REF_OFF32:
    case REF_OFF64:
      return true;
  }
  return false;
}


/// Get descriptions of all standard and custom refinfo types.

struct refinfo_desc_t
{
  uint32 type;      ///< Refinfo type, see \ref REFINFO_
                    ///< Custom refinfo has REFINFO_CUSTOM bit.
  const char *name; ///< Refinfo name
  const char *desc; ///< Refinfo description to use in Ctrl-R dialog
};
DECLARE_TYPE_AS_MOVABLE(refinfo_desc_t);
typedef qvector<refinfo_desc_t> refinfo_desc_vec_t;
idaman void ida_export get_refinfo_descs(refinfo_desc_vec_t *descs);


#define MAXSTRUCPATH  32        ///< maximal inclusion depth of unions

/// Information for structure offsets.
/// ids[0] contains the id of the structure.
/// ids[1..len-1] contain ids of the structure members used in the structure offset
/// expression.
/// len is the length of the path, i.e. the number of elements in 'ids'
struct strpath_t
{
  int len;
  tid_t ids[MAXSTRUCPATH]; // for union member ids
  adiff_t delta;
#ifndef SWIG
  DECLARE_COMPARISONS(strpath_t);
#endif
};

/// See opinfo_t::ec
struct enum_const_t
{
  tid_t tid;
  uchar serial;
#ifndef SWIG
  DECLARE_COMPARISONS(enum_const_t)
  {
    COMPARE_FIELDS(tid);
    COMPARE_FIELDS(serial);
    return 0;
  }
#endif
};

/// Additional information about an operand type
union opinfo_t
{
  refinfo_t ri;              ///< for offset members
  tid_t tid;                 ///< for struct, etc. members
  strpath_t path;            ///< for stroff
  int32 strtype;             ///< for strings (\ref STRTYPE_)
  enum_const_t ec;           ///< for enums
  custom_data_type_ids_t cd; ///< for custom data
#ifndef SWIG
  int compare_opinfos(const opinfo_t &r, flags64_t flag, int n) const;
#endif
};

//-V:printop_t:730 Not all members of a class are initialized inside the constructor
struct printop_t
{
  uint32 unused;        // not used anymore, use flags64 instead (kept for backward compat)
  opinfo_t ti;          // new operand type
#define POF_VALID_TI     0x1 // is operand type initialized?
#define POF_VALID_AFLAGS 0x2 // internal
#define POF_IS_F64       0x4 // internal
  uchar features;       // features this instance holds
  int suspop;           // out: will be set by print_operand()
  aflags_t aflags;      // additional aflags
  flags64_t flags;      // new operand representation flags

  printop_t() : unused(0), features(POF_IS_F64), suspop(0), aflags(0), flags(0) {} //-V730 'ti' is not initialized
  bool is_ti_initialized() const { return (features & POF_VALID_TI) == POF_VALID_TI; }
  void set_ti_initialized(bool v=true) { setflag(features, POF_VALID_TI, v); }
  bool is_aflags_initialized() const { return (features & POF_VALID_AFLAGS) == POF_VALID_AFLAGS; }
  void set_aflags_initialized(bool v=true) { setflag(features, POF_VALID_AFLAGS, v); }
  bool is_f64() const { return (features & POF_IS_F64) != 0; }

  const opinfo_t *get_ti() const { return is_ti_initialized() ? &ti : nullptr; }
};

/// \name Get/Set refinfo
/// n may be 0, 1, 2, #OPND_MASK.
/// #OPND_OUTER may be used too.
/// Don't use these functions, see get_opinfo(), set_opinfo()
//@{
idaman bool ida_export set_refinfo_ex(ea_t ea, int n, const refinfo_t *ri);
idaman bool ida_export set_refinfo(
        ea_t ea,
        int n,
        reftype_t type,
        ea_t target=BADADDR,
        ea_t base=0,
        adiff_t tdelta=0);
idaman bool ida_export get_refinfo(refinfo_t *ri, ea_t ea, int n);
idaman bool ida_export del_refinfo(ea_t ea, int n);
//@}

//--------------------------------------------------------------------------
/// \name Structure paths
/// Structure paths for unions and structures with unions (strpath)
/// a structure path is an array of id's.
/// the first id is the id of the structure itself.
/// additional id's (if any) specify which member of a union we should select
/// the maximal size of array is #MAXSTRUCPATH.
/// strpaths are used to determine how to display structure offsets.
//@{
idaman void ida_export write_struc_path(ea_t ea, int idx, const tid_t *path, int plen, adiff_t delta);
idaman int  ida_export read_struc_path(tid_t *path, adiff_t *delta, ea_t ea, int idx);  // returns plen
//@}

//@}


//--------------------------------------------------------------------------
// type information (ti) storage
// up to 256 operands are supported for ti.

typedef uchar type_t;
typedef uchar p_list;
class tinfo_t;

/// \name Types
/// Work with function/data types
/// These functions may be used if necessary (despite of the AFLNOTE above).
//@{
idaman bool ida_export get_tinfo(tinfo_t *tif, ea_t ea);
idaman bool ida_export set_tinfo(ea_t ea, const tinfo_t *tif);
inline void idaapi del_tinfo(ea_t ea) { set_tinfo(ea, nullptr); }
//@}

/// \name Operand types
/// These functions may be used if necessary (despite of the AFLNOTE above).
//@{
idaman bool ida_export get_op_tinfo(tinfo_t *tif, ea_t ea, int n);
idaman bool ida_export set_op_tinfo(ea_t ea, int n, const tinfo_t *tif);
inline void idaapi del_op_tinfo(ea_t ea, int n) { set_op_tinfo(ea, n, nullptr); }
//@}

//------------------------------------------------------------------------//
/// \defgroup RIDX_ Rootnode indexes:
//@{

// supvals
#define RIDX_FILE_FORMAT_NAME        1     ///< file format name for loader modules
#define RIDX_SELECTORS               2     ///< 2..63 are for selector_t blob (see init_selectors())
#define RIDX_GROUPS                 64     ///< segment group information (see init_groups())
#define RIDX_H_PATH                 65     ///< C header path
#define RIDX_C_MACROS               66     ///< C predefined macros
#define RIDX_SMALL_IDC_OLD          67     ///< Instant IDC statements (obsolete)
#define RIDX_NOTEPAD                68     ///< notepad blob, occupies 1000 indexes (1MB of text)
#define RIDX_INCLUDE              1100     ///< assembler include file name
#define RIDX_SMALL_IDC            1200     ///< Instant IDC statements, blob
#define RIDX_DUALOP_GRAPH         1300     ///< Graph text representation options
#define RIDX_DUALOP_TEXT          1301     ///< Text text representation options
#define RIDX_MD5                  1302     ///< MD5 of the input file
#define RIDX_IDA_VERSION          1303     ///< version of ida which created the database

#define RIDX_STR_ENCODINGS        1305     ///< a list of encodings for the program strings
#define RIDX_SRCDBG_PATHS         1306     ///< source debug paths, occupies 20 indexes
#define RIDX_DBG_BINPATHS         1328     ///< unused (20 indexes)
#define RIDX_SHA256               1349     ///< SHA256 of the input file
#define RIDX_ABINAME              1350     ///< ABI name (processor specific)
#define RIDX_ARCHIVE_PATH         1351     ///< archive file path
#define RIDX_PROBLEMS             1352     ///< problem lists
#define RIDX_SRCDBG_UNDESIRED     1353     ///< user-closed source files, occupies 20 indexes

// altvals
#define RIDX_ALT_VERSION        uval_t(-1) ///< initial version of database
#define RIDX_ALT_CTIME          uval_t(-2) ///< database creation timestamp
#define RIDX_ALT_ELAPSED        uval_t(-3) ///< seconds database stayed open
#define RIDX_ALT_NOPENS         uval_t(-4) ///< how many times the database is opened
#define RIDX_ALT_CRC32          uval_t(-5) ///< input file crc32
#define RIDX_ALT_IMAGEBASE      uval_t(-6) ///< image base
#define RIDX_ALT_IDSNODE        uval_t(-7) ///< ids modnode id (for import_module)
#define RIDX_ALT_FSIZE          uval_t(-8) ///< input file size
#define RIDX_ALT_OUTFILEENC     uval_t(-9) ///< output file encoding index
//@}

//---------------------------------------------------------------------------
/// Get file name only of the input file
idaman ssize_t ida_export get_root_filename(char *buf, size_t bufsize);

/// Get debugger input file name/path (see #LFLG_DBG_NOPATH)
idaman ssize_t ida_export dbg_get_input_path(char *buf, size_t bufsize);

// The following functions should eventually be replaced by exported functions
#ifndef __KERNEL__
/// Get full path of the input file
inline ssize_t idaapi get_input_file_path(char *buf, size_t bufsize)
{
  return getinf_buf(INF_INPUT_FILE_PATH, buf, bufsize);
}

/// Set full path of the input file
inline void set_root_filename(const char *file) { setinf_buf(INF_INPUT_FILE_PATH, file); }

/// Get size of input file in bytes
inline size_t idaapi retrieve_input_file_size(void) { return getinf(INF_FSIZE); }

/// Get input file crc32 stored in the database.
/// it can be used to check that the input file has not been changed.
inline uint32 idaapi retrieve_input_file_crc32(void) { return uint32(getinf(INF_CRC32)); }

/// Get input file md5
inline bool idaapi retrieve_input_file_md5(uchar hash[16]) { return getinf_buf(INF_MD5, hash, 16) == 16; }

/// Get input file sha256
inline bool idaapi retrieve_input_file_sha256(uchar hash[32]) { return getinf_buf(INF_SHA256, hash, 32) == 32; }

/// Get name of the include file
inline ssize_t idaapi get_asm_inc_file(qstring *buf) { return getinf_str(buf, INF_INCLUDE); }

/// Set name of the include file
inline bool idaapi set_asm_inc_file(const char *file) { return setinf_buf(INF_INCLUDE, file); }

/// Get image base address
inline ea_t idaapi get_imagebase(void) { return getinf(INF_IMAGEBASE); }

/// Set image base address
inline void idaapi set_imagebase(ea_t base) { setinf(INF_IMAGEBASE, base); }

/// Get ids modnode
inline netnode idaapi get_ids_modnode(void) { return getinf(INF_IDSNODE); }

/// Set ids modnode
inline void idaapi set_ids_modnode(netnode id) { setinf(INF_IDSNODE, id); }

/// Get archive file path from which input file was extracted
inline ssize_t idaapi get_archive_path(qstring *out) { return getinf_str(out, INF_ARCHIVE_PATH); }

/// Set archive file path from which input file was extracted
inline bool set_archive_path(const char *file) { return setinf_buf(INF_ARCHIVE_PATH, file); }

/// Get file format name for loader modules
inline ssize_t idaapi get_loader_format_name(qstring *out) { return getinf_str(out, INF_FILE_FORMAT_NAME); }

/// Set file format name for loader modules
inline void set_loader_format_name(const char *name) { setinf_buf(INF_FILE_FORMAT_NAME, name); }

/// Get version of ida which created the database (string format like "7.5")
inline ssize_t idaapi get_initial_ida_version(qstring *out) { return getinf_str(out, INF_IDA_VERSION); }

/// Get notepad text
inline ssize_t idaapi get_ida_notepad_text(qstring *out) { return getinf_str(out, INF_NOTEPAD); }

/// Set notepad text
inline void idaapi set_ida_notepad_text(const char *text, size_t size=0) { setinf_buf(INF_NOTEPAD, text, size); }

/// Get source debug paths
inline ssize_t idaapi get_srcdbg_paths(qstring *out) { return getinf_str(out, INF_SRCDBG_PATHS); }

/// Set source debug paths
inline void idaapi set_srcdbg_paths(const char *paths) { setinf_buf(INF_SRCDBG_PATHS, paths); }

/// Get user-closed source files
inline ssize_t idaapi get_srcdbg_undesired_paths(qstring *out) { return getinf_str(out, INF_SRCDBG_UNDESIRED); }

/// Set user-closed source files
inline void idaapi set_srcdbg_undesired_paths(const char *paths) { setinf_buf(INF_SRCDBG_UNDESIRED, paths); }

/// Get initial version of the database (numeric format like 700)
inline ushort idaapi get_initial_idb_version() { return getinf(INF_INITIAL_VERSION); }

/// Get database creation timestamp
inline time_t idaapi get_idb_ctime() { return getinf(INF_CTIME); }

/// Get seconds database stayed open
inline size_t idaapi get_elapsed_secs() { return getinf(INF_ELAPSED); }

/// Get number of times the database is opened
inline size_t idaapi get_idb_nopens() { return getinf(INF_NOPENS); }

#endif

//---------------------------------------------------------------------------
/// \name String encodings
/// Encoding names can be a codepage names (CP1251, windows-1251),
/// charset name (Shift-JIS, UTF-8), or just codepage number (866, 932).
/// user-accessible encodings are counted from 1
/// (index 0 is reserved)
//@{

/// Get total number of encodings (counted from 0)

idaman int ida_export get_encoding_qty();


/// Get encoding name for specific index (1-based).
/// \param idx  the encoding index (1-based)
/// \retval nullptr       if IDX is out of bounds
/// \retval empty string  if the encoding was deleted

idaman const char *ida_export get_encoding_name(int idx);


/// Add a new encoding (e.g. "UTF-8").
/// If it's already in the list, return its index.
/// \param encname  the encoding name
/// \return its index (1-based); -1 means error

idaman int ida_export add_encoding(const char *encname);


/// Delete an encoding
/// The encoding is not actually removed because its index may be used in
/// strtype. So the deletion just clears the encoding name.
/// The default encoding cannot be deleted.
/// \param idx  the encoding index (1-based)

idaman bool ida_export del_encoding(int idx);


/// Change name for an encoding
/// The number of bytes per unit (BPU) of the new encoding must match this
/// number of the existing default encoding.
/// Specifying the empty name simply deletes this encoding.
/// \param idx  the encoding index (1-based)
/// \param encname  the new encoding name

idaman bool ida_export rename_encoding(int idx, const char *encname);


#define BPU_1B 1
#define BPU_2B 2
#define BPU_4B 4

/// Get the amount of bytes per unit (e.g., 2 for UTF-16, 4 for UTF-32)
/// for the encoding with the given index.
/// \param idx  the encoding index (1-based)
/// \return the number of bytes per units (1/2/4); -1 means error

idaman int ida_export get_encoding_bpu(int idx);


/// Get the amount of bytes per unit for the given encoding
/// \param encname  the encoding name
/// \return the number of bytes per units (1/2/4); -1 means error
idaman int ida_export get_encoding_bpu_by_name(const char *encname);


//-------------------------------------------------------------------------
inline int get_strtype_bpu(int32 strtype)
{
  int w = get_str_type_code(strtype) & STRWIDTH_MASK;
  return w == STRWIDTH_2B ? BPU_2B
       : w == STRWIDTH_4B ? BPU_4B
       :                    BPU_1B;
}

/// Get default encoding index for a specific string type.
/// \param bpu the amount of bytes per unit (e.g., 1 for ASCII, CP1252, UTF-8..., 2 for UTF-16, 4 for UTF-32)
/// \retval 0  bad BPU argument

idaman int ida_export get_default_encoding_idx(int bpu);


/// Set default encoding for a string type
/// \param bpu  the amount of bytes per unit
/// \param idx  the encoding index. It cannot be 0

idaman bool ida_export set_default_encoding_idx(int bpu, int idx);


/// Get encoding name for this strtype
/// \retval nullptr       if STRTYPE has an incorrent encoding index
/// \retval empty string  if the encoding was deleted

inline const char *idaapi encoding_from_strtype(int32 strtype)
{
  uchar enc = get_str_encoding_idx(strtype);
  if ( enc == STRENC_DEFAULT )
    enc = get_default_encoding_idx(get_strtype_bpu(strtype));
  return get_encoding_name(enc);
}


/// Get the index of the encoding used when producing files
/// \retval 0  the IDB's default 1 byte-per-unit encoding is used

idaman int ida_export get_outfile_encoding_idx();


/// set encoding to be used when producing files
/// \param idx  the encoding index
/// IDX can be 0 to use the IDB's default 1-byte-per-unit encoding

idaman bool ida_export set_outfile_encoding_idx(int idx);


//@}

//------------------------------------------------------------------------//
/// \name Functions to work with imports
//@{

/// Get number of import modules

idaman uint ida_export get_import_module_qty();


/// Get import module name.
/// \retval true   ok
/// \retval false  bad index

idaman bool ida_export get_import_module_name(qstring *buf, int mod_index);


/// Callback for enumerating imports.
/// \param ea     import address
/// \param name   import name (nullptr if imported by ordinal)
/// \param ord    import ordinal (0 for imports by name)
/// \param param  user parameter passed to enum_import_names()
/// \retval 1  ok
/// \retval 0  stop enumeration

typedef int idaapi import_enum_cb_t(ea_t ea, const char *name, uval_t ord, void *param);


/// Enumerate imports from specific module.
/// \retval  1     finished ok
/// \retval -1     error
/// \retval other  callback return value (<=0)

idaman int ida_export enum_import_names(int mod_index, import_enum_cb_t *callback, void *param=nullptr);


/// Delete all imported modules information

idaman void ida_export delete_imports(void);
//@}


/// Check consistency of name records, return number of bad ones

idaman int ida_export validate_idb_names2(bool do_repair);


#ifndef SWIG
#if !defined(NO_OBSOLETE_FUNCS)
//--------------------------------------------------------------------------
/// \name Ignore micro
/// netnode to keep information about various kinds of instructions
//@{
extern netnode ignore_micro;

#define IM_NONE   0     // regular instruction
#define IM_PROLOG 1     // prolog instruction
#define IM_EPILOG 2     // epilog instruction
#define IM_SWITCH 3     // switch instruction (the indirect jump should not be marked)

inline void init_ignore_micro(void)                  { ignore_micro.create("$ ignore micro"); }
inline void term_ignore_micro(void)                  { ignore_micro = BADNODE; }
inline char get_ignore_micro(ea_t ea)                { return ignore_micro.charval_ea(ea, 0); }
inline void set_ignore_micro(ea_t ea, uchar im_type) { ignore_micro.charset_ea(ea, im_type, 0); }
inline void clr_ignore_micro(ea_t ea)                { ignore_micro.chardel_ea(ea, 0); }
inline ea_t next_marked_insn(ea_t ea)                { return node2ea(ignore_micro.charnext(ea2node(ea), 0)); }
inline void mark_prolog_insn(ea_t ea)                { set_ignore_micro(ea, IM_PROLOG); }
inline void mark_epilog_insn(ea_t ea)                { set_ignore_micro(ea, IM_EPILOG); }
inline void mark_switch_insn(ea_t ea)                { set_ignore_micro(ea, IM_SWITCH); }
inline bool is_prolog_insn(ea_t ea)                  { return get_ignore_micro(ea) == IM_PROLOG; }
inline bool is_epilog_insn(ea_t ea)                  { return get_ignore_micro(ea) == IM_EPILOG; }
inline bool is_switch_insn(ea_t ea)                  { return get_ignore_micro(ea) == IM_SWITCH; }
inline bool should_ignore_micro(ea_t ea)             { return get_ignore_micro(ea) != IM_NONE; }
//@}
#endif
#endif // SWIG

//--------------------------------------------------------------------------
// Set address of .got section
inline void set_gotea(ea_t gotea)
{
  netnode n;
  n.create("$ got");
  n.altset(0, ea2node(gotea)+1);
}

//--------------------------------------------------------------------------
// Get address of .got section
inline ea_t get_gotea(void)
{
  netnode n("$ got");
  return exist(n) ? node2ea(n.altval(0) - 1) : BADADDR;
}


#if !defined(NO_OBSOLETE_FUNCS)
idaman DEPRECATED int ida_export validate_idb_names(); // use validate_idb_names2
#endif

#ifndef BYTES_SOURCE    // undefined bit masks so no one can use them directly
#undef AFL_LINNUM
#undef AFL_USERSP
#undef AFL_PUBNAM
#undef AFL_WEAKNAM
#undef AFL_HIDDEN
#undef AFL_MANUAL
#undef AFL_NOBRD
#undef AFL_ZSTROFF
#undef AFL_BNOT0
#undef AFL_BNOT1
#undef AFL_LIB
#undef AFL_TI
#undef AFL_TI0
#undef AFL_TI1
#undef AFL_LNAME
#undef AFL_TILCMT
#undef AFL_LZERO0
#undef AFL_LZERO1
#undef AFL_COLORED
#undef AFL_TERSESTR
#undef AFL_SIGN0
#undef AFL_SIGN1
#undef AFL_NORET
#undef AFL_FIXEDSPD
#undef NALT_ENUM
#undef NALT_WIDE
#undef NALT_SWITCH
//#undef NALT_STRUCT
#undef NALT_XREFPOS
#undef NALT_AFLAGS
#undef NALT_LINNUM
#undef NALT_ABSBASE
//#undef NALT_ENUM0
//#undef NALT_ENUM1
#undef NALT_PURGE
#undef NALT_STRTYPE
#undef NALT_ALIGN
#undef NALT_COLOR
#undef NSUP_CMT
#undef NSUP_REPCMT
#undef NSUP_FOP1
#undef NSUP_FOP2
#undef NSUP_JINFO
#undef NSUP_ARRAY
#undef NSUP_OMFGRP
#undef NSUP_FOP3
#undef NSUP_SWITCH
#undef NSUP_REF0
#undef NSUP_REF1
#undef NSUP_REF2
#undef NSUP_OREF0
#undef NSUP_OREF1
#undef NSUP_OREF2
#undef NSUP_STROFF0
#undef NSUP_STROFF1
#undef NSUP_SEGTRANS
#undef NSUP_FOP4
#undef NSUP_FOP5
#undef NSUP_FOP6
#undef NSUP_FOP7
#undef NSUP_FOP8
#undef NSUP_REF3
#undef NSUP_REF4
#undef NSUP_REF5
#undef NSUP_REF6
#undef NSUP_REF7
#undef NSUP_OREF3
#undef NSUP_OREF4
#undef NSUP_OREF5
#undef NSUP_OREF6
#undef NSUP_OREF7
#undef NSUP_MANUAL
#undef NSUP_FTAILS
#undef NSUP_GROUP
#endif

#endif // NALT_HPP
