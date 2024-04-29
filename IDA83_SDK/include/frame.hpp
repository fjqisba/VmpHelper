/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _FRAME_HPP
#define _FRAME_HPP
#include <idp.hpp>

/*! \file frame.hpp

  \brief Routines to manipulate function stack frames, stack
  variables, register variables and local labels.

  The frame is represented as a structure:
  <pre>
    +------------------------------------------------+
    | function arguments                             |
    +------------------------------------------------+
    | return address (isn't stored in func_t)        |
    +------------------------------------------------+
    | saved registers (SI, DI, etc - func_t::frregs) |
    +------------------------------------------------+ <- typical BP
    |                                                |  |
    |                                                |  | func_t::fpd
    |                                                |  |
    |                                                | <- real BP
    | local variables (func_t::frsize)               |
    |                                                |
    |                                                |
    +------------------------------------------------+ <- SP
  </pre>

  To access the structure of a function frame, use:
    - get_struc() (use func_t::frame as structure ID)
    - get_frame(const func_t *pfn)
    - get_frame(ea_t ea)
*/

class struc_t;
class member_t;
class op_t;

// We need to trace value of SP register. For this we introduce
// an array of SP register change points.

// SP register change point
//
// NOTE: To manipulate/modify stack points, please use the specialized
// functions provided below in this file (stack pointer change points)

struct stkpnt_t
{
  ea_t ea;              // linear address
  sval_t spd;           // here we keep a cumulative difference from [BP-frsize]

  DECLARE_COMPARISONS(stkpnt_t)
  {
    if ( ea < r.ea )
      return -1;
    if ( ea > r.ea )
      return 1;
    return 0;
  }
};
DECLARE_TYPE_AS_MOVABLE(stkpnt_t);
// we declare a struct to be able to forward declare it in other files
struct stkpnts_t : public qvector<stkpnt_t>
{
  DECLARE_COMPARISONS(stkpnts_t) { return compare_containers(*this, r); }
};

//--------------------------------------------------------------------------
//      F R A M E   M A N I P U L A T I O N
//--------------------------------------------------------------------------

/// Add function frame.
/// \param pfn      pointer to function structure
/// \param frsize   size of function local variables
/// \param frregs   size of saved registers
/// \param argsize  size of function arguments range which will be purged upon return.
///                 this parameter is used for __stdcall and __pascal calling conventions.
///                 for other calling conventions please pass 0.
/// \retval 1  ok
/// \retval 0  failed (no function, frame already exists)

idaman bool ida_export add_frame(
        func_t *pfn,
        sval_t frsize,
        ushort frregs,
        asize_t argsize);


/// Delete a function frame.
/// \param pfn  pointer to function structure
/// \return success

idaman bool ida_export del_frame(func_t *pfn);


/// Set size of function frame.
/// Note: The returned size may not include all stack arguments. It does so
/// only for __stdcall and __fastcall calling conventions. To get the entire
/// frame size for all cases use get_struc_size(get_frame(pfn)).
/// \param pfn      pointer to function structure
/// \param frsize   size of function local variables
/// \param frregs   size of saved registers
/// \param argsize  size of function arguments that will be purged
///                 from the stack upon return
/// \return success

idaman bool ida_export set_frame_size(
        func_t *pfn,
        asize_t frsize,
        ushort frregs,
        asize_t argsize);


/// Get full size of a function frame.
/// This function takes into account size of local variables + size of
/// saved registers + size of return address + number of purged bytes.
/// The purged bytes correspond to the arguments of the functions with
/// __stdcall and __fastcall calling conventions.
/// \param pfn  pointer to function structure, may be nullptr
/// \return size of frame in bytes or zero

idaman asize_t ida_export get_frame_size(const func_t *pfn);


/// Get size of function return address.
/// \param pfn  pointer to function structure, can't be nullptr

idaman int ida_export get_frame_retsize(const func_t *pfn);

/// Parts of a frame
enum frame_part_t
{
  FPC_ARGS,
  FPC_RETADDR,
  FPC_SAVREGS,
  FPC_LVARS,
};

/// Get offsets of the frame part in the frame.
/// \param range  pointer to the output buffer with the frame part
///               start/end(exclusive) offsets, can't be nullptr
/// \param pfn    pointer to function structure, can't be nullptr
/// \param part   frame part

idaman void ida_export get_frame_part(range_t *range, const func_t *pfn, frame_part_t part);

/// Get starting address of arguments section

inline ea_t frame_off_args(const func_t *pfn)
{
  range_t range;
  get_frame_part(&range, pfn, FPC_ARGS);
  return range.start_ea;
}

/// Get starting address of return address section

inline ea_t frame_off_retaddr(const func_t *pfn)
{
  range_t range;
  get_frame_part(&range, pfn, FPC_RETADDR);
  return range.start_ea;
}

/// Get starting address of saved registers section

inline ea_t frame_off_savregs(const func_t *pfn)
{
  range_t range;
  get_frame_part(&range, pfn, FPC_SAVREGS);
  return range.start_ea;
}

/// Get start address of local variables section

inline ea_t frame_off_lvars(const func_t *pfn)
{
  range_t range;
  get_frame_part(&range, pfn, FPC_LVARS);
  return range.start_ea;
}

/// Does the given offset lie within the arguments section?

inline bool processor_t::is_funcarg_off(const func_t *pfn, uval_t frameoff) const
{
  range_t args;
  get_frame_part(&args, pfn, FPC_ARGS);
  return stkup()
       ? frameoff < args.end_ea
       : frameoff >= args.start_ea;
}

/// Does the given offset lie within the local variables section?

inline sval_t processor_t::lvar_off(const func_t *pfn, uval_t frameoff) const
{
  range_t lvars;
  get_frame_part(&lvars, pfn, FPC_LVARS);
  return stkup()
       ? frameoff - lvars.start_ea
       : lvars.end_ea - frameoff;
}

/// Get pointer to function frame.
/// \param pfn  pointer to function structure

idaman struc_t *ida_export get_frame(const func_t *pfn);

/// Get pointer to function frame.
/// \param ea  any address in the function

inline struc_t *get_frame(ea_t ea) { return get_frame(get_func(ea)); }


/// Convert struct offsets into fp-relative offsets.
/// This function converts the offsets inside the struc_t object
/// into the frame pointer offsets (for example, EBP-relative).

inline sval_t soff_to_fpoff(func_t *pfn, uval_t soff)
{
  return pfn != nullptr ? soff - pfn->frsize + pfn->fpd : soff;
}


/// Update frame pointer delta.
/// \param pfn  pointer to function structure
/// \param fpd  new fpd value.
///             cannot be bigger than the local variable range size.
/// \return success

idaman bool ida_export update_fpd(func_t *pfn, asize_t fpd);


/// Set the number of purged bytes for a function or data item (funcptr).
/// This function will update the database and plan to reanalyze items
/// referencing the specified address. It works only for processors
/// with #PR_PURGING bit in 16 and 32 bit modes.
/// \param ea                   address of the function of item
/// \param nbytes               number of purged bytes
/// \param override_old_value   may overwrite old information about purged bytes
/// \return success

idaman bool ida_export set_purged(ea_t ea, int nbytes, bool override_old_value);


/// Get function by its frame id.
/// \warning this function works only with databases created by IDA > 5.6
/// \param frame_id  id of the function frame
/// \return start address of the function or #BADADDR

idaman ea_t ida_export get_func_by_frame(tid_t frame_id);


//--------------------------------------------------------------------------
//      S T A C K   V A R I A B L E S
//--------------------------------------------------------------------------

/// Get pointer to stack variable.
/// \param actval  actual value used to fetch stack variable
///                this pointer may point to 'v'
/// \param insn    the instruction
/// \param x       reference to instruction operand
/// \param v       immediate value in the operand (usually x.addr)
/// \return nullptr or ptr to stack variable

idaman member_t *ida_export get_stkvar(
        sval_t *actval,
        const insn_t &insn,
        const op_t &x,
        sval_t v);

/// Automatically add stack variable if doesn't exist.
/// Processor modules should use insn_t::create_stkvar().
/// \param insn   the instruction
/// \param x      reference to instruction operand
/// \param v      immediate value in the operand (usually x.addr)
/// \param flags  \ref STKVAR_1
/// \return success

idaman bool ida_export add_stkvar(const insn_t &insn, const op_t &x, sval_t v, int flags);

/// \defgroup STKVAR_1 Add stkvar flags
/// Passed as 'flags' parameter to add_stkvar()
//@{
#define STKVAR_VALID_SIZE       0x0001 ///< x.dtyp contains correct variable type
                                       ///< (for insns like 'lea' this bit must be off).
                                       ///< In general, dr_O references do not allow
                                       ///< to determine the variable size
//@}

/// Define/redefine a stack variable.
/// \param pfn     pointer to function
/// \param name    variable name, nullptr means autogenerate a name
/// \param off     offset of the stack variable in the frame.
///                negative values denote local variables, positive - function arguments.
/// \param flags   variable type flags (byte_flag() for a byte variable, for example)
/// \param ti      additional type information (like offsets, structs, etc)
/// \param nbytes  number of bytes occupied by the variable
/// \return success

idaman bool ida_export define_stkvar(
        func_t *pfn,
        const char *name,
        sval_t off,
        flags64_t flags,
        const opinfo_t *ti,
        asize_t nbytes);


/// Build automatic stack variable name.
/// \param buf  pointer to buffer
/// \param pfn  pointer to function (can't be nullptr!)
/// \param v    value of variable offset
/// \return length of stack variable name or -1

idaman ssize_t ida_export build_stkvar_name(
        qstring *buf,
        const func_t *pfn,
        sval_t v);


/// Calculate offset of stack variable in the frame structure.
/// \param pfn  pointer to function (can't be nullptr!)
/// \param insn the instruction
/// \param n    0..#UA_MAXOP-1 operand number
///              -1 if error, return #BADADDR
/// \return #BADADDR if some error (issue a warning if stack frame is bad)

idaman ea_t ida_export calc_stkvar_struc_offset(
        func_t *pfn,
        const insn_t &insn,
        int n);


/// Find and delete wrong frame info.
/// Namely, we delete:
///   - unreferenced stack variable definitions
///   - references to dead stack variables (i.e. operands displayed in red)
///     these operands will be untyped and most likely displayed in hex.
/// We also plan to reanalyze instruction with the stack frame references
/// \param pfn  pointer to the function
/// \param should_reanalyze callback to determine which instructions to reanalyze
/// \return number of deleted definitions

idaman int ida_export delete_wrong_frame_info(
        func_t *pfn,
        bool idaapi should_reanalyze(const insn_t &insn));


//--------------------------------------------------------------------------
//      R E G I S T E R   V A R I A B L E S
//--------------------------------------------------------------------------
/// \defgroup regvar Register variables
/// Definition of ::regvar_t and related functions
//@{

idaman void ida_export free_regvar(struct regvar_t *v);

/// A register variable allows the user to rename a general processor register
/// to a meaningful name.
/// IDA doesn't check whether the target assembler supports the register renaming.
/// All register definitions will appear at the beginning of the function.
struct regvar_t : public range_t
{
  char *canon = nullptr; ///< canonical register name (case-insensitive)
  char *user = nullptr;  ///< user-defined register name
  char *cmt = nullptr;   ///< comment to appear near definition

  regvar_t() {}
  regvar_t(const regvar_t &r) : range_t(r)
  {
    canon = ::qstrdup(r.canon);
    user = ::qstrdup(r.user);
    cmt = ::qstrdup(r.cmt);
  }
  ~regvar_t() { free_regvar(this); }
  regvar_t &operator=(const regvar_t &r)
  {
    if ( this != &r )
    {
      free_regvar(this);
      new (this) regvar_t(r);
    }
    return *this;
  }
  void swap(regvar_t &r)
  {
    uchar buf[sizeof(*this)];
    memcpy(buf, &r, sizeof(buf));
    memcpy(&r, this, sizeof(buf));
    memcpy(this, buf, sizeof(buf));
  }
#ifndef SWIG
  DECLARE_COMPARISONS(regvar_t);
#endif
};
DECLARE_TYPE_AS_MOVABLE(regvar_t);

/// Define a register variable.
/// \param pfn      function in which the definition will be created
/// \param ea1,ea2  range of addresses within the function where the definition
///                 will be used
/// \param canon    name of a general register
/// \param user     user-defined name for the register
/// \param cmt      comment for the definition
/// \return \ref REGVAR_ERROR_

idaman int ida_export add_regvar(
        func_t *pfn,
        ea_t ea1,
        ea_t ea2,
        const char *canon,
        const char *user,
        const char *cmt);
/// \defgroup REGVAR_ERROR_ Register variable error codes
/// Return values for functions in described in \ref regvar
//@{
#define REGVAR_ERROR_OK         0     ///< all ok
#define REGVAR_ERROR_ARG        (-1)  ///< function arguments are bad
#define REGVAR_ERROR_RANGE      (-2)  ///< the definition range is bad
#define REGVAR_ERROR_NAME       (-3)  ///< the provided name(s) can't be accepted
//@}

/// Find a register variable definition (powerful version).
/// One of 'canon' and 'user' should be nullptr.
/// If both 'canon' and 'user' are nullptr it returns the first regvar
/// definition in the range.
/// \param pfn      function in question
/// \param ea1,ea2  range of addresses to search.
///                 ea1==BADADDR means the entire function
/// \param canon    name of a general register
/// \param user     user-defined name for the register
/// \return nullptr-not found, otherwise ptr to regvar_t

idaman regvar_t *ida_export find_regvar(func_t *pfn, ea_t ea1, ea_t ea2, const char *canon, const char *user);


/// Find a register variable definition.
/// \param pfn    function in question
/// \param ea     current address
/// \param canon  name of a general register
/// \return nullptr-not found, otherwise ptr to regvar_t

inline regvar_t *find_regvar(func_t *pfn, ea_t ea, const char *canon)
{
  return find_regvar(pfn, ea, ea+1, canon, nullptr);
}


/// Is there a register variable definition?
/// \param pfn    function in question
/// \param ea     current address

inline bool has_regvar(func_t *pfn, ea_t ea)
{
  return find_regvar(pfn, ea, ea+1, nullptr, nullptr) != nullptr;
}


/// Rename a register variable.
/// \param pfn   function in question
/// \param v     variable to rename
/// \param user  new user-defined name for the register
/// \return \ref REGVAR_ERROR_

idaman int ida_export rename_regvar(func_t *pfn, regvar_t *v, const char *user);


/// Set comment for a register variable.
/// \param pfn  function in question
/// \param v    variable to rename
/// \param cmt  new comment
/// \return \ref REGVAR_ERROR_

idaman int ida_export set_regvar_cmt(func_t *pfn, regvar_t *v, const char *cmt);


/// Delete a register variable definition.
/// \param pfn      function in question
/// \param ea1,ea2  range of addresses within the function where the definition holds
/// \param canon    name of a general register
/// \return \ref REGVAR_ERROR_

idaman int ida_export del_regvar(func_t *pfn, ea_t ea1, ea_t ea2, const char *canon);

//@} regvar

//--------------------------------------------------------------------------
//      S P   R E G I S T E R   C H A N G E   P O I N T S
//--------------------------------------------------------------------------

/// Add automatic SP register change point.
/// \param pfn    pointer to function. may be nullptr.
/// \param ea     linear address where SP changes.
///               usually this is the end of the instruction which
///               modifies the stack pointer (\cmd{ea}+\cmd{size})
/// \param delta  difference between old and new values of SP
/// \return success

idaman bool ida_export add_auto_stkpnt(func_t *pfn, ea_t ea, sval_t delta);


/// Add user-defined SP register change point.
/// \param ea     linear address where SP changes
/// \param delta  difference between old and new values of SP
/// \return success

idaman bool ida_export add_user_stkpnt(ea_t ea, sval_t delta);


/// Delete SP register change point.
/// \param pfn  pointer to function. may be nullptr.
/// \param ea   linear address
/// \return success

idaman bool ida_export del_stkpnt(func_t *pfn, ea_t ea);


/// Get difference between the initial and current values of ESP.
/// \param pfn  pointer to function. may be nullptr.
/// \param ea   linear address of an instruction
/// \return 0 or the difference, usually a negative number.
///         returns the sp-diff before executing the instruction.

idaman sval_t ida_export get_spd(func_t *pfn, ea_t ea);


/// Get effective difference between the initial and current values of ESP.
/// This function returns the sp-diff used by the instruction.
/// The difference between get_spd() and get_effective_spd() is present only
/// for instructions like "pop [esp+N]": they modify sp and use the modified value.
/// \param pfn  pointer to function. may be nullptr.
/// \param ea   linear address
/// \return 0 or the difference, usually a negative number

idaman sval_t ida_export get_effective_spd(func_t *pfn, ea_t ea);


/// Get modification of SP made at the specified location
/// \param pfn  pointer to function. may be nullptr.
/// \param ea   linear address
/// \return 0 if the specified location doesn't contain a SP change point.
///         otherwise return delta of SP modification.

idaman sval_t ida_export get_sp_delta(func_t *pfn, ea_t ea);


/// Recalculate SP delta for an instruction that stops execution.
/// The next instruction is not reached from the current instruction.
/// We need to recalculate SP for the next instruction.
///
/// This function will create a new automatic SP register change
/// point if necessary. It should be called from the emulator (emu.cpp)
/// when auto_state == ::AU_USED if the current instruction doesn't pass
/// the execution flow to the next instruction.
/// \param cur_ea  linear address of the current instruction
/// \retval 1  new stkpnt is added
/// \retval 0  nothing is changed

idaman bool ida_export recalc_spd(ea_t cur_ea);


/// An xref to an argument or variable located in a function's stack frame
struct xreflist_entry_t
{
  ea_t ea;     ///< Location of the insn referencing the stack frame member
  uchar opnum; ///< Number of the operand of that instruction
  uchar type;  ///< The type of xref (::cref_t & ::dref_t)

  DECLARE_COMPARISONS(xreflist_entry_t)
  {
    int code = ::compare(ea, r.ea);
    if ( code == 0 )
    {
      code = ::compare(type, r.type);
      if ( code == 0 )
        code = ::compare(opnum, r.opnum);
    }
    return code;
  }
};
DECLARE_TYPE_AS_MOVABLE(xreflist_entry_t);
typedef qvector<xreflist_entry_t> xreflist_t; ///< vector of xrefs to variables in a function's stack frame

/// Fill 'out' with a list of all the xrefs made from function 'pfn', to
/// the argument or variable 'mptr' in 'pfn's stack frame.
/// \param out   the list of xrefs to fill.
/// \param pfn   the function to scan.
/// \param mptr  the argument/variable in pfn's stack frame.

idaman void ida_export build_stkvar_xrefs(xreflist_t *out, func_t *pfn, const member_t *mptr);


#ifndef NO_OBSOLETE_FUNCS
idaman DEPRECATED ea_t ida_export get_min_spd_ea(func_t *pfn);
idaman DEPRECATED int ida_export delete_unreferenced_stkvars(func_t *pfn);
idaman DEPRECATED int ida_export delete_wrong_stkvar_ops(func_t *pfn);
#endif

#endif // _FRAME_HPP
