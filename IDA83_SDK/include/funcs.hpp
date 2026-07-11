/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef FUNCS_HPP
#define FUNCS_HPP
#include <range.hpp>
#include <bytes.hpp>

/*! \file funcs.hpp

  \brief Routines for working with functions within the disassembled program.

  This file also contains routines for working with library signatures
  (e.g. FLIRT).

  Each function consists of function chunks. At least one function chunk
  must be present in the function definition - the function entry chunk.
  Other chunks are called function tails. There may be several of them
  for a function.

  A function tail is a continuous range of addresses.
  It can be used in the definition of one or more functions.
  One function using the tail is singled out and called the tail owner.
  This function is considered as 'possessing' the tail.
  get_func() on a tail address will return the function possessing the tail.
  You can enumerate the functions using the tail by using ::func_parent_iterator_t.

  Each function chunk in the disassembly is represented as an "range" (a range
  of addresses, see range.hpp for details) with characteristics.

  A function entry must start with an instruction (code) byte.
*/

struct stkpnt_t;                // #include <frame.hpp>
struct regvar_t;                // #include <frame.hpp>
struct llabel_t;                // #include <frame.hpp>
class insn_t;                   // #include <ua.hpp>

idaman void ida_export free_regarg(struct regarg_t *v);

/// Register argument description.
/// regargs are destroyed when the full function type is determined.
struct regarg_t
{
  int reg = 0;
  type_t *type = nullptr;
  char *name = nullptr;

  regarg_t() {}
  regarg_t(const regarg_t &r) : reg(r.reg)
  {
    type = (type_t *)::qstrdup((char *)r.type);
    name = ::qstrdup(r.name);
  }
  ~regarg_t() { free_regarg(this); }
  regarg_t &operator=(const regarg_t &r)
  {
    if ( this != &r )
    {
      free_regarg(this);
      new (this) regarg_t(r);
    }
    return *this;
  }
  void swap(regarg_t &r)
  {
    std::swap(reg, r.reg);
    std::swap(type, r.type);
    std::swap(name, r.name);
  }
#ifndef SWIG
  DECLARE_COMPARISONS(regarg_t);
#endif

};
DECLARE_TYPE_AS_MOVABLE(regarg_t);

//------------------------------------------------------------------------
/// A function is a set of continuous ranges of addresses with characteristics
class func_t : public range_t
{
public:
  uint64 flags;                        ///< \ref FUNC_
/// \defgroup FUNC_ Function flags
/// Used by func_t::flags
//@{
#define FUNC_NORET      0x00000001     ///< Function doesn't return
#define FUNC_FAR        0x00000002     ///< Far function
#define FUNC_LIB        0x00000004     ///< Library function

#define FUNC_STATICDEF  0x00000008     ///< Static function

#define FUNC_FRAME      0x00000010     ///< Function uses frame pointer (BP)
#define FUNC_USERFAR    0x00000020     ///< User has specified far-ness
                                       ///< of the function
#define FUNC_HIDDEN     0x00000040     ///< A hidden function chunk
#define FUNC_THUNK      0x00000080     ///< Thunk (jump) function
#define FUNC_BOTTOMBP   0x00000100     ///< BP points to the bottom of the stack frame
#define FUNC_NORET_PENDING 0x00200     ///< Function 'non-return' analysis must be performed.
                                       ///< This flag is verified upon func_does_return()
#define FUNC_SP_READY   0x00000400     ///< SP-analysis has been performed.
                                       ///< If this flag is on, the stack
                                       ///< change points should not be not
                                       ///< modified anymore. Currently this
                                       ///< analysis is performed only for PC
#define FUNC_FUZZY_SP   0x00000800     ///< Function changes SP in untraceable way,
                                       ///< for example: and esp, 0FFFFFFF0h
#define FUNC_PROLOG_OK  0x00001000     ///< Prolog analysis has been performed
                                       ///< by last SP-analysis
#define FUNC_PURGED_OK  0x00004000     ///< 'argsize' field has been validated.
                                       ///< If this bit is clear and 'argsize'
                                       ///< is 0, then we do not known the real
                                       ///< number of bytes removed from
                                       ///< the stack. This bit is handled
                                       ///< by the processor module.
#define FUNC_TAIL       0x00008000     ///< This is a function tail.
                                       ///< Other bits must be clear
                                       ///< (except #FUNC_HIDDEN).
#define FUNC_LUMINA     0x00010000     ///< Function info is provided by Lumina.
#define FUNC_OUTLINE    0x00020000     ///< Outlined code, not a real function.
#define FUNC_REANALYZE  0x00040000     ///< Function frame changed, request to
                                       ///< reanalyze the function after the last
                                       ///< insn is analyzed.

#define FUNC_RESERVED   0x8000000000000000LL ///< Reserved (for internal usage)
//@}

  /// Is a far function?
  bool is_far(void) const { return (flags & FUNC_FAR) != 0; }
  /// Does function return?
  bool does_return(void) const { return (flags & FUNC_NORET) == 0; }
  /// Has SP-analysis been performed?
  bool analyzed_sp(void) const { return (flags & FUNC_SP_READY) != 0; }
  /// Needs prolog analysis?
  bool need_prolog_analysis(void) const { return (flags & FUNC_PROLOG_OK) == 0; }
#ifndef SWIG
  union
  {
    /// attributes of a function entry chunk
    struct
    {
#endif // SWIG
      //
      // Stack frame of the function. It is represented as a structure:
      //
      //    +------------------------------------------------+
      //    | function arguments                             |
      //    +------------------------------------------------+
      //    | return address (isn't stored in func_t)        |
      //    +------------------------------------------------+
      //    | saved registers (SI, DI, etc - func_t::frregs) |
      //    +------------------------------------------------+ <- typical BP
      //    |                                                |  |
      //    |                                                |  | func_t::fpd
      //    |                                                |  |
      //    |                                                | <- real BP
      //    | local variables (func_t::frsize)               |
      //    |                                                |
      //    |                                                |
      //    +------------------------------------------------+ <- SP
      //
      uval_t frame;        ///< netnode id of frame structure - see frame.hpp
      asize_t frsize;      ///< size of local variables part of frame in bytes.
                           ///< If #FUNC_FRAME is set and #fpd==0, the frame pointer
                           ///< (EBP) is assumed to point to the top of the local
                           ///< variables range.
      ushort frregs;       ///< size of saved registers in frame. This range is
                           ///< immediately above the local variables range.
      asize_t argsize;     ///< number of bytes purged from the stack
                           ///< upon returning
      asize_t fpd;         ///< frame pointer delta. (usually 0, i.e. realBP==typicalBP)
                           ///< use update_fpd() to modify it.

      bgcolor_t color;     ///< user defined function color

        // the following fields should not be accessed directly:

      uint32 pntqty;       ///< number of SP change points
      stkpnt_t *points;    ///< array of SP change points.
                           ///< use ...stkpnt...() functions to access this array.

      int regvarqty;       ///< number of register variables (-1-not read in yet)
                           ///< use find_regvar() to read register variables
      regvar_t *regvars;   ///< array of register variables.
                           ///< this array is sorted by: start_ea.
                           ///< use ...regvar...() functions to access this array.

      int llabelqty;       ///< number of local labels
      llabel_t *llabels;   ///< local labels.
                           ///< this array shouldn't be accessed directly; name.hpp
                           ///< functions should be used instead.

      int regargqty;       ///< number of register arguments.
                           ///< During analysis IDA tries to guess the register
                           ///< arguments. It stores store the guessing outcome
                           ///< in this field. As soon as it determines the final
                           ///< function prototype, regargqty is set to zero.
      regarg_t *regargs;   ///< unsorted array of register arguments.
                           ///< use ...regarg...() functions to access this array.
                           ///< regargs are destroyed when the full function
                           ///< type is determined.

      int tailqty;         ///< number of function tails
      range_t *tails;      ///< array of tails, sorted by ea.
                           ///< use func_tail_iterator_t to access function tails.
#ifndef SWIG
    };
    /// attributes of a function tail chunk
    struct
    {
#endif // SWIG
      ea_t owner;          ///< the address of the main function possessing this tail
      int refqty;          ///< number of referers
      ea_t *referers;      ///< array of referers (function start addresses).
                           ///< use func_parent_iterator_t to access the referers.
#ifndef SWIG
    };
  };
#endif // SWIG

  func_t(ea_t start=0, ea_t end=0, flags64_t f=0)
    : range_t(start, end), flags(f|FUNC_NORET_PENDING), frame(BADNODE),
      frsize(0), frregs(0), argsize(0), fpd(0), color(DEFCOLOR),
      pntqty(0), points(nullptr),
      regvarqty(0), regvars(nullptr),
      llabelqty(0), llabels(nullptr),
      regargqty(0), regargs(nullptr),
      tailqty(0), tails(nullptr)
  {
  }
#ifndef SWIG
  DECLARE_COMPARISONS(func_t);
#endif
};
DECLARE_TYPE_AS_MOVABLE(func_t);

/// Does function describe a function entry chunk?
inline bool is_func_entry(const func_t *pfn) { return pfn != nullptr && (pfn->flags & FUNC_TAIL) == 0; }
/// Does function describe a function tail chunk?
inline bool is_func_tail(const func_t *pfn) { return pfn != nullptr && (pfn->flags & FUNC_TAIL) != 0; }


/// Lock function pointer
/// Locked pointers are guaranteed to remain valid until they are unlocked.
/// Ranges with locked pointers cannot be deleted or moved.

idaman void ida_export lock_func_range(const func_t *pfn, bool lock);

/// Helper class to lock a function pointer so it stays valid
class lock_func
{
  const func_t *pfn;
public:
  lock_func(const func_t *_pfn) : pfn(_pfn)
  {
    lock_func_range(pfn, true);
  }
  ~lock_func(void)
  {
    lock_func_range(pfn, false);
  }
};

/// Is the function pointer locked?

idaman bool ida_export is_func_locked(const func_t *pfn);

//--------------------------------------------------------------------
//      F U N C T I O N S
//--------------------------------------------------------------------
/// Get pointer to function structure by address.
/// \param ea  any address in a function
/// \return ptr to a function or nullptr.
/// This function returns a function entry chunk.

idaman func_t *ida_export get_func(ea_t ea);


/// Get the containing tail chunk of 'ea'.
/// \retval -1   means 'does not contain ea'
/// \retval  0   means the 'pfn' itself contains ea
/// \retval >0   the number of the containing function tail chunk

idaman int ida_export get_func_chunknum(func_t *pfn, ea_t ea);

/// Does the given function contain the given address?

inline bool func_contains(func_t *pfn, ea_t ea)
{
  return get_func_chunknum(pfn, ea) >= 0;
}

/// Do two addresses belong to the same function?
inline bool is_same_func(ea_t ea1, ea_t ea2)
{
  func_t *pfn = get_func(ea1);
  return pfn != nullptr && func_contains(pfn, ea2);
}

/// Get pointer to function structure by number.
/// \param n  number of function, is in range 0..get_func_qty()-1
/// \return ptr to a function or nullptr.
/// This function returns a function entry chunk.

idaman func_t *ida_export getn_func(size_t n);


/// Get total number of functions in the program

idaman size_t ida_export get_func_qty(void);


/// Get ordinal number of a function.
/// \param ea  any address in the function
/// \return number of function (0..get_func_qty()-1).
/// -1 means 'no function at the specified address'.

idaman int ida_export get_func_num(ea_t ea);


/// Get pointer to the previous function.
/// \param ea  any address in the program
/// \return ptr to function or nullptr if previous function doesn't exist

idaman func_t *ida_export get_prev_func(ea_t ea);


/// Get pointer to the next function.
/// \param ea  any address in the program
/// \return ptr to function or nullptr if next function doesn't exist

idaman func_t *ida_export get_next_func(ea_t ea);


/// Get function ranges.
/// \param ranges buffer to receive the range info
/// \param pfn    ptr to function structure
/// \return end address of the last function range (BADADDR-error)

idaman ea_t ida_export get_func_ranges(rangeset_t *ranges, func_t *pfn);


/// Get function comment.
/// \param buf         buffer for the comment
/// \param pfn         ptr to function structure
/// \param repeatable  get repeatable comment?
/// \return size of comment or -1
/// In fact this function works with function chunks too.

idaman ssize_t ida_export get_func_cmt(qstring *buf, const func_t *pfn, bool repeatable);


/// Set function comment.
/// This function works with function chunks too.
/// \param pfn         ptr to function structure
/// \param cmt         comment string, may be multiline (with '\n').
///                    Use empty str ("") to delete comment
/// \param repeatable  set repeatable comment?

idaman bool ida_export set_func_cmt(const func_t *pfn, const char *cmt, bool repeatable);


/// Update information about a function in the database (::func_t).
/// You must not change the function start and end addresses using this function.
/// Use set_func_start() and set_func_end() for it.
/// \param pfn         ptr to function structure
/// \return success

idaman bool ida_export update_func(func_t *pfn);


/// Add a new function.
/// If the fn->end_ea is #BADADDR, then IDA will try to determine the
/// function bounds by calling find_func_bounds(..., #FIND_FUNC_DEFINE).
/// \param pfn  ptr to filled function structure
/// \return success

idaman bool ida_export add_func_ex(func_t *pfn);


/// Add a new function.
/// If the function end address is #BADADDR, then IDA will try to determine
/// the function bounds by calling find_func_bounds(..., #FIND_FUNC_DEFINE).
/// \param ea1  start address
/// \param ea2  end address
/// \return success

inline bool add_func(ea_t ea1, ea_t ea2=BADADDR)
{
  func_t fn(ea1, ea2);
  return add_func_ex(&fn);
}


/// Delete a function.
/// \param ea  any address in the function entry chunk
/// \return success

idaman bool ida_export del_func(ea_t ea);


/// Move function chunk start address.
/// \param ea        any address in the function
/// \param newstart  new end address of the function
/// \return \ref MOVE_FUNC_

idaman int ida_export set_func_start(ea_t ea, ea_t newstart);
/// \defgroup MOVE_FUNC_ Function move result codes
/// Return values for set_func_start()
//@{
#define MOVE_FUNC_OK            0  ///< ok
#define MOVE_FUNC_NOCODE        1  ///< no instruction at 'newstart'
#define MOVE_FUNC_BADSTART      2  ///< bad new start address
#define MOVE_FUNC_NOFUNC        3  ///< no function at 'ea'
#define MOVE_FUNC_REFUSED       4  ///< a plugin refused the action
//@}


/// Move function chunk end address.
/// \param ea      any address in the function
/// \param newend  new end address of the function
/// \return success

idaman bool ida_export set_func_end(ea_t ea, ea_t newend);


/// Reanalyze a function.
/// This function plans to analyzes all chunks of the given function.
/// Optional parameters (ea1, ea2) may be used to narrow the analyzed range.
/// \param pfn              pointer to a function
/// \param ea1              start of the range to analyze
/// \param ea2              end of range to analyze
/// \param analyze_parents  meaningful only if pfn points to a function tail.
///                         if true, all tail parents will be reanalyzed.
///                         if false, only the given tail will be reanalyzed.

idaman void ida_export reanalyze_function(
        func_t *pfn,
        ea_t ea1=0,
        ea_t ea2=BADADDR,
        bool analyze_parents=false);


/// Determine the boundaries of a new function.
/// This function tries to find the start and end addresses of a new function.
/// It calls the module with \ph{func_bounds} in order to fine tune
/// the function boundaries.
/// \param nfn    structure to fill with information
/// \             nfn->start_ea points to the start address of the new function.
/// \param flags  \ref FIND_FUNC_F
/// \return \ref FIND_FUNC_R

idaman int ida_export find_func_bounds(func_t *nfn, int flags);

/// \defgroup FIND_FUNC_F Find function bounds flags
/// Passed as 'flags' parameter to find_func_bounds()
//@{
#define FIND_FUNC_NORMAL   0x0000 ///< stop processing if undefined byte is encountered
#define FIND_FUNC_DEFINE   0x0001 ///< create instruction if undefined byte is encountered
#define FIND_FUNC_IGNOREFN 0x0002 ///< ignore existing function boundaries.
                                  ///< by default the function returns function boundaries
                                  ///< if ea belongs to a function.
#define FIND_FUNC_KEEPBD   0x0004 ///< do not modify incoming function boundaries,
                                  ///< just create instructions inside the boundaries.
//@}

/// \defgroup FIND_FUNC_R Find function bounds result codes
/// Return values for find_func_bounds()
//@{
#define FIND_FUNC_UNDEF 0         ///< function has instructions that pass execution flow to unexplored bytes.
                                  ///< nfn->end_ea will have the address of the unexplored byte.
#define FIND_FUNC_OK    1         ///< ok, 'nfn' is ready for add_func()
#define FIND_FUNC_EXIST 2         ///< function exists already.
                                  ///< its bounds are returned in 'nfn'.
//@}


/// Get function name.
/// \param out      buffer for the answer
/// \param ea       any address in the function
/// \return length of the function name

idaman ssize_t ida_export get_func_name(qstring *out, ea_t ea);


/// Calculate function size.
/// This function takes into account all fragments of the function.
/// \param pfn    ptr to function structure

idaman asize_t ida_export calc_func_size(func_t *pfn);


/// Get function bitness (which is equal to the function segment bitness).
/// pfn==nullptr => returns 0
/// \retval 0  16
/// \retval 1  32
/// \retval 2  64

idaman int ida_export get_func_bitness(const func_t *pfn);

/// Get number of bits in the function addressing
inline int idaapi get_func_bits(const func_t *pfn) { return 1 << (get_func_bitness(pfn)+4); }

/// Get number of bytes in the function addressing
inline int idaapi get_func_bytes(const func_t *pfn) { return get_func_bits(pfn)/8; }


/// Is the function visible (not hidden)?

inline bool is_visible_func(func_t *pfn) { return pfn != nullptr && (pfn->flags & FUNC_HIDDEN) == 0; }

/// Is the function visible (event after considering #SCF_SHHID_FUNC)?
inline bool is_finally_visible_func(func_t *pfn)
{
  return (inf_get_cmtflg() & SCF_SHHID_FUNC) != 0 || is_visible_func(pfn);
}

/// Set visibility of function

idaman void ida_export set_visible_func(func_t *pfn, bool visible);


/// Give a meaningful name to function if it consists of only 'jump' instruction.
/// \param pfn      pointer to function (may be nullptr)
/// \param oldname  old name of function.
///                 if old name was in "j_..." form, then we may discard it
///                 and set a new name.
///                 if oldname is not known, you may pass nullptr.
/// \return success

idaman int ida_export set_func_name_if_jumpfunc(func_t *pfn, const char *oldname);


/// Calculate target of a thunk function.
/// \param pfn   pointer to function (may not be nullptr)
/// \param fptr  out: will hold address of a function pointer (if indirect jump)
/// \return the target function or #BADADDR

idaman ea_t ida_export calc_thunk_func_target(func_t *pfn, ea_t *fptr);


/// Does the function return?.
/// To calculate the answer, #FUNC_NORET flag and is_noret() are consulted
/// The latter is required for imported functions in the .idata section.
/// Since in .idata we have only function pointers but not functions, we have
/// to introduce a special flag for them.

idaman bool ida_export func_does_return(ea_t callee);


/// Plan to reanalyze noret flag.
/// This function does not remove FUNC_NORET if it is already present.
/// It just plans to reanalysis.

idaman bool ida_export reanalyze_noret_flag(ea_t ea);


/// Signal a non-returning instruction.
/// This function can be used by the processor module to tell the kernel
/// about non-returning instructions (like call exit). The kernel will
/// perform the global function analysis and find out if the function
/// returns at all. This analysis will be done at the first call to func_does_return()
/// \return true if the instruction 'noret' flag has been changed

idaman bool ida_export set_noret_insn(ea_t insn_ea, bool noret);


//--------------------------------------------------------------------
//      F U N C T I O N   C H U N K S
//--------------------------------------------------------------------
/// Get pointer to function chunk structure by address.
/// \param ea  any address in a function chunk
/// \return ptr to a function chunk or nullptr.
///         This function may return a function entry as well as a function tail.

idaman func_t *ida_export get_fchunk(ea_t ea);


/// Get pointer to function chunk structure by number.
/// \param n  number of function chunk, is in range 0..get_fchunk_qty()-1
/// \return ptr to a function chunk or nullptr.
///         This function may return a function entry as well as a function tail.

idaman func_t *ida_export getn_fchunk(int n);


/// Get total number of function chunks in the program

idaman size_t ida_export get_fchunk_qty(void);


/// Get ordinal number of a function chunk in the global list of function chunks.
/// \param ea  any address in the function chunk
/// \return number of function chunk (0..get_fchunk_qty()-1).
///         -1 means 'no function chunk at the specified address'.

idaman int ida_export get_fchunk_num(ea_t ea);


/// Get pointer to the previous function chunk in the global list.
/// \param ea  any address in the program
/// \return ptr to function chunk or nullptr if previous function chunk doesn't exist

idaman func_t *ida_export get_prev_fchunk(ea_t ea);


/// Get pointer to the next function chunk in the global list.
/// \param ea  any address in the program
/// \return ptr to function chunk or nullptr if next function chunk doesn't exist

idaman func_t *ida_export get_next_fchunk(ea_t ea);


//--------------------------------------------------------------------
// Functions to manipulate function chunks

/// Append a new tail chunk to the function definition.
/// If the tail already exists, then it will simply be added to the function tail list
/// Otherwise a new tail will be created and its owner will be set to be our function
/// If a new tail cannot be created, then this function will fail.
/// \param pfn  pointer to the function
/// \param ea1  start of the tail. If a tail already exists at the specified address
///             it must start at 'ea1'
/// \param ea2  end of the tail. If a tail already exists at the specified address
///             it must end at 'ea2'. If specified as BADADDR, IDA will determine
///             the end address itself.

idaman bool ida_export append_func_tail(func_t *pfn, ea_t ea1, ea_t ea2);


/// Remove a function tail.
/// If the tail belongs only to one function, it will be completely removed.
/// Otherwise if the function was the tail owner, the first function using
/// this tail becomes the owner of the tail.
/// \param pfn  pointer to the function
/// \param tail_ea any address inside the tail to remove

idaman bool ida_export remove_func_tail(func_t *pfn, ea_t tail_ea);


/// Set a new owner of a function tail.
/// The new owner function must be already referring to the tail (after append_func_tail).
/// \param fnt  pointer to the function tail
/// \param new_owner the entry point of the new owner function

idaman bool ida_export set_tail_owner(func_t *fnt, ea_t new_owner);


// Auxiliary function(s) to be used in func_..._iterator_t

class func_parent_iterator_t;
class func_tail_iterator_t;
class func_item_iterator_t;

/// Declare helper functions for ::func_item_iterator_t
#define DECLARE_FUNC_ITERATORS(prefix) \
prefix bool ida_export func_tail_iterator_set(func_tail_iterator_t *fti, func_t *pfn, ea_t ea);\
prefix bool ida_export func_tail_iterator_set_ea(func_tail_iterator_t *fti, ea_t ea);\
prefix bool ida_export func_parent_iterator_set(func_parent_iterator_t *fpi, func_t *pfn);\
prefix bool ida_export func_item_iterator_next(func_item_iterator_t *fii, testf_t *testf, void *ud);\
prefix bool ida_export func_item_iterator_prev(func_item_iterator_t *fii, testf_t *testf, void *ud);\
prefix bool ida_export func_item_iterator_decode_prev_insn(func_item_iterator_t *fii, insn_t *out); \
prefix bool ida_export func_item_iterator_decode_preceding_insn(func_item_iterator_t *fii, eavec_t *visited, bool *p_farref, insn_t *out); \
prefix bool ida_export func_item_iterator_succ(func_item_iterator_t *fii, testf_t *testf, void *ud);
DECLARE_FUNC_ITERATORS(idaman)

/// Helper function to accept any address
inline THREAD_SAFE bool idaapi f_any(flags64_t, void *) { return true; }

/// Class to enumerate all function tails sorted by addresses.
/// Enumeration is started with main(), first(), or last().
/// If first() is used, the function entry chunk will be excluded from the enumeration.
/// Otherwise it will be included in the enumeration (for main() and last()).
/// The loop may continue until the next() or prev() function returns false.
/// These functions return false when the enumeration is over.
/// The tail chunks are always sorted by their addresses.
///
/// Sample code:
/// \code
///      func_tail_iterator_t fti(pfn);
///      for ( bool ok=fti.first(); ok; ok=fti.next() )
///        const range_t &a = fti.chunk();
///        ....
/// \endcode
///
/// If the 'ea' parameter is used in the constructor, then the iterator is positioned
/// at the chunk containing the specified 'ea'. Otherwise it is positioned at the
/// function entry chunk.
/// If 'pfn' is specified as nullptr then the set() function will fail,
/// but it is still possible to use the class. In this case the iteration will be
/// limited by the segment boundaries.
/// The function main chunk is locked during the iteration.
/// It is also possible to enumerate one single arbitrary range using set_range()
/// This function is mainly designed to be used from ::func_item_iterator_t.
class func_tail_iterator_t
{
  func_t *pfn;
  int idx;
  range_t seglim;        // valid and used only if pfn == nullptr
public:
  func_tail_iterator_t(void) : pfn(nullptr), idx(-1) {}
  func_tail_iterator_t(func_t *_pfn, ea_t ea=BADADDR) : pfn(nullptr) { set(_pfn, ea); }
  ~func_tail_iterator_t(void)
  {
    // if was iterating over function chunks, unlock the main chunk
    if ( pfn != nullptr )
      lock_func_range(pfn, false);
  }
  bool set(func_t *_pfn, ea_t ea=BADADDR) { return func_tail_iterator_set(this, _pfn, ea); }
  bool set_ea(ea_t ea) { return func_tail_iterator_set_ea(this, ea); }
  // set an arbitrary range
  bool set_range(ea_t ea1, ea_t ea2)
  {
    this->~func_tail_iterator_t();
    pfn = nullptr;
    idx = -1;
    seglim = range_t(ea1, ea2);
    return !seglim.empty();
  }
  const range_t &chunk(void) const
  {
    if ( pfn == nullptr )
      return seglim;
    return idx >= 0 && idx < pfn->tailqty ? pfn->tails[idx] : *(range_t*)pfn;
  }
  bool first(void) { if ( pfn != nullptr ) { idx = 0; return pfn->tailqty > 0; } return false; } // get only tail chunks
  bool last(void) { if ( pfn != nullptr ) { idx = pfn->tailqty - 1; return true; } return false; }  // get all chunks (the entry chunk last)
  bool next(void) { if ( pfn != nullptr && idx+1 < pfn->tailqty ) { idx++; return true; } return false; }
  bool prev(void) { if ( idx >= 0 ) { idx--; return true; } return false; }
  bool main(void) { idx = -1; return pfn != nullptr; }  // get all chunks (the entry chunk first)
};


/// Function to iterate function chunks (all of them including the entry chunk)
/// \param pfn              pointer to the function
/// \param func             function to call for each chunk
/// \param ud               user data for 'func'
/// \param include_parents  meaningful only if pfn points to a function tail.
///                         if true, all tail parents will be iterated.
///                         if false, only the given tail will be iterated.

idaman void ida_export iterate_func_chunks(
        func_t *pfn,
        void (idaapi *func)(ea_t ea1, ea_t ea2, void *ud),
        void *ud=nullptr,
        bool include_parents=false);


/// Class to enumerate all function instructions and data sorted by addresses.
/// The function entry chunk items are enumerated first regardless of their addresses
///
/// Sample code:
/// \code
///      func_item_iterator_t fii;
///      for ( bool ok=fii.set(pfn, ea); ok; ok=fii.next_addr() )
///        ea_t ea = fii.current();
///        ....
/// \endcode
///
/// If 'ea' is not specified in the call to set(), then the enumeration starts at
/// the function entry point.
/// If 'pfn' is specified as nullptr then the set() function will fail,
/// but it is still possible to use the class. In this case the iteration will be
/// limited by the segment boundaries.
/// It is also possible to enumerate addresses in an arbitrary range using set_range().
class func_item_iterator_t
{
  func_tail_iterator_t fti;
  ea_t ea;
public:
  func_item_iterator_t(void) : ea(BADADDR) {}
  func_item_iterator_t(func_t *pfn, ea_t _ea=BADADDR) { set(pfn, _ea); }
  /// Set a function range. if pfn == nullptr then a segment range will be set.
  bool set(func_t *pfn, ea_t _ea=BADADDR)
  {
    ea = (_ea != BADADDR || pfn == nullptr) ? _ea : pfn->start_ea;
    return fti.set(pfn, _ea);
  }
  /// Set an arbitrary range
  bool set_range(ea_t ea1, ea_t ea2) { ea = ea1; return fti.set_range(ea1, ea2); }
  bool first(void) { if ( !fti.main() ) return false; ea=fti.chunk().start_ea; return true; }
  bool last(void) { if ( !fti.last() ) return false; ea=fti.chunk().end_ea; return true; }
  ea_t current(void) const { return ea; }
  const range_t &chunk(void) const { return fti.chunk(); }
  bool next(testf_t *func, void *ud) { return func_item_iterator_next(this, func, ud); }
  bool prev(testf_t *func, void *ud) { return func_item_iterator_prev(this, func, ud); }
  bool next_addr(void) { return next(f_any, nullptr); }
  bool next_head(void) { return next(f_is_head, nullptr); }
  bool next_code(void) { return next(f_is_code, nullptr); }
  bool next_data(void) { return next(f_is_data, nullptr); }
  bool next_not_tail(void) { return next(f_is_not_tail, nullptr); }
  bool prev_addr(void) { return prev(f_any, nullptr); }
  bool prev_head(void) { return prev(f_is_head, nullptr); }
  bool prev_code(void) { return prev(f_is_code, nullptr); }
  bool prev_data(void) { return prev(f_is_data, nullptr); }
  bool prev_not_tail(void) { return prev(f_is_not_tail, nullptr); }
  bool decode_prev_insn(insn_t *out) { return func_item_iterator_decode_prev_insn(this, out); }
  bool decode_preceding_insn(eavec_t *visited, bool *p_farref, insn_t *out)
    { return func_item_iterator_decode_preceding_insn(this, visited, p_farref, out); }
  /// Similar to next(), but succ() iterates the chunks from low to high
  /// addresses, while next() iterates through chunks starting at the
  /// function entry chunk
  bool succ(testf_t *func, void *ud) { return func_item_iterator_succ(this, func, ud); }
  bool succ_code(void) { return succ(f_is_code, nullptr); }
};

/// Class to enumerate all function parents sorted by addresses.
/// Enumeration is started with first() or last().
/// The loop may continue until the next() or prev() function returns false.
/// The parent functions are always sorted by their addresses.
/// The tail chunk is locked during the iteration.
///
/// Sample code:
/// \code
///      func_parent_iterator_t fpi(fnt);
///      for ( bool ok=fpi.first(); ok; ok=fpi.next() )
///        ea_t parent = fpi.parent();
///        ....
/// \endcode
class func_parent_iterator_t
{
  func_t *fnt;
  int idx;
public:
  func_parent_iterator_t(void) : fnt(nullptr), idx(0) {}
  func_parent_iterator_t(func_t *_fnt) : fnt(nullptr) { set(_fnt); }
  ~func_parent_iterator_t(void)
  {
    if ( fnt != nullptr )
      lock_func_range(fnt, false);
  }
  bool set(func_t *_fnt) { return func_parent_iterator_set(this, _fnt); }
  ea_t parent(void) const { return fnt->referers[idx]; }
  bool first(void) { idx = 0; return is_func_tail(fnt) && fnt->refqty > 0; }
  bool last(void) { idx = fnt->refqty - 1; return idx >= 0; }
  bool next(void) { if ( idx+1 < fnt->refqty ) { idx++; return true; } return false; }
  bool prev(void) { if ( idx > 0 ) { idx--; return true; } return false; }
  void reset_fnt(func_t *_fnt) { fnt = _fnt; } // for internal use only!
};


/// \name Get prev/next address in function
/// Unlike func_item_iterator_t which always enumerates the main function
/// chunk first, these functions respect linear address ordering.
//@{
idaman ea_t ida_export get_prev_func_addr(func_t *pfn, ea_t ea);
idaman ea_t ida_export get_next_func_addr(func_t *pfn, ea_t ea);
//@}

//--------------------------------------------------------------------
/// \name
/// Functions to work with temporary register argument definitions
//@{
idaman void ida_export read_regargs(func_t *pfn);
idaman void ida_export add_regarg(func_t *pfn, int reg, const tinfo_t &tif, const char *name);
//@}

//--------------------------------------------------------------------
//      L I B R A R Y   M O D U L E   S I G N A T U R E S
//--------------------------------------------------------------------

/// \defgroup IDASGN_ Error codes for signature functions:
/// See calc_idasgn_state() and del_idasgn()
//@{
#define IDASGN_OK       0       ///< ok
#define IDASGN_BADARG   1       ///< bad number of signature
#define IDASGN_APPLIED  2       ///< signature is already applied
#define IDASGN_CURRENT  3       ///< signature is currently being applied
#define IDASGN_PLANNED  4       ///< signature is planned to be applied
//@}

/// Add a signature file to the list of planned signature files.
/// \param fname  file name. should not contain directory part.
/// \return 0 if failed, otherwise number of planned (and applied) signatures

idaman int ida_export plan_to_apply_idasgn(const char *fname); // plan to use library


/// Apply a signature file to the specified address.
/// \param signame     short name of signature file (the file name without path)
/// \param ea          address to apply the signature
/// \param is_startup  if set, then the signature is treated as a startup one
///                    for startup signature ida doesn't rename the first
///                    function of the applied module.
/// \return \ref LIBFUNC_

idaman int ida_export apply_idasgn_to(const char *signame, ea_t ea, bool is_startup);


/// Get number of signatures in the list of planned and applied signatures.
/// \return 0..n

idaman int ida_export get_idasgn_qty(void);


/// Get number of the the current signature.
/// \return 0..n-1

idaman int ida_export get_current_idasgn(void);


/// Get state of a signature in the list of planned signatures
/// \param n  number of signature in the list (0..get_idasgn_qty()-1)
/// \return state of signature or #IDASGN_BADARG

idaman int ida_export calc_idasgn_state(int n);


/// Remove signature from the list of planned signatures.
/// \param n  number of signature in the list (0..get_idasgn_qty()-1)
/// \return #IDASGN_OK, #IDASGN_BADARG, #IDASGN_APPLIED

idaman int ida_export del_idasgn(int n);


/// Get information about a signature in the list.
/// \param signame      buffer for the name of the signature.
///                     (short form, only base name without the directory part
///                      will be stored).
///                     if signame == nullptr, then the name won't be returned.
/// \param optlibs      buffer for the names of the optional libraries
///                     if optlibs == nullptr, then the optional libraries are not returned
/// \param n            number of signature in the list (0..get_idasgn_qty()-1)
/// \return number of successfully recognized modules using this signature.
///          -1 means the 'n' is a bad argument, i.e. no signature with this
///              number exists..

idaman int32 ida_export get_idasgn_desc(
        qstring *signame,
        qstring *optlibs,
        int n);


class idasgn_t;

/// Get idasgn header by a short signature name.
/// \param name  short name of a signature
/// \return nullptr if can't find the signature

idaman idasgn_t *ida_export get_idasgn_header_by_short_name(const char *name);


/// Get full description of the signature by its short name.
/// \param buf      the output buffer
/// \param name     short name of a signature
/// \return size of signature description or -1

idaman ssize_t ida_export get_idasgn_title(
        qstring *buf,
        const char *name);

/// Determine compiler/vendor using the startup signatures.
/// If determined, then appropriate signature files are included into
/// the list of planned signature files.

idaman void ida_export determine_rtl(void);


/// Apply a startup signature file to the specified address.
/// \param ea       address to apply the signature to; usually \inf{start_ea}
/// \param startup  the name of the signature file without path and extension
/// \return true if successfully applied the signature

idaman bool ida_export apply_startup_sig(ea_t ea, const char *startup);


/// Apply the currently loaded signature file to the specified address.
/// If a library function is found, then create a function and name
/// it accordingly.
/// \param ea  any address in the program
/// \returns \ref LIBFUNC_

idaman int ida_export try_to_add_libfunc(ea_t ea);


/// \defgroup LIBFUNC_ Library function codes
/// Return values for try_to_add_libfunc() and apply_idasgn_to()
//@{
#define LIBFUNC_FOUND   0               ///< ok, library function is found
#define LIBFUNC_NONE    1               ///< no, this is not a library function
#define LIBFUNC_DELAY   2               ///< no decision because of lack of information
//@}

// KERNEL mode functions

/// \cond
/// kept in the sdk because inlined
inline void save_signatures(void) {}
bool invalidate_sp_analysis(func_t *pfn);
inline bool invalidate_sp_analysis(ea_t ea)
  { return invalidate_sp_analysis(get_func(ea)); }
/// \endcond


#endif
