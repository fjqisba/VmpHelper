/*!
 *      Hex-Rays Decompiler project
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 * \mainpage
 *      There are 2 representations of the binary code in the decompiler:
 *        - microcode: processor instructions are translated into it and then
 *                     the decompiler optimizes and transforms it
 *        - ctree:     ctree is built from the optimized microcode and represents
 *                     AST-like tree with C statements and expressions. It can
 *                     be printed as C code.
 *
 *      Microcode is represented by the following classes:
 *       - mba_t keeps general info about the decompiled code and
 *                     array of basic blocks. usually mba_t is named 'mba'
 *       - mblock_t    a basic block. includes list of instructions
 *       - minsn_t     an instruction. contains 3 operands: left, right, and
 *                     destination
 *       - mop_t       an operand. depending on its type may hold various info
 *                     like a number, register, stack variable, etc.
 *       - mlist_t     list of memory or register locations; can hold vast areas
 *                     of memory and multiple registers. this class is used
 *                     very extensively in the decompiler. it may represent
 *                     list of locations accessed by an instruction or even
 *                     an entire basic block. it is also used as argument of
 *                     many functions. for example, there is a function
 *                     that searches for an instruction that refers to a mlist_t.

 *      See https://www.hex-rays.com/blog/microcode-in-pictures for some pictures.
 *
 *      Ctree is represented by:
 *       - cfunc_t     keeps general info about the decompiled code, including a
 *                     pointer to mba_t. deleting cfunc_t will delete
 *                     mba_t too (however, decompiler returns cfuncptr_t,
 *                     which is a reference counting object and deletes the
 *                     underlying function as soon as all references to it go
 *                     out of scope). cfunc_t has 'body', which represents the
 *                     decompiled function body as cinsn_t.
 *       - cinsn_t     a C statement. can be a compound statement or any other
 *                     legal C statements (like if, for, while, return,
 *                     expression-statement, etc). depending on the statement
 *                     type has pointers to additional info. for example, the
 *                     'if' statement has poiner to cif_t, which holds the
 *                     'if' condition, 'then' branch, and optionally 'else'
 *                     branch. Please note that despite of the name cinsn_t
 *                     we say "statements", not "instructions". For us
 *                     instructions are part of microcode, not ctree.
 *       - cexpr_t     a C expression. is used as part of a C statement, when
 *                     necessary. cexpr_t has 'type' field, which keeps the
 *                     expression type.
 *       - citem_t     a base class for cinsn_t and cexpr_t, holds common info
 *                     like the address, label, and opcode.
 *       - cnumber_t   a constant 64-bit number. in addition to its value also
 *                     holds information how to represent it: decimal, hex, or
 *                     as a symbolic constant (enum member). please note that
 *                     numbers are represented by another class (mnumber_t)
 *                     in microcode.

 *      See https://www.hex-rays.com/blog/hex-rays-decompiler-primer
 *      for some pictures and more details.
 *
 *      Both microcode and ctree use the following class:
 *       - lvar_t      a local variable. may represent a stack or register
 *                     variable. a variable has a name, type, location, etc.
 *                     the list of variables is stored in mba->vars.
 *       - lvar_locator_t holds a variable location (vdloc_t) and its definition
 *                     address.
 *       - vdloc_t     describes a variable location, like a register number,
 *                     a stack offset, or, in complex cases, can be a mix of
 *                     register and stack locations. very similar to argloc_t,
 *                     which is used in ida. the differences between argloc_t
 *                     and vdloc_t are:
 *                       - vdloc_t never uses ARGLOC_REG2
 *                       - vdloc_t uses micro register numbers instead of
 *                         processor register numbers
 *                       - the stack offsets are never negative in vdloc_t, while
 *                         in argloc_t there can be negative offsets
 *
 *      The above are the most important classes in this header file. There are
 *      many auxiliary classes, please see their definitions in the header file.
 *
 *      See also the description of \ref vmpage.
 *
 */

#ifndef __HEXRAYS_HPP
#define __HEXRAYS_HPP

#include <pro.h>
#include <fpro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <gdl.hpp>
#include <ieee.h>
#include <loader.hpp>
#include <kernwin.hpp>
#include <typeinf.hpp>
#include <deque>
#include <queue>

/*!
 * \page vmpage Virtual Machine used by Microcode
 *      We can imagine a virtual micro machine that executes microcode.
 *      This virtual micro machine has many registers.
 *      Each register is 8 bits wide. During translation of processor
 *      instructions into microcode, multibyte processor registers are mapped
 *      to adjacent microregisters. Processor condition codes are also
 *      represented by microregisters. The microregisters are grouped
 *      into following groups:
 *       - 0..7: condition codes
 *       - 8..n: all processor registers (including fpu registers, if necessary)
 *               this range may also include temporary registers used during
 *               the initial microcode generation
 *       - n.. : so called kernel registers; they are used during optimization
 *               see is_kreg()
 *
 *      Each micro-instruction (minsn_t) has zero to three operands.
 *      Some of the possible operands types are:
 *        - immediate value
 *        - register
 *        - memory reference
 *        - result of another micro-instruction
 *
 *      The operands (mop_t) are l (left), r (right), d (destination).
 *      An example of a microinstruction:
 *
 *              add r0.4, #8.4, r2.4
 *
 *      which means 'add constant 8 to r0 and place the result into r2'.
 *      where
 *       - the left operand is 'r0', its size is 4 bytes (r0.4)
 *       - the right operand is a constant '8', its size is 4 bytes (#8.4)
 *       - the destination operand is 'r2', its size is 4 bytes (r2.4)
 *      Note that 'd' is almost always the destination but there are exceptions.
 *      See mcode_modifies_d(). For example, stx does not modify 'd'.
 *      See the opcode map below for the list of microinstructions and their
 *      operands. Most instructions are very simple and do not need
 *      detailed explanations. There are no side effects in microinstructions.
 *
 *      Each operand has a size specifier. The following sizes can be used in
 *      practically all contexts: 1, 2, 4, 8, 16 bytes. Floating types may have
 *      other sizes. Functions may return objects of arbitrary size, as well as
 *      operations upon UDT's (user-defined types, i.e. are structs and unions).
 *
 *      Memory is considered to consist of several segments.
 *      A memory reference is made using a (selector, offset) pair.
 *      A selector is always 2 bytes long. An offset can be 4 or 8 bytes long,
 *      depending on the bitness of the target processor.
 *      Currently the selectors are not used very much. The decompiler tries to
 *      resolve (selector, offset) pairs into direct memory references at each
 *      opportunity and then operates on mop_v operands. In other words,
 *      while the decompiler can handle segmented memory models, internally
 *      it still uses simple linear addresses.
 *
 *      The following memory regions are recognized:
 *        - GLBLOW   global memory: low part, everything below the stack
 *        - LVARS    stack: local variables
 *        - RETADDR  stack: return address
 *        - SHADOW   stack: shadow arguments
 *        - ARGS     stack: regular stack arguments
 *        - GLBHIGH  global memory: high part, everything above the stack
 *      Any stack region may be empty. Objects residing in one memory region
 *      are considered to be completely distinct from objects in other regions.
 *      We allocate the stack frame in some memory region, which is not
 *      allocated for any purposes in IDA. This permits us to use linear addresses
 *      for all memory references, including the stack frame.
 *
 *      If the operand size is bigger than 1 then the register
 *      operand references a block of registers. For example:
 *
 *              ldc   #1.4, r8.4
 *
 *      loads the constant 1 to registers 8, 9, 10, 11:
 *
 *               #1  ->  r8
 *               #0  ->  r9
 *               #0  ->  r10
 *               #0  ->  r11
 *
 *      This example uses little-endian byte ordering.
 *      Big-endian byte ordering is supported too. Registers are always little-
 *      endian, regardless of the memory endianness.
 *
 *      Each instruction has 'next' and 'prev' fields that are used to form
 *      a doubly linked list. Such lists are present for each basic block (mblock_t).
 *      Basic blocks have other attributes, including:
 *        - dead_at_start: list of dead locations at the block start
 *        - maybuse:  list of locations the block may use
 *        - maybdef:  list of locations the block may define (or spoil)
 *        - mustbuse: list of locations the block will certainly use
 *        - mustbdef: list of locations the block will certainly define
 *        - dnu:      list of locations the block will certainly define
 *                    but will not use (registers or non-aliasable stkack vars)
 *
 *      These lists are represented by the mlist_t class. It consists of 2 parts:
 *        - rlist_t: list of microregisters (possibly including virtual stack locations)
 *        - ivlset_t: list of memory locations represented as intervals
 *                    we use linear addresses in this list.
 *      The mlist_t class is used quite often. For example, to find what an operand
 *      can spoil, we build its 'maybe-use' list. Then we can find out if this list
 *      is accessed using the is_accessed() or is_accessed_globally() functions.
 *
 *      All basic blocks of the decompiled function constitute an array called
 *      mba_t (array of microblocks). This is a huge class that has too
 *      many fields to describe here (some of the fields are not visible in the sdk)
 *      The most importants ones are:
 *        - stack frame: frregs, stacksize, etc
 *        - memory: aliased, restricted, and other ranges
 *        - type: type of the current function, its arguments (argidx) and
 *                local variables (vars)
 *        - natural: array of pointers to basic blocks. the basic blocks
 *                   are also accessible as a doubly linked list starting from 'blocks'.
 *        - bg: control flow graph. the graph gives access to the use-def
 *                   chains that describe data dependencies between basic blocks
 *
 *   Facilities for debugging decompiler plugins:
 *      Many decompiler objects have a member function named dstr().
 *      These functions create a text representation of the object and return
 *      a pointer to it. They are very convenient to use in a debugger instead of
 *      inspecting class fields manually. The mba_t object does not have the
 *      dstr() function because its text representation very long. Instead, we
 *      provide the mba_t::dump_mba() and mba_t::dump() functions.
 *
 *      To ensure that your plugin manipulates the microcode in a correct way,
 *      please call mba_t::verify() before returning control to the decompiler.
 *
 */

#ifdef __NT__
#pragma warning(push)
#pragma warning(disable:4062) // enumerator 'x' in switch of enum 'y' is not handled
#pragma warning(disable:4265) // virtual functions without virtual destructor
#endif

#define hexapi                ///< Public functions are marked with this keyword

// Warning suppressions for PVS Studio:
//-V:2:654 The condition '2' of loop is always true.
//-V::719  The switch statement does not cover all values
//-V:verify:678
//-V:chain_keeper_t:690 copy ctr will be generated
//-V:add_block:656 call to the same function
//-V:add:792 The 'add' function located to the right of the operator '|' will be called regardless of the value of the left operand
//-V:sub:792 The 'sub' function located to the right of the operator '|' will be called regardless of the value of the left operand
//-V:intersect:792 The 'intersect' function located to the right of the operator '|' will be called regardless of the value of the left operand
// Lint suppressions:
//lint -sem(mop_t::_make_cases, custodial(1))
//lint -sem(mop_t::_make_pair, custodial(1))
//lint -sem(mop_t::_make_callinfo, custodial(1))
//lint -sem(mop_t::_make_insn, custodial(1))
//lint -sem(mop_t::make_insn, custodial(1))

// Microcode level forward definitions:
class mop_t;            // microinstruction operand
class mop_pair_t;       // pair of operands.      example, :(edx.4,eax.4).8
class mop_addr_t;       // address of an operand. example: &global_var
class mcallinfo_t;      // function call info.    example: <cdecl:"int x" #10.4>.8
class mcases_t;         // jump table cases.      example: {0 => 12, 1 => 13}
class minsn_t;          // microinstruction
class mblock_t;         // basic block
class mba_t;            // array of blocks, represents microcode for a function
class codegen_t;        // helper class to generate the initial microcode
class mbl_graph_t;      // control graph of microcode
struct vdui_t;          // widget representing the pseudocode window
struct hexrays_failure_t; // decompilation failure object, is thrown by exceptions
struct mba_stats_t;     // statistics about decompilation of a function
struct mlist_t;         // list of memory and register locations
struct voff_t;          // value offset (microregister number or stack offset)
typedef std::set<voff_t> voff_set_t;
struct vivl_t;          // value interval (register or stack range)
typedef int mreg_t;     ///< Micro register

// Ctree level forward definitions:
struct cfunc_t;         // result of decompilation, the highest level object
struct citem_t;         // base class for cexpr_t and cinsn_t
struct cexpr_t;         // C expression
struct cinsn_t;         // C statement
struct cblock_t;        // C statement block (sequence of statements)
struct cswitch_t;       // C switch statement
struct carg_t;          // call argument
struct carglist_t;      // vector of call arguments

typedef std::set<ea_t> easet_t;
typedef std::set<minsn_t *> minsn_ptr_set_t;
typedef std::set<qstring> strings_t;
typedef qvector<minsn_t*> minsnptrs_t;
typedef qvector<mop_t*> mopptrs_t;
typedef qvector<mop_t> mopvec_t;
typedef qvector<uint64> uint64vec_t;
typedef qvector<mreg_t> mregvec_t;
typedef qrefcnt_t<cfunc_t> cfuncptr_t;

// Function frames must be smaller than this value, otherwise
// the decompiler will bail out with MERR_HUGESTACK
#define MAX_SUPPORTED_STACK_SIZE 0x100000 // 1MB

//-------------------------------------------------------------------------
// Original version of macro DEFINE_MEMORY_ALLOCATION_FUNCS
// (uses decompiler-specific memory allocation functions)
#define HEXRAYS_PLACEMENT_DELETE void operator delete(void *, void *) {}
#define HEXRAYS_MEMORY_ALLOCATION_FUNCS()                          \
  void *operator new  (size_t _s) { return hexrays_alloc(_s); }    \
  void *operator new[](size_t _s) { return hexrays_alloc(_s); }    \
  void *operator new(size_t /*size*/, void *_v) { return _v; }     \
  void operator delete  (void *_blk) { hexrays_free(_blk); }       \
  void operator delete[](void *_blk) { hexrays_free(_blk); }       \
  HEXRAYS_PLACEMENT_DELETE

void *hexapi hexrays_alloc(size_t size);
void hexapi  hexrays_free(void *ptr);

typedef uint64 uvlr_t;
typedef int64 svlr_t;
enum { MAX_VLR_SIZE = sizeof(uvlr_t) };
const uvlr_t MAX_VALUE = uvlr_t(-1);
const svlr_t MAX_SVALUE = svlr_t(uvlr_t(-1) >> 1);
const svlr_t MIN_SVALUE = ~MAX_SVALUE;

enum cmpop_t
{ // the order of comparisons is the same as in microcode opcodes
  CMP_NZ,
  CMP_Z,
  CMP_AE,
  CMP_B,
  CMP_A,
  CMP_BE,
  CMP_GT,
  CMP_GE,
  CMP_LT,
  CMP_LE,
};

//-------------------------------------------------------------------------
// value-range class to keep possible operand value(s).
class valrng_t
{
protected:
  int flags;
#define VLR_TYPE 0x0F     // valrng_t type
#define   VLR_NONE   0x00 //   no values
#define   VLR_ALL    0x01 //   all values
#define   VLR_IVLS   0x02 //   union of disjoint intervals
#define   VLR_RANGE  0x03 //   strided range
#define   VLR_SRANGE 0x04 //   strided range with signed bound
#define   VLR_BITS   0x05 //   known bits
#define   VLR_SECT   0x06 //   intersection of sub-ranges
                          //   each sub-range should be simple or union
#define   VLR_UNION  0x07 //   union of sub-ranges
                          //   each sub-range should be simple or
                          //   intersection
#define   VLR_UNK    0x08 //   unknown value (like 'null' in SQL)
  int size;               // operand size: 1..8 bytes
                          // all values must fall within the size
  union
  {
    struct                // VLR_RANGE/VLR_SRANGE
    {                     // values that are between VALUE and LIMIT
                          // and conform to: value+stride*N
      uvlr_t value;       // initial value
      uvlr_t limit;       // final value
                          // we adjust LIMIT to be on the STRIDE lattice
      svlr_t stride;      // stride between values
    };
    struct                // VLR_BITS
    {
      uvlr_t zeroes;      // bits known to be clear
      uvlr_t ones;        // bits known to be set
    };
    char reserved[sizeof(qvector<int>)];
                          // VLR_IVLS/VLR_SECT/VLR_UNION
  };
  void hexapi clear(void);
  void hexapi copy(const valrng_t &r);
  valrng_t &hexapi assign(const valrng_t &r);

public:
  explicit valrng_t(int size_ = MAX_VLR_SIZE)
    : flags(VLR_NONE), size(size_), value(0), limit(0), stride(0) {}
  valrng_t(const valrng_t &r) { copy(r); }
  ~valrng_t(void) { clear(); }
  valrng_t &operator=(const valrng_t &r) { return assign(r); }
  void swap(valrng_t &r) { qswap(*this, r); }
  DECLARE_COMPARISONS(valrng_t);
  DEFINE_MEMORY_ALLOCATION_FUNCS()

  void set_none(void) { clear(); }
  void set_all(void) { clear(); flags = VLR_ALL; }
  void set_unk(void) { clear(); flags = VLR_UNK; }
  void hexapi set_eq(uvlr_t v);
  void hexapi set_cmp(cmpop_t cmp, uvlr_t _value);

  // reduce size
  // it takes the low part of size NEW_SIZE
  // it returns "true" if size is changed successfully.
  // e.g.: valrng_t vr(2); vr.set_eq(0x1234);
  //       vr.reduce_size(1);
  //       uvlr_t v; vr.cvt_to_single_value(&v);
  //       assert(v == 0x34);
  bool hexapi reduce_size(int new_size);

  // Perform intersection or union or inversion.
  // \return did we change something in THIS?
  bool hexapi intersect_with(const valrng_t &r);
  bool hexapi unite_with(const valrng_t &r);
  void hexapi inverse(); // works for VLR_IVLS only

  bool empty(void) const { return flags == VLR_NONE; }
  bool all_values(void) const { return flags == VLR_ALL; }
  bool is_unknown(void) const { return flags == VLR_UNK; }
  bool hexapi has(uvlr_t v) const;

  void hexapi print(qstring *vout) const;
  const char *hexapi dstr(void) const;

  bool hexapi cvt_to_single_value(uvlr_t *v) const;
  bool hexapi cvt_to_cmp(cmpop_t *cmp, uvlr_t *val, bool strict) const;

  int get_size() const { return size; }
  static uvlr_t max_value(int size_)
  {
    return size_ == MAX_VLR_SIZE
         ? MAX_VALUE
         : (uvlr_t(1) << (size_ * 8)) - 1;
  }
  static uvlr_t min_svalue(int size_)
  {
    return size_ == MAX_VLR_SIZE
         ? MIN_SVALUE
         : (uvlr_t(1) << (size_ * 8 - 1));
  }
  static uvlr_t max_svalue(int size_)
  {
    return size_ == MAX_VLR_SIZE
         ? MAX_SVALUE
         : (uvlr_t(1) << (size_ * 8 - 1)) - 1;
  }
  uvlr_t max_value()  const { return max_value(size);  }
  uvlr_t min_svalue() const { return min_svalue(size); }
  uvlr_t max_svalue() const { return max_svalue(size); }
};
DECLARE_TYPE_AS_MOVABLE(valrng_t);

//-------------------------------------------------------------------------
// Are we looking for 'must access' or 'may access' information?
// 'must access' means that the code will always access the specified location(s)
// 'may access' means that the code may in some cases access the specified location(s)
// Example:     ldx cs.2, r0.4, r1.4
//      MUST_ACCESS: r0.4 and r1.4, usually displayed as r0.8 because r0 and r1 are adjacent
//      MAY_ACCESS: r0.4 and r1.4, and all aliasable memory, because
//                  ldx may access any part of the aliasable memory
typedef int maymust_t;
const maymust_t
  // One of the following two bits should be specified:
  MUST_ACCESS = 0x00, // access information we can count on
  MAY_ACCESS  = 0x01, // access information we should take into account
  // Optionally combined with the following bits:
  MAYMUST_ACCESS_MASK = 0x01,

  ONE_ACCESS_TYPE = 0x20,      // for find_first_use():
                               // use only the specified maymust access type
                               // (by default it inverts the access type for def-lists)
  INCLUDE_SPOILED_REGS = 0x40, // for build_def_list() with MUST_ACCESS:
                               // include spoiled registers in the list
  EXCLUDE_PASS_REGS = 0x80,    // for build_def_list() with MAY_ACCESS:
                               // exclude pass_regs from the list
  FULL_XDSU = 0x100,           // for build_def_list():
                               // if xds/xdu source and targets are the same
                               // treat it as if xdsu redefines the entire destination
  WITH_ASSERTS = 0x200,        // for find_first_use():
                               // do not ignore assertions
  EXCLUDE_VOLATILE = 0x400,    // for build_def_list():
                               // exclude volatile memory from the list
  INCLUDE_UNUSED_SRC = 0x800,  // for build_use_list():
                               // do not exclude unused source bytes for m_and/m_or insns
  INCLUDE_DEAD_RETREGS = 0x1000, // for build_def_list():
                               // include dead returned registers in the list
  INCLUDE_RESTRICTED = 0x2000,// for MAY_ACCESS: include restricted memory
  CALL_SPOILS_ONLY_ARGS = 0x4000;// for build_def_list() & MAY_ACCESS:
                               // do not include global memory into the
                               // spoiled list of a call

inline THREAD_SAFE bool is_may_access(maymust_t maymust)
{
  return (maymust & MAYMUST_ACCESS_MASK) != MUST_ACCESS;
}

//-------------------------------------------------------------------------
/// \defgroup MERR_ Microcode error codes
//@{
enum merror_t
{
  MERR_OK        = 0,   ///< ok
  MERR_BLOCK     = 1,   ///< no error, switch to new block
  MERR_INTERR    = -1,  ///< internal error
  MERR_INSN      = -2,  ///< cannot convert to microcode
  MERR_MEM       = -3,  ///< not enough memory
  MERR_BADBLK    = -4,  ///< bad block found
  MERR_BADSP     = -5,  ///< positive sp value has been found
  MERR_PROLOG    = -6,  ///< prolog analysis failed
  MERR_SWITCH    = -7,  ///< wrong switch idiom
  MERR_EXCEPTION = -8,  ///< exception analysis failed
  MERR_HUGESTACK = -9,  ///< stack frame is too big
  MERR_LVARS     = -10, ///< local variable allocation failed
  MERR_BITNESS   = -11, ///< 16-bit functions cannot be decompiled
  MERR_BADCALL   = -12, ///< could not determine call arguments
  MERR_BADFRAME  = -13, ///< function frame is wrong
  MERR_UNKTYPE   = -14, ///< undefined type %s (currently unused error code)
  MERR_BADIDB    = -15, ///< inconsistent database information
  MERR_SIZEOF    = -16, ///< wrong basic type sizes in compiler settings
  MERR_REDO      = -17, ///< redecompilation has been requested
  MERR_CANCELED  = -18, ///< decompilation has been cancelled
  MERR_RECDEPTH  = -19, ///< max recursion depth reached during lvar allocation
  MERR_OVERLAP   = -20, ///< variables would overlap: %s
  MERR_PARTINIT  = -21, ///< partially initialized variable %s
  MERR_COMPLEX   = -22, ///< too complex function
  MERR_LICENSE   = -23, ///< no license available
  MERR_ONLY32    = -24, ///< only 32-bit functions can be decompiled for the current database
  MERR_ONLY64    = -25, ///< only 64-bit functions can be decompiled for the current database
  MERR_BUSY      = -26, ///< already decompiling a function
  MERR_FARPTR    = -27, ///< far memory model is supported only for pc
  MERR_EXTERN    = -28, ///< special segments cannot be decompiled
  MERR_FUNCSIZE  = -29, ///< too big function
  MERR_BADRANGES = -30, ///< bad input ranges
  MERR_BADARCH   = -31, ///< current architecture is not supported
  MERR_DSLOT     = -32, ///< bad instruction in the delay slot
  MERR_STOP      = -33, ///< no error, stop the analysis
  MERR_CLOUD     = -34, ///< cloud: %s
  MERR_MAX_ERR   = 34,
  MERR_LOOP      = -35, ///< internal code: redo last loop (never reported)
};
//@}

/// Get textual description of an error code
/// \param out  the output buffer for the error description
/// \param code \ref MERR_
/// \param mba  the microcode array
/// \return the error address

ea_t hexapi get_merror_desc(qstring *out, merror_t code, mba_t *mba);

//-------------------------------------------------------------------------
// List of microinstruction opcodes.
// The order of setX and jX insns is important, it is used in the code.

// Instructions marked with *F may have the FPINSN bit set and operate on fp values
// Instructions marked with +F must have the FPINSN bit set. They always operate on fp values
// Other instructions do not operate on fp values.

enum mcode_t
{
  m_nop    = 0x00, // nop                       // no operation
  m_stx    = 0x01, // stx  l,    {r=sel, d=off} // store register to memory     *F
  m_ldx    = 0x02, // ldx  {l=sel,r=off}, d     // load register from memory    *F
  m_ldc    = 0x03, // ldc  l=const,     d       // load constant
  m_mov    = 0x04, // mov  l,           d       // move                         *F
  m_neg    = 0x05, // neg  l,           d       // negate
  m_lnot   = 0x06, // lnot l,           d       // logical not
  m_bnot   = 0x07, // bnot l,           d       // bitwise not
  m_xds    = 0x08, // xds  l,           d       // extend (signed)
  m_xdu    = 0x09, // xdu  l,           d       // extend (unsigned)
  m_low    = 0x0A, // low  l,           d       // take low part
  m_high   = 0x0B, // high l,           d       // take high part
  m_add    = 0x0C, // add  l,   r,      d       // l + r -> dst
  m_sub    = 0x0D, // sub  l,   r,      d       // l - r -> dst
  m_mul    = 0x0E, // mul  l,   r,      d       // l * r -> dst
  m_udiv   = 0x0F, // udiv l,   r,      d       // l / r -> dst
  m_sdiv   = 0x10, // sdiv l,   r,      d       // l / r -> dst
  m_umod   = 0x11, // umod l,   r,      d       // l % r -> dst
  m_smod   = 0x12, // smod l,   r,      d       // l % r -> dst
  m_or     = 0x13, // or   l,   r,      d       // bitwise or
  m_and    = 0x14, // and  l,   r,      d       // bitwise and
  m_xor    = 0x15, // xor  l,   r,      d       // bitwise xor
  m_shl    = 0x16, // shl  l,   r,      d       // shift logical left
  m_shr    = 0x17, // shr  l,   r,      d       // shift logical right
  m_sar    = 0x18, // sar  l,   r,      d       // shift arithmetic right
  m_cfadd  = 0x19, // cfadd l,  r,    d=carry   // calculate carry    bit of (l+r)
  m_ofadd  = 0x1A, // ofadd l,  r,    d=overf   // calculate overflow bit of (l+r)
  m_cfshl  = 0x1B, // cfshl l,  r,    d=carry   // calculate carry    bit of (l<<r)
  m_cfshr  = 0x1C, // cfshr l,  r,    d=carry   // calculate carry    bit of (l>>r)
  m_sets   = 0x1D, // sets  l,          d=byte  SF=1          Sign
  m_seto   = 0x1E, // seto  l,  r,      d=byte  OF=1          Overflow of (l-r)
  m_setp   = 0x1F, // setp  l,  r,      d=byte  PF=1          Unordered/Parity        *F
  m_setnz  = 0x20, // setnz l,  r,      d=byte  ZF=0          Not Equal               *F
  m_setz   = 0x21, // setz  l,  r,      d=byte  ZF=1          Equal                   *F
  m_setae  = 0x22, // setae l,  r,      d=byte  CF=0          Unsigned Above or Equal *F
  m_setb   = 0x23, // setb  l,  r,      d=byte  CF=1          Unsigned Below          *F
  m_seta   = 0x24, // seta  l,  r,      d=byte  CF=0 & ZF=0   Unsigned Above          *F
  m_setbe  = 0x25, // setbe l,  r,      d=byte  CF=1 | ZF=1   Unsigned Below or Equal *F
  m_setg   = 0x26, // setg  l,  r,      d=byte  SF=OF & ZF=0  Signed Greater
  m_setge  = 0x27, // setge l,  r,      d=byte  SF=OF         Signed Greater or Equal
  m_setl   = 0x28, // setl  l,  r,      d=byte  SF!=OF        Signed Less
  m_setle  = 0x29, // setle l,  r,      d=byte  SF!=OF | ZF=1 Signed Less or Equal
  m_jcnd   = 0x2A, // jcnd   l,         d       // d is mop_v or mop_b
  m_jnz    = 0x2B, // jnz    l, r,      d       // ZF=0          Not Equal               *F
  m_jz     = 0x2C, // jz     l, r,      d       // ZF=1          Equal                   *F
  m_jae    = 0x2D, // jae    l, r,      d       // CF=0          Unsigned Above or Equal *F
  m_jb     = 0x2E, // jb     l, r,      d       // CF=1          Unsigned Below          *F
  m_ja     = 0x2F, // ja     l, r,      d       // CF=0 & ZF=0   Unsigned Above          *F
  m_jbe    = 0x30, // jbe    l, r,      d       // CF=1 | ZF=1   Unsigned Below or Equal *F
  m_jg     = 0x31, // jg     l, r,      d       // SF=OF & ZF=0  Signed Greater
  m_jge    = 0x32, // jge    l, r,      d       // SF=OF         Signed Greater or Equal
  m_jl     = 0x33, // jl     l, r,      d       // SF!=OF        Signed Less
  m_jle    = 0x34, // jle    l, r,      d       // SF!=OF | ZF=1 Signed Less or Equal
  m_jtbl   = 0x35, // jtbl   l, r=mcases        // Table jump
  m_ijmp   = 0x36, // ijmp       {r=sel, d=off} // indirect unconditional jump
  m_goto   = 0x37, // goto   l                  // l is mop_v or mop_b
  m_call   = 0x38, // call   l          d       // l is mop_v or mop_b or mop_h
  m_icall  = 0x39, // icall  {l=sel, r=off} d   // indirect call
  m_ret    = 0x3A, // ret
  m_push   = 0x3B, // push   l
  m_pop    = 0x3C, // pop               d
  m_und    = 0x3D, // und               d       // undefine
  m_ext    = 0x3E, // ext  in1, in2,  out1      // external insn, not microcode *F
  m_f2i    = 0x3F, // f2i    l,    d       int(l) => d; convert fp -> integer   +F
  m_f2u    = 0x40, // f2u    l,    d       uint(l)=> d; convert fp -> uinteger  +F
  m_i2f    = 0x41, // i2f    l,    d       fp(l)  => d; convert integer -> fp   +F
  m_u2f    = 0x42, // i2f    l,    d       fp(l)  => d; convert uinteger -> fp  +F
  m_f2f    = 0x43, // f2f    l,    d       l      => d; change fp precision     +F
  m_fneg   = 0x44, // fneg   l,    d       -l     => d; change sign             +F
  m_fadd   = 0x45, // fadd   l, r, d       l + r  => d; add                     +F
  m_fsub   = 0x46, // fsub   l, r, d       l - r  => d; subtract                +F
  m_fmul   = 0x47, // fmul   l, r, d       l * r  => d; multiply                +F
  m_fdiv   = 0x48, // fdiv   l, r, d       l / r  => d; divide                  +F
#define m_max 0x49 // first unused opcode
};

/// Must an instruction with the given opcode be the last one in a block?
/// Such opcodes are called closing opcodes.
/// \param mcode instruction opcode
/// \param including_calls should m_call/m_icall be considered as the closing opcodes?
/// If this function returns true, the opcode cannot appear in the middle
/// of a block. Calls are a special case: unknown calls (\ref is_unknown_call)
/// are considered as closing opcodes.

THREAD_SAFE bool hexapi must_mcode_close_block(mcode_t mcode, bool including_calls);


/// May opcode be propagated?
/// Such opcodes can be used in sub-instructions (nested instructions)
/// There is a handful of non-propagatable opcodes, like jumps, ret, nop, etc
/// All other regular opcodes are propagatable and may appear in a nested
/// instruction.

THREAD_SAFE bool hexapi is_mcode_propagatable(mcode_t mcode);


// Is add or sub instruction?
inline THREAD_SAFE bool is_mcode_addsub(mcode_t mcode) { return mcode == m_add || mcode == m_sub; }
// Is xds or xdu instruction? We use 'xdsu' as a shortcut for 'xds or xdu'
inline THREAD_SAFE bool is_mcode_xdsu(mcode_t mcode) { return mcode == m_xds || mcode == m_xdu; }
// Is a 'set' instruction? (an instruction that sets a condition code)
inline THREAD_SAFE bool is_mcode_set(mcode_t mcode) { return mcode >= m_sets && mcode <= m_setle; }
// Is a 1-operand 'set' instruction? Only 'sets' is in this group
inline THREAD_SAFE bool is_mcode_set1(mcode_t mcode) { return mcode == m_sets; }
// Is a 1-operand conditional jump instruction? Only 'jcnd' is in this group
inline THREAD_SAFE bool is_mcode_j1(mcode_t mcode) { return mcode == m_jcnd; }
// Is a conditional jump?
inline THREAD_SAFE bool is_mcode_jcond(mcode_t mcode) { return mcode >= m_jcnd && mcode <= m_jle; }
// Is a 'set' instruction that can be converted into a conditional jump?
inline THREAD_SAFE bool is_mcode_convertible_to_jmp(mcode_t mcode) { return mcode >= m_setnz && mcode <= m_setle; }
// Is a conditional jump instruction that can be converted into a 'set'?
inline THREAD_SAFE bool is_mcode_convertible_to_set(mcode_t mcode) { return mcode >= m_jnz && mcode <= m_jle; }
// Is a call instruction? (direct or indirect)
inline THREAD_SAFE bool is_mcode_call(mcode_t mcode) { return mcode == m_call || mcode == m_icall; }
// Must be an FPU instruction?
inline THREAD_SAFE bool is_mcode_fpu(mcode_t mcode) { return mcode >= m_f2i; }
// Is a commutative instruction?
inline THREAD_SAFE bool is_mcode_commutative(mcode_t mcode)
{
  return mcode == m_add
      || mcode == m_mul
      || mcode == m_or
      || mcode == m_and
      || mcode == m_xor
      || mcode == m_setz
      || mcode == m_setnz
      || mcode == m_cfadd
      || mcode == m_ofadd;
}
// Is a shift instruction?
inline THREAD_SAFE bool is_mcode_shift(mcode_t mcode)
{
  return mcode == m_shl
      || mcode == m_shr
      || mcode == m_sar;
}
// Is a kind of div or mod instruction?
inline THREAD_SAFE bool is_mcode_divmod(mcode_t op)
{
  return op == m_udiv || op == m_sdiv || op == m_umod || op == m_smod;
}
// Is an instruction with the selector/offset pair?
inline THREAD_SAFE bool has_mcode_seloff(mcode_t op)
{
  return op == m_ldx || op == m_stx || op == m_icall || op == m_ijmp;
}

// Convert setX opcode into corresponding jX opcode
// This function relies on the order of setX and jX opcodes!
inline THREAD_SAFE mcode_t set2jcnd(mcode_t code)
{
  return mcode_t(code - m_setnz + m_jnz);
}

// Convert setX opcode into corresponding jX opcode
// This function relies on the order of setX and jX opcodes!
inline THREAD_SAFE mcode_t jcnd2set(mcode_t code)
{
  return mcode_t(code + m_setnz - m_jnz);
}

// Negate a conditional opcode.
// Conditional jumps can be negated, example: jle -> jg
// 'Set' instruction can be negated, example: seta -> setbe
// If the opcode cannot be negated, return m_nop
THREAD_SAFE mcode_t hexapi negate_mcode_relation(mcode_t code);


// Swap a conditional opcode.
// Only conditional jumps and set instructions can be swapped.
// The returned opcode the one required for swapped operands.
// Example "x > y" is the same as "y < x", therefore swap(m_jg) is m_jl.
// If the opcode cannot be swapped, return m_nop

THREAD_SAFE mcode_t hexapi swap_mcode_relation(mcode_t code);

// Return the opcode that performs signed operation.
// Examples: jae -> jge; udiv -> sdiv
// If the opcode cannot be transformed into signed form, simply return it.

THREAD_SAFE mcode_t hexapi get_signed_mcode(mcode_t code);


// Return the opcode that performs unsigned operation.
// Examples: jl -> jb; xds -> xdu
// If the opcode cannot be transformed into unsigned form, simply return it.

THREAD_SAFE mcode_t hexapi get_unsigned_mcode(mcode_t code);

// Does the opcode perform a signed operation?
inline THREAD_SAFE bool is_signed_mcode(mcode_t code) { return get_unsigned_mcode(code) != code; }
// Does the opcode perform a unsigned operation?
inline THREAD_SAFE bool is_unsigned_mcode(mcode_t code) { return get_signed_mcode(code) != code; }


// Does the 'd' operand gets modified by the instruction?
// Example: "add l,r,d" modifies d, while instructions
// like jcnd, ijmp, stx does not modify it.
// Note: this function returns 'true' for m_ext but it may be wrong.
// Use minsn_t::modifies_d() if you have minsn_t.

THREAD_SAFE bool hexapi mcode_modifies_d(mcode_t mcode);


// Processor condition codes are mapped to the first microregisters
// The order is important, see mop_t::is_cc()
const mreg_t mr_none  = mreg_t(-1);
const mreg_t mr_cf    = mreg_t(0);      // carry bit
const mreg_t mr_zf    = mreg_t(1);      // zero bit
const mreg_t mr_sf    = mreg_t(2);      // sign bit
const mreg_t mr_of    = mreg_t(3);      // overflow bit
const mreg_t mr_pf    = mreg_t(4);      // parity bit
const int    cc_count = mr_pf - mr_cf + 1; // number of condition code registers
const mreg_t mr_cc    = mreg_t(5);       // synthetic condition code, used internally
const mreg_t mr_first = mreg_t(8);       // the first processor specific register

//-------------------------------------------------------------------------
/// Operand locator.
/// It is used to denote a particular operand in the ctree, for example,
/// when the user right clicks on a constant and requests to represent it, say,
/// as a hexadecimal number.
struct operand_locator_t
{
private:
  // forbid the default constructor, force the user to initialize objects of this class.
  operand_locator_t(void) {}
public:
  ea_t ea;              ///< address of the original processor instruction
  int opnum;            ///< operand number in the instruction
  operand_locator_t(ea_t _ea, int _opnum) : ea(_ea), opnum(_opnum) {}
  DECLARE_COMPARISONS(operand_locator_t);
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
};

//-------------------------------------------------------------------------
/// Number representation.
/// This structure holds information about a number format.
struct number_format_t
{
  flags_t flags32 = 0;    ///< low 32bit of flags (for compatibility)
  char opnum;             ///< operand number: 0..UA_MAXOP
  char props = 0;         ///< properties: combination of NF_ bits (\ref NF_)
/// \defgroup NF_ Number format property bits
/// Used in number_format_t::props
//@{
#define NF_FIXED    0x01  ///< number format has been defined by the user
#define NF_NEGDONE  0x02  ///< temporary internal bit: negation has been performed
#define NF_BINVDONE 0x04  ///< temporary internal bit: inverting bits is done
#define NF_NEGATE   0x08  ///< The user asked to negate the constant
#define NF_BITNOT   0x10  ///< The user asked to invert bits of the constant
#define NF_VALID    0x20  ///< internal bit: stroff or enum is valid
                          ///< for enums: this bit is set immediately
                          ///< for stroffs: this bit is set at the end of decompilation
//@}
  uchar serial = 0;       ///< for enums: constant serial number
  char org_nbytes = 0;    ///< original number size in bytes
  qstring type_name;      ///< for stroffs: structure for offsetof()\n
                          ///< for enums: enum name
  flags64_t flags = 0;    ///< ida flags, which describe number radix, enum, etc
  /// Contructor
  number_format_t(int _opnum=0) : opnum(char(_opnum)) {}
  /// Get number radix
  /// \return 2,8,10, or 16
  int get_radix() const { return ::get_radix(flags, opnum); }
  /// Is number representation fixed?
  /// Fixed representation cannot be modified by the decompiler
  bool is_fixed() const { return props != 0; }
  /// Is a hexadecimal number?
  bool is_hex() const { return ::is_numop(flags, opnum) && get_radix() == 16; }
  /// Is a decimal number?
  bool is_dec() const { return ::is_numop(flags, opnum) && get_radix() == 10; }
  /// Is a octal number?
  bool is_oct() const { return ::is_numop(flags, opnum) && get_radix() == 8; }
  /// Is a symbolic constant?
  bool is_enum() const { return ::is_enum(flags, opnum); }
  /// Is a character constant?
  bool is_char() const { return ::is_char(flags, opnum); }
  /// Is a structure field offset?
  bool is_stroff() const { return ::is_stroff(flags, opnum); }
  /// Is a number?
  bool is_numop() const { return !is_enum() && !is_char() && !is_stroff(); }
  /// Does the number need to be negated or bitwise negated?
  /// Returns true if the user requested a negation but it is not done yet
  bool needs_to_be_inverted() const
  {
    return (props & (NF_NEGATE|NF_BITNOT)) != 0      // the user requested it
        && (props & (NF_NEGDONE|NF_BINVDONE)) == 0;  // not done yet
  }
  // symbolic constants and struct offsets cannot easily change
  // their sign or size without a cast. only simple numbers can do that.
  // for example, by modifying the expression type we can convert:
  // 10u -> 10
  // but replacing the type of a symbol constant would lead to an inconsistency.
  bool has_unmutable_type() const
  {
    return (props & NF_VALID) != 0 && (is_stroff() || is_enum());
  }
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
};

// Number formats are attached to (ea,opnum) pairs
typedef std::map<operand_locator_t, number_format_t> user_numforms_t;

//-------------------------------------------------------------------------
/// Base helper class to convert binary data structures into text.
/// Other classes are derived from this class.
struct vd_printer_t
{
  qstring tmpbuf;
  int hdrlines;         ///< number of header lines (prototype+typedef+lvars)
                        ///< valid at the end of print process
  /// Print.
  /// This function is called to generate a portion of the output text.
  /// The output text may contain color codes.
  /// \return the number of printed characters
  /// \param indent  number of spaces to generate as prefix
  /// \param format  printf-style format specifier
  /// \return length of printed string
  AS_PRINTF(3, 4) virtual int hexapi print(int indent, const char *format, ...);
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
};

/// Helper class to convert cfunc_t into text.
struct vc_printer_t : public vd_printer_t
{
  const cfunc_t *func;          ///< cfunc_t to generate text for
  char lastchar;                ///< internal: last printed character
  /// Constructor
  vc_printer_t(const cfunc_t *f) : func(f), lastchar(0) {}
  /// Are we generating one-line text representation?
  /// \return \c true if the output will occupy one line without line breaks
  virtual bool idaapi oneliner(void) const newapi { return false; }
};

/// Helper class to convert binary data structures into text and put into a file.
struct file_printer_t : public vd_printer_t
{
  FILE *fp;                     ///< Output file pointer
  /// Print.
  /// This function is called to generate a portion of the output text.
  /// The output text may contain color codes.
  /// \return the number of printed characters
  /// \param indent  number of spaces to generate as prefix
  /// \param format  printf-style format specifier
  /// \return length of printed string
  AS_PRINTF(3, 4) int hexapi print(int indent, const char *format, ...) override;
  /// Constructor
  file_printer_t(FILE *_fp) : fp(_fp) {}
};

/// Helper class to convert cfunc_t into a text string
struct qstring_printer_t : public vc_printer_t
{
  bool with_tags;               ///< Generate output with color tags
  qstring &s;                   ///< Reference to the output string
  /// Constructor
  qstring_printer_t(const cfunc_t *f, qstring &_s, bool tags)
    : vc_printer_t(f), with_tags(tags), s(_s) {}
  /// Print.
  /// This function is called to generate a portion of the output text.
  /// The output text may contain color codes.
  /// \return the number of printed characters
  /// \param indent  number of spaces to generate as prefix
  /// \param format  printf-style format specifier
  /// \return length of the printed string
  AS_PRINTF(3, 4) int hexapi print(int indent, const char *format, ...) override;
};

//-------------------------------------------------------------------------
/// \defgroup type Type string related declarations
/// Type related functions and class.
//@{

/// Print the specified type info.
/// This function can be used from a debugger by typing "tif->dstr()"

const char *hexapi dstr(const tinfo_t *tif);


/// Verify a type string.
/// \return true if type string is correct

bool hexapi is_type_correct(const type_t *ptr);


/// Is a small structure or union?
/// \return true if the type is a small UDT (user defined type).
///              Small UDTs fit into a register (or pair or registers) as a rule.

bool hexapi is_small_udt(const tinfo_t &tif);


/// Is definitely a non-boolean type?
/// \return true if the type is a non-boolean type (non bool and well defined)

bool hexapi is_nonbool_type(const tinfo_t &type);


/// Is a boolean type?
/// \return true if the type is a boolean type

bool hexapi is_bool_type(const tinfo_t &type);


/// Is a pointer or array type?
inline THREAD_SAFE bool is_ptr_or_array(type_t t)
{
  return is_type_ptr(t) || is_type_array(t);
}

/// Is a pointer, array, or function type?
inline THREAD_SAFE bool is_paf(type_t t)
{
  return is_ptr_or_array(t) || is_type_func(t);
}

/// Is struct/union/enum definition (not declaration)?
inline THREAD_SAFE bool is_inplace_def(const tinfo_t &type)
{
  return type.is_decl_complex() && !type.is_typeref();
}

/// Calculate number of partial subtypes.
/// \return number of partial subtypes. The bigger is this number, the uglier is the type.

int hexapi partial_type_num(const tinfo_t &type);


/// Get a type of a floating point value with the specified width
/// \returns type info object
/// \param width width of the desired type

tinfo_t hexapi get_float_type(int width);


/// Create a type info by width and sign.
/// Returns a simple type (examples: int, short) with the given width and sign.
/// \param srcwidth size of the type in bytes
/// \param sign sign of the type

tinfo_t hexapi get_int_type_by_width_and_sign(int srcwidth, type_sign_t sign);


/// Create a partial type info by width.
/// Returns a partially defined type (examples: _DWORD, _BYTE) with the given width.
/// \param size size of the type in bytes

tinfo_t hexapi get_unk_type(int size);


/// Generate a dummy pointer type
///  \param ptrsize size of pointed object
///  \param isfp is floating point object?

tinfo_t hexapi dummy_ptrtype(int ptrsize, bool isfp);


/// Get type of a structure field.
/// This function performs validity checks of the field type. Wrong types are rejected.
/// \param mptr structure field
/// \param type pointer to the variable where the type is returned. This parameter can be nullptr.
/// \return false if failed

bool hexapi get_member_type(const member_t *mptr, tinfo_t *type);


/// Create a pointer type.
/// This function performs the following conversion: "type" -> "type*"
/// \param type object type.
/// \return "type*". for example, if 'char' is passed as the argument,
//          the function will return 'char *'

tinfo_t hexapi make_pointer(const tinfo_t &type);


/// Create a reference to a named type.
/// \param name type name
/// \return type which refers to the specified name. For example, if name is "DWORD",
///             the type info which refers to "DWORD" is created.

tinfo_t hexapi create_typedef(const char *name);


/// Create a reference to an ordinal type.
/// \param n ordinal number of the type
/// \return type which refers to the specified ordinal. For example, if n is 1,
///             the type info which refers to ordinal type 1 is created.

inline tinfo_t create_typedef(int n)
{
  tinfo_t tif;
  tif.create_typedef(nullptr, n);
  return tif;
}

/// Type source (where the type information comes from)
enum type_source_t
{
  GUESSED_NONE,  // not guessed, specified by the user
  GUESSED_WEAK,  // not guessed, comes from idb
  GUESSED_FUNC,  // guessed as a function
  GUESSED_DATA,  // guessed as a data item
  TS_NOELL   = 0x8000000, // can be used in set_type() to avoid merging into ellipsis
  TS_SHRINK  = 0x4000000, // can be used in set_type() to prefer smaller arguments
  TS_DONTREF = 0x2000000, // do not mark type as referenced (referenced_types)
  TS_MASK    = 0xE000000, // all high bits
};


/// Get a global type.
/// Global types are types of addressable objects and struct/union/enum types
/// \param id address or id of the object
/// \param tif buffer for the answer
/// \param guess what kind of types to consider
/// \return success

bool hexapi get_type(uval_t id, tinfo_t *tif, type_source_t guess);


/// Set a global type.
/// \param id address or id of the object
/// \param tif new type info
/// \param source where the type comes from
/// \param force true means to set the type as is, false means to merge the
///        new type with the possibly existing old type info.
/// \return success

bool hexapi set_type(uval_t id, const tinfo_t &tif, type_source_t source, bool force=false);

//@}

//-------------------------------------------------------------------------
// We use our own class to store argument and variable locations.
// It is called vdloc_t that stands for 'vd location'.
// 'vd' is the internal name of the decompiler, it stands for 'visual decompiler'.
// The main differences between vdloc and argloc_t:
//   ALOC_REG1: the offset is always 0, so it is not used. the register number
//              uses the whole ~VLOC_MASK field.
//   ALOCK_STKOFF: stack offsets are always positive because they are based on
//              the lowest value of sp in the function.
class vdloc_t : public argloc_t
{
  int regoff(void); // inaccessible & undefined: regoff() should not be used
public:
  // Get the register number.
  // This function works only for ALOC_REG1 and ALOC_REG2 location types.
  // It uses all available bits for register number for ALOC_REG1
  int reg1(void) const { return atype() == ALOC_REG2 ? argloc_t::reg1() : get_reginfo(); }

  // Set vdloc to point to the specified register without cleaning it up.
  // This is a dangerous function, use set_reg1() instead unless you understand
  // what it means to cleanup an argloc.
  void _set_reg1(int r1) { argloc_t::_set_reg1(r1, r1>>16); }

  // Set vdloc to point to the specified register.
  void set_reg1(int r1) { cleanup_argloc(this); _set_reg1(r1); }

  // Use member functions of argloc_t for other location types.

  // Return textual representation.
  // Note: this and all other dstr() functions can be used from a debugger.
  // It is much easier than to inspect the memory contents byte by byte.
  const char *hexapi dstr(int width=0) const;
  DECLARE_COMPARISONS(vdloc_t);
  bool hexapi is_aliasable(const mba_t *mb, int size) const;
};

/// Print vdloc.
/// Since vdloc does not always carry the size info, we pass it as NBYTES..
void hexapi print_vdloc(qstring *vout, const vdloc_t &loc, int nbytes);

//-------------------------------------------------------------------------
/// Do two arglocs overlap?
bool hexapi arglocs_overlap(const vdloc_t &loc1, size_t w1, const vdloc_t &loc2, size_t w2);

/// Local variable locator.
/// Local variables are located using definition ea and location.
/// Each variable must have a unique locator, this is how we tell them apart.
struct lvar_locator_t
{
  vdloc_t location;     ///< Variable location.
  ea_t defea;           ///< Definition address. Usually, this is the address
                        ///< of the instruction that initializes the variable.
                        ///< In some cases it can be a fictional address.

  lvar_locator_t(void) : defea(BADADDR) {}
  lvar_locator_t(const vdloc_t &loc, ea_t ea) : location(loc), defea(ea) {}
  /// Get offset of the varialbe in the stack frame.
  /// \return a non-negative value for stack variables. The value is
  ///         an offset from the bottom of the stack frame in terms of
  ///         vd-offsets.
  ///         negative values mean error (not a stack variable)
  sval_t get_stkoff(void) const
  {
    return location.is_stkoff() ? location.stkoff() : -1;
  }
  /// Is variable located on one register?
  bool is_reg1(void) const { return  location.is_reg1(); }
  /// Is variable located on two registers?
  bool is_reg2(void) const { return  location.is_reg2(); }
  /// Is variable located on register(s)?
  bool is_reg_var(void) const { return location.is_reg(); }
  /// Is variable located on the stack?
  bool is_stk_var(void) const { return location.is_stkoff(); }
  /// Is variable scattered?
  bool is_scattered(void) const { return location.is_scattered(); }
  /// Get the register number of the variable
  mreg_t get_reg1(void) const { return location.reg1(); }
  /// Get the number of the second register (works only for ALOC_REG2 lvars)
  mreg_t get_reg2(void) const { return location.reg2(); }
  /// Get information about scattered variable
  const scattered_aloc_t &get_scattered(void) const { return location.scattered(); }
        scattered_aloc_t &get_scattered(void)       { return location.scattered(); }
  DECLARE_COMPARISONS(lvar_locator_t);
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
  // Debugging: get textual representation of a lvar locator.
  const char *hexapi dstr() const;
};

/// Definition of a local variable (register or stack) #var #lvar
class lvar_t : public lvar_locator_t
{
  friend class mba_t;
  int flags;                    ///< \ref CVAR_
/// \defgroup CVAR_ Local variable property bits
/// Used in lvar_t::flags
//@{
#define CVAR_USED    0x00000001 ///< is used in the code?
#define CVAR_TYPE    0x00000002 ///< the type is defined?
#define CVAR_NAME    0x00000004 ///< has nice name?
#define CVAR_MREG    0x00000008 ///< corresponding mregs were replaced?
#define CVAR_NOWD    0x00000010 ///< width is unknown
#define CVAR_UNAME   0x00000020 ///< user-defined name
#define CVAR_UTYPE   0x00000040 ///< user-defined type
#define CVAR_RESULT  0x00000080 ///< function result variable
#define CVAR_ARG     0x00000100 ///< function argument
#define CVAR_FAKE    0x00000200 ///< fake variable (return var or va_list)
#define CVAR_OVER    0x00000400 ///< overlapping variable
#define CVAR_FLOAT   0x00000800 ///< used in a fpu insn
#define CVAR_SPOILED 0x00001000 ///< internal flag, do not use: spoiled var
#define CVAR_MAPDST  0x00002000 ///< other variables are mapped to this var
#define CVAR_PARTIAL 0x00004000 ///< variable type is partialy defined
#define CVAR_THISARG 0x00008000 ///< 'this' argument of c++ member functions
#define CVAR_FORCED  0x00010000 ///< variable was created by an explicit request
                                ///< otherwise we could reuse an existing var
#define CVAR_REGNAME 0x00020000 ///< has a register name (like _RAX): if lvar
                                ///< is used by an m_ext instruction
#define CVAR_NOPTR   0x00040000 ///< variable cannot be a pointer (user choice)
#define CVAR_DUMMY   0x00080000 ///< dummy argument (added to fill a hole in
                                ///< the argument list)
#define CVAR_NOTARG  0x00100000 ///< variable cannot be an input argument
#define CVAR_AUTOMAP 0x00200000 ///< variable was automatically mapped
#define CVAR_BYREF   0x00400000 ///< the address of the variable was taken
#define CVAR_INASM   0x00800000 ///< variable is used in instructions translated
                                ///< into __asm {...}
#define CVAR_UNUSED  0x01000000 ///< user-defined __unused attribute
                                ///< meaningful only if: is_arg_var() && !mba->final_type
#define CVAR_SHARED  0x02000000 ///< variable is mapped to several chains
//@}

public:
  qstring name;          ///< variable name.
                         ///< use mba_t::set_nice_lvar_name() and
                         ///< mba_t::set_user_lvar_name() to modify it
  qstring cmt;           ///< variable comment string
  tinfo_t tif;           ///< variable type
  int width = 0;         ///< variable size in bytes
  int defblk = -1;       ///< first block defining the variable.
                         ///< 0 for args, -1 if unknown
  uint64 divisor = 0;    ///< max known divisor of the variable

  lvar_t(void) : flags(CVAR_USED) {}
  lvar_t(const qstring &n, const vdloc_t &l, ea_t e, const tinfo_t &t, int w, int db)
    : lvar_locator_t(l, e), flags(CVAR_USED), name(n), tif(t), width(w), defblk(db)
  {
  }
  // Debugging: get textual representation of a local variable.
  const char *hexapi dstr() const;

  /// Is the variable used in the code?
  bool used(void)  const { return (flags & CVAR_USED) != 0; }
  /// Has the variable a type?
  bool typed(void) const { return (flags & CVAR_TYPE) != 0; }
  /// Have corresponding microregs been replaced by references to this variable?
  bool mreg_done(void) const { return (flags & CVAR_MREG) != 0; }
  /// Does the variable have a nice name?
  bool has_nice_name(void) const { return (flags & CVAR_NAME) != 0; }
  /// Do we know the width of the variable?
  bool is_unknown_width(void) const { return (flags & CVAR_NOWD) != 0; }
  /// Has any user-defined information?
  bool has_user_info(void) const
  {
    return (flags & (CVAR_UNAME|CVAR_UTYPE|CVAR_NOPTR|CVAR_UNUSED)) != 0
        || !cmt.empty();
  }
  /// Has user-defined name?
  bool has_user_name(void) const { return (flags & CVAR_UNAME) != 0; }
  /// Has user-defined type?
  bool has_user_type(void) const { return (flags & CVAR_UTYPE) != 0; }
  /// Is the function result?
  bool is_result_var(void) const { return (flags & CVAR_RESULT) != 0; }
  /// Is the function argument?
  bool is_arg_var(void) const { return (flags & CVAR_ARG) != 0; }
  /// Is the promoted function argument?
  bool hexapi is_promoted_arg(void) const;
  /// Is fake return variable?
  bool is_fake_var(void) const { return (flags & CVAR_FAKE) != 0; }
  /// Is overlapped variable?
  bool is_overlapped_var(void) const { return (flags & CVAR_OVER) != 0; }
  /// Used by a fpu insn?
  bool is_floating_var(void) const { return (flags & CVAR_FLOAT) != 0; }
  /// Is spoiled var? (meaningful only during lvar allocation)
  bool is_spoiled_var(void) const { return (flags & CVAR_SPOILED) != 0; }
  /// Variable type should be handled as a partial one
  bool is_partialy_typed(void) const { return (flags & CVAR_PARTIAL) != 0; }
  /// Variable type should not be a pointer
  bool is_noptr_var(void) const { return (flags & CVAR_NOPTR) != 0; }
  /// Other variable(s) map to this var?
  bool is_mapdst_var(void) const { return (flags & CVAR_MAPDST) != 0; }
  /// Is 'this' argument of a C++ member function?
  bool is_thisarg(void) const { return (flags & CVAR_THISARG) != 0; }
  /// Is a forced variable?
  bool is_forced_var(void) const { return (flags & CVAR_FORCED) != 0; }
  /// Has a register name? (like _RAX)
  bool has_regname(void) const { return (flags & CVAR_REGNAME) != 0; }
  /// Is variable used in an instruction translated into __asm?
  bool in_asm(void) const { return (flags & CVAR_INASM) != 0; }
  /// Is a dummy argument (added to fill a hole in the argument list)
  bool is_dummy_arg(void) const { return (flags & CVAR_DUMMY) != 0; }
  /// Is a local variable? (local variable cannot be an input argument)
  bool is_notarg(void) const { return (flags & CVAR_NOTARG) != 0; }
  /// Was the variable automatically mapped to another variable?
  bool is_automapped(void) const { return (flags & CVAR_AUTOMAP) != 0; }
  /// Was the address of the variable taken?
  bool is_used_byref(void) const { return (flags & CVAR_BYREF) != 0; }
  /// Was declared as __unused by the user? See CVAR_UNUSED
  bool is_decl_unused(void) const { return (flags & CVAR_UNUSED) != 0; }
  /// Is lvar mapped to several chains
  bool is_shared(void) const { return (flags & CVAR_SHARED) != 0; }
  void set_used(void) { flags |= CVAR_USED; }
  void clear_used(void) { flags &= ~CVAR_USED; }
  void set_typed(void) { flags |= CVAR_TYPE; clr_noptr_var(); }
  void set_non_typed(void) { flags &= ~CVAR_TYPE; }
  void clr_user_info(void) { flags &= ~(CVAR_UNAME|CVAR_UTYPE|CVAR_NOPTR); }
  void set_user_name(void) { flags |= CVAR_NAME|CVAR_UNAME; }
  void set_user_type(void) { flags |= CVAR_TYPE|CVAR_UTYPE; }
  void clr_user_type(void) { flags &= ~CVAR_UTYPE; }
  void clr_user_name(void) { flags &= ~CVAR_UNAME; }
  void set_mreg_done(void) { flags |= CVAR_MREG; }
  void clr_mreg_done(void) { flags &= ~CVAR_MREG; }
  void set_unknown_width(void) { flags |= CVAR_NOWD; }
  void clr_unknown_width(void) { flags &= ~CVAR_NOWD; }
  void set_arg_var(void) { flags |= CVAR_ARG; }
  void clr_arg_var(void) { flags &= ~(CVAR_ARG|CVAR_THISARG); }
  void set_fake_var(void) { flags |= CVAR_FAKE; }
  void clr_fake_var(void) { flags &= ~CVAR_FAKE; }
  void set_overlapped_var(void) { flags |= CVAR_OVER; }
  void clr_overlapped_var(void) { flags &= ~CVAR_OVER; }
  void set_floating_var(void) { flags |= CVAR_FLOAT; }
  void clr_floating_var(void) { flags &= ~CVAR_FLOAT; }
  void set_spoiled_var(void) { flags |= CVAR_SPOILED; }
  void clr_spoiled_var(void) { flags &= ~CVAR_SPOILED; }
  void set_mapdst_var(void) { flags |= CVAR_MAPDST; }
  void clr_mapdst_var(void) { flags &= ~CVAR_MAPDST; }
  void set_partialy_typed(void) { flags |= CVAR_PARTIAL; }
  void clr_partialy_typed(void) { flags &= ~CVAR_PARTIAL; }
  void set_noptr_var(void) { flags |= CVAR_NOPTR; }
  void clr_noptr_var(void) { flags &= ~CVAR_NOPTR; }
  void set_thisarg(void) { flags |= CVAR_THISARG; }
  void clr_thisarg(void) { flags &= ~CVAR_THISARG; }
  void set_forced_var(void) { flags |= CVAR_FORCED; }
  void clr_forced_var(void) { flags &= ~CVAR_FORCED; }
  void set_dummy_arg(void) { flags |= CVAR_DUMMY; }
  void clr_dummy_arg(void) { flags &= ~CVAR_DUMMY; }
  void set_notarg(void) { clr_arg_var(); flags |= CVAR_NOTARG; }
  void clr_notarg(void) { flags &= ~CVAR_NOTARG; }
  void set_automapped(void) { flags |= CVAR_AUTOMAP; }
  void clr_automapped(void) { flags &= ~CVAR_AUTOMAP; }
  void set_used_byref(void) { flags |= CVAR_BYREF; }
  void clr_used_byref(void) { flags &= ~CVAR_BYREF; }
  void set_decl_unused(void) { flags |= CVAR_UNUSED; }
  void clr_decl_unused(void) { flags &= ~CVAR_UNUSED; }
  void set_shared(void) { flags |= CVAR_SHARED; }
  void clr_shared(void) { flags &= ~CVAR_SHARED; }

  /// Do variables overlap?
  bool has_common(const lvar_t &v) const
  {
    return arglocs_overlap(location, width, v.location, v.width);
  }
  /// Does the variable overlap with the specified location?
  bool has_common_bit(const vdloc_t &loc, asize_t width2) const
  {
    return arglocs_overlap(location, width, loc, width2);
  }
  /// Get variable type
  const tinfo_t &type(void) const { return tif; }
  tinfo_t &type(void) { return tif; }

  /// Check if the variable accept the specified type.
  /// Some types are forbidden (void, function types, wrong arrays, etc)
  bool hexapi accepts_type(const tinfo_t &t, bool may_change_thisarg=false);
  /// Set variable type
  /// Note: this function does not modify the idb, only the lvar instance
  /// in the memory. For permanent changes see modify_user_lvars()
  /// Also, the variable type is not considered as final by the decompiler
  /// and may be modified later by the type derivation.
  /// In some cases set_final_var_type() may work better, but it does not
  /// do persistent changes to the database neither.
  /// \param t new type
  /// \param may_fail if false and type is bad, interr
  /// \return success
  bool hexapi set_lvar_type(const tinfo_t &t, bool may_fail=false);

  /// Set final variable type.
  void set_final_lvar_type(const tinfo_t &t)
  {
    set_lvar_type(t);
    set_typed();
  }

  /// Change the variable width.
  /// We call the variable size 'width', it is represents the number of bytes.
  /// This function may change the variable type using set_lvar_type().
  /// \param w new width
  /// \param svw_flags combination of SVW_... bits
  /// \return success
  bool hexapi set_width(int w, int svw_flags=0);
#define SVW_INT   0x00 // integer value
#define SVW_FLOAT 0x01 // floating point value
#define SVW_SOFT  0x02 // may fail and return false;
                       // if this bit is not set and the type is bad, interr

  /// Append local variable to mlist.
  /// \param mba ptr to the current mba_t
  /// \param lst list to append to
  /// \param pad_if_scattered if true, append padding bytes in case of scattered lvar
  void hexapi append_list(const mba_t *mba, mlist_t *lst, bool pad_if_scattered=false) const;

  /// Is the variable aliasable?
  /// \param mba ptr to the current mba_t
  /// Aliasable variables may be modified indirectly (through a pointer)
  bool is_aliasable(const mba_t *mba) const
  {
    return location.is_aliasable(mba, width);
  }

};
DECLARE_TYPE_AS_MOVABLE(lvar_t);

/// Vector of local variables
struct lvars_t : public qvector<lvar_t>
{
  /// Find input variable at the specified location.
  /// \param argloc variable location
  /// \param _size variable size
  /// \return -1 if failed, otherwise the index into the variables vector.
  int find_input_lvar(const vdloc_t &argloc, int _size) { return find_lvar(argloc, _size, 0); }


  /// Find stack variable at the specified location.
  /// \param spoff offset from the minimal sp
  /// \param width variable size
  /// \return -1 if failed, otherwise the index into the variables vector.
  int hexapi find_stkvar(sval_t spoff, int width);


  /// Find variable at the specified location.
  /// \param ll variable location
  /// \return pointer to variable or nullptr
  lvar_t *hexapi find(const lvar_locator_t &ll);


  /// Find variable at the specified location.
  /// \param location variable location
  /// \param width variable size
  /// \param defblk definition block of the lvar. -1 means any block
  /// \return -1 if failed, otherwise the index into the variables vector.
  int hexapi find_lvar(const vdloc_t &location, int width, int defblk=-1) const;
};

/// Saved user settings for local variables: name, type, comment.
struct lvar_saved_info_t
{
  lvar_locator_t ll;            ///< Variable locator
  qstring name;                 ///< Name
  tinfo_t type;                 ///< Type
  qstring cmt;                  ///< Comment
  ssize_t size;                 ///< Type size (if not initialized then -1)
  int flags;                    ///< \ref LVINF_
/// \defgroup LVINF_ saved user lvar info property bits
/// Used in lvar_saved_info_t::flags
//@{
#define LVINF_KEEP   0x0001     ///< preserve saved user settings regardless of vars
                                ///< for example, if a var loses all its
                                ///< user-defined attributes or even gets
                                ///< destroyed, keep its lvar_saved_info_t.
                                ///< this is used for ephemeral variables that
                                ///< get destroyed by macro recognition.
#define LVINF_FORCE  0x0002     ///< force allocation of a new variable.
                                ///< forces the decompiler to create a new
                                ///< variable at ll.defea
#define LVINF_NOPTR  0x0004     ///< variable type should not be a pointer
#define LVINF_NOMAP  0x0008     ///< forbid automatic mapping of the variable
#define LVINF_UNUSED 0x0010     ///< unused argument, corresponds to CVAR_UNUSED
//@}
  lvar_saved_info_t(void) : size(BADSIZE), flags(0) {}
  bool has_info(void) const
  {
    return !name.empty()
        || !type.empty()
        || !cmt.empty()
        || is_forced_lvar()
        || is_noptr_lvar()
        || is_nomap_lvar();
  }
  bool operator==(const lvar_saved_info_t &r) const
  {
    return name == r.name
        && cmt == r.cmt
        && ll == r.ll
        && type == r.type;
  }
  bool operator!=(const lvar_saved_info_t &r) const { return !(*this == r); }
  bool is_kept(void) const { return (flags & LVINF_KEEP) != 0; }
  void clear_keep(void) { flags &= ~LVINF_KEEP; }
  void set_keep(void) { flags |= LVINF_KEEP; }
  bool is_forced_lvar(void) const { return (flags & LVINF_FORCE) != 0; }
  void set_forced_lvar(void) { flags |= LVINF_FORCE; }
  void clr_forced_lvar(void) { flags &= ~LVINF_FORCE; }
  bool is_noptr_lvar(void) const { return (flags & LVINF_NOPTR) != 0; }
  void set_noptr_lvar(void) { flags |= LVINF_NOPTR; }
  void clr_noptr_lvar(void) { flags &= ~LVINF_NOPTR; }
  bool is_nomap_lvar(void) const { return (flags & LVINF_NOMAP) != 0; }
  void set_nomap_lvar(void) { flags |= LVINF_NOMAP; }
  void clr_nomap_lvar(void) { flags &= ~LVINF_NOMAP; }
  bool is_unused_lvar(void) const { return (flags & LVINF_UNUSED) != 0; }
  void set_unused_lvar(void) { flags |= LVINF_UNUSED; }
  void clr_unused_lvar(void) { flags &= ~LVINF_UNUSED; }
};
DECLARE_TYPE_AS_MOVABLE(lvar_saved_info_t);
typedef qvector<lvar_saved_info_t> lvar_saved_infos_t;

/// Local variable mapping (is used to merge variables)
typedef std::map<lvar_locator_t, lvar_locator_t> lvar_mapping_t;

/// All user-defined information about local variables
struct lvar_uservec_t
{
  /// User-specified names, types, comments for lvars. Variables without
  /// user-specified info are not present in this vector.
  lvar_saved_infos_t lvvec;

  /// Local variable mapping (used for merging variables)
  lvar_mapping_t lmaps;

  /// Delta to add to IDA stack offset to calculate Hex-Rays stack offsets.
  /// Should be set by the caller before calling save_user_lvar_settings();
  uval_t stkoff_delta;

  /// Various flags. Possible values are from \ref ULV_
  int ulv_flags;
/// \defgroup ULV_ lvar_uservec_t property bits
/// Used in lvar_uservec_t::ulv_flags
//@{
#define ULV_PRECISE_DEFEA 0x0001        ///< Use precise defea's for lvar locations
//@}

  lvar_uservec_t(void) : stkoff_delta(0), ulv_flags(ULV_PRECISE_DEFEA) {}
  void swap(lvar_uservec_t &r)
  {
    lvvec.swap(r.lvvec);
    lmaps.swap(r.lmaps);
    std::swap(stkoff_delta, r.stkoff_delta);
    std::swap(ulv_flags, r.ulv_flags);
  }
  void clear()
  {
    lvvec.clear();
    lmaps.clear();
    stkoff_delta = 0;
    ulv_flags = ULV_PRECISE_DEFEA;
  }
  bool empty() const
  {
    return lvvec.empty()
        && lmaps.empty()
        && stkoff_delta == 0
        && ulv_flags == ULV_PRECISE_DEFEA;
  }

  /// find saved user settings for given var
  lvar_saved_info_t *find_info(const lvar_locator_t &vloc)
  {
    for ( lvar_saved_infos_t::iterator p=lvvec.begin(); p != lvvec.end(); ++p )
    {
      if ( p->ll == vloc )
        return p;
    }
    return nullptr;
  }

  /// Preserve user settings for given var
  void keep_info(const lvar_t &v)
  {
    lvar_saved_info_t *p = find_info(v);
    if ( p != nullptr )
      p->set_keep();
  }
};

/// Restore user defined local variable settings in the database.
/// \param func_ea entry address of the function
/// \param lvinf ptr to output buffer
/// \return success

bool hexapi restore_user_lvar_settings(lvar_uservec_t *lvinf, ea_t func_ea);


/// Save user defined local variable settings into the database.
/// \param func_ea entry address of the function
/// \param lvinf user-specified info about local variables

void hexapi save_user_lvar_settings(ea_t func_ea, const lvar_uservec_t &lvinf);


/// Helper class to modify saved local variable settings.
struct user_lvar_modifier_t
{
  /// Modify lvar settings.
  /// Returns: true-modified
  virtual bool idaapi modify_lvars(lvar_uservec_t *lvinf) = 0;
};

/// Modify saved local variable settings.
/// \param entry_ea         function start address
/// \param mlv              local variable modifier
/// \return true if modified variables

bool hexapi modify_user_lvars(ea_t entry_ea, user_lvar_modifier_t &mlv);


/// Modify saved local variable settings of one variable.
/// \param func_ea          function start address
/// \param info             local variable info attrs
/// \param mli_flags        bits that specify which attrs defined by INFO are to be set
/// \return true if modified, false if invalid MLI_FLAGS passed

bool hexapi modify_user_lvar_info(
        ea_t func_ea,
        uint mli_flags,
        const lvar_saved_info_t &info);

/// \defgroup MLI_ user info bits
//@{
#define MLI_NAME        0x01 ///< apply lvar name
#define MLI_TYPE        0x02 ///< apply lvar type
#define MLI_CMT         0x04 ///< apply lvar comment
#define MLI_SET_FLAGS   0x08 ///< set LVINF_... bits
#define MLI_CLR_FLAGS   0x10 ///< clear LVINF_... bits
//@}


/// Find a variable by name.
/// \param out              output buffer for the variable locator
/// \param func_ea          function start address
/// \param varname          variable name
/// \return success
/// Since VARNAME is not always enough to find the variable, it may decompile
/// the function.

bool hexapi locate_lvar(
        lvar_locator_t *out,
        ea_t func_ea,
        const char *varname);


/// Rename a local variable.
/// \param func_ea          function start address
/// \param oldname          old name of the variable
/// \param newname          new name of the variable
/// \return success
/// This is a convenience function.
/// For bulk renaming consider using modify_user_lvars.

inline bool rename_lvar(
        ea_t func_ea,
        const char *oldname,
        const char *newname)
{
  lvar_saved_info_t info;
  if ( !locate_lvar(&info.ll, func_ea, oldname) )
    return false;
  info.name = newname;
  return modify_user_lvar_info(func_ea, MLI_NAME, info);
}

//-------------------------------------------------------------------------
/// User-defined function calls
struct udcall_t
{
  qstring name;         // name of the function
  tinfo_t tif;          // function prototype
  DECLARE_COMPARISONS(udcall_t)
  {
    int code = ::compare(name, r.name);
    if ( code == 0 )
      code = ::compare(tif, r.tif);
    return code;
  }

  bool empty() const { return name.empty() && tif.empty(); }
};

// All user-defined function calls (map address -> udcall)
typedef std::map<ea_t, udcall_t> udcall_map_t;

/// Restore user defined function calls from the database.
/// \param udcalls ptr to output buffer
/// \param func_ea entry address of the function
/// \return success

bool hexapi restore_user_defined_calls(udcall_map_t *udcalls, ea_t func_ea);


/// Save user defined local function calls into the database.
/// \param func_ea entry address of the function
/// \param udcalls user-specified info about user defined function calls

void hexapi save_user_defined_calls(ea_t func_ea, const udcall_map_t &udcalls);


/// Convert function type declaration into internal structure
/// \param udc    - pointer to output structure
/// \param decl   - function type declaration
/// \param silent - if TRUE: do not show warning in case of incorrect type
/// \return success

bool hexapi parse_user_call(udcall_t *udc, const char *decl, bool silent);


/// try to generate user-defined call for an instruction
/// \return \ref MERR_ code:
///   MERR_OK      - user-defined call generated
///   else         - error (MERR_INSN == inacceptable udc.tif)

merror_t hexapi convert_to_user_call(const udcall_t &udc, codegen_t &cdg);


//-------------------------------------------------------------------------
/// Generic microcode generator class.
/// An instance of a derived class can be registered to be used for
/// non-standard microcode generation. Before microcode generation for an
/// instruction all registered object will be visited by the following way:
///   if ( filter->match(cdg) )
///     code = filter->apply(cdg);
///   if ( code == MERR_OK )
///     continue;     // filter generated microcode, go to the next instruction
struct microcode_filter_t
{
  /// check if the filter object is to be applied
  /// \return success
  virtual bool match(codegen_t &cdg) = 0;

  /// generate microcode for an instruction
  /// \return MERR_... code:
  ///   MERR_OK      - user-defined microcode generated, go to the next instruction
  ///   MERR_INSN    - not generated - the caller should try the standard way
  ///   else         - error
  virtual merror_t apply(codegen_t &cdg) = 0;
};

/// register/unregister non-standard microcode generator
/// \param filter  - microcode generator object
/// \param install - TRUE - register the object, FALSE - unregister
/// \return success
bool hexapi install_microcode_filter(microcode_filter_t *filter, bool install=true);

//-------------------------------------------------------------------------
/// Abstract class: User-defined call generator
/// derived classes should implement method 'match'
class udc_filter_t : public microcode_filter_t
{
  udcall_t udc;

public:
  ~udc_filter_t() { cleanup(); }

  /// Cleanup the filter
  /// This function properly clears type information associated to this filter.
  void hexapi cleanup(void);

  /// return true if the filter object should be applied to given instruction
  virtual bool match(codegen_t &cdg) override = 0;

  bool hexapi init(const char *decl);
  virtual merror_t hexapi apply(codegen_t &cdg) override;

  bool empty(void) const { return udc.empty(); }
};

//-------------------------------------------------------------------------
typedef size_t mbitmap_t;
const size_t bitset_width = sizeof(mbitmap_t) * CHAR_BIT;
const size_t bitset_align = bitset_width - 1;
const size_t bitset_shift = 6;

/// Bit set class. See https://en.wikipedia.org/wiki/Bit_array
class bitset_t
{
  mbitmap_t *bitmap;    ///< pointer to bitmap
  size_t high;          ///< highest bit+1 (multiply of bitset_width)

public:
  bitset_t(void) : bitmap(nullptr), high(0) {}
  hexapi bitset_t(const bitset_t &m);          // copy constructor
  ~bitset_t(void)
  {
    qfree(bitmap);
    bitmap = nullptr;
  }
  void swap(bitset_t &r)
  {
    std::swap(bitmap, r.bitmap);
    std::swap(high, r.high);
  }
  bitset_t &operator=(const bitset_t &m) { return copy(m); }
  bitset_t &hexapi copy(const bitset_t &m);    // assignment operator
  bool hexapi add(int bit);                    // add a bit
  bool hexapi add(int bit, int width);         // add bits
  bool hexapi add(const bitset_t &ml);         // add another bitset
  bool hexapi sub(int bit);                    // delete a bit
  bool hexapi sub(int bit, int width);         // delete bits
  bool hexapi sub(const bitset_t &ml);         // delete another bitset
  bool hexapi cut_at(int maxbit);              // delete bits >= maxbit
  void hexapi shift_down(int shift);           // shift bits down
  bool hexapi has(int bit) const;       // test presence of a bit
  bool hexapi has_all(int bit, int width) const; // test presence of bits
  bool hexapi has_any(int bit, int width) const; // test presence of bits
  void print(
        qstring *vout,
        int (*get_bit_name)(qstring *out, int bit, int width, void *ud)=nullptr,
        void *ud=nullptr) const;
  const char *hexapi dstr() const;
  bool hexapi empty(void) const;        // is empty?
  int hexapi count(void) const;         // number of set bits
  int hexapi count(int bit) const;      // get number set bits starting from 'bit'
  int hexapi last(void) const;          // get the number of the last bit (-1-no bits)
  void clear(void) { high = 0; }        // make empty
  void hexapi fill_with_ones(int maxbit);
  bool hexapi fill_gaps(int total_nbits);
  bool hexapi has_common(const bitset_t &ml) const; // has common elements?
  bool hexapi intersect(const bitset_t &ml);    // intersect sets. returns true if changed
  bool hexapi is_subset_of(const bitset_t &ml) const; // is subset of?
  bool includes(const bitset_t &ml) const { return ml.is_subset_of(*this); }
  void extract(intvec_t &out) const;
  DECLARE_COMPARISONS(bitset_t);
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
  class iterator
  {
    friend class bitset_t;
    int i;
  public:
    iterator(int n=-1) : i(n) {}
    bool operator==(const iterator &n) const { return i == n.i; }
    bool operator!=(const iterator &n) const { return i != n.i; }
    int operator*(void) const { return i; }
  };
  typedef iterator const_iterator;
  iterator itat(int n) const { return iterator(goup(n)); }
  iterator begin(void) const { return itat(0); }
  iterator end(void)   const { return iterator(high); }
  int front(void)      const { return *begin(); }
  int back(void)       const { return *end(); }
  void inc(iterator &p, int n=1) const { p.i = goup(p.i+n); }
private:
  int hexapi goup(int reg) const;
};
DECLARE_TYPE_AS_MOVABLE(bitset_t);
typedef qvector<bitset_t> array_of_bitsets;

//-------------------------------------------------------------------------
template <class T>
struct ivl_tpl  // an interval
{
  ivl_tpl() = delete;
public:
  T off;
  T size;
  ivl_tpl(T _off, T _size) : off(_off), size(_size) {}
  bool valid() const { return last() >= off; }
  T end() const { return off + size; }
  T last() const { return off + size - 1; }

  DEFINE_MEMORY_ALLOCATION_FUNCS()
};

//-------------------------------------------------------------------------
typedef ivl_tpl<uval_t> uval_ivl_t;
struct ivl_t : public uval_ivl_t
{
private:
  typedef ivl_tpl<uval_t> inherited;

public:
  ivl_t(uval_t _off=0, uval_t _size=0) : inherited(_off,_size) {}
  bool empty(void) const { return size == 0; }
  void clear(void) { size = 0; }
  void print(qstring *vout) const;
  const char *hexapi dstr(void) const;

  bool extend_to_cover(const ivl_t &r) // extend interval to cover 'r'
  {
    uval_t new_end = end();
    bool changed = false;
    if ( off > r.off )
    {
      off = r.off;
      changed = true;
    }
    if ( new_end < r.end() )
    {
      new_end = r.end();
      changed = true;
    }
    if ( changed )
      size = new_end - off;
    return changed;
  }
  void intersect(const ivl_t &r)
  {
    uval_t new_off = qmax(off, r.off);
    uval_t new_end = end();
    if ( new_end > r.end() )
      new_end = r.end();
    if ( new_off < new_end )
    {
      off = new_off;
      size = new_end - off;
    }
    else
    {
      size = 0;
    }
  }

  // do *this and ivl overlap?
  bool overlap(const ivl_t &ivl) const
  {
    return interval::overlap(off, size, ivl.off, ivl.size);
  }
  // does *this include ivl?
  bool includes(const ivl_t &ivl) const
  {
    return interval::includes(off, size, ivl.off, ivl.size);
  }
  // does *this contain off2?
  bool contains(uval_t off2) const
  {
    return interval::contains(off, size, off2);
  }

  DECLARE_COMPARISONS(ivl_t);
  static const ivl_t allmem;
#define ALLMEM ivl_t::allmem
};
DECLARE_TYPE_AS_MOVABLE(ivl_t);

//-------------------------------------------------------------------------
struct ivl_with_name_t
{
  ivl_t ivl;
  const char *whole;            // name of the whole interval
  const char *part;             // prefix to use for parts of the interval (e.g. sp+4)
  ivl_with_name_t(): ivl(0, BADADDR), whole("<unnamed inteval>"), part(nullptr) {}
  DEFINE_MEMORY_ALLOCATION_FUNCS()
};

//-------------------------------------------------------------------------
template <class Ivl, class T>
class ivlset_tpl // set of intervals
{
public:
  typedef qvector<Ivl> bag_t;

protected:
  bag_t bag;
  bool verify(void) const;
  // we do not store the empty intervals in bag so size == 0 denotes
  // MAX_VALUE<T>+1, e.g. 0x100000000 for uint32
  static bool ivl_all_values(const Ivl &ivl) { return ivl.off == 0 && ivl.size == 0; }

public:
  ivlset_tpl(void) {}
  ivlset_tpl(const Ivl &ivl) { if ( ivl.valid() ) bag.push_back(ivl); }
  DEFINE_MEMORY_ALLOCATION_FUNCS()

  void swap(ivlset_tpl &r) { bag.swap(r.bag); }
  const Ivl &getivl(int idx) const { return bag[idx]; }
  const Ivl &lastivl(void) const { return bag.back(); }
  size_t nivls(void) const { return bag.size(); }
  bool empty(void) const { return bag.empty(); }
  void clear(void) { bag.clear(); }
  void qclear(void) { bag.qclear(); }
  bool all_values() const { return nivls() == 1 && ivl_all_values(bag[0]); }
  void set_all_values() { clear(); bag.push_back(Ivl(0, 0)); }
  bool single_value() const { return nivls() == 1 && bag[0].size == 1; }
  bool single_value(T v) const { return single_value() && bag[0].off == v; }

  bool operator==(const Ivl &v) const { return nivls() == 1 && bag[0] == v; }
  bool operator!=(const Ivl &v) const { return !(*this == v); }

  typedef typename bag_t::iterator iterator;
  typedef typename bag_t::const_iterator const_iterator;
  const_iterator begin(void) const { return bag.begin(); }
  const_iterator end(void)   const { return bag.end(); }
  iterator begin(void) { return bag.begin(); }
  iterator end(void)   { return bag.end(); }
};

//-------------------------------------------------------------------------
/// Set of address intervals.
/// Bit arrays are efficient only for small sets. Potentially huge
/// sets, like memory ranges, require another representation.
/// ivlset_t is used for a list of memory locations in our decompiler.
typedef ivlset_tpl<ivl_t, uval_t> uval_ivl_ivlset_t;
struct ivlset_t : public uval_ivl_ivlset_t
{
  typedef ivlset_tpl<ivl_t, uval_t> inherited;
  ivlset_t() {}
  ivlset_t(const ivl_t &ivl) : inherited(ivl) {}
  bool hexapi add(const ivl_t &ivl);
  bool add(ea_t ea, asize_t size) { return add(ivl_t(ea, size)); }
  bool hexapi add(const ivlset_t &ivs);
  bool hexapi addmasked(const ivlset_t &ivs, const ivl_t &mask);
  bool hexapi sub(const ivl_t &ivl);
  bool sub(ea_t ea, asize_t size) { return sub(ivl_t(ea, size)); }
  bool hexapi sub(const ivlset_t &ivs);
  bool hexapi has_common(const ivl_t &ivl, bool strict=false) const;
  void hexapi print(qstring *vout) const;
  const char *hexapi dstr(void) const;
  asize_t hexapi count(void) const;
  bool hexapi has_common(const ivlset_t &ivs) const;
  bool hexapi contains(uval_t off) const;
  bool hexapi includes(const ivlset_t &ivs) const;
  bool hexapi intersect(const ivlset_t &ivs);

  DECLARE_COMPARISONS(ivlset_t);

};
DECLARE_TYPE_AS_MOVABLE(ivlset_t);
typedef qvector<ivlset_t> array_of_ivlsets;
//-------------------------------------------------------------------------
// We use bitset_t to keep list of registers.
// This is the most optimal storage for them.
class rlist_t : public bitset_t
{
public:
  rlist_t(void) {}
  rlist_t(const rlist_t &m) : bitset_t(m)
  {
  }
  rlist_t(mreg_t reg, int width) { add(reg, width); }
  ~rlist_t(void) {}
  rlist_t &operator=(const rlist_t &) = default;
  void hexapi print(qstring *vout) const;
  const char *hexapi dstr() const;
};
DECLARE_TYPE_AS_MOVABLE(rlist_t);

//-------------------------------------------------------------------------
// Microlist: list of register and memory locations
struct mlist_t
{
  rlist_t reg;         // registers
  ivlset_t mem;        // memory locations

  mlist_t(void) {}
  mlist_t(const ivl_t &ivl) : mem(ivl) {}
  mlist_t(mreg_t r, int size) : reg(r, size) {}

  void swap(mlist_t &r) { reg.swap(r.reg); mem.swap(r.mem); }
  bool hexapi addmem(ea_t ea, asize_t size);
  bool add(mreg_t r, int size) { return add(mlist_t(r, size)); } // also see append_def_list()
  bool add(const rlist_t &r)   { return reg.add(r); }
  bool add(const ivl_t &ivl)   { return add(mlist_t(ivl)); }
  bool add(const mlist_t &lst) { return reg.add(lst.reg) | mem.add(lst.mem); }
  bool sub(mreg_t r, int size) { return sub(mlist_t(r, size)); }
  bool sub(const ivl_t &ivl)   { return sub(mlist_t(ivl)); }
  bool sub(const mlist_t &lst) { return reg.sub(lst.reg) | mem.sub(lst.mem); }
  asize_t count(void) const { return reg.count() + mem.count(); }
  void hexapi print(qstring *vout) const;
  const char *hexapi dstr() const;
  bool empty(void) const { return reg.empty() && mem.empty(); }
  void clear(void) { reg.clear(); mem.clear(); }
  bool has(mreg_t r) const { return reg.has(r); }
  bool has_all(mreg_t r, int size) const { return reg.has_all(r, size); }
  bool has_any(mreg_t r, int size) const { return reg.has_any(r, size); }
  bool has_memory(void) const { return !mem.empty(); }
  bool has_allmem(void) const { return mem == ALLMEM; }
  bool has_common(const mlist_t &lst) const { return reg.has_common(lst.reg) || mem.has_common(lst.mem); }
  bool includes(const mlist_t &lst) const { return reg.includes(lst.reg) && mem.includes(lst.mem); }
  bool intersect(const mlist_t &lst) { return reg.intersect(lst.reg) | mem.intersect(lst.mem); }
  bool is_subset_of(const mlist_t &lst) const { return lst.includes(*this); }

  DECLARE_COMPARISONS(mlist_t);
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
};
DECLARE_TYPE_AS_MOVABLE(mlist_t);
typedef qvector<mlist_t> mlistvec_t;
DECLARE_TYPE_AS_MOVABLE(mlistvec_t);

//-------------------------------------------------------------------------
/// Get list of temporary registers.
/// Tempregs are temporary registers that are used during code generation.
/// They do not map to regular processor registers. They are used only to
/// store temporary values during execution of one instruction.
/// Tempregs may not be used to pass a value from one block to another.
/// In other words, at the end of a block all tempregs must be dead.
const mlist_t &hexapi get_temp_regs(void);

/// Is a kernel register?
/// Kernel registers are temporary registers that can be used freely.
/// They may be used to store values that cross instruction or basic block
/// boundaries. Kernel registers do not map to regular processor registers.
/// See also \ref mba_t::alloc_kreg()
bool hexapi is_kreg(mreg_t r);

/// Map a processor register to a microregister.
/// \param reg   processor register number
/// \return microregister register id or mr_none
mreg_t hexapi reg2mreg(int reg);

/// Map a microregister to a processor register.
/// \param reg   microregister number
/// \param width size of microregister in bytes
/// \return processor register id or -1
int hexapi mreg2reg(mreg_t reg, int width);

/// Get the microregister name.
/// \param out   output buffer, may be nullptr
/// \param reg   microregister number
/// \param width size of microregister in bytes. may be bigger than the real
///              register size.
/// \param ud    reserved, must be nullptr
/// \return width of the printed register. this value may be less than
///         the WIDTH argument.

int hexapi get_mreg_name(qstring *out, mreg_t reg, int width, void *ud=nullptr);

//-------------------------------------------------------------------------
/// User defined callback to optimize individual microcode instructions
struct optinsn_t
{
  /// Optimize an instruction.
  /// \param blk current basic block. maybe nullptr, which means that
  ///            the instruction must be optimized without context
  /// \param ins instruction to optimize; it is always a top-level instruction.
  ///            the callback may not delete the instruction but may
  ///            convert it into nop (see mblock_t::make_nop). to optimize
  ///            sub-instructions, visit them using minsn_visitor_t.
  ///            sub-instructions may not be converted into nop but
  ///            can be converted to "mov x,x". for example:
  ///               add x,0,x => mov x,x
  ///            this callback may change other instructions in the block,
  ///            but should do this with care, e.g. to no break the
  ///            propagation algorithm if called with OPTI_NO_LDXOPT.
  /// \param optflags combination of \ref OPTI_ bits
  /// \return number of changes made to the instruction.
  ///         if after this call the instruction's use/def lists have changed,
  ///         you must mark the block level lists as dirty (see mark_lists_dirty)
  virtual int idaapi func(mblock_t *blk, minsn_t *ins, int optflags) = 0;
};

/// Install an instruction level custom optimizer
/// \param opt an instance of optinsn_t. cannot be destroyed before calling
///        remove_optinsn_handler().
void hexapi install_optinsn_handler(optinsn_t *opt);

/// Remove an instruction level custom optimizer
bool hexapi remove_optinsn_handler(optinsn_t *opt);

/// User defined callback to optimize microcode blocks
struct optblock_t
{
  /// Optimize a block.
  /// This function usually performs the optimizations that require analyzing
  /// the entire block and/or its neighbors. For example it can recognize
  /// patterns and perform conversions like:
  /// b0:                                 b0:
  ///    ...                                 ...
  ///    jnz x, 0, @b2      =>               jnz x, 0, @b2
  /// b1:                                 b1:
  ///    add x, 0, y                         mov x, y
  ///    ...                                 ...
  /// \param blk Basic block to optimize as a whole.
  /// \return number of changes made to the block. See also mark_lists_dirty.
  virtual int idaapi func(mblock_t *blk) = 0;
};

/// Install a block level custom optimizer.
/// \param opt an instance of optblock_t. cannot be destroyed before calling
///        remove_optblock_handler().
void hexapi install_optblock_handler(optblock_t *opt);

/// Remove a block level custom optimizer
bool hexapi remove_optblock_handler(optblock_t *opt);


//-------------------------------------------------------------------------
// abstract graph interface
class simple_graph_t : public gdl_graph_t
{
public:
  qstring title;
  bool colored_gdl_edges;
private:
  friend class iterator;
  virtual int goup(int node) const newapi;
};

//-------------------------------------------------------------------------
// Since our data structures are quite complex, we use the visitor pattern
// in many of our algorthims. This functionality is available for plugins too.
// https://en.wikipedia.org/wiki/Visitor_pattern

// All our visitor callbacks return an integer value.
// Visiting is interrupted as soon an the return value is non-zero.
// This non-zero value is returned as the result of the for_all_... function.
// If for_all_... returns 0, it means that it successfully visited all items.

/// The context info used by visitors
struct op_parent_info_t
{
  mba_t *mba;          // current microcode
  mblock_t *blk;       // current block
  minsn_t *topins;     // top level instruction (parent of curins or curins itself)
  minsn_t *curins;     // currently visited instruction
  op_parent_info_t(
        mba_t *_mba=nullptr,
        mblock_t *_blk=nullptr,
        minsn_t *_topins=nullptr)
    : mba(_mba), blk(_blk), topins(_topins), curins(nullptr) {}
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
  bool really_alloc(void) const;
};

/// Micro instruction visitor.
/// See mba_t::for_all_topinsns, minsn_t::for_all_insns,
///     mblock_::for_all_insns, mba_t::for_all_insns
struct minsn_visitor_t : public op_parent_info_t
{
  minsn_visitor_t(
        mba_t *_mba=nullptr,
        mblock_t *_blk=nullptr,
        minsn_t *_topins=nullptr)
    : op_parent_info_t(_mba, _blk, _topins) {}
  virtual int idaapi visit_minsn(void) = 0;
};

/// Micro operand visitor.
/// See mop_t::for_all_ops, minsn_t::for_all_ops, mblock_t::for_all_insns,
///     mba_t::for_all_insns
struct mop_visitor_t : public op_parent_info_t
{
  mop_visitor_t(
        mba_t *_mba=nullptr,
        mblock_t *_blk=nullptr,
        minsn_t *_topins=nullptr)
    : op_parent_info_t(_mba, _blk, _topins), prune(false) {}
  /// Should skip sub-operands of the current operand?
  /// visit_mop() may set 'prune=true' for that.
  bool prune;
  virtual int idaapi visit_mop(mop_t *op, const tinfo_t *type, bool is_target) = 0;
};

/// Scattered mop: visit each of the scattered locations as a separate mop.
/// See mop_t::for_all_scattered_submops
struct scif_visitor_t
{
  virtual int idaapi visit_scif_mop(const mop_t &r, int off) = 0;
};

// Used operand visitor.
// See mblock_t::for_all_uses
struct mlist_mop_visitor_t
{
  minsn_t *topins;
  minsn_t *curins;
  bool changed;
  mlist_t *list;
  mlist_mop_visitor_t(void): topins(nullptr), curins(nullptr), changed(false), list(nullptr) {}
  virtual int idaapi visit_mop(mop_t *op) = 0;
};

//-------------------------------------------------------------------------
/// Instruction operand types

typedef uint8 mopt_t;
const mopt_t
  mop_z   = 0,  ///< none
  mop_r   = 1,  ///< register (they exist until MMAT_LVARS)
  mop_n   = 2,  ///< immediate number constant
  mop_str = 3,  ///< immediate string constant (user representation)
  mop_d   = 4,  ///< result of another instruction
  mop_S   = 5,  ///< local stack variable (they exist until MMAT_LVARS)
  mop_v   = 6,  ///< global variable
  mop_b   = 7,  ///< micro basic block (mblock_t)
  mop_f   = 8,  ///< list of arguments
  mop_l   = 9,  ///< local variable
  mop_a   = 10, ///< mop_addr_t: address of operand (mop_l, mop_v, mop_S, mop_r)
  mop_h   = 11, ///< helper function
  mop_c   = 12, ///< mcases
  mop_fn  = 13, ///< floating point constant
  mop_p   = 14, ///< operand pair
  mop_sc  = 15; ///< scattered

const int NOSIZE = -1; ///< wrong or unexisting operand size

//-------------------------------------------------------------------------
/// Reference to a local variable. Used by mop_l
struct lvar_ref_t
{
  /// Pointer to the parent mba_t object.
  /// Since we need to access the 'mba->vars' array in order to retrieve
  /// the referenced variable, we keep a pointer to mba_t here.
  /// Note: this means this class and consequently mop_t, minsn_t, mblock_t
  ///       are specific to a mba_t object and cannot migrate between
  ///       them. fortunately this is not something we need to do.
  ///       second, lvar_ref_t's appear only after MMAT_LVARS.
  mba_t *const mba;
  sval_t off;           ///< offset from the beginning of the variable
  int idx;              ///< index into mba->vars
  lvar_ref_t(mba_t *m, int i, sval_t o=0) : mba(m), off(o), idx(i) {}
  lvar_ref_t(const lvar_ref_t &r) : mba(r.mba), off(r.off), idx(r.idx) {}
  lvar_ref_t &operator=(const lvar_ref_t &r)
  {
    off = r.off;
    idx = r.idx;
    return *this;
  }
  DECLARE_COMPARISONS(lvar_ref_t);
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
  void swap(lvar_ref_t &r)
  {
    std::swap(off, r.off);
    std::swap(idx, r.idx);
  }
  lvar_t &hexapi var(void) const;       ///< Retrieve the referenced variable
};

//-------------------------------------------------------------------------
/// Reference to a stack variable. Used for mop_S
struct stkvar_ref_t
{
  /// Pointer to the parent mba_t object.
  /// We need it in order to retrieve the referenced stack variable.
  /// See notes for lvar_ref_t::mba.
  mba_t *const mba;

  /// Offset to the stack variable from the bottom of the stack frame.
  /// It is called 'decompiler stkoff' and it is different from IDA stkoff.
  /// See a note and a picture about 'decompiler stkoff' below.
  sval_t off;

  stkvar_ref_t(mba_t *m, sval_t o) : mba(m), off(o) {}
  DECLARE_COMPARISONS(stkvar_ref_t);
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
  void swap(stkvar_ref_t &r)
  {
    std::swap(off, r.off);
  }
  /// Retrieve the referenced stack variable.
  /// \param p_off if specified, will hold IDA stkoff after the call.
  /// \return pointer to the stack variable
  member_t *hexapi get_stkvar(uval_t *p_off=nullptr) const;
};

//-------------------------------------------------------------------------
/// Scattered operand info. Used for mop_sc
struct scif_t : public vdloc_t
{
  /// Pointer to the parent mba_t object.
  /// Some operations may convert a scattered operand into something simpler,
  /// (a stack operand, for example). We will need to create stkvar_ref_t at
  /// that moment, this is why we need this pointer.
  /// See notes for lvar_ref_t::mba.
  mba_t *mba;

  /// Usually scattered operands are created from a function prototype,
  /// which has the name information. We preserve it and use it to name
  /// the corresponding local variable.
  qstring name;

  /// Scattered operands always have type info assigned to them
  /// because without it we won't be able to manipulte them.
  tinfo_t type;

  scif_t(mba_t *_mba, tinfo_t *tif, qstring *n=nullptr) : mba(_mba)
  {
    if ( n != nullptr )
      n->swap(name);
    tif->swap(type);
  }
  scif_t &operator =(const vdloc_t &loc)
  {
    *(vdloc_t *)this = loc;
    return *this;
  }
};

//-------------------------------------------------------------------------
/// An integer constant. Used for mop_n
/// We support 64-bit values but 128-bit values can be represented with mop_p
struct mnumber_t : public operand_locator_t
{
  uint64 value;
  uint64 org_value;     // original value before changing the operand size
  mnumber_t(uint64 v, ea_t _ea=BADADDR, int n=0)
    : operand_locator_t(_ea, n), value(v), org_value(v) {}
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
  DECLARE_COMPARISONS(mnumber_t)
  {
    if ( value < r.value )
      return -1;
    if ( value > r.value )
      return -1;
    return 0;
  }
  // always use this function instead of manually modifying the 'value' field
  void update_value(uint64 val64)
  {
    value = val64;
    org_value = val64;
  }
};

//-------------------------------------------------------------------------
/// Floating point constant. Used for mop_fn
/// For more details, please see the ieee.h file from IDA SDK.
struct fnumber_t
{
  fpvalue_t fnum;       ///< Internal representation of the number
  int nbytes;           ///< Original size of the constant in bytes
  operator       uint16 *(void)       { return fnum.w; }
  operator const uint16 *(void) const { return fnum.w; }
  void hexapi print(qstring *vout) const;
  const char *hexapi dstr() const;
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
  DECLARE_COMPARISONS(fnumber_t)
  {
    return ecmp(fnum, r.fnum);
  }
};

//-------------------------------------------------------------------------
/// \defgroup SHINS_ Bits to control how we print instructions
//@{
#define SHINS_NUMADDR 0x01 ///< display definition addresses for numbers
#define SHINS_VALNUM  0x02 ///< display value numbers
#define SHINS_SHORT   0x04 ///< do not display use-def chains and other attrs
#define SHINS_LDXEA   0x08 ///< display address of ldx expressions (not used)
//@}

//-------------------------------------------------------------------------
/// How to handle side effect of change_size()
/// Sometimes we need to create a temporary operand and change its size in order
/// to check some hypothesis. If we revert our changes, we do not want that the
/// database (global variables, stack frame, etc) changes in any manner.
enum side_effect_t
{
  NO_SIDEFF,          ///< change operand size but ignore side effects
                      ///< if you decide to keep the changed operand,
                      ///< handle_new_size() must be called
  WITH_SIDEFF,        ///< change operand size and handle side effects
  ONLY_SIDEFF,        ///< only handle side effects
  ANY_REGSIZE = 0x80, ///< any register size is permitted
  ANY_FPSIZE = 0x100, ///< any size of floating operand is permitted
};

//-------------------------------------------------------------------------
/// A microinstruction operand.
/// This is the smallest building block of our microcode.
/// Operands will be part of instructions, which are then grouped into basic blocks.
/// The microcode consists of an array of such basic blocks + some additional info.
class mop_t
{
  void hexapi copy(const mop_t &rop);
public:
  /// Operand type.
  mopt_t t;

  /// Operand properties.
  uint8 oprops;
#define OPROP_IMPDONE 0x01 ///< imported operand (a pointer) has been dereferenced
#define OPROP_UDT     0x02 ///< a struct or union
#define OPROP_FLOAT   0x04 ///< possibly floating value
#define OPROP_CCFLAGS 0x08 ///< mop_n: a pc-relative value
                           ///< mop_a: an address obtained from a relocation
                           ///< else: value of a condition code register (like mr_cc)
#define OPROP_UDEFVAL 0x10 ///< uses undefined value
#define OPROP_LOWADDR 0x20 ///< a low address offset

  /// Value number.
  /// Zero means unknown.
  /// Operands with the same value number are equal.
  uint16 valnum;

  /// Operand size.
  /// Usually it is 1,2,4,8 or NOSIZE but for UDTs other sizes are permitted
  int size;

  /// The following union holds additional details about the operand.
  /// Depending on the operand type different kinds of info are stored.
  /// You should access these fields only after verifying the operand type.
  /// All pointers are owned by the operand and are freed by its destructor.
  union
  {
    mreg_t r;           // mop_r   register number
    mnumber_t *nnn;     // mop_n   immediate value
    minsn_t *d;         // mop_d   result (destination) of another instruction
    stkvar_ref_t *s;    // mop_S   stack variable
    ea_t g;             // mop_v   global variable (its linear address)
    int b;              // mop_b   block number (used in jmp,call instructions)
    mcallinfo_t *f;     // mop_f   function call information
    lvar_ref_t *l;      // mop_l   local variable
    mop_addr_t *a;      // mop_a   variable whose address is taken
    char *helper;       // mop_h   helper function name
    char *cstr;         // mop_str utf8 string constant, user representation
    mcases_t *c;        // mop_c   cases
    fnumber_t *fpc;     // mop_fn  floating point constant
    mop_pair_t *pair;   // mop_p   operand pair
    scif_t *scif;       // mop_sc  scattered operand info
  };
  // -- End of data fields, member function declarations follow:

  void set_impptr_done(void) { oprops |= OPROP_IMPDONE; }
  void set_udt(void)         { oprops |= OPROP_UDT; }
  void set_undef_val(void)   { oprops |= OPROP_UDEFVAL; }
  void set_lowaddr(void)     { oprops |= OPROP_LOWADDR; }
  bool is_impptr_done(void) const { return (oprops & OPROP_IMPDONE) != 0; }
  bool is_udt(void)         const { return (oprops & OPROP_UDT) != 0; }
  bool probably_floating(void) const { return (oprops & OPROP_FLOAT) != 0; }
  bool is_undef_val(void)   const { return (oprops & OPROP_UDEFVAL) != 0; }
  bool is_lowaddr(void)     const { return (oprops & OPROP_LOWADDR) != 0; }
  bool is_ccflags(void) const
  {
    return (oprops & OPROP_CCFLAGS) != 0
        && (t == mop_l || t == mop_v || t == mop_S || t == mop_r);
  }
  bool is_pcval(void) const
  {
    return t == mop_n && (oprops & OPROP_CCFLAGS) != 0;
  }
  bool is_glbaddr_from_fixup() const
  {
    return is_glbaddr() && (oprops & OPROP_CCFLAGS) != 0;
  }

  mop_t(void) { zero(); }
  mop_t(const mop_t &rop) { copy(rop); }
  mop_t(mreg_t _r, int _s) : t(mop_r), oprops(0), valnum(0), size(_s), r(_r) {}
  mop_t &operator=(const mop_t &rop) { return assign(rop); }
  mop_t &hexapi assign(const mop_t &rop);
  ~mop_t(void)
  {
    erase();
  }
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
  void zero() { t = mop_z; oprops = 0; valnum = 0; size = NOSIZE; nnn = nullptr; }
  void hexapi swap(mop_t &rop);
  void hexapi erase(void);
  void erase_but_keep_size(void) { int s2 = size; erase(); size = s2; }

  void hexapi print(qstring *vout, int shins_flags=SHINS_SHORT|SHINS_VALNUM) const;
  const char *hexapi dstr() const; // use this function for debugging

  //-----------------------------------------------------------------------
  // Operand creation
  //-----------------------------------------------------------------------
  /// Create operand from mlist_t.
  /// Example: if LST contains 4 bits for R0.4, our operand will be
  ///          (t=mop_r, r=R0, size=4)
  /// \param mba pointer to microcode
  /// \param lst list of locations
  /// \param fullsize mba->fullsize
  /// \return success
  bool hexapi create_from_mlist(mba_t *mba, const mlist_t &lst, sval_t fullsize);

  /// Create operand from ivlset_t.
  /// Example: if IVS contains [glbvar..glbvar+4), our operand will be
  ///          (t=mop_v, g=&glbvar, size=4)
  /// \param mba pointer to microcode
  /// \param ivs set of memory intervals
  /// \param fullsize mba->fullsize
  /// \return success
  bool hexapi create_from_ivlset(mba_t *mba, const ivlset_t &ivs, sval_t fullsize);

  /// Create operand from vdloc_t.
  /// Example: if LOC contains (type=ALOC_REG1, r=R0), our operand will be
  ///          (t=mop_r, r=R0, size=_SIZE)
  /// \param mba pointer to microcode
  /// \param loc location
  /// \param _size operand size
  /// Note: this function cannot handle scattered locations.
  /// \return success
  void hexapi create_from_vdloc(mba_t *mba, const vdloc_t &loc, int _size);

  /// Create operand from scattered vdloc_t.
  /// Example: if LOC is (ALOC_DIST, {EAX.4, EDX.4}) and TYPE is _LARGE_INTEGER,
  /// our operand will be
  ///          (t=mop_sc, scif={EAX.4, EDX.4})
  /// \param mba pointer to microcode
  /// \param name name of the operand, if available
  /// \param type type of the operand, must be present
  /// \param loc a scattered location
  /// \return success
  void hexapi create_from_scattered_vdloc(
        mba_t *mba,
        const char *name,
        tinfo_t type,
        const vdloc_t &loc);

  /// Create operand from an instruction.
  /// This function creates a nested instruction that can be used as an operand.
  /// Example: if m="add x,y,z", our operand will be (t=mop_d,d=m).
  /// The destination operand of 'add' (z) is lost.
  /// \param m instruction to embed into operand. may not be nullptr.
  void hexapi create_from_insn(const minsn_t *m);

  /// Create an integer constant operand.
  /// \param _value value to store in the operand
  /// \param _size size of the value in bytes (1,2,4,8)
  /// \param _ea   address of the processor instruction that made the value
  /// \param opnum operand number of the processor instruction
  void hexapi make_number(uint64 _value, int _size, ea_t _ea=BADADDR, int opnum=0);

  /// Create a floating point constant operand.
  /// \param bytes pointer to the floating point value as used by the current
  ///              processor (e.g. for x86 it must be in IEEE 754)
  /// \param _size number of bytes occupied by the constant.
  /// \return success
  bool hexapi make_fpnum(const void *bytes, size_t _size);

  /// Create a register operand without erasing previous data.
  /// \param reg  micro register number
  /// Note: this function does not erase the previous contents of the operand;
  ///       call erase() if necessary
  void _make_reg(mreg_t reg)
  {
    t = mop_r;
    r = reg;
  }
  void _make_reg(mreg_t reg, int _size)
  {
    t = mop_r;
    r = reg;
    size = _size;
  }
  /// Create a register operand.
  void make_reg(mreg_t reg) { erase(); _make_reg(reg); }
  void make_reg(mreg_t reg, int _size) { erase(); _make_reg(reg, _size); }

  /// Create a local variable operand.
  /// \param mba pointer to microcode
  /// \param idx index into mba->vars
  /// \param off offset from the beginning of the variable
  /// Note: this function does not erase the previous contents of the operand;
  ///       call erase() if necessary
  void _make_lvar(mba_t *mba, int idx, sval_t off=0)
  {
    t = mop_l;
    l = new lvar_ref_t(mba, idx, off);
  }

  /// Create a global variable operand without erasing previous data.
  /// \param ea  address of the variable
  /// Note: this function does not erase the previous contents of the operand;
  ///       call erase() if necessary
  void hexapi _make_gvar(ea_t ea);
  /// Create a global variable operand.
  void hexapi make_gvar(ea_t ea);

  /// Create a stack variable operand.
  /// \param mba pointer to microcode
  /// \param off decompiler stkoff
  /// Note: this function does not erase the previous contents of the operand;
  ///       call erase() if necessary
  void _make_stkvar(mba_t *mba, sval_t off)
  {
    t = mop_S;
    s = new stkvar_ref_t(mba, off);
  }
  void make_stkvar(mba_t *mba, sval_t off) { erase(); _make_stkvar(mba, off); }

  /// Create pair of registers.
  /// \param loreg register holding the low part of the value
  /// \param hireg register holding the high part of the value
  /// \param halfsize the size of each of loreg/hireg
  void hexapi make_reg_pair(int loreg, int hireg, int halfsize);

  /// Create a nested instruction without erasing previous data.
  /// \param ins pointer to the instruction to encapsulate into the operand
  /// Note: this function does not erase the previous contents of the operand;
  ///       call erase() if necessary
  /// See also create_from_insn, which is higher level
  void _make_insn(minsn_t *ins);
  /// Create a nested instruction.
  void make_insn(minsn_t *ins) { erase(); _make_insn(ins); }

  /// Create a block reference operand without erasing previous data.
  /// \param blknum block number
  /// Note: this function does not erase the previous contents of the operand;
  ///       call erase() if necessary
  void _make_blkref(int blknum)
  {
    t = mop_b;
    b = blknum;
  }
  /// Create a global variable operand.
  void make_blkref(int blknum) { erase(); _make_blkref(blknum); }

  /// Create a helper operand.
  /// A helper operand usually keeps a built-in function name like "va_start"
  /// It is essentially just an arbitrary identifier without any additional info.
  void hexapi make_helper(const char *name);

  /// Create a constant string operand.
  void _make_strlit(const char *str)
  {
    t = mop_str;
    cstr = ::qstrdup(str);
  }
  void _make_strlit(qstring *str) // str is consumed
  {
    t = mop_str;
    cstr = str->extract();
  }

  /// Create a call info operand without erasing previous data.
  /// \param fi callinfo
  /// Note: this function does not erase the previous contents of the operand;
  ///       call erase() if necessary
  void _make_callinfo(mcallinfo_t *fi)
  {
    t = mop_f;
    f = fi;
  }

  /// Create a 'switch cases' operand without erasing previous data.
  /// Note: this function does not erase the previous contents of the operand;
  ///       call erase() if necessary
  void _make_cases(mcases_t *_cases)
  {
    t = mop_c;
    c = _cases;
  }

  /// Create a pair operand without erasing previous data.
  /// Note: this function does not erase the previous contents of the operand;
  ///       call erase() if necessary
  void _make_pair(mop_pair_t *_pair)
  {
    t = mop_p;
    pair = _pair;
  }

  //-----------------------------------------------------------------------
  // Various operand tests
  //-----------------------------------------------------------------------
  bool empty(void) const { return t == mop_z; }
  /// Is a register operand?
  /// See also get_mreg_name()
  bool is_reg(void) const { return t == mop_r; }
  /// Is the specified register?
  bool is_reg(mreg_t _r) const { return t == mop_r && r == _r; }
  /// Is the specified register of the specified size?
  bool is_reg(mreg_t _r, int _size) const { return t == mop_r && r == _r && size == _size; }
  /// Is a list of arguments?
  bool is_arglist(void) const { return t == mop_f; }
  /// Is a condition code?
  bool is_cc(void) const { return is_reg() && r >= mr_cf && r < mr_first; }
  /// Is a bit register?
  /// This includes condition codes and eventually other bit registers
  static bool hexapi is_bit_reg(mreg_t reg);
  bool is_bit_reg(void) const { return is_reg() && is_bit_reg(r); }
  /// Is a kernel register?
  bool is_kreg(void) const;
  /// Is a block reference to the specified block?
  bool is_mob(int serial) const { return t == mop_b && b == serial; }
  /// Is a scattered operand?
  bool is_scattered(void) const { return t == mop_sc; }
  /// Is address of a global memory cell?
  bool is_glbaddr() const;
  /// Is address of the specified global memory cell?
  bool is_glbaddr(ea_t ea) const;
  /// Is address of a stack variable?
  bool is_stkaddr() const;
  /// Is a sub-instruction?
  bool is_insn(void) const { return t == mop_d; }
  /// Is a sub-instruction with the specified opcode?
  bool is_insn(mcode_t code) const;
  /// Has any side effects?
  /// \param include_ldx_and_divs consider ldx/div/mod as having side effects?
  bool has_side_effects(bool include_ldx_and_divs=false) const;
  /// Is it possible for the operand to use aliased memory?
  bool hexapi may_use_aliased_memory(void) const;

  /// Are the possible values of the operand only 0 and 1?
  /// This function returns true for 0/1 constants, bit registers,
  /// the result of 'set' insns, etc.
  bool hexapi is01(void) const;

  /// Does the high part of the operand consist of the sign bytes?
  /// \param nbytes number of bytes that were sign extended.
  ///               the remaining size-nbytes high bytes must be sign bytes
  /// Example: is_sign_extended_from(xds.4(op.1), 1) -> true
  ///          because the high 3 bytes are certainly sign bits
  bool hexapi is_sign_extended_from(int nbytes) const;

  /// Does the high part of the operand consist of zero bytes?
  /// \param nbytes number of bytes that were zero extended.
  ///               the remaining size-nbytes high bytes must be zero
  /// Example: is_zero_extended_from(xdu.8(op.1), 2) -> true
  ///          because the high 6 bytes are certainly zero
  bool hexapi is_zero_extended_from(int nbytes) const;

  /// Does the high part of the operand consist of zero or sign bytes?
  bool is_extended_from(int nbytes, bool is_signed) const
  {
    if ( is_signed )
      return is_sign_extended_from(nbytes);
    else
      return is_zero_extended_from(nbytes);
  }

  //-----------------------------------------------------------------------
  // Comparisons
  //-----------------------------------------------------------------------
  /// Compare operands.
  /// This is the main comparison function for operands.
  /// \param rop     operand to compare with
  /// \param eqflags combination of \ref EQ_ bits
  bool hexapi equal_mops(const mop_t &rop, int eqflags) const;
  bool operator==(const mop_t &rop) const { return  equal_mops(rop, 0); }
  bool operator!=(const mop_t &rop) const { return !equal_mops(rop, 0); }

  /// Lexographical operand comparison.
  /// It can be used to store mop_t in various containers, like std::set
  bool operator <(const mop_t &rop) const { return lexcompare(rop) < 0; }
  friend int lexcompare(const mop_t &a, const mop_t &b) { return a.lexcompare(b); }
  int hexapi lexcompare(const mop_t &rop) const;

  //-----------------------------------------------------------------------
  // Visiting operand parts
  //-----------------------------------------------------------------------
  /// Visit the operand and all its sub-operands.
  /// This function visits the current operand as well.
  /// \param mv        visitor object
  /// \param type      operand type
  /// \param is_target is a destination operand?
  int hexapi for_all_ops(
        mop_visitor_t &mv,
        const tinfo_t *type=nullptr,
        bool is_target=false);

  /// Visit all sub-operands of a scattered operand.
  /// This function does not visit the current operand, only its sub-operands.
  /// All sub-operands are synthetic and are destroyed after the visitor.
  /// This function works only with scattered operands.
  /// \param sv        visitor object
  int hexapi for_all_scattered_submops(scif_visitor_t &sv) const;

  //-----------------------------------------------------------------------
  // Working with mop_n operands
  //-----------------------------------------------------------------------
  /// Retrieve value of a constant integer operand.
  /// These functions can be called only for mop_n operands.
  /// See is_constant() that can be called on any operand.
  uint64 value(bool is_signed) const { return extend_sign(nnn->value, size, is_signed); }
  int64 signed_value(void) const { return value(true); }
  uint64 unsigned_value(void) const { return value(false); }
  void update_numop_value(uint64 val)
  {
    nnn->update_value(extend_sign(val, size, false));
  }

  /// Retrieve value of a constant integer operand.
  /// \param out pointer to the output buffer
  /// \param is_signed should treat the value as signed
  /// \return true if the operand is mop_n
  bool hexapi is_constant(uint64 *out=nullptr, bool is_signed=true) const;

  bool is_equal_to(uint64 n, bool is_signed=true) const
  {
    uint64 v;
    return is_constant(&v, is_signed) && v == n;
  }
  bool is_zero(void) const { return is_equal_to(0, false); }
  bool is_one(void) const { return is_equal_to(1, false); }
  bool is_positive_constant(void) const
  {
    uint64 v;
    return is_constant(&v, true) && int64(v) > 0;
  }
  bool is_negative_constant(void) const
  {
    uint64 v;
    return is_constant(&v, true) && int64(v) < 0;
  }

  //-----------------------------------------------------------------------
  // Working with mop_S operands
  //-----------------------------------------------------------------------
  /// Retrieve the referenced stack variable.
  /// \param p_off if specified, will hold IDA stkoff after the call.
  /// \return pointer to the stack variable
  member_t *get_stkvar(uval_t *p_off) const { return s->get_stkvar(p_off); }

  /// Get the referenced stack offset.
  /// This function can also handle mop_sc if it is entirely mapped into
  /// a continuous stack region.
  /// \param p_off the output buffer
  /// \return success
  bool hexapi get_stkoff(sval_t *p_off) const;

  //-----------------------------------------------------------------------
  // Working with mop_d operands
  //-----------------------------------------------------------------------
  /// Get subinstruction of the operand.
  /// If the operand has a subinstruction with the specified opcode, return it.
  /// \param code desired opcode
  /// \return pointer to the instruction or nullptr
  const minsn_t *get_insn(mcode_t code) const;
        minsn_t *get_insn(mcode_t code);

  //-----------------------------------------------------------------------
  // Transforming operands
  //-----------------------------------------------------------------------
  /// Make the low part of the operand.
  /// This function takes into account the memory endianness (byte sex)
  /// \param width the desired size of the operand part in bytes
  /// \return success
  bool hexapi make_low_half(int width);

  /// Make the high part of the operand.
  /// This function takes into account the memory endianness (byte sex)
  /// \param width the desired size of the operand part in bytes
  /// \return success
  bool hexapi make_high_half(int width);

  /// Make the first part of the operand.
  /// This function does not care about the memory endianness
  /// \param width the desired size of the operand part in bytes
  /// \return success
  bool hexapi make_first_half(int width);

  /// Make the second part of the operand.
  /// This function does not care about the memory endianness
  /// \param width the desired size of the operand part in bytes
  /// \return success
  bool hexapi make_second_half(int width);

  /// Shift the operand.
  /// This function shifts only the beginning of the operand.
  /// The operand size will be changed.
  /// Examples: shift_mop(AH.1, -1) -> AX.2
  ///           shift_mop(qword_00000008.8, 4) -> dword_0000000C.4
  ///           shift_mop(xdu.8(op.4), 4) -> #0.4
  ///           shift_mop(#0x12345678.4, 3) -> #12.1
  /// \param offset shift count (the number of bytes to shift)
  /// \return success
  bool hexapi shift_mop(int offset);

  /// Change the operand size.
  /// Examples: change_size(AL.1, 2) -> AX.2
  ///           change_size(qword_00000008.8, 4) -> dword_00000008.4
  ///           change_size(xdu.8(op.4), 4) -> op.4
  ///           change_size(#0x12345678.4, 1) -> #0x78.1
  /// \param nsize  new operand size
  /// \param sideff may modify the database because of the size change?
  /// \return success
  bool hexapi change_size(int nsize, side_effect_t sideff=WITH_SIDEFF);
  bool double_size(side_effect_t sideff=WITH_SIDEFF) { return change_size(size*2, sideff); }

  /// Move subinstructions with side effects out of the operand.
  /// If we decide to delete an instruction operand, it is a good idea to
  /// call this function. Alternatively we should skip such operands
  /// by calling mop_t::has_side_effects()
  /// For example, if we transform: jnz x, x, @blk => goto @blk
  /// then we must call this function before deleting the X operands.
  /// \param blk  current block
  /// \param top  top level instruction that contains our operand
  /// \param moved_calls pointer to the boolean that will track if all side
  ///                    effects get handled correctly. must be false initially.
  /// \return false failed to preserve a side effect, it is not safe to
  ///               delete the operand
  ///         true  no side effects or successfully preserved them
  bool hexapi preserve_side_effects(
        mblock_t *blk,
        minsn_t *top,
        bool *moved_calls=nullptr);

  /// Apply a unary opcode to the operand.
  /// \param mcode   opcode to apply. it must accept 'l' and 'd' operands
  ///                but not 'r'. examples: m_low/m_high/m_xds/m_xdu
  /// \param ea      value of minsn_t::ea for the newly created insruction
  /// \param newsize new operand size
  /// Example: apply_ld_mcode(m_low) will convert op => low(op)
  void hexapi apply_ld_mcode(mcode_t mcode, ea_t ea, int newsize);
  void apply_xdu(ea_t ea, int newsize) { apply_ld_mcode(m_xdu, ea, newsize); }
  void apply_xds(ea_t ea, int newsize) { apply_ld_mcode(m_xds, ea, newsize); }
};
DECLARE_TYPE_AS_MOVABLE(mop_t);

/// Pair of operands
class mop_pair_t
{
public:
  mop_t lop;            ///< low operand
  mop_t hop;            ///< high operand
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
};

/// Address of an operand (mop_l, mop_v, mop_S, mop_r)
class mop_addr_t : public mop_t
{
public:
  int insize;   // how many bytes of the pointed operand can be read
  int outsize;  // how many bytes of the pointed operand can be written

  mop_addr_t(): insize(NOSIZE), outsize(NOSIZE) {}
  mop_addr_t(const mop_addr_t &ra)
    : mop_t(ra), insize(ra.insize), outsize(ra.outsize) {}
  mop_addr_t(const mop_t &ra, int isz, int osz)
    : mop_t(ra), insize(isz), outsize(osz) {}

  mop_addr_t &operator=(const mop_addr_t &rop)
  {
    *(mop_t *)this = mop_t(rop);
    insize = rop.insize;
    outsize = rop.outsize;
    return *this;
  }
  int lexcompare(const mop_addr_t &ra) const
  {
    int code = mop_t::lexcompare(ra);
    return code    != 0          ? code
         : insize  != ra.insize  ? (insize-ra.insize)
         : outsize != ra.outsize ? (outsize-ra.outsize)
         :                         0;
  }
};

/// A call argument
class mcallarg_t : public mop_t // #callarg
{
public:
  ea_t ea = BADADDR;            ///< address where the argument was initialized.
                                ///< BADADDR means unknown.
  tinfo_t type;                 ///< formal argument type
  qstring name;                 ///< formal argument name
  argloc_t argloc;              ///< ida argloc
  uint32 flags = 0;             ///< FAI_...

  mcallarg_t() {}
  mcallarg_t(const mop_t &rarg) : mop_t(rarg) {}
  void copy_mop(const mop_t &op) { *(mop_t *)this = op; }
  void hexapi print(qstring *vout, int shins_flags=SHINS_SHORT|SHINS_VALNUM) const;
  const char *hexapi dstr() const;
  void hexapi set_regarg(mreg_t mr, int sz, const tinfo_t &tif);
  void set_regarg(mreg_t mr, const tinfo_t &tif)
  {
    set_regarg(mr, tif.get_size(), tif);
  }
  void set_regarg(mreg_t mr, char dt, type_sign_t sign = type_unsigned)
  {
    int sz = get_dtype_size(dt);
    set_regarg(mr, sz, get_int_type_by_width_and_sign(sz, sign));
  }
  void make_int(int val, ea_t val_ea, int opno = 0)
  {
    type = tinfo_t(BTF_INT);
    make_number(val, inf_get_cc_size_i(), val_ea, opno);
  }
  void make_uint(int val, ea_t val_ea, int opno = 0)
  {
    type = tinfo_t(BTF_UINT);
    make_number(val, inf_get_cc_size_i(), val_ea, opno);
  }
};
DECLARE_TYPE_AS_MOVABLE(mcallarg_t);
typedef qvector<mcallarg_t> mcallargs_t;

/// Function roles.
/// They are used to calculate use/def lists and to recognize functions
/// without using string comparisons.
enum funcrole_t
{
  ROLE_UNK,                  ///< unknown function role
  ROLE_EMPTY,                ///< empty, does not do anything (maybe spoils regs)
  ROLE_MEMSET,               ///< memset(void *dst, uchar value, size_t count);
  ROLE_MEMSET32,             ///< memset32(void *dst, uint32 value, size_t count);
  ROLE_MEMSET64,             ///< memset64(void *dst, uint64 value, size_t count);
  ROLE_MEMCPY,               ///< memcpy(void *dst, const void *src, size_t count);
  ROLE_STRCPY,               ///< strcpy(char *dst, const char *src);
  ROLE_STRLEN,               ///< strlen(const char *src);
  ROLE_STRCAT,               ///< strcat(char *dst, const char *src);
  ROLE_TAIL,                 ///< char *tail(const char *str);
  ROLE_BUG,                  ///< BUG() helper macro: never returns, causes exception
  ROLE_ALLOCA,               ///< alloca() function
  ROLE_BSWAP,                ///< bswap() function (any size)
  ROLE_PRESENT,              ///< present() function (used in patterns)
  ROLE_CONTAINING_RECORD,    ///< CONTAINING_RECORD() macro
  ROLE_FASTFAIL,             ///< __fastfail()
  ROLE_READFLAGS,            ///< __readeflags, __readcallersflags
  ROLE_IS_MUL_OK,            ///< is_mul_ok
  ROLE_SATURATED_MUL,        ///< saturated_mul
  ROLE_BITTEST,              ///< [lock] bt
  ROLE_BITTESTANDSET,        ///< [lock] bts
  ROLE_BITTESTANDRESET,      ///< [lock] btr
  ROLE_BITTESTANDCOMPLEMENT, ///< [lock] btc
  ROLE_VA_ARG,               ///< va_arg() macro
  ROLE_VA_COPY,              ///< va_copy() function
  ROLE_VA_START,             ///< va_start() function
  ROLE_VA_END,               ///< va_end() function
  ROLE_ROL,                  ///< rotate left
  ROLE_ROR,                  ///< rotate right
  ROLE_CFSUB3,               ///< carry flag after subtract with carry
  ROLE_OFSUB3,               ///< overflow flag after subtract with carry
  ROLE_ABS,                  ///< integer absolute value
  ROLE_3WAYCMP0,             ///< 3-way compare helper, returns -1/0/1
  ROLE_3WAYCMP1,             ///< 3-way compare helper, returns 0/1/2
  ROLE_WMEMCPY,              ///< wchar_t *wmemcpy(wchar_t *dst, const wchar_t *src, size_t n)
  ROLE_WMEMSET,              ///< wchar_t *wmemset(wchar_t *dst, wchar_t wc, size_t n)
  ROLE_WCSCPY,               ///< wchar_t *wcscpy(wchar_t *dst, const wchar_t *src);
  ROLE_WCSLEN,               ///< size_t wcslen(const wchar_t *s)
  ROLE_WCSCAT,               ///< wchar_t *wcscat(wchar_t *dst, const wchar_t *src)
  ROLE_SSE_CMP4,             ///< e.g. _mm_cmpgt_ss
  ROLE_SSE_CMP8,             ///< e.g. _mm_cmpgt_sd
};

/// \defgroup FUNC_NAME_ Well known function names
//@{
#define FUNC_NAME_MEMCPY   "memcpy"
#define FUNC_NAME_WMEMCPY  "wmemcpy"
#define FUNC_NAME_MEMSET   "memset"
#define FUNC_NAME_WMEMSET  "wmemset"
#define FUNC_NAME_MEMSET32 "memset32"
#define FUNC_NAME_MEMSET64 "memset64"
#define FUNC_NAME_STRCPY   "strcpy"
#define FUNC_NAME_WCSCPY   "wcscpy"
#define FUNC_NAME_STRLEN   "strlen"
#define FUNC_NAME_WCSLEN   "wcslen"
#define FUNC_NAME_STRCAT   "strcat"
#define FUNC_NAME_WCSCAT   "wcscat"
#define FUNC_NAME_TAIL     "tail"
#define FUNC_NAME_VA_ARG   "va_arg"
#define FUNC_NAME_EMPTY    "$empty"
#define FUNC_NAME_PRESENT  "$present"
#define FUNC_NAME_CONTAINING_RECORD "CONTAINING_RECORD"
//@}


// the default 256 function arguments is too big, we use a lower value
#undef MAX_FUNC_ARGS
#define MAX_FUNC_ARGS 64

/// Information about a call
class mcallinfo_t               // #callinfo
{
public:
  ea_t callee;                  ///< address of the called function, if known
  int solid_args;               ///< number of solid args.
                                ///< there may be variadic args in addtion
  int call_spd;                 ///< sp value at call insn
  int stkargs_top;              ///< first offset past stack arguments
  cm_t cc;                      ///< calling convention
  mcallargs_t args;             ///< call arguments
  mopvec_t retregs;             ///< return register(s) (e.g., AX, AX:DX, etc.)
                                ///< this vector is built from return_regs
  tinfo_t return_type;          ///< type of the returned value
  argloc_t return_argloc;       ///< location of the returned value

  mlist_t return_regs;          ///< list of values returned by the function
  mlist_t spoiled;              ///< list of spoiled locations (includes return_regs)
  mlist_t pass_regs;            ///< passthrough registers: registers that depend on input
                                ///< values (subset of spoiled)
  ivlset_t visible_memory;      ///< what memory is visible to the call?
  mlist_t dead_regs;            ///< registers defined by the function but never used.
                                ///< upon propagation we do the following:
                                ///<   - dead_regs += return_regs
                                ///<   - retregs.clear() since the call is propagated
  int flags;                    ///< combination of \ref FCI_... bits
/// \defgroup FCI_ Call properties
//@{
#define FCI_PROP    0x001       ///< call has been propagated
#define FCI_DEAD    0x002       ///< some return registers were determined dead
#define FCI_FINAL   0x004       ///< call type is final, should not be changed
#define FCI_NORET   0x008       ///< call does not return
#define FCI_PURE    0x010       ///< pure function
#define FCI_NOSIDE  0x020       ///< call does not have side effects
#define FCI_SPLOK   0x040       ///< spoiled/visible_memory lists have been
                                ///< optimized. for some functions we can reduce them
                                ///< as soon as information about the arguments becomes
                                ///< available. in order not to try optimize them again
                                ///< we use this bit.
#define FCI_HASCALL 0x080       ///< A function is an synthetic helper combined
                                ///< from several instructions and at least one
                                ///< of them was a call to a real functions
#define FCI_HASFMT  0x100       ///< A variadic function with recognized
                                ///< printf- or scanf-style format string
#define FCI_EXPLOCS 0x400       ///< all arglocs are specified explicitly
//@}
  funcrole_t role;              ///< function role
  type_attrs_t fti_attrs;       ///< extended function attributes

  mcallinfo_t(ea_t _callee=BADADDR, int _sargs=0)
    : callee(_callee), solid_args(_sargs), call_spd(0), stkargs_top(0),
      cc(CM_CC_INVALID), flags(0), role(ROLE_UNK) {}
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
  int hexapi lexcompare(const mcallinfo_t &f) const;
  bool hexapi set_type(const tinfo_t &type);
  tinfo_t hexapi get_type(void) const;
  bool is_vararg(void) const { return is_vararg_cc(cc); }
  void hexapi print(qstring *vout, int size=-1, int shins_flags=SHINS_SHORT|SHINS_VALNUM) const;
  const char *hexapi dstr() const;
};

/// List of switch cases and targets
class mcases_t                  // #cases
{
public:
  casevec_t values;             ///< expression values for each target
  intvec_t targets;             ///< target block numbers

  void swap(mcases_t &r) { values.swap(r.values); targets.swap(r.targets); }
  DECLARE_COMPARISONS(mcases_t);
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
  bool empty(void) const { return targets.empty(); }
  size_t size(void) const { return targets.size(); }
  void resize(int s) { values.resize(s); targets.resize(s); }
  void hexapi print(qstring *vout) const;
  const char *hexapi dstr() const;
};

//-------------------------------------------------------------------------
/// Value offset (microregister number or stack offset)
struct voff_t
{
  sval_t off;         ///< register number or stack offset
  mopt_t type;        ///< mop_r - register, mop_S - stack, mop_z - undefined

  voff_t() : off(-1), type(mop_z) {}
  voff_t(mopt_t _type, sval_t _off) : off(_off), type(_type) {}
  voff_t(const mop_t &op) : off(-1), type(mop_z)
  {
    if ( op.is_reg() || op.t == mop_S )
      set(op.t, op.is_reg() ? op.r : op.s->off);
  }

  void set(mopt_t _type, sval_t _off) { type = _type; off = _off; }
  void set_stkoff(sval_t stkoff)      { set(mop_S, stkoff); }
  void set_reg(mreg_t mreg)           { set(mop_r, mreg); }
  void undef()                        { set(mop_z, -1); }

  bool defined()      const { return type != mop_z; }
  bool is_reg()       const { return type == mop_r; }
  bool is_stkoff()    const { return type == mop_S; }
  mreg_t get_reg()    const { QASSERT(51892, is_reg()); return off; }
  sval_t get_stkoff() const { QASSERT(51893, is_stkoff()); return off; }

  void inc(sval_t delta)              { off += delta; }
  voff_t add(int width) const         { return voff_t(type, off+width); }
  sval_t diff(const voff_t &r) const  { QASSERT(51894, type == r.type); return off - r.off; }

  DECLARE_COMPARISONS(voff_t)
  {
    int code = ::compare(type, r.type);
    return code != 0 ? code : ::compare(off, r.off);
  }
};

//-------------------------------------------------------------------------
/// Value interval (register or stack range)
struct vivl_t : voff_t
{
  int size;     ///< Interval size in bytes

  vivl_t(mopt_t _type = mop_z, sval_t _off = -1, int _size = 0)
    : voff_t(_type, _off), size(_size) {}
  vivl_t(const class chain_t &ch);
  vivl_t(const mop_t &op) : voff_t(op), size(op.size) {}

  // Make a value interval
  void set(mopt_t _type, sval_t _off, int _size = 0)
    { voff_t::set(_type, _off); size = _size; }
  void set(const voff_t &voff, int _size)
    { set(voff.type, voff.off, _size); }
  void set_stkoff(sval_t stkoff, int sz = 0) { set(mop_S, stkoff, sz); }
  void set_reg   (mreg_t mreg,   int sz = 0) { set(mop_r, mreg,   sz); }

  /// Extend a value interval using another value interval of the same type
  /// \return success
  bool hexapi extend_to_cover(const vivl_t &r);

  /// Intersect value intervals the same type
  /// \return size of the resulting intersection
  uval_t hexapi intersect(const vivl_t &r);

  /// Do two value intervals overlap?
  bool overlap(const vivl_t &r) const
  {
    return type == r.type
        && interval::overlap(off, size, r.off, r.size);
  }
  /// Does our value interval include another?
  bool includes(const vivl_t &r) const
  {
    return type == r.type
        && interval::includes(off, size, r.off, r.size);
  }

  /// Does our value interval contain the specified value offset?
  bool contains(const voff_t &voff2) const
  {
    return type == voff2.type
        && interval::contains(off, size, voff2.off);
  }

  // Comparisons
  DECLARE_COMPARISONS(vivl_t)
  {
    int code = voff_t::compare(r);
    return code; //return code != 0 ? code : ::compare(size, r.size);
  }
  bool operator==(const mop_t &mop) const
  {
    return type == mop.t && off == (mop.is_reg() ? mop.r : mop.s->off);
  }
  void hexapi print(qstring *vout) const;
  const char *hexapi dstr() const;
};

//-------------------------------------------------------------------------
/// ud (use->def) and du (def->use) chain.
/// We store in chains only the block numbers, not individual instructions
/// See https://en.wikipedia.org/wiki/Use-define_chain
class chain_t : public intvec_t // sequence of block numbers
{
  voff_t k;             ///< Value offset of the chain.
                        ///< (what variable is this chain about)

public:
  int width;            ///< size of the value in bytes
  int varnum;           ///< allocated variable index (-1 - not allocated yet)
  uchar flags;          ///< combination \ref CHF_ bits
/// \defgroup CHF_ Chain properties
//@{
#define CHF_INITED     0x01 ///< is chain initialized? (valid only after lvar allocation)
#define CHF_REPLACED   0x02 ///< chain operands have been replaced?
#define CHF_OVER       0x04 ///< overlapped chain
#define CHF_FAKE       0x08 ///< fake chain created by widen_chains()
#define CHF_PASSTHRU   0x10 ///< pass-thru chain, must use the input variable to the block
#define CHF_TERM       0x20 ///< terminating chain; the variable does not survive across the block
//@}
  chain_t() : width(0), varnum(-1), flags(CHF_INITED) {}
  chain_t(mopt_t t, sval_t off, int w=1, int v=-1)
    : k(t, off), width(w), varnum(v), flags(CHF_INITED) {}
  chain_t(const voff_t &_k, int w=1)
    : k(_k), width(w), varnum(-1), flags(CHF_INITED) {}
  void set_value(const chain_t &r)
    { width = r.width; varnum = r.varnum; flags = r.flags; *(intvec_t *)this = (intvec_t &)r; }
  const voff_t &key() const { return k; }
  bool is_inited(void) const { return (flags & CHF_INITED) != 0; }
  bool is_reg(void) const { return k.is_reg(); }
  bool is_stkoff(void) const { return k.is_stkoff(); }
  bool is_replaced(void) const { return (flags & CHF_REPLACED) != 0; }
  bool is_overlapped(void) const { return (flags & CHF_OVER) != 0; }
  bool is_fake(void) const { return (flags & CHF_FAKE) != 0; }
  bool is_passreg(void) const { return (flags & CHF_PASSTHRU) != 0; }
  bool is_term(void) const { return (flags & CHF_TERM) != 0; }
  void set_inited(bool b) { setflag(flags, CHF_INITED, b); }
  void set_replaced(bool b) { setflag(flags, CHF_REPLACED, b); }
  void set_overlapped(bool b) { setflag(flags, CHF_OVER, b); }
  void set_term(bool b) { setflag(flags, CHF_TERM, b); }
  mreg_t get_reg() const { return k.get_reg(); }
  sval_t get_stkoff() const { return k.get_stkoff(); }
  bool overlap(const chain_t &r) const
    { return k.type == r.k.type && interval::overlap(k.off, width, r.k.off, r.width); }
  bool includes(const chain_t &r) const
    { return k.type == r.k.type && interval::includes(k.off, width, r.k.off, r.width); }
  const voff_t endoff() const { return k.add(width); }

  bool operator<(const chain_t &r) const { return key() < r.key(); }

  void hexapi print(qstring *vout) const;
  const char *hexapi dstr() const;
  /// Append the contents of the chain to the specified list of locations.
  void hexapi append_list(const mba_t *mba, mlist_t *list) const;
  void clear_varnum(void) { varnum = -1; set_replaced(false); }
};

//-------------------------------------------------------------------------
#if defined(__NT__)
#  ifdef _DEBUG
#    define SIZEOF_BLOCK_CHAINS  32
#else
#    define SIZEOF_BLOCK_CHAINS  24
#  endif
#elif defined(__MAC__)
#  define SIZEOF_BLOCK_CHAINS  32
#else
#  define SIZEOF_BLOCK_CHAINS  56
#endif

/// Chains of one block.
/// Please note that this class is based on std::set and it must be accessed
/// using the block_chains_begin(), block_chains_find() and similar functions.
/// This is required because different compilers use different implementations
/// of std::set. However, since the size of std::set depends on the compilation
/// options, we replace it with a byte array.
class block_chains_t
{
  size_t body[SIZEOF_BLOCK_CHAINS/sizeof(size_t)]; // opaque std::set, uncopyable
public:
  /// Get chain for the specified register
  /// \param reg   register number
  /// \param width size of register in bytes
  const chain_t *get_reg_chain(mreg_t reg, int width=1) const
    { return get_chain((chain_t(mop_r, reg, width))); }
  chain_t *get_reg_chain(mreg_t reg, int width=1)
    { return get_chain((chain_t(mop_r, reg, width))); }

  /// Get chain for the specified stack offset
  /// \param off   stack offset
  /// \param width size of stack value in bytes
  const chain_t *get_stk_chain(sval_t off, int width=1) const
    { return get_chain(chain_t(mop_S, off, width)); }
  chain_t *get_stk_chain(sval_t off, int width=1)
    { return get_chain(chain_t(mop_S, off, width)); }

  /// Get chain for the specified value offset.
  /// \param k     value offset (register number or stack offset)
  /// \param width size of value in bytes
  const chain_t *get_chain(const voff_t &k, int width=1) const
    { return get_chain(chain_t(k, width)); }
  chain_t *get_chain(const voff_t &k, int width=1)
    { return (chain_t*)((const block_chains_t *)this)->get_chain(k, width); }

  /// Get chain similar to the specified chain
  /// \param ch    chain to search for. only its 'k' and 'width' are used.
  const chain_t *hexapi get_chain(const chain_t &ch) const;
  chain_t *get_chain(const chain_t &ch)
    { return (chain_t*)((const block_chains_t *)this)->get_chain(ch); }

  void hexapi print(qstring *vout) const;
  const char *hexapi dstr() const;
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
};
//-------------------------------------------------------------------------
/// Chain visitor class
struct chain_visitor_t
{
  block_chains_t *parent;          ///< parent of the current chain
  chain_visitor_t(void) : parent(nullptr) {}
  virtual int idaapi visit_chain(int nblock, chain_t &ch) = 0;
};

//-------------------------------------------------------------------------
/// Graph chains.
/// This class represents all ud and du chains of the decompiled function
typedef qvector<block_chains_t> block_chains_vec_t;
class graph_chains_t : public block_chains_vec_t
{
  int lock;             ///< are chained locked? (in-use)
public:
  graph_chains_t(void) : lock(0) {}
  ~graph_chains_t(void) { QASSERT(50444, !lock); }
  /// Visit all chains
  /// \param cv chain visitor
  /// \param gca_flags combination of GCA_ bits
  int hexapi for_all_chains(chain_visitor_t &cv, int gca_flags);
  /// \defgroup GCA_ chain visitor flags
  //@{
#define GCA_EMPTY  0x01 ///< include empty chains
#define GCA_SPEC   0x02 ///< include chains for special registers
#define GCA_ALLOC  0x04 ///< enumerate only allocated chains
#define GCA_NALLOC 0x08 ///< enumerate only non-allocated chains
#define GCA_OFIRST 0x10 ///< consider only chains of the first block
#define GCA_OLAST  0x20 ///< consider only chains of the last block
  //@}
  /// Are the chains locked?
  /// It is a good idea to lock the chains before using them. This ensures
  /// that they won't be recalculated and reallocated during the use.
  /// See the \ref chain_keeper_t class for that.
  bool is_locked(void) const { return lock != 0; }
  /// Lock the chains
  void acquire(void) { lock++; }
  /// Unlock the chains
  void hexapi release(void);
  void swap(graph_chains_t &r)
  {
    qvector<block_chains_t>::swap(r);
    std::swap(lock, r.lock);
  }
};
//-------------------------------------------------------------------------
/// Microinstruction class #insn
class minsn_t
{
  void hexapi init(ea_t _ea);
  void hexapi copy(const minsn_t &m);
public:
  mcode_t opcode;       ///< instruction opcode
  int iprops;           ///< combination of \ref IPROP_ bits
  minsn_t *next;        ///< next insn in doubly linked list. check also nexti()
  minsn_t *prev;        ///< prev insn in doubly linked list. check also previ()
  ea_t ea;              ///< instruction address
  mop_t l;              ///< left operand
  mop_t r;              ///< right operand
  mop_t d;              ///< destination operand

  /// \defgroup IPROP_ instruction property bits
  //@{
  // bits to be used in patterns:
#define IPROP_OPTIONAL  0x0001 ///< optional instruction
#define IPROP_PERSIST   0x0002 ///< persistent insn; they are not destroyed
#define IPROP_WILDMATCH 0x0004 ///< match multiple insns

  // instruction attributes:
#define IPROP_CLNPOP    0x0008 ///< the purpose of the instruction is to clean stack
                               ///< (e.g. "pop ecx" is often used for that)
#define IPROP_FPINSN    0x0010 ///< floating point insn
#define IPROP_FARCALL   0x0020 ///< call of a far function using push cs/call sequence
#define IPROP_TAILCALL  0x0040 ///< tail call
#define IPROP_ASSERT    0x0080 ///< assertion: usually mov #val, op.
                               ///< assertions are used to help the optimizer.
                               ///< assertions are ignored when generating ctree

  // instruction history:
#define IPROP_SPLIT     0x0700 ///< the instruction has been split:
#define IPROP_SPLIT1    0x0100 ///<   into 1 byte
#define IPROP_SPLIT2    0x0200 ///<   into 2 bytes
#define IPROP_SPLIT4    0x0300 ///<   into 4 bytes
#define IPROP_SPLIT8    0x0400 ///<   into 8 bytes
#define IPROP_COMBINED  0x0800 ///< insn has been modified because of a partial reference
#define IPROP_EXTSTX    0x1000 ///< this is m_ext propagated into m_stx
#define IPROP_IGNLOWSRC 0x2000 ///< low part of the instruction source operand
                               ///< has been created artificially
                               ///< (this bit is used only for 'and x, 80...')
#define IPROP_INV_JX    0x4000 ///< inverted conditional jump
#define IPROP_WAS_NORET 0x8000 ///< was noret icall
#define IPROP_MULTI_MOV 0x10000 ///< the minsn was generated as part of insn that moves multiple registers
                                ///< (example: STM on ARM may transfer multiple registers)

                                ///< bits that can be set by plugins:
#define IPROP_DONT_PROP 0x20000 ///< may not propagate
#define IPROP_DONT_COMB 0x40000 ///< may not combine this instruction with others
#define IPROP_MBARRIER  0x80000 ///< this instruction acts as a memory barrier
                                ///< (instructions accessing memory may not be reordered past it)
#define IPROP_UNMERGED 0x100000 ///< 'goto' instruction was transformed info 'call'
  //@}

  bool is_optional(void)     const { return (iprops & IPROP_OPTIONAL)  != 0; }
  bool is_combined(void)     const { return (iprops & IPROP_COMBINED)  != 0; }
  bool is_farcall(void)      const { return (iprops & IPROP_FARCALL)   != 0; }
  bool is_cleaning_pop(void) const { return (iprops & IPROP_CLNPOP)    != 0; }
  bool is_extstx(void)       const { return (iprops & IPROP_EXTSTX)    != 0; }
  bool is_tailcall(void)     const { return (iprops & IPROP_TAILCALL)  != 0; }
  bool is_fpinsn(void)       const { return (iprops & IPROP_FPINSN)    != 0; }
  bool is_assert(void)       const { return (iprops & IPROP_ASSERT)    != 0; }
  bool is_persistent(void)   const { return (iprops & IPROP_PERSIST)   != 0; }
  bool is_wild_match(void)   const { return (iprops & IPROP_WILDMATCH) != 0; }
  bool is_propagatable(void) const { return (iprops & IPROP_DONT_PROP) == 0; }
  bool is_ignlowsrc(void)    const { return (iprops & IPROP_IGNLOWSRC) != 0; }
  bool is_inverted_jx(void)  const { return (iprops & IPROP_INV_JX)    != 0; }
  bool was_noret_icall(void) const { return (iprops & IPROP_WAS_NORET) != 0; }
  bool is_multimov(void)     const { return (iprops & IPROP_MULTI_MOV) != 0; }
  bool is_combinable(void)   const { return (iprops & IPROP_DONT_COMB) == 0; }
  bool was_split(void)       const { return (iprops & IPROP_SPLIT)     != 0; }
  bool is_mbarrier(void)     const { return (iprops & IPROP_MBARRIER)  != 0; }
  bool was_unmerged(void)    const { return (iprops & IPROP_UNMERGED)  != 0; }

  void set_optional(void) { iprops |= IPROP_OPTIONAL; }
  void hexapi set_combined(void);
  void clr_combined(void) { iprops &= ~IPROP_COMBINED; }
  void set_farcall(void)  { iprops |= IPROP_FARCALL; }
  void set_cleaning_pop(void) { iprops |= IPROP_CLNPOP; }
  void set_extstx(void)   { iprops |= IPROP_EXTSTX; }
  void set_tailcall(void) { iprops |= IPROP_TAILCALL; }
  void clr_tailcall(void) { iprops &= ~IPROP_TAILCALL; }
  void set_fpinsn(void)   { iprops |= IPROP_FPINSN; }
  void clr_fpinsn(void)   { iprops &= ~IPROP_FPINSN; }
  void set_assert(void)   { iprops |= IPROP_ASSERT; }
  void clr_assert(void)   { iprops &= ~IPROP_ASSERT; }
  void set_persistent(void) { iprops |= IPROP_PERSIST; }
  void set_wild_match(void) { iprops |= IPROP_WILDMATCH; }
  void clr_propagatable(void) { iprops |= IPROP_DONT_PROP; }
  void set_ignlowsrc(void) { iprops |= IPROP_IGNLOWSRC; }
  void clr_ignlowsrc(void) { iprops &= ~IPROP_IGNLOWSRC; }
  void set_inverted_jx(void) { iprops |= IPROP_INV_JX; }
  void set_noret_icall(void) { iprops |= IPROP_WAS_NORET; }
  void clr_noret_icall(void) { iprops &= ~IPROP_WAS_NORET; }
  void set_multimov(void) { iprops |= IPROP_MULTI_MOV; }
  void clr_multimov(void) { iprops &= ~IPROP_MULTI_MOV; }
  void set_combinable(void) { iprops &= ~IPROP_DONT_COMB; }
  void clr_combinable(void) { iprops |= IPROP_DONT_COMB; }
  void set_mbarrier(void) { iprops |= IPROP_MBARRIER; }
  void set_unmerged(void) { iprops |= IPROP_UNMERGED; }
  void set_split_size(int s)
  { // s may be only 1,2,4,8. other values are ignored
    iprops &= ~IPROP_SPLIT;
    iprops |= (s == 1 ? IPROP_SPLIT1
             : s == 2 ? IPROP_SPLIT2
             : s == 4 ? IPROP_SPLIT4
             : s == 8 ? IPROP_SPLIT8 : 0);
  }
  int get_split_size(void) const
  {
    int cnt = (iprops & IPROP_SPLIT) >> 8;
    return cnt == 0 ? 0 : 1 << (cnt-1);
  }

  /// Constructor
  minsn_t(ea_t _ea) { init(_ea); }
  minsn_t(const minsn_t &m) { next = prev = nullptr; copy(m); } //-V1077 uninitialized: opcode, iprops, ea
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()

  /// Assignment operator. It does not copy prev/next fields.
  minsn_t &operator=(const minsn_t &m) { copy(m); return *this; }

  /// Swap two instructions.
  /// The prev/next fields are not modified by this function
  /// because it would corrupt the doubly linked list.
  void hexapi swap(minsn_t &m);

  /// Generate insn text into the buffer
  void hexapi print(qstring *vout, int shins_flags=SHINS_SHORT|SHINS_VALNUM) const;

  /// Get displayable text without tags in a static buffer
  const char *hexapi dstr() const;

  /// Change the instruction address.
  /// This function modifies subinstructions as well.
  void hexapi setaddr(ea_t new_ea);

  /// Optimize one instruction without context.
  /// This function does not have access to the instruction context (the
  /// previous and next instructions in the list, the block number, etc).
  /// It performs only basic optimizations that are available without this info.
  /// \param optflags combination of \ref OPTI_ bits
  /// \return number of changes, 0-unchanged
  /// See also mblock_t::optimize_insn()
  int optimize_solo(int optflags=0) { return optimize_subtree(nullptr, nullptr, nullptr, nullptr, optflags); }
  /// \defgroup OPTI_ optimization flags
  //@{
#define OPTI_ADDREXPRS 0x0001 ///< optimize all address expressions (&x+N; &x-&y)
#define OPTI_MINSTKREF 0x0002 ///< may update minstkref
#define OPTI_COMBINSNS 0x0004 ///< may combine insns (only for optimize_insn)
#define OPTI_NO_LDXOPT 0x0008 ///< the function is called after the
                              ///< propagation attempt, we do not optimize
                              ///< low/high(ldx) in this case
  //@}

  /// Optimize instruction in its context.
  /// Do not use this function, use mblock_t::optimize()
  int hexapi optimize_subtree(
        mblock_t *blk,
        minsn_t *top,
        minsn_t *parent,
        ea_t *converted_call,
        int optflags=OPTI_MINSTKREF);

  /// Visit all instruction operands.
  /// This function visits subinstruction operands as well.
  /// \param mv operand visitor
  /// \return non-zero value returned by mv.visit_mop() or zero
  int hexapi for_all_ops(mop_visitor_t &mv);

  /// Visit all instructions.
  /// This function visits the instruction itself and all its subinstructions.
  /// \param mv instruction visitor
  /// \return non-zero value returned by mv.visit_mop() or zero
  int hexapi for_all_insns(minsn_visitor_t &mv);

  /// Convert instruction to nop.
  /// This function erases all info but the prev/next fields.
  /// In most cases it is better to use mblock_t::make_nop(), which also
  /// marks the block lists as dirty.
  void hexapi _make_nop(void);

  /// Compare instructions.
  /// This is the main comparison function for instructions.
  /// \param m       instruction to compare with
  /// \param eqflags combination of \ref EQ_ bits
  bool hexapi equal_insns(const minsn_t &m, int eqflags) const; // intelligent comparison
  /// \defgroup EQ_ comparison bits
  //@{
#define EQ_IGNSIZE 0x0001      ///< ignore source operand sizes
#define EQ_IGNCODE 0x0002      ///< ignore instruction opcodes
#define EQ_CMPDEST 0x0004      ///< compare instruction destinations
#define EQ_OPTINSN 0x0008      ///< optimize mop_d operands
  //@}

  /// Lexographical comparison
  /// It can be used to store minsn_t in various containers, like std::set
  bool operator <(const minsn_t &ri) const { return lexcompare(ri) < 0; }
  int hexapi lexcompare(const minsn_t &ri) const;

  //-----------------------------------------------------------------------
  // Call instructions
  //-----------------------------------------------------------------------
  /// Is a non-returing call?
  /// \param flags combination of NORET_... bits
  bool hexapi is_noret_call(int flags=0);
#define NORET_IGNORE_WAS_NORET_ICALL 0x01 // ignore was_noret_icall() bit
#define NORET_FORBID_ANALYSIS        0x02 // forbid additional analysis

  /// Is an unknown call?
  /// Unknown calls are calls without the argument list (mcallinfo_t).
  /// Usually the argument lists are determined by mba_t::analyze_calls().
  /// Unknown calls exist until the MMAT_CALLS maturity level.
  /// See also \ref mblock_t::is_call_block
  bool is_unknown_call(void) const { return is_mcode_call(opcode) && d.empty(); }

  /// Is a helper call with the specified name?
  /// Helper calls usually have well-known function names (see \ref FUNC_NAME_)
  /// but they may have any other name. The decompiler does not assume any
  /// special meaning for non-well-known names.
  bool hexapi is_helper(const char *name) const;

  /// Find a call instruction.
  /// Check for the current instruction and its subinstructions.
  /// \param with_helpers consider helper calls as well?
  minsn_t *hexapi find_call(bool with_helpers=false) const;

  /// Does the instruction contain a call?
  bool contains_call(bool with_helpers=false) const { return find_call(with_helpers) != nullptr; }

  /// Does the instruction have a side effect?
  /// \param include_ldx_and_divs consider ldx/div/mod as having side effects?
  ///                    stx is always considered as having side effects.
  /// Apart from ldx/std only call may have side effects.
  bool hexapi has_side_effects(bool include_ldx_and_divs=false) const;

  /// Get the function role of a call
  funcrole_t get_role(void) const { return d.is_arglist() ? d.f->role : ROLE_UNK; }
  bool is_memcpy(void) const { return get_role() == ROLE_MEMCPY; }
  bool is_memset(void) const { return get_role() == ROLE_MEMSET; }
  bool is_alloca(void) const { return get_role() == ROLE_ALLOCA; }
  bool is_bswap (void) const { return get_role() == ROLE_BSWAP;  }
  bool is_readflags (void) const { return get_role() == ROLE_READFLAGS;  }

  //-----------------------------------------------------------------------
  // Misc
  //-----------------------------------------------------------------------
  /// Does the instruction have the specified opcode?
  /// This function searches subinstructions as well.
  /// \param mcode opcode to search for.
  bool contains_opcode(mcode_t mcode) const { return find_opcode(mcode) != nullptr; }

  /// Find a (sub)insruction with the specified opcode.
  /// \param mcode opcode to search for.
  const minsn_t *find_opcode(mcode_t mcode) const { return (CONST_CAST(minsn_t*)(this))->find_opcode(mcode); }
  minsn_t *hexapi find_opcode(mcode_t mcode);

  /// Find an operand that is a subinsruction with the specified opcode.
  /// This function checks only the 'l' and 'r' operands of the current insn.
  /// \param[out] other pointer to the other operand
  ///             (&r if we return &l and vice versa)
  /// \param op   opcode to search for
  /// \return &l or &r or nullptr
  const minsn_t *hexapi find_ins_op(const mop_t **other, mcode_t op=m_nop) const;
  minsn_t *find_ins_op(mop_t **other, mcode_t op=m_nop) { return CONST_CAST(minsn_t*)((CONST_CAST(const minsn_t*)(this))->find_ins_op((const mop_t**)other, op)); }

  /// Find a numeric operand of the current instruction.
  /// This function checks only the 'l' and 'r' operands of the current insn.
  /// \param[out] other pointer to the other operand
  ///             (&r if we return &l and vice versa)
  /// \return &l or &r or nullptr
  const mop_t *hexapi find_num_op(const mop_t **other) const;
  mop_t *find_num_op(mop_t **other) { return CONST_CAST(mop_t*)((CONST_CAST(const minsn_t*)(this))->find_num_op((const mop_t**)other)); }

  bool is_mov(void) const { return opcode == m_mov || (opcode == m_f2f && l.size == d.size); }
  bool is_like_move(void) const { return is_mov() || is_mcode_xdsu(opcode) || opcode == m_low; }

  /// Does the instruction modify its 'd' operand?
  /// Some instructions (e.g. m_stx) do not modify the 'd' operand.
  bool hexapi modifies_d(void) const;
  bool modifies_pair_mop(void) const { return d.t == mop_p && modifies_d(); }

  /// Is the instruction in the specified range of instructions?
  /// \param m1 beginning of the range in the doubly linked list
  /// \param m2 end of the range in the doubly linked list (excluded, may be nullptr)
  /// This function assumes that m1 and m2 belong to the same basic block
  /// and they are top level instructions.
  bool hexapi is_between(const minsn_t *m1, const minsn_t *m2) const;

  /// Is the instruction after the specified one?
  /// \param m the instruction to compare against in the list
  bool is_after(const minsn_t *m) const { return m != nullptr && is_between(m->next, nullptr); }

  /// Is it possible for the instruction to use aliased memory?
  bool hexapi may_use_aliased_memory(void) const;

  /// Serialize an instruction
  /// \param b the output buffer
  /// \return the serialization format that was used to store info
  int hexapi serialize(bytevec_t *b) const;

  /// Deserialize an instruction
  /// \param bytes pointer to serialized data
  /// \param nbytes number of bytes to deserialize
  /// \param format_version serialization format version. this value is returned by minsn_t::serialize()
  /// \return success
  bool hexapi deserialize(const uchar *bytes, size_t nbytes, int format_version);

};

/// Skip assertions forward
const minsn_t *hexapi getf_reginsn(const minsn_t *ins);
/// Skip assertions backward
const minsn_t *hexapi getb_reginsn(const minsn_t *ins);
inline minsn_t *getf_reginsn(minsn_t *ins) { return CONST_CAST(minsn_t*)(getf_reginsn(CONST_CAST(const minsn_t *)(ins))); }
inline minsn_t *getb_reginsn(minsn_t *ins) { return CONST_CAST(minsn_t*)(getb_reginsn(CONST_CAST(const minsn_t *)(ins))); }

//-------------------------------------------------------------------------
/// Basic block types
enum mblock_type_t
{
  BLT_NONE = 0, ///< unknown block type
  BLT_STOP = 1, ///< stops execution regularly (must be the last block)
  BLT_0WAY = 2, ///< does not have successors (tail is a noret function)
  BLT_1WAY = 3, ///< passes execution to one block (regular or goto block)
  BLT_2WAY = 4, ///< passes execution to two blocks (conditional jump)
  BLT_NWAY = 5, ///< passes execution to many blocks (switch idiom)
  BLT_XTRN = 6, ///< external block (out of function address)
};

// Maximal bit range
#define MAXRANGE bitrange_t(0, USHRT_MAX)

//-------------------------------------------------------------------------
/// Microcode of one basic block.
/// All blocks are part of a doubly linked list. They can also be addressed
/// by indexing the mba->natural array. A block contains a doubly linked list
/// of instructions, various location lists that are used for data flow
/// analysis, and other attributes.
class mblock_t
{
  friend class codegen_t;
  DECLARE_UNCOPYABLE(mblock_t)
  void hexapi init(void);
public:
  mblock_t *nextb;              ///< next block in the doubly linked list
  mblock_t *prevb;              ///< previous block in the doubly linked list
  uint32 flags;                 ///< combination of \ref MBL_ bits
  /// \defgroup MBL_ Basic block properties
  //@{
#define MBL_PRIV        0x0001  ///< private block - no instructions except
                                ///< the specified are accepted (used in patterns)
#define MBL_NONFAKE     0x0000  ///< regular block
#define MBL_FAKE        0x0002  ///< fake block
#define MBL_GOTO        0x0004  ///< this block is a goto target
#define MBL_TCAL        0x0008  ///< aritifical call block for tail calls
#define MBL_PUSH        0x0010  ///< needs "convert push/pop instructions"
#define MBL_DMT64       0x0020  ///< needs "demote 64bits"
#define MBL_COMB        0x0040  ///< needs "combine" pass
#define MBL_PROP        0x0080  ///< needs 'propagation' pass
#define MBL_DEAD        0x0100  ///< needs "eliminate deads" pass
#define MBL_LIST        0x0200  ///< use/def lists are ready (not dirty)
#define MBL_INCONST     0x0400  ///< inconsistent lists: we are building them
#define MBL_CALL        0x0800  ///< call information has been built
#define MBL_BACKPROP    0x1000  ///< performed backprop_cc
#define MBL_NORET       0x2000  ///< dead end block: doesn't return execution control
#define MBL_DSLOT       0x4000  ///< block for delay slot
#define MBL_VALRANGES   0x8000  ///< should optimize using value ranges
#define MBL_KEEP       0x10000  ///< do not remove even if unreachable
  //@}
  ea_t start;                   ///< start address
  ea_t end;                     ///< end address
                                ///< note: we cannot rely on start/end addresses
                                ///<       very much because instructions are
                                ///<       propagated between blocks
  minsn_t *head;                ///< pointer to the first instruction of the block
  minsn_t *tail;                ///< pointer to the last instruction of the block
  mba_t *mba;                   ///< the parent micro block array
  int serial;                   ///< block number
  mblock_type_t type;           ///< block type (BLT_NONE - not computed yet)

  mlist_t dead_at_start;        ///< data that is dead at the block entry
  mlist_t mustbuse;             ///< data that must be used by the block
  mlist_t maybuse;              ///< data that may  be used by the block
  mlist_t mustbdef;             ///< data that must be defined by the block
  mlist_t maybdef;              ///< data that may  be defined by the block
  mlist_t dnu;                  ///< data that is defined but not used in the block

  sval_t maxbsp;                ///< maximal sp value in the block (0...stacksize)
  sval_t minbstkref;            ///< lowest stack location accessible with indirect
                                ///< addressing (offset from the stack bottom)
                                ///< initially it is 0 (not computed)
  sval_t minbargref;            ///< the same for arguments

  intvec_t predset;             ///< control flow graph: list of our predecessors
                                ///< use npred() and pred() to access it
  intvec_t succset;             ///< control flow graph: list of our successors
                                ///< use nsucc() and succ() to access it

  // the exact size of this class is not documented, there may be more fields
  char reserved[];

  void mark_lists_dirty(void) { flags &= ~MBL_LIST; request_propagation(); }
  void request_propagation(void) { flags |= MBL_PROP; }
  bool needs_propagation(void) const { return (flags & MBL_PROP) != 0; }
  void request_demote64(void) { flags |= MBL_DMT64; }
  bool lists_dirty(void) const { return (flags & MBL_LIST) == 0; }
  bool lists_ready(void) const { return (flags & (MBL_LIST|MBL_INCONST)) == MBL_LIST; }
  int make_lists_ready(void) // returns number of changes
  {
    if ( lists_ready() )
      return 0;
    return build_lists(false);
  }

  /// Get number of block predecessors
  int npred(void) const { return predset.size(); } // number of xrefs to the block
  /// Get number of block successors
  int nsucc(void) const { return succset.size(); } // number of xrefs from the block
  // Get predecessor number N
  int pred(int n) const { return predset[n]; }
  // Get successor number N
  int succ(int n) const { return succset[n]; }

  mblock_t(void) = delete;
  virtual ~mblock_t(void);
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
  bool empty(void) const { return head == nullptr; }

  /// Print block contents.
  /// \param vp print helpers class. it can be used to direct the printed
  ///           info to any destination
  void hexapi print(vd_printer_t &vp) const;

  /// Dump block info.
  /// This function is useful for debugging, see mba_t::dump for info
  void hexapi dump(void) const;
  AS_PRINTF(2, 0) void hexapi vdump_block(const char *title, va_list va) const;
  AS_PRINTF(2, 3) void dump_block(const char *title, ...) const
  {
    va_list va;
    va_start(va, title);
    vdump_block(title, va);
    va_end(va);
  }

  //-----------------------------------------------------------------------
  // Functions to insert/remove insns during the microcode optimization phase.
  // See codegen_t, microcode_filter_t, udcall_t classes for the initial
  // microcode generation.
  //-----------------------------------------------------------------------
  /// Insert instruction into the doubly linked list
  /// \param nm new instruction
  /// \param om existing instruction, part of the doubly linked list
  ///           if nullptr, then the instruction will be inserted at the beginning
  ///           of the list
  /// NM will be inserted immediately after OM
  /// \return pointer to NM
  minsn_t *hexapi insert_into_block(minsn_t *nm, minsn_t *om);

  /// Remove instruction from the doubly linked list
  /// \param m instruction to remove
  /// The removed instruction is not deleted, the caller gets its ownership
  /// \return pointer to the next instruction
  minsn_t *hexapi remove_from_block(minsn_t *m);

  //-----------------------------------------------------------------------
  // Iterator over instructions and operands
  //-----------------------------------------------------------------------
  /// Visit all instructions.
  /// This function visits subinstructions too.
  /// \param mv instruction visitor
  /// \return zero or the value returned by mv.visit_insn()
  /// See also mba_t::for_all_topinsns()
  int hexapi for_all_insns(minsn_visitor_t &mv);

  /// Visit all operands.
  /// This function visit subinstruction operands too.
  /// \param mv operand visitor
  /// \return zero or the value returned by mv.visit_mop()
  int hexapi for_all_ops(mop_visitor_t &mv);

  /// Visit all operands that use LIST.
  /// \param list ptr to the list of locations. it may be modified:
  ///             parts that get redefined by the instructions in [i1,i2)
  ///             will be deleted.
  /// \param i1   starting instruction. must be a top level insn.
  /// \param i2   ending instruction (excluded). must be a top level insn.
  /// \param mmv  operand visitor
  /// \return zero or the value returned by mmv.visit_mop()
  int hexapi for_all_uses(
        mlist_t *list,
        minsn_t *i1,
        minsn_t *i2,
        mlist_mop_visitor_t &mmv);

  //-----------------------------------------------------------------------
  // Optimization functions
  //-----------------------------------------------------------------------
  /// Optimize one instruction in the context of the block.
  /// \param m pointer to a top level instruction
  /// \param optflags combination of \ref OPTI_ bits
  /// \return number of changes made to the block
  /// This function may change other instructions in the block too.
  /// However, it will not destroy top level instructions (it may convert them
  /// to nop's). This function performs only intrablock modifications.
  /// See also minsn_t::optimize_solo()
  int hexapi optimize_insn(minsn_t *m, int optflags=OPTI_MINSTKREF|OPTI_COMBINSNS);

  /// Optimize a basic block.
  /// Usually there is no need to call this function explicitly because the
  /// decompiler will call it itself if optinsn_t::func or optblock_t::func
  /// return non-zero.
  /// \return number of changes made to the block
  int hexapi optimize_block(void);

  /// Build def-use lists and eliminate deads.
  /// \param kill_deads do delete dead instructions?
  /// \return the number of eliminated instructions
  /// Better mblock_t::call make_lists_ready() rather than this function.
  int hexapi build_lists(bool kill_deads);

  /// Remove a jump at the end of the block if it is useless.
  /// This function preserves any side effects when removing a useless jump.
  /// Both conditional and unconditional jumps are handled (and jtbl too).
  /// This function deletes useless jumps, not only replaces them with a nop.
  /// (please note that \optimize_insn does not handle useless jumps).
  /// \return number of changes made to the block
  int hexapi optimize_useless_jump(void);

  //-----------------------------------------------------------------------
  // Functions that build with use/def lists. These lists are used to
  // reprsent list of registers and stack locations that are either modified
  // or accessed by microinstructions.
  //-----------------------------------------------------------------------
  /// Append use-list of an operand.
  /// This function calculates list of locations that may or must be used
  /// by the operand and appends it to LIST.
  /// \param list    ptr to the output buffer. we will append to it.
  /// \param op      operand to calculate the use list of
  /// \param maymust should we calculate 'may-use' or 'must-use' list?
  ///                see \ref maymust_t for more details.
  /// \param mask    if only part of the operand should be considered,
  ///                a bitmask can be used to specify which part.
  ///                example: op=AX,mask=0xFF means that we will consider only AL.
  void hexapi append_use_list(
        mlist_t *list,
        const mop_t &op,
        maymust_t maymust,
        bitrange_t mask=MAXRANGE) const;

  /// Append def-list of an operand.
  /// This function calculates list of locations that may or must be modified
  /// by the operand and appends it to LIST.
  /// \param list    ptr to the output buffer. we will append to it.
  /// \param op      operand to calculate the def list of
  /// \param maymust should we calculate 'may-def' or 'must-def' list?
  ///                see \ref maymust_t for more details.
  void hexapi append_def_list(
        mlist_t *list,
        const mop_t &op,
        maymust_t maymust) const;

  /// Build use-list of an instruction.
  /// This function calculates list of locations that may or must be used
  /// by the instruction. Examples:
  ///   "ldx ds.2, eax.4, ebx.4", may-list: all aliasable memory
  ///   "ldx ds.2, eax.4, ebx.4", must-list: empty
  /// Since LDX uses EAX for indirect access, it may access any aliasable
  /// memory. On the other hand, we cannot tell for sure which memory cells
  /// will be accessed, this is why the must-list is empty.
  /// \param ins     instruction to calculate the use list of
  /// \param maymust should we calculate 'may-use' or 'must-use' list?
  ///                see \ref maymust_t for more details.
  /// \return the calculated use-list
  mlist_t hexapi build_use_list(const minsn_t &ins, maymust_t maymust) const;

  /// Build def-list of an instruction.
  /// This function calculates list of locations that may or must be modified
  /// by the instruction. Examples:
  ///   "stx ebx.4, ds.2, eax.4", may-list: all aliasable memory
  ///   "stx ebx.4, ds.2, eax.4", must-list: empty
  /// Since STX uses EAX for indirect access, it may modify any aliasable
  /// memory. On the other hand, we cannot tell for sure which memory cells
  /// will be modified, this is why the must-list is empty.
  /// \param ins     instruction to calculate the def list of
  /// \param maymust should we calculate 'may-def' or 'must-def' list?
  ///                see \ref maymust_t for more details.
  /// \return the calculated def-list
  mlist_t hexapi build_def_list(const minsn_t &ins, maymust_t maymust) const;

  //-----------------------------------------------------------------------
  // The use/def lists can be used to search for interesting instructions
  //-----------------------------------------------------------------------
  /// Is the list used by the specified instruction range?
  /// \param list list of locations. LIST may be modified by the function:
  ///             redefined locations will be removed from it.
  /// \param i1   starting instruction of the range (must be a top level insn)
  /// \param i2   end instruction of the range (must be a top level insn)
  ///             i2 is excluded from the range. it can be specified as nullptr.
  ///             i1 and i2 must belong to the same block.
  /// \param maymust should we search in 'may-access' or 'must-access' mode?
  bool is_used(mlist_t *list, const minsn_t *i1, const minsn_t *i2, maymust_t maymust=MAY_ACCESS) const
    { return find_first_use(list, i1, i2, maymust) != nullptr; }

  /// Find the first insn that uses the specified list in the insn range.
  /// \param list list of locations. LIST may be modified by the function:
  ///             redefined locations will be removed from it.
  /// \param i1   starting instruction of the range (must be a top level insn)
  /// \param i2   end instruction of the range (must be a top level insn)
  ///             i2 is excluded from the range. it can be specified as nullptr.
  ///             i1 and i2 must belong to the same block.
  /// \param maymust should we search in 'may-access' or 'must-access' mode?
  /// \return pointer to such instruction or nullptr.
  ///         Upon return LIST will contain only locations not redefined
  ///         by insns [i1..result]
  const minsn_t *hexapi find_first_use(mlist_t *list, const minsn_t *i1, const minsn_t *i2, maymust_t maymust=MAY_ACCESS) const;
  minsn_t *find_first_use(mlist_t *list, minsn_t *i1, const minsn_t *i2, maymust_t maymust=MAY_ACCESS) const
  {
    return CONST_CAST(minsn_t*)(find_first_use(list,
                                               CONST_CAST(const minsn_t*)(i1),
                                               i2,
                                               maymust));
  }

  /// Is the list redefined by the specified instructions?
  /// \param list list of locations to check.
  /// \param i1   starting instruction of the range (must be a top level insn)
  /// \param i2   end instruction of the range (must be a top level insn)
  ///             i2 is excluded from the range. it can be specified as nullptr.
  ///             i1 and i2 must belong to the same block.
  /// \param maymust should we search in 'may-access' or 'must-access' mode?
  bool is_redefined(
        const mlist_t &list,
        const minsn_t *i1,
        const minsn_t *i2,
        maymust_t maymust=MAY_ACCESS) const
  {
    return find_redefinition(list, i1, i2, maymust) != nullptr;
  }

  /// Find the first insn that redefines any part of the list in the insn range.
  /// \param list list of locations to check.
  /// \param i1   starting instruction of the range (must be a top level insn)
  /// \param i2   end instruction of the range (must be a top level insn)
  ///             i2 is excluded from the range. it can be specified as nullptr.
  ///             i1 and i2 must belong to the same block.
  /// \param maymust should we search in 'may-access' or 'must-access' mode?
  /// \return pointer to such instruction or nullptr.
  const minsn_t *hexapi find_redefinition(
        const mlist_t &list,
        const minsn_t *i1,
        const minsn_t *i2,
        maymust_t maymust=MAY_ACCESS) const;
  minsn_t *find_redefinition(
        const mlist_t &list,
        minsn_t *i1,
        const minsn_t *i2,
        maymust_t maymust=MAY_ACCESS) const
  {
    return CONST_CAST(minsn_t*)(find_redefinition(list,
                                                  CONST_CAST(const minsn_t*)(i1),
                                                  i2,
                                                  maymust));
  }

  /// Is the right hand side of the instruction redefined the insn range?
  /// "right hand side" corresponds to the source operands of the instruction.
  /// \param ins instruction to consider
  /// \param i1   starting instruction of the range (must be a top level insn)
  /// \param i2   end instruction of the range (must be a top level insn)
  ///             i2 is excluded from the range. it can be specified as nullptr.
  ///             i1 and i2 must belong to the same block.
  bool hexapi is_rhs_redefined(const minsn_t *ins, const minsn_t *i1, const minsn_t *i2) const;

  /// Find the instruction that accesses the specified operand.
  /// This function search inside one block.
  /// \param op     operand to search for
  /// \param parent ptr to ptr to a top level instruction.
  ///               denotes the beginning of the search range.
  /// \param mend   end instruction of the range (must be a top level insn)
  ///               mend is excluded from the range. it can be specified as nullptr.
  ///               parent and mend must belong to the same block.
  /// \param fdflags combination of \ref FD_ bits
  /// \return       the instruction that accesses the operand. this instruction
  ///               may be a sub-instruction. to find out the top level
  ///               instruction, check out *p_i1.
  ///               nullptr means 'not found'.
  minsn_t *hexapi find_access(
        const mop_t &op,
        minsn_t **parent,
        const minsn_t *mend,
        int fdflags) const;
  /// \defgroup FD_ bits for mblock_t::find_access
  //@{
#define FD_BACKWARD 0x0000  ///< search direction
#define FD_FORWARD  0x0001  ///< search direction
#define FD_USE      0x0000  ///< look for use
#define FD_DEF      0x0002  ///< look for definition
#define FD_DIRTY    0x0004  ///< ignore possible implicit definitions
                            ///< by function calls and indirect memory access
  //@}

  // Convenience functions:
  minsn_t *find_def(
        const mop_t &op,
        minsn_t **p_i1,
        const minsn_t *i2,
        int fdflags)
  {
    return find_access(op, p_i1, i2, fdflags|FD_DEF);
  }
  minsn_t *find_use(
        const mop_t &op,
        minsn_t **p_i1,
        const minsn_t *i2,
        int fdflags)
  {
    return find_access(op, p_i1, i2, fdflags|FD_USE);
  }

  /// Find possible values for a block.
  /// \param res     set of value ranges
  /// \param vivl    what to search for
  /// \param vrflags combination of \ref VR_ bits
  bool hexapi get_valranges(
        valrng_t *res,
        const vivl_t &vivl,
        int vrflags) const;

  /// Find possible values for an instruction.
  /// \param res     set of value ranges
  /// \param vivl    what to search for
  /// \param m       insn to search value ranges at. \sa VR_ bits
  /// \param vrflags combination of \ref VR_ bits
  bool hexapi get_valranges(
        valrng_t *res,
        const vivl_t &vivl,
        const minsn_t *m,
        int vrflags) const;

  /// \defgroup VR_ bits for get_valranges
  //@{
#define VR_AT_START 0x0000    ///< get value ranges before the instruction or
                              ///< at the block start (if M is nullptr)
#define VR_AT_END   0x0001    ///< get value ranges after the instruction or
                              ///< at the block end, just after the last
                              ///< instruction (if M is nullptr)
#define VR_EXACT    0x0002    ///< find exact match. if not set, the returned
                              ///< valrng size will be >= vivl.size
  //@}

  /// Erase the instruction (convert it to nop) and mark the lists dirty.
  /// This is the recommended function to use because it also marks the block
  /// use-def lists dirty.
  void make_nop(minsn_t *m) { m->_make_nop(); mark_lists_dirty(); }

  /// Calculate number of regular instructions in the block.
  /// Assertions are skipped by this function.
  /// \return Number of non-assertion instructions in the block.
  size_t hexapi get_reginsn_qty(void) const;

  bool is_call_block(void) const { return tail != nullptr && is_mcode_call(tail->opcode); }
  bool is_unknown_call(void) const { return tail != nullptr && tail->is_unknown_call(); }
  bool is_nway(void) const { return type == BLT_NWAY; }
  bool is_branch(void) const { return type == BLT_2WAY && tail->d.t == mop_b; }
  bool is_simple_goto_block(void) const
  {
    return get_reginsn_qty() == 1
        && tail->opcode == m_goto
        && tail->l.t == mop_b;
  }
  bool is_simple_jcnd_block() const
  {
    return is_branch()
        && npred() == 1
        && get_reginsn_qty() == 1
        && is_mcode_convertible_to_set(tail->opcode);
  }
};
//-------------------------------------------------------------------------
/// Warning ids
enum warnid_t
{
  WARN_VARARG_REGS,   ///<  0 cannot handle register arguments in vararg function, discarded them
  WARN_ILL_PURGED,    ///<  1 odd caller purged bytes %d, correcting
  WARN_ILL_FUNCTYPE,  ///<  2 invalid function type '%s' has been ignored
  WARN_VARARG_TCAL,   ///<  3 cannot handle tail call to vararg
  WARN_VARARG_NOSTK,  ///<  4 call vararg without local stack
  WARN_VARARG_MANY,   ///<  5 too many varargs, some ignored
  WARN_ADDR_OUTARGS,  ///<  6 cannot handle address arithmetics in outgoing argument area of stack frame -- unused
  WARN_DEP_UNK_CALLS, ///<  7 found interdependent unknown calls
  WARN_ILL_ELLIPSIS,  ///<  8 erroneously detected ellipsis type has been ignored
  WARN_GUESSED_TYPE,  ///<  9 using guessed type %s;
  WARN_EXP_LINVAR,    ///< 10 failed to expand a linear variable
  WARN_WIDEN_CHAINS,  ///< 11 failed to widen chains
  WARN_BAD_PURGED,    ///< 12 inconsistent function type and number of purged bytes
  WARN_CBUILD_LOOPS,  ///< 13 too many cbuild loops
  WARN_NO_SAVE_REST,  ///< 14 could not find valid save-restore pair for %s
  WARN_ODD_INPUT_REG, ///< 15 odd input register %s
  WARN_ODD_ADDR_USE,  ///< 16 odd use of a variable address
  WARN_MUST_RET_FP,   ///< 17 function return type is incorrect (must be floating point)
  WARN_ILL_FPU_STACK, ///< 18 inconsistent fpu stack
  WARN_SELFREF_PROP,  ///< 19 self-referencing variable has been detected
  WARN_WOULD_OVERLAP, ///< 20 variables would overlap: %s
  WARN_ARRAY_INARG,   ///< 21 array has been used for an input argument
  WARN_MAX_ARGS,      ///< 22 too many input arguments, some ignored
  WARN_BAD_FIELD_TYPE,///< 23 incorrect structure member type for %s::%s, ignored
  WARN_WRITE_CONST,   ///< 24 write access to const memory at %a has been detected
  WARN_BAD_RETVAR,    ///< 25 wrong return variable
  WARN_FRAG_LVAR,     ///< 26 fragmented variable at %s may be wrong
  WARN_HUGE_STKOFF,   ///< 27 exceedingly huge offset into the stack frame
  WARN_UNINITED_REG,  ///< 28 reference to an uninitialized register has been removed: %s
  WARN_FIXED_MACRO,   ///< 29 fixed broken macro-insn
  WARN_WRONG_VA_OFF,  ///< 30 wrong offset of va_list variable
  WARN_CR_NOFIELD,    ///< 31 CONTAINING_RECORD: no field '%s' in struct '%s' at %d
  WARN_CR_BADOFF,     ///< 32 CONTAINING_RECORD: too small offset %d for struct '%s'
  WARN_BAD_STROFF,    ///< 33 user specified stroff has not been processed: %s
  WARN_BAD_VARSIZE,   ///< 34 inconsistent variable size for '%s'
  WARN_UNSUPP_REG,    ///< 35 unsupported processor register '%s'
  WARN_UNALIGNED_ARG, ///< 36 unaligned function argument '%s'
  WARN_BAD_STD_TYPE,  ///< 37 corrupted or unexisting local type '%s'
  WARN_BAD_CALL_SP,   ///< 38 bad sp value at call
  WARN_MISSED_SWITCH, ///< 39 wrong markup of switch jump, skipped it
  WARN_BAD_SP,        ///< 40 positive sp value %a has been found
  WARN_BAD_STKPNT,    ///< 41 wrong sp change point
  WARN_UNDEF_LVAR,    ///< 42 variable '%s' is possibly undefined
  WARN_JUMPOUT,       ///< 43 control flows out of bounds
  WARN_BAD_VALRNG,    ///< 44 values range analysis failed
  WARN_BAD_SHADOW,    ///< 45 ignored the value written to the shadow area of the succeeding call
  WARN_OPT_VALRNG,    ///< 46 conditional instruction was optimized away because %s
  WARN_RET_LOCREF,    ///< 47 returning address of temporary local variable '%s'
  WARN_BAD_MAPDST,    ///< 48 too short map destination '%s' for variable '%s'
  WARN_BAD_INSN,      ///< 49 bad instruction
  WARN_ODD_ABI,       ///< 50 encountered odd instruction for the current ABI
  WARN_UNBALANCED_STACK, ///< 51 unbalanced stack, ignored a potential tail call

  WARN_OPT_VALRNG2,   ///< 52 mask 0x%X is shortened because %s <= 0x%X"

  WARN_OPT_VALRNG3,   ///< 53 masking with 0X%X was optimized away because %s <= 0x%X
  WARN_OPT_USELESS_JCND, ///< 54 simplified comparisons for '%s': %s became %s
  WARN_MAX,           ///< may be used in notes as a placeholder when the
                      ///< warning id is not available
};

/// Warning instances
struct hexwarn_t
{
  ea_t ea;            ///< Address where the warning occurred
  warnid_t id;        ///< Warning id
  qstring text;       ///< Fully formatted text of the warning
  DECLARE_COMPARISONS(hexwarn_t)
  {
    if ( ea < r.ea )
      return -1;
    if ( ea > r.ea )
      return 1;
    if ( id < r.id )
      return -1;
    if ( id > r.id )
      return 1;
    return strcmp(text.c_str(), r.text.c_str());
  }
};
DECLARE_TYPE_AS_MOVABLE(hexwarn_t);
typedef qvector<hexwarn_t> hexwarns_t;

//-------------------------------------------------------------------------
/// Microcode maturity levels
enum mba_maturity_t
{
  MMAT_ZERO,         ///< microcode does not exist
  MMAT_GENERATED,    ///< generated microcode
  MMAT_PREOPTIMIZED, ///< preoptimized pass is complete
  MMAT_LOCOPT,       ///< local optimization of each basic block is complete.
                     ///< control flow graph is ready too.
  MMAT_CALLS,        ///< detected call arguments
  MMAT_GLBOPT1,      ///< performed the first pass of global optimization
  MMAT_GLBOPT2,      ///< most global optimization passes are done
  MMAT_GLBOPT3,      ///< completed all global optimization. microcode is fixed now.
  MMAT_LVARS,        ///< allocated local variables
};

//-------------------------------------------------------------------------
enum memreg_index_t  ///< memory region types
{
  MMIDX_GLBLOW,      ///< global memory: low part
  MMIDX_LVARS,       ///< stack: local variables
  MMIDX_RETADDR,     ///< stack: return address
  MMIDX_SHADOW,      ///< stack: shadow arguments
  MMIDX_ARGS,        ///< stack: regular stack arguments
  MMIDX_GLBHIGH,     ///< global memory: high part
};

//-------------------------------------------------------------------------
/// Ranges to decompile. Either a function or an explicit vector of ranges.
struct mba_ranges_t
{
  func_t *pfn = nullptr; ///< function to decompile. if not null, then function mode.
  rangevec_t ranges;     ///< snippet mode: ranges to decompile.
                         ///< function mode: list of outlined ranges
  mba_ranges_t(func_t *_pfn=nullptr) : pfn(_pfn) {}
  mba_ranges_t(const rangevec_t &r) : ranges(r) {}
  ea_t start(void) const { return (pfn != nullptr ? *pfn : ranges[0]).start_ea; }
  bool empty(void) const { return pfn == nullptr && ranges.empty(); }
  void clear(void) { pfn = nullptr; ranges.clear(); }
  bool is_snippet(void) const { return pfn == nullptr; }
  bool hexapi range_contains(ea_t ea) const;
  bool is_fragmented(void) const
  {
    int n_frags = ranges.size();
    if ( pfn != nullptr )
      n_frags += pfn->tailqty + 1;
    return n_frags > 1;
  }
};

/// Item iterator of arbitrary rangevec items
struct range_item_iterator_t
{
  const rangevec_t *ranges = nullptr;
  const range_t *rptr = nullptr;       // pointer into ranges
  ea_t cur = BADADDR;                  // current address
  bool set(const rangevec_t &r);
  bool next_code(void);
  ea_t current(void) const { return cur; }
};

/// Item iterator for mba_ranges_t
struct mba_item_iterator_t
{
  range_item_iterator_t rii;
  func_item_iterator_t fii;
  bool func_items_done = true;
  bool set(const mba_ranges_t &mbr)
  {
    bool ok = false;
    if ( mbr.pfn != nullptr )
    {
      ok = fii.set(mbr.pfn);
      if ( ok )
        func_items_done = false;
    }
    if ( rii.set(mbr.ranges) )
      ok = true;
    return ok;
  }
  bool next_code(void)
  {
    bool ok = false;
    if ( !func_items_done )
    {
      ok = fii.next_code();
      if ( !ok )
        func_items_done = true;
    }
    if ( !ok )
      ok = rii.next_code();
    return ok;
  }
  ea_t current(void) const
  {
    return func_items_done ? rii.current() : fii.current();
  }
};

/// Chunk iterator of arbitrary rangevec items
struct range_chunk_iterator_t
{
  const range_t *rptr = nullptr;          // pointer into ranges
  const range_t *rend = nullptr;
  bool set(const rangevec_t &r) { rptr = r.begin(); rend = r.end(); return rptr != rend; }
  bool next(void) { return ++rptr != rend; }
  const range_t &chunk(void) const { return *rptr; }
};

/// Chunk iterator for mba_ranges_t
struct mba_range_iterator_t
{
  range_chunk_iterator_t rii;
  func_tail_iterator_t fii;     // this is used if rii.rptr==nullptr
  bool is_snippet(void) const { return rii.rptr != nullptr; }
  bool set(const mba_ranges_t &mbr)
  {
    if ( mbr.is_snippet() )
      return rii.set(mbr.ranges);
    else
      return fii.set(mbr.pfn);
  }
  bool next(void)
  {
    if ( is_snippet() )
      return rii.next();
    else
      return fii.next();
  }
  const range_t &chunk(void) const
  {
    return is_snippet() ? rii.chunk() : fii.chunk();
  }
};

//-------------------------------------------------------------------------
/// Array of micro blocks representing microcode for a decompiled function.
/// The first micro block is the entry point, the last one is the exit point.
/// The entry and exit blocks are always empty. The exit block is generated
/// at MMAT_LOCOPT maturity level.
class mba_t
{
  DECLARE_UNCOPYABLE(mba_t)
  uint32 flags;
  uint32 flags2;

public:
                     // bits to describe the microcode, set by the decompiler
#define MBA_PRCDEFS  0x00000001 ///< use precise defeas for chain-allocated lvars
#define MBA_NOFUNC   0x00000002 ///< function is not present, addresses might be wrong
#define MBA_PATTERN  0x00000004 ///< microcode pattern, callinfo is present
#define MBA_LOADED   0x00000008 ///< loaded gdl, no instructions (debugging)
#define MBA_RETFP    0x00000010 ///< function returns floating point value
#define MBA_SPLINFO  0x00000020 ///< (final_type ? idb_spoiled : spoiled_regs) is valid
#define MBA_PASSREGS 0x00000040 ///< has mcallinfo_t::pass_regs
#define MBA_THUNK    0x00000080 ///< thunk function
#define MBA_CMNSTK   0x00000100 ///< stkvars+stkargs should be considered as one area

                     // bits to describe analysis stages and requests
#define MBA_PREOPT   0x00000200 ///< preoptimization stage complete
#define MBA_CMBBLK   0x00000400 ///< request to combine blocks
#define MBA_ASRTOK   0x00000800 ///< assertions have been generated
#define MBA_CALLS    0x00001000 ///< callinfo has been built
#define MBA_ASRPROP  0x00002000 ///< assertion have been propagated
#define MBA_SAVRST   0x00004000 ///< save-restore analysis has been performed
#define MBA_RETREF   0x00008000 ///< return type has been refined
#define MBA_GLBOPT   0x00010000 ///< microcode has been optimized globally
#define MBA_LVARS0   0x00040000 ///< lvar pre-allocation has been performed
#define MBA_LVARS1   0x00080000 ///< lvar real allocation has been performed
#define MBA_DELPAIRS 0x00100000 ///< pairs have been deleted once
#define MBA_CHVARS   0x00200000 ///< can verify chain varnums

                     // bits that can be set by the caller:
#define MBA_SHORT    0x00400000 ///< use short display
#define MBA_COLGDL   0x00800000 ///< display graph after each reduction
#define MBA_INSGDL   0x01000000 ///< display instruction in graphs
#define MBA_NICE     0x02000000 ///< apply transformations to c code
#define MBA_REFINE   0x04000000 ///< may refine return value size
#define MBA_WINGR32  0x10000000 ///< use wingraph32
#define MBA_NUMADDR  0x20000000 ///< display definition addresses for numbers
#define MBA_VALNUM   0x40000000 ///< display value numbers

#define MBA_INITIAL_FLAGS  (MBA_INSGDL|MBA_NICE|MBA_CMBBLK|MBA_REFINE\
        |MBA_PRCDEFS|MBA_WINGR32|MBA_VALNUM)

#define MBA2_LVARNAMES_OK  0x00000001 ///< may verify lvar_names?
#define MBA2_LVARS_RENAMED 0x00000002 ///< accept empty names now?
#define MBA2_OVER_CHAINS   0x00000004 ///< has overlapped chains?
#define MBA2_VALRNG_DONE   0x00000008 ///< calculated valranges?
#define MBA2_IS_CTR        0x00000010 ///< is constructor?
#define MBA2_IS_DTR        0x00000020 ///< is destructor?
#define MBA2_ARGIDX_OK     0x00000040 ///< may verify input argument list?
#define MBA2_NO_DUP_CALLS  0x00000080 ///< forbid multiple calls with the same ea
#define MBA2_NO_DUP_LVARS  0x00000100 ///< forbid multiple lvars with the same ea
#define MBA2_UNDEF_RETVAR  0x00000200 ///< return value is undefined
#define MBA2_ARGIDX_SORTED 0x00000400 ///< args finally sorted according to ABI
                                      ///< (e.g. reverse stkarg order in Borland)
#define MBA2_CODE16_BIT    0x00000800 ///< the code16 bit removed
#define MBA2_STACK_RETVAL  0x00001000 ///< the return value is on the stack
#define MBA2_HAS_OUTLINES  0x00002000 ///< calls to outlined code have been inlined
#define MBA2_NO_FRAME      0x00004000 ///< do not use function frame info (only snippet mode)
#define MBA2_PROP_COMPLEX  0x00008000 ///< allow propagation of more complex variable definitions

#define MBA2_DONT_VERIFY   0x80000000 ///< Do not verify microcode. This flag
                                      ///< is recomended to be set only when
                                      ///< debugging decompiler plugins

#define MBA2_INITIAL_FLAGS  (MBA2_LVARNAMES_OK|MBA2_LVARS_RENAMED)

#define MBA2_ALL_FLAGS    0x0000FFFF

  bool precise_defeas(void) const { return (flags & MBA_PRCDEFS) != 0; }
  bool optimized(void)      const { return (flags & MBA_GLBOPT) != 0; }
  bool short_display(void)  const { return (flags & MBA_SHORT ) != 0; }
  bool show_reduction(void) const { return (flags & MBA_COLGDL) != 0; }
  bool graph_insns(void)    const { return (flags & MBA_INSGDL) != 0; }
  bool loaded_gdl(void)     const { return (flags & MBA_LOADED) != 0; }
  bool should_beautify(void)const { return (flags & MBA_NICE  ) != 0; }
  bool rtype_refined(void)  const { return (flags & MBA_RETREF) != 0; }
  bool may_refine_rettype(void) const { return (flags & MBA_REFINE) != 0; }
  bool use_wingraph32(void) const { return (flags & MBA_WINGR32) != 0; }
  bool display_numaddrs(void) const { return (flags & MBA_NUMADDR) != 0; }
  bool display_valnums(void) const { return (flags & MBA_VALNUM) != 0; }
  bool is_pattern(void)     const { return (flags & MBA_PATTERN) != 0; }
  bool is_thunk(void)       const { return (flags & MBA_THUNK) != 0; }
  bool saverest_done(void)  const { return (flags & MBA_SAVRST) != 0; }
  bool callinfo_built(void) const { return (flags & MBA_CALLS) != 0; }
  bool really_alloc(void)   const { return (flags & MBA_LVARS0) != 0; }
  bool lvars_allocated(void)const { return (flags & MBA_LVARS1) != 0; }
  bool chain_varnums_ok(void)const { return (flags & MBA_CHVARS) != 0; }
  bool returns_fpval(void)  const { return (flags & MBA_RETFP) != 0; }
  bool has_passregs(void)   const { return (flags & MBA_PASSREGS) != 0; }
  bool generated_asserts(void) const { return (flags & MBA_ASRTOK) != 0; }
  bool propagated_asserts(void) const { return (flags & MBA_ASRPROP) != 0; }
  bool deleted_pairs(void) const { return (flags & MBA_DELPAIRS) != 0; }
  bool common_stkvars_stkargs(void) const { return (flags & MBA_CMNSTK) != 0; }
  bool lvar_names_ok(void) const { return (flags2 & MBA2_LVARNAMES_OK) != 0; }
  bool lvars_renamed(void) const { return (flags2 & MBA2_LVARS_RENAMED) != 0; }
  bool has_over_chains(void) const { return (flags2 & MBA2_OVER_CHAINS) != 0; }
  bool valranges_done(void) const { return (flags2 & MBA2_VALRNG_DONE) != 0; }
  bool argidx_ok(void) const { return (flags2 & MBA2_ARGIDX_OK) != 0; }
  bool argidx_sorted(void) const { return (flags2 & MBA2_ARGIDX_SORTED) != 0; }
  bool code16_bit_removed(void) const { return (flags2 & MBA2_CODE16_BIT) != 0; }
  bool has_stack_retval(void) const { return (flags2 & MBA2_STACK_RETVAL) != 0; }
  bool has_outlines(void) const { return (flags2 & MBA2_HAS_OUTLINES) != 0; }
  bool is_ctr(void) const { return (flags2 & MBA2_IS_CTR) != 0; }
  bool is_dtr(void) const { return (flags2 & MBA2_IS_DTR) != 0; }
  bool is_cdtr(void) const { return (flags2 & (MBA2_IS_CTR|MBA2_IS_DTR)) != 0; }
  bool prop_complex(void) const { return (flags2 & MBA2_PROP_COMPLEX) != 0; }
  int  get_mba_flags(void) const { return flags; }
  int  get_mba_flags2(void) const { return flags2; }
  void set_mba_flags(int f) { flags |= f; }
  void clr_mba_flags(int f) { flags &= ~f; }
  void set_mba_flags2(int f) { flags2 |= f; }
  void clr_mba_flags2(int f) { flags2 &= ~f; }
  void clr_cdtr(void) { flags2 &= ~(MBA2_IS_CTR|MBA2_IS_DTR); }
  int calc_shins_flags(void) const
  {
    int shins_flags = 0;
    if ( short_display() )
      shins_flags |= SHINS_SHORT;
    if ( display_valnums() )
      shins_flags |= SHINS_VALNUM;
    if ( display_numaddrs() )
      shins_flags |= SHINS_NUMADDR;
    return shins_flags;
  }

/*
                     +-----------+ <- inargtop
                     |   prmN    |
                     |   ...     | <- minargref
                     |   prm0    |
                     +-----------+ <- inargoff
                     |shadow_args|
                     +-----------+
                     |  retaddr  |
     frsize+frregs   +-----------+ <- initial esp  |
                     |  frregs   |                 |
           +frsize   +-----------+ <- typical ebp  |
                     |           |  |              |
                     |           |  | fpd          |
                     |           |  |              |
                     |  frsize   | <- current ebp  |
                     |           |                 |
                     |           |                 |
                     |           |                 | stacksize
                     |           |                 |
                     |           |                 |
                     |           | <- minstkref    |
 stkvar base off 0   +---..      |                 |    | current
                     |           |                 |    | stack
                     |           |                 |    | pointer
                     |           |                 |    | range
                     |tmpstk_size|                 |    | (what getspd() returns)
                     |           |                 |    |
                     |           |                 |    |
                     +-----------+ <- minimal sp   |    | offset 0 for the decompiler (vd)

  There is a detail that may add confusion when working with stack variables.
  The decompiler does not use the same stack offsets as IDA.
  The picture above should explain the difference:
  - IDA stkoffs are displayed on the left, decompiler stkoffs - on the right
  - Decompiler stkoffs are always >= 0
  - IDA stkoff==0 corresponds to stkoff==tmpstk_size in the decompiler
  - See stkoff_vd2ida and stkoff_ida2vd below to convert IDA stkoffs to vd stkoff

*/

  // convert a stack offset used in vd to a stack offset used in ida stack frame
  sval_t hexapi stkoff_vd2ida(sval_t off) const;
  // convert a ida stack frame offset to a stack offset used in vd
  sval_t hexapi stkoff_ida2vd(sval_t off) const;
  sval_t argbase() const
  {
    return retsize + stacksize;
  }
  static vdloc_t hexapi idaloc2vd(const argloc_t &loc, int width, sval_t spd);
  vdloc_t hexapi idaloc2vd(const argloc_t &loc, int width) const;

  static argloc_t hexapi vd2idaloc(const vdloc_t &loc, int width, sval_t spd);
  argloc_t hexapi vd2idaloc(const vdloc_t &loc, int width) const;

  bool is_stkarg(const lvar_t &v) const
  {
    return v.is_stk_var() && v.get_stkoff() >= inargoff;
  }
  member_t *get_stkvar(sval_t vd_stkoff, uval_t *poff) const;
  // get lvar location
  argloc_t get_ida_argloc(const lvar_t &v) const
  {
    return vd2idaloc(v.location, v.width);
  }
  mba_ranges_t mbr;
  ea_t entry_ea = BADADDR;
  ea_t last_prolog_ea = BADADDR;
  ea_t first_epilog_ea = BADADDR;
  int qty = 0;                  ///< number of basic blocks
  int npurged = -1;             ///< -1 - unknown
  cm_t cc = CM_CC_UNKNOWN;      ///< calling convention
  sval_t tmpstk_size = 0;       ///< size of the temporary stack part
                                ///< (which dynamically changes with push/pops)
  sval_t frsize = 0;            ///< size of local stkvars range in the stack frame
  sval_t frregs = 0;            ///< size of saved registers range in the stack frame
  sval_t fpd = 0;               ///< frame pointer delta
  int pfn_flags = 0;            ///< copy of func_t::flags
  int retsize = 0;              ///< size of return address in the stack frame
  int shadow_args = 0;          ///< size of shadow argument area
  sval_t fullsize = 0;          ///< Full stack size including incoming args
  sval_t stacksize = 0;         ///< The maximal size of the function stack including
                                ///< bytes allocated for outgoing call arguments
                                ///< (up to retaddr)
  sval_t inargoff = 0;          ///< offset of the first stack argument;
                                ///< after fix_scattered_movs() INARGOFF may
                                ///< be less than STACKSIZE
  sval_t minstkref = 0;         ///< The lowest stack location whose address was taken
  ea_t minstkref_ea = BADADDR;  ///< address with lowest minstkref (for debugging)
  sval_t minargref = 0;         ///< The lowest stack argument location whose address was taken
                                ///< This location and locations above it can be aliased
                                ///< It controls locations >= inargoff-shadow_args
  sval_t spd_adjust = 0;        ///< If sp>0, the max positive sp value
  ivl_t aliased_vars = ivl_t(0, 0); ///< Aliased stkvar locations
  ivl_t aliased_args = ivl_t(0, 0); ///< Aliased stkarg locations
  ivlset_t gotoff_stkvars;      ///< stkvars that hold .got offsets. considered to be unaliasable
  ivlset_t restricted_memory;
  ivlset_t aliased_memory = ALLMEM; ///< aliased_memory+restricted_memory=ALLMEM
  mlist_t nodel_memory;         ///< global dead elimination may not delete references to this area
  rlist_t consumed_argregs;     ///< registers converted into stack arguments, should not be used as arguments

  mba_maturity_t maturity = MMAT_ZERO; ///< current maturity level
  mba_maturity_t reqmat = MMAT_ZERO;   ///< required maturity level

  bool final_type = false;      ///< is the function type final? (specified by the user)
  tinfo_t idb_type;             ///< function type as retrieved from the database
  reginfovec_t idb_spoiled;     ///< MBA_SPLINFO && final_type: info in ida format
  mlist_t spoiled_list;         ///< MBA_SPLINFO && !final_type: info in vd format
  int fti_flags = 0;            ///< FTI_... constants for the current function

  netnode deprecated_idb_node;  ///< netnode with additional decompiler info.
                                ///< deprecated, do not use it anymore. it may get
                                ///< stale after undo.
#define NALT_VD 2               ///< this index is not used by ida

  qstring label;                ///< name of the function or pattern (colored)
  lvars_t vars;                 ///< local variables
  intvec_t argidx;              ///< input arguments (indexes into 'vars')
  int retvaridx = -1;           ///< index of variable holding the return value
                                ///< -1 means none

  ea_t error_ea = BADADDR;      ///< during microcode generation holds ins.ea
  qstring error_strarg;

  mblock_t *blocks = nullptr;   ///< double linked list of blocks
  mblock_t **natural = nullptr; ///< natural order of blocks

  ivl_with_name_t std_ivls[6];  ///< we treat memory as consisting of 6 parts
                                ///< see \ref memreg_index_t

  mutable hexwarns_t notes;
  mutable uchar occurred_warns[32]; // occurred warning messages
                                    // (even disabled warnings are taken into account)
  bool write_to_const_detected(void) const
  {
    return test_bit(occurred_warns, WARN_WRITE_CONST);
  }
  bool bad_call_sp_detected(void) const
  {
    return test_bit(occurred_warns, WARN_BAD_CALL_SP);
  }
  bool regargs_is_not_aligned(void) const
  {
    return test_bit(occurred_warns, WARN_UNALIGNED_ARG);
  }
  bool has_bad_sp(void) const
  {
    return test_bit(occurred_warns, WARN_BAD_SP);
  }

  // the exact size of this class is not documented, there may be more fields
  char reserved[];
  mba_t(); // use gen_microcode() or create_empty_mba() to create microcode objects
  ~mba_t() { term(); }
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
  void hexapi term(void);
  func_t *hexapi get_curfunc() const;
  bool use_frame(void) const { return get_curfunc() != nullptr; }
  bool range_contains(ea_t ea) const { return mbr.range_contains(map_fict_ea(ea)); }
  bool is_snippet(void) const { return mbr.is_snippet(); }

  /// Set maturity level.
  /// \param mat new maturity level
  /// \return true if it is time to stop analysis
  /// Plugins may use this function to skip some parts of the analysis.
  /// The maturity level cannot be decreased.
  bool hexapi set_maturity(mba_maturity_t mat);

  /// Optimize each basic block locally
  /// \param locopt_bits combination of \ref LOCOPT_ bits
  /// \return number of changes. 0 means nothing changed
  /// This function is called by the decompiler, usually there is no need to
  /// call it explicitly.
  int hexapi optimize_local(int locopt_bits);
  /// \defgroup LOCOPT_ Bits for optimize_local()
  //@{
#define LOCOPT_ALL     0x0001 ///< redo optimization for all blocks. if this bit
                              ///< is not set, only dirty blocks will be optimized
#define LOCOPT_REFINE  0x0002 ///< refine return type, ok to fail
#define LOCOPT_REFINE2 0x0004 ///< refine return type, try harder
  //@}

  /// Build control flow graph.
  /// This function may be called only once. It calculates the type of each
  /// basic block and the adjacency list. optimize_local() calls this function
  /// if necessary. You need to call this function only before MMAT_LOCOPT.
  /// \return error code
  merror_t hexapi build_graph(void);

  /// Get control graph.
  /// Call build_graph() if you need the graph before MMAT_LOCOPT.
  mbl_graph_t *hexapi get_graph(void);

  /// Analyze calls and determine calling conventions.
  /// \param acflags permitted actions that are necessary for successful detection
  ///                of calling conventions. See \ref ACFL_
  /// \return number of calls. -1 means error.
  int hexapi analyze_calls(int acflags);
  /// \defgroup ACFL_ Bits for analyze_calls()
  //@{
#define ACFL_LOCOPT  0x01 ///< perform local propagation (requires ACFL_BLKOPT)
#define ACFL_BLKOPT  0x02 ///< perform interblock transformations
#define ACFL_GLBPROP 0x04 ///< perform global propagation
#define ACFL_GLBDEL  0x08 ///< perform dead code eliminition
#define ACFL_GUESS   0x10 ///< may guess calling conventions
  //@}

  /// Optimize microcode globally.
  /// This function applies various optimization methods until we reach the
  /// fixed point. After that it preallocates lvars unless reqmat forbids it.
  /// \return error code
  merror_t hexapi optimize_global(void);

  /// Allocate local variables.
  /// Must be called only immediately after optimize_global(), with no
  /// modifications to the microcode. Converts registers,
  /// stack variables, and similar operands into mop_l. This call will not fail
  /// because all necessary checks were performed in optimize_global().
  /// After this call the microcode reaches its final state.
  void hexapi alloc_lvars(void);

  /// Dump microcode to a file.
  /// The file will be created in the directory pointed by IDA_DUMPDIR envvar.
  /// Dump will be created only if IDA is run under debugger.
  void hexapi dump(void) const;
  AS_PRINTF(3, 0) void hexapi vdump_mba(bool _verify, const char *title, va_list va) const;
  AS_PRINTF(3, 4) void dump_mba(bool _verify, const char *title, ...) const
  {
    va_list va;
    va_start(va, title);
    vdump_mba(_verify, title, va);
    va_end(va);
  }

  /// Print microcode to any destination.
  /// \param vp print sink
  void hexapi print(vd_printer_t &vp) const;

  /// Verify microcode consistency.
  /// \param always if false, the check will be performed only if ida runs
  ///               under debugger
  /// If any inconsistency is discovered, an internal error will be generated.
  /// We strongly recommend you to call this function before returing control
  /// to the decompiler from your callbacks, in the case if you modified
  /// the microcode. If the microcode is inconsistent, this function will
  /// generate an internal error. We provide the source code of this function
  /// in the plugins/hexrays_sdk/verifier directory for your reference.
  void hexapi verify(bool always) const;

  /// Mark the microcode use-def chains dirty.
  /// Call this function is any inter-block data dependencies got changed
  /// because of your modifications to the microcode. Failing to do so may
  /// cause an internal error.
  void hexapi mark_chains_dirty(void);

  /// Get basic block by its serial number.
  const mblock_t *get_mblock(int n) const { return natural[n]; }
  mblock_t *get_mblock(int n) { return CONST_CAST(mblock_t*)((CONST_CAST(const mba_t *)(this))->get_mblock(n)); }

  /// Insert a block in the middle of the mbl array.
  /// The very first block of microcode must be empty, it is the entry block.
  /// The very last block of microcode must be BLT_STOP, it is the exit block.
  /// Therefore inserting a new block before the entry point or after the exit
  /// block is not a good idea.
  /// \param bblk the new block will be inserted before BBLK
  /// \return ptr to the new block
  mblock_t *hexapi insert_block(int bblk);

  /// Delete a block.
  /// \param blk block to delete
  /// \return true if at least one of the other blocks became empty or unreachable
  bool hexapi remove_block(mblock_t *blk);

  /// Make a copy of a block.
  /// This function makes a simple copy of the block. It does not fix the
  /// predecessor and successor lists, they must be fixed if necessary.
  /// \param blk         block to copy
  /// \param new_serial  position of the copied block
  /// \param cpblk_flags combination of \ref CPBLK_... bits
  /// \return pointer to the new copy
  mblock_t *hexapi copy_block(mblock_t *blk, int new_serial, int cpblk_flags=3);
/// \defgroup CPBLK_ Batch decompilation bits
//@{
#define CPBLK_FAST   0x0000     ///< do not update minbstkref and minbargref
#define CPBLK_MINREF 0x0001     ///< update minbstkref and minbargref
#define CPBLK_OPTJMP 0x0002     ///< del the jump insn at the end of the block
                                ///< if it becomes useless
//@}

  /// Delete all empty and unreachable blocks.
  /// Blocks marked with MBL_KEEP won't be deleted.
  bool hexapi remove_empty_and_unreachable_blocks(void);

  /// Combine blocks.
  /// This function merges blocks constituting linear flow.
  /// It calls remove_empty_and_unreachable_blocks() as well.
  /// \return true if changed any blocks
  bool hexapi combine_blocks(void);

  /// Visit all operands of all instructions.
  /// \param mv operand visitor
  /// \return non-zero value returned by mv.visit_mop() or zero
  int hexapi for_all_ops(mop_visitor_t &mv);

  /// Visit all instructions.
  /// This function visits all instruction and subinstructions.
  /// \param mv instruction visitor
  /// \return non-zero value returned by mv.visit_mop() or zero
  int hexapi for_all_insns(minsn_visitor_t &mv);

  /// Visit all top level instructions.
  /// \param mv instruction visitor
  /// \return non-zero value returned by mv.visit_mop() or zero
  int hexapi for_all_topinsns(minsn_visitor_t &mv);

  /// Find an operand in the microcode.
  /// This function tries to find the operand that matches LIST.
  /// Any operand that overlaps with LIST is considered as a match.
  /// \param[out] ctx context information for the result
  /// \param ea       desired address of the operand. BADADDR means to accept any address.
  /// \param is_dest  search for destination operand? this argument may be
  ///                 ignored if the exact match could not be found
  /// \param list     list of locations the correspond to the operand
  /// \return pointer to the operand or nullptr.
  mop_t *hexapi find_mop(op_parent_info_t *ctx, ea_t ea, bool is_dest, const mlist_t &list);

  /// Create a call of a helper function.
  /// \param ea       The desired address of the instruction
  /// \param helper   The helper name
  /// \param rettype  The return type (nullptr or empty type means 'void')
  /// \param callargs The helper arguments (nullptr-no arguments)
  /// \param out      The operand where the call result should be stored.
  ///                 If this argument is not nullptr, "mov helper_call(), out"
  ///                 will be generated. Otherwise "call helper()" will be
  ///                 generated. Note: the size of this operand must be equal
  ///                 to the RETTYPE size
  /// \return pointer to the created instruction or nullptr if error
  minsn_t *hexapi create_helper_call(
        ea_t ea,
        const char *helper,
        const tinfo_t *rettype=nullptr,
        const mcallargs_t *callargs=nullptr,
        const mop_t *out=nullptr);

  /// Prepare the lists of registers & memory that are defined/killed by a
  /// function
  /// \param[out] return_regs  defined regs to return (eax,edx)
  /// \param[out] spoiled      spoiled regs (flags,ecx,mem)
  /// \param      type         the function type
  /// \param      call_ea      the call insn address (if known)
  /// \param      tail_call    is it the tail call?
  void hexapi get_func_output_lists(
        mlist_t *return_regs,
        mlist_t *spoiled,
        const tinfo_t &type,
        ea_t call_ea=BADADDR,
        bool tail_call=false);

  /// Get input argument of the decompiled function.
  /// \param n argument number (0..nargs-1)
  lvar_t &hexapi arg(int n);
  const lvar_t &arg(int n) const { return CONST_CAST(mba_t*)(this)->arg(n); }

  /// Allocate a fictional address.
  /// This function can be used to allocate a new unique address for a new
  /// instruction, if re-using any existing address leads to conflicts.
  /// For example, if the last instruction of the function modifies R0
  /// and falls through to the next function, it will be a tail call:
  ///    LDM R0!, {R4,R7}
  ///    end of the function
  ///    start of another function
  /// In this case R0 generates two different lvars at the same address:
  ///   - one modified by LDM
  ///   - another that represents the return value from the tail call
  /// Another example: a third-party plugin makes a copy of an instruction.
  /// This may lead to the generation of two variables at the same address.
  /// Example 3: fictional addresses can be used for new instructions created
  /// while modifying the microcode.
  /// This function can be used to allocate a new unique address for a new
  /// instruction or a variable.
  /// The fictional address is selected from an unallocated address range.
  /// \param real_ea real instruction address (BADADDR is ok too)
  /// \return a unique fictional address
  ea_t hexapi alloc_fict_ea(ea_t real_ea);

  /// Resolve a fictional address.
  /// This function provides a reverse of the mapping made by alloc_fict_ea().
  /// \param fict_ea fictional definition address
  /// \return the real instruction address
  ea_t hexapi map_fict_ea(ea_t fict_ea) const;

  /// Get information about various memory regions.
  /// We map the stack frame to the global memory, to some unused range.
  const ivl_t &get_std_region(memreg_index_t idx) const;
  const ivl_t &get_lvars_region(void) const;
  const ivl_t &get_shadow_region(void) const;
  const ivl_t &get_args_region(void) const;
  ivl_t get_stack_region(void) const; // get entire stack region

  /// Serialize mbl array into a sequence of bytes.
  void hexapi serialize(bytevec_t &vout) const;

  /// Deserialize a byte sequence into mbl array.
  /// \param bytes pointer to the beginning of the byte sequence.
  /// \param nbytes number of bytes in the byte sequence.
  /// \return new mbl array
  WARN_UNUSED_RESULT static mba_t *hexapi deserialize(const uchar *bytes, size_t nbytes);

  /// Create and save microcode snapshot
  void hexapi save_snapshot(const char *description);

  /// Allocate a kernel register.
  /// \param size size of the register in bytes
  /// \param check_size if true, only the sizes that correspond to a size of
  ///                   a basic type will be accepted.
  /// \return allocated register. mr_none means failure.
  mreg_t hexapi alloc_kreg(size_t size, bool check_size=true);

  /// Free a kernel register.
  /// If wrong arguments are passed, this function will generate an internal error.
  /// \param reg a previously allocated kernel register
  /// \param size size of the register in bytes
  void hexapi free_kreg(mreg_t reg, size_t size);
  bool hexapi set_lvar_name(lvar_t &v, const char *name, int flagbits);
  bool set_nice_lvar_name(lvar_t &v, const char *name) { return set_lvar_name(v, name, CVAR_NAME); }
  bool set_user_lvar_name(lvar_t &v, const char *name) { return set_lvar_name(v, name, CVAR_NAME|CVAR_UNAME); }
};
using mbl_array_t = mba_t;
//-------------------------------------------------------------------------
/// Convenience class to release graph chains automatically.
/// Use this class instead of using graph_chains_t directly.
class chain_keeper_t
{
  graph_chains_t *gc;
  chain_keeper_t &operator=(const chain_keeper_t &); // not defined
public:
  chain_keeper_t(graph_chains_t *_gc) : gc(_gc) { QASSERT(50446, gc != nullptr); gc->acquire(); }
  ~chain_keeper_t(void)
  {
    gc->release();
  }
  block_chains_t &operator[](size_t idx) { return (*gc)[idx]; }
  block_chains_t &front(void) { return gc->front(); }
  block_chains_t &back(void) { return gc->back(); }
  operator graph_chains_t &(void) { return *gc; }
  int for_all_chains(chain_visitor_t &cv, int gca) { return gc->for_all_chains(cv, gca); }
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
};

//-------------------------------------------------------------------------
/// Kind of use-def and def-use chains
enum gctype_t
{
  GC_REGS_AND_STKVARS, ///< registers and stkvars (restricted memory only)
  GC_ASR,              ///< all the above and assertions
  GC_XDSU,             ///< only registers calculated with FULL_XDSU
  GC_END,              ///< number of chain types
  GC_DIRTY_ALL = (1 << (2*GC_END))-1, ///< bitmask to represent all chains
};

//-------------------------------------------------------------------------
/// Control flow graph of microcode.
class mbl_graph_t : public simple_graph_t
{
  mba_t *mba;     ///< pointer to the mbl array
  int dirty;            ///< what kinds of use-def chains are dirty?
  int chain_stamp;      ///< we increment this counter each time chains are recalculated
  graph_chains_t gcs[2*GC_END]; ///< cached use-def chains

  /// Is LIST accessed between two instructions?
  /// This function can analyze all path between the specified instructions
  /// and find if the specified list is used in any of them. The instructions
  /// may be located in different basic blocks. This function does not use
  /// use-def chains but use the graph for analysis. It may be slow in some
  /// cases but its advantage is that is does not require building the use-def
  /// chains.
  /// \param list list to verify
  /// \param b1   starting block
  /// \param b2   ending block. may be -1, it means all possible paths from b1
  /// \param m1   starting instruction (in b1)
  /// \param m2   ending instruction (in b2). excluded. may be nullptr.
  /// \param access_type read or write access?
  /// \param maymust may access or must access?
  /// \return true if found an access to the list
  bool hexapi is_accessed_globally(
        const mlist_t &list,   // list to verify
        int b1,                // starting block
        int b2,                // ending block
        const minsn_t *m1,     // starting instruction (in b1)
        const minsn_t *m2,     // ending instruction (in b2)
        access_type_t access_type,
        maymust_t maymust) const;
  int get_ud_gc_idx(gctype_t gctype) const { return (gctype << 1); }
  int get_du_gc_idx(gctype_t gctype) const { return (gctype << 1)+1; }
  int get_ud_dirty_bit(gctype_t gctype) { return 1 << get_ud_gc_idx(gctype); }
  int get_du_dirty_bit(gctype_t gctype) { return 1 << get_du_gc_idx(gctype); }

public:
  /// Is the use-def chain of the specified kind dirty?
  bool is_ud_chain_dirty(gctype_t gctype)
  {
    int bit = get_ud_dirty_bit(gctype);
    return (dirty & bit) != 0;
  }

  /// Is the def-use chain of the specified kind dirty?
  bool is_du_chain_dirty(gctype_t gctype)
  {
    int bit = get_du_dirty_bit(gctype);
    return (dirty & bit) != 0;
  }
  int get_chain_stamp(void) const { return chain_stamp; }

  /// Get use-def chains.
  graph_chains_t *hexapi get_ud(gctype_t gctype);

  /// Get def-use chains.
  graph_chains_t *hexapi get_du(gctype_t gctype);

  /// Is LIST redefined in the graph?
  bool is_redefined_globally(const mlist_t &list, int b1, int b2, const minsn_t *m1, const minsn_t *m2, maymust_t maymust=MAY_ACCESS) const
    { return is_accessed_globally(list, b1, b2, m1, m2, WRITE_ACCESS, maymust); }

  /// Is LIST used in the graph?
  bool is_used_globally(const mlist_t &list, int b1, int b2, const minsn_t *m1, const minsn_t *m2, maymust_t maymust=MAY_ACCESS) const
    { return is_accessed_globally(list, b1, b2, m1, m2, READ_ACCESS, maymust); }

  mblock_t *get_mblock(int n) const { return mba->get_mblock(n); }
};

//-------------------------------------------------------------------------
// Helper for codegen_t. It takes into account delay slots
struct cdg_insn_iterator_t
{
  const mba_t *mba;       // to check range
  ea_t ea = BADADDR;      // next insn to decode
  ea_t end = BADADDR;     // end of the block
  ea_t dslot = BADADDR;   // address of the insn in the delay slot
  insn_t dslot_insn;      // instruction in the delay slot
  ea_t severed_branch = BADADDR; // address of the severed branch insn
                          // (when this branch insn ends the previous block)
  bool is_likely_dslot = false; // execute delay slot only when jumping

  cdg_insn_iterator_t(const mba_t *mba_) : mba(mba_) {}
  cdg_insn_iterator_t(const cdg_insn_iterator_t &r) = default;
  cdg_insn_iterator_t &operator=(const cdg_insn_iterator_t &r) = default;

  bool ok() const { return ea < end; }
  bool has_dslot() const { return dslot != BADADDR; }
  bool dslot_with_xrefs() const { return dslot >= end; }
  // the current insn is the severed delayed insn (when this starts a block)
  bool is_severed_dslot() const { return severed_branch != BADADDR; }
  void start(const range_t &rng)
  {
    ea = rng.start_ea;
    end = rng.end_ea;
  }
  merror_t hexapi next(insn_t *ins);
};

//-------------------------------------------------------------------------
/// Helper class to generate the initial microcode
class codegen_t
{
public:
  mba_t *mba;             // ptr to mbl array
  mblock_t *mb = nullptr; // current basic block
  insn_t insn;            // instruction to generate microcode for
  char ignore_micro = IM_NONE; // value of get_ignore_micro() for the insn
  cdg_insn_iterator_t ii; // instruction iterator
  size_t reserved;

  codegen_t() = delete;
  virtual ~codegen_t(void)
  {
  }

  /// Analyze prolog/epilog of the function to decompile.
  /// If prolog is found, allocate and fill 'mba->pi' structure.
  /// \param fc flow chart
  /// \param reachable bitmap of reachable blocks
  /// \return error code
  virtual merror_t idaapi analyze_prolog(
        const class qflow_chart_t &fc,
        const class bitset_t &reachable) = 0;

  /// Generate microcode for one instruction.
  /// The instruction is in INSN
  /// \return MERR_OK     - all ok
  ///         MERR_BLOCK  - all ok, need to switch to new block
  ///         MERR_BADBLK - delete current block and continue
  ///         other error codes are fatal
  virtual merror_t idaapi gen_micro() = 0;

  /// Generate microcode to load one operand.
  /// \param opnum number of INSN operand
  /// \param flags reserved for future use
  /// \return register containing the operand.
  virtual mreg_t idaapi load_operand(int opnum, int flags=0) = 0;

  /// This method is called when the microcode generation is done
  virtual void idaapi microgen_completed() {}

  /// Setup internal data to handle new instruction.
  /// This method should be called before calling gen_micro().
  /// Usually gen_micro() is called by the decompiler. You have to call this
  /// function explicitly only if you yourself call gen_micro().
  /// The instruction is in INSN
  /// \return MERR_OK     - all ok
  ///         other error codes are fatal
  virtual merror_t idaapi prepare_gen_micro() { return MERR_OK; }

  /// Generate microcode to calculate the address of a memory operand.
  /// \param n     - number of INSN operand
  /// \param flags - reserved for future use
  /// \return register containing the operand address.
  ///         mr_none - failed (not a memory operand)
  virtual mreg_t idaapi load_effective_address(int n, int flags=0) = 0;

  /// Generate microcode to store an operand.
  /// In case of success an arbitrary number of instructions can be
  /// generated (and even no instruction if the source and target are the same)
  /// \param n      - number of target INSN operand
  /// \param mop    - operand to be stored
  /// \param flags  - reserved for future use
  /// \param outins - (OUT) the last generated instruction
  //                  (nullptr if no instruction was generated)
  /// \return success
  virtual bool idaapi store_operand(int n, const mop_t &mop, int flags=0, minsn_t **outins=nullptr);

  /// Emit one microinstruction.
  /// The L, R, D arguments usually mean the register number. However, they depend
  /// on CODE. For example:
  ///   - for m_goto and m_jcnd L is the target address
  ///   - for m_ldc L is the constant value to load
  /// \param code  instruction opcode
  /// \param width operand size in bytes
  /// \param l     left operand
  /// \param r     right operand
  /// \param d     destination operand
  /// \param offsize for ldx/stx, the size of the offset operand
  ///                for ldc, operand number of the constant value
  ///                -1, set the FP instruction (e.g. for m_mov)
  /// \return created microinstruction. can be nullptr if the instruction got
  ///         immediately optimized away.
  minsn_t *hexapi emit(mcode_t code, int width, uval_t l, uval_t r, uval_t d, int offsize);

  /// Emit one microinstruction.
  /// This variant takes a data type not a size.
  minsn_t *idaapi emit_micro_mvm(
        mcode_t code,
        op_dtype_t dtype,
        uval_t l,
        uval_t r,
        uval_t d,
        int offsize)
  {
    return emit(code, get_dtype_size(dtype), l, r, d, offsize);
  }

  /// Emit one microinstruction.
  /// This variant accepts pointers to operands. It is more difficult to use
  /// but permits to create virtually any instruction. Operands may be nullptr
  /// when it makes sense.
  minsn_t *hexapi emit(mcode_t code, const mop_t *l, const mop_t *r, const mop_t *d);

};

//-------------------------------------------------------------------------
/// Parse DIRECTIVE and update the current configuration variables.
/// For the syntax see hexrays.cfg
bool hexapi change_hexrays_config(const char *directive);

//-------------------------------------------------------------------------
inline void mop_t::_make_insn(minsn_t *ins)
{
  t = mop_d;
  d = ins;
}

inline bool mop_t::has_side_effects(bool include_ldx_and_divs) const
{
  return is_insn() && d->has_side_effects(include_ldx_and_divs);
}

inline bool mop_t::is_kreg(void) const
{
  return t == mop_r && ::is_kreg(r);
}

inline minsn_t *mop_t::get_insn(mcode_t code)
{
  return is_insn(code) ? d : nullptr;
}
inline const minsn_t *mop_t::get_insn(mcode_t code) const
{
  return is_insn(code) ? d : nullptr;
}

inline bool mop_t::is_insn(mcode_t code) const
{
  return is_insn() && d->opcode == code;
}

inline bool mop_t::is_glbaddr() const
{
  return t == mop_a && a->t == mop_v;
}

inline bool mop_t::is_glbaddr(ea_t ea) const
{
  return is_glbaddr() && a->g == ea;
}

inline bool mop_t::is_stkaddr() const
{
  return t == mop_a && a->t == mop_S;
}

inline vivl_t::vivl_t(const chain_t &ch)
  : voff_t(ch.key().type, ch.is_reg() ? ch.get_reg() : ch.get_stkoff()),
    size(ch.width)
{
}

// The following memory regions exist
//          start                     length
//          ------------------------  ---------
// lvars    spbase                    stacksize
// retaddr  spbase+stacksize          retsize
// shadow   spbase+stacksize+retsize  shadow_args
// args     inargoff                  MAX_FUNC_ARGS*sp_width-shadow_args
// globals  data_segment              sizeof_data_segment
// heap     everything else?

inline const ivl_t &mba_t::get_std_region(memreg_index_t idx) const
{
  return std_ivls[idx].ivl;
}

inline const ivl_t &mba_t::get_lvars_region(void) const
{
  return get_std_region(MMIDX_LVARS);
}

inline const ivl_t &mba_t::get_shadow_region(void) const
{
  return get_std_region(MMIDX_SHADOW);
}

inline const ivl_t &mba_t::get_args_region(void) const
{
  return get_std_region(MMIDX_ARGS);
}

inline ivl_t mba_t::get_stack_region(void) const
{
  return ivl_t(std_ivls[MMIDX_LVARS].ivl.off, fullsize);
}

//-------------------------------------------------------------------------
/// Get decompiler version.
/// The returned string is of the form <major>.<minor>.<revision>.<build-date>
/// \return pointer to version string. For example: "2.0.0.140605"

const char *hexapi get_hexrays_version(void);


/// Check out a floating decompiler license.
/// This function will display a dialog box if the license is not available.
/// For non-floating licenses this function is effectively no-op.
/// It is not necessary to call this function before decompiling.
/// If the license was not checked out, the decompiler will automatically do it.
/// This function can be used to check out a license in advance and ensure
/// that a license is available.
/// \param silent silently fail if the license cannot be checked out.
/// \return false if failed

bool hexapi checkout_hexrays_license(bool silent);

/// \defgroup OPF_ open_pseudocode flags
/// Used in open_pseudocode
//@{
#define OPF_REUSE        0x00  ///< reuse existing window
#define OPF_NEW_WINDOW   0x01  ///< open new window
#define OPF_REUSE_ACTIVE 0x02  ///< reuse existing window, only if the
                               ///< currently active widget is a pseudocode view
#define OPF_NO_WAIT      0x08  ///< do not display waitbox if decompilation happens
//@}

#define OPF_WINDOW_MGMT_MASK 0x07


/// Open pseudocode window.
/// The specified function is decompiled and the pseudocode window is opened.
/// \param ea function to decompile
/// \param flags: a combination of OPF_ flags
/// \return false if failed

vdui_t *hexapi open_pseudocode(ea_t ea, int flags);


/// Close pseudocode window.
/// \param f pointer to window
/// \return false if failed

bool hexapi close_pseudocode(TWidget *f);


/// Get the vdui_t instance associated to the TWidget
/// \param f pointer to window
/// \return a vdui_t *, or nullptr

vdui_t *hexapi get_widget_vdui(TWidget *f);


/// \defgroup VDRUN_ Batch decompilation bits
//@{
#define VDRUN_NEWFILE 0x00000000  ///< Create a new file or overwrite existing file
#define VDRUN_APPEND  0x00000001  ///< Create a new file or append to existing file
#define VDRUN_ONLYNEW 0x00000002  ///< Fail if output file already exists
#define VDRUN_SILENT  0x00000004  ///< Silent decompilation
#define VDRUN_SENDIDB 0x00000008  ///< Send problematic databases to hex-rays.com
#define VDRUN_MAYSTOP 0x00000010  ///< The user can cancel decompilation
#define VDRUN_CMDLINE 0x00000020  ///< Called from ida's command line
#define VDRUN_STATS   0x00000040  ///< Print statistics into vd_stats.txt
#define VDRUN_LUMINA  0x00000080  ///< Use lumina server
//@}

/// Batch decompilation.
/// Decompile all or the specified functions
/// \return true if no internal error occurred and the user has not cancelled decompilation
/// \param outfile name of the output file
/// \param funcaddrs list of functions to decompile.
///                  If nullptr or empty, then decompile all nonlib functions
/// \param flags \ref VDRUN_

bool hexapi decompile_many(const char *outfile, const eavec_t *funcaddrs, int flags);


/// Exception object: decompiler failure information
struct hexrays_failure_t
{
  merror_t code;                ///< \ref MERR_
  ea_t errea;                   ///< associated address
  qstring str;                  ///< string information
  hexrays_failure_t(void) : code(MERR_OK), errea(BADADDR) {}
  hexrays_failure_t(merror_t c, ea_t ea, const char *buf=nullptr) : code(c), errea(ea), str(buf) {}
  hexrays_failure_t(merror_t c, ea_t ea, const qstring &buf) : code(c), errea(ea), str(buf) {}
  qstring hexapi desc(void) const;
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
};

/// Exception object: decompiler exception
struct vd_failure_t : public std::exception
{
  hexrays_failure_t hf;
  vd_failure_t(void) {}
  vd_failure_t(merror_t code, ea_t ea, const char *buf=nullptr) : hf(code, ea, buf) {}
  vd_failure_t(merror_t code, ea_t ea, const qstring &buf) : hf(code, ea, buf) {}
  vd_failure_t(const hexrays_failure_t &_hf) : hf(_hf) {}
  qstring desc(void) const { return hf.desc(); }
#ifdef __GNUC__
  ~vd_failure_t(void) throw() {}
#endif
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
};

/// Exception object: decompiler internal error
struct vd_interr_t : public vd_failure_t
{
  vd_interr_t(ea_t ea, const qstring &buf) : vd_failure_t(MERR_INTERR, ea, buf) {}
  vd_interr_t(ea_t ea, const char *buf) : vd_failure_t(MERR_INTERR, ea, buf) {}
};

/// Send the database to Hex-Rays.
/// This function sends the current database to the Hex-Rays server.
/// The database is sent in the compressed form over an encrypted (SSL) connection.
/// \param err failure description object. Empty hexrays_failure_t object can
///            be used if error information is not available.
/// \param silent if false, a dialog box will be displayed before sending the database.

void hexapi send_database(const hexrays_failure_t &err, bool silent);

/// Result of get_current_operand()
struct gco_info_t
{
  qstring name;         ///< register or stkvar name
  union
  {
    sval_t stkoff;      ///< if stkvar, stack offset
    int regnum;         ///< if register, the register id
  };
  int size;             ///< operand size
  int flags;
#define GCO_STK 0x0000  ///< a stack variable
#define GCO_REG 0x0001  ///< is register? otherwise a stack variable
#define GCO_USE 0x0002  ///< is source operand?
#define GCO_DEF 0x0004  ///< is destination operand?
  bool is_reg(void) const { return (flags & GCO_REG) != 0; }
  bool is_use(void) const { return (flags & GCO_USE) != 0; }
  bool is_def(void) const { return (flags & GCO_DEF) != 0; }

  /// Append operand info to LIST.
  /// This function converts IDA register number or stack offset to
  /// a decompiler list.
  /// \param list list to append to
  /// \param mba microcode object
  bool hexapi append_to_list(mlist_t *list, const mba_t *mba) const;

  /// Convert operand info to VIVL.
  /// The returned VIVL can be used, for example, in a call of
  /// get_valranges().
  vivl_t cvt_to_ivl() const
  {
    vivl_t ret;
    if ( is_reg() )
      ret.set_reg(regnum, size);
    else
      ret.set_stkoff(stkoff, size);
    return ret;
  }
};

/// Get the instruction operand under the cursor.
/// This function determines the operand that is under the cursor in the active
/// disassembly listing. If the operand refers to a register or stack variable,
/// it returns true.
/// \param out[out] output buffer
bool hexapi get_current_operand(gco_info_t *out);

void hexapi remitem(const citem_t *e);
//-------------------------------------------------------------------------
/// Ctree item code. At the beginning of this list there are expression
/// codes (cot_...), followed by statement codes (cit_...).
enum ctype_t
{
  cot_empty    = 0,
  cot_comma    = 1,   ///< x, y
  cot_asg      = 2,   ///< x = y
  cot_asgbor   = 3,   ///< x |= y
  cot_asgxor   = 4,   ///< x ^= y
  cot_asgband  = 5,   ///< x &= y
  cot_asgadd   = 6,   ///< x += y
  cot_asgsub   = 7,   ///< x -= y
  cot_asgmul   = 8,   ///< x *= y
  cot_asgsshr  = 9,   ///< x >>= y signed
  cot_asgushr  = 10,  ///< x >>= y unsigned
  cot_asgshl   = 11,  ///< x <<= y
  cot_asgsdiv  = 12,  ///< x /= y signed
  cot_asgudiv  = 13,  ///< x /= y unsigned
  cot_asgsmod  = 14,  ///< x %= y signed
  cot_asgumod  = 15,  ///< x %= y unsigned
  cot_tern     = 16,  ///< x ? y : z
  cot_lor      = 17,  ///< x || y
  cot_land     = 18,  ///< x && y
  cot_bor      = 19,  ///< x | y
  cot_xor      = 20,  ///< x ^ y
  cot_band     = 21,  ///< x & y
  cot_eq       = 22,  ///< x == y int or fpu (see EXFL_FPOP)
  cot_ne       = 23,  ///< x != y int or fpu (see EXFL_FPOP)
  cot_sge      = 24,  ///< x >= y signed or fpu (see EXFL_FPOP)
  cot_uge      = 25,  ///< x >= y unsigned
  cot_sle      = 26,  ///< x <= y signed or fpu (see EXFL_FPOP)
  cot_ule      = 27,  ///< x <= y unsigned
  cot_sgt      = 28,  ///< x >  y signed or fpu (see EXFL_FPOP)
  cot_ugt      = 29,  ///< x >  y unsigned
  cot_slt      = 30,  ///< x <  y signed or fpu (see EXFL_FPOP)
  cot_ult      = 31,  ///< x <  y unsigned
  cot_sshr     = 32,  ///< x >> y signed
  cot_ushr     = 33,  ///< x >> y unsigned
  cot_shl      = 34,  ///< x << y
  cot_add      = 35,  ///< x + y
  cot_sub      = 36,  ///< x - y
  cot_mul      = 37,  ///< x * y
  cot_sdiv     = 38,  ///< x / y signed
  cot_udiv     = 39,  ///< x / y unsigned
  cot_smod     = 40,  ///< x % y signed
  cot_umod     = 41,  ///< x % y unsigned
  cot_fadd     = 42,  ///< x + y fp
  cot_fsub     = 43,  ///< x - y fp
  cot_fmul     = 44,  ///< x * y fp
  cot_fdiv     = 45,  ///< x / y fp
  cot_fneg     = 46,  ///< -x fp
  cot_neg      = 47,  ///< -x
  cot_cast     = 48,  ///< (type)x
  cot_lnot     = 49,  ///< !x
  cot_bnot     = 50,  ///< ~x
  cot_ptr      = 51,  ///< *x, access size in 'ptrsize'
  cot_ref      = 52,  ///< &x
  cot_postinc  = 53,  ///< x++
  cot_postdec  = 54,  ///< x--
  cot_preinc   = 55,  ///< ++x
  cot_predec   = 56,  ///< --x
  cot_call     = 57,  ///< x(...)
  cot_idx      = 58,  ///< x[y]
  cot_memref   = 59,  ///< x.m
  cot_memptr   = 60,  ///< x->m, access size in 'ptrsize'
  cot_num      = 61,  ///< n
  cot_fnum     = 62,  ///< fpc
  cot_str      = 63,  ///< string constant (user representation)
  cot_obj      = 64,  ///< obj_ea
  cot_var      = 65,  ///< v
  cot_insn     = 66,  ///< instruction in expression, internal representation only
  cot_sizeof   = 67,  ///< sizeof(x)
  cot_helper   = 68,  ///< arbitrary name
  cot_type     = 69,  ///< arbitrary type
  cot_last     = cot_type,
  cit_empty    = 70,  ///< instruction types start here
  cit_block    = 71,  ///< block-statement: { ... }
  cit_expr     = 72,  ///< expression-statement: expr;
  cit_if       = 73,  ///< if-statement
  cit_for      = 74,  ///< for-statement
  cit_while    = 75,  ///< while-statement
  cit_do       = 76,  ///< do-statement
  cit_switch   = 77,  ///< switch-statement
  cit_break    = 78,  ///< break-statement
  cit_continue = 79,  ///< continue-statement
  cit_return   = 80,  ///< return-statement
  cit_goto     = 81,  ///< goto-statement
  cit_asm      = 82,  ///< asm-statement
  cit_end
};

/// Negate a comparison operator. For example, \ref cot_sge becomes \ref cot_slt
ctype_t hexapi negated_relation(ctype_t op);
/// Swap a comparison operator. For example, \ref cot_sge becomes \ref cot_sle
ctype_t hexapi swapped_relation(ctype_t op);
/// Get operator sign. Meaningful for sign-dependent operators, like \ref cot_sdiv
type_sign_t hexapi get_op_signness(ctype_t op);
/// Convert plain operator into assignment operator. For example, \ref cot_add returns \ref cot_asgadd
ctype_t hexapi asgop(ctype_t cop);
/// Convert assignment operator into plain operator. For example, \ref cot_asgadd returns \ref cot_add
/// \return cot_empty is the input operator is not an assignment operator.
ctype_t hexapi asgop_revert(ctype_t cop);
/// Does operator use the 'x' field of cexpr_t?
inline bool op_uses_x(ctype_t op) { return (op >= cot_comma && op <= cot_memptr) || op == cot_sizeof; }
/// Does operator use the 'y' field of cexpr_t?
inline bool op_uses_y(ctype_t op) { return (op >= cot_comma && op <= cot_fdiv) || op == cot_idx; }
/// Does operator use the 'z' field of cexpr_t?
inline bool op_uses_z(ctype_t op) { return op == cot_tern; }
/// Is binary operator?
inline bool is_binary(ctype_t op) { return op_uses_y(op) && op != cot_tern; } // x,y
/// Is unary operator?
inline bool is_unary(ctype_t op) { return op >= cot_fneg && op <= cot_predec; }
/// Is comparison operator?
inline bool is_relational(ctype_t op) { return op >= cot_eq && op <= cot_ult; }
/// Is assignment operator?
inline bool is_assignment(ctype_t op) { return op >= cot_asg && op <= cot_asgumod; }
// Can operate on UDTs?
inline bool accepts_udts(ctype_t op) { return op == cot_asg || op == cot_comma || op > cot_last; }
/// Is pre/post increment/decrement operator?
inline bool is_prepost(ctype_t op)    { return op >= cot_postinc && op <= cot_predec; }
/// Is commutative operator?
inline bool is_commutative(ctype_t op)
{
  return op == cot_bor
      || op == cot_xor
      || op == cot_band
      || op == cot_add
      || op == cot_mul
      || op == cot_fadd
      || op == cot_fmul
      || op == cot_ne
      || op == cot_eq;
}
/// Is additive operator?
inline bool is_additive(ctype_t op)
{
  return op == cot_add
      || op == cot_sub
      || op == cot_fadd
      || op == cot_fsub;
}
/// Is multiplicative operator?
inline bool is_multiplicative(ctype_t op)
{
  return op == cot_mul
      || op == cot_sdiv
      || op == cot_udiv
      || op == cot_fmul
      || op == cot_fdiv;
}

/// Is bit related operator?
inline bool is_bitop(ctype_t op)
{
  return op == cot_bor
      || op == cot_xor
      || op == cot_band
      || op == cot_bnot;
}

/// Is logical operator?
inline bool is_logical(ctype_t op)
{
  return op == cot_lor
      || op == cot_land
      || op == cot_lnot;
}

/// Is loop statement code?
inline bool is_loop(ctype_t op)
{
  return op == cit_for
      || op == cit_while
      || op == cit_do;
}
/// Does a break statement influence the specified statement code?
inline bool is_break_consumer(ctype_t op)
{
  return is_loop(op) || op == cit_switch;
}

/// Is Lvalue operator?
inline bool is_lvalue(ctype_t op)
{
  return op == cot_ptr      // *x
      || op == cot_idx      // x[y]
      || op == cot_memref   // x.m
      || op == cot_memptr   // x->m
      || op == cot_obj      // v
      || op == cot_var;     // l
}

/// Is the operator allowed on small structure or union?
inline bool accepts_small_udts(ctype_t op)
{
  return op == cit_return
      || op == cot_asg
      || op == cot_eq
      || op == cot_ne
      || op == cot_comma
      || op == cot_tern
      || (op > cot_last && op < cit_end); // any insn
}

/// An immediate number
struct cnumber_t
{
  uint64 _value;                ///< its value
  number_format_t nf;           ///< how to represent it
  cnumber_t(int _opnum=0) : _value(0), nf(_opnum) {}

  /// Get text representation
  /// \param vout output buffer
  /// \param type number type
  /// \param parent parent expression
  /// \param nice_stroff out: printed as stroff expression
  void hexapi print(
        qstring *vout,
        const tinfo_t &type,
        const citem_t *parent=nullptr,
        bool *nice_stroff=nullptr) const;

  /// Get value.
  /// This function will properly extend the number sign to 64bits
  /// depending on the type sign.
  uint64 hexapi value(const tinfo_t &type) const;

  /// Assign new value
  /// \param v new value
  /// \param nbytes size of the new value in bytes
  /// \param sign sign of the value
  void hexapi assign(uint64 v, int nbytes, type_sign_t sign);

  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
  DECLARE_COMPARISONS(cnumber_t);
};

/// Reference to a local variable
struct var_ref_t
{
  mba_t *mba;     ///< pointer to the underlying micro array
  int idx;              ///< index into lvars_t
  lvar_t &getv(void) const { return mba->vars[idx]; }
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
  DECLARE_COMPARISONS(var_ref_t);
};

/// Vector of parents
typedef qvector<citem_t *> ctree_items_t;
typedef ctree_items_t parents_t;

/// A generic helper class that is used for ctree traversal.
/// When traversing the ctree, the currently visited ctree item and its children
/// can be freely modified without interrupting the traversal. However, if a
/// parent of the visited item is modified, the traversal must be immediately
/// stopped by returning a non-zero value.
struct ctree_visitor_t
{
  int cv_flags;           ///< \ref CV_
/// \defgroup CV_ Ctree visitor property bits
/// Used in ctree_visitor_t::cv_flags
//@{
#define CV_FAST    0x0000 ///< do not maintain parent information
#define CV_PRUNE   0x0001 ///< this bit is set by visit...() to prune the walk
#define CV_PARENTS 0x0002 ///< maintain parent information
#define CV_POST    0x0004 ///< call the leave...() functions
#define CV_RESTART 0x0008 ///< restart enumeration at the top expr (apply_to_exprs)
#define CV_INSNS   0x0010 ///< visit only statements, prune all expressions
                          ///< do not use before the final ctree maturity because
                          ///< expressions may contain statements at intermediate
                          ///< stages (see cot_insn). Otherwise you risk missing
                          ///< statements embedded into expressions.
//@}
  /// Should the parent information by maintained?
  bool maintain_parents(void) const { return (cv_flags & CV_PARENTS) != 0; }
  /// Should the traversal skip the children of the current item?
  bool must_prune(void)       const { return (cv_flags & CV_PRUNE) != 0; }
  /// Should the traversal restart?
  bool must_restart(void)     const { return (cv_flags & CV_RESTART) != 0; }
  /// Should the leave...() functions be called?
  bool is_postorder(void)     const { return (cv_flags & CV_POST) != 0; }
  /// Should all expressions be automatically pruned?
  bool only_insns(void)       const { return (cv_flags & CV_INSNS) != 0; }
  /// Prune children.
  /// This function may be called by a visitor() to skip all children of the current item.
  void prune_now(void) { cv_flags |= CV_PRUNE; }
  /// Do not prune children. This is an internal function, no need to call it.
  void clr_prune(void) { cv_flags &= ~CV_PRUNE; }
  /// Restart the travesal. Meaningful only in apply_to_exprs()
  void set_restart(void) { cv_flags |= CV_RESTART; }
  /// Do not restart. This is an internal function, no need to call it.
  void clr_restart(void) { cv_flags &= ~CV_RESTART; }

  parents_t parents;      ///< Vector of parents of the current item

  /// Constructor.
  /// This constructor can be used with CV_FAST, CV_PARENTS
  /// combined with CV_POST, CV_ONLYINS
  ctree_visitor_t(int _flags) : cv_flags(_flags) {}

  virtual ~ctree_visitor_t() {}
  /// Traverse ctree.
  /// The traversal will start at the specified item and continue until
  /// of one the visit_...() functions return a non-zero value.
  /// \param item root of the ctree to traverse
  /// \param parent parent of the specified item. can be specified as nullptr.
  /// \return 0 or a non-zero value returned by a visit_...() function
  int hexapi apply_to(citem_t *item, citem_t *parent);

  /// Traverse only expressions.
  /// The traversal will start at the specified item and continue until
  /// of one the visit_...() functions return a non-zero value.
  /// \param item root of the ctree to traverse
  /// \param parent parent of the specified item. can be specified as nullptr.
  /// \return 0 or a non-zero value returned by a visit_...() function
  int hexapi apply_to_exprs(citem_t *item, citem_t *parent);

  /// Get parent of the current item as an expression
  cexpr_t *parent_expr(void) { return (cexpr_t *)parents.back(); }
  /// Get parent of the current item as a statement
  cinsn_t *parent_insn(void) { return (cinsn_t *)parents.back(); }

  // the following functions are redefined by the derived class
  // in order to perform the desired actions during the traversal

  /// Visit a statement.
  /// This is a visitor function which should be overridden by a derived
  /// class to do some useful work.
  /// This visitor performs pre-order traserval, i.e. an item is visited before
  /// its children.
  /// \return 0 to continue the traversal, nonzero to stop.
  virtual int idaapi visit_insn(cinsn_t *) { return 0; }

  /// Visit an expression.
  /// This is a visitor function which should be overridden by a derived
  /// class to do some useful work.
  /// This visitor performs pre-order traserval, i.e. an item is visited before
  /// its children.
  /// \return 0 to continue the traversal, nonzero to stop.
  virtual int idaapi visit_expr(cexpr_t *) { return 0; }

  /// Visit a statement after having visited its children.
  /// This is a visitor function which should be overridden by a derived
  /// class to do some useful work.
  /// This visitor performs post-order traserval, i.e. an item is visited after
  /// its children.
  /// \return 0 to continue the traversal, nonzero to stop.
  virtual int idaapi leave_insn(cinsn_t *) { return 0; }

  /// Visit an expression after having visited its children.
  /// This is a visitor function which should be overridden by a derived
  /// class to do some useful work.
  /// This visitor performs post-order traserval, i.e. an item is visited after
  /// its children.
  /// \return 0 to continue the traversal, nonzero to stop.
  virtual int idaapi leave_expr(cexpr_t *) { return 0; }

  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
};

/// A helper ctree traversal class that maintains parent information
struct ctree_parentee_t : public ctree_visitor_t
{
  ctree_parentee_t(bool post=false)
    : ctree_visitor_t((post ? CV_POST : 0)|CV_PARENTS) {}

  /// Recalculate type of parent nodes.
  /// If a node type has been changed, the visitor must recalculate
  /// all parent types, otherwise the ctree becomes inconsistent.
  /// If during this recalculation a parent node is added/deleted,
  /// this function returns true. In this case the traversal must be
  /// stopped because the information about parent nodes is stale.
  /// \return false-ok to continue the traversal, true-must stop.
  bool hexapi recalc_parent_types(void);

  /// Get pointer to the parent block of the currently visited item.
  /// This function should be called only when the parent is a block.
  cblock_t *get_block();
};

/// Class to traverse the whole function.
struct cfunc_parentee_t : public ctree_parentee_t
{
  cfunc_t *func;        ///< Pointer to current function
  cfunc_parentee_t(cfunc_t *f, bool post=false)
    : ctree_parentee_t(post), func(f) {}

  /// Calculate rvalue type.
  /// This function tries to determine the type of the specified item
  /// based on its context. For example, if the current expression is the
  /// right side of an assignment operator, the type
  /// of its left side will be returned. This function can be used to determine the 'best'
  /// type of the specified expression.
  /// \param[in] e expression to determine the desired type
  /// \param[out] target 'best' type of the expression will be returned here
  /// \return false if failed
  bool hexapi calc_rvalue_type(tinfo_t *target, const cexpr_t *e);
};

/// Ctree maturity level. The level will increase
/// as we switch from one phase of ctree generation to the next one
enum ctree_maturity_t
{
  CMAT_ZERO,            ///< does not exist
  CMAT_BUILT,           ///< just generated
  CMAT_TRANS1,          ///< applied first wave of transformations
  CMAT_NICE,            ///< nicefied expressions
  CMAT_TRANS2,          ///< applied second wave of transformations
  CMAT_CPA,             ///< corrected pointer arithmetic
  CMAT_TRANS3,          ///< applied third wave of transformations
  CMAT_CASTED,          ///< added necessary casts
  CMAT_FINAL,           ///< ready-to-use
};

//--------------------------------------------------------------------------
/// Comment item preciser.
/// Item preciser is used to assign comments to ctree items
/// A ctree item may have several comments attached to it. For example,
/// an if-statement may have the following comments: <pre>
///  if ( ... )    // cmt1
///  {             // cmt2
///  }             // cmt3
///  else          // cmt4
///  {                     -- usually the else block has a separate ea
///  } </pre>
/// The first 4 comments will have the same ea. In order to denote the exact
/// line for the comment, we store the item_preciser along with ea.
enum item_preciser_t
{
  // inner comments (comments within an expression)
  ITP_EMPTY,    ///< nothing
  ITP_ARG1,     ///< , (64 entries are reserved for 64 call arguments)
  ITP_ARG64 = ITP_ARG1+63, // ,
  ITP_BRACE1,   // (
  ITP_INNER_LAST = ITP_BRACE1,
  // outer comments
  ITP_ASM,      ///< __asm-line
  ITP_ELSE,     ///< else-line
  ITP_DO,       ///< do-line
  ITP_SEMI,     ///< semicolon
  ITP_CURLY1,   ///< {
  ITP_CURLY2,   ///< }
  ITP_BRACE2,   ///< )
  ITP_COLON,    ///< : (label)
  ITP_BLOCK1,   ///< opening block comment. this comment is printed before the item
                ///< (other comments are indented and printed after the item)
  ITP_BLOCK2,   ///< closing block comment.
  ITP_CASE = 0x40000000, ///< bit for switch cases
  ITP_SIGN = 0x20000000, ///< if this bit is set too, then we have a negative case value
                         // this is a hack, we better introduce special indexes for case values
                         // case value >= ITP_CASE will be processed incorrectly
};
/// Ctree location. Used to denote comment locations.
struct treeloc_t
{
  ea_t ea;
  item_preciser_t itp;
  bool operator < (const treeloc_t &r) const
  {
    return ea < r.ea
        || (ea == r.ea && itp < r.itp);
  }
  bool operator == (const treeloc_t &r) const
  {
    return ea == r.ea && itp == r.itp;
  }
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
};

/// Comment retrieval type.
/// Ctree remembers what comments have already been retrieved.
/// This is done because our mechanism of item_precisers is still
/// not perfect and in theory some listing lines cannot be told
/// apart. To avoid comment duplication, we remember if a comment
/// has already been used or not.
enum cmt_retrieval_type_t
{
  RETRIEVE_ONCE,        ///< Retrieve comment if it has not been used yet
  RETRIEVE_ALWAYS,      ///< Retrieve comment even if it has been used
};

/// Ctree item comment.
/// For each comment we remember its body and the fact of its retrieval
struct citem_cmt_t : public qstring
{
  mutable bool used;    ///< the comment has been retrieved?
  citem_cmt_t(void) : used(false) {}
  citem_cmt_t(const char *s) : qstring(s), used(false) {}
};

// Comments are attached to tree locations:
typedef std::map<treeloc_t, citem_cmt_t> user_cmts_t;

/// Generic ctree item locator. It can be used for instructions and some expression
/// types. However, we need more precise locators for other items (e.g. for numbers)
struct citem_locator_t
{
  ea_t ea;              ///< citem address
  ctype_t op;           ///< citem operation
  citem_locator_t(void) = delete;
public:
  citem_locator_t(ea_t _ea, ctype_t _op) : ea(_ea), op(_op) {}
  citem_locator_t(const citem_t *i);
  DECLARE_COMPARISONS(citem_locator_t);
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
};

// citem_t::iflags are attached to (ea,op) pairs
typedef std::map<citem_locator_t, int32> user_iflags_t;

// union field selections
// they are represented as a vector of integers. each integer represents the
// number of union field (0 means the first union field, etc)
// the size of this vector is equal to the number of nested unions in the selection.
typedef std::map<ea_t, intvec_t> user_unions_t;

//--------------------------------------------------------------------------
struct bit_bound_t
{
  int16 nbits; // total number of non-zero bits. we cannot guarantee that
               // they are zero. example: a random "int var" has nbits==32
  int16 sbits; // number of sign bits (they can be either 0 or 1, all of them)
               // if bits are known to be zeroes, they are not taken into account here
               // (in this case nbits should be reduced)
               // if bits are unknown and can be anything, they cannot be included
               // in sbits.
               // sbits==1 is a special case and should not be used
  bit_bound_t(int n=0, int s=0) : nbits(n), sbits(s) {}
};

//--------------------------------------------------------------------------
/// Basic ctree item. This is an abstract class (but we don't use virtual
/// functions in ctree, so the compiler will not disallow you to create citem_t
/// instances). However, items of pure citem_t type must never be created.
/// Two classes, cexpr_t and cinsn_t are derived from it.
struct citem_t
{
  ea_t ea = BADADDR;      ///< address that corresponds to the item. may be BADADDR
  ctype_t op = cot_empty; ///< item type
  int label_num = -1;     ///< label number. -1 means no label. items of the expression
                          ///< types (cot_...) should not have labels at the final maturity
                          ///< level, but at the intermediate levels any ctree item
                          ///< may have a label. Labels must be unique. Usually
                          ///< they correspond to the basic block numbers.
  mutable int index = -1; ///< an index in cfunc_t::treeitems.
                          ///< meaningful only after print_func()
  citem_t(ctype_t o=cot_empty) : op(o) {}
  /// Swap two citem_t
  void swap(citem_t &r)
  {
    std::swap(ea, r.ea);
    std::swap(op, r.op);
    std::swap(label_num, r.label_num);
  }
  /// Is an expression?
  bool is_expr(void) const { return op <= cot_last; }
  /// Does the item contain an expression?
  bool hexapi contains_expr(const cexpr_t *e) const;
  /// Does the item contain a label?
  bool hexapi contains_label(void) const;
  /// Find parent of the specified item.
  /// \param sitem Item to find the parent of. The search will be performed
  ///            among the children of the item pointed by \c this.
  /// \return nullptr if not found
  const citem_t *hexapi find_parent_of(const citem_t *sitem) const;
  citem_t *find_parent_of(const citem_t *item)
  { return CONST_CAST(citem_t*)((CONST_CAST(const citem_t*)(this))->find_parent_of(item)); }
  citem_t *hexapi find_closest_addr(ea_t _ea);
  void print1(qstring *vout, const cfunc_t *func) const;
  ~citem_t(void)
  {
    remitem(this);
  }
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
};
DECLARE_TYPE_AS_MOVABLE(citem_t);

/// Ctree item: expression.
/// Depending on the exact expression item type, various fields of this structure are used.
struct cexpr_t : public citem_t
{
  union
  {
    cnumber_t *n;     ///< used for \ref cot_num
    fnumber_t *fpc;   ///< used for \ref cot_fnum
    struct
    {
      union
      {
        var_ref_t v;  ///< used for \ref cot_var
        ea_t obj_ea;  ///< used for \ref cot_obj
      };
      int refwidth;   ///< how many bytes are accessed? (-1: none)
    };
    struct
    {
      cexpr_t *x;     ///< the first operand of the expression
      union
      {
        cexpr_t *y;   ///< the second operand of the expression
        carglist_t *a;///< argument list (used for \ref cot_call)
        uint32 m;     ///< member offset (used for \ref cot_memptr, \ref cot_memref)
                      ///< for unions, the member number
      };
      union
      {
        cexpr_t *z;   ///< the third operand of the expression
        int ptrsize;  ///< memory access size (used for \ref cot_ptr, \ref cot_memptr)
      };
    };
    cinsn_t *insn;    ///< an embedded statement, they are prohibited
                      ///< at the final maturity stage (\ref CMAT_FINAL)
    char *helper;     ///< helper name (used for \ref cot_helper)
    char *string;     ///< utf8 string constant, user representation (used for \ref cot_str)
  };
  tinfo_t type;       ///< expression type. must be carefully maintained
  uint32 exflags;     ///< \ref EXFL_
/// \defgroup EXFL_ Expression attributes
/// Used in cexpr_t::exflags
//@{
#define EXFL_CPADONE 0x0001 ///< pointer arithmetic correction done
#define EXFL_LVALUE  0x0002 ///< expression is lvalue even if it doesn't look like it
#define EXFL_FPOP    0x0004 ///< floating point operation
#define EXFL_ALONE   0x0008 ///< standalone helper
#define EXFL_CSTR    0x0010 ///< string literal
#define EXFL_PARTIAL 0x0020 ///< type of the expression is considered partial
#define EXFL_UNDEF   0x0040 ///< expression uses undefined value
#define EXFL_JUMPOUT 0x0080 ///< jump out-of-function
#define EXFL_VFTABLE 0x0100 ///< is ptr to vftable (used for \ref cot_memptr, \ref cot_memref)
#define EXFL_ALL     0x01FF ///< all currently defined bits
//@}
  /// Pointer arithmetic correction done for this expression?
  bool cpadone(void) const         { return (exflags & EXFL_CPADONE) != 0; }
  bool is_odd_lvalue(void) const   { return (exflags & EXFL_LVALUE) != 0; }
  bool is_fpop(void) const         { return (exflags & EXFL_FPOP) != 0; }
  bool is_cstr(void) const         { return (exflags & EXFL_CSTR) != 0; }
  bool is_type_partial(void) const { return (exflags & EXFL_PARTIAL) != 0; }
  bool is_undef_val(void) const    { return (exflags & EXFL_UNDEF) != 0; }
  bool is_jumpout(void) const      { return (exflags & EXFL_JUMPOUT) != 0; }
  bool is_vftable(void) const      { return (exflags & EXFL_VFTABLE) != 0; }


  void set_cpadone(void)      { exflags |= EXFL_CPADONE; }
  void set_vftable(void)      { exflags |= EXFL_VFTABLE; }
  void set_type_partial(bool val = true)
  {
    if ( val )
      exflags |= EXFL_PARTIAL;
    else
      exflags &= ~EXFL_PARTIAL;
  }

  cexpr_t(void) : x(nullptr), y(nullptr), z(nullptr), exflags(0) {}
  cexpr_t(ctype_t cexpr_op, cexpr_t *_x) : citem_t(cexpr_op), x(_x), y(nullptr), z(nullptr), exflags(0) {}
  cexpr_t(ctype_t cexpr_op, cexpr_t *_x, cexpr_t *_y) : citem_t(cexpr_op), x(_x), y(_y), z(nullptr), exflags(0) {}
  cexpr_t(ctype_t cexpr_op, cexpr_t *_x, cexpr_t *_y, cexpr_t *_z) : citem_t(cexpr_op), x(_x), y(_y), z(_z), exflags(0) {}
  cexpr_t(mba_t *mba, const lvar_t &v);
  cexpr_t(const cexpr_t &r) : citem_t() { *this = r; }
  void swap(cexpr_t &r) { qswap(*this, r); }
  cexpr_t &operator=(const cexpr_t &r) { return assign(r); }
  cexpr_t &hexapi assign(const cexpr_t &r);
  DECLARE_COMPARISONS(cexpr_t);
  ~cexpr_t(void) { cleanup(); }

  /// Replace the expression.
  /// The children of the expression are abandoned (not freed).
  /// The expression pointed by 'r' is moved to 'this' expression
  /// \param r the source expression. It is deleted after being copied
  void hexapi replace_by(cexpr_t *r);

  /// Cleanup the expression.
  /// This function properly deletes all children and sets the item type to cot_empty.
  void hexapi cleanup(void);

  /// Assign a number to the expression.
  /// \param func current function
  /// \param value number value
  /// \param nbytes size of the number in bytes
  /// \param sign number sign
  void hexapi put_number(cfunc_t *func, uint64 value, int nbytes, type_sign_t sign=no_sign);

  /// Print expression into one line.
  /// \param vout output buffer
  /// \param func parent function. This argument is used to find out the referenced variable names.
  void hexapi print1(qstring *vout, const cfunc_t *func) const;

  /// Calculate the type of the expression.
  /// Use this function to calculate the expression type when a new expression is built
  /// \param recursive if true, types of all children expression will be calculated
  ///                  before calculating our type
  void hexapi calc_type(bool recursive);

  /// Compare two expressions.
  /// This function tries to compare two expressions in an 'intelligent' manner.
  /// For example, it knows about commutitive operators and can ignore useless casts.
  /// \param r the expression to compare against the current expression
  /// \return true expressions can be considered equal
  bool hexapi equal_effect(const cexpr_t &r) const;

  /// Verify if the specified item is our parent.
  /// \param parent possible parent item
  /// \return true if the specified item is our parent
  bool hexapi is_child_of(const citem_t *parent) const;

  /// Check if the expression contains the specified operator.
  /// \param needed_op operator code to search for
  /// \param times how many times the operator code should be present
  /// \return true if the expression has at least TIMES children with NEEDED_OP
  bool hexapi contains_operator(ctype_t needed_op, int times=1) const;

  /// Does the expression contain a comma operator?
  bool contains_comma(int times=1) const { return contains_operator(cot_comma, times); }
  /// Does the expression contain an embedded statement operator?
  bool contains_insn(int times=1) const { return contains_operator(cot_insn, times); }
  /// Does the expression contain an embedded statement operator or a label?
  bool contains_insn_or_label(void) const { return contains_insn() || contains_label(); }
  /// Does the expression contain a comma operator or an embedded statement operator or a label?
  bool contains_comma_or_insn_or_label(int maxcommas=1) const { return contains_comma(maxcommas) || contains_insn_or_label(); }
  /// Is nice expression?
  /// Nice expressions do not contain comma operators, embedded statements, or labels.
  bool is_nice_expr(void) const { return !contains_comma_or_insn_or_label(); }
  /// Is nice condition?.
  /// Nice condition is a nice expression of the boolean type.
  bool is_nice_cond(void) const { return is_nice_expr() && type.is_bool(); }
  /// Is call object?
  /// \return true if our expression is the call object of the specified parent expression.
  bool is_call_object_of(const citem_t *parent) const { return parent != nullptr && parent->op == cot_call && ((cexpr_t*)parent)->x == this; }
  /// Is call argument?
  /// \return true if our expression is a call argument of the specified parent expression.
  bool is_call_arg_of(const citem_t *parent) const { return parent != nullptr && parent->op == cot_call && ((cexpr_t*)parent)->x != this; }
  /// Get expression sign
  type_sign_t get_type_sign(void) const { return type.get_sign(); }
  /// Is expression unsigned?
  bool is_type_unsigned(void) const { return type.is_unsigned(); }
  /// Is expression signed?
  bool is_type_signed(void) const { return type.is_signed(); }
  /// Get max number of bits that can really be used by the expression.
  /// For example, x % 16 can yield only 4 non-zero bits, higher bits are zero
  bit_bound_t hexapi get_high_nbit_bound(void) const;
  /// Get min number of bits that are certainly required to represent the expression.
  /// For example, constant 16 always uses 5 bits: 10000.
  int hexapi get_low_nbit_bound() const;
  /// Check if the expression requires an lvalue.
  /// \param child The function will check if this child of our expression must be an lvalue.
  /// \return true if child must be an lvalue.
  bool hexapi requires_lvalue(const cexpr_t *child) const;
  /// Check if the expression has side effects.
  /// Calls, pre/post inc/dec, and assignments have side effects.
  bool hexapi has_side_effects(void) const;
  /// Does the expression look like a boolean expression?
  /// In other words, its possible values are only 0 and 1.
  bool like_boolean(void) const;
  /// Check if the expression if aliasable.
  /// Simple registers and non-aliasble stack slots return false.
  bool is_aliasable(void) const;
  /// Get numeric value of the expression.
  /// This function can be called only on cot_num expressions!
  uint64 numval(void) const
  {
    QASSERT(50071, op == cot_num);
    return n->value(type);
  }
  /// Check if the expression is a number with the specified value.
  bool is_const_value(uint64 _v) const
  {
    return op == cot_num && numval() == _v;
  }
  /// Check if the expression is a negative number.
  bool is_negative_const(void) const
  {
    return op == cot_num && int64(numval()) < 0;
  }
  /// Check if the expression is a non-negative number.
  bool is_non_negative_const(void) const
  {
    return op == cot_num && int64(numval()) >= 0;
  }
  /// Check if the expression is a non-zero number.
  bool is_non_zero_const(void) const
  {
    return op == cot_num && numval() != 0;
  }
  /// Check if the expression is a zero.
  bool is_zero_const(void) const { return is_const_value(0); }
  /// Does the PARENT need the expression value
  bool is_value_used(const citem_t *parent) const;
  /// Get expression value.
  /// \param out Pointer to the variable where the expression value is returned.
  /// \return true if the expression is a number.
  bool get_const_value(uint64 *out) const
  {
    if ( op == cot_num )
    {
      if ( out != nullptr )
        *out = numval();
      return true;
    }
    return false;
  }
  /// May the expression be a pointer?
  bool hexapi maybe_ptr(void) const;

  /// Find pointer or array child.
  cexpr_t *get_ptr_or_array(void)
  {
    if ( x->type.is_ptr_or_array() )
      return x;
    if ( y->type.is_ptr_or_array() )
      return y;
    return nullptr;
  }
  /// Find the child with the specified operator.
  const cexpr_t *find_op(ctype_t _op) const
  {
    if ( x->op == _op )
      return x;
    if ( y->op == _op )
      return y;
    return nullptr;
  }
  cexpr_t *find_op(ctype_t _op)
  {
    return (cexpr_t *)((const cexpr_t *)this)->find_op(_op);
  }

  /// Find the operand with a numeric value
  const cexpr_t *find_num_op(void) const { return find_op(cot_num); }
        cexpr_t *find_num_op(void)       { return find_op(cot_num); }
  /// Find the pointer operand.
  /// This function returns the pointer operand for binary expressions.
  const cexpr_t *find_ptr_or_array(bool remove_eqsize_casts) const;
  /// Get the other operand.
  /// This function returns the other operand (not the specified one)
  /// for binary expressions.
  const cexpr_t *theother(const cexpr_t *what) const { return what == x ? y : x; }
        cexpr_t *theother(const cexpr_t *what)       { return what == x ? y : x; }

  // these are inline functions, see below
  bool get_1num_op(cexpr_t **o1, cexpr_t **o2);
  bool get_1num_op(const cexpr_t **o1, const cexpr_t **o2) const;

  const char *hexapi dstr() const;
};
DECLARE_TYPE_AS_MOVABLE(cexpr_t);

/// Statement with an expression.
/// This is a base class for various statements with expressions.
struct ceinsn_t
{
  cexpr_t expr;         ///< Expression of the statement
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
};
DECLARE_TYPE_AS_MOVABLE(ceinsn_t);

/// Should curly braces be printed?
enum use_curly_t
{
  CALC_CURLY_BRACES,    ///< print curly braces if necessary
  NO_CURLY_BRACES,      ///< don't print curly braces
  USE_CURLY_BRACES,     ///< print curly braces without any checks
};

/// If statement
struct cif_t : public ceinsn_t
{
  cinsn_t *ithen;       ///< Then-branch of the if-statement
  cinsn_t *ielse;       ///< Else-branch of the if-statement. May be nullptr.
  cif_t(void) : ithen(nullptr), ielse(nullptr) {}
  cif_t(const cif_t &r) : ceinsn_t(), ithen(nullptr), ielse(nullptr) { *this = r; }
  cif_t &operator=(const cif_t &r) { return assign(r); }
  cif_t &hexapi assign(const cif_t &r);
  DECLARE_COMPARISONS(cif_t);
  ~cif_t(void) { cleanup(); }
  void cleanup(void);
};

/// Base class for loop statements
struct cloop_t : public ceinsn_t
{
  cinsn_t *body;
  cloop_t(void) : body(nullptr) {}
  cloop_t(cinsn_t *b) : body(b) {}
  cloop_t(const cloop_t &r) : ceinsn_t(), body(nullptr) { *this = r; }
  cloop_t &operator=(const cloop_t &r) { return assign(r); }
  cloop_t &hexapi assign(const cloop_t &r);
  ~cloop_t(void) { cleanup(); }
  void cleanup(void);
};

/// For-loop
struct cfor_t : public cloop_t
{
  cexpr_t init;                 ///< Initialization expression
  cexpr_t step;                 ///< Step expression
  DECLARE_COMPARISONS(cfor_t);
};

/// While-loop
struct cwhile_t : public cloop_t
{
  DECLARE_COMPARISONS(cwhile_t);
};

/// Do-loop
struct cdo_t : public cloop_t
{
  DECLARE_COMPARISONS(cdo_t);
};

/// Return statement
struct creturn_t : public ceinsn_t
{
  DECLARE_COMPARISONS(creturn_t);
};

/// Goto statement
struct cgoto_t
{
  int label_num;        ///< Target label number
  void print(const citem_t *parent, int indent, vc_printer_t &vp) const;
  DECLARE_COMPARISONS(cgoto_t);
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
};

/// asm statement
struct casm_t : public eavec_t
{
  casm_t(ea_t ea) { push_back(ea); }
  casm_t(const casm_t &r) : eavec_t(eavec_t(r)) {}
  DECLARE_COMPARISONS(casm_t);
  void print(const citem_t *parent, int indent, vc_printer_t &vp) const;
  bool one_insn(void) const { return size() == 1; }
  void genasm(qstring *buf, ea_t ea) const;
};

/// Vector of pointers to statements.
typedef qvector<cinsn_t *> cinsnptrvec_t;

/// Ctree item: statement.
/// Depending on the exact statement type, various fields of the union are used.
struct cinsn_t : public citem_t
{
  union
  {
    cblock_t *cblock;   ///< details of block-statement
    cexpr_t *cexpr;     ///< details of expression-statement
    cif_t *cif;         ///< details of if-statement
    cfor_t *cfor;       ///< details of for-statement
    cwhile_t *cwhile;   ///< details of while-statement
    cdo_t *cdo;         ///< details of do-statement
    cswitch_t *cswitch; ///< details of switch-statement
    creturn_t *creturn; ///< details of return-statement
    cgoto_t *cgoto;     ///< details of goto-statement
    casm_t *casm;       ///< details of asm-statement
  };

  cinsn_t(void) { zero(); }
  cinsn_t(const cinsn_t &r) : citem_t(cit_empty) { *this = r; }
  void swap(cinsn_t &r) { citem_t::swap(r); std::swap(cblock, r.cblock); }
  cinsn_t &operator=(const cinsn_t &r) { return assign(r); }
  cinsn_t &hexapi assign(const cinsn_t &r);
  DECLARE_COMPARISONS(cinsn_t);
  ~cinsn_t(void) { cleanup(); }

  /// Replace the statement.
  /// The children of the statement are abandoned (not freed).
  /// The statement pointed by 'r' is moved to 'this' statement
  /// \param r the source statement. It is deleted after being copied
  void hexapi replace_by(cinsn_t *r);

  /// Cleanup the statement.
  /// This function properly deletes all children and sets the item type to cit_empty.
  void hexapi cleanup(void);

  /// Overwrite with zeroes without cleaning memory or deleting children
  void zero(void) { op = cit_empty; cblock = nullptr; }

  /// Create a new statement.
  /// The current statement must be a block. The new statement will be appended to it.
  /// \param insn_ea statement address
  cinsn_t &hexapi new_insn(ea_t insn_ea);

  /// Create a new if-statement.
  /// The current statement must be a block. The new statement will be appended to it.
  /// \param cnd if condition. It will be deleted after being copied.
  cif_t &hexapi create_if(cexpr_t *cnd);

  /// Print the statement into many lines.
  /// \param indent indention (number of spaces) for the statement
  /// \param vp printer helper class which will receive the generated text.
  /// \param use_curly if the statement is a block, how should curly braces be printed.
  void hexapi print(int indent, vc_printer_t &vp, use_curly_t use_curly=CALC_CURLY_BRACES) const;

  /// Print the statement into one line.
  /// Currently this function is not available.
  /// \param vout output buffer
  /// \param func parent function. This argument is used to find out the referenced variable names.
  void hexapi print1(qstring *vout, const cfunc_t *func) const;

  /// Check if the statement passes execution to the next statement.
  /// \return false if the statement breaks the control flow (like goto, return, etc)
  bool hexapi is_ordinary_flow(void) const;

  /// Check if the statement contains a statement of the specified type.
  /// \param type statement opcode to look for
  /// \param times how many times TYPE should be present
  /// \return true if the statement has at least TIMES children with opcode == TYPE
  bool hexapi contains_insn(ctype_t type, int times=1) const;

  /// Collect free \c break statements.
  /// This function finds all free \c break statements within the current statement.
  /// A \c break statement is free if it does not have a loop or switch parent that
  /// that is also within the current statement.
  /// \param breaks pointer to the variable where the vector of all found free
  ///               \c break statements is returned. This argument can be nullptr.
  /// \return true if some free \c break statements have been found
  bool hexapi collect_free_breaks(cinsnptrvec_t *breaks);

  /// Collect free \c continue statements.
  /// This function finds all free \c continue statements within the current statement.
  /// A \c continue statement is free if it does not have a loop parent that
  /// that is also within the current statement.
  /// \param continues pointer to the variable where the vector of all found free
  ///               \c continue statements is returned. This argument can be nullptr.
  /// \return true if some free \c continue statements have been found
  bool hexapi collect_free_continues(cinsnptrvec_t *continues);

  /// Check if the statement has free \c break statements.
  bool contains_free_break(void) const { return CONST_CAST(cinsn_t*)(this)->collect_free_breaks(nullptr); }
  /// Check if the statement has free \c continue statements.
  bool contains_free_continue(void) const { return CONST_CAST(cinsn_t*)(this)->collect_free_continues(nullptr); }

  const char *hexapi dstr() const;
};
DECLARE_TYPE_AS_MOVABLE(cinsn_t);

typedef qlist<cinsn_t> cinsn_list_t;

/// Compound statement (curly braces)
struct cblock_t : public cinsn_list_t // we need list to be able to manipulate
{                                       // its elements freely
  DECLARE_COMPARISONS(cblock_t);
};

/// Function argument
struct carg_t : public cexpr_t
{
  bool is_vararg;             ///< is a vararg (matches ...)
  tinfo_t formal_type;        ///< formal parameter type (if known)
  void consume_cexpr(cexpr_t *e)
  {
    qswap(*(cexpr_t*)this, *e);
    delete e;
  }
  carg_t(void) : is_vararg(false) {}
  DECLARE_COMPARISONS(carg_t)
  {
    return cexpr_t::compare(r);
  }
};
DECLARE_TYPE_AS_MOVABLE(carg_t);

/// Function argument list
struct carglist_t : public qvector<carg_t>
{
  tinfo_t functype;   ///< function object type
  int flags;          ///< call flags
#define CFL_FINAL   0x0001  ///< call type is final, should not be changed
#define CFL_HELPER  0x0002  ///< created from a decompiler helper function
#define CFL_NORET   0x0004  ///< call does not return
  carglist_t(void) : flags(0) {}
  carglist_t(const tinfo_t &ftype, int fl = 0) : functype(ftype), flags(fl) {}
  DECLARE_COMPARISONS(carglist_t);
  void print(qstring *vout, const cfunc_t *func) const;
  int print(int curpos, vc_printer_t &vp) const;
};

/// Switch case. Usually cinsn_t is a block
struct ccase_t : public cinsn_t
{
  uint64vec_t values;        ///< List of case values.
                             ///< if empty, then 'default' case
  DECLARE_COMPARISONS(ccase_t);
  void set_insn(cinsn_t *i); // deletes 'i'
  size_t size(void) const { return values.size(); }
  const uint64 &value(int i) const { return values[i]; }
};
DECLARE_TYPE_AS_MOVABLE(ccase_t);

/// Vector of switch cases
struct ccases_t : public qvector<ccase_t>
{
  DECLARE_COMPARISONS(ccases_t);
  int find_value(uint64 v) const;
};

/// Switch statement
struct cswitch_t : public ceinsn_t
{
  cnumber_t mvnf;       ///< Maximal switch value and number format
  ccases_t cases;       ///< Switch cases: values and instructions
  DECLARE_COMPARISONS(cswitch_t);
};

//---------------------------------------------------------------------------
/// Invisible COLOR_ADDR tags in the output text are used to refer to ctree items and variables
struct ctree_anchor_t
{
  uval_t value = BADADDR;
#define ANCHOR_INDEX  0x1FFFFFFF
#define ANCHOR_MASK   0xC0000000
#define   ANCHOR_CITEM 0x00000000 ///< c-tree item
#define   ANCHOR_LVAR  0x40000000 ///< declaration of local variable
#define   ANCHOR_ITP   0x80000000 ///< item type preciser
#define ANCHOR_BLKCMT 0x20000000  ///< block comment (for ctree items)
  int get_index(void) const { return value & ANCHOR_INDEX; }
  item_preciser_t get_itp(void) const { return item_preciser_t(value & ~ANCHOR_ITP); }
  bool is_valid_anchor(void) const { return value != BADADDR; }
  bool is_citem_anchor(void) const { return (value & ANCHOR_MASK) == ANCHOR_CITEM; }
  bool is_lvar_anchor(void) const { return (value & ANCHOR_MASK) == ANCHOR_LVAR; }
  bool is_itp_anchor(void) const { return (value & ANCHOR_ITP) != 0; }
  bool is_blkcmt_anchor(void) const { return (value & ANCHOR_BLKCMT) != 0; }
};

/// Type of the cursor item.
enum cursor_item_type_t
{
  VDI_NONE, ///< undefined
  VDI_EXPR, ///< c-tree item
  VDI_LVAR, ///< declaration of local variable
  VDI_FUNC, ///< the function itself (the very first line with the function prototype)
  VDI_TAIL, ///< cursor is at (beyond) the line end (commentable line)
};

/// Cursor item.
/// Information about the item under the cursor
struct ctree_item_t
{
  cursor_item_type_t citype; ///< Item type
  union
  {
    citem_t *it;
    cexpr_t *e;         ///< VDI_EXPR: Expression
    cinsn_t *i;         ///< VDI_EXPR: Statement
    lvar_t *l;          ///< VDI_LVAR: Local variable
    cfunc_t *f;         ///< VDI_FUNC: Function
    treeloc_t loc;      ///< VDI_TAIL: Line tail
  };

  ctree_item_t(): citype(VDI_NONE) {}

  void verify(const mba_t *mba) const;

  /// Get pointer to structure member.
  /// If the current item is a structure field,
  /// this function will return pointer to its definition.
  /// \return nullptr if failed
  /// \param[out] p_sptr pointer to the variable where the pointer to the
  ///               parent structure is returned. This parameter can be nullptr.

  member_t *hexapi get_memptr(struc_t **p_sptr=nullptr) const;

  /// Get pointer to local variable.
  /// If the current item is a local variable,
  /// this function will return pointer to its definition.
  /// \return nullptr if failed

  lvar_t *hexapi get_lvar(void) const;


  /// Get address of the current item.
  /// Each ctree item has an address.
  /// \return BADADDR if failed

  ea_t hexapi get_ea(void) const;


  /// Get label number of the current item.
  /// \param[in] gln_flags Combination of \ref GLN_ bits
  /// \return -1 if failed or no label

  int hexapi get_label_num(int gln_flags) const;
/// \defgroup GLN_ get_label_num control
//@{
#define GLN_CURRENT     0x01 ///< get label of the current item
#define GLN_GOTO_TARGET 0x02 ///< get goto target
#define GLN_ALL         0x03 ///< get both
//@}

  /// Is the current item is a ctree item?
  bool is_citem(void) const { return citype == VDI_EXPR; }

  void hexapi print(qstring *vout) const;
  const char *hexapi dstr() const;
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
};

/// Unused label disposition.
enum allow_unused_labels_t
{
  FORBID_UNUSED_LABELS = 0,     ///< Unused labels cause interr
  ALLOW_UNUSED_LABELS = 1,      ///< Unused labels are permitted
};

typedef std::map<int, qstring> user_labels_t;

/// Logically negate the specified expression.
/// The specified expression will be logically negated.
/// For example, "x == y" is converted into "x != y" by this function.
/// \param e expression to negate. After the call, e must not be used anymore
///          because it can be changed by the function. The function return value
///          must be used to refer to the expression.
/// \return logically negated expression.

cexpr_t *hexapi lnot(cexpr_t *e);


/// Create a new block-statement.

cinsn_t *hexapi new_block(void);


/// Create a helper object.
/// This function creates a helper object.
/// The named function is not required to exist, the decompiler will only print
/// its name in the output. Helper functions are usually used to represent arbitrary
/// function or macro calls in the output.
/// \param standalone false:helper must be called; true:helper can be used in any expression
/// \param type type of the create function object
/// \param format printf-style format string that will be used to create the function name.
/// \param va additional arguments for printf
/// \return the created expression.

AS_PRINTF(3, 0) cexpr_t *hexapi vcreate_helper(bool standalone, const tinfo_t &type, const char *format, va_list va);

/// Create a helper object..
AS_PRINTF(3, 4) inline cexpr_t *create_helper(bool standalone, const tinfo_t &type, const char *format, ...)
{
  va_list va;
  va_start(va, format);
  cexpr_t *e = vcreate_helper(standalone, type, format, va);
  va_end(va);
  return e;
}


/// Create a helper call expression.
/// This function creates a new expression: a call of a helper function.
/// \param rettype type of the whole expression.
/// \param args helper arguments. this object will be consumed by the function.
///             if there are no args, this parameter may be specified as nullptr.
/// \param format printf-style format string that will be used to create the function name.
/// \param va additional arguments for printf
/// \return the created expression.

AS_PRINTF(3, 0) cexpr_t *hexapi vcall_helper(const tinfo_t &rettype, carglist_t *args, const char *format, va_list va);

/// Create a helper call.
AS_PRINTF(3, 4) inline cexpr_t *call_helper(
        const tinfo_t &rettype,
        carglist_t *args,
        const char *format, ...)
{
  va_list va;
  va_start(va, format);
  cexpr_t *e = vcall_helper(rettype, args, format, va);
  va_end(va);
  return e;
}


/// Create a number expression
/// \param n value
/// \param func current function
/// \param ea definition address of the number
/// \param opnum operand number of the number (in the disassembly listing)
/// \param sign number sign
/// \param size size of number in bytes
/// Please note that the type of the resulting expression can be anything because
/// it can be inherited from the disassembly listing or taken from the user
/// specified number representation in the pseudocode view.

cexpr_t *hexapi make_num(uint64 n, cfunc_t *func=nullptr, ea_t ea=BADADDR, int opnum=0, type_sign_t sign=no_sign, int size=0);


/// Create a reference.
/// This function performs the following conversion: "obj" => "&obj".
/// It can handle casts, annihilate "&*", and process other special cases.

cexpr_t *hexapi make_ref(cexpr_t *e);


/// Dereference a pointer.
/// This function dereferences a pointer expression.
/// It performs the following conversion: "ptr" => "*ptr"
/// It can handle discrepancies in the pointer type and the access size.
/// \param e expression to deference
/// \param ptrsize access size
/// \param is_flt dereferencing for floating point access?
/// \return dereferenced expression

cexpr_t *hexapi dereference(cexpr_t *e, int ptrsize, bool is_flt=false);


/// Save user defined labels into the database.
/// \param func_ea the entry address of the function,
///                ignored if FUNC != nullptr
/// \param user_labels collection of user defined labels
/// \param func pointer to current function,
///             if FUNC != nullptr, then save labels using a more stable
///             method that preserves them even when the decompiler
///             output drastically changes

void hexapi save_user_labels(ea_t func_ea, const user_labels_t *user_labels);   // DEPRECATED
void hexapi save_user_labels2(ea_t func_ea, const user_labels_t *user_labels, const cfunc_t *func=nullptr);


/// Save user defined comments into the database.
/// \param func_ea the entry address of the function
/// \param user_cmts collection of user defined comments

void hexapi save_user_cmts(ea_t func_ea, const user_cmts_t *user_cmts);

/// Save user defined number formats into the database.
/// \param func_ea the entry address of the function
/// \param numforms collection of user defined comments

void hexapi save_user_numforms(ea_t func_ea, const user_numforms_t *numforms);


/// Save user defined citem iflags into the database.
/// \param func_ea the entry address of the function
/// \param iflags collection of user defined citem iflags

void hexapi save_user_iflags(ea_t func_ea, const user_iflags_t *iflags);


/// Save user defined union field selections into the database.
/// \param func_ea the entry address of the function
/// \param unions collection of union field selections

void hexapi save_user_unions(ea_t func_ea, const user_unions_t *unions);


/// Restore user defined labels from the database.
/// \param func_ea the entry address of the function,
///                ignored if FUNC != nullptr
/// \param func    pointer to current function
/// \return collection of user defined labels.
///         The returned object must be deleted by the caller using delete_user_labels()

user_labels_t *hexapi restore_user_labels(ea_t func_ea);    // DEPRECATED
user_labels_t *hexapi restore_user_labels2(ea_t func_ea, const cfunc_t *func=nullptr);


/// Restore user defined comments from the database.
/// \param func_ea the entry address of the function
/// \return collection of user defined comments.
///         The returned object must be deleted by the caller using delete_user_cmts()

user_cmts_t *hexapi restore_user_cmts(ea_t func_ea);


/// Restore user defined number formats from the database.
/// \param func_ea the entry address of the function
/// \return collection of user defined number formats.
///         The returned object must be deleted by the caller using delete_user_numforms()

user_numforms_t *hexapi restore_user_numforms(ea_t func_ea);


/// Restore user defined citem iflags from the database.
/// \param func_ea the entry address of the function
/// \return collection of user defined iflags.
///         The returned object must be deleted by the caller using delete_user_iflags()

user_iflags_t *hexapi restore_user_iflags(ea_t func_ea);


/// Restore user defined union field selections from the database.
/// \param func_ea the entry address of the function
/// \return collection of union field selections
///         The returned object must be deleted by the caller using delete_user_unions()

user_unions_t *hexapi restore_user_unions(ea_t func_ea);


typedef std::map<ea_t, cinsnptrvec_t> eamap_t;
// map of instruction boundaries. may contain INS_EPILOG for the epilog instructions
typedef std::map<cinsn_t *, rangeset_t> boundaries_t;
#define INS_EPILOG ((cinsn_t *)1)

// Tags to find this location quickly: #cfunc_t #func_t
//-------------------------------------------------------------------------
/// Decompiled function. Decompilation result is kept here.
struct cfunc_t
{
  ea_t entry_ea;             ///< function entry address
  mba_t *mba;                ///< underlying microcode
  cinsn_t body;              ///< function body, must be a block
  intvec_t &argidx;          ///< list of arguments (indexes into vars)
  ctree_maturity_t maturity; ///< maturity level
  // The following maps must be accessed using helper functions.
  // Example: for user_labels_t, see functions starting with "user_labels_".
  user_labels_t *user_labels;///< user-defined labels.
  user_cmts_t *user_cmts;    ///< user-defined comments.
  user_numforms_t *numforms; ///< user-defined number formats.
  user_iflags_t *user_iflags;///< user-defined item flags \ref CIT_
  user_unions_t *user_unions;///< user-defined union field selections.
/// \defgroup CIT_ ctree item iflags bits
//@{
#define CIT_COLLAPSED 0x0001 ///< display ctree item in collapsed form
//@}
  int refcnt;                ///< reference count to this object. use cfuncptr_t
  int statebits;             ///< current cfunc_t state. see \ref CFS_
/// \defgroup CFS_ cfunc state bits
#define CFS_BOUNDS       0x0001 ///< 'eamap' and 'boundaries' are ready
#define CFS_TEXT         0x0002 ///< 'sv' is ready (and hdrlines)
#define CFS_LVARS_HIDDEN 0x0004 ///< local variable definitions are collapsed
#define CFS_LOCKED       0x0008 ///< cfunc is temporarily locked
  eamap_t *eamap;            ///< ea->insn map. use \ref get_eamap
  boundaries_t *boundaries;  ///< map of instruction boundaries. use \ref get_boundaries
  strvec_t sv;               ///< decompilation output: function text. use \ref get_pseudocode
  int hdrlines;              ///< number of lines in the declaration area
  mutable ctree_items_t treeitems; ///< vector of ctree items

  // the exact size of this class is not documented, there may be more fields
  char reserved[];

public:
  cfunc_t(mba_t *mba);          // use create_cfunc()
  ~cfunc_t(void) { cleanup(); }
  void release(void) { delete this; }
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()

  /// Generate the function body.
  /// This function (re)generates the function body from the underlying microcode.
  void hexapi build_c_tree(void);

  /// Verify the ctree.
  /// This function verifies the ctree. If the ctree is malformed, an internal error
  /// is generated. Use it to verify the ctree after your modifications.
  /// \param aul Are unused labels acceptable?
  /// \param even_without_debugger if false and there is no debugger, the verification will be skipped
  void hexapi verify(allow_unused_labels_t aul, bool even_without_debugger) const;

  /// Print function prototype.
  /// \param vout output buffer
  void hexapi print_dcl(qstring *vout) const;

  /// Print function text.
  /// \param vp printer helper class to receive the generated text.
  void hexapi print_func(vc_printer_t &vp) const;

  /// Get the function type.
  /// \param type variable where the function type is returned
  /// \return false if failure
  bool hexapi get_func_type(tinfo_t *type) const;

  /// Get vector of local variables.
  /// \return pointer to the vector of local variables. If you modify this vector,
  ///         the ctree must be regenerated in order to have correct cast operators.
  ///         Use build_c_tree() for that.
  ///         Removing lvars should be done carefully: all references in ctree
  ///         and microcode must be corrected after that.
  lvars_t *hexapi get_lvars(void);

  /// Get stack offset delta.
  /// The local variable stack offsets retrieved by v.location.stkoff()
  /// should be adjusted before being used as stack frame offsets in IDA.
  /// \return the delta to apply.
  ///         example: ida_stkoff = v.location.stkoff() - f->get_stkoff_delta()
  sval_t hexapi get_stkoff_delta(void);

  /// Find the label.
  /// \return pointer to the ctree item with the specified label number.
  citem_t *hexapi find_label(int label);

  /// Remove unused labels.
  /// This function checks what labels are really used by the function and
  /// removes the unused ones. You must call it after deleting a goto statement.
  void hexapi remove_unused_labels(void);

  /// Retrieve a user defined comment.
  /// \param loc ctree location
  /// \param rt should already retrieved comments retrieved again?
  /// \return pointer to the comment string or nullptr
  const char *hexapi get_user_cmt(const treeloc_t &loc, cmt_retrieval_type_t rt) const;

  /// Set a user defined comment.
  /// This function stores the specified comment in the cfunc_t structure.
  /// The save_user_cmts() function must be called after it.
  /// \param loc ctree location
  /// \param cmt new comment. if empty or nullptr, then an existing comment is deleted.
  void hexapi set_user_cmt(const treeloc_t &loc, const char *cmt);

  /// Retrieve citem iflags.
  /// \param loc citem locator
  /// \return \ref CIT_ or 0
  int32 hexapi get_user_iflags(const citem_locator_t &loc) const;

  /// Set citem iflags.
  /// \param loc citem locator
  /// \param iflags new iflags
  void hexapi set_user_iflags(const citem_locator_t &loc, int32 iflags);

  /// Check if there are orphan comments.
  bool hexapi has_orphan_cmts(void) const;

  /// Delete all orphan comments.
  /// The save_user_cmts() function must be called after this call.
  int hexapi del_orphan_cmts(void);

  /// Retrieve a user defined union field selection.
  /// \param ea address
  /// \param path out: path describing the union selection.
  /// \return pointer to the path or nullptr
  bool hexapi get_user_union_selection(ea_t ea, intvec_t *path);

  /// Set a union field selection.
  /// The save_user_unions() function must be called after calling this function.
  /// \param ea address
  /// \param path in: path describing the union selection.
  void hexapi set_user_union_selection(ea_t ea, const intvec_t &path);

  /// Save user-defined labels into the database
  void hexapi save_user_labels() const;
  /// Save user-defined comments into the database
  void hexapi save_user_cmts() const;
  /// Save user-defined number formats into the database
  void hexapi save_user_numforms() const;
  /// Save user-defined iflags into the database
  void hexapi save_user_iflags() const;
  /// Save user-defined union field selections into the database
  void hexapi save_user_unions() const;

  /// Get ctree item for the specified cursor position.
  /// \return false if failed to get the current item
  /// \param line line of decompilation text (element of \ref sv)
  /// \param x x cursor coordinate in the line
  /// \param is_ctree_line does the line belong to statement area? (if not, it is assumed to belong to the declaration area)
  /// \param phead ptr to the first item on the line (used to attach block comments). May be nullptr
  /// \param pitem ptr to the current item. May be nullptr
  /// \param ptail ptr to the last item on the line (used to attach indented comments). May be nullptr
  /// \sa vdui_t::get_current_item()
  bool hexapi get_line_item(
        const char *line,
        int x,
        bool is_ctree_line,
        ctree_item_t *phead,
        ctree_item_t *pitem,
        ctree_item_t *ptail);

  /// Get information about decompilation warnings.
  /// \return reference to the vector of warnings
  hexwarns_t &hexapi get_warnings(void);

  /// Get pointer to ea->insn map.
  /// This function initializes eamap if not done yet.
  eamap_t &hexapi get_eamap(void);

  /// Get pointer to map of instruction boundaries.
  /// This function initializes the boundary map if not done yet.
  boundaries_t &hexapi get_boundaries(void);

  /// Get pointer to decompilation output: the pseudocode.
  /// This function generates pseudocode if not done yet.
  const strvec_t &hexapi get_pseudocode(void);

  /// Refresh ctext after a ctree modification.
  /// This function informs the decompiler that ctree (\ref body) have been
  /// modified and ctext (\ref sv) does not correspond to it anymore.
  /// It also refreshes the pseudocode windows if there is any.
  void hexapi refresh_func_ctext(void);

  bool hexapi gather_derefs(const ctree_item_t &ci, udt_type_data_t *udm=nullptr) const;
  bool hexapi find_item_coords(const citem_t *item, int *px, int *py);
  bool locked(void) const { return (statebits & CFS_LOCKED) != 0; }
private:
  /// Cleanup.
  /// Properly delete all children and free memory.
  void hexapi cleanup(void);
  DECLARE_UNCOPYABLE(cfunc_t)
};
typedef qvector<cfuncptr_t> cfuncptrs_t;

/// \defgroup DECOMP_ decompile() flags
//@{
#define DECOMP_NO_WAIT      0x0001 ///< do not display waitbox
#define DECOMP_NO_CACHE     0x0002 ///< do not use decompilation cache (snippets are never cached)
#define DECOMP_NO_FRAME     0x0004 ///< do not use function frame info (only snippet mode)
#define DECOMP_WARNINGS     0x0008 ///< display warnings in the output window
#define DECOMP_ALL_BLKS     0x0010 ///< generate microcode for unreachable blocks
#define DECOMP_NO_HIDE      0x0020 ///< do not close display waitbox. see close_hexrays_waitboxes()
#define DECOMP_NO_XREFS     0x0040 ///< Obsolete. Use DECOMP_GXREFS_NOUPD
#define DECOMP_GXREFS_DEFLT 0x0000 ///< the default behavior: do not update the
                                   ///< global xrefs cache upon decompile() call,
                                   ///< but when the pseudocode text is generated
                                   ///< (e.g., through cfunc_t.get_pseudocode())
#define DECOMP_GXREFS_NOUPD 0x0040 ///< do not update the global xrefs cache
#define DECOMP_GXREFS_FORCE 0x0080 ///< update the global xrefs cache immediately
#define DECOMP_VOID_MBA     0x0100 ///< return empty mba object (to be used with gen_microcode)
//@}

/// Close the waitbox displayed by the decompiler.
/// Useful if DECOMP_NO_HIDE was used during decompilation.

void hexapi close_hexrays_waitbox(void);


/// Decompile a snippet or a function.
/// \param mbr          what to decompile
/// \param hf           extended error information (if failed)
/// \param decomp_flags bitwise combination of \ref DECOMP_... bits
/// \return pointer to the decompilation result (a reference counted pointer).
///         nullptr if failed.

cfuncptr_t hexapi decompile(
        const mba_ranges_t &mbr,
        hexrays_failure_t *hf=nullptr,
        int decomp_flags=0);


/// Decompile a function.
/// Multiple decompilations of the same function return the same object.
/// \param pfn pointer to function to decompile
/// \param hf  extended error information (if failed)
/// \param decomp_flags bitwise combination of \ref DECOMP_... bits
/// \return pointer to the decompilation result (a reference counted pointer).
///         nullptr if failed.

inline cfuncptr_t decompile_func(
        func_t *pfn,
        hexrays_failure_t *hf=nullptr,
        int decomp_flags=0)
{
  mba_ranges_t mbr(pfn);
  return decompile(mbr, hf, decomp_flags);
}


/// Decompile a snippet.
/// \param ranges       snippet ranges. ranges[0].start_ea is the entry point
/// \param hf           extended error information (if failed)
/// \param decomp_flags bitwise combination of \ref DECOMP_... bits
/// \return pointer to the decompilation result (a reference counted pointer).
///         nullptr if failed.

inline cfuncptr_t decompile_snippet(
        const rangevec_t &ranges,
        hexrays_failure_t *hf=nullptr,
        int decomp_flags=0)
{
  mba_ranges_t mbr(ranges);
  return decompile(mbr, hf, decomp_flags);
}


/// Generate microcode of an arbitrary code snippet
/// \param mbr          snippet ranges
/// \param hf           extended error information (if failed)
/// \param retlist      list of registers the snippet returns
/// \param decomp_flags bitwise combination of \ref DECOMP_... bits
/// \param reqmat       required microcode maturity
/// \return pointer to  the microcode, nullptr if failed.

mba_t *hexapi gen_microcode(
        const mba_ranges_t &mbr,
        hexrays_failure_t *hf=nullptr,
        const mlist_t *retlist=nullptr,
        int decomp_flags=0,
        mba_maturity_t reqmat=MMAT_GLBOPT3);

/// Create an empty microcode object
inline mba_t *create_empty_mba(
        const mba_ranges_t &mbr,
        hexrays_failure_t *hf=nullptr)
{
  return gen_microcode(mbr, hf, nullptr, DECOMP_VOID_MBA);
}


/// Create a new cfunc_t object.
/// \param mba microcode object.
/// After creating the cfunc object it takes the ownership of MBA.

cfuncptr_t hexapi create_cfunc(mba_t *mba);


/// Flush the cached decompilation results.
/// Erases a cache entry for the specified function.
/// \param ea function to erase from the cache
/// \param close_views close pseudocode windows that show the function
/// \return if a cache entry existed.

bool hexapi mark_cfunc_dirty(ea_t ea, bool close_views=false);


/// Flush all cached decompilation results.

void hexapi clear_cached_cfuncs(void);


/// Do we have a cached decompilation result for 'ea'?

bool hexapi has_cached_cfunc(ea_t ea);

//--------------------------------------------------------------------------
// Now cinsn_t class is defined, define the cleanup functions:
inline void cif_t::cleanup(void)     { delete ithen; delete ielse; }
inline void cloop_t::cleanup(void)   { delete body; }

/// Print item into one line.
/// \param vout output buffer
/// \param func parent function. This argument is used to find out the referenced variable names.
/// \return length of the generated text.

inline void citem_t::print1(qstring *vout, const cfunc_t *func) const
{
  if ( is_expr() )
    ((cexpr_t*)this)->print1(vout, func);
  else
    ((cinsn_t*)this)->print1(vout, func);
}

/// Get pointers to operands. at last one operand should be a number
/// o1 will be pointer to the number

inline bool cexpr_t::get_1num_op(cexpr_t **o1, cexpr_t **o2)
{
  if ( x->op == cot_num )
  {
    *o1 = x;
    *o2 = y;
  }
  else
  {
    if ( y->op != cot_num )
      return false;
    *o1 = y;
    *o2 = x;
  }
  return true;
}

inline bool cexpr_t::get_1num_op(const cexpr_t **o1, const cexpr_t **o2) const
{
  return CONST_CAST(cexpr_t*)(this)->get_1num_op(
         CONST_CAST(cexpr_t**)(o1),
         CONST_CAST(cexpr_t**)(o2));
}

inline citem_locator_t::citem_locator_t(const citem_t *i)
  : ea(i != nullptr ? i->ea : BADADDR),
    op(i != nullptr ? i->op : cot_empty)
{
}

inline cblock_t *ctree_parentee_t::get_block(void)
{
  cinsn_t *block = (cinsn_t *)parents.back();
  QASSERT(50600, block->op == cit_block);
  return block->cblock;
}

const char *hexapi get_ctype_name(ctype_t op);
qstring hexapi create_field_name(const tinfo_t &type, uval_t offset=BADADDR);
typedef void *hexdsp_t(int code, ...);
const int64 HEXRAYS_API_MAGIC = 0x00DEC0DE00000003LL;

/// Decompiler events.
/// Use install_hexrays_callback() to install a handler for decompiler events.
/// When the possible return value is not specified, your callback
/// must return zero.
enum hexrays_event_t ENUM_SIZE(int)
{
  // When a function is decompiled, the following events occur:

  hxe_flowchart,        ///< Flowchart has been generated.
                        ///< \param fc (qflow_chart_t *)

  hxe_stkpnts,          ///< SP change points have been calculated.
                        ///< \param mba (mba_t *)
                        ///< \param stkpnts (stkpnts_t *)
                        ///< return \ref MERR_ code

  hxe_prolog,           ///< Prolog analysis has been finished.
                        ///< \param mba (mba_t *)
                        ///< \param fc (qflow_chart_t *)
                        ///< \param reachable_blocks (bitset_t *)
                        ///< \param decomp_flags (int)
                        ///< return \ref MERR_ code

  hxe_microcode,        ///< Microcode has been generated.
                        ///< \param mba (mba_t *)
                        ///< return \ref MERR_ code

  hxe_preoptimized,     ///< Microcode has been preoptimized.
                        ///< \param mba (mba_t *)
                        ///< return \ref MERR_ code

  hxe_locopt,           ///< Basic block level optimization has been finished.
                        ///< \param mba (mba_t *)
                        ///< return \ref MERR_ code

  hxe_prealloc,         ///< Local variables: preallocation step begins.
                        ///< \param mba (mba_t *)
                        ///< This event may occur several times.
                        ///< Should return: 1 if modified microcode
                        ///< Negative values are \ref MERR_ error codes

  hxe_glbopt,           ///< Global optimization has been finished.
                        ///< If microcode is modified, MERR_LOOP must be returned.
                        ///< It will cause a complete restart of the optimization.
                        ///< \param mba (mba_t *)
                        ///< return \ref MERR_ code

  hxe_structural,       ///< Structural analysis has been finished.
                        ///< \param ct (control_graph_t *)

  hxe_maturity,         ///< Ctree maturity level is being changed.
                        ///< \param cfunc (cfunc_t *)
                        ///< \param new_maturity (ctree_maturity_t)

  hxe_interr,           ///< Internal error has occurred.
                        ///< \param errcode (int )

  hxe_combine,          ///< Trying to combine instructions of basic block.
                        ///< \param blk (mblock_t *)
                        ///< \param insn (minsn_t *)
                        ///< Should return: 1 if combined the current instruction with a preceding one
                        ///                 -1 if the instruction should not be combined
                        ///                 0 else

  hxe_print_func,       ///< Printing ctree and generating text.
                        ///< \param cfunc (cfunc_t *)
                        ///< \param vp (vc_printer_t *)
                        ///< Returns: 1 if text has been generated by the plugin
                        ///< It is forbidden to modify ctree at this event.

  hxe_func_printed,     ///< Function text has been generated. Plugins may
                        ///< modify the text in \ref cfunc_t::sv.
                        ///< The text uses regular color codes (see lines.hpp)
                        ///< COLOR_ADDR is used to store pointers to ctree items.
                        ///< \param cfunc (cfunc_t *)

  hxe_resolve_stkaddrs, ///< The optimizer is about to resolve stack addresses.
                        ///< \param mba (mba_t *)

  hxe_build_callinfo,   ///< Analyzing a call instruction.
                        ///< \param blk (mblock_t *) blk->tail is the call.
                        ///< \param type (tinfo_t *) buffer for the output type.
                        ///< \param callinfo (mcallinfo_t **) prepared callinfo.
                        ///< The plugin should either specify the function type,
                        ///< either allocate and return a new mcallinfo_t object.

  // User interface related events:

  hxe_open_pseudocode=100,
                        ///< New pseudocode view has been opened.
                        ///< \param vu (vdui_t *)

  hxe_switch_pseudocode,///< Existing pseudocode view has been reloaded
                        ///< with a new function. Its text has not been
                        ///< refreshed yet, only cfunc and mba pointers are ready.
                        ///< \param vu (vdui_t *)

  hxe_refresh_pseudocode,///< Existing pseudocode text has been refreshed.
                        ///< Adding/removing pseudocode lines is forbidden in this event.
                        ///< \param vu (vdui_t *)
                        ///< See also hxe_text_ready, which happens earlier

  hxe_close_pseudocode, ///< Pseudocode view is being closed.
                        ///< \param vu (vdui_t *)

  hxe_keyboard,         ///< Keyboard has been hit.
                        ///< \param vu (vdui_t *)
                        ///< \param key_code (int) VK_...
                        ///< \param shift_state (int)
                        ///< Should return: 1 if the event has been handled

  hxe_right_click,      ///< Mouse right click.
                        ///< Use hxe_populating_popup instead, in case you
                        ///< want to add items in the popup menu.
                        ///< \param vu (vdui_t *)

  hxe_double_click,     ///< Mouse double click.
                        ///< \param vu (vdui_t *)
                        ///< \param shift_state (int)
                        ///< Should return: 1 if the event has been handled

  hxe_curpos,           ///< Current cursor position has been changed.
                        ///< (for example, by left-clicking or using keyboard)\n
                        ///< \param vu (vdui_t *)

  hxe_create_hint,      ///< Create a hint for the current item.
                        ///< \see ui_get_custom_viewer_hint
                        ///< \param vu (vdui_t *)
                        ///< \param hint (qstring *)
                        ///< \param important_lines (int *)
                        ///< Possible return values:
                        ///< \retval 0 continue collecting hints with other subscribers
                        ///< \retval 1 stop collecting hints

  hxe_text_ready,       ///< Decompiled text is ready.
                        ///< \param vu (vdui_t *)
                        ///< This event can be used to modify the output text (sv).
                        ///< Obsolete. Please use hxe_func_printed instead.

  hxe_populating_popup, ///< Populating popup menu. We can add menu items now.
                        ///< \param widget (TWidget *)
                        ///< \param popup_handle (TPopupMenu *)
                        ///< \param vu (vdui_t *)

  lxe_lvar_name_changed,///< Local variable got renamed.
                        ///< \param vu (vdui_t *)
                        ///< \param v (lvar_t *)
                        ///< \param name (const char *)
                        ///< \param is_user_name (bool)
                        ///< Please note that it is possible to read/write
                        ///< user settings for lvars directly from the idb.

  lxe_lvar_type_changed,///< Local variable type got changed.
                        ///< \param vu (vdui_t *)
                        ///< \param v (lvar_t *)
                        ///< \param tinfo (const tinfo_t *)
                        ///< Please note that it is possible to read/write
                        ///< user settings for lvars directly from the idb.

  lxe_lvar_cmt_changed, ///< Local variable comment got changed.
                        ///< \param vu (vdui_t *)
                        ///< \param v (lvar_t *)
                        ///< \param cmt (const char *)
                        ///< Please note that it is possible to read/write
                        ///< user settings for lvars directly from the idb.

  lxe_lvar_mapping_changed, ///< Local variable mapping got changed.
                        ///< \param vu (vdui_t *)
                        ///< \param from (lvar_t *)
                        ///< \param to (lvar_t *)
                        ///< Please note that it is possible to read/write
                        ///< user settings for lvars directly from the idb.

  hxe_cmt_changed,      ///< Comment got changed.
                        ///< \param cfunc (cfunc_t *)
                        ///< \param loc (const treeloc_t *)
                        ///< \param cmt (const char *)
};

/// Handler of decompiler events.
/// \param ud user data. the value specified at the handler installation time
///           is passed here.
/// \param event decompiler event code
/// \param va additional arguments
/// \return as a rule the callback must return 0 unless specified otherwise
///         in the event description.

typedef ssize_t idaapi hexrays_cb_t(void *ud, hexrays_event_t event, va_list va);


/// Install handler for decompiler events.
/// \param callback handler to install
/// \param ud user data. this pointer will be passed to your handler by the decompiler.
/// \return false if failed

bool hexapi install_hexrays_callback(hexrays_cb_t *callback, void *ud);

/// Uninstall handler for decompiler events.
/// \param callback handler to uninstall
/// \param ud user data. if nullptr, all handler corresponding to \c callback is uninstalled.
///             if not nullptr, only the callback instance with the specified \c ud value is uninstalled.
/// \return number of uninstalled handlers.

int hexapi remove_hexrays_callback(hexrays_cb_t *callback, void *ud);


//---------------------------------------------------------------------------
/// \defgroup vdui User interface definitions
//@{

/// Type of the input device.
/// How the user command has been invoked
enum input_device_t
{
  USE_KEYBOARD = 0,     ///< Keyboard
  USE_MOUSE = 1,        ///< Mouse
};
//@}

//---------------------------------------------------------------------------
/// Cursor position in the output text (pseudocode).
struct ctext_position_t
{
  int lnnum;            ///< Line number
  int x;                ///< x coordinate of the cursor within the window
  int y;                ///< y coordinate of the cursor within the window
  /// Is the cursor in the variable/type declaration area?
  /// \param hdrlines Number of lines of the declaration area
  bool in_ctree(int hdrlines) const { return lnnum >= hdrlines; }
  /// Comparison operators
  DECLARE_COMPARISONS(ctext_position_t)
  {
    if ( lnnum < r.lnnum ) return -1;
    if ( lnnum > r.lnnum ) return  1;
    if ( x < r.x ) return -1;
    if ( x > r.x ) return  1;
    return 0;
  }
  ctext_position_t(int _lnnum=-1, int _x=0, int _y=0)
    : lnnum(_lnnum), x(_x), y(_y) {}
};

/// Navigation history item.
/// Holds information about interactive decompilation history.
/// Currently this is not saved in the database.
struct history_item_t : public ctext_position_t
{
  ea_t ea;              ///< The entry address of the decompiled function
  ea_t end;             ///< BADADDR-decompile function; otherwise end of the range
  history_item_t(ea_t _ea=BADADDR, int _lnnum=-1, int _x=0, int _y=0)
    : ctext_position_t(_lnnum, _x, _y), ea(_ea), end(BADADDR) {}
  history_item_t(ea_t _ea, const ctext_position_t &p)
    : ctext_position_t(p), ea(_ea), end(BADADDR) {}
};

/// Navigation history.
typedef qstack<history_item_t> history_t;

/// Comment types
typedef int cmt_type_t;
const cmt_type_t
  CMT_NONE   = 0x0000,  ///< No comment is possible
  CMT_TAIL   = 0x0001,  ///< Indented comment
  CMT_BLOCK1 = 0x0002,  ///< Anterioir block comment
  CMT_BLOCK2 = 0x0004,  ///< Posterior block comment
  CMT_LVAR   = 0x0008,  ///< Local variable comment
  CMT_FUNC   = 0x0010,  ///< Function comment
  CMT_ALL    = 0x001F;  ///< All comments

//---------------------------------------------------------------------------
/// Information about the pseudocode window
struct vdui_t
{
  int flags;            ///< \ref VDUI_
/// \defgroup VDUI_ Properties of pseudocode window
/// Used in vdui_t::flags
//@{
#define VDUI_VISIBLE 0x0001     ///< is visible?
#define VDUI_VALID   0x0002     ///< is valid?
//@}

  /// Is the pseudocode window visible?
  /// if not, it might be invisible or destroyed
  bool visible(void) const { return (flags & VDUI_VISIBLE) != 0; }
  /// Does the pseudocode window contain valid code?
  /// It can become invalid if the function type gets changed in IDA.
  bool valid(void) const { return (flags & VDUI_VALID) != 0; }
  /// Does the pseudocode window contain valid code?
  /// We lock windows before modifying them, to avoid recursion due to
  /// the events generated by the IDA kernel.
  /// \retval true The window is locked and may have stale info
  bool locked(void) const { return cfunc != nullptr && cfunc->locked(); }
  void set_visible(bool v) { setflag(flags, VDUI_VISIBLE, v); }
  void set_valid(bool v)   { setflag(flags, VDUI_VALID, v); }
  bool hexapi set_locked(bool v); // returns true-redecompiled

  int view_idx;         ///< pseudocode window index (0..)
  TWidget *ct;          ///< pseudocode view
  TWidget *toplevel;

  mba_t *mba;           ///< pointer to underlying microcode
  cfuncptr_t cfunc;     ///< pointer to function object
  merror_t last_code;   ///< result of the last user action. See \ref MERR_

  // The following fields are valid after get_current_item():
  ctext_position_t cpos;        ///< Current ctext position
  ctree_item_t head;            ///< First ctree item on the current line (for block comments)
  ctree_item_t item;            ///< Current ctree item
  ctree_item_t tail;            ///< Tail ctree item on the current line (for indented comments)

  vdui_t(void);                 // do not create your own vdui_t objects

  /// Refresh pseudocode window.
  /// This is the highest level refresh function.
  /// It causes the most profound refresh possible and can lead to redecompilation
  /// of the current function. Please consider using refresh_ctext()
  /// if you need a more superficial refresh.
  /// \param redo_mba true means to redecompile the current function\n
  ///                 false means to rebuild ctree without regenerating microcode
  /// \sa refresh_ctext()
  void hexapi refresh_view(bool redo_mba);

  /// Refresh pseudocode window.
  /// This function refreshes the pseudocode window by regenerating its text
  /// from cfunc_t. Instead of this function use refresh_func_ctext(), which
  /// refreshes all pseudocode windows for the function.
  /// \sa refresh_view(), refresh_func_ctext()
  void hexapi refresh_ctext(bool activate=true); // deprecated

  /// Display the specified pseudocode.
  /// This function replaces the pseudocode window contents with the
  /// specified cfunc_t.
  /// \param f pointer to the function to display.
  /// \param activate should the pseudocode window get focus?
  void hexapi switch_to(cfuncptr_t f, bool activate);

  /// Is the current item a statement?
  //// \return false if the cursor is in the local variable/type declaration area\n
  ///          true if the cursor is in the statement area
  bool in_ctree(void) const { return cpos.in_ctree(cfunc->hdrlines); }

  /// Get current number.
  /// If the current item is a number, return pointer to it.
  /// \return nullptr if the current item is not a number
  /// This function returns non-null for the cases of a 'switch' statement
  /// Also, if the current item is a casted number, then this function will succeed.
  cnumber_t *hexapi get_number(void);

  /// Get current label.
  /// If there is a label under the cursor, return its number.
  /// \return -1 if there is no label under the cursor.
  /// prereq: get_current_item() has been called
  int hexapi get_current_label(void);

  /// Clear the pseudocode window.
  /// It deletes the current function and microcode.
  void hexapi clear(void);

  /// Refresh the current position.
  /// This function refreshes the \ref cpos field.
  /// \return false if failed
  /// \param idv keyboard or mouse
  bool hexapi refresh_cpos(input_device_t idv);

  /// Get current item.
  /// This function refreshes the \ref cpos, \ref item, \ref tail fields.
  /// \return false if failed
  /// \param idv keyboard or mouse
  /// \sa cfunc_t::get_line_item()
  bool hexapi get_current_item(input_device_t idv);

  /// Rename local variable.
  /// This function displays a dialog box and allows the user to rename a local variable.
  /// \return false if failed or cancelled
  /// \param v pointer to local variable
  bool hexapi ui_rename_lvar(lvar_t *v);

  /// Rename local variable.
  /// This function permanently renames a local variable.
  /// \return false if failed
  /// \param v pointer to local variable
  /// \param name new variable name
  /// \param is_user_name use true to save the new name into the database.
  ///                     use false to delete the saved name.
  /// \sa ::rename_lvar()
  bool hexapi rename_lvar(lvar_t *v, const char *name, bool is_user_name);

  /// Set type of a function call
  /// This function displays a dialog box and allows the user to change
  /// the type of a function call
  /// \return false if failed or cancelled
  /// \param e pointer to call expression
  bool hexapi ui_set_call_type(const cexpr_t *e);

  /// Set local variable type.
  /// This function displays a dialog box and allows the user to change
  /// the type of a local variable.
  /// \return false if failed or cancelled
  /// \param v pointer to local variable
  bool hexapi ui_set_lvar_type(lvar_t *v);

  /// Set local variable type.
  /// This function permanently sets a local variable type and clears
  /// NOPTR flag if it was set before by function 'set_noptr_lvar'
  /// \return false if failed
  /// \param v pointer to local variable
  /// \param type new variable type
  bool hexapi set_lvar_type(lvar_t *v, const tinfo_t &type);

  /// Inform that local variable should have a non-pointer type
  /// This function permanently sets a corresponding variable flag (NOPTR)
  /// and removes type if it was set before by function 'set_lvar_type'
  /// \return false if failed
  /// \param v pointer to local variable
  bool hexapi set_noptr_lvar(lvar_t *v);

  /// Set local variable comment.
  /// This function displays a dialog box and allows the user to edit
  /// the comment of a local variable.
  /// \return false if failed or cancelled
  /// \param v pointer to local variable
  bool hexapi ui_edit_lvar_cmt(lvar_t *v);

  /// Set local variable comment.
  /// This function permanently sets a variable comment.
  /// \return false if failed
  /// \param v pointer to local variable
  /// \param cmt new comment
  bool hexapi set_lvar_cmt(lvar_t *v, const char *cmt);

  /// Map a local variable to another.
  /// This function displays a variable list and allows the user to select mapping.
  /// \return false if failed or cancelled
  /// \param v pointer to local variable
  bool hexapi ui_map_lvar(lvar_t *v);

  /// Unmap a local variable.
  /// This function displays list of variables mapped to the specified variable
  /// and allows the user to select a variable to unmap.
  /// \return false if failed or cancelled
  /// \param v pointer to local variable
  bool hexapi ui_unmap_lvar(lvar_t *v);

  /// Map a local variable to another.
  /// This function permanently maps one lvar to another.
  /// All occurrences of the mapped variable are replaced by the new variable
  /// \return false if failed
  /// \param from the variable being mapped
  /// \param to the variable to map to. if nullptr, unmaps the variable
  bool hexapi map_lvar(lvar_t *from, lvar_t *to);

  /// Set structure field type.
  /// This function displays a dialog box and allows the user to change
  /// the type of a structure field.
  /// \return false if failed or cancelled
  /// \param sptr pointer to structure
  /// \param mptr pointer to structure member
  bool hexapi set_strmem_type(struc_t *sptr, member_t *mptr);

  /// Rename structure field.
  /// This function displays a dialog box and allows the user to rename
  /// a structure field.
  /// \return false if failed or cancelled
  /// \param sptr pointer to structure
  /// \param mptr pointer to structure member
  bool hexapi rename_strmem(struc_t *sptr, member_t *mptr);

  /// Set global item type.
  /// This function displays a dialog box and allows the user to change
  /// the type of a global item (data or function).
  /// \return false if failed or cancelled
  /// \param ea address of the global item
  bool hexapi set_global_type(ea_t ea);

  /// Rename global item.
  /// This function displays a dialog box and allows the user to rename
  /// a global item (data or function).
  /// \return false if failed or cancelled
  /// \param ea address of the global item
  bool hexapi rename_global(ea_t ea);

  /// Rename a label.
  /// This function displays a dialog box and allows the user to rename
  /// a statement label.
  /// \return false if failed or cancelled
  /// \param label label number
  bool hexapi rename_label(int label);

  /// Process the Enter key.
  /// This function jumps to the definition of the item under the cursor.
  /// If the current item is a function, it will be decompiled.
  /// If the current item is a global data, its disassemly text will be displayed.
  /// \return false if failed
  /// \param idv what cursor must be used, the keyboard or the mouse
  /// \param omflags OM_NEWWIN: new pseudocode window will open, 0: reuse the existing window
  bool hexapi jump_enter(input_device_t idv, int omflags);

  /// Jump to disassembly.
  /// This function jumps to the address in the disassembly window
  /// which corresponds to the current item. The current item is determined
  /// based on the current keyboard cursor position.
  /// \return false if failed
  bool hexapi ctree_to_disasm(void);

  /// Check if the specified line can have a comment.
  /// Due to the coordinate system for comments:
  /// (https://www.hex-rays.com/blog/coordinate-system-for-hex-rays)
  /// some function lines cannot have comments. This function checks if a
  /// comment can be attached to the specified line.
  /// \return possible comment types
  /// \param lnnum line number (0 based)
  /// \param cmttype comment types to check
  cmt_type_t hexapi calc_cmt_type(size_t lnnum, cmt_type_t cmttype) const;

  /// Edit an indented comment.
  /// This function displays a dialog box and allows the user to edit
  /// the comment for the specified ctree location.
  /// \return false if failed or cancelled
  /// \param loc comment location
  bool hexapi edit_cmt(const treeloc_t &loc);

  /// Edit a function comment.
  /// This function displays a dialog box and allows the user to edit
  /// the function comment.
  /// \return false if failed or cancelled
  bool hexapi edit_func_cmt(void);

  /// Delete all orphan comments.
  /// Delete all orphan comments and refresh the screen.
  /// \return true
  bool hexapi del_orphan_cmts(void);

  /// Change number base.
  /// This function changes the current number representation.
  /// \return false if failed
  /// \param base number radix (10 or 16)\n
  ///             0 means a character constant
  bool hexapi set_num_radix(int base);

  /// Convert number to symbolic constant.
  /// This function displays a dialog box and allows the user to select
  /// a symbolic constant to represent the number.
  /// \return false if failed or cancelled
  bool hexapi set_num_enum(void);

  /// Convert number to structure field offset.
  /// Currently not implemented.
  /// \return false if failed or cancelled
  bool hexapi set_num_stroff(void);

  /// Negate a number.
  /// This function negates the current number.
  /// \return false if failed.
  bool hexapi invert_sign(void);

  /// Bitwise negate a number.
  /// This function inverts all bits of the current number.
  /// \return false if failed.
  bool hexapi invert_bits(void);

  /// Collapse/uncollapse item.
  /// This function collapses the current item.
  /// \return false if failed.
  bool hexapi collapse_item(bool hide);

  /// Collapse/uncollapse local variable declarations.
  /// \return false if failed.
  bool hexapi collapse_lvars(bool hide);

  /// Split/unsplit item.
  /// This function splits the current assignment expression.
  /// \return false if failed.
  bool hexapi split_item(bool split);

};

//---------------------------------------------------------------------------
/// Select UDT for the operands using "Select offsets" widget

/// Operand represention
struct ui_stroff_op_t
{
  qstring text;   ///< any text for the column "Operand" of widget
  uval_t offset;  ///< operand offset, will be used when calculating the UDT path
  bool operator==(const ui_stroff_op_t &r) const
  {
    return text == r.text && offset == r.offset;
  }
  bool operator!=(const ui_stroff_op_t &r) const { return !(*this == r); }
};
DECLARE_TYPE_AS_MOVABLE(ui_stroff_op_t);
typedef qvector<ui_stroff_op_t> ui_stroff_ops_t;

/// Callback to apply the selection
/// \return success
struct ui_stroff_applicator_t
{
  /// \param opnum   operand ordinal number, see below
  /// \param path    path describing the union selection, maybe empty
  /// \param top_tif tinfo_t of the selected toplevel UDT
  /// \param spath   selected path
  virtual bool idaapi apply(size_t opnum, const intvec_t &path, const tinfo_t &top_tif, const char *spath) = 0;
};

/// Select UDT
/// \param udts list of UDT tinfo_t for the selection,
///             if nullptr or empty then UDTs from the "Local types" will be used
/// \param ops  operands
/// \param applicator callback will be called to apply the selection for every operand
int hexapi select_udt_by_offset(
        const qvector<tinfo_t> *udts,
        const ui_stroff_ops_t &ops,
        ui_stroff_applicator_t &applicator);




//--------------------------------------------------------------------------
// PUBLIC HEX-RAYS API
//--------------------------------------------------------------------------

/// Hex-Rays decompiler dispatcher.
/// All interaction with the decompiler is carried out by the intermediary of this dispatcher.
typedef void *hexdsp_t(int code, ...);

#ifndef SWIG
//==========================================================================
//       PLEASE REMOVE 'hexdsp' VARIABLE, IT IS OUT OF USE NOW
//==========================================================================
extern int hexdsp;
#endif

/// API call numbers
enum hexcall_t
{
  hx_user_numforms_begin,
  hx_user_numforms_end,
  hx_user_numforms_next,
  hx_user_numforms_prev,
  hx_user_numforms_first,
  hx_user_numforms_second,
  hx_user_numforms_find,
  hx_user_numforms_insert,
  hx_user_numforms_erase,
  hx_user_numforms_clear,
  hx_user_numforms_size,
  hx_user_numforms_free,
  hx_user_numforms_new,
  hx_lvar_mapping_begin,
  hx_lvar_mapping_end,
  hx_lvar_mapping_next,
  hx_lvar_mapping_prev,
  hx_lvar_mapping_first,
  hx_lvar_mapping_second,
  hx_lvar_mapping_find,
  hx_lvar_mapping_insert,
  hx_lvar_mapping_erase,
  hx_lvar_mapping_clear,
  hx_lvar_mapping_size,
  hx_lvar_mapping_free,
  hx_lvar_mapping_new,
  hx_udcall_map_begin,
  hx_udcall_map_end,
  hx_udcall_map_next,
  hx_udcall_map_prev,
  hx_udcall_map_first,
  hx_udcall_map_second,
  hx_udcall_map_find,
  hx_udcall_map_insert,
  hx_udcall_map_erase,
  hx_udcall_map_clear,
  hx_udcall_map_size,
  hx_udcall_map_free,
  hx_udcall_map_new,
  hx_user_cmts_begin,
  hx_user_cmts_end,
  hx_user_cmts_next,
  hx_user_cmts_prev,
  hx_user_cmts_first,
  hx_user_cmts_second,
  hx_user_cmts_find,
  hx_user_cmts_insert,
  hx_user_cmts_erase,
  hx_user_cmts_clear,
  hx_user_cmts_size,
  hx_user_cmts_free,
  hx_user_cmts_new,
  hx_user_iflags_begin,
  hx_user_iflags_end,
  hx_user_iflags_next,
  hx_user_iflags_prev,
  hx_user_iflags_first,
  hx_user_iflags_second,
  hx_user_iflags_find,
  hx_user_iflags_insert,
  hx_user_iflags_erase,
  hx_user_iflags_clear,
  hx_user_iflags_size,
  hx_user_iflags_free,
  hx_user_iflags_new,
  hx_user_unions_begin,
  hx_user_unions_end,
  hx_user_unions_next,
  hx_user_unions_prev,
  hx_user_unions_first,
  hx_user_unions_second,
  hx_user_unions_find,
  hx_user_unions_insert,
  hx_user_unions_erase,
  hx_user_unions_clear,
  hx_user_unions_size,
  hx_user_unions_free,
  hx_user_unions_new,
  hx_user_labels_begin,
  hx_user_labels_end,
  hx_user_labels_next,
  hx_user_labels_prev,
  hx_user_labels_first,
  hx_user_labels_second,
  hx_user_labels_find,
  hx_user_labels_insert,
  hx_user_labels_erase,
  hx_user_labels_clear,
  hx_user_labels_size,
  hx_user_labels_free,
  hx_user_labels_new,
  hx_eamap_begin,
  hx_eamap_end,
  hx_eamap_next,
  hx_eamap_prev,
  hx_eamap_first,
  hx_eamap_second,
  hx_eamap_find,
  hx_eamap_insert,
  hx_eamap_erase,
  hx_eamap_clear,
  hx_eamap_size,
  hx_eamap_free,
  hx_eamap_new,
  hx_boundaries_begin,
  hx_boundaries_end,
  hx_boundaries_next,
  hx_boundaries_prev,
  hx_boundaries_first,
  hx_boundaries_second,
  hx_boundaries_find,
  hx_boundaries_insert,
  hx_boundaries_erase,
  hx_boundaries_clear,
  hx_boundaries_size,
  hx_boundaries_free,
  hx_boundaries_new,
  hx_block_chains_begin,
  hx_block_chains_end,
  hx_block_chains_next,
  hx_block_chains_prev,
  hx_block_chains_get,
  hx_block_chains_find,
  hx_block_chains_insert,
  hx_block_chains_erase,
  hx_block_chains_clear,
  hx_block_chains_size,
  hx_block_chains_free,
  hx_block_chains_new,
  hx_valrng_t_clear,
  hx_valrng_t_copy,
  hx_valrng_t_assign,
  hx_valrng_t_compare,
  hx_valrng_t_set_eq,
  hx_valrng_t_set_cmp,
  hx_valrng_t_reduce_size,
  hx_valrng_t_intersect_with,
  hx_valrng_t_unite_with,
  hx_valrng_t_inverse,
  hx_valrng_t_has,
  hx_valrng_t_print,
  hx_valrng_t_dstr,
  hx_valrng_t_cvt_to_single_value,
  hx_valrng_t_cvt_to_cmp,
  hx_get_merror_desc,
  hx_reg2mreg,
  hx_mreg2reg,
  hx_install_optinsn_handler,
  hx_remove_optinsn_handler,
  hx_install_optblock_handler,
  hx_remove_optblock_handler,
  hx_must_mcode_close_block,
  hx_is_mcode_propagatable,
  hx_negate_mcode_relation,
  hx_swap_mcode_relation,
  hx_get_signed_mcode,
  hx_get_unsigned_mcode,
  hx_mcode_modifies_d,
  hx_operand_locator_t_compare,
  hx_vd_printer_t_print,
  hx_file_printer_t_print,
  hx_qstring_printer_t_print,
  hx_dstr,
  hx_is_type_correct,
  hx_is_small_udt,
  hx_is_nonbool_type,
  hx_is_bool_type,
  hx_partial_type_num,
  hx_get_float_type,
  hx_get_int_type_by_width_and_sign,
  hx_get_unk_type,
  hx_dummy_ptrtype,
  hx_get_member_type,
  hx_make_pointer,
  hx_create_typedef,
  hx_get_type,
  hx_set_type,
  hx_vdloc_t_dstr,
  hx_vdloc_t_compare,
  hx_vdloc_t_is_aliasable,
  hx_print_vdloc,
  hx_arglocs_overlap,
  hx_lvar_locator_t_compare,
  hx_lvar_locator_t_dstr,
  hx_lvar_t_dstr,
  hx_lvar_t_is_promoted_arg,
  hx_lvar_t_accepts_type,
  hx_lvar_t_set_lvar_type,
  hx_lvar_t_set_width,
  hx_lvar_t_append_list_,
  hx_lvars_t_find_stkvar,
  hx_lvars_t_find,
  hx_lvars_t_find_lvar,
  hx_restore_user_lvar_settings,
  hx_save_user_lvar_settings,
  hx_modify_user_lvars,
  hx_restore_user_defined_calls,
  hx_save_user_defined_calls,
  hx_parse_user_call,
  hx_convert_to_user_call,
  hx_install_microcode_filter,
  hx_udc_filter_t_init,
  hx_udc_filter_t_apply,
  hx_bitset_t_bitset_t,
  hx_bitset_t_copy,
  hx_bitset_t_add,
  hx_bitset_t_add_,
  hx_bitset_t_add__,
  hx_bitset_t_sub,
  hx_bitset_t_sub_,
  hx_bitset_t_sub__,
  hx_bitset_t_cut_at,
  hx_bitset_t_shift_down,
  hx_bitset_t_has,
  hx_bitset_t_has_all,
  hx_bitset_t_has_any,
  hx_bitset_t_dstr,
  hx_bitset_t_empty,
  hx_bitset_t_count,
  hx_bitset_t_count_,
  hx_bitset_t_last,
  hx_bitset_t_fill_with_ones,
  hx_bitset_t_has_common,
  hx_bitset_t_intersect,
  hx_bitset_t_is_subset_of,
  hx_bitset_t_compare,
  hx_bitset_t_goup,
  hx_ivl_t_dstr,
  hx_ivl_t_compare,
  hx_ivlset_t_add,
  hx_ivlset_t_add_,
  hx_ivlset_t_addmasked,
  hx_ivlset_t_sub,
  hx_ivlset_t_sub_,
  hx_ivlset_t_has_common,
  hx_ivlset_t_print,
  hx_ivlset_t_dstr,
  hx_ivlset_t_count,
  hx_ivlset_t_has_common_,
  hx_ivlset_t_contains,
  hx_ivlset_t_includes,
  hx_ivlset_t_intersect,
  hx_ivlset_t_compare,
  hx_get_mreg_name,
  hx_rlist_t_print,
  hx_rlist_t_dstr,
  hx_mlist_t_addmem,
  hx_mlist_t_print,
  hx_mlist_t_dstr,
  hx_mlist_t_compare,
  hx_lvar_ref_t_compare,
  hx_lvar_ref_t_var,
  hx_stkvar_ref_t_compare,
  hx_stkvar_ref_t_get_stkvar,
  hx_fnumber_t_print,
  hx_fnumber_t_dstr,
  hx_mop_t_copy,
  hx_mop_t_assign,
  hx_mop_t_swap,
  hx_mop_t_erase,
  hx_mop_t_print,
  hx_mop_t_dstr,
  hx_mop_t_create_from_mlist,
  hx_mop_t_create_from_ivlset,
  hx_mop_t_create_from_vdloc,
  hx_mop_t_create_from_scattered_vdloc,
  hx_mop_t_create_from_insn,
  hx_mop_t_make_number,
  hx_mop_t_make_fpnum,
  hx_mop_t_make_reg_pair,
  hx_mop_t_make_helper,
  hx_mop_t_is_bit_reg,
  hx_mop_t_may_use_aliased_memory,
  hx_mop_t_is01,
  hx_mop_t_is_sign_extended_from,
  hx_mop_t_is_zero_extended_from,
  hx_mop_t_equal_mops,
  hx_mop_t_lexcompare,
  hx_mop_t_for_all_ops,
  hx_mop_t_for_all_scattered_submops,
  hx_mop_t_is_constant,
  hx_mop_t_get_stkoff,
  hx_mop_t_make_low_half,
  hx_mop_t_make_high_half,
  hx_mop_t_make_first_half,
  hx_mop_t_make_second_half,
  hx_mop_t_shift_mop,
  hx_mop_t_change_size,
  hx_mop_t_preserve_side_effects,
  hx_mop_t_apply_ld_mcode,
  hx_mcallarg_t_print,
  hx_mcallarg_t_dstr,
  hx_mcallarg_t_set_regarg,
  hx_mcallinfo_t_lexcompare,
  hx_mcallinfo_t_set_type,
  hx_mcallinfo_t_get_type,
  hx_mcallinfo_t_print,
  hx_mcallinfo_t_dstr,
  hx_mcases_t_compare,
  hx_mcases_t_print,
  hx_mcases_t_dstr,
  hx_vivl_t_extend_to_cover,
  hx_vivl_t_intersect,
  hx_vivl_t_print,
  hx_vivl_t_dstr,
  hx_chain_t_print,
  hx_chain_t_dstr,
  hx_chain_t_append_list_,
  hx_block_chains_t_get_chain,
  hx_block_chains_t_print,
  hx_block_chains_t_dstr,
  hx_graph_chains_t_for_all_chains,
  hx_graph_chains_t_release,
  hx_minsn_t_init,
  hx_minsn_t_copy,
  hx_minsn_t_swap,
  hx_minsn_t_print,
  hx_minsn_t_dstr,
  hx_minsn_t_setaddr,
  hx_minsn_t_optimize_subtree,
  hx_minsn_t_for_all_ops,
  hx_minsn_t_for_all_insns,
  hx_minsn_t__make_nop,
  hx_minsn_t_equal_insns,
  hx_minsn_t_lexcompare,
  hx_minsn_t_is_noret_call,
  hx_minsn_t_is_helper,
  hx_minsn_t_find_call,
  hx_minsn_t_has_side_effects,
  hx_minsn_t_find_opcode,
  hx_minsn_t_find_ins_op,
  hx_minsn_t_find_num_op,
  hx_minsn_t_modifies_d,
  hx_minsn_t_is_between,
  hx_minsn_t_may_use_aliased_memory,
  hx_getf_reginsn,
  hx_getb_reginsn,
  hx_mblock_t_init,
  hx_mblock_t_print,
  hx_mblock_t_dump,
  hx_mblock_t_vdump_block,
  hx_mblock_t_insert_into_block,
  hx_mblock_t_remove_from_block,
  hx_mblock_t_for_all_insns,
  hx_mblock_t_for_all_ops,
  hx_mblock_t_for_all_uses,
  hx_mblock_t_optimize_insn,
  hx_mblock_t_optimize_block,
  hx_mblock_t_build_lists,
  hx_mblock_t_append_use_list,
  hx_mblock_t_append_def_list,
  hx_mblock_t_build_use_list,
  hx_mblock_t_build_def_list,
  hx_mblock_t_find_first_use,
  hx_mblock_t_find_redefinition,
  hx_mblock_t_is_rhs_redefined,
  hx_mblock_t_find_access,
  hx_mblock_t_get_valranges,
  hx_mba_t_idaloc2vd,
  hx_mba_t_vd2idaloc,
  hx_mba_t_term,
  hx_mba_t_optimize_local,
  hx_mba_t_build_graph,
  hx_mba_t_get_graph,
  hx_mba_t_analyze_calls,
  hx_mba_t_optimize_global,
  hx_mba_t_alloc_lvars,
  hx_mba_t_dump,
  hx_mba_t_vdump_mba,
  hx_mba_t_print,
  hx_mba_t_verify,
  hx_mba_t_mark_chains_dirty,
  hx_mba_t_insert_block,
  hx_mba_t_remove_block,
  hx_mba_t_remove_empty_and_unreachable_blocks,
  hx_mba_t_combine_blocks,
  hx_mba_t_for_all_ops,
  hx_mba_t_for_all_insns,
  hx_mba_t_for_all_topinsns,
  hx_mba_t_find_mop,
  hx_mba_t_arg,
  hx_mba_t_serialize,
  hx_mba_t_deserialize,
  hx_mbl_graph_t_is_accessed_globally,
  hx_mbl_graph_t_get_ud,
  hx_mbl_graph_t_get_du,
  hx_codegen_t_emit,
  hx_codegen_t_emit_,
  hx_is_kreg,
  hx_get_temp_regs,
  hx_get_hexrays_version,
  hx_open_pseudocode,
  hx_close_pseudocode,
  hx_get_widget_vdui,
  hx_decompile_many,
  hx_hexrays_failure_t_desc,
  hx_send_database,
  hx_gco_info_t_append_to_list,
  hx_get_current_operand,
  hx_remitem,
  hx_negated_relation,
  hx_swapped_relation,
  hx_get_op_signness,
  hx_asgop,
  hx_asgop_revert,
  hx_cnumber_t_print,
  hx_cnumber_t_value,
  hx_cnumber_t_assign,
  hx_cnumber_t_compare,
  hx_var_ref_t_compare,
  hx_ctree_visitor_t_apply_to,
  hx_ctree_visitor_t_apply_to_exprs,
  hx_ctree_parentee_t_recalc_parent_types,
  hx_cfunc_parentee_t_calc_rvalue_type,
  hx_citem_locator_t_compare,
  hx_citem_t_contains_expr,
  hx_citem_t_contains_label,
  hx_citem_t_find_parent_of,
  hx_citem_t_find_closest_addr,
  hx_cexpr_t_assign,
  hx_cexpr_t_compare,
  hx_cexpr_t_replace_by,
  hx_cexpr_t_cleanup,
  hx_cexpr_t_put_number,
  hx_cexpr_t_print1,
  hx_cexpr_t_calc_type,
  hx_cexpr_t_equal_effect,
  hx_cexpr_t_is_child_of,
  hx_cexpr_t_contains_operator,
  hx_cexpr_t_get_high_nbit_bound,
  hx_cexpr_t_get_low_nbit_bound,
  hx_cexpr_t_requires_lvalue,
  hx_cexpr_t_has_side_effects,
  hx_cif_t_assign,
  hx_cif_t_compare,
  hx_cloop_t_assign,
  hx_cfor_t_compare,
  hx_cwhile_t_compare,
  hx_cdo_t_compare,
  hx_creturn_t_compare,
  hx_cgoto_t_compare,
  hx_casm_t_compare,
  hx_cinsn_t_assign,
  hx_cinsn_t_compare,
  hx_cinsn_t_replace_by,
  hx_cinsn_t_cleanup,
  hx_cinsn_t_new_insn,
  hx_cinsn_t_create_if,
  hx_cinsn_t_print,
  hx_cinsn_t_print1,
  hx_cinsn_t_is_ordinary_flow,
  hx_cinsn_t_contains_insn,
  hx_cinsn_t_collect_free_breaks,
  hx_cinsn_t_collect_free_continues,
  hx_cblock_t_compare,
  hx_carglist_t_compare,
  hx_ccase_t_compare,
  hx_ccases_t_compare,
  hx_cswitch_t_compare,
  hx_ctree_item_t_get_memptr,
  hx_ctree_item_t_get_lvar,
  hx_ctree_item_t_get_ea,
  hx_ctree_item_t_get_label_num,
  hx_lnot,
  hx_new_block,
  hx_vcreate_helper,
  hx_vcall_helper,
  hx_make_num,
  hx_make_ref,
  hx_dereference,
  hx_save_user_labels,
  hx_save_user_cmts,
  hx_save_user_numforms,
  hx_save_user_iflags,
  hx_save_user_unions,
  hx_restore_user_labels,
  hx_restore_user_cmts,
  hx_restore_user_numforms,
  hx_restore_user_iflags,
  hx_restore_user_unions,
  hx_cfunc_t_build_c_tree,
  hx_cfunc_t_verify,
  hx_cfunc_t_print_dcl,
  hx_cfunc_t_print_func,
  hx_cfunc_t_get_func_type,
  hx_cfunc_t_get_lvars,
  hx_cfunc_t_get_stkoff_delta,
  hx_cfunc_t_find_label,
  hx_cfunc_t_remove_unused_labels,
  hx_cfunc_t_get_user_cmt,
  hx_cfunc_t_set_user_cmt,
  hx_cfunc_t_get_user_iflags,
  hx_cfunc_t_set_user_iflags,
  hx_cfunc_t_has_orphan_cmts,
  hx_cfunc_t_del_orphan_cmts,
  hx_cfunc_t_get_user_union_selection,
  hx_cfunc_t_set_user_union_selection,
  hx_cfunc_t_get_line_item,
  hx_cfunc_t_get_warnings,
  hx_cfunc_t_get_eamap,
  hx_cfunc_t_get_boundaries,
  hx_cfunc_t_get_pseudocode,
  hx_cfunc_t_gather_derefs,
  hx_cfunc_t_find_item_coords,
  hx_cfunc_t_cleanup,
  hx_decompile,
  hx_gen_microcode,
  hx_mark_cfunc_dirty,
  hx_clear_cached_cfuncs,
  hx_has_cached_cfunc,
  hx_get_ctype_name,
  hx_create_field_name,
  hx_install_hexrays_callback,
  hx_remove_hexrays_callback,
  hx_vdui_t_set_locked,
  hx_vdui_t_refresh_view,
  hx_vdui_t_refresh_ctext,
  hx_vdui_t_switch_to,
  hx_vdui_t_get_number,
  hx_vdui_t_get_current_label,
  hx_vdui_t_clear,
  hx_vdui_t_refresh_cpos,
  hx_vdui_t_get_current_item,
  hx_vdui_t_ui_rename_lvar,
  hx_vdui_t_rename_lvar,
  hx_vdui_t_ui_set_call_type,
  hx_vdui_t_ui_set_lvar_type,
  hx_vdui_t_set_lvar_type,
  hx_vdui_t_ui_edit_lvar_cmt,
  hx_vdui_t_set_lvar_cmt,
  hx_vdui_t_ui_map_lvar,
  hx_vdui_t_ui_unmap_lvar,
  hx_vdui_t_map_lvar,
  hx_vdui_t_set_strmem_type,
  hx_vdui_t_rename_strmem,
  hx_vdui_t_set_global_type,
  hx_vdui_t_rename_global,
  hx_vdui_t_rename_label,
  hx_vdui_t_jump_enter,
  hx_vdui_t_ctree_to_disasm,
  hx_vdui_t_calc_cmt_type,
  hx_vdui_t_edit_cmt,
  hx_vdui_t_edit_func_cmt,
  hx_vdui_t_del_orphan_cmts,
  hx_vdui_t_set_num_radix,
  hx_vdui_t_set_num_enum,
  hx_vdui_t_set_num_stroff,
  hx_vdui_t_invert_sign,
  hx_vdui_t_invert_bits,
  hx_vdui_t_collapse_item,
  hx_vdui_t_collapse_lvars,
  hx_vdui_t_split_item,
  hx_hexrays_alloc,
  hx_hexrays_free,
  hx_vdui_t_set_noptr_lvar,
  hx_select_udt_by_offset,
  hx_mblock_t_get_valranges_,
  hx_cfunc_t_refresh_func_ctext,
  hx_checkout_hexrays_license,
  hx_mba_t_copy_block,
  hx_mblock_t_optimize_useless_jump,
  hx_mblock_t_get_reginsn_qty,
  hx_modify_user_lvar_info,
  hx_cdg_insn_iterator_t_next,
  hx_restore_user_labels2,
  hx_save_user_labels2,
  hx_mba_ranges_t_range_contains,
  hx_close_hexrays_waitbox,
  hx_mba_t_map_fict_ea,
  hx_mba_t_alloc_fict_ea,
  hx_mba_t_alloc_kreg,
  hx_mba_t_free_kreg,
  hx_mba_t_idaloc2vd_,
  hx_mba_t_vd2idaloc_,
  hx_bitset_t_fill_gaps,
  hx_cfunc_t_save_user_labels,
  hx_cfunc_t_save_user_cmts,
  hx_cfunc_t_save_user_numforms,
  hx_cfunc_t_save_user_iflags,
  hx_cfunc_t_save_user_unions,
  hx_minsn_t_set_combined,
  hx_mba_t_save_snapshot,
  hx_create_cfunc,
  hx_mba_t_set_maturity,
  hx_rename_lvar,
  hx_locate_lvar,
  hx_mba_t_create_helper_call,
  hx_lvar_t_append_list,
  hx_chain_t_append_list,
  hx_udc_filter_t_cleanup,
  hx_mba_t_get_curfunc,
  hx_mop_t__make_gvar,
  hx_mop_t_make_gvar,
  hx_cexpr_t_maybe_ptr,
  hx_minsn_t_serialize,
  hx_minsn_t_deserialize,
  hx_mba_t_stkoff_vd2ida,
  hx_mba_t_stkoff_ida2vd,
  hx_cexpr_t_dstr,
  hx_cinsn_t_dstr,
  hx_ctree_item_t_print,
  hx_ctree_item_t_dstr,
  hx_mba_t_set_lvar_name,
  hx_change_hexrays_config,
  hx_mba_t_get_func_output_lists,
};

typedef size_t iterator_word;

//--------------------------------------------------------------------------
/// Check that your plugin is compatible with hex-rays decompiler.
/// This function must be called before calling any other decompiler function.
/// \param flags reserved, must be 0
/// \return true if the decompiler exists and is compatible with your plugin
inline bool init_hexrays_plugin(int flags=0)
{
  hexdsp_t *dummy;
  return callui(ui_broadcast, HEXRAYS_API_MAGIC, &dummy, flags).i == (HEXRAYS_API_MAGIC >> 32);
}

//--------------------------------------------------------------------------
/// Stop working with hex-rays decompiler.
inline void term_hexrays_plugin()
{
}


//-------------------------------------------------------------------------
struct user_numforms_iterator_t
{
  iterator_word x;
  bool operator==(const user_numforms_iterator_t &p) const { return x == p.x; }
  bool operator!=(const user_numforms_iterator_t &p) const { return x != p.x; }
};

//-------------------------------------------------------------------------
/// Get reference to the current map key
inline operand_locator_t const &user_numforms_first(user_numforms_iterator_t p)
{
  return *(operand_locator_t *)HEXDSP(hx_user_numforms_first, &p);
}

//-------------------------------------------------------------------------
/// Get reference to the current map value
inline number_format_t &user_numforms_second(user_numforms_iterator_t p)
{
  return *(number_format_t *)HEXDSP(hx_user_numforms_second, &p);
}

//-------------------------------------------------------------------------
/// Find the specified key in user_numforms_t
inline user_numforms_iterator_t user_numforms_find(const user_numforms_t *map, const operand_locator_t &key)
{
  user_numforms_iterator_t p;
  HEXDSP(hx_user_numforms_find, &p, map, &key);
  return p;
}

//-------------------------------------------------------------------------
/// Insert new (operand_locator_t, number_format_t) pair into user_numforms_t
inline user_numforms_iterator_t user_numforms_insert(user_numforms_t *map, const operand_locator_t &key, const number_format_t &val)
{
  user_numforms_iterator_t p;
  HEXDSP(hx_user_numforms_insert, &p, map, &key, &val);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the beginning of user_numforms_t
inline user_numforms_iterator_t user_numforms_begin(const user_numforms_t *map)
{
  user_numforms_iterator_t p;
  HEXDSP(hx_user_numforms_begin, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the end of user_numforms_t
inline user_numforms_iterator_t user_numforms_end(const user_numforms_t *map)
{
  user_numforms_iterator_t p;
  HEXDSP(hx_user_numforms_end, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the next element
inline user_numforms_iterator_t user_numforms_next(user_numforms_iterator_t p)
{
  HEXDSP(hx_user_numforms_next, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the previous element
inline user_numforms_iterator_t user_numforms_prev(user_numforms_iterator_t p)
{
  HEXDSP(hx_user_numforms_prev, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Erase current element from user_numforms_t
inline void user_numforms_erase(user_numforms_t *map, user_numforms_iterator_t p)
{
  HEXDSP(hx_user_numforms_erase, map, &p);
}

//-------------------------------------------------------------------------
/// Clear user_numforms_t
inline void user_numforms_clear(user_numforms_t *map)
{
  HEXDSP(hx_user_numforms_clear, map);
}

//-------------------------------------------------------------------------
/// Get size of user_numforms_t
inline size_t user_numforms_size(user_numforms_t *map)
{
  return (size_t)HEXDSP(hx_user_numforms_size, map);
}

//-------------------------------------------------------------------------
/// Delete user_numforms_t instance
inline void user_numforms_free(user_numforms_t *map)
{
  HEXDSP(hx_user_numforms_free, map);
}

//-------------------------------------------------------------------------
/// Create a new user_numforms_t instance
inline user_numforms_t *user_numforms_new()
{
  return (user_numforms_t *)HEXDSP(hx_user_numforms_new);
}

//-------------------------------------------------------------------------
struct lvar_mapping_iterator_t
{
  iterator_word x;
  bool operator==(const lvar_mapping_iterator_t &p) const { return x == p.x; }
  bool operator!=(const lvar_mapping_iterator_t &p) const { return x != p.x; }
};

//-------------------------------------------------------------------------
/// Get reference to the current map key
inline lvar_locator_t const &lvar_mapping_first(lvar_mapping_iterator_t p)
{
  return *(lvar_locator_t *)HEXDSP(hx_lvar_mapping_first, &p);
}

//-------------------------------------------------------------------------
/// Get reference to the current map value
inline lvar_locator_t &lvar_mapping_second(lvar_mapping_iterator_t p)
{
  return *(lvar_locator_t *)HEXDSP(hx_lvar_mapping_second, &p);
}

//-------------------------------------------------------------------------
/// Find the specified key in lvar_mapping_t
inline lvar_mapping_iterator_t lvar_mapping_find(const lvar_mapping_t *map, const lvar_locator_t &key)
{
  lvar_mapping_iterator_t p;
  HEXDSP(hx_lvar_mapping_find, &p, map, &key);
  return p;
}

//-------------------------------------------------------------------------
/// Insert new (lvar_locator_t, lvar_locator_t) pair into lvar_mapping_t
inline lvar_mapping_iterator_t lvar_mapping_insert(lvar_mapping_t *map, const lvar_locator_t &key, const lvar_locator_t &val)
{
  lvar_mapping_iterator_t p;
  HEXDSP(hx_lvar_mapping_insert, &p, map, &key, &val);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the beginning of lvar_mapping_t
inline lvar_mapping_iterator_t lvar_mapping_begin(const lvar_mapping_t *map)
{
  lvar_mapping_iterator_t p;
  HEXDSP(hx_lvar_mapping_begin, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the end of lvar_mapping_t
inline lvar_mapping_iterator_t lvar_mapping_end(const lvar_mapping_t *map)
{
  lvar_mapping_iterator_t p;
  HEXDSP(hx_lvar_mapping_end, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the next element
inline lvar_mapping_iterator_t lvar_mapping_next(lvar_mapping_iterator_t p)
{
  HEXDSP(hx_lvar_mapping_next, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the previous element
inline lvar_mapping_iterator_t lvar_mapping_prev(lvar_mapping_iterator_t p)
{
  HEXDSP(hx_lvar_mapping_prev, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Erase current element from lvar_mapping_t
inline void lvar_mapping_erase(lvar_mapping_t *map, lvar_mapping_iterator_t p)
{
  HEXDSP(hx_lvar_mapping_erase, map, &p);
}

//-------------------------------------------------------------------------
/// Clear lvar_mapping_t
inline void lvar_mapping_clear(lvar_mapping_t *map)
{
  HEXDSP(hx_lvar_mapping_clear, map);
}

//-------------------------------------------------------------------------
/// Get size of lvar_mapping_t
inline size_t lvar_mapping_size(lvar_mapping_t *map)
{
  return (size_t)HEXDSP(hx_lvar_mapping_size, map);
}

//-------------------------------------------------------------------------
/// Delete lvar_mapping_t instance
inline void lvar_mapping_free(lvar_mapping_t *map)
{
  HEXDSP(hx_lvar_mapping_free, map);
}

//-------------------------------------------------------------------------
/// Create a new lvar_mapping_t instance
inline lvar_mapping_t *lvar_mapping_new()
{
  return (lvar_mapping_t *)HEXDSP(hx_lvar_mapping_new);
}

//-------------------------------------------------------------------------
struct udcall_map_iterator_t
{
  iterator_word x;
  bool operator==(const udcall_map_iterator_t &p) const { return x == p.x; }
  bool operator!=(const udcall_map_iterator_t &p) const { return x != p.x; }
};

//-------------------------------------------------------------------------
/// Get reference to the current map key
inline ea_t const &udcall_map_first(udcall_map_iterator_t p)
{
  return *(ea_t *)HEXDSP(hx_udcall_map_first, &p);
}

//-------------------------------------------------------------------------
/// Get reference to the current map value
inline udcall_t &udcall_map_second(udcall_map_iterator_t p)
{
  return *(udcall_t *)HEXDSP(hx_udcall_map_second, &p);
}

//-------------------------------------------------------------------------
/// Find the specified key in udcall_map_t
inline udcall_map_iterator_t udcall_map_find(const udcall_map_t *map, const ea_t &key)
{
  udcall_map_iterator_t p;
  HEXDSP(hx_udcall_map_find, &p, map, &key);
  return p;
}

//-------------------------------------------------------------------------
/// Insert new (ea_t, udcall_t) pair into udcall_map_t
inline udcall_map_iterator_t udcall_map_insert(udcall_map_t *map, const ea_t &key, const udcall_t &val)
{
  udcall_map_iterator_t p;
  HEXDSP(hx_udcall_map_insert, &p, map, &key, &val);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the beginning of udcall_map_t
inline udcall_map_iterator_t udcall_map_begin(const udcall_map_t *map)
{
  udcall_map_iterator_t p;
  HEXDSP(hx_udcall_map_begin, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the end of udcall_map_t
inline udcall_map_iterator_t udcall_map_end(const udcall_map_t *map)
{
  udcall_map_iterator_t p;
  HEXDSP(hx_udcall_map_end, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the next element
inline udcall_map_iterator_t udcall_map_next(udcall_map_iterator_t p)
{
  HEXDSP(hx_udcall_map_next, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the previous element
inline udcall_map_iterator_t udcall_map_prev(udcall_map_iterator_t p)
{
  HEXDSP(hx_udcall_map_prev, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Erase current element from udcall_map_t
inline void udcall_map_erase(udcall_map_t *map, udcall_map_iterator_t p)
{
  HEXDSP(hx_udcall_map_erase, map, &p);
}

//-------------------------------------------------------------------------
/// Clear udcall_map_t
inline void udcall_map_clear(udcall_map_t *map)
{
  HEXDSP(hx_udcall_map_clear, map);
}

//-------------------------------------------------------------------------
/// Get size of udcall_map_t
inline size_t udcall_map_size(udcall_map_t *map)
{
  return (size_t)HEXDSP(hx_udcall_map_size, map);
}

//-------------------------------------------------------------------------
/// Delete udcall_map_t instance
inline void udcall_map_free(udcall_map_t *map)
{
  HEXDSP(hx_udcall_map_free, map);
}

//-------------------------------------------------------------------------
/// Create a new udcall_map_t instance
inline udcall_map_t *udcall_map_new()
{
  return (udcall_map_t *)HEXDSP(hx_udcall_map_new);
}

//-------------------------------------------------------------------------
struct user_cmts_iterator_t
{
  iterator_word x;
  bool operator==(const user_cmts_iterator_t &p) const { return x == p.x; }
  bool operator!=(const user_cmts_iterator_t &p) const { return x != p.x; }
};

//-------------------------------------------------------------------------
/// Get reference to the current map key
inline treeloc_t const &user_cmts_first(user_cmts_iterator_t p)
{
  return *(treeloc_t *)HEXDSP(hx_user_cmts_first, &p);
}

//-------------------------------------------------------------------------
/// Get reference to the current map value
inline citem_cmt_t &user_cmts_second(user_cmts_iterator_t p)
{
  return *(citem_cmt_t *)HEXDSP(hx_user_cmts_second, &p);
}

//-------------------------------------------------------------------------
/// Find the specified key in user_cmts_t
inline user_cmts_iterator_t user_cmts_find(const user_cmts_t *map, const treeloc_t &key)
{
  user_cmts_iterator_t p;
  HEXDSP(hx_user_cmts_find, &p, map, &key);
  return p;
}

//-------------------------------------------------------------------------
/// Insert new (treeloc_t, citem_cmt_t) pair into user_cmts_t
inline user_cmts_iterator_t user_cmts_insert(user_cmts_t *map, const treeloc_t &key, const citem_cmt_t &val)
{
  user_cmts_iterator_t p;
  HEXDSP(hx_user_cmts_insert, &p, map, &key, &val);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the beginning of user_cmts_t
inline user_cmts_iterator_t user_cmts_begin(const user_cmts_t *map)
{
  user_cmts_iterator_t p;
  HEXDSP(hx_user_cmts_begin, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the end of user_cmts_t
inline user_cmts_iterator_t user_cmts_end(const user_cmts_t *map)
{
  user_cmts_iterator_t p;
  HEXDSP(hx_user_cmts_end, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the next element
inline user_cmts_iterator_t user_cmts_next(user_cmts_iterator_t p)
{
  HEXDSP(hx_user_cmts_next, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the previous element
inline user_cmts_iterator_t user_cmts_prev(user_cmts_iterator_t p)
{
  HEXDSP(hx_user_cmts_prev, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Erase current element from user_cmts_t
inline void user_cmts_erase(user_cmts_t *map, user_cmts_iterator_t p)
{
  HEXDSP(hx_user_cmts_erase, map, &p);
}

//-------------------------------------------------------------------------
/// Clear user_cmts_t
inline void user_cmts_clear(user_cmts_t *map)
{
  HEXDSP(hx_user_cmts_clear, map);
}

//-------------------------------------------------------------------------
/// Get size of user_cmts_t
inline size_t user_cmts_size(user_cmts_t *map)
{
  return (size_t)HEXDSP(hx_user_cmts_size, map);
}

//-------------------------------------------------------------------------
/// Delete user_cmts_t instance
inline void user_cmts_free(user_cmts_t *map)
{
  HEXDSP(hx_user_cmts_free, map);
}

//-------------------------------------------------------------------------
/// Create a new user_cmts_t instance
inline user_cmts_t *user_cmts_new()
{
  return (user_cmts_t *)HEXDSP(hx_user_cmts_new);
}

//-------------------------------------------------------------------------
struct user_iflags_iterator_t
{
  iterator_word x;
  bool operator==(const user_iflags_iterator_t &p) const { return x == p.x; }
  bool operator!=(const user_iflags_iterator_t &p) const { return x != p.x; }
};

//-------------------------------------------------------------------------
/// Get reference to the current map key
inline citem_locator_t const &user_iflags_first(user_iflags_iterator_t p)
{
  return *(citem_locator_t *)HEXDSP(hx_user_iflags_first, &p);
}

//-------------------------------------------------------------------------
/// Get reference to the current map value
inline int32 &user_iflags_second(user_iflags_iterator_t p)
{
  return *(int32 *)HEXDSP(hx_user_iflags_second, &p);
}

//-------------------------------------------------------------------------
/// Find the specified key in user_iflags_t
inline user_iflags_iterator_t user_iflags_find(const user_iflags_t *map, const citem_locator_t &key)
{
  user_iflags_iterator_t p;
  HEXDSP(hx_user_iflags_find, &p, map, &key);
  return p;
}

//-------------------------------------------------------------------------
/// Insert new (citem_locator_t, int32) pair into user_iflags_t
inline user_iflags_iterator_t user_iflags_insert(user_iflags_t *map, const citem_locator_t &key, const int32 &val)
{
  user_iflags_iterator_t p;
  HEXDSP(hx_user_iflags_insert, &p, map, &key, &val);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the beginning of user_iflags_t
inline user_iflags_iterator_t user_iflags_begin(const user_iflags_t *map)
{
  user_iflags_iterator_t p;
  HEXDSP(hx_user_iflags_begin, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the end of user_iflags_t
inline user_iflags_iterator_t user_iflags_end(const user_iflags_t *map)
{
  user_iflags_iterator_t p;
  HEXDSP(hx_user_iflags_end, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the next element
inline user_iflags_iterator_t user_iflags_next(user_iflags_iterator_t p)
{
  HEXDSP(hx_user_iflags_next, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the previous element
inline user_iflags_iterator_t user_iflags_prev(user_iflags_iterator_t p)
{
  HEXDSP(hx_user_iflags_prev, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Erase current element from user_iflags_t
inline void user_iflags_erase(user_iflags_t *map, user_iflags_iterator_t p)
{
  HEXDSP(hx_user_iflags_erase, map, &p);
}

//-------------------------------------------------------------------------
/// Clear user_iflags_t
inline void user_iflags_clear(user_iflags_t *map)
{
  HEXDSP(hx_user_iflags_clear, map);
}

//-------------------------------------------------------------------------
/// Get size of user_iflags_t
inline size_t user_iflags_size(user_iflags_t *map)
{
  return (size_t)HEXDSP(hx_user_iflags_size, map);
}

//-------------------------------------------------------------------------
/// Delete user_iflags_t instance
inline void user_iflags_free(user_iflags_t *map)
{
  HEXDSP(hx_user_iflags_free, map);
}

//-------------------------------------------------------------------------
/// Create a new user_iflags_t instance
inline user_iflags_t *user_iflags_new()
{
  return (user_iflags_t *)HEXDSP(hx_user_iflags_new);
}

//-------------------------------------------------------------------------
struct user_unions_iterator_t
{
  iterator_word x;
  bool operator==(const user_unions_iterator_t &p) const { return x == p.x; }
  bool operator!=(const user_unions_iterator_t &p) const { return x != p.x; }
};

//-------------------------------------------------------------------------
/// Get reference to the current map key
inline ea_t const &user_unions_first(user_unions_iterator_t p)
{
  return *(ea_t *)HEXDSP(hx_user_unions_first, &p);
}

//-------------------------------------------------------------------------
/// Get reference to the current map value
inline intvec_t &user_unions_second(user_unions_iterator_t p)
{
  return *(intvec_t *)HEXDSP(hx_user_unions_second, &p);
}

//-------------------------------------------------------------------------
/// Find the specified key in user_unions_t
inline user_unions_iterator_t user_unions_find(const user_unions_t *map, const ea_t &key)
{
  user_unions_iterator_t p;
  HEXDSP(hx_user_unions_find, &p, map, &key);
  return p;
}

//-------------------------------------------------------------------------
/// Insert new (ea_t, intvec_t) pair into user_unions_t
inline user_unions_iterator_t user_unions_insert(user_unions_t *map, const ea_t &key, const intvec_t &val)
{
  user_unions_iterator_t p;
  HEXDSP(hx_user_unions_insert, &p, map, &key, &val);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the beginning of user_unions_t
inline user_unions_iterator_t user_unions_begin(const user_unions_t *map)
{
  user_unions_iterator_t p;
  HEXDSP(hx_user_unions_begin, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the end of user_unions_t
inline user_unions_iterator_t user_unions_end(const user_unions_t *map)
{
  user_unions_iterator_t p;
  HEXDSP(hx_user_unions_end, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the next element
inline user_unions_iterator_t user_unions_next(user_unions_iterator_t p)
{
  HEXDSP(hx_user_unions_next, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the previous element
inline user_unions_iterator_t user_unions_prev(user_unions_iterator_t p)
{
  HEXDSP(hx_user_unions_prev, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Erase current element from user_unions_t
inline void user_unions_erase(user_unions_t *map, user_unions_iterator_t p)
{
  HEXDSP(hx_user_unions_erase, map, &p);
}

//-------------------------------------------------------------------------
/// Clear user_unions_t
inline void user_unions_clear(user_unions_t *map)
{
  HEXDSP(hx_user_unions_clear, map);
}

//-------------------------------------------------------------------------
/// Get size of user_unions_t
inline size_t user_unions_size(user_unions_t *map)
{
  return (size_t)HEXDSP(hx_user_unions_size, map);
}

//-------------------------------------------------------------------------
/// Delete user_unions_t instance
inline void user_unions_free(user_unions_t *map)
{
  HEXDSP(hx_user_unions_free, map);
}

//-------------------------------------------------------------------------
/// Create a new user_unions_t instance
inline user_unions_t *user_unions_new()
{
  return (user_unions_t *)HEXDSP(hx_user_unions_new);
}

//-------------------------------------------------------------------------
struct user_labels_iterator_t
{
  iterator_word x;
  bool operator==(const user_labels_iterator_t &p) const { return x == p.x; }
  bool operator!=(const user_labels_iterator_t &p) const { return x != p.x; }
};

//-------------------------------------------------------------------------
/// Get reference to the current map key
inline int const &user_labels_first(user_labels_iterator_t p)
{
  return *(int *)HEXDSP(hx_user_labels_first, &p);
}

//-------------------------------------------------------------------------
/// Get reference to the current map value
inline qstring &user_labels_second(user_labels_iterator_t p)
{
  return *(qstring *)HEXDSP(hx_user_labels_second, &p);
}

//-------------------------------------------------------------------------
/// Find the specified key in user_labels_t
inline user_labels_iterator_t user_labels_find(const user_labels_t *map, const int &key)
{
  user_labels_iterator_t p;
  HEXDSP(hx_user_labels_find, &p, map, &key);
  return p;
}

//-------------------------------------------------------------------------
/// Insert new (int, qstring) pair into user_labels_t
inline user_labels_iterator_t user_labels_insert(user_labels_t *map, const int &key, const qstring &val)
{
  user_labels_iterator_t p;
  HEXDSP(hx_user_labels_insert, &p, map, &key, &val);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the beginning of user_labels_t
inline user_labels_iterator_t user_labels_begin(const user_labels_t *map)
{
  user_labels_iterator_t p;
  HEXDSP(hx_user_labels_begin, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the end of user_labels_t
inline user_labels_iterator_t user_labels_end(const user_labels_t *map)
{
  user_labels_iterator_t p;
  HEXDSP(hx_user_labels_end, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the next element
inline user_labels_iterator_t user_labels_next(user_labels_iterator_t p)
{
  HEXDSP(hx_user_labels_next, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the previous element
inline user_labels_iterator_t user_labels_prev(user_labels_iterator_t p)
{
  HEXDSP(hx_user_labels_prev, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Erase current element from user_labels_t
inline void user_labels_erase(user_labels_t *map, user_labels_iterator_t p)
{
  HEXDSP(hx_user_labels_erase, map, &p);
}

//-------------------------------------------------------------------------
/// Clear user_labels_t
inline void user_labels_clear(user_labels_t *map)
{
  HEXDSP(hx_user_labels_clear, map);
}

//-------------------------------------------------------------------------
/// Get size of user_labels_t
inline size_t user_labels_size(user_labels_t *map)
{
  return (size_t)HEXDSP(hx_user_labels_size, map);
}

//-------------------------------------------------------------------------
/// Delete user_labels_t instance
inline void user_labels_free(user_labels_t *map)
{
  HEXDSP(hx_user_labels_free, map);
}

//-------------------------------------------------------------------------
/// Create a new user_labels_t instance
inline user_labels_t *user_labels_new()
{
  return (user_labels_t *)HEXDSP(hx_user_labels_new);
}

//-------------------------------------------------------------------------
struct eamap_iterator_t
{
  iterator_word x;
  bool operator==(const eamap_iterator_t &p) const { return x == p.x; }
  bool operator!=(const eamap_iterator_t &p) const { return x != p.x; }
};

//-------------------------------------------------------------------------
/// Get reference to the current map key
inline ea_t const &eamap_first(eamap_iterator_t p)
{
  return *(ea_t *)HEXDSP(hx_eamap_first, &p);
}

//-------------------------------------------------------------------------
/// Get reference to the current map value
inline cinsnptrvec_t &eamap_second(eamap_iterator_t p)
{
  return *(cinsnptrvec_t *)HEXDSP(hx_eamap_second, &p);
}

//-------------------------------------------------------------------------
/// Find the specified key in eamap_t
inline eamap_iterator_t eamap_find(const eamap_t *map, const ea_t &key)
{
  eamap_iterator_t p;
  HEXDSP(hx_eamap_find, &p, map, &key);
  return p;
}

//-------------------------------------------------------------------------
/// Insert new (ea_t, cinsnptrvec_t) pair into eamap_t
inline eamap_iterator_t eamap_insert(eamap_t *map, const ea_t &key, const cinsnptrvec_t &val)
{
  eamap_iterator_t p;
  HEXDSP(hx_eamap_insert, &p, map, &key, &val);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the beginning of eamap_t
inline eamap_iterator_t eamap_begin(const eamap_t *map)
{
  eamap_iterator_t p;
  HEXDSP(hx_eamap_begin, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the end of eamap_t
inline eamap_iterator_t eamap_end(const eamap_t *map)
{
  eamap_iterator_t p;
  HEXDSP(hx_eamap_end, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the next element
inline eamap_iterator_t eamap_next(eamap_iterator_t p)
{
  HEXDSP(hx_eamap_next, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the previous element
inline eamap_iterator_t eamap_prev(eamap_iterator_t p)
{
  HEXDSP(hx_eamap_prev, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Erase current element from eamap_t
inline void eamap_erase(eamap_t *map, eamap_iterator_t p)
{
  HEXDSP(hx_eamap_erase, map, &p);
}

//-------------------------------------------------------------------------
/// Clear eamap_t
inline void eamap_clear(eamap_t *map)
{
  HEXDSP(hx_eamap_clear, map);
}

//-------------------------------------------------------------------------
/// Get size of eamap_t
inline size_t eamap_size(eamap_t *map)
{
  return (size_t)HEXDSP(hx_eamap_size, map);
}

//-------------------------------------------------------------------------
/// Delete eamap_t instance
inline void eamap_free(eamap_t *map)
{
  HEXDSP(hx_eamap_free, map);
}

//-------------------------------------------------------------------------
/// Create a new eamap_t instance
inline eamap_t *eamap_new()
{
  return (eamap_t *)HEXDSP(hx_eamap_new);
}

//-------------------------------------------------------------------------
struct boundaries_iterator_t
{
  iterator_word x;
  bool operator==(const boundaries_iterator_t &p) const { return x == p.x; }
  bool operator!=(const boundaries_iterator_t &p) const { return x != p.x; }
};

//-------------------------------------------------------------------------
/// Get reference to the current map key
inline cinsn_t *const &boundaries_first(boundaries_iterator_t p)
{
  return *(cinsn_t * *)HEXDSP(hx_boundaries_first, &p);
}

//-------------------------------------------------------------------------
/// Get reference to the current map value
inline rangeset_t &boundaries_second(boundaries_iterator_t p)
{
  return *(rangeset_t *)HEXDSP(hx_boundaries_second, &p);
}

//-------------------------------------------------------------------------
/// Find the specified key in boundaries_t
inline boundaries_iterator_t boundaries_find(const boundaries_t *map, const cinsn_t * &key)
{
  boundaries_iterator_t p;
  HEXDSP(hx_boundaries_find, &p, map, &key);
  return p;
}

//-------------------------------------------------------------------------
/// Insert new (cinsn_t *, rangeset_t) pair into boundaries_t
inline boundaries_iterator_t boundaries_insert(boundaries_t *map, const cinsn_t * &key, const rangeset_t &val)
{
  boundaries_iterator_t p;
  HEXDSP(hx_boundaries_insert, &p, map, &key, &val);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the beginning of boundaries_t
inline boundaries_iterator_t boundaries_begin(const boundaries_t *map)
{
  boundaries_iterator_t p;
  HEXDSP(hx_boundaries_begin, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the end of boundaries_t
inline boundaries_iterator_t boundaries_end(const boundaries_t *map)
{
  boundaries_iterator_t p;
  HEXDSP(hx_boundaries_end, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the next element
inline boundaries_iterator_t boundaries_next(boundaries_iterator_t p)
{
  HEXDSP(hx_boundaries_next, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the previous element
inline boundaries_iterator_t boundaries_prev(boundaries_iterator_t p)
{
  HEXDSP(hx_boundaries_prev, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Erase current element from boundaries_t
inline void boundaries_erase(boundaries_t *map, boundaries_iterator_t p)
{
  HEXDSP(hx_boundaries_erase, map, &p);
}

//-------------------------------------------------------------------------
/// Clear boundaries_t
inline void boundaries_clear(boundaries_t *map)
{
  HEXDSP(hx_boundaries_clear, map);
}

//-------------------------------------------------------------------------
/// Get size of boundaries_t
inline size_t boundaries_size(boundaries_t *map)
{
  return (size_t)HEXDSP(hx_boundaries_size, map);
}

//-------------------------------------------------------------------------
/// Delete boundaries_t instance
inline void boundaries_free(boundaries_t *map)
{
  HEXDSP(hx_boundaries_free, map);
}

//-------------------------------------------------------------------------
/// Create a new boundaries_t instance
inline boundaries_t *boundaries_new()
{
  return (boundaries_t *)HEXDSP(hx_boundaries_new);
}

//-------------------------------------------------------------------------
struct block_chains_iterator_t
{
  iterator_word x;
  bool operator==(const block_chains_iterator_t &p) const { return x == p.x; }
  bool operator!=(const block_chains_iterator_t &p) const { return x != p.x; }
};

//-------------------------------------------------------------------------
/// Get reference to the current set value
inline chain_t &block_chains_get(block_chains_iterator_t p)
{
  return *(chain_t *)HEXDSP(hx_block_chains_get, &p);
}

//-------------------------------------------------------------------------
/// Find the specified key in set block_chains_t
inline block_chains_iterator_t block_chains_find(const block_chains_t *set, const chain_t &val)
{
  block_chains_iterator_t p;
  HEXDSP(hx_block_chains_find, &p, set, &val);
  return p;
}

//-------------------------------------------------------------------------
/// Insert new (chain_t) into set block_chains_t
inline block_chains_iterator_t block_chains_insert(block_chains_t *set, const chain_t &val)
{
  block_chains_iterator_t p;
  HEXDSP(hx_block_chains_insert, &p, set, &val);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the beginning of block_chains_t
inline block_chains_iterator_t block_chains_begin(const block_chains_t *set)
{
  block_chains_iterator_t p;
  HEXDSP(hx_block_chains_begin, &p, set);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the end of block_chains_t
inline block_chains_iterator_t block_chains_end(const block_chains_t *set)
{
  block_chains_iterator_t p;
  HEXDSP(hx_block_chains_end, &p, set);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the next element
inline block_chains_iterator_t block_chains_next(block_chains_iterator_t p)
{
  HEXDSP(hx_block_chains_next, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the previous element
inline block_chains_iterator_t block_chains_prev(block_chains_iterator_t p)
{
  HEXDSP(hx_block_chains_prev, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Erase current element from block_chains_t
inline void block_chains_erase(block_chains_t *set, block_chains_iterator_t p)
{
  HEXDSP(hx_block_chains_erase, set, &p);
}

//-------------------------------------------------------------------------
/// Clear block_chains_t
inline void block_chains_clear(block_chains_t *set)
{
  HEXDSP(hx_block_chains_clear, set);
}

//-------------------------------------------------------------------------
/// Get size of block_chains_t
inline size_t block_chains_size(block_chains_t *set)
{
  return (size_t)HEXDSP(hx_block_chains_size, set);
}

//-------------------------------------------------------------------------
/// Delete block_chains_t instance
inline void block_chains_free(block_chains_t *set)
{
  HEXDSP(hx_block_chains_free, set);
}

//-------------------------------------------------------------------------
/// Create a new block_chains_t instance
inline block_chains_t *block_chains_new()
{
  return (block_chains_t *)HEXDSP(hx_block_chains_new);
}

//--------------------------------------------------------------------------
inline void *hexrays_alloc(size_t size)
{
  return HEXDSP(hx_hexrays_alloc, size);
}

//--------------------------------------------------------------------------
inline void hexrays_free(void *ptr)
{
  HEXDSP(hx_hexrays_free, ptr);
}

//--------------------------------------------------------------------------
inline void valrng_t::clear(void)
{
  HEXDSP(hx_valrng_t_clear, this);
}

//--------------------------------------------------------------------------
inline void valrng_t::copy(const valrng_t &r)
{
  HEXDSP(hx_valrng_t_copy, this, &r);
}

//--------------------------------------------------------------------------
inline valrng_t &valrng_t::assign(const valrng_t &r)
{
  return *(valrng_t *)HEXDSP(hx_valrng_t_assign, this, &r);
}

//--------------------------------------------------------------------------
inline int valrng_t::compare(const valrng_t &r) const
{
  return (int)(size_t)HEXDSP(hx_valrng_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline void valrng_t::set_eq(uvlr_t v)
{
  HEXDSP(hx_valrng_t_set_eq, this, v);
}

//--------------------------------------------------------------------------
inline void valrng_t::set_cmp(cmpop_t cmp, uvlr_t _value)
{
  HEXDSP(hx_valrng_t_set_cmp, this, cmp, _value);
}

//--------------------------------------------------------------------------
inline bool valrng_t::reduce_size(int new_size)
{
  return (uchar)(size_t)HEXDSP(hx_valrng_t_reduce_size, this, new_size) != 0;
}

//--------------------------------------------------------------------------
inline bool valrng_t::intersect_with(const valrng_t &r)
{
  return (uchar)(size_t)HEXDSP(hx_valrng_t_intersect_with, this, &r) != 0;
}

//--------------------------------------------------------------------------
inline bool valrng_t::unite_with(const valrng_t &r)
{
  return (uchar)(size_t)HEXDSP(hx_valrng_t_unite_with, this, &r) != 0;
}

//--------------------------------------------------------------------------
inline void valrng_t::inverse(void)
{
  HEXDSP(hx_valrng_t_inverse, this);
}

//--------------------------------------------------------------------------
inline bool valrng_t::has(uvlr_t v) const
{
  return (uchar)(size_t)HEXDSP(hx_valrng_t_has, this, v) != 0;
}

//--------------------------------------------------------------------------
inline void valrng_t::print(qstring *vout) const
{
  HEXDSP(hx_valrng_t_print, this, vout);
}

//--------------------------------------------------------------------------
inline const char *valrng_t::dstr(void) const
{
  return (const char *)HEXDSP(hx_valrng_t_dstr, this);
}

//--------------------------------------------------------------------------
inline bool valrng_t::cvt_to_single_value(uvlr_t *v) const
{
  return (uchar)(size_t)HEXDSP(hx_valrng_t_cvt_to_single_value, this, v) != 0;
}

//--------------------------------------------------------------------------
inline bool valrng_t::cvt_to_cmp(cmpop_t *cmp, uvlr_t *val, bool strict) const
{
  return (uchar)(size_t)HEXDSP(hx_valrng_t_cvt_to_cmp, this, cmp, val, strict) != 0;
}

//--------------------------------------------------------------------------
inline ea_t get_merror_desc(qstring *out, merror_t code, mba_t *mba)
{
  ea_t retval;
  HEXDSP(hx_get_merror_desc, &retval, out, code, mba);
  return retval;
}

//--------------------------------------------------------------------------
inline THREAD_SAFE bool must_mcode_close_block(mcode_t mcode, bool including_calls)
{
  return (uchar)(size_t)HEXDSP(hx_must_mcode_close_block, mcode, including_calls) != 0;
}

//--------------------------------------------------------------------------
inline THREAD_SAFE bool is_mcode_propagatable(mcode_t mcode)
{
  return (uchar)(size_t)HEXDSP(hx_is_mcode_propagatable, mcode) != 0;
}

//--------------------------------------------------------------------------
inline THREAD_SAFE mcode_t negate_mcode_relation(mcode_t code)
{
  return (mcode_t)(size_t)HEXDSP(hx_negate_mcode_relation, code);
}

//--------------------------------------------------------------------------
inline THREAD_SAFE mcode_t swap_mcode_relation(mcode_t code)
{
  return (mcode_t)(size_t)HEXDSP(hx_swap_mcode_relation, code);
}

//--------------------------------------------------------------------------
inline THREAD_SAFE mcode_t get_signed_mcode(mcode_t code)
{
  return (mcode_t)(size_t)HEXDSP(hx_get_signed_mcode, code);
}

//--------------------------------------------------------------------------
inline THREAD_SAFE mcode_t get_unsigned_mcode(mcode_t code)
{
  return (mcode_t)(size_t)HEXDSP(hx_get_unsigned_mcode, code);
}

//--------------------------------------------------------------------------
inline THREAD_SAFE bool mcode_modifies_d(mcode_t mcode)
{
  return (uchar)(size_t)HEXDSP(hx_mcode_modifies_d, mcode) != 0;
}

//--------------------------------------------------------------------------
inline int operand_locator_t::compare(const operand_locator_t &r) const
{
  return (int)(size_t)HEXDSP(hx_operand_locator_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline AS_PRINTF(3, 4) int vd_printer_t::print(int indent, const char *format, ...)
{
  va_list va;
  va_start(va, format);
  int retval = (int)(size_t)HEXDSP(hx_vd_printer_t_print, this, indent, format, va);
  va_end(va);
  return retval;
}

//--------------------------------------------------------------------------
inline AS_PRINTF(3, 4) int file_printer_t::print(int indent, const char *format, ...)
{
  va_list va;
  va_start(va, format);
  int retval = (int)(size_t)HEXDSP(hx_file_printer_t_print, this, indent, format, va);
  va_end(va);
  return retval;
}

//--------------------------------------------------------------------------
inline AS_PRINTF(3, 4) int qstring_printer_t::print(int indent, const char *format, ...)
{
  va_list va;
  va_start(va, format);
  int retval = (int)(size_t)HEXDSP(hx_qstring_printer_t_print, this, indent, format, va);
  va_end(va);
  return retval;
}

//--------------------------------------------------------------------------
inline const char *dstr(const tinfo_t *tif)
{
  return (const char *)HEXDSP(hx_dstr, tif);
}

//--------------------------------------------------------------------------
inline bool is_type_correct(const type_t *ptr)
{
  return (uchar)(size_t)HEXDSP(hx_is_type_correct, ptr) != 0;
}

//--------------------------------------------------------------------------
inline bool is_small_udt(const tinfo_t &tif)
{
  return (uchar)(size_t)HEXDSP(hx_is_small_udt, &tif) != 0;
}

//--------------------------------------------------------------------------
inline bool is_nonbool_type(const tinfo_t &type)
{
  return (uchar)(size_t)HEXDSP(hx_is_nonbool_type, &type) != 0;
}

//--------------------------------------------------------------------------
inline bool is_bool_type(const tinfo_t &type)
{
  return (uchar)(size_t)HEXDSP(hx_is_bool_type, &type) != 0;
}

//--------------------------------------------------------------------------
inline int partial_type_num(const tinfo_t &type)
{
  return (int)(size_t)HEXDSP(hx_partial_type_num, &type);
}

//--------------------------------------------------------------------------
inline tinfo_t get_float_type(int width)
{
  tinfo_t retval;
  HEXDSP(hx_get_float_type, &retval, width);
  return retval;
}

//--------------------------------------------------------------------------
inline tinfo_t get_int_type_by_width_and_sign(int srcwidth, type_sign_t sign)
{
  tinfo_t retval;
  HEXDSP(hx_get_int_type_by_width_and_sign, &retval, srcwidth, sign);
  return retval;
}

//--------------------------------------------------------------------------
inline tinfo_t get_unk_type(int size)
{
  tinfo_t retval;
  HEXDSP(hx_get_unk_type, &retval, size);
  return retval;
}

//--------------------------------------------------------------------------
inline tinfo_t dummy_ptrtype(int ptrsize, bool isfp)
{
  tinfo_t retval;
  HEXDSP(hx_dummy_ptrtype, &retval, ptrsize, isfp);
  return retval;
}

//--------------------------------------------------------------------------
inline bool get_member_type(const member_t *mptr, tinfo_t *type)
{
  return (uchar)(size_t)HEXDSP(hx_get_member_type, mptr, type) != 0;
}

//--------------------------------------------------------------------------
inline tinfo_t make_pointer(const tinfo_t &type)
{
  tinfo_t retval;
  HEXDSP(hx_make_pointer, &retval, &type);
  return retval;
}

//--------------------------------------------------------------------------
inline tinfo_t create_typedef(const char *name)
{
  tinfo_t retval;
  HEXDSP(hx_create_typedef, &retval, name);
  return retval;
}

//--------------------------------------------------------------------------
inline bool get_type(uval_t id, tinfo_t *tif, type_source_t guess)
{
  return (uchar)(size_t)HEXDSP(hx_get_type, id, tif, guess) != 0;
}

//--------------------------------------------------------------------------
inline bool set_type(uval_t id, const tinfo_t &tif, type_source_t source, bool force)
{
  return (uchar)(size_t)HEXDSP(hx_set_type, id, &tif, source, force) != 0;
}

//--------------------------------------------------------------------------
inline const char *vdloc_t::dstr(int width) const
{
  return (const char *)HEXDSP(hx_vdloc_t_dstr, this, width);
}

//--------------------------------------------------------------------------
inline int vdloc_t::compare(const vdloc_t &r) const
{
  return (int)(size_t)HEXDSP(hx_vdloc_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline bool vdloc_t::is_aliasable(const mba_t *mb, int size) const
{
  return (uchar)(size_t)HEXDSP(hx_vdloc_t_is_aliasable, this, mb, size) != 0;
}

//--------------------------------------------------------------------------
inline void print_vdloc(qstring *vout, const vdloc_t &loc, int nbytes)
{
  HEXDSP(hx_print_vdloc, vout, &loc, nbytes);
}

//--------------------------------------------------------------------------
inline bool arglocs_overlap(const vdloc_t &loc1, size_t w1, const vdloc_t &loc2, size_t w2)
{
  return (uchar)(size_t)HEXDSP(hx_arglocs_overlap, &loc1, w1, &loc2, w2) != 0;
}

//--------------------------------------------------------------------------
inline int lvar_locator_t::compare(const lvar_locator_t &r) const
{
  return (int)(size_t)HEXDSP(hx_lvar_locator_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline const char *lvar_locator_t::dstr(void) const
{
  return (const char *)HEXDSP(hx_lvar_locator_t_dstr, this);
}

//--------------------------------------------------------------------------
inline const char *lvar_t::dstr(void) const
{
  return (const char *)HEXDSP(hx_lvar_t_dstr, this);
}

//--------------------------------------------------------------------------
inline bool lvar_t::is_promoted_arg(void) const
{
  return (uchar)(size_t)HEXDSP(hx_lvar_t_is_promoted_arg, this) != 0;
}

//--------------------------------------------------------------------------
inline bool lvar_t::accepts_type(const tinfo_t &t, bool may_change_thisarg)
{
  return (uchar)(size_t)HEXDSP(hx_lvar_t_accepts_type, this, &t, may_change_thisarg) != 0;
}

//--------------------------------------------------------------------------
inline bool lvar_t::set_lvar_type(const tinfo_t &t, bool may_fail)
{
  return (uchar)(size_t)HEXDSP(hx_lvar_t_set_lvar_type, this, &t, may_fail) != 0;
}

//--------------------------------------------------------------------------
inline bool lvar_t::set_width(int w, int svw_flags)
{
  return (uchar)(size_t)HEXDSP(hx_lvar_t_set_width, this, w, svw_flags) != 0;
}

//--------------------------------------------------------------------------
inline void lvar_t::append_list(const mba_t *mba, mlist_t *lst, bool pad_if_scattered) const
{
  HEXDSP(hx_lvar_t_append_list, this, mba, lst, pad_if_scattered);
}

//--------------------------------------------------------------------------
inline int lvars_t::find_stkvar(sval_t spoff, int width)
{
  return (int)(size_t)HEXDSP(hx_lvars_t_find_stkvar, this, spoff, width);
}

//--------------------------------------------------------------------------
inline lvar_t *lvars_t::find(const lvar_locator_t &ll)
{
  return (lvar_t *)HEXDSP(hx_lvars_t_find, this, &ll);
}

//--------------------------------------------------------------------------
inline int lvars_t::find_lvar(const vdloc_t &location, int width, int defblk) const
{
  return (int)(size_t)HEXDSP(hx_lvars_t_find_lvar, this, &location, width, defblk);
}

//--------------------------------------------------------------------------
inline bool restore_user_lvar_settings(lvar_uservec_t *lvinf, ea_t func_ea)
{
  return (uchar)(size_t)HEXDSP(hx_restore_user_lvar_settings, lvinf, func_ea) != 0;
}

//--------------------------------------------------------------------------
inline void save_user_lvar_settings(ea_t func_ea, const lvar_uservec_t &lvinf)
{
  HEXDSP(hx_save_user_lvar_settings, func_ea, &lvinf);
}

//--------------------------------------------------------------------------
inline bool modify_user_lvars(ea_t entry_ea, user_lvar_modifier_t &mlv)
{
  return (uchar)(size_t)HEXDSP(hx_modify_user_lvars, entry_ea, &mlv) != 0;
}

//--------------------------------------------------------------------------
inline bool modify_user_lvar_info(ea_t func_ea, uint mli_flags, const lvar_saved_info_t &info)
{
  return (uchar)(size_t)HEXDSP(hx_modify_user_lvar_info, func_ea, mli_flags, &info) != 0;
}

//--------------------------------------------------------------------------
inline bool locate_lvar(lvar_locator_t *out, ea_t func_ea, const char *varname)
{
  return (uchar)(size_t)HEXDSP(hx_locate_lvar, out, func_ea, varname) != 0;
}

//--------------------------------------------------------------------------
inline bool restore_user_defined_calls(udcall_map_t *udcalls, ea_t func_ea)
{
  return (uchar)(size_t)HEXDSP(hx_restore_user_defined_calls, udcalls, func_ea) != 0;
}

//--------------------------------------------------------------------------
inline void save_user_defined_calls(ea_t func_ea, const udcall_map_t &udcalls)
{
  HEXDSP(hx_save_user_defined_calls, func_ea, &udcalls);
}

//--------------------------------------------------------------------------
inline bool parse_user_call(udcall_t *udc, const char *decl, bool silent)
{
  return (uchar)(size_t)HEXDSP(hx_parse_user_call, udc, decl, silent) != 0;
}

//--------------------------------------------------------------------------
inline merror_t convert_to_user_call(const udcall_t &udc, codegen_t &cdg)
{
  return (merror_t)(size_t)HEXDSP(hx_convert_to_user_call, &udc, &cdg);
}

//--------------------------------------------------------------------------
inline bool install_microcode_filter(microcode_filter_t *filter, bool install)
{
  auto hrdsp = HEXDSP;
  return hrdsp != nullptr && (uchar)(size_t)hrdsp(hx_install_microcode_filter, filter, install) != 0;
}

//--------------------------------------------------------------------------
inline void udc_filter_t::cleanup(void)
{
  HEXDSP(hx_udc_filter_t_cleanup, this);
}

//--------------------------------------------------------------------------
inline bool udc_filter_t::init(const char *decl)
{
  return (uchar)(size_t)HEXDSP(hx_udc_filter_t_init, this, decl) != 0;
}

//--------------------------------------------------------------------------
inline merror_t udc_filter_t::apply(codegen_t &cdg)
{
  return (merror_t)(size_t)HEXDSP(hx_udc_filter_t_apply, this, &cdg);
}

//--------------------------------------------------------------------------
inline bitset_t::bitset_t(const bitset_t &m)
{
  HEXDSP(hx_bitset_t_bitset_t, this, &m);
}

//--------------------------------------------------------------------------
inline bitset_t &bitset_t::copy(const bitset_t &m)
{
  return *(bitset_t *)HEXDSP(hx_bitset_t_copy, this, &m);
}

//--------------------------------------------------------------------------
inline bool bitset_t::add(int bit)
{
  return (uchar)(size_t)HEXDSP(hx_bitset_t_add, this, bit) != 0;
}

//--------------------------------------------------------------------------
inline bool bitset_t::add(int bit, int width)
{
  return (uchar)(size_t)HEXDSP(hx_bitset_t_add_, this, bit, width) != 0;
}

//--------------------------------------------------------------------------
inline bool bitset_t::add(const bitset_t &ml)
{
  return (uchar)(size_t)HEXDSP(hx_bitset_t_add__, this, &ml) != 0;
}

//--------------------------------------------------------------------------
inline bool bitset_t::sub(int bit)
{
  return (uchar)(size_t)HEXDSP(hx_bitset_t_sub, this, bit) != 0;
}

//--------------------------------------------------------------------------
inline bool bitset_t::sub(int bit, int width)
{
  return (uchar)(size_t)HEXDSP(hx_bitset_t_sub_, this, bit, width) != 0;
}

//--------------------------------------------------------------------------
inline bool bitset_t::sub(const bitset_t &ml)
{
  return (uchar)(size_t)HEXDSP(hx_bitset_t_sub__, this, &ml) != 0;
}

//--------------------------------------------------------------------------
inline bool bitset_t::cut_at(int maxbit)
{
  return (uchar)(size_t)HEXDSP(hx_bitset_t_cut_at, this, maxbit) != 0;
}

//--------------------------------------------------------------------------
inline void bitset_t::shift_down(int shift)
{
  HEXDSP(hx_bitset_t_shift_down, this, shift);
}

//--------------------------------------------------------------------------
inline bool bitset_t::has(int bit) const
{
  return (uchar)(size_t)HEXDSP(hx_bitset_t_has, this, bit) != 0;
}

//--------------------------------------------------------------------------
inline bool bitset_t::has_all(int bit, int width) const
{
  return (uchar)(size_t)HEXDSP(hx_bitset_t_has_all, this, bit, width) != 0;
}

//--------------------------------------------------------------------------
inline bool bitset_t::has_any(int bit, int width) const
{
  return (uchar)(size_t)HEXDSP(hx_bitset_t_has_any, this, bit, width) != 0;
}

//--------------------------------------------------------------------------
inline const char *bitset_t::dstr(void) const
{
  return (const char *)HEXDSP(hx_bitset_t_dstr, this);
}

//--------------------------------------------------------------------------
inline bool bitset_t::empty(void) const
{
  return (uchar)(size_t)HEXDSP(hx_bitset_t_empty, this) != 0;
}

//--------------------------------------------------------------------------
inline int bitset_t::count(void) const
{
  return (int)(size_t)HEXDSP(hx_bitset_t_count, this);
}

//--------------------------------------------------------------------------
inline int bitset_t::count(int bit) const
{
  return (int)(size_t)HEXDSP(hx_bitset_t_count_, this, bit);
}

//--------------------------------------------------------------------------
inline int bitset_t::last(void) const
{
  return (int)(size_t)HEXDSP(hx_bitset_t_last, this);
}

//--------------------------------------------------------------------------
inline void bitset_t::fill_with_ones(int maxbit)
{
  HEXDSP(hx_bitset_t_fill_with_ones, this, maxbit);
}

//--------------------------------------------------------------------------
inline bool bitset_t::fill_gaps(int total_nbits)
{
  return (uchar)(size_t)HEXDSP(hx_bitset_t_fill_gaps, this, total_nbits) != 0;
}

//--------------------------------------------------------------------------
inline bool bitset_t::has_common(const bitset_t &ml) const
{
  return (uchar)(size_t)HEXDSP(hx_bitset_t_has_common, this, &ml) != 0;
}

//--------------------------------------------------------------------------
inline bool bitset_t::intersect(const bitset_t &ml)
{
  return (uchar)(size_t)HEXDSP(hx_bitset_t_intersect, this, &ml) != 0;
}

//--------------------------------------------------------------------------
inline bool bitset_t::is_subset_of(const bitset_t &ml) const
{
  return (uchar)(size_t)HEXDSP(hx_bitset_t_is_subset_of, this, &ml) != 0;
}

//--------------------------------------------------------------------------
inline int bitset_t::compare(const bitset_t &r) const
{
  return (int)(size_t)HEXDSP(hx_bitset_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int bitset_t::goup(int reg) const
{
  return (int)(size_t)HEXDSP(hx_bitset_t_goup, this, reg);
}

//--------------------------------------------------------------------------
inline const char *ivl_t::dstr(void) const
{
  return (const char *)HEXDSP(hx_ivl_t_dstr, this);
}

//--------------------------------------------------------------------------
inline int ivl_t::compare(const ivl_t &r) const
{
  return (int)(size_t)HEXDSP(hx_ivl_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline bool ivlset_t::add(const ivl_t &ivl)
{
  return (uchar)(size_t)HEXDSP(hx_ivlset_t_add, this, &ivl) != 0;
}

//--------------------------------------------------------------------------
inline bool ivlset_t::add(const ivlset_t &ivs)
{
  return (uchar)(size_t)HEXDSP(hx_ivlset_t_add_, this, &ivs) != 0;
}

//--------------------------------------------------------------------------
inline bool ivlset_t::addmasked(const ivlset_t &ivs, const ivl_t &mask)
{
  return (uchar)(size_t)HEXDSP(hx_ivlset_t_addmasked, this, &ivs, &mask) != 0;
}

//--------------------------------------------------------------------------
inline bool ivlset_t::sub(const ivl_t &ivl)
{
  return (uchar)(size_t)HEXDSP(hx_ivlset_t_sub, this, &ivl) != 0;
}

//--------------------------------------------------------------------------
inline bool ivlset_t::sub(const ivlset_t &ivs)
{
  return (uchar)(size_t)HEXDSP(hx_ivlset_t_sub_, this, &ivs) != 0;
}

//--------------------------------------------------------------------------
inline bool ivlset_t::has_common(const ivl_t &ivl, bool strict) const
{
  return (uchar)(size_t)HEXDSP(hx_ivlset_t_has_common, this, &ivl, strict) != 0;
}

//--------------------------------------------------------------------------
inline void ivlset_t::print(qstring *vout) const
{
  HEXDSP(hx_ivlset_t_print, this, vout);
}

//--------------------------------------------------------------------------
inline const char *ivlset_t::dstr(void) const
{
  return (const char *)HEXDSP(hx_ivlset_t_dstr, this);
}

//--------------------------------------------------------------------------
inline asize_t ivlset_t::count(void) const
{
  asize_t retval;
  HEXDSP(hx_ivlset_t_count, &retval, this);
  return retval;
}

//--------------------------------------------------------------------------
inline bool ivlset_t::has_common(const ivlset_t &ivs) const
{
  return (uchar)(size_t)HEXDSP(hx_ivlset_t_has_common_, this, &ivs) != 0;
}

//--------------------------------------------------------------------------
inline bool ivlset_t::contains(uval_t off) const
{
  return (uchar)(size_t)HEXDSP(hx_ivlset_t_contains, this, off) != 0;
}

//--------------------------------------------------------------------------
inline bool ivlset_t::includes(const ivlset_t &ivs) const
{
  return (uchar)(size_t)HEXDSP(hx_ivlset_t_includes, this, &ivs) != 0;
}

//--------------------------------------------------------------------------
inline bool ivlset_t::intersect(const ivlset_t &ivs)
{
  return (uchar)(size_t)HEXDSP(hx_ivlset_t_intersect, this, &ivs) != 0;
}

//--------------------------------------------------------------------------
inline int ivlset_t::compare(const ivlset_t &r) const
{
  return (int)(size_t)HEXDSP(hx_ivlset_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline void rlist_t::print(qstring *vout) const
{
  HEXDSP(hx_rlist_t_print, this, vout);
}

//--------------------------------------------------------------------------
inline const char *rlist_t::dstr(void) const
{
  return (const char *)HEXDSP(hx_rlist_t_dstr, this);
}

//--------------------------------------------------------------------------
inline bool mlist_t::addmem(ea_t ea, asize_t size)
{
  return (uchar)(size_t)HEXDSP(hx_mlist_t_addmem, this, ea, size) != 0;
}

//--------------------------------------------------------------------------
inline void mlist_t::print(qstring *vout) const
{
  HEXDSP(hx_mlist_t_print, this, vout);
}

//--------------------------------------------------------------------------
inline const char *mlist_t::dstr(void) const
{
  return (const char *)HEXDSP(hx_mlist_t_dstr, this);
}

//--------------------------------------------------------------------------
inline int mlist_t::compare(const mlist_t &r) const
{
  return (int)(size_t)HEXDSP(hx_mlist_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline const mlist_t &get_temp_regs(void)
{
  return *(const mlist_t *)HEXDSP(hx_get_temp_regs);
}

//--------------------------------------------------------------------------
inline bool is_kreg(mreg_t r)
{
  return (uchar)(size_t)HEXDSP(hx_is_kreg, r) != 0;
}

//--------------------------------------------------------------------------
inline mreg_t reg2mreg(int reg)
{
  return (mreg_t)(size_t)HEXDSP(hx_reg2mreg, reg);
}

//--------------------------------------------------------------------------
inline int mreg2reg(mreg_t reg, int width)
{
  return (int)(size_t)HEXDSP(hx_mreg2reg, reg, width);
}

//--------------------------------------------------------------------------
inline int get_mreg_name(qstring *out, mreg_t reg, int width, void *ud)
{
  return (int)(size_t)HEXDSP(hx_get_mreg_name, out, reg, width, ud);
}

//--------------------------------------------------------------------------
inline void install_optinsn_handler(optinsn_t *opt)
{
  HEXDSP(hx_install_optinsn_handler, opt);
}

//--------------------------------------------------------------------------
inline bool remove_optinsn_handler(optinsn_t *opt)
{
  auto hrdsp = HEXDSP;
  return hrdsp != nullptr && (uchar)(size_t)hrdsp(hx_remove_optinsn_handler, opt) != 0;
}

//--------------------------------------------------------------------------
inline void install_optblock_handler(optblock_t *opt)
{
  HEXDSP(hx_install_optblock_handler, opt);
}

//--------------------------------------------------------------------------
inline bool remove_optblock_handler(optblock_t *opt)
{
  auto hrdsp = HEXDSP;
  return hrdsp != nullptr && (uchar)(size_t)hrdsp(hx_remove_optblock_handler, opt) != 0;
}

//--------------------------------------------------------------------------
inline int lvar_ref_t::compare(const lvar_ref_t &r) const
{
  return (int)(size_t)HEXDSP(hx_lvar_ref_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline lvar_t &lvar_ref_t::var(void) const
{
  return *(lvar_t *)HEXDSP(hx_lvar_ref_t_var, this);
}

//--------------------------------------------------------------------------
inline int stkvar_ref_t::compare(const stkvar_ref_t &r) const
{
  return (int)(size_t)HEXDSP(hx_stkvar_ref_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline member_t *stkvar_ref_t::get_stkvar(uval_t *p_off) const
{
  return (member_t *)HEXDSP(hx_stkvar_ref_t_get_stkvar, this, p_off);
}

//--------------------------------------------------------------------------
inline void fnumber_t::print(qstring *vout) const
{
  HEXDSP(hx_fnumber_t_print, this, vout);
}

//--------------------------------------------------------------------------
inline const char *fnumber_t::dstr(void) const
{
  return (const char *)HEXDSP(hx_fnumber_t_dstr, this);
}

//--------------------------------------------------------------------------
inline void mop_t::copy(const mop_t &rop)
{
  HEXDSP(hx_mop_t_copy, this, &rop);
}

//--------------------------------------------------------------------------
inline mop_t &mop_t::assign(const mop_t &rop)
{
  return *(mop_t *)HEXDSP(hx_mop_t_assign, this, &rop);
}

//--------------------------------------------------------------------------
inline void mop_t::swap(mop_t &rop)
{
  HEXDSP(hx_mop_t_swap, this, &rop);
}

//--------------------------------------------------------------------------
inline void mop_t::erase(void)
{
  HEXDSP(hx_mop_t_erase, this);
}

//--------------------------------------------------------------------------
inline void mop_t::print(qstring *vout, int shins_flags) const
{
  HEXDSP(hx_mop_t_print, this, vout, shins_flags);
}

//--------------------------------------------------------------------------
inline const char *mop_t::dstr(void) const
{
  return (const char *)HEXDSP(hx_mop_t_dstr, this);
}

//--------------------------------------------------------------------------
inline bool mop_t::create_from_mlist(mba_t *mba, const mlist_t &lst, sval_t fullsize)
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_create_from_mlist, this, mba, &lst, fullsize) != 0;
}

//--------------------------------------------------------------------------
inline bool mop_t::create_from_ivlset(mba_t *mba, const ivlset_t &ivs, sval_t fullsize)
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_create_from_ivlset, this, mba, &ivs, fullsize) != 0;
}

//--------------------------------------------------------------------------
inline void mop_t::create_from_vdloc(mba_t *mba, const vdloc_t &loc, int _size)
{
  HEXDSP(hx_mop_t_create_from_vdloc, this, mba, &loc, _size);
}

//--------------------------------------------------------------------------
inline void mop_t::create_from_scattered_vdloc(mba_t *mba, const char *name, tinfo_t type, const vdloc_t &loc)
{
  HEXDSP(hx_mop_t_create_from_scattered_vdloc, this, mba, name, &type, &loc);
}

//--------------------------------------------------------------------------
inline void mop_t::create_from_insn(const minsn_t *m)
{
  HEXDSP(hx_mop_t_create_from_insn, this, m);
}

//--------------------------------------------------------------------------
inline void mop_t::make_number(uint64 _value, int _size, ea_t _ea, int opnum)
{
  HEXDSP(hx_mop_t_make_number, this, _value, _size, _ea, opnum);
}

//--------------------------------------------------------------------------
inline bool mop_t::make_fpnum(const void *bytes, size_t _size)
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_make_fpnum, this, bytes, _size) != 0;
}

//--------------------------------------------------------------------------
inline void mop_t::_make_gvar(ea_t ea)
{
  HEXDSP(hx_mop_t__make_gvar, this, ea);
}

//--------------------------------------------------------------------------
inline void mop_t::make_gvar(ea_t ea)
{
  HEXDSP(hx_mop_t_make_gvar, this, ea);
}

//--------------------------------------------------------------------------
inline void mop_t::make_reg_pair(int loreg, int hireg, int halfsize)
{
  HEXDSP(hx_mop_t_make_reg_pair, this, loreg, hireg, halfsize);
}

//--------------------------------------------------------------------------
inline void mop_t::make_helper(const char *name)
{
  HEXDSP(hx_mop_t_make_helper, this, name);
}

//--------------------------------------------------------------------------
inline bool mop_t::is_bit_reg(mreg_t reg)
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_is_bit_reg, reg) != 0;
}

//--------------------------------------------------------------------------
inline bool mop_t::may_use_aliased_memory(void) const
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_may_use_aliased_memory, this) != 0;
}

//--------------------------------------------------------------------------
inline bool mop_t::is01(void) const
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_is01, this) != 0;
}

//--------------------------------------------------------------------------
inline bool mop_t::is_sign_extended_from(int nbytes) const
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_is_sign_extended_from, this, nbytes) != 0;
}

//--------------------------------------------------------------------------
inline bool mop_t::is_zero_extended_from(int nbytes) const
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_is_zero_extended_from, this, nbytes) != 0;
}

//--------------------------------------------------------------------------
inline bool mop_t::equal_mops(const mop_t &rop, int eqflags) const
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_equal_mops, this, &rop, eqflags) != 0;
}

//--------------------------------------------------------------------------
inline int mop_t::lexcompare(const mop_t &rop) const
{
  return (int)(size_t)HEXDSP(hx_mop_t_lexcompare, this, &rop);
}

//--------------------------------------------------------------------------
inline int mop_t::for_all_ops(mop_visitor_t &mv, const tinfo_t *type, bool is_target)
{
  return (int)(size_t)HEXDSP(hx_mop_t_for_all_ops, this, &mv, type, is_target);
}

//--------------------------------------------------------------------------
inline int mop_t::for_all_scattered_submops(scif_visitor_t &sv) const
{
  return (int)(size_t)HEXDSP(hx_mop_t_for_all_scattered_submops, this, &sv);
}

//--------------------------------------------------------------------------
inline bool mop_t::is_constant(uint64 *out, bool is_signed) const
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_is_constant, this, out, is_signed) != 0;
}

//--------------------------------------------------------------------------
inline bool mop_t::get_stkoff(sval_t *p_off) const
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_get_stkoff, this, p_off) != 0;
}

//--------------------------------------------------------------------------
inline bool mop_t::make_low_half(int width)
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_make_low_half, this, width) != 0;
}

//--------------------------------------------------------------------------
inline bool mop_t::make_high_half(int width)
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_make_high_half, this, width) != 0;
}

//--------------------------------------------------------------------------
inline bool mop_t::make_first_half(int width)
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_make_first_half, this, width) != 0;
}

//--------------------------------------------------------------------------
inline bool mop_t::make_second_half(int width)
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_make_second_half, this, width) != 0;
}

//--------------------------------------------------------------------------
inline bool mop_t::shift_mop(int offset)
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_shift_mop, this, offset) != 0;
}

//--------------------------------------------------------------------------
inline bool mop_t::change_size(int nsize, side_effect_t sideff)
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_change_size, this, nsize, sideff) != 0;
}

//--------------------------------------------------------------------------
inline bool mop_t::preserve_side_effects(mblock_t *blk, minsn_t *top, bool *moved_calls)
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_preserve_side_effects, this, blk, top, moved_calls) != 0;
}

//--------------------------------------------------------------------------
inline void mop_t::apply_ld_mcode(mcode_t mcode, ea_t ea, int newsize)
{
  HEXDSP(hx_mop_t_apply_ld_mcode, this, mcode, ea, newsize);
}

//--------------------------------------------------------------------------
inline void mcallarg_t::print(qstring *vout, int shins_flags) const
{
  HEXDSP(hx_mcallarg_t_print, this, vout, shins_flags);
}

//--------------------------------------------------------------------------
inline const char *mcallarg_t::dstr(void) const
{
  return (const char *)HEXDSP(hx_mcallarg_t_dstr, this);
}

//--------------------------------------------------------------------------
inline void mcallarg_t::set_regarg(mreg_t mr, int sz, const tinfo_t &tif)
{
  HEXDSP(hx_mcallarg_t_set_regarg, this, mr, sz, &tif);
}

//--------------------------------------------------------------------------
inline int mcallinfo_t::lexcompare(const mcallinfo_t &f) const
{
  return (int)(size_t)HEXDSP(hx_mcallinfo_t_lexcompare, this, &f);
}

//--------------------------------------------------------------------------
inline bool mcallinfo_t::set_type(const tinfo_t &type)
{
  return (uchar)(size_t)HEXDSP(hx_mcallinfo_t_set_type, this, &type) != 0;
}

//--------------------------------------------------------------------------
inline tinfo_t mcallinfo_t::get_type(void) const
{
  tinfo_t retval;
  HEXDSP(hx_mcallinfo_t_get_type, &retval, this);
  return retval;
}

//--------------------------------------------------------------------------
inline void mcallinfo_t::print(qstring *vout, int size, int shins_flags) const
{
  HEXDSP(hx_mcallinfo_t_print, this, vout, size, shins_flags);
}

//--------------------------------------------------------------------------
inline const char *mcallinfo_t::dstr(void) const
{
  return (const char *)HEXDSP(hx_mcallinfo_t_dstr, this);
}

//--------------------------------------------------------------------------
inline int mcases_t::compare(const mcases_t &r) const
{
  return (int)(size_t)HEXDSP(hx_mcases_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline void mcases_t::print(qstring *vout) const
{
  HEXDSP(hx_mcases_t_print, this, vout);
}

//--------------------------------------------------------------------------
inline const char *mcases_t::dstr(void) const
{
  return (const char *)HEXDSP(hx_mcases_t_dstr, this);
}

//--------------------------------------------------------------------------
inline bool vivl_t::extend_to_cover(const vivl_t &r)
{
  return (uchar)(size_t)HEXDSP(hx_vivl_t_extend_to_cover, this, &r) != 0;
}

//--------------------------------------------------------------------------
inline uval_t vivl_t::intersect(const vivl_t &r)
{
  uval_t retval;
  HEXDSP(hx_vivl_t_intersect, &retval, this, &r);
  return retval;
}

//--------------------------------------------------------------------------
inline void vivl_t::print(qstring *vout) const
{
  HEXDSP(hx_vivl_t_print, this, vout);
}

//--------------------------------------------------------------------------
inline const char *vivl_t::dstr(void) const
{
  return (const char *)HEXDSP(hx_vivl_t_dstr, this);
}

//--------------------------------------------------------------------------
inline void chain_t::print(qstring *vout) const
{
  HEXDSP(hx_chain_t_print, this, vout);
}

//--------------------------------------------------------------------------
inline const char *chain_t::dstr(void) const
{
  return (const char *)HEXDSP(hx_chain_t_dstr, this);
}

//--------------------------------------------------------------------------
inline void chain_t::append_list(const mba_t *mba, mlist_t *list) const
{
  HEXDSP(hx_chain_t_append_list, this, mba, list);
}

//--------------------------------------------------------------------------
inline const chain_t *block_chains_t::get_chain(const chain_t &ch) const
{
  return (const chain_t *)HEXDSP(hx_block_chains_t_get_chain, this, &ch);
}

//--------------------------------------------------------------------------
inline void block_chains_t::print(qstring *vout) const
{
  HEXDSP(hx_block_chains_t_print, this, vout);
}

//--------------------------------------------------------------------------
inline const char *block_chains_t::dstr(void) const
{
  return (const char *)HEXDSP(hx_block_chains_t_dstr, this);
}

//--------------------------------------------------------------------------
inline int graph_chains_t::for_all_chains(chain_visitor_t &cv, int gca_flags)
{
  return (int)(size_t)HEXDSP(hx_graph_chains_t_for_all_chains, this, &cv, gca_flags);
}

//--------------------------------------------------------------------------
inline void graph_chains_t::release(void)
{
  HEXDSP(hx_graph_chains_t_release, this);
}

//--------------------------------------------------------------------------
inline void minsn_t::init(ea_t _ea)
{
  HEXDSP(hx_minsn_t_init, this, _ea);
}

//--------------------------------------------------------------------------
inline void minsn_t::copy(const minsn_t &m)
{
  HEXDSP(hx_minsn_t_copy, this, &m);
}

//--------------------------------------------------------------------------
inline void minsn_t::set_combined(void)
{
  HEXDSP(hx_minsn_t_set_combined, this);
}

//--------------------------------------------------------------------------
inline void minsn_t::swap(minsn_t &m)
{
  HEXDSP(hx_minsn_t_swap, this, &m);
}

//--------------------------------------------------------------------------
inline void minsn_t::print(qstring *vout, int shins_flags) const
{
  HEXDSP(hx_minsn_t_print, this, vout, shins_flags);
}

//--------------------------------------------------------------------------
inline const char *minsn_t::dstr(void) const
{
  return (const char *)HEXDSP(hx_minsn_t_dstr, this);
}

//--------------------------------------------------------------------------
inline void minsn_t::setaddr(ea_t new_ea)
{
  HEXDSP(hx_minsn_t_setaddr, this, new_ea);
}

//--------------------------------------------------------------------------
inline int minsn_t::optimize_subtree(mblock_t *blk, minsn_t *top, minsn_t *parent, ea_t *converted_call, int optflags)
{
  return (int)(size_t)HEXDSP(hx_minsn_t_optimize_subtree, this, blk, top, parent, converted_call, optflags);
}

//--------------------------------------------------------------------------
inline int minsn_t::for_all_ops(mop_visitor_t &mv)
{
  return (int)(size_t)HEXDSP(hx_minsn_t_for_all_ops, this, &mv);
}

//--------------------------------------------------------------------------
inline int minsn_t::for_all_insns(minsn_visitor_t &mv)
{
  return (int)(size_t)HEXDSP(hx_minsn_t_for_all_insns, this, &mv);
}

//--------------------------------------------------------------------------
inline void minsn_t::_make_nop(void)
{
  HEXDSP(hx_minsn_t__make_nop, this);
}

//--------------------------------------------------------------------------
inline bool minsn_t::equal_insns(const minsn_t &m, int eqflags) const
{
  return (uchar)(size_t)HEXDSP(hx_minsn_t_equal_insns, this, &m, eqflags) != 0;
}

//--------------------------------------------------------------------------
inline int minsn_t::lexcompare(const minsn_t &ri) const
{
  return (int)(size_t)HEXDSP(hx_minsn_t_lexcompare, this, &ri);
}

//--------------------------------------------------------------------------
inline bool minsn_t::is_noret_call(int flags)
{
  return (uchar)(size_t)HEXDSP(hx_minsn_t_is_noret_call, this, flags) != 0;
}

//--------------------------------------------------------------------------
inline bool minsn_t::is_helper(const char *name) const
{
  return (uchar)(size_t)HEXDSP(hx_minsn_t_is_helper, this, name) != 0;
}

//--------------------------------------------------------------------------
inline minsn_t *minsn_t::find_call(bool with_helpers) const
{
  return (minsn_t *)HEXDSP(hx_minsn_t_find_call, this, with_helpers);
}

//--------------------------------------------------------------------------
inline bool minsn_t::has_side_effects(bool include_ldx_and_divs) const
{
  return (uchar)(size_t)HEXDSP(hx_minsn_t_has_side_effects, this, include_ldx_and_divs) != 0;
}

//--------------------------------------------------------------------------
inline minsn_t *minsn_t::find_opcode(mcode_t mcode)
{
  return (minsn_t *)HEXDSP(hx_minsn_t_find_opcode, this, mcode);
}

//--------------------------------------------------------------------------
inline const minsn_t *minsn_t::find_ins_op(const mop_t **other, mcode_t op) const
{
  return (const minsn_t *)HEXDSP(hx_minsn_t_find_ins_op, this, other, op);
}

//--------------------------------------------------------------------------
inline const mop_t *minsn_t::find_num_op(const mop_t **other) const
{
  return (const mop_t *)HEXDSP(hx_minsn_t_find_num_op, this, other);
}

//--------------------------------------------------------------------------
inline bool minsn_t::modifies_d(void) const
{
  return (uchar)(size_t)HEXDSP(hx_minsn_t_modifies_d, this) != 0;
}

//--------------------------------------------------------------------------
inline bool minsn_t::is_between(const minsn_t *m1, const minsn_t *m2) const
{
  return (uchar)(size_t)HEXDSP(hx_minsn_t_is_between, this, m1, m2) != 0;
}

//--------------------------------------------------------------------------
inline bool minsn_t::may_use_aliased_memory(void) const
{
  return (uchar)(size_t)HEXDSP(hx_minsn_t_may_use_aliased_memory, this) != 0;
}

//--------------------------------------------------------------------------
inline int minsn_t::serialize(bytevec_t *b) const
{
  return (int)(size_t)HEXDSP(hx_minsn_t_serialize, this, b);
}

//--------------------------------------------------------------------------
inline bool minsn_t::deserialize(const uchar *bytes, size_t nbytes, int format_version)
{
  return (uchar)(size_t)HEXDSP(hx_minsn_t_deserialize, this, bytes, nbytes, format_version) != 0;
}

//--------------------------------------------------------------------------
inline const minsn_t *getf_reginsn(const minsn_t *ins)
{
  return (const minsn_t *)HEXDSP(hx_getf_reginsn, ins);
}

//--------------------------------------------------------------------------
inline const minsn_t *getb_reginsn(const minsn_t *ins)
{
  return (const minsn_t *)HEXDSP(hx_getb_reginsn, ins);
}

//--------------------------------------------------------------------------
inline void mblock_t::init(void)
{
  HEXDSP(hx_mblock_t_init, this);
}

//--------------------------------------------------------------------------
inline void mblock_t::print(vd_printer_t &vp) const
{
  HEXDSP(hx_mblock_t_print, this, &vp);
}

//--------------------------------------------------------------------------
inline void mblock_t::dump(void) const
{
  HEXDSP(hx_mblock_t_dump, this);
}

//--------------------------------------------------------------------------
inline AS_PRINTF(2, 0) void mblock_t::vdump_block(const char *title, va_list va) const
{
  HEXDSP(hx_mblock_t_vdump_block, this, title, va);
}

//--------------------------------------------------------------------------
inline minsn_t *mblock_t::insert_into_block(minsn_t *nm, minsn_t *om)
{
  return (minsn_t *)HEXDSP(hx_mblock_t_insert_into_block, this, nm, om);
}

//--------------------------------------------------------------------------
inline minsn_t *mblock_t::remove_from_block(minsn_t *m)
{
  return (minsn_t *)HEXDSP(hx_mblock_t_remove_from_block, this, m);
}

//--------------------------------------------------------------------------
inline int mblock_t::for_all_insns(minsn_visitor_t &mv)
{
  return (int)(size_t)HEXDSP(hx_mblock_t_for_all_insns, this, &mv);
}

//--------------------------------------------------------------------------
inline int mblock_t::for_all_ops(mop_visitor_t &mv)
{
  return (int)(size_t)HEXDSP(hx_mblock_t_for_all_ops, this, &mv);
}

//--------------------------------------------------------------------------
inline int mblock_t::for_all_uses(mlist_t *list, minsn_t *i1, minsn_t *i2, mlist_mop_visitor_t &mmv)
{
  return (int)(size_t)HEXDSP(hx_mblock_t_for_all_uses, this, list, i1, i2, &mmv);
}

//--------------------------------------------------------------------------
inline int mblock_t::optimize_insn(minsn_t *m, int optflags)
{
  return (int)(size_t)HEXDSP(hx_mblock_t_optimize_insn, this, m, optflags);
}

//--------------------------------------------------------------------------
inline int mblock_t::optimize_block(void)
{
  return (int)(size_t)HEXDSP(hx_mblock_t_optimize_block, this);
}

//--------------------------------------------------------------------------
inline int mblock_t::build_lists(bool kill_deads)
{
  return (int)(size_t)HEXDSP(hx_mblock_t_build_lists, this, kill_deads);
}

//--------------------------------------------------------------------------
inline int mblock_t::optimize_useless_jump(void)
{
  return (int)(size_t)HEXDSP(hx_mblock_t_optimize_useless_jump, this);
}

//--------------------------------------------------------------------------
inline void mblock_t::append_use_list(mlist_t *list, const mop_t &op, maymust_t maymust, bitrange_t mask) const
{
  HEXDSP(hx_mblock_t_append_use_list, this, list, &op, maymust, &mask);
}

//--------------------------------------------------------------------------
inline void mblock_t::append_def_list(mlist_t *list, const mop_t &op, maymust_t maymust) const
{
  HEXDSP(hx_mblock_t_append_def_list, this, list, &op, maymust);
}

//--------------------------------------------------------------------------
inline mlist_t mblock_t::build_use_list(const minsn_t &ins, maymust_t maymust) const
{
  mlist_t retval;
  HEXDSP(hx_mblock_t_build_use_list, &retval, this, &ins, maymust);
  return retval;
}

//--------------------------------------------------------------------------
inline mlist_t mblock_t::build_def_list(const minsn_t &ins, maymust_t maymust) const
{
  mlist_t retval;
  HEXDSP(hx_mblock_t_build_def_list, &retval, this, &ins, maymust);
  return retval;
}

//--------------------------------------------------------------------------
inline const minsn_t *mblock_t::find_first_use(mlist_t *list, const minsn_t *i1, const minsn_t *i2, maymust_t maymust) const
{
  return (const minsn_t *)HEXDSP(hx_mblock_t_find_first_use, this, list, i1, i2, maymust);
}

//--------------------------------------------------------------------------
inline const minsn_t *mblock_t::find_redefinition(const mlist_t &list, const minsn_t *i1, const minsn_t *i2, maymust_t maymust) const
{
  return (const minsn_t *)HEXDSP(hx_mblock_t_find_redefinition, this, &list, i1, i2, maymust);
}

//--------------------------------------------------------------------------
inline bool mblock_t::is_rhs_redefined(const minsn_t *ins, const minsn_t *i1, const minsn_t *i2) const
{
  return (uchar)(size_t)HEXDSP(hx_mblock_t_is_rhs_redefined, this, ins, i1, i2) != 0;
}

//--------------------------------------------------------------------------
inline minsn_t *mblock_t::find_access(const mop_t &op, minsn_t **parent, const minsn_t *mend, int fdflags) const
{
  return (minsn_t *)HEXDSP(hx_mblock_t_find_access, this, &op, parent, mend, fdflags);
}

//--------------------------------------------------------------------------
inline bool mblock_t::get_valranges(valrng_t *res, const vivl_t &vivl, int vrflags) const
{
  return (uchar)(size_t)HEXDSP(hx_mblock_t_get_valranges, this, res, &vivl, vrflags) != 0;
}

//--------------------------------------------------------------------------
inline bool mblock_t::get_valranges(valrng_t *res, const vivl_t &vivl, const minsn_t *m, int vrflags) const
{
  return (uchar)(size_t)HEXDSP(hx_mblock_t_get_valranges_, this, res, &vivl, m, vrflags) != 0;
}

//--------------------------------------------------------------------------
inline size_t mblock_t::get_reginsn_qty(void) const
{
  return (size_t)HEXDSP(hx_mblock_t_get_reginsn_qty, this);
}

//--------------------------------------------------------------------------
inline bool mba_ranges_t::range_contains(ea_t ea) const
{
  return (uchar)(size_t)HEXDSP(hx_mba_ranges_t_range_contains, this, ea) != 0;
}

//--------------------------------------------------------------------------
inline sval_t mba_t::stkoff_vd2ida(sval_t off) const
{
  sval_t retval;
  HEXDSP(hx_mba_t_stkoff_vd2ida, &retval, this, off);
  return retval;
}

//--------------------------------------------------------------------------
inline sval_t mba_t::stkoff_ida2vd(sval_t off) const
{
  sval_t retval;
  HEXDSP(hx_mba_t_stkoff_ida2vd, &retval, this, off);
  return retval;
}

//--------------------------------------------------------------------------
inline vdloc_t mba_t::idaloc2vd(const argloc_t &loc, int width, sval_t spd)
{
  vdloc_t retval;
  HEXDSP(hx_mba_t_idaloc2vd, &retval, &loc, width, spd);
  return retval;
}

//--------------------------------------------------------------------------
inline vdloc_t mba_t::idaloc2vd(const argloc_t &loc, int width) const
{
  vdloc_t retval;
  HEXDSP(hx_mba_t_idaloc2vd_, &retval, this, &loc, width);
  return retval;
}

//--------------------------------------------------------------------------
inline argloc_t mba_t::vd2idaloc(const vdloc_t &loc, int width, sval_t spd)
{
  argloc_t retval;
  HEXDSP(hx_mba_t_vd2idaloc, &retval, &loc, width, spd);
  return retval;
}

//--------------------------------------------------------------------------
inline argloc_t mba_t::vd2idaloc(const vdloc_t &loc, int width) const
{
  argloc_t retval;
  HEXDSP(hx_mba_t_vd2idaloc_, &retval, this, &loc, width);
  return retval;
}

//--------------------------------------------------------------------------
inline void mba_t::term(void)
{
  HEXDSP(hx_mba_t_term, this);
}

//--------------------------------------------------------------------------
inline func_t *mba_t::get_curfunc(void) const
{
  return (func_t *)HEXDSP(hx_mba_t_get_curfunc, this);
}

//--------------------------------------------------------------------------
inline bool mba_t::set_maturity(mba_maturity_t mat)
{
  return (uchar)(size_t)HEXDSP(hx_mba_t_set_maturity, this, mat) != 0;
}

//--------------------------------------------------------------------------
inline int mba_t::optimize_local(int locopt_bits)
{
  return (int)(size_t)HEXDSP(hx_mba_t_optimize_local, this, locopt_bits);
}

//--------------------------------------------------------------------------
inline merror_t mba_t::build_graph(void)
{
  return (merror_t)(size_t)HEXDSP(hx_mba_t_build_graph, this);
}

//--------------------------------------------------------------------------
inline mbl_graph_t *mba_t::get_graph(void)
{
  return (mbl_graph_t *)HEXDSP(hx_mba_t_get_graph, this);
}

//--------------------------------------------------------------------------
inline int mba_t::analyze_calls(int acflags)
{
  return (int)(size_t)HEXDSP(hx_mba_t_analyze_calls, this, acflags);
}

//--------------------------------------------------------------------------
inline merror_t mba_t::optimize_global(void)
{
  return (merror_t)(size_t)HEXDSP(hx_mba_t_optimize_global, this);
}

//--------------------------------------------------------------------------
inline void mba_t::alloc_lvars(void)
{
  HEXDSP(hx_mba_t_alloc_lvars, this);
}

//--------------------------------------------------------------------------
inline void mba_t::dump(void) const
{
  HEXDSP(hx_mba_t_dump, this);
}

//--------------------------------------------------------------------------
inline AS_PRINTF(3, 0) void mba_t::vdump_mba(bool _verify, const char *title, va_list va) const
{
  HEXDSP(hx_mba_t_vdump_mba, this, _verify, title, va);
}

//--------------------------------------------------------------------------
inline void mba_t::print(vd_printer_t &vp) const
{
  HEXDSP(hx_mba_t_print, this, &vp);
}

//--------------------------------------------------------------------------
inline void mba_t::verify(bool always) const
{
  HEXDSP(hx_mba_t_verify, this, always);
}

//--------------------------------------------------------------------------
inline void mba_t::mark_chains_dirty(void)
{
  HEXDSP(hx_mba_t_mark_chains_dirty, this);
}

//--------------------------------------------------------------------------
inline mblock_t *mba_t::insert_block(int bblk)
{
  return (mblock_t *)HEXDSP(hx_mba_t_insert_block, this, bblk);
}

//--------------------------------------------------------------------------
inline bool mba_t::remove_block(mblock_t *blk)
{
  return (uchar)(size_t)HEXDSP(hx_mba_t_remove_block, this, blk) != 0;
}

//--------------------------------------------------------------------------
inline mblock_t *mba_t::copy_block(mblock_t *blk, int new_serial, int cpblk_flags)
{
  return (mblock_t *)HEXDSP(hx_mba_t_copy_block, this, blk, new_serial, cpblk_flags);
}

//--------------------------------------------------------------------------
inline bool mba_t::remove_empty_and_unreachable_blocks(void)
{
  return (uchar)(size_t)HEXDSP(hx_mba_t_remove_empty_and_unreachable_blocks, this) != 0;
}

//--------------------------------------------------------------------------
inline bool mba_t::combine_blocks(void)
{
  return (uchar)(size_t)HEXDSP(hx_mba_t_combine_blocks, this) != 0;
}

//--------------------------------------------------------------------------
inline int mba_t::for_all_ops(mop_visitor_t &mv)
{
  return (int)(size_t)HEXDSP(hx_mba_t_for_all_ops, this, &mv);
}

//--------------------------------------------------------------------------
inline int mba_t::for_all_insns(minsn_visitor_t &mv)
{
  return (int)(size_t)HEXDSP(hx_mba_t_for_all_insns, this, &mv);
}

//--------------------------------------------------------------------------
inline int mba_t::for_all_topinsns(minsn_visitor_t &mv)
{
  return (int)(size_t)HEXDSP(hx_mba_t_for_all_topinsns, this, &mv);
}

//--------------------------------------------------------------------------
inline mop_t *mba_t::find_mop(op_parent_info_t *ctx, ea_t ea, bool is_dest, const mlist_t &list)
{
  return (mop_t *)HEXDSP(hx_mba_t_find_mop, this, ctx, ea, is_dest, &list);
}

//--------------------------------------------------------------------------
inline minsn_t *mba_t::create_helper_call(ea_t ea, const char *helper, const tinfo_t *rettype, const mcallargs_t *callargs, const mop_t *out)
{
  return (minsn_t *)HEXDSP(hx_mba_t_create_helper_call, this, ea, helper, rettype, callargs, out);
}

//--------------------------------------------------------------------------
inline void mba_t::get_func_output_lists(mlist_t *return_regs, mlist_t *spoiled, const tinfo_t &type, ea_t call_ea, bool tail_call)
{
  HEXDSP(hx_mba_t_get_func_output_lists, this, return_regs, spoiled, &type, call_ea, tail_call);
}

//--------------------------------------------------------------------------
inline lvar_t &mba_t::arg(int n)
{
  return *(lvar_t *)HEXDSP(hx_mba_t_arg, this, n);
}

//--------------------------------------------------------------------------
inline ea_t mba_t::alloc_fict_ea(ea_t real_ea)
{
  ea_t retval;
  HEXDSP(hx_mba_t_alloc_fict_ea, &retval, this, real_ea);
  return retval;
}

//--------------------------------------------------------------------------
inline ea_t mba_t::map_fict_ea(ea_t fict_ea) const
{
  ea_t retval;
  HEXDSP(hx_mba_t_map_fict_ea, &retval, this, fict_ea);
  return retval;
}

//--------------------------------------------------------------------------
inline void mba_t::serialize(bytevec_t &vout) const
{
  HEXDSP(hx_mba_t_serialize, this, &vout);
}

//--------------------------------------------------------------------------
inline WARN_UNUSED_RESULT mba_t *mba_t::deserialize(const uchar *bytes, size_t nbytes)
{
  return (mba_t *)HEXDSP(hx_mba_t_deserialize, bytes, nbytes);
}

//--------------------------------------------------------------------------
inline void mba_t::save_snapshot(const char *description)
{
  HEXDSP(hx_mba_t_save_snapshot, this, description);
}

//--------------------------------------------------------------------------
inline mreg_t mba_t::alloc_kreg(size_t size, bool check_size)
{
  return (mreg_t)(size_t)HEXDSP(hx_mba_t_alloc_kreg, this, size, check_size);
}

//--------------------------------------------------------------------------
inline void mba_t::free_kreg(mreg_t reg, size_t size)
{
  HEXDSP(hx_mba_t_free_kreg, this, reg, size);
}

//--------------------------------------------------------------------------
inline bool mba_t::set_lvar_name(lvar_t &v, const char *name, int flagbits)
{
  return (uchar)(size_t)HEXDSP(hx_mba_t_set_lvar_name, this, &v, name, flagbits) != 0;
}

//--------------------------------------------------------------------------
inline bool mbl_graph_t::is_accessed_globally(const mlist_t &list, int b1, int b2, const minsn_t *m1, const minsn_t *m2, access_type_t access_type, maymust_t maymust) const
{
  return (uchar)(size_t)HEXDSP(hx_mbl_graph_t_is_accessed_globally, this, &list, b1, b2, m1, m2, access_type, maymust) != 0;
}

//--------------------------------------------------------------------------
inline graph_chains_t *mbl_graph_t::get_ud(gctype_t gctype)
{
  return (graph_chains_t *)HEXDSP(hx_mbl_graph_t_get_ud, this, gctype);
}

//--------------------------------------------------------------------------
inline graph_chains_t *mbl_graph_t::get_du(gctype_t gctype)
{
  return (graph_chains_t *)HEXDSP(hx_mbl_graph_t_get_du, this, gctype);
}

//--------------------------------------------------------------------------
inline merror_t cdg_insn_iterator_t::next(insn_t *ins)
{
  return (merror_t)(size_t)HEXDSP(hx_cdg_insn_iterator_t_next, this, ins);
}

//--------------------------------------------------------------------------
inline minsn_t *codegen_t::emit(mcode_t code, int width, uval_t l, uval_t r, uval_t d, int offsize)
{
  return (minsn_t *)HEXDSP(hx_codegen_t_emit, this, code, width, l, r, d, offsize);
}

//--------------------------------------------------------------------------
inline minsn_t *codegen_t::emit(mcode_t code, const mop_t *l, const mop_t *r, const mop_t *d)
{
  return (minsn_t *)HEXDSP(hx_codegen_t_emit_, this, code, l, r, d);
}

//--------------------------------------------------------------------------
inline bool change_hexrays_config(const char *directive)
{
  return (uchar)(size_t)HEXDSP(hx_change_hexrays_config, directive) != 0;
}

//--------------------------------------------------------------------------
inline const char *get_hexrays_version(void)
{
  return (const char *)HEXDSP(hx_get_hexrays_version);
}

//--------------------------------------------------------------------------
inline bool checkout_hexrays_license(bool silent)
{
  return (uchar)(size_t)HEXDSP(hx_checkout_hexrays_license, silent) != 0;
}

//--------------------------------------------------------------------------
inline vdui_t *open_pseudocode(ea_t ea, int flags)
{
  return (vdui_t *)HEXDSP(hx_open_pseudocode, ea, flags);
}

//--------------------------------------------------------------------------
inline bool close_pseudocode(TWidget *f)
{
  return (uchar)(size_t)HEXDSP(hx_close_pseudocode, f) != 0;
}

//--------------------------------------------------------------------------
inline vdui_t *get_widget_vdui(TWidget *f)
{
  return (vdui_t *)HEXDSP(hx_get_widget_vdui, f);
}

//--------------------------------------------------------------------------
inline bool decompile_many(const char *outfile, const eavec_t *funcaddrs, int flags)
{
  return (uchar)(size_t)HEXDSP(hx_decompile_many, outfile, funcaddrs, flags) != 0;
}

//--------------------------------------------------------------------------
inline qstring hexrays_failure_t::desc(void) const
{
  qstring retval;
  HEXDSP(hx_hexrays_failure_t_desc, &retval, this);
  return retval;
}

//--------------------------------------------------------------------------
inline void send_database(const hexrays_failure_t &err, bool silent)
{
  HEXDSP(hx_send_database, &err, silent);
}

//--------------------------------------------------------------------------
inline bool gco_info_t::append_to_list(mlist_t *list, const mba_t *mba) const
{
  return (uchar)(size_t)HEXDSP(hx_gco_info_t_append_to_list, this, list, mba) != 0;
}

//--------------------------------------------------------------------------
inline bool get_current_operand(gco_info_t *out)
{
  return (uchar)(size_t)HEXDSP(hx_get_current_operand, out) != 0;
}

//--------------------------------------------------------------------------
inline void remitem(const citem_t *e)
{
  HEXDSP(hx_remitem, e);
}

//--------------------------------------------------------------------------
inline ctype_t negated_relation(ctype_t op)
{
  return (ctype_t)(size_t)HEXDSP(hx_negated_relation, op);
}

//--------------------------------------------------------------------------
inline ctype_t swapped_relation(ctype_t op)
{
  return (ctype_t)(size_t)HEXDSP(hx_swapped_relation, op);
}

//--------------------------------------------------------------------------
inline type_sign_t get_op_signness(ctype_t op)
{
  return (type_sign_t)(size_t)HEXDSP(hx_get_op_signness, op);
}

//--------------------------------------------------------------------------
inline ctype_t asgop(ctype_t cop)
{
  return (ctype_t)(size_t)HEXDSP(hx_asgop, cop);
}

//--------------------------------------------------------------------------
inline ctype_t asgop_revert(ctype_t cop)
{
  return (ctype_t)(size_t)HEXDSP(hx_asgop_revert, cop);
}

//--------------------------------------------------------------------------
inline void cnumber_t::print(qstring *vout, const tinfo_t &type, const citem_t *parent, bool *nice_stroff) const
{
  HEXDSP(hx_cnumber_t_print, this, vout, &type, parent, nice_stroff);
}

//--------------------------------------------------------------------------
inline uint64 cnumber_t::value(const tinfo_t &type) const
{
  uint64 retval;
  HEXDSP(hx_cnumber_t_value, &retval, this, &type);
  return retval;
}

//--------------------------------------------------------------------------
inline void cnumber_t::assign(uint64 v, int nbytes, type_sign_t sign)
{
  HEXDSP(hx_cnumber_t_assign, this, v, nbytes, sign);
}

//--------------------------------------------------------------------------
inline int cnumber_t::compare(const cnumber_t &r) const
{
  return (int)(size_t)HEXDSP(hx_cnumber_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int var_ref_t::compare(const var_ref_t &r) const
{
  return (int)(size_t)HEXDSP(hx_var_ref_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int ctree_visitor_t::apply_to(citem_t *item, citem_t *parent)
{
  return (int)(size_t)HEXDSP(hx_ctree_visitor_t_apply_to, this, item, parent);
}

//--------------------------------------------------------------------------
inline int ctree_visitor_t::apply_to_exprs(citem_t *item, citem_t *parent)
{
  return (int)(size_t)HEXDSP(hx_ctree_visitor_t_apply_to_exprs, this, item, parent);
}

//--------------------------------------------------------------------------
inline bool ctree_parentee_t::recalc_parent_types(void)
{
  return (uchar)(size_t)HEXDSP(hx_ctree_parentee_t_recalc_parent_types, this) != 0;
}

//--------------------------------------------------------------------------
inline bool cfunc_parentee_t::calc_rvalue_type(tinfo_t *target, const cexpr_t *e)
{
  return (uchar)(size_t)HEXDSP(hx_cfunc_parentee_t_calc_rvalue_type, this, target, e) != 0;
}

//--------------------------------------------------------------------------
inline int citem_locator_t::compare(const citem_locator_t &r) const
{
  return (int)(size_t)HEXDSP(hx_citem_locator_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline bool citem_t::contains_expr(const cexpr_t *e) const
{
  return (uchar)(size_t)HEXDSP(hx_citem_t_contains_expr, this, e) != 0;
}

//--------------------------------------------------------------------------
inline bool citem_t::contains_label(void) const
{
  return (uchar)(size_t)HEXDSP(hx_citem_t_contains_label, this) != 0;
}

//--------------------------------------------------------------------------
inline const citem_t *citem_t::find_parent_of(const citem_t *sitem) const
{
  return (const citem_t *)HEXDSP(hx_citem_t_find_parent_of, this, sitem);
}

//--------------------------------------------------------------------------
inline citem_t *citem_t::find_closest_addr(ea_t _ea)
{
  return (citem_t *)HEXDSP(hx_citem_t_find_closest_addr, this, _ea);
}

//--------------------------------------------------------------------------
inline cexpr_t &cexpr_t::assign(const cexpr_t &r)
{
  return *(cexpr_t *)HEXDSP(hx_cexpr_t_assign, this, &r);
}

//--------------------------------------------------------------------------
inline int cexpr_t::compare(const cexpr_t &r) const
{
  return (int)(size_t)HEXDSP(hx_cexpr_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline void cexpr_t::replace_by(cexpr_t *r)
{
  HEXDSP(hx_cexpr_t_replace_by, this, r);
}

//--------------------------------------------------------------------------
inline void cexpr_t::cleanup(void)
{
  HEXDSP(hx_cexpr_t_cleanup, this);
}

//--------------------------------------------------------------------------
inline void cexpr_t::put_number(cfunc_t *func, uint64 value, int nbytes, type_sign_t sign)
{
  HEXDSP(hx_cexpr_t_put_number, this, func, value, nbytes, sign);
}

//--------------------------------------------------------------------------
inline void cexpr_t::print1(qstring *vout, const cfunc_t *func) const
{
  HEXDSP(hx_cexpr_t_print1, this, vout, func);
}

//--------------------------------------------------------------------------
inline void cexpr_t::calc_type(bool recursive)
{
  HEXDSP(hx_cexpr_t_calc_type, this, recursive);
}

//--------------------------------------------------------------------------
inline bool cexpr_t::equal_effect(const cexpr_t &r) const
{
  return (uchar)(size_t)HEXDSP(hx_cexpr_t_equal_effect, this, &r) != 0;
}

//--------------------------------------------------------------------------
inline bool cexpr_t::is_child_of(const citem_t *parent) const
{
  return (uchar)(size_t)HEXDSP(hx_cexpr_t_is_child_of, this, parent) != 0;
}

//--------------------------------------------------------------------------
inline bool cexpr_t::contains_operator(ctype_t needed_op, int times) const
{
  return (uchar)(size_t)HEXDSP(hx_cexpr_t_contains_operator, this, needed_op, times) != 0;
}

//--------------------------------------------------------------------------
inline bit_bound_t cexpr_t::get_high_nbit_bound(void) const
{
  bit_bound_t retval;
  HEXDSP(hx_cexpr_t_get_high_nbit_bound, &retval, this);
  return retval;
}

//--------------------------------------------------------------------------
inline int cexpr_t::get_low_nbit_bound(void) const
{
  return (int)(size_t)HEXDSP(hx_cexpr_t_get_low_nbit_bound, this);
}

//--------------------------------------------------------------------------
inline bool cexpr_t::requires_lvalue(const cexpr_t *child) const
{
  return (uchar)(size_t)HEXDSP(hx_cexpr_t_requires_lvalue, this, child) != 0;
}

//--------------------------------------------------------------------------
inline bool cexpr_t::has_side_effects(void) const
{
  return (uchar)(size_t)HEXDSP(hx_cexpr_t_has_side_effects, this) != 0;
}

//--------------------------------------------------------------------------
inline bool cexpr_t::maybe_ptr(void) const
{
  return (uchar)(size_t)HEXDSP(hx_cexpr_t_maybe_ptr, this) != 0;
}

//--------------------------------------------------------------------------
inline const char *cexpr_t::dstr(void) const
{
  return (const char *)HEXDSP(hx_cexpr_t_dstr, this);
}

//--------------------------------------------------------------------------
inline cif_t &cif_t::assign(const cif_t &r)
{
  return *(cif_t *)HEXDSP(hx_cif_t_assign, this, &r);
}

//--------------------------------------------------------------------------
inline int cif_t::compare(const cif_t &r) const
{
  return (int)(size_t)HEXDSP(hx_cif_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline cloop_t &cloop_t::assign(const cloop_t &r)
{
  return *(cloop_t *)HEXDSP(hx_cloop_t_assign, this, &r);
}

//--------------------------------------------------------------------------
inline int cfor_t::compare(const cfor_t &r) const
{
  return (int)(size_t)HEXDSP(hx_cfor_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int cwhile_t::compare(const cwhile_t &r) const
{
  return (int)(size_t)HEXDSP(hx_cwhile_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int cdo_t::compare(const cdo_t &r) const
{
  return (int)(size_t)HEXDSP(hx_cdo_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int creturn_t::compare(const creturn_t &r) const
{
  return (int)(size_t)HEXDSP(hx_creturn_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int cgoto_t::compare(const cgoto_t &r) const
{
  return (int)(size_t)HEXDSP(hx_cgoto_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int casm_t::compare(const casm_t &r) const
{
  return (int)(size_t)HEXDSP(hx_casm_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline cinsn_t &cinsn_t::assign(const cinsn_t &r)
{
  return *(cinsn_t *)HEXDSP(hx_cinsn_t_assign, this, &r);
}

//--------------------------------------------------------------------------
inline int cinsn_t::compare(const cinsn_t &r) const
{
  return (int)(size_t)HEXDSP(hx_cinsn_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline void cinsn_t::replace_by(cinsn_t *r)
{
  HEXDSP(hx_cinsn_t_replace_by, this, r);
}

//--------------------------------------------------------------------------
inline void cinsn_t::cleanup(void)
{
  HEXDSP(hx_cinsn_t_cleanup, this);
}

//--------------------------------------------------------------------------
inline cinsn_t &cinsn_t::new_insn(ea_t insn_ea)
{
  return *(cinsn_t *)HEXDSP(hx_cinsn_t_new_insn, this, insn_ea);
}

//--------------------------------------------------------------------------
inline cif_t &cinsn_t::create_if(cexpr_t *cnd)
{
  return *(cif_t *)HEXDSP(hx_cinsn_t_create_if, this, cnd);
}

//--------------------------------------------------------------------------
inline void cinsn_t::print(int indent, vc_printer_t &vp, use_curly_t use_curly) const
{
  HEXDSP(hx_cinsn_t_print, this, indent, &vp, use_curly);
}

//--------------------------------------------------------------------------
inline void cinsn_t::print1(qstring *vout, const cfunc_t *func) const
{
  HEXDSP(hx_cinsn_t_print1, this, vout, func);
}

//--------------------------------------------------------------------------
inline bool cinsn_t::is_ordinary_flow(void) const
{
  return (uchar)(size_t)HEXDSP(hx_cinsn_t_is_ordinary_flow, this) != 0;
}

//--------------------------------------------------------------------------
inline bool cinsn_t::contains_insn(ctype_t type, int times) const
{
  return (uchar)(size_t)HEXDSP(hx_cinsn_t_contains_insn, this, type, times) != 0;
}

//--------------------------------------------------------------------------
inline bool cinsn_t::collect_free_breaks(cinsnptrvec_t *breaks)
{
  return (uchar)(size_t)HEXDSP(hx_cinsn_t_collect_free_breaks, this, breaks) != 0;
}

//--------------------------------------------------------------------------
inline bool cinsn_t::collect_free_continues(cinsnptrvec_t *continues)
{
  return (uchar)(size_t)HEXDSP(hx_cinsn_t_collect_free_continues, this, continues) != 0;
}

//--------------------------------------------------------------------------
inline const char *cinsn_t::dstr(void) const
{
  return (const char *)HEXDSP(hx_cinsn_t_dstr, this);
}

//--------------------------------------------------------------------------
inline int cblock_t::compare(const cblock_t &r) const
{
  return (int)(size_t)HEXDSP(hx_cblock_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int carglist_t::compare(const carglist_t &r) const
{
  return (int)(size_t)HEXDSP(hx_carglist_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int ccase_t::compare(const ccase_t &r) const
{
  return (int)(size_t)HEXDSP(hx_ccase_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int ccases_t::compare(const ccases_t &r) const
{
  return (int)(size_t)HEXDSP(hx_ccases_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int cswitch_t::compare(const cswitch_t &r) const
{
  return (int)(size_t)HEXDSP(hx_cswitch_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline member_t *ctree_item_t::get_memptr(struc_t **p_sptr) const
{
  return (member_t *)HEXDSP(hx_ctree_item_t_get_memptr, this, p_sptr);
}

//--------------------------------------------------------------------------
inline lvar_t *ctree_item_t::get_lvar(void) const
{
  return (lvar_t *)HEXDSP(hx_ctree_item_t_get_lvar, this);
}

//--------------------------------------------------------------------------
inline ea_t ctree_item_t::get_ea(void) const
{
  ea_t retval;
  HEXDSP(hx_ctree_item_t_get_ea, &retval, this);
  return retval;
}

//--------------------------------------------------------------------------
inline int ctree_item_t::get_label_num(int gln_flags) const
{
  return (int)(size_t)HEXDSP(hx_ctree_item_t_get_label_num, this, gln_flags);
}

//--------------------------------------------------------------------------
inline void ctree_item_t::print(qstring *vout) const
{
  HEXDSP(hx_ctree_item_t_print, this, vout);
}

//--------------------------------------------------------------------------
inline const char *ctree_item_t::dstr(void) const
{
  return (const char *)HEXDSP(hx_ctree_item_t_dstr, this);
}

//--------------------------------------------------------------------------
inline cexpr_t *lnot(cexpr_t *e)
{
  return (cexpr_t *)HEXDSP(hx_lnot, e);
}

//--------------------------------------------------------------------------
inline cinsn_t *new_block(void)
{
  return (cinsn_t *)HEXDSP(hx_new_block);
}

//--------------------------------------------------------------------------
inline AS_PRINTF(3, 0) cexpr_t *vcreate_helper(bool standalone, const tinfo_t &type, const char *format, va_list va)
{
  return (cexpr_t *)HEXDSP(hx_vcreate_helper, standalone, &type, format, va);
}

//--------------------------------------------------------------------------
inline AS_PRINTF(3, 0) cexpr_t *vcall_helper(const tinfo_t &rettype, carglist_t *args, const char *format, va_list va)
{
  return (cexpr_t *)HEXDSP(hx_vcall_helper, &rettype, args, format, va);
}

//--------------------------------------------------------------------------
inline cexpr_t *make_num(uint64 n, cfunc_t *func, ea_t ea, int opnum, type_sign_t sign, int size)
{
  return (cexpr_t *)HEXDSP(hx_make_num, n, func, ea, opnum, sign, size);
}

//--------------------------------------------------------------------------
inline cexpr_t *make_ref(cexpr_t *e)
{
  return (cexpr_t *)HEXDSP(hx_make_ref, e);
}

//--------------------------------------------------------------------------
inline cexpr_t *dereference(cexpr_t *e, int ptrsize, bool is_flt)
{
  return (cexpr_t *)HEXDSP(hx_dereference, e, ptrsize, is_flt);
}

//--------------------------------------------------------------------------
inline void save_user_labels(ea_t func_ea, const user_labels_t *user_labels)
{
  HEXDSP(hx_save_user_labels, func_ea, user_labels);
}

//--------------------------------------------------------------------------
inline void save_user_labels2(ea_t func_ea, const user_labels_t *user_labels, const cfunc_t *func)
{
  HEXDSP(hx_save_user_labels2, func_ea, user_labels, func);
}

//--------------------------------------------------------------------------
inline void save_user_cmts(ea_t func_ea, const user_cmts_t *user_cmts)
{
  HEXDSP(hx_save_user_cmts, func_ea, user_cmts);
}

//--------------------------------------------------------------------------
inline void save_user_numforms(ea_t func_ea, const user_numforms_t *numforms)
{
  HEXDSP(hx_save_user_numforms, func_ea, numforms);
}

//--------------------------------------------------------------------------
inline void save_user_iflags(ea_t func_ea, const user_iflags_t *iflags)
{
  HEXDSP(hx_save_user_iflags, func_ea, iflags);
}

//--------------------------------------------------------------------------
inline void save_user_unions(ea_t func_ea, const user_unions_t *unions)
{
  HEXDSP(hx_save_user_unions, func_ea, unions);
}

//--------------------------------------------------------------------------
inline user_labels_t *restore_user_labels(ea_t func_ea)
{
  return (user_labels_t *)HEXDSP(hx_restore_user_labels, func_ea);
}

//--------------------------------------------------------------------------
inline user_labels_t *restore_user_labels2(ea_t func_ea, const cfunc_t *func)
{
  return (user_labels_t *)HEXDSP(hx_restore_user_labels2, func_ea, func);
}

//--------------------------------------------------------------------------
inline user_cmts_t *restore_user_cmts(ea_t func_ea)
{
  return (user_cmts_t *)HEXDSP(hx_restore_user_cmts, func_ea);
}

//--------------------------------------------------------------------------
inline user_numforms_t *restore_user_numforms(ea_t func_ea)
{
  return (user_numforms_t *)HEXDSP(hx_restore_user_numforms, func_ea);
}

//--------------------------------------------------------------------------
inline user_iflags_t *restore_user_iflags(ea_t func_ea)
{
  return (user_iflags_t *)HEXDSP(hx_restore_user_iflags, func_ea);
}

//--------------------------------------------------------------------------
inline user_unions_t *restore_user_unions(ea_t func_ea)
{
  return (user_unions_t *)HEXDSP(hx_restore_user_unions, func_ea);
}

//--------------------------------------------------------------------------
inline void cfunc_t::build_c_tree(void)
{
  HEXDSP(hx_cfunc_t_build_c_tree, this);
}

//--------------------------------------------------------------------------
inline void cfunc_t::verify(allow_unused_labels_t aul, bool even_without_debugger) const
{
  HEXDSP(hx_cfunc_t_verify, this, aul, even_without_debugger);
}

//--------------------------------------------------------------------------
inline void cfunc_t::print_dcl(qstring *vout) const
{
  HEXDSP(hx_cfunc_t_print_dcl, this, vout);
}

//--------------------------------------------------------------------------
inline void cfunc_t::print_func(vc_printer_t &vp) const
{
  HEXDSP(hx_cfunc_t_print_func, this, &vp);
}

//--------------------------------------------------------------------------
inline bool cfunc_t::get_func_type(tinfo_t *type) const
{
  return (uchar)(size_t)HEXDSP(hx_cfunc_t_get_func_type, this, type) != 0;
}

//--------------------------------------------------------------------------
inline lvars_t *cfunc_t::get_lvars(void)
{
  return (lvars_t *)HEXDSP(hx_cfunc_t_get_lvars, this);
}

//--------------------------------------------------------------------------
inline sval_t cfunc_t::get_stkoff_delta(void)
{
  sval_t retval;
  HEXDSP(hx_cfunc_t_get_stkoff_delta, &retval, this);
  return retval;
}

//--------------------------------------------------------------------------
inline citem_t *cfunc_t::find_label(int label)
{
  return (citem_t *)HEXDSP(hx_cfunc_t_find_label, this, label);
}

//--------------------------------------------------------------------------
inline void cfunc_t::remove_unused_labels(void)
{
  HEXDSP(hx_cfunc_t_remove_unused_labels, this);
}

//--------------------------------------------------------------------------
inline const char *cfunc_t::get_user_cmt(const treeloc_t &loc, cmt_retrieval_type_t rt) const
{
  return (const char *)HEXDSP(hx_cfunc_t_get_user_cmt, this, &loc, rt);
}

//--------------------------------------------------------------------------
inline void cfunc_t::set_user_cmt(const treeloc_t &loc, const char *cmt)
{
  HEXDSP(hx_cfunc_t_set_user_cmt, this, &loc, cmt);
}

//--------------------------------------------------------------------------
inline int32 cfunc_t::get_user_iflags(const citem_locator_t &loc) const
{
  return (int32)(size_t)HEXDSP(hx_cfunc_t_get_user_iflags, this, &loc);
}

//--------------------------------------------------------------------------
inline void cfunc_t::set_user_iflags(const citem_locator_t &loc, int32 iflags)
{
  HEXDSP(hx_cfunc_t_set_user_iflags, this, &loc, iflags);
}

//--------------------------------------------------------------------------
inline bool cfunc_t::has_orphan_cmts(void) const
{
  return (uchar)(size_t)HEXDSP(hx_cfunc_t_has_orphan_cmts, this) != 0;
}

//--------------------------------------------------------------------------
inline int cfunc_t::del_orphan_cmts(void)
{
  return (int)(size_t)HEXDSP(hx_cfunc_t_del_orphan_cmts, this);
}

//--------------------------------------------------------------------------
inline bool cfunc_t::get_user_union_selection(ea_t ea, intvec_t *path)
{
  return (uchar)(size_t)HEXDSP(hx_cfunc_t_get_user_union_selection, this, ea, path) != 0;
}

//--------------------------------------------------------------------------
inline void cfunc_t::set_user_union_selection(ea_t ea, const intvec_t &path)
{
  HEXDSP(hx_cfunc_t_set_user_union_selection, this, ea, &path);
}

//--------------------------------------------------------------------------
inline void cfunc_t::save_user_labels(void) const
{
  HEXDSP(hx_cfunc_t_save_user_labels, this);
}

//--------------------------------------------------------------------------
inline void cfunc_t::save_user_cmts(void) const
{
  HEXDSP(hx_cfunc_t_save_user_cmts, this);
}

//--------------------------------------------------------------------------
inline void cfunc_t::save_user_numforms(void) const
{
  HEXDSP(hx_cfunc_t_save_user_numforms, this);
}

//--------------------------------------------------------------------------
inline void cfunc_t::save_user_iflags(void) const
{
  HEXDSP(hx_cfunc_t_save_user_iflags, this);
}

//--------------------------------------------------------------------------
inline void cfunc_t::save_user_unions(void) const
{
  HEXDSP(hx_cfunc_t_save_user_unions, this);
}

//--------------------------------------------------------------------------
inline bool cfunc_t::get_line_item(const char *line, int x, bool is_ctree_line, ctree_item_t *phead, ctree_item_t *pitem, ctree_item_t *ptail)
{
  return (uchar)(size_t)HEXDSP(hx_cfunc_t_get_line_item, this, line, x, is_ctree_line, phead, pitem, ptail) != 0;
}

//--------------------------------------------------------------------------
inline hexwarns_t &cfunc_t::get_warnings(void)
{
  return *(hexwarns_t *)HEXDSP(hx_cfunc_t_get_warnings, this);
}

//--------------------------------------------------------------------------
inline eamap_t &cfunc_t::get_eamap(void)
{
  return *(eamap_t *)HEXDSP(hx_cfunc_t_get_eamap, this);
}

//--------------------------------------------------------------------------
inline boundaries_t &cfunc_t::get_boundaries(void)
{
  return *(boundaries_t *)HEXDSP(hx_cfunc_t_get_boundaries, this);
}

//--------------------------------------------------------------------------
inline const strvec_t &cfunc_t::get_pseudocode(void)
{
  return *(const strvec_t *)HEXDSP(hx_cfunc_t_get_pseudocode, this);
}

//--------------------------------------------------------------------------
inline void cfunc_t::refresh_func_ctext(void)
{
  HEXDSP(hx_cfunc_t_refresh_func_ctext, this);
}

//--------------------------------------------------------------------------
inline bool cfunc_t::gather_derefs(const ctree_item_t &ci, udt_type_data_t *udm) const
{
  return (uchar)(size_t)HEXDSP(hx_cfunc_t_gather_derefs, this, &ci, udm) != 0;
}

//--------------------------------------------------------------------------
inline bool cfunc_t::find_item_coords(const citem_t *item, int *px, int *py)
{
  return (uchar)(size_t)HEXDSP(hx_cfunc_t_find_item_coords, this, item, px, py) != 0;
}

//--------------------------------------------------------------------------
inline void cfunc_t::cleanup(void)
{
  HEXDSP(hx_cfunc_t_cleanup, this);
}

//--------------------------------------------------------------------------
inline void close_hexrays_waitbox(void)
{
  HEXDSP(hx_close_hexrays_waitbox);
}

//--------------------------------------------------------------------------
inline cfuncptr_t decompile(const mba_ranges_t &mbr, hexrays_failure_t *hf, int decomp_flags)
{
  return cfuncptr_t((cfunc_t *)HEXDSP(hx_decompile, &mbr, hf, decomp_flags));
}

//--------------------------------------------------------------------------
inline mba_t *gen_microcode(const mba_ranges_t &mbr, hexrays_failure_t *hf, const mlist_t *retlist, int decomp_flags, mba_maturity_t reqmat)
{
  return (mba_t *)HEXDSP(hx_gen_microcode, &mbr, hf, retlist, decomp_flags, reqmat);
}

//--------------------------------------------------------------------------
inline cfuncptr_t create_cfunc(mba_t *mba)
{
  return cfuncptr_t((cfunc_t *)HEXDSP(hx_create_cfunc, mba));
}

//--------------------------------------------------------------------------
inline bool mark_cfunc_dirty(ea_t ea, bool close_views)
{
  return (uchar)(size_t)HEXDSP(hx_mark_cfunc_dirty, ea, close_views) != 0;
}

//--------------------------------------------------------------------------
inline void clear_cached_cfuncs(void)
{
  HEXDSP(hx_clear_cached_cfuncs);
}

//--------------------------------------------------------------------------
inline bool has_cached_cfunc(ea_t ea)
{
  return (uchar)(size_t)HEXDSP(hx_has_cached_cfunc, ea) != 0;
}

//--------------------------------------------------------------------------
inline const char *get_ctype_name(ctype_t op)
{
  return (const char *)HEXDSP(hx_get_ctype_name, op);
}

//--------------------------------------------------------------------------
inline qstring create_field_name(const tinfo_t &type, uval_t offset)
{
  qstring retval;
  HEXDSP(hx_create_field_name, &retval, &type, offset);
  return retval;
}

//--------------------------------------------------------------------------
inline bool install_hexrays_callback(hexrays_cb_t *callback, void *ud)
{
  return (uchar)(size_t)HEXDSP(hx_install_hexrays_callback, callback, ud) != 0;
}

//--------------------------------------------------------------------------
inline int remove_hexrays_callback(hexrays_cb_t *callback, void *ud)
{
  auto hrdsp = HEXDSP;
  return hrdsp == nullptr ? 0 : (int)(size_t)hrdsp(hx_remove_hexrays_callback, callback, ud);
}

//--------------------------------------------------------------------------
inline bool vdui_t::set_locked(bool v)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_set_locked, this, v) != 0;
}

//--------------------------------------------------------------------------
inline void vdui_t::refresh_view(bool redo_mba)
{
  HEXDSP(hx_vdui_t_refresh_view, this, redo_mba);
}

//--------------------------------------------------------------------------
inline void vdui_t::refresh_ctext(bool activate)
{
  HEXDSP(hx_vdui_t_refresh_ctext, this, activate);
}

//--------------------------------------------------------------------------
inline void vdui_t::switch_to(cfuncptr_t f, bool activate)
{
  HEXDSP(hx_vdui_t_switch_to, this, &f, activate);
}

//--------------------------------------------------------------------------
inline cnumber_t *vdui_t::get_number(void)
{
  return (cnumber_t *)HEXDSP(hx_vdui_t_get_number, this);
}

//--------------------------------------------------------------------------
inline int vdui_t::get_current_label(void)
{
  return (int)(size_t)HEXDSP(hx_vdui_t_get_current_label, this);
}

//--------------------------------------------------------------------------
inline void vdui_t::clear(void)
{
  HEXDSP(hx_vdui_t_clear, this);
}

//--------------------------------------------------------------------------
inline bool vdui_t::refresh_cpos(input_device_t idv)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_refresh_cpos, this, idv) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::get_current_item(input_device_t idv)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_get_current_item, this, idv) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::ui_rename_lvar(lvar_t *v)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_ui_rename_lvar, this, v) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::rename_lvar(lvar_t *v, const char *name, bool is_user_name)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_rename_lvar, this, v, name, is_user_name) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::ui_set_call_type(const cexpr_t *e)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_ui_set_call_type, this, e) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::ui_set_lvar_type(lvar_t *v)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_ui_set_lvar_type, this, v) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::set_lvar_type(lvar_t *v, const tinfo_t &type)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_set_lvar_type, this, v, &type) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::set_noptr_lvar(lvar_t *v)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_set_noptr_lvar, this, v) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::ui_edit_lvar_cmt(lvar_t *v)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_ui_edit_lvar_cmt, this, v) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::set_lvar_cmt(lvar_t *v, const char *cmt)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_set_lvar_cmt, this, v, cmt) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::ui_map_lvar(lvar_t *v)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_ui_map_lvar, this, v) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::ui_unmap_lvar(lvar_t *v)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_ui_unmap_lvar, this, v) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::map_lvar(lvar_t *from, lvar_t *to)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_map_lvar, this, from, to) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::set_strmem_type(struc_t *sptr, member_t *mptr)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_set_strmem_type, this, sptr, mptr) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::rename_strmem(struc_t *sptr, member_t *mptr)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_rename_strmem, this, sptr, mptr) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::set_global_type(ea_t ea)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_set_global_type, this, ea) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::rename_global(ea_t ea)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_rename_global, this, ea) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::rename_label(int label)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_rename_label, this, label) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::jump_enter(input_device_t idv, int omflags)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_jump_enter, this, idv, omflags) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::ctree_to_disasm(void)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_ctree_to_disasm, this) != 0;
}

//--------------------------------------------------------------------------
inline cmt_type_t vdui_t::calc_cmt_type(size_t lnnum, cmt_type_t cmttype) const
{
  return (cmt_type_t)(size_t)HEXDSP(hx_vdui_t_calc_cmt_type, this, lnnum, cmttype);
}

//--------------------------------------------------------------------------
inline bool vdui_t::edit_cmt(const treeloc_t &loc)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_edit_cmt, this, &loc) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::edit_func_cmt(void)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_edit_func_cmt, this) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::del_orphan_cmts(void)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_del_orphan_cmts, this) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::set_num_radix(int base)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_set_num_radix, this, base) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::set_num_enum(void)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_set_num_enum, this) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::set_num_stroff(void)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_set_num_stroff, this) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::invert_sign(void)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_invert_sign, this) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::invert_bits(void)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_invert_bits, this) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::collapse_item(bool hide)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_collapse_item, this, hide) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::collapse_lvars(bool hide)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_collapse_lvars, this, hide) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::split_item(bool split)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_split_item, this, split) != 0;
}

//--------------------------------------------------------------------------
inline int select_udt_by_offset(const qvector<tinfo_t> *udts, const ui_stroff_ops_t &ops, ui_stroff_applicator_t &applicator)
{
  return (int)(size_t)HEXDSP(hx_select_udt_by_offset, udts, &ops, &applicator);
}

#ifdef __NT__
#pragma warning(pop)
#endif
#endif
