/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef __JUMPTABLE_HPP
#define __JUMPTABLE_HPP

#include <pro.h>
#include <ua.hpp>   // op_t
#include <nalt.hpp> // switch_info_t, jumptable_info_t

// Class to check for a jump table sequence.
// This class should be used in preference to the hard encoding of jump table sequences
// because it allows for:
//      - instruction rescheduling
//      - intermingling the jump sequence with other instructions
//      - sequence variants
//
// For this class:
//   all instructions of the sequence are numbered starting from the last instruction.
//   The last instruction has the number 0.
//   The instruction before the last instruciton has the number 1, etc.
//   There is a virtual function jpiN() for each instruction of the sequence
//   These functions return true if 'insn' is filled with the required instruction
//
// The comparison is made in the match() function:
//
//   ea points to the last instruction of the sequence (instruction #0)
//
//   the 'depends' array contains dependencies between the instructions of the sequence.
//   For example:
//      ARM thumb LDRH switch
//      7 SUB     Ra, #minv (optional)
//      6 CMP     Ra, #size
//      5 BCS     defea
//      4 ADR     Rb, jt
//      3 ADD     Rb, Rb, Ra
//      2 LDRH    Rb, [Rb,Ra]
//      1 LSL     Rb, Rb, #1
//      0 ADD     PC, Rb
//   In this sequence, instruction #0 depends on the value of Rb which is produced
//   by the instruction #1. So, the instruction #0 depends on #1. Therefore, depends[0]
//   will contain '1' as its element.
//   The instruction #3 depends on 2 registers: Ra and Rb, or in other words,
//   it depends on the instructions #4 and #6. Therefore, depends[2] will contain { 4, 6 }
//   Maximum 4 dependencies per instruction are allowed.
//
//   FIXME
//   The 'roots' array contains the first instruction of the dependency chains.
//   In our case we can say that there are 2 dependency chains:
//      0 -> 1 -> 2 -> 3 -> 4
//                       -> 6 -> 7
//                     5 -> 6
//   Therefore the roots array will consist of {1, 5}.
//   0 denotes the end of the chain and cannot be the root of a dependency chain
//   Usually 1 is a root of any jump sequence.
//
//   The dependency array allows for checking for optimized sequences of instructions.
//   If 2 instructions are not dependent on each other, they may appear in any order.
//   (for example, the instruction #4 and the instruction sequence #5-6-7 may appear
//   in any order because they do not depend on each other)
//   Also any other instructions not modifying the register values may appear between
//   the instructions of the sequence (due to the instruction rescheduling performed
//   by the compiler).
//
//   Provision for optional instructions:
//   The presence of an optional instruction in the sequence (like #7) is signalled
//   by a negative number of the dependency in the 'depends' array.
//
//   Provision for variable instructions:
//   In some cases several variants of the same instructions may be supported.
//   For example, the instruction #5 might be BCS as well as BGE. It is the job of
//   the jpi5() function to check for all variants.
//
// In order to use the 'jump_pattern_t' class you should derive another class from it
// and define the jpiN() virtual functions.
// Then you have to define the 'depends' and 'roots' arrays and call the match()
// function.
// If you processor contains instructions who modify registers in peculiar ways
// you might want to override the check_spoiled() function.


//----------------------------------------------------------------------
// Macro to declare implementation of methods of jump_pattern_t
class jump_pattern_t;
// tracked registers
// We use the 'size' term to denote the number of bits involved in the insn.
// E.g. an operand of type dt_byte has 8-bit size.
// We store the current size (the number of used bits) in the DTYPE field
// of the 'op_t' structure. It may differ from the size of operand in the
// insn. See the comment for set_moved().
// We extend the 'op_dtype_t' type by some negative constants to denote
// sizes from 2 to 7 bits.
typedef qvector<op_t> tracked_regs_t;
#define DECLARE_JUMP_PATTERN_HELPERS(decl)\
decl void ida_export check_spoiled_jpt(const jump_pattern_t *_this, tracked_regs_t *_regs); \
decl bool ida_export match_jpt(jump_pattern_t *_this);\
decl bool ida_export same_value_jpt(jump_pattern_t *_this, const op_t &op, int r_i);\
decl bool ida_export track_value_until_address_jpt(jump_pattern_t *_this, op_t *op, ea_t ea);\
decl void ida_export combine_regs_jpt(jump_pattern_t *_this, tracked_regs_t *dst, const tracked_regs_t &src, ea_t ea);\
decl void ida_export mark_switch_insns_jpt(const jump_pattern_t *_this, int last, int);\
decl bool ida_export set_moved_jpt(const jump_pattern_t *_this, const op_t &dst, const op_t &src, tracked_regs_t &_regs, op_dtype_t real_dst_dtype, op_dtype_t real_src_dtype);

DECLARE_JUMP_PATTERN_HELPERS(idaman)

class jump_pattern_t
{
protected:
  // 32-bit operand generates a 32-bit result, zero- or sign-extended to a
  // 64-bit result. This flag may be overwritten in processor modules.
  // For example:
  //   ARM: MOV  W8, #0x3C will clear the upper 32 bits of X8,
  //   PC : mov eax, 3Ch   will clear the upper 32 bits of rax
  bool modifying_r32_spoils_r64;

public:
  typedef bool (jump_pattern_t::*check_insn_t)(void);
  inline jump_pattern_t(
          switch_info_t *si,        // may be nullptr
          const char (*depends)[4],
          int last_reg);

  insn_t insn; // current instruction
  switch_info_t *si; // answers will be here

  enum
  {
    NINS = 16,              // the maximum length of the sequence
    INS_MASK = 0x0F,
  };
  ea_t eas[NINS];
  bool skip[NINS];          // do not check the Nth insn if skip[N] is true
  int  non_spoiled_reg;     // if non_spoiled_reg was spoiled then we stop
                            // matching
  check_insn_t check[NINS];
  // this is the hidden return value of the jpiN() methods. If it is set and
  // jpiN() returned 'true' then we stop processing the dependency chain. If
  // it is set and jpiN() returned 'false' then we stop checking the insns
  // in the current basic block and we are switching to the next one (and we
  // fail if there is no such block).
  bool stop_matching;
  // this flag can be analyzed by jpiN(). It means that the current insn is
  // in the linear flow from the previous insn. It is always 'true' if the
  // insn has JPT_NEAR flag.
  bool in_linear_flow;
  // this address can be analyzed by jpiN(). It means the end of the current
  // block. It may help if we want to check in-block jumps.
  ea_t block_end;

  #define JPT_OPT  0x10     // the dependent insn might be missing
  #define JPT_NEAR 0x20     // the dependent insn must be in the linear flow

  const char (*depends)[4]; // instruction, on which we depend, and
                            // additional JPT_... flags

  // mark swith instructions to be ignored by the decompiler
  // do not mark the indirect jmp (eas[0]) as ignored
  // it will be used to recognize switch idioms
  // unmark NLOWCASE insns after LAST (in the case of SWI_HXNOLOWCASE flag)
  void mark_switch_insns(int last = NINS - 1, int nlowcase = 0) const
  {
    mark_switch_insns_jpt(this, last, nlowcase);
  }

  // for fragmented switch idioms, cmp/jbe might be located in a separate
  // fragment. we must not mark these instructions as part of the switch
  // idiom because doing so would spoil the program logic for the decompiler
  // and make the switch operator unreachable. the following vector keeps
  // addresses of all instructions which must not be marked. this vector is
  // maintained by derived classes.
  eavec_t remote_code;
  // extra insns used to calculate values (discovered by find_op_value)
  eavec_t extra_insn_eas;
  // tracked registers
  tracked_regs_t regs;

  // handle a possible delay slot situation
  // while walking backwards in the execution flow
  // if <branch> is false  and <ea> is in a delay
  // slot of a branch likely instruction
  // then set <ea> to the branch instruction
  // (=annul the delay slot)
  // if <branch> is true and the instruction at <ea>
  // has a delay slot then set <ea> to the delay slot
  // (=execute the delay slot)
  virtual void process_delay_slot(ea_t &/*ea*/, bool /*branch*/) const {}

  // an artificial register to track the address of the conditional jump
  // .value   - condition
  // .addr    - address of the conditional jump
  // .specval - address of the default case
  // the derived class can use .reg to track the condition register
  enum
  {
    o_condjump = 99,
    cc_inc_ncases       = 0x01, // increment ncases
    cc_check_max_ncases = 0x02, // comparison with the maximum value
  };

  // compare supported operands
  virtual bool equal_ops(const op_t &x, const op_t &y) const
  {
    if ( x.type != y.type )
      return false;
    switch ( x.type )
    {
      case o_void:
        // consider spoiled values as not equal
        return false;
      case o_reg:
        // ignore difference in the data size of registers
        return x.reg == y.reg;
      case o_condjump:
        // we do not track the condition flags
        return true;
    }
    return false;
  }

  // return true if the instruction `insn' is a move one,
  // there is no need check spoiled registers in this case
  virtual bool handle_mov(tracked_regs_t & /*_regs*/ )
  {
    return false;
  }
  // does the instruction `insn' spoil `_regs' ?
  virtual void check_spoiled(tracked_regs_t *_regs) const
  {
    check_spoiled_jpt(this, _regs);
  }
  // some binaries use the following pattern
  //   xor eax, eax | mov al, cl
  // so we can extend dtype of the operand from dt_byte to dt_dword
  virtual op_dtype_t extend_dtype(const op_t &op) const
  {
    return op.dtype;  // do not extend
  }

  // these methods are not virtual and should be used in processor
  // module only
  inline void track(int reg, int r_i, op_dtype_t dtype);
  inline void trackop(const op_t &op, int r_i);
  inline bool is_spoiled(int r_i) { return regs[r_i].type == o_void; }
  inline bool is_equal(int reg, int r_i, op_dtype_t dtype);
  inline bool is_equal(const op_t &op, int r_i);
  inline bool same_value(const op_t &op, int r_i);
  inline bool track_value_until_address(op_t *op, ea_t ea);

  virtual bool jpi0(void) = 0;
  virtual bool jpi1(void) { return false; }
  virtual bool jpi2(void) { return false; }
  virtual bool jpi3(void) { return false; }
  virtual bool jpi4(void) { return false; }
  virtual bool jpi5(void) { return false; }
  virtual bool jpi6(void) { return false; }
  virtual bool jpi7(void) { return false; }
  virtual bool jpi8(void) { return false; }
  virtual bool jpi9(void) { return false; }
  virtual bool jpia(void) { return false; }
  virtual bool jpib(void) { return false; }
  virtual bool jpic(void) { return false; }
  virtual bool jpid(void) { return false; }
  virtual bool jpie(void) { return false; }
  virtual bool jpif(void) { return false; }
  // jpi<n> will be called if pre_jpi returns true
  virtual bool pre_jpi(int /*n*/) { return true; }

  bool match(const insn_t &_insn) { insn = _insn; return match_jpt(this); }

  // remove compiler warnings -- class with virtual functions MUST have virtual destructor
  virtual ~jump_pattern_t() {}

  // helpers for mov instruction tracing (see methods handle_mov(),
  // check_spoiled() above)
  inline static void set_spoiled(tracked_regs_t *_regs);
  inline void set_spoiled(tracked_regs_t *_regs, const op_t &op) const;
  // track 'mov' insn: dst <- src
  // it returns 'true' if insn changes any of the tracked registers
  // REAL_DST_DTYPE is the size that will be changed in the DST operand by
  // the insn. It can be greater than the operand size because some insns
  // clear the upper bits. For example:
  //   xor eax, eax | mov ax, cx  REAL_DST_DTYPE is 32
  //   xor bh, bh   | mov bl, cl  REAL_DST_DTYPE is 16
  // Extending of the 32-bit register to 64 bits is performed automatically
  // based on the modifying_r32_spoils_r64 flag.
  // REAL_SRC_DTYPE is the size that will be used in the SRC operand by the
  // insn. It can be less than the operand size. For example:
  //   ARM: AND  W8, W8, #0xFF will use 8 bits of X8,
  //   PC : cwde               will use 16 bits of rax.
  bool set_moved(
        const op_t &dst,
        const op_t &src,
        tracked_regs_t &_regs,
        op_dtype_t real_dst_dtype = dt_void,
        op_dtype_t real_src_dtype = dt_void) const
  {
    return set_moved_jpt(this, dst, src, _regs, real_dst_dtype, real_src_dtype);
  }
  // calculate state of registers before a conditional jump <ea> as the
  // combination of states of each branch
  void combine_regs(
        tracked_regs_t *dst,
        const tracked_regs_t &src,
        ea_t ea)
  {
    combine_regs_jpt(this, dst, src, ea);
  }

protected:
  bool match_tree();
  bool follow_tree(ea_t ea, int n);
  bool same_value_impl(const op_t &op, int r_i);
  bool track_value_until_address_impl(op_t *op, ea_t ea);

  inline bool equal_ops_dtype(const op_t &op, const op_t &reg) const;
  static inline bool is_narrower(op_dtype_t dt1, op_dtype_t dt2);
  enum
  {
    dt_7bit = 255,
    dt_6bit = 254,
    dt_5bit = 253,
    dt_4bit = 252,
    dt_3bit = 251,
    dt_2bit = 250,
  };
  static inline int get_dtype_nbits(op_dtype_t dtype);

  // helper for check_spoiled()
  // TODO introduce new virtual methods spoils() and spoils_flags() and
  // replace check_spoiled() by non-virtual method
  inline void check_spoiled_not_reg(
          tracked_regs_t *_regs,
          uint maxop = UA_MAXOP) const;

  DECLARE_JUMP_PATTERN_HELPERS(friend)
};

//----------------------------------------------------------------------
// kinds of jump tables
enum { JT_NONE = 0, JT_SWITCH, JT_CALL };
// It returns a nonzero JT_... kind if it found a jump pattern. This kind is
// passed to the check_table() function.
typedef int is_pattern_t(switch_info_t *si, const insn_t &insn, procmod_t *procmod);
// It returns a refined kind. For example, JT_NONE if the found jump pattern
// is not a switch, or JT_CALL if it is a call of a func from an array
typedef int table_checker_t(
        switch_info_t *si,
        ea_t jump_ea,
        int is_pattern_res,
        procmod_t *pm);
// check a flat 32/16/8 bit jump table -- the most common case
idaman int ida_export check_flat_jump_table(
        switch_info_t *si,
        ea_t jump_ea,
        int is_pattern_res = JT_SWITCH);

// This function finds a switch. It calls functions from the PATTERNS
// array in turn until the first one returns a nonzero value.
// If a suitable pattern is found, it calls check_table() for the final
// check, passing a nonzero result code of the 'is_pattern_t' function.
// If the CHECK_TABLE parameter is nullptr then check_flat_jump_table() is
// called.
// NAME is used for a debug output.
// It returns 'false' if INSN is not a switch or it is a call of a func from
// an array. In the latter case it defines this array.
idaman bool ida_export check_for_table_jump(
        switch_info_t *si,
        const insn_t &insn,
        is_pattern_t *const patterns[],
        size_t qty,
        table_checker_t *check_table = nullptr,
        const char *name = nullptr);

//----------------------------------------------------------------------
// sometimes the size of the jump table is misdetected
// check if any of the would-be targets point into the table
// and if so, truncate it
// if 'ignore_refs' is false, also stop at first data reference
idaman void ida_export trim_jtable(
        switch_info_t *si,
        ea_t jump_ea,
        bool ignore_refs = false);

//----------------------------------------------------------------------
// this function find the size of the jump table for indirect switches
// (indirect switches have the values table which contains indexes into
// the jump table)
// in: si->ncases has the size of the values table
// out: si->jcases is initialized
idaman bool ida_export find_jtable_size(switch_info_t *si);

//----------------------------------------------------------------------
// get default jump address from the jump table.
// This method can be used only for a sparse nonindirect switch with default
// case in the jump table.
idaman ea_t ida_export find_defjump_from_table(
        ea_t jump_ea,
        const switch_info_t &si);

//----------------------------------------------------------------------
// get the specified target from the jump table.
idaman ea_t ida_export get_jtable_target(
        ea_t jump_ea,
        const switch_info_t &si,
        int i);


//----------------------------------------------------------------------
// iterate instructions in the backward execution flow
//lint -esym(1512,backward_flow_iterator_t*) destructor is not virtual
template<class State,class Ctrl>
// State: default constructor, operator=
// Ctrl:  combine_regs(State *, const State& ,ea_t)
//        process_delay_slot(ea_t &/*ea*/, bool /*branch*/)
struct backward_flow_iterator_t
{
public:
  ea_t  cur_ea;     // current address
  State &regs;      // current state of the tracked registers
  Ctrl  &ctrl;      // to combine state
  bool  only_near;  // should we follow only the linear flow?
  uint  max_insn_cnt;

protected:
  //lint --e{958} padding is required
  func_t *pfn;      // to check bounds
  const segment_t *seg;
  ea_t start_ea;
  ea_t cur_end;     // end of current basic block
  uint insn_cnt;
  // visited basic blocks:
  // key_type - start of the block, mapped_type - end of the block;
  typedef std::map<ea_t, ea_t> visited_t;
  visited_t visited;
  // waiting basic blocks:
  // key_type - end of the block, mapped_type - state at the end;
  struct state_t
  {
    State regs;
    uint  insn_cnt;
    state_t() : regs(), insn_cnt(UINT_MAX) {}
  };
  typedef std::map<ea_t, state_t> waiting_t;
  waiting_t waiting;

public:
  backward_flow_iterator_t(
          ea_t start_ea_,
          State &start_regs,
          Ctrl &ctrl_,
          bool only_near_,
          uint max_insn_cnt_ = 0)
    : cur_ea(start_ea_),
      regs(start_regs),
      ctrl(ctrl_),
      only_near(only_near_),
      max_insn_cnt(max_insn_cnt_),
      pfn(nullptr),
      seg(nullptr),
      start_ea(start_ea_),
      cur_end(BADADDR),
      insn_cnt(0),
      visited(),
      waiting()
  {
    // to check bounds
    pfn = get_func(start_ea);
    if ( pfn == nullptr )
    {
      seg = getseg(start_ea);
      QASSERT(10183, seg != nullptr);
    }
  }

  // fl_U : no previous instruction (start of a function or a cycle,
  //        or non linear flow if ONLY_NEAR is true),
  // fl_F : got previous instruction by linear flow,
  // fl_JF: got previous instruction by jump;
  inline cref_t prev_insn();
  // stop iterating the current basic block, switch to the lowest waiting
  // block
  inline cref_t skip_block();

  inline ea_t get_cur_end() const
  {
    return cur_end == BADADDR ? cur_ea : cur_end;
  }

protected:
  // find visited basic block containing the address
  // it returns the pointer to the address of the block end or nullptr
  inline ea_t *find_visited(ea_t ea);
  // get the lowest to start_ea waiting block
  inline cref_t get_waiting();
  // combine insn counter - count the shortest path
  static inline void combine_insn_cnt(uint *dst, uint src)
  {
    if ( src < *dst )
      *dst = src;
  }

  bool check_bounds() const
  {
    if ( pfn != nullptr )
      return func_contains(pfn, cur_ea);
    return seg->contains(cur_ea);
  }
};

//-------------------------------------------------------------------------
// simple backward flow iterator
struct no_regs_t {};
struct simple_bfi_t
  : public backward_flow_iterator_t<no_regs_t, simple_bfi_t>
{
  typedef backward_flow_iterator_t<no_regs_t, simple_bfi_t> base_t;

protected:
  no_regs_t regs_;

public:
  simple_bfi_t(ea_t ea)
    : base_t(ea, regs_, *this, false) {}
  static void combine_regs(no_regs_t *, const no_regs_t &, ea_t) {}
  static void process_delay_slot(ea_t &, bool) {}
};


//======================================================================
// inline implementation
//----------------------------------------------------------------------
//-V:jump_pattern_t:730 not all members of a class are initialized inside the constructor
inline jump_pattern_t::jump_pattern_t(
        switch_info_t *_si,
        const char (*_depends)[4],
        int last_reg)
  : modifying_r32_spoils_r64(true),
    si(_si),
    non_spoiled_reg(-1),
    in_linear_flow(false),
    depends(_depends),
    regs()
{
  if ( si != nullptr )
    si->clear();
  regs.resize(last_reg + 1);
}

//----------------------------------------------------------------------
inline bool jump_pattern_t::equal_ops_dtype(
        const op_t &op,
        const op_t &reg) const
{
  if ( !equal_ops(op, reg) )
    return false;
  // operand should be wider than a tracked register
  // e.g. after 'cmp cl, imm' we cannot use cx
  if ( !is_narrower(op.dtype, reg.dtype) )
    return true;
  // we believe that dword is widened to qword
  if ( modifying_r32_spoils_r64 && op.dtype == dt_dword )
    return true;
  // try to extend
  if ( !is_narrower(extend_dtype(op), reg.dtype) )
    return true;
  return false;
}

//----------------------------------------------------------------------
// return true if size1 is narrow than size2
inline bool jump_pattern_t::is_narrower(op_dtype_t dt1, op_dtype_t dt2)
{
  if ( dt1 < dt_2bit )
    return dt2 < dt_2bit && dt1 < dt2;
  else
    return dt2 < dt_2bit || dt1 < dt2;
}

//----------------------------------------------------------------------
inline int jump_pattern_t::get_dtype_nbits(op_dtype_t dtype)
{
  switch ( dtype )
  {
    case dt_byte:  return 8;
    case dt_word:  return 16;
    case dt_dword: return 32;
    case dt_qword: return 64;
    case dt_7bit:  return 7;
    case dt_6bit:  return 6;
    case dt_5bit:  return 5;
    case dt_4bit:  return 4;
    case dt_3bit:  return 3;
    case dt_2bit:  return 2;
    default:       return -1;
  }
}

//----------------------------------------------------------------------
inline void jump_pattern_t::check_spoiled_not_reg(
        tracked_regs_t *_regs,
        uint maxop) const
{
  uint32 feature = insn.get_canon_feature(PH);
  if ( feature == 0 )
    return;
  for ( uint i = 0; i < maxop; ++i )
  {
    if ( has_cf_chg(feature, i)
      && insn.ops[i].type != o_void
      && insn.ops[i].type != o_reg )
    {
      set_spoiled(_regs, insn.ops[i]);
    }
  }
}

//----------------------------------------------------------------------
inline void jump_pattern_t::track(int reg, int r_i, op_dtype_t dtype)
{
  regs[r_i].type  = o_reg;
  regs[r_i].reg   = reg;
  regs[r_i].dtype = dtype;
}
inline void jump_pattern_t::trackop(const op_t &op, int r_i)
{
  regs[r_i] = op;
}

//----------------------------------------------------------------------
inline bool jump_pattern_t::is_equal(int reg, int r_i, op_dtype_t dtype)
{
  op_t op;
  op.type  = o_reg;
  op.reg   = reg;
  op.dtype = dtype;
  return is_equal(op, r_i);
}
inline bool jump_pattern_t::is_equal(const op_t &op, int r_i)
{
  if ( regs[r_i].type == o_void )
  {
    // there is no reason to continue match
    stop_matching = true;
    return false;
  }
  return equal_ops_dtype(op, regs[r_i]);
}

//----------------------------------------------------------------------
inline bool jump_pattern_t::same_value(const op_t &op, int r_i)
{
  return same_value_jpt(this, op, r_i);
}

//----------------------------------------------------------------------
inline bool jump_pattern_t::track_value_until_address(op_t *op, ea_t ea)
{
  return track_value_until_address_jpt(this, op, ea);
}

//----------------------------------------------------------------------
inline void jump_pattern_t::set_spoiled(tracked_regs_t *__regs)
{
  tracked_regs_t &_regs = *__regs;
  // spoil all registers
  for ( size_t i = 0; i < _regs.size(); ++i )
    _regs[i].type = o_void;
}
inline void jump_pattern_t::set_spoiled(tracked_regs_t *__regs, const op_t &op) const
{
  tracked_regs_t &_regs = *__regs;
  for ( size_t i = 0; i < _regs.size(); ++i )
    if ( equal_ops(_regs[i], op) )
      _regs[i].type = o_void;  // spoil register
}

//----------------------------------------------------------------------
// find the previous instruction in code flow
// take into account branches and potential delay slots
template<class State,class Ctrl>
inline cref_t backward_flow_iterator_t<State,Ctrl>::prev_insn()
{
  size_t refcnt = 0;
  // check visited basic block
  ea_t *visited_end = find_visited(cur_ea);
  if ( visited_end == nullptr )
  {
    // analyze references to the current address
    flags64_t F = get_flags(cur_ea);
    if ( is_flow(F) )
      ++refcnt;
    if ( has_xref(F) && !is_func(F) ) // do not count jumps to function
    {
      xrefblk_t xb;
      for ( bool ok = xb.first_to(cur_ea, XREF_FAR);
            ok && xb.iscode;
            ok = xb.next_to() )
      {
        // count only xrefs from jumps
        if ( xb.type == fl_JF || xb.type == fl_JN )
        {
          if ( only_near )
          {
            if ( refcnt > 0 )
              return fl_U;
            // do not consider the flow through another switch as linear
            if ( (get_flags(xb.from) & FF_JUMP) != 0 )
              return fl_U;
          }
          ++refcnt;
          ea_t ea = xb.from;
          ctrl.process_delay_slot(ea, true);
          // ignore jumps from already visited blocks
          if ( find_visited(ea) != nullptr )
            continue;
          // add basic block to the waiting set (combine state of the
          // tracked registers at the jump source)
          state_t &src_state = waiting[ea];
          ctrl.combine_regs(&src_state.regs, regs, ea);
          combine_insn_cnt(&src_state.insn_cnt, insn_cnt);
        }
      }
    }

    if ( cur_end == BADADDR )
      cur_end = cur_ea;

    // try ordinary flow
    if ( is_flow(F) )
    {
      ea_t prev_ea = prev_not_tail(cur_ea);
      if ( prev_ea != BADADDR )
      {
        cur_ea = prev_ea;
        if ( check_bounds()
          && (max_insn_cnt == 0 || insn_cnt < max_insn_cnt) )
        {
          ++insn_cnt;
          // remove reached waiting basic block
          typename waiting_t::iterator w = waiting.find(cur_ea);
          if ( w != waiting.end() )
          {
            ctrl.combine_regs(&regs, w->second.regs, cur_ea);
            combine_insn_cnt(&insn_cnt, w->second.insn_cnt);
            waiting.erase(w);
          }
          else
          {
            ctrl.process_delay_slot(cur_ea, false);
          }
          return fl_F;
        }
      }
      // choose another branch
    }

    // save block [cur_ea, cur_end] as visited
    visited[cur_ea] = cur_end;
  }
  else if ( cur_end != BADADDR )
  {
    // reach visited basic block => extend it
    *visited_end = cur_end;
  }

  // get the lowest waiting block
  cref_t ret = get_waiting();
  // consider one xref as a linear flow
  if ( ret == fl_JF && refcnt == 1 && waiting.empty() )
    ret = fl_F;
  return ret;
}

//----------------------------------------------------------------------
template<class State,class Ctrl>
inline cref_t backward_flow_iterator_t<State,Ctrl>::skip_block()
{
  // check visited basic block
  ea_t *visited_end = find_visited(cur_ea);
  if ( visited_end == nullptr )
  {
    if ( cur_end == BADADDR )
      cur_end = cur_ea;
    // save block [cur_ea, cur_end] as visited
    visited[cur_ea] = cur_end;
  }
  else if ( cur_end != BADADDR )
  {
    // reach visited basic block => extend it
    *visited_end = cur_end;
  }

  // get the lowest waiting block
  return get_waiting();
}

//----------------------------------------------------------------------
template<class State,class Ctrl>
inline cref_t backward_flow_iterator_t<State,Ctrl>::get_waiting()
{
  while ( !waiting.empty() )
  {
    typename waiting_t::iterator w = waiting.upper_bound(start_ea);
    if ( w != waiting.begin() )
      --w;
    cur_ea = w->first;
    if ( check_bounds() )
    {
      cur_end = BADADDR;
      regs = w->second.regs;
      insn_cnt = w->second.insn_cnt;
      waiting.erase(w);
      return fl_JF;
    }
    waiting.erase(w);
  }
  return fl_U;
}

//----------------------------------------------------------------------
template<class State,class Ctrl>
inline ea_t *backward_flow_iterator_t<State,Ctrl>::find_visited(ea_t ea)
{
  visited_t::iterator v = visited.upper_bound(ea);
  // assert: v == visited.end() || v->first > ea
  if ( v == visited.begin() )
    return nullptr;
  --v;
  // assert: v->first <= ea
  if ( ea > v->second )
    return nullptr;
  return &v->second;
}


#endif
