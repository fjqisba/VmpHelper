/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _UA_HPP
#define _UA_HPP

#include <kernwin.hpp>  // for btoa()
#include <lines.hpp>    // for colors
#include <xref.hpp>     // add_cref()
#include <bytes.hpp>    // get_byte(), ...

/*! \file ua.hpp

  \brief Functions that deal with the disassembling of program instructions.

  There are 2 kinds of functions:
    - functions that are called from the kernel
      to disassemble an instruction. These functions
      call IDP module for it.
    - functions that are called from IDP module to
      disassemble an instruction. We will call them
      'helper functions'.

  Disassembly of an instruction is made in three steps:
    -# analysis:             ana.cpp
    -# emulation:            emu.cpp
    -# conversion to text:   out.cpp

  The kernel calls the IDP module to perform these steps.
  At first, the kernel always calls the analysis. The analyzer
  must decode the instruction and fill the insn_t instance
  that it receives through its callback.
  It must not change anything in the database.

  The second step, the emulation, is called for each instruction.
  This step must make necessary changes to the database,
  plan analysis of subsequent instructions, track register
  values, memory contents, etc. Please keep in mind that the kernel may call
  the emulation step for any address in the program - there is no
  ordering of addresses. Usually, the emulation is called
  for consecutive addresses but this is not guaranteed.

  The last step, conversion to text, is called each time an instruction
  is displayed on the screen. The kernel will always call the analysis step
  before calling the text conversion step.
  The emulation and the text conversion steps should use the information stored
  in the insn_t instance they receive. They should not access the bytes
  of the instruction and decode it again - this should only be done in
  the analysis step.
*/

struct procmod_t;
struct processor_t;
struct asm_t;

/// \defgroup operands Operands
/// Work with instruction operands

//--------------------------------------------------------------------------
//      T Y P E   O F   O P E R A N D
//--------------------------------------------------------------------------
typedef uchar optype_t; ///< see \ref o_
/// \defgroup o_ Operand types
/// \ingroup operands
///
/// Various types of instruction operands.
/// The kernel already knows about some operand types and associates them
/// with fields in ::op_t.
///
/// IDA also allows you define processor specific operand types (o_idpspec...).
/// You are free to give any meaning to these types. We suggest you to create a
/// #define to use mnemonic names. However, don't forget that the kernel will
/// know nothing about operands of those types.
/// You may use any additional fields of ::op_t to store
/// processor specific operand information.
//@{
const optype_t
  o_void     =  0, ///< No Operand.
  o_reg      =  1, ///< General Register (al,ax,es,ds...).
  o_mem      =  2, ///< Direct Memory Reference  (DATA).
  o_phrase   =  3, ///< Memory Ref [Base Reg + Index Reg].
  o_displ    =  4, ///< Memory Ref [Base Reg + Index Reg + Displacement].
  o_imm      =  5, ///< Immediate Value.
  o_far      =  6, ///< Immediate Far Address  (CODE).
  o_near     =  7, ///< Immediate Near Address (CODE).
  o_idpspec0 =  8, ///< processor specific type.
  o_idpspec1 =  9, ///< processor specific type.
  o_idpspec2 = 10, ///< processor specific type.
  o_idpspec3 = 11, ///< processor specific type.
  o_idpspec4 = 12, ///< processor specific type.
  o_idpspec5 = 13; ///< processor specific type.
                   ///< (there can be more processor specific types)
//@}

/// \var o_reg
/// The register number should be stored in op_t::reg.
/// All processor registers, including special registers, can be
/// represented by this operand type.
///
/// \var o_mem
/// A direct memory data reference whose target address is known at compilation time.
/// The target virtual address is stored in op_t::addr and the full address
/// is calculated as to_ea( \insn_t{cs}, op_t::addr ). For the processors with
/// complex memory organization the final address can be calculated
/// using other segment registers. For flat memories, op_t::addr is the final
/// address and \insn_t{cs} is usually equal to zero. In any case, the address
/// within the segment should be stored in op_t::addr.
///
/// \var o_phrase
/// A memory reference using register contents. Indexed, register based,
/// and other addressing modes can be represented with the operand type.
/// This addressing mode cannot contain immediate values (use ::o_displ instead).
/// The phrase number should be stored in op_t::phrase. To denote the pre-increment
/// and similar features please use additional operand fields like op_t::specflag...
/// Usually op_t::phrase contains the register number and additional information
/// is stored in op_t::specflags... Please note that this operand type cannot
/// contain immediate values (except the scaling coefficients).
///
/// \var o_displ
/// A memory reference using register contents with displacement.
/// The displacement should be stored in the op_t::addr field. The rest of information
/// is stored the same way as in ::o_phrase.
///
/// \var o_imm
/// Any operand consisting of only a number is represented by this operand type.
/// The value should be stored in op_t::value. You may sign extend short (1-2 byte) values.
/// In any case don't forget to specify op_t::dtype (should be set for all operand types).
///
/// \var o_far
/// If the current processor has a special addressing mode for inter-segment
/// references, then this operand type should be used instead of ::o_near.
/// If you want, you may use #PR_CHK_XREF in \ph{flag} to disable inter-segment
/// calls if ::o_near operand type is used. Currently only IBM PC uses this flag.
///
/// \var o_near
/// A direct memory code reference whose target address is known at the compilation time.
/// The target virtual address is stored in op_t::addr and the final address
/// is always to_ea(\insn_t{cs}, op_t::addr). Usually this operand type is used for
/// the branches and calls whose target address is known. If the current
/// processor has 2 different types of references for inter-segment and intra-segment
/// references, then this should be used only for intra-segment references.
///
/// If the above operand types do not cover all possible addressing modes,
/// then use o_idpspec... operand types.

//--------------------------------------------------------------------------
//      O P E R A N D   O F   I N S T R U C T I O N
//--------------------------------------------------------------------------
/// \defgroup operands_t Operand structure
/// \ingroup operands
/// Definition of ::op_t and related items.

/// Operand of an instruction. \ingroup operands_t
/// This structure is filled by the analyzer.
/// Upon entrance to the analyzer, some fields of this structure are initialized:
///   - #type:    ::o_void
///   - #offb:    0
///   - #offo:    0
///   - #flags:   #OF_SHOW
class op_t
{
public:

  /// Number of operand (0,1,2). Initialized once at the start of work.
  /// You have no right to change its value.
  uchar n = 0;

  /// Type of operand (see \ref o_)
  optype_t type = o_void;

  /// Offset of operand value from the instruction start (0 means unknown).
  /// Of course this field is meaningful only for certain types of operands.
  /// Leave it equal to zero if the operand has no offset.
  /// This offset should point to the 'interesting' part of operand.
  /// For example, it may point to the address of a function in
  ///      \v{call func}
  /// or it may point to bytes holding '5' in
  ///      \v{mov  ax, [bx+5]}
  /// Usually bytes pointed to this offset are relocated (have fixup information).
  char offb = 0;

  /// Same as #offb (some operands have 2 numeric values used to form an operand).
  /// This field is used for the second part of operand if it exists.
  /// Currently this field is used only for outer offsets of Motorola processors.
  /// Leave it equal to zero if the operand has no offset.
  char offo = 0;

  uchar flags = 0;            ///< \ref OF_
/// \defgroup OF_ Operand flags
/// \ingroup operands_t
/// Used by op_t::flags
//@{
#define OF_NO_BASE_DISP 0x80  ///< base displacement doesn't exist.
                              ///< meaningful only for ::o_displ type.
                              ///< if set, base displacement (op_t::addr)
                              ///< doesn't exist.
#define OF_OUTER_DISP   0x40  ///< outer displacement exists.
                              ///< meaningful only for ::o_displ type.
                              ///< if set, outer displacement (op_t::value) exists.
#define PACK_FORM_DEF   0x20  ///< packed factor defined.
                              ///< (!::o_reg + #dt_packreal)
#define OF_NUMBER       0x10  ///< the operand can be converted to a number only
#define OF_SHOW         0x08  ///< should the operand be displayed?
//@}

  /// Set operand to be shown
  void set_shown()     { flags |=  OF_SHOW; }
  /// Set operand to hidden
  void clr_shown()     { flags &= ~OF_SHOW; }
  /// Is operand set to be shown?
  bool shown() const   { return (flags & OF_SHOW) != 0; }

  /// Type of operand value (see \ref dt_). Usually first 9 types are used.
  /// This is the type of the operand itself, not the size of the addressing mode.
  /// for example, byte ptr [epb+32_bit_offset]  will have #dt_byte type.
  op_dtype_t dtype = 0;
/// \defgroup dt_ Operand value types
/// \ingroup operands_t
/// Used by op_t::dtype
//@{
// from here..
#define dt_byte         0     ///< 8 bit integer
#define dt_word         1     ///< 16 bit integer
#define dt_dword        2     ///< 32 bit integer
#define dt_float        3     ///< 4 byte floating point
#define dt_double       4     ///< 8 byte floating point
#define dt_tbyte        5     ///< variable size (\ph{tbyte_size}) floating point
#define dt_packreal     6     ///< packed real format for mc68040
// ...to here the order should not be changed, see mc68000
#define dt_qword        7     ///< 64 bit integer
#define dt_byte16       8     ///< 128 bit integer
#define dt_code         9     ///< ptr to code (not used?)
#define dt_void         10    ///< none
#define dt_fword        11    ///< 48 bit
#define dt_bitfild      12    ///< bit field (mc680x0)
#define dt_string       13    ///< pointer to asciiz string
#define dt_unicode      14    ///< pointer to unicode string
#define dt_ldbl         15    ///< long double (which may be different from tbyte)
#define dt_byte32       16    ///< 256 bit integer
#define dt_byte64       17    ///< 512 bit integer
#define dt_half         18    ///< 2-byte floating point
//@}

  // REG
  union
  {
    uint16 reg;               ///< number of register (::o_reg)
    uint16 phrase;            ///< number of register phrase (::o_phrase,::o_displ).
                              ///< you yourself define numbers of phrases
                              ///< as you like
  };

  /// Is register operand?
  bool is_reg(int r) const { return type == o_reg && reg == r; }

  //  Next 12 bytes are used by mc68k for some float types

  // VALUE
  union
  {
    uval_t value;             ///< operand value (::o_imm) or
                              ///< outer displacement (::o_displ+#OF_OUTER_DISP).
                              ///< integer values should be in IDA's (little-endian) order.
                              ///< when using ieee_realcvt(), floating point values should be in the processor's native byte order.
                              ///< #dt_double and #dt_qword values take up 8 bytes (value and addr fields for 32-bit modules).
                              ///< NB: in case a #dt_dword/#dt_qword immediate is forced to float by user,
                              ///< the kernel converts it to processor's native order before calling FP conversion routines.

    /// This structure is defined for
    /// your convenience only
    struct
    {
      uint16 low;
      uint16 high;
    } value_shorts;
  };

  /// Is immediate operand?
  bool is_imm(uval_t v) const { return type == o_imm && value == v; }

  // VIRTUAL ADDRESS (offset within the segment)
  union
  {
    ea_t addr;                ///< virtual address pointed or used by the operand.
                              ///< (::o_mem,::o_displ,::o_far,::o_near)

    /// This structure is defined for
    /// your convenience only
    struct
    {
      uint16 low;
      uint16 high;
    } addr_shorts;
  };

  // IDP SPECIFIC INFORMATION
  union
  {
    ea_t specval;             ///< This field may be used as you want.
    /// This structure is defined for
    /// your convenience only
    struct
    {
      uint16 low;             ///< IBM PC: segment register number (::o_mem,::o_far,::o_near)
      uint16 high;            ///< IBM PC: segment selector value  (::o_mem,::o_far,::o_near)
    } specval_shorts;
  };

  /// \name Special flags
  /// The following fields are used only in idp modules.
  /// You may use them as you want to store additional information about
  /// the operand.
  //@{
  char specflag1 = 0;
  char specflag2 = 0;
  char specflag3 = 0;
  char specflag4 = 0;
  //@}
};


//--------------------------------------------------------------------------
//      I N S T R U C T I O N
//--------------------------------------------------------------------------
/// \defgroup instruction Instruction
/// Definition of ::insn_t and related items.

/// Structure to hold information about an instruction. \ingroup instruction
/// This structure is filled by the analysis step of IDP and used by
/// the emulation and conversion to text steps. The kernel uses this structure too.
/// All structure fields except #cs, #ip, #ea, and op_t::n,op_t::flags of #ops
/// are initialized to zero by the kernel. The rest should be filled by ana().

class insn_t;
#define DECLARE_INSN_HELPERS(decl) \
decl uint8  ida_export insn_get_next_byte(insn_t *insn); \
decl uint16 ida_export insn_get_next_word(insn_t *insn); \
decl uint32 ida_export insn_get_next_dword(insn_t *insn); \
decl uint64 ida_export insn_get_next_qword(insn_t *insn); \
decl bool ida_export insn_create_op_data(const insn_t &insn, ea_t ea, int opoff, op_dtype_t dtype); \
decl void ida_export insn_add_cref(const insn_t &insn, ea_t to, int opoff, cref_t type); \
decl void ida_export insn_add_dref(const insn_t &insn, ea_t to, int opoff, dref_t type); \
decl ea_t ida_export insn_add_off_drefs(const insn_t &insn, const op_t &x, dref_t type, int outf); \
decl bool ida_export insn_create_stkvar(const insn_t &insn, const op_t &x, adiff_t v, int flags);

DECLARE_INSN_HELPERS(idaman)

//-V:insn_t:730 not all members of a class are initialized inside the constructor
class insn_t
{
public:
  insn_t() : ea(BADADDR), itype(0), size(0) {}

  /// Current segment base paragraph. Initialized by the kernel.
  ea_t cs;

  /// Virtual address of the instruction (address within the segment).
  /// Initialized by the kernel.
  ea_t ip;

  /// Linear address of the instruction.
  /// Initialized by the kernel.
  ea_t ea;

  /// Internal code of instruction (only for canonical insns - not user defined!).
  /// IDP should define its own instruction codes. These codes are usually
  /// defined in ins.hpp. The array of instruction names and features (ins.cpp)
  /// is accessed using this code.
  uint16 itype;

  inline bool is_canon_insn(const processor_t &ph) const;         ///< see \ph{is_canon_insn()}
  inline uint32 get_canon_feature(const processor_t &ph) const;   ///< see instruc_t::feature
  inline const char *get_canon_mnem(const processor_t &ph) const; ///< see instruc_t::name

  /// Size of instruction in bytes.
  /// The analyzer should put here the actual size of the instruction.
  uint16 size;

  union
  {
    uint32 auxpref;             ///< processor dependent field
    uint16 auxpref_u16[2];
    uint8  auxpref_u8[4];
  };
  /*u*/ char segpref;           ///< processor dependent field
  /*u*/ char insnpref;          ///< processor dependent field

  /*u*/ int16 flags;            ///< \ref INSN_

  op_t ops[UA_MAXOP];           ///< array of operands

  /// \defgroup Op_ Operand shortcuts
  /// \ingroup instruction
  /// Used for accessing members of insn_t::ops
  //@{
  #define Op1 ops[0]       ///< first operand
  #define Op2 ops[1]       ///< second operand
  #define Op3 ops[2]       ///< third operand
  #define Op4 ops[3]       ///< fourth operand
  #define Op5 ops[4]       ///< fifth operand
  #define Op6 ops[5]       ///< sixth operand
  #define Op7 ops[6]       ///< seventh operand
  #define Op8 ops[7]       ///< eighth operand
  //@}

/// \defgroup INSN_ Instruction flags
/// \ingroup instruction
/// Used by insn_t::flags
//@{
#define INSN_MACRO  0x01        ///< macro instruction
#define INSN_MODMAC 0x02        ///< may modify the database to make room for the macro insn
#define INSN_64BIT  0x04        ///< belongs to 64bit segment?
//@}

  /// Is a macro instruction?
  bool is_macro(void) const { return (flags & INSN_MACRO) != 0; }

  /// Belongs to a 64bit segment?
#ifdef __EA64__
  bool is_64bit(void) const { return (flags & INSN_64BIT) != 0; }
#else
  bool is_64bit(void) const { return false; }
#endif

  /// \name Analysis helpers
  /// The following functions return the next byte, 2 bytes, 4 bytes,
  /// and 8 bytes of insn. They use and modify the size field (\insn_t{size}).
  /// Normally they are used in the analyzer to get bytes of the instruction.
  /// \warning These methods work only for normal (8bit) byte processors!
  //@{
  uint8 get_next_byte()
  {
    return insn_get_next_byte(this);
  }
  uint16 get_next_word()
  {
    return insn_get_next_word(this);
  }
  uint32 get_next_dword()
  {
    return insn_get_next_dword(this);
  }
  uint64 get_next_qword()
  {
    return insn_get_next_qword(this);
  }
  //@}

  /// \name Emulator helpers
  //@{

  /// Convert to data using information about operand value type (op_t::dtype).
  /// Emulator could use this function to convert unexplored bytes to data
  /// when an instruction references them.
  /// This function creates data only if the address was unexplored.
  /// \param ea_    linear address to be converted to data
  /// \param opoff  offset of the operand from the start of instruction
  ///               if the offset is unknown, then 0
  /// \param dtype  operand value type (from op_t::dtype)
  /// \retval true  ok
  /// \retval false failed to create data item

  bool create_op_data(ea_t ea_, int opoff, op_dtype_t dtype) const
  {
    return insn_create_op_data(*this, ea_, opoff, dtype);
  }

  /// Convenient alias
  bool create_op_data(ea_t ea_, const op_t &op) const
  {
    return insn_create_op_data(*this, ea_, op.offb, op.dtype);
  }


  /// Create or modify a stack variable in the function frame.
  /// The emulator could use this function to create stack variables
  /// in the function frame before converting the operand to a stack variable.
  /// Please check with may_create_stkvars() before calling this function.
  /// \param x       operand (used to determine the addressing type)
  /// \param v       a displacement in the operand
  /// \param flags_  \ref STKVAR_2
  /// \retval 1  ok, a stack variable exists now
  /// \retval 0  no, couldn't create stack variable

  bool create_stkvar(const op_t &x, adiff_t v, int flags_) const
  {
    return insn_create_stkvar(*this, x, v, flags_);
  }

  /// \defgroup STKVAR_2 Stack variable flags
  /// Passed as 'flags' parameter to create_stkvar()
  //@{
#define STKVAR_VALID_SIZE       0x0001 ///< x.dtype contains correct variable type
                                       ///< (for insns like 'lea' this bit must be off).
                                       ///< in general, dr_O references do not allow
                                       ///< to determine the variable size
  //@}


  /// Add a code cross-reference from the instruction.
  /// \param opoff  offset of the operand from the start of instruction.
  ///               if the offset is unknown, then 0.
  /// \param to     target linear address
  /// \param type   type of xref

  void add_cref(ea_t to, int opoff, cref_t type) const
  {
    insn_add_cref(*this, to, opoff, type);
  }


  /// Add a data cross-reference from the instruction.
  /// See add_off_drefs() - usually it can be used in most cases.
  /// \param opoff  offset of the operand from the start of instruction
  ///               if the offset is unknown, then 0
  /// \param to     target linear address
  /// \param type   type of xref

  void add_dref(ea_t to, int opoff, dref_t type) const
  {
    insn_add_dref(*this, to, opoff, type);
  }


  /// Add xrefs for an operand of the instruction.
  /// This function creates all cross references for 'enum', 'offset' and
  /// 'structure offset' operands.
  /// Use add_off_drefs() in the presence of negative offsets.
  /// \param x     reference to operand
  /// \param type  type of xref
  /// \param outf  out_value() flags. These flags should match
  ///              the flags used to output the operand
  /// \return if is_off(): the reference target address (the same as calc_reference_data).
  ///         if is_stroff(): #BADADDR because for stroffs the target address is unknown
  ///         else: #BADADDR because enums do not represent addresses

  ea_t add_off_drefs(const op_t &x, dref_t type, int outf) const
  {
    return insn_add_off_drefs(*this, x, type, outf);
  }

  //@}

};
#ifdef __EA64__
CASSERT(sizeof(insn_t) == 360);
#else
CASSERT(sizeof(insn_t) == 216);
#endif

//--------------------------------------------------------------------------
//      V A L U E   O F   O P E R A N D
//--------------------------------------------------------------------------
#ifndef SWIG
/// This structure is used to pass values of bytes to helper functions.
union value_u
{
  uint8  v_char;
  uint16 v_short;
  uint32 v_long;
  uint64 v_int64;
  uval_t v_uval;
  struct dq_t { uint32 low; uint32 high; } _dq;
  struct dt_t { uint32 low; uint32 high; uint16 upper; } dt;
  struct d128_t { uint64 low; uint64 high; } d128;
  uint8 byte16[16];
  uint32 dword3[3];
};

#endif // SWIG

/// Get immediate values at the specified address.
/// This function decodes instruction at the specified address or inspects
/// the data item. It finds immediate values and copies them to 'out'.
/// This function will store the original value of the operands in 'out',
/// unless the last bits of 'F' are "...0 11111111", in which case the
/// transformed values (as needed for printing) will be stored instead.
/// \param out   array of immediate values (at least 2*#UA_MAXOP elements)
/// \param ea    address to analyze
/// \param n     0..#UA_MAXOP-1 operand number, OPND_ALL all the operands
/// \param F     flags for the specified address
/// \param cache optional already decoded instruction or buffer for it.
///              if the cache does not contain the decoded instruction,
///              it will be updated (useful if we call get_immvals for the same
///              address multiple times)
/// \return number of immediate values (0..2*#UA_MAXOP)

idaman size_t ida_export get_immvals(
        uval_t *out,
        ea_t ea,
        int n,
        flags64_t F,
        insn_t *cache=nullptr);


/// Get immediate ready-to-print values at the specified address
/// \param out   array of immediate values (at least 2*#UA_MAXOP elements)
/// \param ea    address to analyze
/// \param n     0..#UA_MAXOP-1 operand number, OPND_ALL all the operands
/// \param F     flags for the specified address
/// \param cache optional already decoded instruction or buffer for it.
///              if the cache does not contain the decoded instruction,
///              it will be updated (useful if we call get_immvals for the same
///              address multiple times)
/// \return number of immediate values (0..2*#UA_MAXOP)

inline size_t get_printable_immvals(
        uval_t *out,
        ea_t ea,
        int n,
        flags64_t F,
        insn_t *cache=nullptr)
{
  F &= ~0x100; // no FF_IVL...
  F |= 0xFF;   // ...but a value of 0xFF
  return get_immvals(out, ea, n, F, cache);
}


/// Number of instructions to look back.
/// This variable is not used by the kernel.
/// Its value may be specified in ida.cfg:
///      LOOKBACK = <number>.
/// IDP may use it as you like it.
/// (TMS module uses it)

idaman int ida_export get_lookback(void);


//--------------------------------------------------------------------------
//      I D P   H E L P E R   F U N C T I O N S  -  C O M M O N
//--------------------------------------------------------------------------

/// \name Address translation
/// The following functions can be used by processor modules to map
/// addresses from one region to another. They are especially useful
/// for microprocessors that map the same memory region to multiple address
/// ranges or use memory bank switching.
/// The user can use the following techniques to desribe address translations:
///   - some processors support the segment transation feature.
///     the user can specify the mapping in Edit, Segments, Change segment translation
///   - the user can specify mapping for an individual direct call instruction
///     by specifying it as an offset (Edit, Operand types, Offset)
///   - specify the value of the data segment virtual register (ds).
///     it will be used to calculate data addresses
//@{

/// Get data segment for the instruction operand.
/// 'opnum' and 'rgnum' are meaningful only if the processor
/// has segment registers.

idaman ea_t ida_export calc_dataseg(const insn_t &insn, int n=-1, int rgnum=-1);

/// Map a data address.
/// \param insn   the current instruction
/// \param addr   the referenced address to map
/// \param opnum  operand number

inline ea_t map_data_ea(const insn_t &insn, ea_t addr, int opnum=-1)
{
  return to_ea(calc_dataseg(insn, opnum), addr);
}

inline ea_t map_data_ea(const insn_t &insn, const op_t &op)
{
  return map_data_ea(insn, op.addr, op.n);
}

/// Map a code address.
/// This function takes into account the segment translations.
/// \param insn   the current instruction
/// \param addr   the referenced address to map
/// \param opnum  operand number

idaman ea_t ida_export map_code_ea(const insn_t &insn, ea_t addr, int opnum);

inline ea_t map_code_ea(const insn_t &insn, const op_t &op)
{
  return map_code_ea(insn, op.addr, op.n);
}

inline ea_t map_ea(const insn_t &insn, const op_t &op, bool iscode)
{
  return iscode ? map_code_ea(insn, op) : map_data_ea(insn, op);
}

inline ea_t map_ea(const insn_t &insn, ea_t addr, int opnum, bool iscode)
{
  return iscode ? map_code_ea(insn, addr, opnum) : map_data_ea(insn, addr, opnum);
}

//@}

//--------------------------------------------------------------------------
//      I D P   H E L P E R   F U N C T I O N S  -  O U T P U T
//--------------------------------------------------------------------------
struct outctx_base_t
{
  // information for creating one line
  ea_t insn_ea;
  qstring outbuf;      // buffer for the current output line
                       // once ready, it is moved to lnar
  ssize_t regname_idx; // to rename registers
  int suspop;          // controls color for out_long()
  flags_t F32;         // please use outctx_t::F instead
  uval_t *outvalues;   // at least 2*UA_MAXOP elements
  int outvalue_getn_flags; // additional flags for print_operand()
  void *user_data;     // pointer to be used by the processor module for any purpose
  void *kern_data;     // internal info used by the kernel

  // information for generating many lines
  qstrvec_t *lnar;     // vector of output lines
  int lnar_maxsize;    // max permitted size of lnar
  int default_lnnum;   // index of the most important line in lnar

  qstring line_prefix; // usually segname:offset
  ssize_t prefix_len;  // visible length of line_prefix
  int ctxflags;        // various bits
#define CTXF_MAIN         0x00001 // produce only the essential line(s)
#define CTXF_MULTI        0x00002 // enable multi-line essential lines
#define CTXF_CODE         0x00004 // display as code regardless of the database flags
#define CTXF_STACK        0x00008 // stack view (display undefined items as 2/4/8 bytes)
#define CTXF_GEN_XREFS    0x00010 // generate the xrefs along with the next line
#define CTXF_XREF_STATE   0x00060 // xref state:
#define   XREFSTATE_NONE   0x00   // not generated yet
#define   XREFSTATE_GO     0x20   // being generated
#define   XREFSTATE_DONE   0x40   // have been generated
#define CTXF_GEN_CMT      0x00080 // generate the comment along with the next line
#define CTXF_CMT_STATE    0x00300 // comment state:
#define   COMMSTATE_NONE   0x000  // not generated yet
#define   COMMSTATE_GO     0x100  // being generated
#define   COMMSTATE_DONE   0x200  // have been generated
#define CTXF_VOIDS        0x00400 // display void marks
#define CTXF_NORMAL_LABEL 0x00800 // generate plain label (+demangled label as cmt)
#define CTXF_DEMANGLED_LABEL 0x01000 // generate only demangled label as comment
#define CTXF_LABEL_OK     0x02000 // the label have been generated
#define CTXF_DEMANGLED_OK 0x04000 // the label has been demangled successfully
#define CTXF_OVSTORE_PRNT 0x08000 // out_value should store modified values
#define CTXF_OUTCTX_T     0x10000 // instance is, in fact, a outctx_t
#define CTXF_DBLIND_OPND  0x20000 // an operand was printed with double indirection (e.g. =var in arm)
#define CTXF_BINOP_STATE  0xC0000 // opcode bytes state:
#define   BINOPSTATE_NONE  0x00000 // not generated yet
#define   BINOPSTATE_GO    0x40000 // being generated
#define   BINOPSTATE_DONE  0x80000 // have been generated
#define CTXF_HIDDEN_ADDR  0x100000 // To generate an hidden addr tag at the beginning of the line

  // internal data used by the kernel
  int ind0;
  ea_t cmt_ea;         // indirectly referenced address (used to generate cmt)
  qstring cmtbuf;      // indented comment
  const char *cmtptr;  // rest of indented comment
  color_t cmtcolor;    // comment color

  inline bool only_main_line() const { return (ctxflags & CTXF_MAIN) != 0; }
  inline bool multiline() const { return (ctxflags & CTXF_MULTI) != 0; }
  inline bool force_code() const { return (ctxflags & CTXF_CODE) != 0; }
  inline bool stack_view() const { return (ctxflags & CTXF_STACK) != 0; }
  inline bool display_voids() const { return (ctxflags & CTXF_VOIDS) != 0; }
  inline void set_gen_xrefs(bool on=true) { setflag(ctxflags, CTXF_GEN_XREFS, on); }
  inline int get_xrefgen_state() const { return ctxflags & CTXF_XREF_STATE; }
  inline void set_gen_cmt(bool on=true) { setflag(ctxflags, CTXF_GEN_CMT, on); }
  inline int get_cmtgen_state() const { return ctxflags & CTXF_CMT_STATE; }
  inline int get_binop_state() const { return ctxflags & CTXF_BINOP_STATE; }
  inline void clr_gen_label(void) { ctxflags &= ~(CTXF_NORMAL_LABEL|CTXF_DEMANGLED_LABEL); }
  inline void set_gen_label(void) { ctxflags |= CTXF_NORMAL_LABEL; }
  inline void set_gen_demangled_label(void) { ctxflags |= CTXF_DEMANGLED_LABEL; ctxflags &= ~CTXF_NORMAL_LABEL; }
  inline void set_comment_addr(ea_t ea) { cmt_ea = ea; }
  inline void set_dlbind_opnd(void) { ctxflags |= CTXF_DBLIND_OPND; }
  inline bool print_label_now() const
  {
    return (ctxflags & (CTXF_LABEL_OK|CTXF_MAIN)) == 0                 // label not ready
        && (ctxflags & (CTXF_NORMAL_LABEL|CTXF_DEMANGLED_LABEL)) != 0; // requested it
  }
  int forbid_annotations()
  { // temporarily forbid printing of xrefs, label, cmt
    int bits = CTXF_GEN_XREFS|CTXF_NORMAL_LABEL|CTXF_DEMANGLED_LABEL|CTXF_GEN_CMT;
    int saved_flags = ctxflags & bits;
    ctxflags &= ~bits;
    return saved_flags;
  }
  void restore_ctxflags(int saved_flags)
  {
    ctxflags |= saved_flags;
  }

  outctx_base_t(ea_t ea, flags64_t flags, int _suspop=0)
    : insn_ea(ea), regname_idx(-1), suspop(_suspop), F32(flags),
      outvalues(nullptr), outvalue_getn_flags(0), user_data(nullptr), kern_data(nullptr),
      lnar(nullptr), lnar_maxsize(0), default_lnnum(-1),
      prefix_len(0), ctxflags(0), ind0(0), cmt_ea(BADADDR), cmtptr(nullptr), cmtcolor(0xFF)
  {
    outbuf.reserve(MAXSTR);
  }
  virtual ~outctx_base_t(void);

  ///-------------------------------------------------------------------------
  /// Functions to append text to the current output buffer (outbuf)

  /// Append a formatted string to the output string.
  /// \return the number of characters appended
  AS_PRINTF(2, 3) void out_printf(const char *format, ...)
  {
    va_list va;
    va_start(va, format);
    out_vprintf(format, va);
    va_end(va);
  }

  GCC_DIAG_OFF(format-nonliteral);
  void nowarn_out_printf(const char *format, ...) //-V524 body is equal to out_printf
  {
    va_list va;
    va_start(va, format);
    out_vprintf(format, va);
    va_end(va);
  }
  GCC_DIAG_ON(format-nonliteral);

  virtual AS_PRINTF(2, 0) void idaapi out_vprintf(const char *format, va_list va);

  /// Output immediate value.
  /// Try to use this function to output all constants of instruction operands.
  /// This function outputs a number from x.addr or x.value in the form
  /// determined by ::uFlag. It outputs a colored text.
  ///   - -1 is output with #COLOR_ERROR
  ///   -  0 is output as a number or character or segment
  /// \param x    value to output
  /// \param outf \ref OOF_
  /// \return flags of the output value
  virtual flags64_t idaapi out_value(const op_t &x, int outf=0);

  /// \defgroup OOF_ Output value flags
  /// Flags passed to out_value().
  /// (don't use #OOF_SIGNMASK and #OOF_WIDTHMASK, they are for the kernel)
  //@{
#define OOF_SIGNMASK    0x0003      ///< sign symbol (+/-) output
#define   OOFS_IFSIGN   0x0000      ///<   output sign if needed
#define   OOFS_NOSIGN   0x0001      ///<   don't output sign, forbid the user to change the sign
#define   OOFS_NEEDSIGN 0x0002      ///<   always out sign         (+-)
#define OOF_SIGNED      0x0004      ///< output as signed if < 0
#define OOF_NUMBER      0x0008      ///< always as a number
#define OOF_WIDTHMASK   0x0070      ///< width of value in bits
#define   OOFW_IMM      0x0000      ///<   take from x.dtype
#define   OOFW_8        0x0010      ///<   8 bit width
#define   OOFW_16       0x0020      ///<   16 bit width
#define   OOFW_24       0x0030      ///<   24 bit width
#define   OOFW_32       0x0040      ///<   32 bit width
#define   OOFW_64       0x0050      ///<   64 bit width
#define OOF_ADDR        0x0080      ///< output x.addr, otherwise x.value
#define OOF_OUTER       0x0100      ///< output outer operand
#define OOF_ZSTROFF     0x0200      ///< meaningful only if is_stroff(uFlag);
                                    ///< append a struct field name if
                                    ///< the field offset is zero?
                                    ///< if #AFL_ZSTROFF is set, then this flag
                                    ///< is ignored.
#define OOF_NOBNOT      0x0400      ///< prohibit use of binary not
#define OOF_SPACES      0x0800      ///< do not suppress leading spaces;
                                    ///< currently works only for floating point numbers
#define OOF_ANYSERIAL   0x1000      ///< if enum: select first available serial
  //@}

  /// Output a character with #COLOR_SYMBOL color.
  virtual void idaapi out_symbol(char c);

  /// Append a character multiple times
  virtual void idaapi out_chars(char c, int n);

  /// Appends spaces to outbuf until its tag_strlen becomes 'len'
  void out_spaces(ssize_t len) { add_spaces(&outbuf, len); }
  virtual void idaapi add_spaces(qstring *buf, ssize_t len);

  /// Output a string with the specified color.
  virtual void idaapi out_line(const char *str, color_t color=0);

  /// Output a string with #COLOR_KEYWORD color.
  inline void out_keyword(const char *str)
  {
    out_line(str, COLOR_KEYWORD);
  }

  /// Output a character with #COLOR_REG color.
  inline void out_register(const char *str)
  {
    out_line(str, COLOR_REG);
  }

  /// Output "turn color on" escape sequence
  virtual void idaapi out_tagon(color_t tag);

  /// Output "turn color off" escape sequence
  virtual void idaapi out_tagoff(color_t tag);

  /// Output "address" escape sequence
  virtual void idaapi out_addr_tag(ea_t ea);

  /// Output a colored line with register names in it.
  /// The register names will be substituted by user-defined names (regvar_t)
  /// Please note that out_tagoff tries to make substitutions too (when called with COLOR_REG)
  virtual void idaapi out_colored_register_line(const char *str);

  /// Output one character.
  /// The character is output without color codes.
  /// see also out_symbol()
  virtual void idaapi out_char(char c) { outbuf.append(c); }

  /// Output a number with the specified base (binary, octal, decimal, hex)
  /// The number is output without color codes.
  /// see also out_long()
  virtual void idaapi out_btoa(uval_t Word, char radix=0);

  /// \fn void out_long(sval_t, char)
  /// Output a number with appropriate color.
  /// Low level function. Use out_value() if you can.
  /// if 'suspop' is set then
  ///   this function uses #COLOR_VOIDOP instead of #COLOR_NUMBER.
  /// 'suspop' is initialized:
  ///   - in out_one_operand()
  ///   - in ..\ida\gl.cpp (before calling \ph{d_out()})
  /// \param v      value to output
  /// \param radix  base (2,8,10,16)
  /// \param suspop ::suspop
  ///               - suspop==0: operand is ok
  ///               - suspop==1: operand is suspicious and should be output with #COLOR_VOIDOP
  ///               - suspop==2: operand can't be output as requested and should be output with #COLOR_ERROR
  virtual void idaapi out_long(sval_t v, char radix);

  /// Output a name expression.
  /// \param x    instruction operand referencing the name expression
  /// \param ea   address to convert to name expression
  /// \param off  the value of name expression. this parameter is used only to
  ///             check that the name expression will have the wanted value.
  ///             You may pass #BADADDR for this parameter but I discourage it
  ///             because it prohibits checks.
  /// \return true if the name expression has been produced
  virtual bool idaapi out_name_expr(
        const op_t &x,
        ea_t ea,
        adiff_t off=BADADDR);

  // Generate the closing comment if if it required by the assembler

  inline void close_comment(void) { out_line(closing_comment()); }

  ///-------------------------------------------------------------------------
  /// Functions to populate the output line array (lnar)

  /// Move the contents of the output buffer to the line array (outbuf->lnar)
  /// The kernel augments the outbuf contents with additional text like
  /// the line prefix, user-defined comments, xrefs, etc at this call.
  virtual bool idaapi flush_outbuf(int indent=-1);

  /// Append contents of 'buf' to the line array.
  /// Behaves like flush_outbuf but accepts an arbitrary buffer
  virtual bool idaapi flush_buf(const char *buf, int indent=-1);

  /// Finalize the output context.
  /// \return the number of generated lines.
  virtual int idaapi term_outctx(const char *prefix=nullptr);

  /// See gen_printf()
  virtual AS_PRINTF(3, 0) bool idaapi gen_vprintf(
        int indent,
        const char *format,
        va_list va);

  /// printf-like function to add lines to the line array.
  /// \param indent   indention of the line.
  ///                 if indent == -1, the kernel will indent the line
  ///                 at \inf{indent}. if indent < 0, -indent will be used for indention.
  ///                 The first line printed with indent < 0 is considered as the
  ///                 most important line at the current address. Usually it is
  ///                 the line with the instruction itself. This line will be
  ///                 displayed in the cross-reference lists and other places.
  ///                 If you need to output an additional line before the main line
  ///                 then pass DEFAULT_INDENT instead of -1. The kernel will know
  ///                 that your line is not the most important one.
  /// \param format   printf style colored line to generate
  /// \return overflow, lnar_maxsize has been reached

  AS_PRINTF(3, 4) inline bool gen_printf(int indent, const char *format, ...)
  {
    va_list va;
    va_start(va, format);
    bool code = gen_vprintf(indent, format, va);
    va_end(va);
    return code;
  }
#define DEFAULT_INDENT 0xFFFF

  /// Generate empty line. This function does nothing if generation of empty
  /// lines is disabled.
  /// \return overflow, lnar_maxsize has been reached

  virtual bool idaapi gen_empty_line(void);


  /// Generate thin border line. This function does nothing if generation
  /// of border lines is disabled.
  /// \param solid generate solid border line (with =), otherwise with -
  /// \return overflow, lnar_maxsize has been reached

  virtual bool idaapi gen_border_line(bool solid=false);

  /// See gen_cmt_line()
  virtual AS_PRINTF(3, 0) bool idaapi gen_colored_cmt_line_v(
          color_t color,
          const char *format,
          va_list va);

  /// See gen_cmt_line()

  AS_PRINTF(2, 0) inline bool gen_cmt_line_v(const char *format, va_list va)
  {
    return gen_colored_cmt_line_v(COLOR_AUTOCMT, format, va);
  }

  /// Generate one non-indented comment line, colored with ::COLOR_AUTOCMT.
  /// \param format  printf() style format line. The resulting comment line
  ///                should not include comment character (;)
  /// \return overflow, lnar_maxsize has been reached

  AS_PRINTF(2, 3) inline bool gen_cmt_line(const char *format, ...)
  {
    va_list va;
    va_start(va, format);
    bool code = gen_cmt_line_v(format, va);
    va_end(va);
    return code;
  }

  /// Generate one non-indented comment line, colored with ::COLOR_COLLAPSED.
  /// \param format  printf() style format line. The resulting comment line
  ///                should not include comment character (;)
  /// \return overflow, lnar_maxsize has been reached

  AS_PRINTF(2, 3) inline bool gen_collapsed_line(const char *format, ...)
  {
    va_list va;
    va_start(va,format);
    bool answer = gen_colored_cmt_line_v(COLOR_COLLAPSED, format, va);
    va_end(va);
    return answer;
  }

  /// Generate big non-indented comment lines.
  /// \param cmt    comment text. may contain \\n characters to denote new lines.
  ///               should not contain comment character (;)
  /// \param color  color of comment text (one of \ref COLOR_)
  /// \return overflow, lnar_maxsize has been reached

  virtual bool idaapi gen_block_cmt(const char *cmt, color_t color);

  //-------------------------------------------------------------------------
  /// Initialization; normally used only by the kernel
  virtual void idaapi setup_outctx(const char *prefix, int makeline_flags);
#define MAKELINE_NONE           0x00
#define MAKELINE_BINPREF        0x01    // allow display of binary prefix
#define MAKELINE_VOID           0x02    // allow display of '<suspicious>' marks
#define MAKELINE_STACK          0x04    // allow display of sp trace prefix

  virtual ssize_t idaapi retrieve_cmt(void) { return -1; }
  virtual ssize_t idaapi retrieve_name(qstring *, color_t *) { return -1; }
  virtual bool idaapi gen_xref_lines(void) { return false; }

  virtual void idaapi init_lines_array(qstrvec_t *answers, int maxsize);

  virtual member_t *idaapi get_stkvar(const op_t &, uval_t, sval_t *, int *);

  void gen_empty_line_without_annotations(void)
  {
    int saved_flags = forbid_annotations();
    gen_empty_line();
    restore_ctxflags(saved_flags);
  }

  inline flags64_t getF() const;


protected:
  virtual bool idaapi flush_and_reinit(void);
  virtual void idaapi append_user_prefix(const char *, int) {}
  virtual void idaapi add_aux_prefix(const char *, int) {}
  virtual void idaapi out_label_addr_tag(void) {}
  virtual void idaapi out_aux_cmts(void) {}
};

//--------------------------------------------------------------------------
// This class is used to print instructions and data items
struct outctx_t : public outctx_base_t
{
  // kernel only data:
  ea_t bin_ea;                 // Current binary format EA
  char bin_state;              // =0 not generated,1-in process,2-finished
  int gl_bpsize = 0;           // binary line prefix size
  int bin_width = 0;

  // instruction to display:
  insn_t insn;                 // valid only when ph.out_insn() is called

  // colorized and demangled label of the current address
  qstring curlabel;

  // opinfo_t to use for out_value()
  const printop_t *wif;

  // processor module and its description
  procmod_t *procmod;
  processor_t &ph;
  asm_t &ash;

  // out_value() saves the printed values here
  uval_t saved_immvals[UA_MAXOP] = { 0 };

  ea_t prefix_ea = BADADDR;
  ea_t next_line_ea = BADADDR;       // EA of next line (for prefix)
  flags64_t F = 0;

  outctx_t(
        procmod_t *p,
        processor_t &ph,
        asm_t &ash,
        ea_t ea,
        flags64_t flags=0,
        int _suspop=0,
        const printop_t *_wif=nullptr);
  ~outctx_t(void)
  {
  }
  virtual void idaapi setup_outctx(const char *prefix, int flags) override;
  virtual int idaapi term_outctx(const char *prefix=nullptr) override;
  virtual ssize_t idaapi retrieve_cmt(void) override;
  virtual ssize_t idaapi retrieve_name(qstring *, color_t *) override;
  virtual bool idaapi gen_xref_lines(void) override;
  virtual void idaapi out_btoa(uval_t Word, char radix=0) override;

  void set_bin_state(int value)
  {
    bin_state = value;
    ctxflags &= ~CTXF_BINOP_STATE;
    ctxflags |= value == 0 ? BINOPSTATE_NONE
              : value == 1 ? BINOPSTATE_GO
              :              BINOPSTATE_DONE;
  }

  /// Output instruction mnemonic for 'insn' using information in 'ph.instruc' array.
  /// This function outputs a colored text.
  /// It should be called from \ph{ev_out_insn()} or \ph{ev_out_mnem()} handler.
  /// It will output at least one space after the instruction.
  /// mnemonic even if the specified 'width' is not enough.
  /// \param width    width of field with mnemonic.
  ///                 if < 0, then 'postfix' will be output before
  ///                 the mnemonic, i.e. as a prefix
  /// \param postfix  optional postfix added to the instruction mnemonic
  virtual void idaapi out_mnem(int width=8, const char *postfix=nullptr) newapi;

  /// Output custom mnemonic for 'insn'.
  /// E.g. if it should differ from the one in 'ph.instruc'.
  /// This function outputs colored text. See \ref out_mnem
  /// \param mnem     custom mnemonic
  /// \param width    width of field with mnemonic.
  ///                 if < 0, then 'postfix' will be output before
  ///                 the mnemonic, i.e. as a prefix
  /// \param postfix  optional postfix added to 'mnem'
  virtual void idaapi out_custom_mnem(
        const char *mnem,
        int width=8,
        const char *postfix=nullptr) newapi;

  /// Output instruction mnemonic using information in 'insn'.
  /// It should be called from \ph{ev_out_insn()} and
  /// it will call \ph{ev_out_mnem()} or \ref out_mnem.
  /// This function outputs a colored text.
  virtual void idaapi out_mnemonic(void) newapi;

  /// Use this function to output an operand of an instruction.
  /// This function checks for the existence of a manually defined operand
  /// and will output it if it exists.
  /// It should be called from \ph{ev_out_insn()} and it will call \ph{ev_out_operand()}.
  /// This function outputs a colored text.
  /// \param n   0..#UA_MAXOP-1 operand number
  /// \retval 1  operand is displayed
  /// \retval 0  operand is hidden
  virtual bool idaapi out_one_operand(int n) newapi;

  /// Get the immediate values used at the specified address.
  /// This function can handle instructions and data items.
  /// \param out array of values, size at least 2*UA_MAXOP
  /// \param i   operand number
  /// \return number of immediate values
  virtual size_t idaapi get_immvals(uval_t *out, int i) newapi;

  /// Print all operand values as commented character constants.
  /// This function is used to comment void operands with their representation
  /// in the form of character constants.
  /// This function outputs a colored text.
  virtual void idaapi out_immchar_cmts(void) newapi;

  virtual void idaapi gen_func_header(func_t *pfn) newapi;
  virtual void idaapi gen_func_footer(const func_t *pfn) newapi;

  // display data items and undefined bytes.
  virtual void idaapi out_data(bool analyze_only) newapi;

  // generate declaration for item in a special segment
  // return: 0-ok, 1-overflow
  virtual bool idaapi out_specea(uchar segtype) newapi;

  // convenience functions for processor modules
  // print lines from ash.header
  virtual void idaapi gen_header_extra() newapi;

  // flags for gen_header()
#define GH_PRINT_PROC           (1 << 0)  // processor name
#define GH_PRINT_ASM            (1 << 1)  // selected assembler
#define GH_PRINT_BYTESEX        (1 << 2)  // byte sex
#define GH_PRINT_HEADER         (1 << 3)  // lines from ash.header
#define GH_BYTESEX_HAS_HIGHBYTE (1 << 4)  // describe inf.is_wide_high_byte_first()
#define GH_PRINT_PROC_AND_ASM (GH_PRINT_PROC | GH_PRINT_ASM)
#define GH_PRINT_PROC_ASM_AND_BYTESEX (GH_PRINT_PROC_AND_ASM | GH_PRINT_BYTESEX)
#define GH_PRINT_ALL (GH_PRINT_PROC_ASM_AND_BYTESEX | GH_PRINT_HEADER)
#define GH_PRINT_ALL_BUT_BYTESEX (GH_PRINT_PROC_AND_ASM | GH_PRINT_HEADER)
  virtual void idaapi gen_header(
        int flags = GH_PRINT_PROC_AND_ASM,
        const char *proc_name = nullptr,
        const char *proc_flavour = nullptr) newapi;
};

//-------------------------------------------------------------------------
inline flags64_t outctx_base_t::getF() const
{
  return (ctxflags & CTXF_OUTCTX_T) != 0 ? ((outctx_t *) this)->F : F32;
}

//--------------------------------------------------------------------------
/// Create a new output context.
/// To delete it, just use "delete pctx"

idaman outctx_base_t *ida_export create_outctx(ea_t ea, flags64_t F=0, int suspop=0);


/// Print instruction mnemonics.
/// \param out      output buffer
/// \param ea       linear address of the instruction
/// \return success

idaman bool ida_export print_insn_mnem(qstring *out, ea_t ea);


/// \defgroup FCBF_ format flags
/// Used by format_charlit
//@{
#define FCBF_CONT     0x00000001 ///< don't stop on decoding, or any other kind of error
#define FCBF_ERR_REPL 0x00000002 ///< in case of an error, use a CP_REPLCHAR instead
                                 ///< of a hex representation of the problematic byte

#define FCBF_FF_LIT   0x00000004 ///< in case of codepoints == 0xFF, use it as-is (i.e., LATIN SMALL LETTER Y WITH DIAERESIS).
                                 ///< If both this, and FCBF_REPL are specified,
                                 ///< this will take precedence

#define FCBF_DELIM    0x00000008 ///< add the 'ash'-specified delimiters around the generated data.
                                 ///< Note: if those are not defined and the INFFL_ALLASM is not set,
                                 ///< format_charlit() will return an error
//@}


/// Format character literal.
///
/// Try and format 'size' bytes pointed to by '*ptr', as literal characters,
/// using the 'encidx' encoding, and with the specified 'flags' directives.
///
/// By default, format_charlit() will fail and return an error, in
/// any of the following cases:
///  - a byte cannot be decoded using the specified (or default) encoding
///  - a codepoint is < 0x20 (i.e., ' ')
///  - a codepoint is present in 'ash.esccodes'
///  - a codepoint is 0xFF
///  - a codepoint is >= 0x80, and AS_NHIAS was specified in ash.flag
/// The function can be told to keep going instead of bailing out, for any
/// of these situations, by using one of the FCBF_*_OK flags.
///
/// If the function is told to proceed on a specific error, by default
/// it will format the byte as a C-encoded byte value (i.e., '\xNN'),
/// unless the corresponding FCBF_*_REPL flag is passed, in which case
/// the problematic byte/codepoint will be replaced by the Unicode
/// replacement character in the output.
///
/// \param out    output buffer (can be nullptr)
/// \param ptr    pointer to pointer to bytes to print (will be advanced
///               by the number of bytes that were successfully printed)
/// \param size   size of input value in bytes
/// \param flags  \ref FCBF_
/// \param encidx the 1 byte-per-unit encoding to use (or 0 to use the default 1 BPU encoding)
/// \return success

idaman bool ida_export format_charlit(
        qstring *out,
        const uchar **ptr,
        size_t size,
        uint32 flags=0,
        int encidx=0);


/// Print a floating point value.
/// \param buf      output buffer. may be nullptr
/// \param bufsize  size of the output buffer
/// \param v        floating point value in processor native format
/// \param size     size of the value in bytes
/// \return true    ok
/// \return false   can't represent as floating point number

idaman bool ida_export print_fpval(char *buf, size_t bufsize, const void *v, int size);


//--------------------------------------------------------------------------
//      I D P   H E L P E R   F U N C T I O N S  -  E M U L A T O R
//--------------------------------------------------------------------------
/// Get flags for op_t::dtype field
idaman flags64_t ida_export get_dtype_flag(op_dtype_t dtype);
/// Get size of opt_::dtype field
idaman size_t ida_export get_dtype_size(op_dtype_t dtype);
/// Get op_t::dtype from size
idaman op_dtype_t ida_export get_dtype_by_size(asize_t size);

/// Is a floating type operand?
inline bool is_floating_dtype(op_dtype_t dtype)
{
  return dtype == dt_float
      || dtype == dt_double
      || dtype == dt_tbyte
      || dtype == dt_ldbl
      || dtype == dt_half;
}


//--------------------------------------------------------------------------
//      K E R N E L   I N T E R F A C E   T O   I D P   F U N C T I O N S
//--------------------------------------------------------------------------
/// Create an instruction at the specified address.
/// This function checks if an instruction is present at the specified address
/// and will try to create one if there is none. It will fail if there is
/// a data item or other items hindering the creation of the new instruction.
/// This function will also fill the 'out' structure.
/// \param ea   linear address
/// \param out  the resulting instruction
/// \return the length of the instruction or 0
idaman int ida_export create_insn(ea_t ea, insn_t *out=nullptr);


/// Analyze the specified address and fill 'out'.
/// This function does not modify the database.
/// It just tries to interpret the specified address as an instruction and fills
/// the 'out' structure.
/// \param out  the resulting instruction
/// \param ea  linear address
/// \return the length of the (possible) instruction or 0

idaman int ida_export decode_insn(insn_t *out, ea_t ea);

/// Can the bytes at address 'ea' be decoded as instruction?
/// \param ea linear address
/// \return whether or not the contents at that address could be a valid instruction

inline bool can_decode(ea_t ea) { insn_t insn; return decode_insn(&insn, ea) > 0; }


/// Generate text representation for operand #n.
/// This function will generate the text representation of the specified
/// operand (includes color codes.)
/// \param out      output buffer
/// \param ea       the item address (instruction or data)
/// \param n        0..#UA_MAXOP-1 operand number, meaningful only for instructions
/// \param getn_flags \ref GETN_
///                 Currently only #GETN_NODUMMY is accepted.
/// \param newtype  if specified, print the operand using the specified type
/// \return success

idaman bool ida_export print_operand(
        qstring *out,
        ea_t ea,
        int n,
        int getn_flags=0,
        struct printop_t *newtype=nullptr);


//--------------------------------------------------------------------------
//      Helper functions for the processor emulator/analyzer
//--------------------------------------------------------------------------

/// Decode previous instruction if it exists, fill 'out'.
/// \param out      the resulting instruction
/// \param ea       the address to decode the previous instruction from
/// \return the previous instruction address (#BADADDR-no such insn)

idaman ea_t ida_export decode_prev_insn(insn_t *out, ea_t ea);


/// Decode preceding instruction in the execution flow.
/// Prefer far xrefs from addresses < the current to ordinary flows.
/// \param out      the resulting instruction
/// \param ea       the address to decode the preceding instruction from
/// \param p_farref will contain 'true' if followed an xref, false otherwise.
/// \return the preceding instruction address (#BADADDR-no such insn) and 'out'.

idaman ea_t ida_export decode_preceding_insn(insn_t *out, ea_t ea, bool *p_farref=nullptr);


/// Helper class for processor modules to build macro instructions.
struct macro_constructor_t
{
  size_t reserved = 0;

  virtual ~macro_constructor_t() {}

  /// Construct a macro instruction.
  /// This function may be called from ana() to generate a macro instruction.
  ///
  /// The real work is done by the 'build_macro()' virtual function.
  /// It must be defined by the processor module.
  ///
  /// construct_macro() modifies the database using the info provided
  /// by build_macro(). It verifies if the instruction can really be created
  /// (for example, that other items do not hinder), may plan to reanalyze
  /// the macro, etc.
  /// If the macro instructions are disabled by the user, construct_macro()
  /// will destroy the macro instruction. Note: if INSN_MODMAC is not set in
  /// insn.flags, the database will not be modified.
  ///
  /// \param insn   the instruction to modify into a macro
  /// \param enable enable macro generation
  /// \retval true   the macro instruction is generated in 'insn'
  /// \retval false  did not create a macro
  inline bool construct_macro(insn_t *insn, bool enable);

  /// Try to extend the instruction.
  /// \param insn           Instruction to modify, usually the first
  ///                       instruction of the macro
  /// \param may_go_forward Is it ok to consider the next instruction for the macro?
  ///                       This argument may be false, for example, if there is
  ///                       a cross reference to the end of INSN. In this case
  ///                       creating a macro is not desired. However, it may still
  ///                       be useful to perform minor tweaks to the instruction
  ///                       using the information about the surrounding instructions.
  /// \return true if created an macro instruction.
  /// This function may modify 'insn' and return false; these changes will be
  /// accepted by the kernel but the instruction will not be considered as a macro.
  virtual bool idaapi build_macro(insn_t *insn, bool may_go_forward) = 0;
};

// Do not directly call this function, use macro_constructor_t
idaman bool ida_export construct_macro2(
        macro_constructor_t *_this,
        insn_t *insn,
        bool enable);

inline bool macro_constructor_t::construct_macro(insn_t *insn, bool enable)
{
  return construct_macro2(this, insn, enable);
}


/// Does the instruction spoil any register from 'regs'?.
/// This function checks the \ref CF_ flags from the instructions array.
/// Only ::o_reg operand types are consulted.
/// \param  insn  the instruction
/// \param  regs  array with register indexes
/// \param  n     size of 'regs'
/// \return index in the 'regs' array or -1

idaman int ida_export get_spoiled_reg(const insn_t &insn, const uint32 *regs, size_t n);


//-------------------------------------------------------------------------

#ifndef NO_OBSOLETE_FUNCS
idaman DEPRECATED bool ida_export print_charlit(char *buf, const void *ptr, int size);
idaman DEPRECATED bool ida_export construct_macro(insn_t &insn, bool enable, bool (idaapi *build_macro)(insn_t &insn, bool may_go_forward)); // use construct_macro2()
#endif // NO_OBSOLETE_FUNCS

#endif // _UA_HPP
