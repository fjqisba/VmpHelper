/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _INTEL_HPP
#define _INTEL_HPP
#include <ua.hpp>
#include <typeinf.hpp>
#include <allins.hpp>

#define PROC_MAXOP 5  // max number of operands
CASSERT(PROC_MAXOP <= UA_MAXOP);

//---------------------------------
// Intel 80x86 insn_t.auxpref bits
#define aux_lock        0x00000001
#define aux_rep         0x00000002
#define aux_repne       0x00000004
#define aux_use32       0x00000008  // segment type is 32-bits
#define aux_use64       0x00000010  // segment type is 64-bits
#define aux_large       0x00000020  // offset field is 32-bit (16-bit is not enough)
#define aux_short       0x00000040  // short (byte) displacement used
#define aux_sgpref      0x00000080  // a segment prefix byte is not used
#define aux_oppref      0x00000100  // operand size prefix byte is not used
#define aux_adpref      0x00000200  // address size prefix byte is not used
#define aux_basess      0x00000400  // SS based instruction
#define aux_natop       0x00000800  // operand size is not overridden by prefix
#define aux_natad       0x00001000  // addressing mode is not overridden by prefix
#define aux_fpemu       0x00002000  // FP emulator instruction
#define aux_vexpr       0x00004000  // VEX-encoded instruction
#define aux_bnd         0x00008000  // MPX-encoded instruction
#define aux_evex        0x00010000  // EVEX-encoded instruction
#define aux_xop         0x00020000  // XOP-encoded instruction
#define aux_xacquire    0x00040000  // HLE prefix hints
#define aux_xrelease    0x00080000  // HLE prefix hints

//---------------------------------
// operand types and other customization:
#define o_trreg         o_idpspec0      // IDP specific type
#define o_dbreg         o_idpspec1      // IDP specific type
#define o_crreg         o_idpspec2      // IDP specific type
#define o_fpreg         o_idpspec3      // IDP specific type
#define o_mmxreg        o_idpspec4      // IDP specific type
#define o_xmmreg        o_idpspec5      // xmm register
#define o_ymmreg        o_idpspec5+1    // ymm register
#define o_zmmreg        o_idpspec5+2    // zmm register
#define o_kreg          o_idpspec5+3    // opmask register

// 04.10.97: For o_mem,o_near,o_far we keep segment information as
// segrg - number of segment register to use
// if it is == SEGREG_IMM, then the segment was specified as an immediate
// value, look at segsel.

#define segrg           specval_shorts.high
#define SEGREG_IMM      0xFFFF          // this value of segrg means that
                                        // segment selector value is in
                                        // "segsel":
#define segsel          specval_shorts.low
#define hasSIB          specflag1
#define sib             specflag2
#define rex             insnpref        // REX byte for 64-bit mode, or bits from the VEX byte if vexpr()

// Op6 is used for opmask registers in EVEX.
// specflags from Op6 are used to extend insn_t.
#define evex_flags      Op6.specflag2   // bits from the EVEX byte if evexpr()

#define cr_suff         specflag1       // o_crreg: D suffix for cr registers (used for CR8D)

// bits in insn_t.evex_flags:
const int EVEX_R = 0x01;           // High-16 register specifier modifier
const int EVEX_L = 0x02;           // Vector length/RC
const int EVEX_z = 0x04;           // Zeroing/Merging
const int EVEX_b = 0x08;           // Broadcast/RC/SAE Context
const int EVEX_V = 0x10;           // High-16 NDS/VIDX register specifier

// bits in insn_t.rex:
const int REX_W = 8;               // 64-bit operand size
const int REX_R = 4;               // modrm reg field extension
const int REX_X = 2;               // sib index field extension
const int REX_B = 1;               // modrm r/m, sib base, or opcode reg fields extension
const int VEX_L = 0x80;            // 256-bit operation (YMM register)

typedef short regnum_t;

enum RegNo
{
  R_none = -1,
  R_ax = 0,
  R_cx,         //  1
  R_dx,         //  2
  R_bx,         //  3
  R_sp,         //  4
  R_bp,         //  5
  R_si,         //  6
  R_di,         //  7
  R_r8,         //  8
  R_r9,         //  9
  R_r10,        // 10
  R_r11,        // 11
  R_r12,        // 12
  R_r13,        // 13
  R_r14,        // 14
  R_r15,        // 15

  R_al,
  R_cl,
  R_dl,
  R_bl,
  R_ah,
  R_ch,
  R_dh,
  R_bh,

  R_spl,
  R_bpl,
  R_sil,
  R_dil,

  R_ip,

  R_es,    // 0
  R_cs,    // 1
  R_ss,    // 2
  R_ds,    // 3
  R_fs,
  R_gs,

  R_cf,    // main cc's
  R_zf,
  R_sf,
  R_of,

  R_pf,    // additional cc's
  R_af,
  R_tf,
  R_if,
  R_df,

  R_efl,   // eflags

  // the following registers will be used in the disassembly
  // starting from ida v5.7

  R_st0,   // floating point registers (not used in disassembly)
  R_st1,
  R_st2,
  R_st3,
  R_st4,
  R_st5,
  R_st6,
  R_st7,
  R_fpctrl,// fpu control register
  R_fpstat,// fpu status register
  R_fptags,// fpu tags register

  R_mm0,   // mmx registers
  R_mm1,
  R_mm2,
  R_mm3,
  R_mm4,
  R_mm5,
  R_mm6,
  R_mm7,

  R_xmm0,  // xmm registers
  R_xmm1,
  R_xmm2,
  R_xmm3,
  R_xmm4,
  R_xmm5,
  R_xmm6,
  R_xmm7,
  R_xmm8,
  R_xmm9,
  R_xmm10,
  R_xmm11,
  R_xmm12,
  R_xmm13,
  R_xmm14,
  R_xmm15,
  R_mxcsr,

  R_ymm0,  // AVX 256-bit registers
  R_ymm1,
  R_ymm2,
  R_ymm3,
  R_ymm4,
  R_ymm5,
  R_ymm6,
  R_ymm7,
  R_ymm8,
  R_ymm9,
  R_ymm10,
  R_ymm11,
  R_ymm12,
  R_ymm13,
  R_ymm14,
  R_ymm15,

  R_bnd0, // MPX registers
  R_bnd1,
  R_bnd2,
  R_bnd3,

  R_xmm16, // AVX-512 extended XMM registers
  R_xmm17,
  R_xmm18,
  R_xmm19,
  R_xmm20,
  R_xmm21,
  R_xmm22,
  R_xmm23,
  R_xmm24,
  R_xmm25,
  R_xmm26,
  R_xmm27,
  R_xmm28,
  R_xmm29,
  R_xmm30,
  R_xmm31,

  R_ymm16, // AVX-512 extended YMM registers
  R_ymm17,
  R_ymm18,
  R_ymm19,
  R_ymm20,
  R_ymm21,
  R_ymm22,
  R_ymm23,
  R_ymm24,
  R_ymm25,
  R_ymm26,
  R_ymm27,
  R_ymm28,
  R_ymm29,
  R_ymm30,
  R_ymm31,

  R_zmm0, // AVX-512 ZMM registers
  R_zmm1,
  R_zmm2,
  R_zmm3,
  R_zmm4,
  R_zmm5,
  R_zmm6,
  R_zmm7,
  R_zmm8,
  R_zmm9,
  R_zmm10,
  R_zmm11,
  R_zmm12,
  R_zmm13,
  R_zmm14,
  R_zmm15,
  R_zmm16,
  R_zmm17,
  R_zmm18,
  R_zmm19,
  R_zmm20,
  R_zmm21,
  R_zmm22,
  R_zmm23,
  R_zmm24,
  R_zmm25,
  R_zmm26,
  R_zmm27,
  R_zmm28,
  R_zmm29,
  R_zmm30,
  R_zmm31,

  R_k0, // AVX-512 opmask registers
  R_k1,
  R_k2,
  R_k3,
  R_k4,
  R_k5,
  R_k6,
  R_k7,

  R_last,
};

CASSERT(R_last == 173);

inline bool is_segreg(int r) { return r >= R_es && r <= R_gs; }
inline bool is_fpureg(int r) { return r >= R_st0 && r <= R_st7; }
inline bool is_mmxreg(int r) { return r >= R_mm0 && r <= R_mm7; }
inline bool is_xmmreg(int r) { return r >= R_xmm0 && r <= R_xmm15; }
inline bool is_ymmreg(int r) { return r >= R_ymm0 && r <= R_ymm15; }

int cvt_to_wholereg(int _reg, bool allow_high_byte_regs); // byte reg -> whole reg
int calc_dbg_reg_index(const char *name);

//-------------------------------------------------------------------------
// is conditional branch?
inline bool insn_jcc(const insn_t &insn)
{
  switch ( insn.itype )
  {
    case NN_ja:
    case NN_jae:
    case NN_jb:
    case NN_jbe:
    case NN_jc:
    case NN_je:
    case NN_jg:
    case NN_jge:
    case NN_jl:
    case NN_jle:
    case NN_jna:
    case NN_jnae:
    case NN_jnb:
    case NN_jnbe:
    case NN_jnc:
    case NN_jne:
    case NN_jng:
    case NN_jnge:
    case NN_jnl:
    case NN_jnle:
    case NN_jno:
    case NN_jnp:
    case NN_jns:
    case NN_jnz:
    case NN_jo:
    case NN_jp:
    case NN_jpe:
    case NN_jpo:
    case NN_js:
    case NN_jz:
      return true;
  }
  return false;
}

//-------------------------------------------------------------------------
inline bool insn_default_opsize_64(const insn_t &insn)
{
  if ( insn_jcc(insn) )
    return true;
  switch ( insn.itype )
  {
    // use ss
    case NN_pop:
    case NN_popf:
    case NN_popfq:
    case NN_push:
    case NN_pushf:
    case NN_pushfq:
    case NN_retn:
    case NN_retf:
    case NN_retnq:
    case NN_retfq:
    case NN_call:
    case NN_callfi:
    case NN_callni:
    case NN_enter:
    case NN_enterq:
    case NN_leave:
    case NN_leaveq:

    // near branches
    case NN_jcxz:
    case NN_jecxz:
    case NN_jrcxz:
    case NN_jmp:
    case NN_jmpni:
    case NN_jmpshort:
    case NN_loop:
    case NN_loopq:
    case NN_loope:
    case NN_loopqe:
    case NN_loopne:
    case NN_loopqne:
      return true;
  }
  return false;
}

inline bool mode16(const insn_t &insn)  { return (insn.auxpref & (aux_use32|aux_use64)) == 0; } // 16-bit mode?
inline bool mode32(const insn_t &insn)  { return (insn.auxpref & aux_use32) != 0; } // 32-bit mode?
inline bool mode64(const insn_t &insn)  { return (insn.auxpref & aux_use64) != 0; } // 64-bit mode?
inline bool natad(const insn_t &insn)   { return (insn.auxpref & aux_natad) != 0; } // natural address size (no prefixes)?
inline bool natop(const insn_t &insn)   { return (insn.auxpref & aux_natop) != 0; } // natural operand size (no prefixes)?
inline bool vexpr(const insn_t &insn)   { return (insn.auxpref & aux_vexpr) != 0; } // VEX encoding used
inline bool evexpr(const insn_t &insn)  { return (insn.auxpref & aux_evex)  != 0; } // EVEX encoding used
inline bool xopexpr(const insn_t &insn) { return (insn.auxpref & aux_xop)   != 0; } // XOP encoding used

inline bool ad16(const insn_t &insn)          // is current addressing 16-bit?
{
  int p = insn.auxpref & (aux_use32|aux_use64|aux_natad);
  return p == aux_natad || p == aux_use32;
}

inline bool ad32(const insn_t &insn)          // is current addressing 32-bit?
{
  int p = insn.auxpref & (aux_use32|aux_use64|aux_natad);
  return p == (aux_natad|aux_use32)
      || p == 0
      || p == aux_use64;
}

inline bool ad64(const insn_t &insn)          // is current addressing 64-bit?
{
#ifdef __EA64__
  int p = insn.auxpref & (aux_use32|aux_use64|aux_natad);
  return p == (aux_natad|aux_use64);
#else
  qnotused(insn);
  return false;
#endif
}

inline bool op16(const insn_t &insn)          // is current operand size 16-bit?
{
  int p = insn.auxpref & (aux_use32|aux_use64|aux_natop);
  return p == aux_natop                                 // 16-bit segment, no prefixes
      || p == aux_use32                                 // 32-bit segment, 66h
      || p == aux_use64 && (insn.rex & REX_W) == 0;      // 64-bit segment, 66h, no rex.w
}

inline bool op32(const insn_t &insn)          // is current operand size 32-bit?
{
  int p = insn.auxpref & (aux_use32|aux_use64|aux_natop);
  return p == 0                                         // 16-bit segment, 66h
      || p == (aux_use32|aux_natop)                     // 32-bit segment, no prefixes
      || p == (aux_use64|aux_natop) && (insn.rex & REX_W) == 0; // 64-bit segment, 66h, no rex.w
}

inline bool op64(const insn_t &insn)          // is current operand size 64-bit?
{
#ifdef __EA64__
  return mode64(insn)
      && ((insn.rex & REX_W) != 0
       || natop(insn) && insn_default_opsize_64(insn)); // 64-bit segment, rex.w or insns-64
#else
  qnotused(insn);
  return false;
#endif
}

inline bool op256(const insn_t &insn)        // is VEX.L == 1 or EVEX.L'L == 01?
{
  return (insn.rex & VEX_L) != 0
      && (vexpr(insn)
       || xopexpr(insn)
       || evexpr(insn) && (insn.evex_flags & EVEX_L) == 0);
}

inline bool op512(const insn_t &insn)        // is EVEX.L'L == 10?
{
  return evexpr(insn) && (insn.rex & VEX_L) == 0 && (insn.evex_flags & EVEX_L) != 0;
}

inline bool is_vsib(const insn_t &insn)  // does instruction use VSIB variant of the sib byte?
{
  switch ( insn.itype )
  {
    case NN_vgatherdps:
    case NN_vgatherdpd:
    case NN_vgatherqps:
    case NN_vgatherqpd:
    case NN_vpgatherdd:
    case NN_vpgatherdq:
    case NN_vpgatherqd:
    case NN_vpgatherqq:

    case NN_vscatterdps:
    case NN_vscatterdpd:
    case NN_vscatterqps:
    case NN_vscatterqpd:
    case NN_vpscatterdd:
    case NN_vpscatterdq:
    case NN_vpscatterqd:
    case NN_vpscatterqq:

    case NN_vgatherpf0dps:
    case NN_vgatherpf0qps:
    case NN_vgatherpf0dpd:
    case NN_vgatherpf0qpd:
    case NN_vgatherpf1dps:
    case NN_vgatherpf1qps:
    case NN_vgatherpf1dpd:
    case NN_vgatherpf1qpd:

    case NN_vscatterpf0dps:
    case NN_vscatterpf0qps:
    case NN_vscatterpf0dpd:
    case NN_vscatterpf0qpd:
    case NN_vscatterpf1dps:
    case NN_vscatterpf1qps:
    case NN_vscatterpf1dpd:
    case NN_vscatterpf1qpd:
      return true;
  }
  return false;
}

inline regnum_t vsib_index_fixreg(const insn_t &insn, regnum_t index)
{
  switch ( insn.itype )
  {
    case NN_vscatterdps:
    case NN_vscatterqps:
    case NN_vscatterqpd:
    case NN_vpscatterdd:
    case NN_vpscatterqd:
    case NN_vpscatterqq:

    case NN_vpgatherdd:
    case NN_vpgatherqd:
    case NN_vpgatherqq:
    case NN_vgatherdps:
    case NN_vgatherqps:
    case NN_vgatherqpd:
      if ( index > 15 )
        index += op512(insn) ? R_zmm0 : op256(insn) ? (R_ymm16 - 16) : (R_xmm16 - 16);
      else
        index += op512(insn) ? R_zmm0 : op256(insn) ? R_ymm0 : R_xmm0;
      break;

    case NN_vscatterdpd:
    case NN_vpscatterdq:

    case NN_vgatherdpd:
    case NN_vpgatherdq:
      if ( index > 15 )
        index += op512(insn) ? (R_ymm16 - 16) : (R_xmm16 - 16);
      else
        index += op512(insn) ? R_ymm0 : R_xmm0;
      break;

    case NN_vgatherpf0dps:
    case NN_vgatherpf0qps:
    case NN_vgatherpf0qpd:
    case NN_vgatherpf1dps:
    case NN_vgatherpf1qps:
    case NN_vgatherpf1qpd:

    case NN_vscatterpf0dps:
    case NN_vscatterpf0qps:
    case NN_vscatterpf0qpd:
    case NN_vscatterpf1dps:
    case NN_vscatterpf1qps:
    case NN_vscatterpf1qpd:
      index += R_zmm0;
      break;

    case NN_vgatherpf0dpd:
    case NN_vgatherpf1dpd:
    case NN_vscatterpf0dpd:
    case NN_vscatterpf1dpd:
      if ( index > 15 )
        index += R_ymm16 - 16;
      else
        index += R_ymm0;
      break;
  }
  return index;
}

inline int sib_base(const insn_t &insn, const op_t &x)                    // get extended sib base
{
  int base = x.sib & 7;
#ifdef __EA64__
  if ( insn.rex & REX_B )
    base |= 8;
#else
  qnotused(insn);
#endif
  return base;
}

inline regnum_t sib_index(const insn_t &insn, const op_t &x)                   // get extended sib index
{
  regnum_t index = regnum_t((x.sib >> 3) & 7);
#ifdef __EA64__
  if ( (insn.rex & REX_X) != 0 )
    index |= 8;
#endif
  if ( is_vsib(insn) )
  {
    if ( (insn.evex_flags & EVEX_V) != 0 )
      index |= 16;
    index = vsib_index_fixreg(insn, index);
  }
  return index;
}

inline int sib_scale(const op_t &x)
{
  int scale = (x.sib >> 6) & 3;
  return scale;
}

// get the base register of the operand with a displacement
// NB: for 16-bit code, returns a phrase number
// use x86_base_reg() if you need to handle 16-bit instructions
inline int x86_base(const insn_t &insn, const op_t &x)
{
  return x.hasSIB ? sib_base(insn, x) : x.phrase;
}

// get the base register of the operand with a displacement
// returns correct register for 16-bit code too
inline int x86_base_reg(const insn_t &insn, const op_t &x)
{
  if ( x.hasSIB )
  {
    if ( x.type == o_mem )
      return R_none;
    return sib_base(insn, x); // base register is encoded in the SIB
  }
  else if ( !ad16(insn) )
  {
    return x.phrase; // 'phrase' contains the base register number
  }
  else if ( x.phrase == ushort(R_none) )
  {
    return R_sp;
  }
  switch ( x.phrase )
  {
    case 0: // [BX+SI]
    case 1: // [BX+DI]
    case 7: // [BX]
      return R_bx;
    case 2: // [BP+SI]
    case 3: // [BP+DI]
    case 6: // [BP]
      return R_bp;
    case 4: // [SI]
      return R_si;
    case 5: // [DI]
      return R_di;
    default:
      INTERR(10259);
  }
}

const int INDEX_NONE = 4;       // no index register is present
// get the index register of the operand with a displacement
inline int x86_index(const insn_t &insn, const op_t &x)
{
  return x.hasSIB ? sib_index(insn, x) : INDEX_NONE;
}

inline int x86_index_reg(const insn_t &insn, const op_t &x)
{
  if ( x.hasSIB )
  {
    int idx = sib_index(insn, x);
    if ( idx != INDEX_NONE )
      return idx;
    return R_none;
  }
  if ( !ad16(insn) )
    return R_none;
  switch ( x.phrase )
  {
    case 0: // [BX+SI]
    case 2: // [BP+SI]
      return R_si;
    case 1: // [BX+DI]
    case 3: // [BP+DI]
      return R_di;
    case 4: // [SI]
    case 5: // [DI]
    case 7: // [BX]
    case 6: // [BP]
      return R_none;
    default:
      INTERR(10260);
  }
}
// get the scale factor of the operand with a displacement
inline int x86_scale(const op_t &x)
{
  return x.hasSIB ? sib_scale(x) : 0;
}

// does the operand have a displacement?
inline int has_displ(const op_t &x)
{
  return x.type == o_displ || x.type == o_mem && x.hasSIB;
}

// does the insn refer to the TLS variable?
inline bool has_tls_segpref(const insn_t &insn)
{
  if ( insn.segpref == 0 )
    return false;
  return mode64(insn) && insn.segpref == R_fs
      || mode32(insn) && insn.segpref == R_gs;
}

// should we treat the memory operand as a displacement?
inline bool mem_as_displ(const insn_t &insn, const op_t &x)
{
  // the operand should be an offset and it should be the TLS variable
  // or the second operand of "lea" instruction
  // .text:08000000 mov eax, gs:(ti1 - static_TP)
  // .text:08000E8F lea ecx, (_ZN4dmngL4sessE - _GLOBAL_OFFSET_TABLE_)
  return (has_tls_segpref(insn) || insn.itype == NN_lea)
      && is_off(get_flags(insn.ea), x.n);
}

// does the operand refer to stack? (sp or bp based)
bool is_stack_ref(const insn_t &insn, const op_t &x, int breg);

// return addressing width in form of dt_... constant
inline op_dtype_t address_dtype(const insn_t &insn)
{
  return char(ad64(insn) ? dt_qword : ad32(insn) ? dt_dword : dt_word);
}

// return operand width in form of dt_... constant
inline op_dtype_t operand_dtype(const insn_t &insn)
{
  return char(op64(insn) ? dt_qword : op32(insn) ? dt_dword : op16(insn) ? dt_word : dt_byte);
}

inline bool is_io_insn(const insn_t &insn)
{
  return insn.itype == NN_ins
      || insn.itype == NN_outs
      || insn.itype == NN_out
      || insn.itype == NN_in;
}

//---------------------------------
#define PROCMOD_NAME              pc
#define PROCMOD_NODE_NAME         "$ vmm functions"
#define IDPFLAGS_NODE_NAME        "$ idpflags"
#define EXC_NODE_NAME             "$ ExceptionInfo $"
#define BP_NODE_NAME              "$ Bdsc $"
#define WRONG_DECISIONS_NODE_NAME "$ handled wrong decisions"

const char callee_tag   = 'A';
const char fbase_tag    = 'b';
const char frame_tag    = 'f';
const char purge_tag    = 'p';
const char ret_tag      = 'r';
const char pushinfo_tag = 's';
const char is_ptr_tag   = 'P';
const char finally_tag  = 'F';
const char handler_tag  = 'h';
const char vxd_tag1     = 'V';
const char vxd_tag2     = 'W';

// fbase reg is a register used to access data for the current function
// it is usually initialized by __i686_get_pc_thunk() function

struct fbase_reg_t
{
  ea_t value;
  ea_t minea; // address where the fbase reg is defined
  int16 reg;
};

// the second operand of lea instruction should not be treated as memory reference
// unless there is cs: prefix or the user has specified 'offset' flag
// in other cases lea is used for arbirary calculations
inline bool is_arith_lea(const insn_t &insn, const op_t &x)
{
  return insn.itype == NN_lea
      && x.segrg != R_cs
      && !is_off(get_flags(insn.ea), x.n);
}

inline bool is_push_ecx(uchar b)
{
  return b == 0x51; // push ecx
}

inline bool is_push_eax(uchar b)
{
  return b == 0x50; // push eax
}

inline bool is_push_edx(uchar b)
{
  return b == 0x52; // push edx
}

inline bool is_push_ebx(uchar b)
{
  return b == 0x53; // push ebx
}

inline bool is_volatile_reg(int r)
{
  return r != R_bx
      && r != R_bp
      && r != R_si
      && r != R_di
      && r != R_r12
      && r != R_r13
      && r != R_r14
      && r != R_r15;
}

//------------------------------------------------------------------
struct pushreg_t
{
  ea_t     ea;    // instruction ea
  sval_t   off;   // offset from the frame top (sp delta)
  sval_t   width; // register width (or number of allocated bytes)
  regnum_t reg;   // register number (R_none means stack space allocation)
  uint16   flags; // additional flags
#define PRF_NONE   0x0000 // Entry describes a push or an allocation
#define PRF_MOVE   0x0001 // Entrz describes a register save by a move instruction
#define PRF_SPILL  0x0002 // Indicates that entry is located before local stack region
#define PRF_MASK (PRF_MOVE | PRF_SPILL)
};

struct pushinfo_t
{
  enum { PUSHINFO_VERSION = 4 };
  int flags;
#define PINF_SEHCALL    0x0001  // call to SEH_prolog is present
#define PINF_SEHMAN     0x0002  // Manual SEH setup
#define PINF_COOKIE     0x0004  // Has security cookie
#define PINF_ALIGNED    0x0008  // Lvars are align stred (visual studio)
#define PINF_VARARG     0x0010  // Vararg prolog (currently used for gcc64)
#define PINF_BPOFF      0x0020  // xmm_stkoff/reg_stkoff are from rbp (otherwise from rsp)
#define PINF_HAVE_SSIZE 0x0040  // pushinfo_t structure contains its own size (field 'cb')
#define PINF_PSI_FLAGS  0x0080  // pushreg_t structure contains flags field
  qvector<pushreg_t> psi;       // stack allocation instructions
  ssize_t bpidx = -1;           // index into psi
  uint32 spoiled = 0;           // bitmask of spoiled registers at the end of prolog

  eavec_t prolog_insns;         // additional prolog instruction addresses
                                // (in addition to instructions from psi)

  typedef qvector<eavec_t> pop_info_t;
  pop_info_t pops;              // pop insns for pushs (indexes shifted by one)
                                // in other words, this is epilog instructions
                                // index 0: epilog insns not linked to a push insn
                                // 1..psi.size(): epilog insns for each push insn
                                // usually there will be only one pop for each push.
                                // but there might be several pops for each push.
                                // (because the function has several returns)

  int eh_type;                  // function has exception handling
                                // low 16 bits: type, high 16 bits: version
#define EH_NONE    0            // no EH found
#define EH_VCSEH   1            // SEH (__except_handlerN, __SEH_prologN)
#define EH_VCCPPEH 2            // MSVC C++ EH (_EH_prolog[N])
  int seh_ver()
  {
    if ( (eh_type & 0xFFFF) == EH_VCSEH )
      return (eh_type >> 16) & 0xFFFF;
    return 0;
  }
  int eh_ver()
  {
    if ( (eh_type & 0xFFFF) == EH_VCCPPEH )
      return (eh_type >> 16) & 0xFFFF;
    return 0;
  }

  ea_t eh_info = BADADDR;       // for SEH: scopetable address, for C++ EH: __ehhandler address

  // for gcc64 vararg (see PINF_VARARG):
  sval_t xmm_stkoff = 0;        // offset from ebp to xmm savearea
  sval_t reg_stkoff = 0;        // offset from ebp to gpreg savearea
                                // these 2 offsets are either from rsp or rbp
                                // see PINF_BPOFF for that
  int xmm_nsaved = 0;           // number of saved xmm regs
  int reg_nsaved = 0;           // number of saved general purpose regs

  int cb = sizeof(pushinfo_t);  // size of this structure

  pushinfo_t(void) : flags(PINF_HAVE_SSIZE|PINF_PSI_FLAGS), eh_type(EH_NONE) {}
};

enum spec_func_type_t
{
  SF_NONE,
  SF_EH_PROLOG,
  SF_SEH_PROLOG,
  SF_SEH_EPILOG,
  SF_ALLOCA,
  SF_CHK,
  SF_SYSINIT,
  SF_EH_EPILOG,
  SF_LSTRCATN,
};

inline bool is_mingw_abi(void)
{
  if ( default_compiler() != COMP_MS )
    return false; // "mingw" abi can be defined only for MSVC
  qstring abiname;
  get_abi_name(&abiname);
  return abiname == "mingw";
}

inline bool is_msabi(void)
{
  comp_t cc = default_compiler();
  return cc == COMP_MS || cc == COMP_UNK && inf_get_filetype() == f_PE;
}

inline int pc_shadow_area_size()
{
  return inf_is_64bit() && is_msabi() ? 4 * 8 : 0;
}

struct regval_t;
typedef const regval_t &idaapi getreg_t(const char *name, const regval_t *regvalues);

// Structure where information about a mmx/xmm/ymm type is returned
struct mmtype_t
{
  const char *name;
  const type_t *type;
  const type_t *fields;
  tinfo_t tif;
};

//----------------------------------------------------------------------
// The following events are supported by the PC module in the processor_t::notify() function
namespace pc_module_t
{
  enum event_codes_t
  {
    ev_set_difbase = processor_t::ev_loader,
                        // set AFIDP_DIFBASE flag
                        // in: int onoff
                        // Returns: nothing
    ev_restore_pushinfo,// Restore function prolog info from the database
                        // in: pushinfo_t *pi
                        //     ea_t func_start
                        // Returns: 1-ok, otherwise-failed
    ev_save_pushinfo,   // Save function prolog info to the database
                        // in: ea_t func_start
                        //     pushinfo_t *pi
                        // Returns: 1-ok, otherwise-failed
    ev_prolog_analyzed,    // This event is generated by the PC module
                        // at the end of prolog analysis. Plugins may
                        // hook to it and improve the analysis.
                        // in: ea_t first_past_prolog_insn
                        //     pushinfo_t *pi
                        // Returns: 1-ok, 2-ok but do not automatically verify epilog
    ev_verify_epilog,   // Verify function epilog
                        // in: int *answer
                        //     pushinfo_t *pi
                        //     const insn_t *insn
                        // 'insn' structure must be filled with the first epilog instruction
                        // number of verified epilog instructions will be in the 'answer'
                        // returns: 1-ok, otherwise-failed
    obsolete_ev_find_reg_value,  // not used anymore, use ev_find_reg_value
    ev_dbgtools_path,   // Returns the configuration value of the debugging tools path (from IDA.CFG)
                        // in: char *path
                        //     size_t path_size
                        // returns: 1-if value is set, 0-if value not set in IDA.CFG
    ev_is_get_pc_thunk, // Detect get_pc_thunk calls
                        // in: RegNo *p_reg,
                        //     ea_t *p_end
                        //     const insn_t *ins
                        // returns: 1-found, -1-not found, 0-not implemented

    ev_vxd_loaded,      // notification: a virtual device driver (Vxd) is loaded

    ev_get_borland_template_node,
                        // out: netnode *node
                        // returns: 1-found, -1-not found
    ev_clear_borland_template_node,
                        // returns: nothing
    ev_borland_template,// Applies Borland RTTI template for the given address
                        // in: ea_t ea,
                        //     bool bp_mode if false - bc
                        //     bool recursive
                        // returns: 1-created, -1-not created
    ev_get_segval,      // Get segment for the specified instruction operand
                        // in: ea_t *out,
                        //     const insn_t *insn,
                        //     const op_t *x
                        // returns: 1-success
    ev_get_idpflags,    // Get idpflags
                        // in: uint32 *idpflags
                        // returns: 1 success, fill IDPFLAGS
    ev_get_ret_target,  // Some 'ret' insns do not return from the function but are used for short jumps
                        // (for example: push off; ret). The following functions mark such 'ret' instructions.
                        // in: ea_t ea
                        //     ea_t *target
                        // returns: 1 success, fill TARGET
    ev_set_ret_target,  // in: ea_t ea
                        //     ea_t target
    ev_del_ret_target,  // in: ea_t ea
  };

  inline processor_t::event_t idp_ev(event_codes_t ev)
  {
    return processor_t::event_t(ev);
  }

  inline void set_difbase(int onoff)
  {
    processor_t::notify(idp_ev(ev_set_difbase), onoff);
  }

  inline bool restore_pushinfo(pushinfo_t *pi, ea_t func_start)
  {
    return processor_t::notify(idp_ev(ev_restore_pushinfo), pi, func_start) == 1;
  }

  inline bool save_pushinfo(ea_t func_start, pushinfo_t *pi)
  {
    return processor_t::notify(idp_ev(ev_restore_pushinfo), func_start, pi) == 1;
  }

  inline int prolog_analyzed(ea_t first_past_prolog_insn, pushinfo_t *pi)
  {
    return processor_t::notify(idp_ev(ev_prolog_analyzed), first_past_prolog_insn, pi);
  }

  inline bool verify_epilog(int *answer, pushinfo_t *pi, const insn_t &insn)
  {
    return processor_t::notify(idp_ev(ev_verify_epilog), answer, pi, &insn) == 1;
  }

  inline bool dbgtools_path(char *path, size_t path_size)
  {
    return processor_t::notify(idp_ev(ev_dbgtools_path), path, path_size) == 1;
  }

  inline int is_get_pc_thunk(RegNo *p_reg, ea_t *p_end, const insn_t &insn)
  {
    return processor_t::notify(idp_ev(ev_is_get_pc_thunk), p_reg, p_end, &insn);
  }

  inline int vxd_loaded()
  {
    return processor_t::notify(idp_ev(ev_vxd_loaded));
  }

  inline bool get_borland_template_node(netnode *node)
  {
    return processor_t::notify(idp_ev(ev_get_borland_template_node), node) > 0;
  }

  inline void clear_borland_template_node(void)
  {
    processor_t::notify(idp_ev(ev_clear_borland_template_node));
  }

  inline bool borland_template(ea_t ea, bool bp_mode, bool recursive)
  {
    return processor_t::notify(idp_ev(ev_borland_template),
                     ea,
                     bp_mode,
                     recursive) > 0;
  }

  inline ea_t get_segval(const insn_t &insn, const op_t &x)
  {
    ea_t ea = BADADDR;
    processor_t::notify(idp_ev(ev_get_segval), &ea, &insn, &x);
    return ea;
  }

  inline uint32 get_idpflags()
  {
    uint32 idpflags;
    processor_t::notify(idp_ev(ev_get_idpflags), &idpflags);
    return idpflags;
  }

  inline bool get_ret_target(ea_t ea, ea_t *target)
  {
    return processor_t::notify(idp_ev(ev_get_ret_target), ea, target) == 1;
  }

  inline void set_ret_target(ea_t ea, ea_t target)
  {
    processor_t::notify(idp_ev(ev_set_ret_target), ea, target);
  }

  inline void del_ret_target(ea_t ea)
  {
    processor_t::notify(idp_ev(ev_del_ret_target), ea);
  }

}

//-------------------------------------------------------------------------
#define AFIDP_PUSH        0x0001        // push seg; push num; is converted to offset
#define AFIDP_NOP         0x0002        // db 90h after jmp is converted to nop

#define AFIDP_MOVOFF      0x0004        // mov     reg, numoff  <- convert to offset
                                        // mov     segreg, immseg

#define AFIDP_MOVOFF2     0x0008        // mov     z, numoff    <- convert to offset
                                        // mov     z, immseg
                                        // where z - o_mem, o_displ
#define AFIDP_ZEROINS     0x0010        // allow zero opcode instructions:
                                        //      add [bx+si], al  (16bit)
                                        //      add [eax], al    (32bit)
                                        //      add [rax], al    (64bit)

#define AFIDP_BRTTI       0x0020        // Advanced analysis of Borlands RTTI
#define AFIDP_UNKRTTI     0x0040        // -"- with 'unknown_libname'
#define AFIDP_EXPFUNC     0x0080        // for PE? bc(ms?) - expanding
                                        // function (exception subblock)
#define AFIDP_DIFBASE     0x0100        // Allow references with different segment bases
#define AFIDP_NOPREF      0x0200        // Don't display superfluous prefixes
#define AFIDP_NOVXD       0x0400        // Don't interpret int 20 as VxDcall
#define AFIDP_NOFPEMU     0x0800        // Disable FPU emulation instructions
#define AFIDP_SHOWRIP     0x1000        // Explicit RIP-addressing
#define AFIDP_NOSEH       0x2000        // Disable SEH/EH analysis
#define AFIDP_INT3STOP    0x4000        // int 3 may stop code flow
                                        //      call <func>
                                        //      int 3 <- this is likely a no-return guard
#define AFIDP_NOAGGRJMPS  0x8000        // Don't aggressively convert jumps to thunk functions
                                        // 'NO' is used to simplify upgrading existing idbs

inline bool should_af_push(void)     { return (pc_module_t::get_idpflags() & AFIDP_PUSH) != 0; }
inline bool should_af_nop(void)      { return (pc_module_t::get_idpflags() & AFIDP_NOP) != 0; }
inline bool should_af_movoff(void)   { return (pc_module_t::get_idpflags() & AFIDP_MOVOFF) != 0; }
inline bool should_af_movoff2(void)  { return (pc_module_t::get_idpflags() & AFIDP_MOVOFF2) != 0; }
inline bool should_af_zeroins(void)  { return (pc_module_t::get_idpflags() & AFIDP_ZEROINS) != 0; }
inline bool should_af_brtti(void)    { return (pc_module_t::get_idpflags() & AFIDP_BRTTI) != 0; }
inline bool should_af_urtti(void)    { return (pc_module_t::get_idpflags() & AFIDP_UNKRTTI) != 0; }
inline bool should_af_fexp(void)     { return (pc_module_t::get_idpflags() & AFIDP_EXPFUNC) != 0; }
inline bool should_af_difbase(void)  { return (pc_module_t::get_idpflags() & AFIDP_DIFBASE) != 0; }
inline bool should_af_nopref(void)   { return (pc_module_t::get_idpflags() & AFIDP_NOPREF) != 0; }
inline bool should_af_vxd(void)      { return (pc_module_t::get_idpflags() & AFIDP_NOVXD) == 0; }
inline bool should_af_fpemu(void)    { return (pc_module_t::get_idpflags() & AFIDP_NOFPEMU) == 0; }
inline bool should_af_showrip(void)  { return (pc_module_t::get_idpflags() & AFIDP_SHOWRIP) != 0; }
inline bool should_af_seh(void)      { return (pc_module_t::get_idpflags() & AFIDP_NOSEH) == 0; }
inline bool should_af_int3stop(void) { return (pc_module_t::get_idpflags() & AFIDP_INT3STOP) != 0; }
inline bool should_af_aggrjmps(void) { return (pc_module_t::get_idpflags() & AFIDP_NOAGGRJMPS) == 0; }

//-------------------------------------------------------------------------
inline bool get_ret_target(ea_t ea, ea_t *target) { return pc_module_t::get_ret_target(ea, target); }
inline void set_ret_target(ea_t ea, ea_t target) { return pc_module_t::set_ret_target(ea, target); }
inline void del_ret_target(ea_t ea) { return pc_module_t::del_ret_target(ea); }

//-------------------------------------------------------------------------
// Don't use the following define's with underscores at the start!
#define _PT_486p        0x00000001
#define _PT_486r        0x00000002
#define _PT_386p        0x00000004
#define _PT_386r        0x00000008
#define _PT_286p        0x00000010
#define _PT_286r        0x00000020
#define _PT_086         0x00000040
#define _PT_586p        0x00000080      // Pentium real mode
#define _PT_586r        0x00000100      // Pentium protected mode
#define _PT_686r        0x00000200      // Pentium Pro real
#define _PT_686p        0x00000400      // Pentium Pro protected
#define _PT_mmx         0x00000800      // MMX extensions
#define _PT_pii         0x00001000      // Pentium II
#define _PT_3d          0x00002000      // 3DNow! extensions
#define _PT_piii        0x00004000      // Pentium III
#define _PT_k7          0x00008000      // AMD K7
#define _PT_p4          0x00010000      // Pentium 4
#define _PT_sse3        0x00020000      // SSE3 + SSSE3
#define _PT_sse4        0x00040000      // SSE4.1 + SSE4.2

//
//   The following values mean 'is XXX processor or better?'
//

#define PT_sse4          _PT_sse4
#define PT_sse3         (_PT_sse3 | _PT_sse4 )
#define PT_p4           ( PT_sse3 | _PT_p4   )
#define PT_k7           ( PT_p4   | _PT_k7   )
#define PT_piii         ( PT_k7   | _PT_piii )
#define PT_k62          ( PT_piii | _PT_3d   )
#define PT_3d            _PT_3d
#define PT_pii          ( PT_piii | _PT_pii  )
#define PT_mmx          (_PT_mmx  | _PT_3d   )
#define PT_686p         ( PT_pii  | _PT_686p )
#define PT_686r         ( PT_686p | _PT_686r )
#define PT_586p         ( PT_686r | _PT_586p )
#define PT_586r         ( PT_586p | _PT_586r )
#define PT_486p         ( PT_586r | _PT_486p )
#define PT_486r         ( PT_486p | _PT_486r )
#define PT_386p         ( PT_486r | _PT_386p )
#define PT_386r         ( PT_386p | _PT_386r )
#define PT_286p         ( PT_386r | _PT_286p )
#define PT_286r         ( PT_286p | _PT_286r )
#define PT_086          ( PT_286r | _PT_086  )

//
//   The following values mean 'is exactly XXX processor?'
//

#define PT_ismmx        (_PT_mmx            )
#define PT_is686        (_PT_686r | _PT_686p)
#define PT_is586        (_PT_586r | _PT_586p)
#define PT_is486        (_PT_486r | _PT_486p)
#define PT_is386        (_PT_386r | _PT_386p)
#define PT_is286        (_PT_286r | _PT_286p)
#define PT_is086        (_PT_086)

//---------------------------------------------------------------------
inline bool isProtected(uint32 type)
{
  return (type
        & (_PT_286p
         | _PT_386p
         | _PT_486p
         | _PT_586p
         | _PT_686p
         | _PT_pii)) != 0;
}

inline bool isAMD(uint32 type)   { return (type & PT_k7  ) != 0; }
inline bool isp4(uint32 type)    { return (type & PT_p4  ) != 0; }
inline bool isp3(uint32 type)    { return (type & PT_piii) != 0; }
inline bool is3dnow(uint32 type) { return (type & PT_3d  ) != 0; }
inline bool ismmx(uint32 type)   { return (type & PT_mmx ) != 0; }
inline bool isp2(uint32 type)    { return (type & PT_pii ) != 0; }
inline bool is686(uint32 type)   { return (type & PT_686r) != 0; }
inline bool is586(uint32 type)   { return (type & PT_586r) != 0; }
inline bool is486(uint32 type)   { return (type & PT_486r) != 0; }
inline bool is386(uint32 type)   { return (type & PT_386r) != 0; } // is 386 or better ?
inline bool is286(uint32 type)   { return (type & PT_286r) != 0; } // is 286 or better ?

#endif // _INTEL_HPP
