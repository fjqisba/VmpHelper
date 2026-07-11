/*
 *      Interactive disassembler (IDA)
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.

 *      Floating Point Number Libary.
 *      Copyright (c) 1995-2006 by Iouri Kharon.
 *                        E-mail: yjh@styx.cabel.net
 *
 */

#ifndef _IEEE_H_
#define _IEEE_H_

/*! \file ieee.h

  \brief IEEE floating point functions

*/

struct fpvalue_t;       // processor-independent representation of floats

#define FPVAL_NWORDS 6  // number of words in fpvalue_t

/// Floating value kinds.
/// They are useful when checking for NaN/Inf
enum fpvalue_kind_t
{
  FPV_BADARG,  ///< wrong value of max_exp
  FPV_NORM,    ///< regular value
  FPV_NAN,     ///< NaN
  FPV_PINF,    ///< positive infinity
  FPV_NINF,    ///< negative infinity
};

/// \name max_exp values
/// Common values for max_exp (for IEEE floating point values)
//@{
const uint32
  MAXEXP_FLOAT  = 0x80,
  MAXEXP_DOUBLE = 0x400,
  MAXEXP_LNGDBL = 0x4000;
//@}

/// \defgroup REAL_ERROR_ Floating point/IEEE Conversion codes
/// Return values for ieee_realcvt and processor_t::realcvt request
enum fpvalue_error_t
{
  REAL_ERROR_OK = 0,       ///< no error
  REAL_ERROR_FORMAT  = -1, ///< realcvt: not supported format for current .idp
  REAL_ERROR_RANGE   = -2, ///< realcvt: number too big (small) for store (mem NOT modified)
  REAL_ERROR_BADDATA = -3, ///< realcvt: illegal real data for load (IEEE data not filled)
  REAL_ERROR_FPOVER  = 1,  ///< floating overflow or underflow
  REAL_ERROR_BADSTR  = 2,  ///< asctoreal: illegal input string
  REAL_ERROR_ZERODIV = 3,  ///< ediv: divide by 0
  REAL_ERROR_INTOVER = 4,  ///< eetol*: integer overflow
};

/// Standard IEEE 754 floating point conversion function
/// \param m    pointer to data
/// \param out  internal IEEE format data
/// \param swt  operation:
///               - 000: load trunc. float (DEC ^F)    2 bytes (m->e)
///               - 001: load float                    4 bytes (m->e)
///               - 003: load double                   8 bytes (m->e)
///               - 004: load long double             10 bytes (m->e)
///               - 005: load long double             12 bytes (m->e)
///               - 010: store trunc. float (DEC ^F)   2 bytes (e->m)
///               - 011: store float                   4 bytes (e->m)
///               - 013: store double                  8 bytes (e->m)
///               - 014: store long double            10 bytes (e->m)
///               - 015: store long double            12 bytes (e->m)
///              bit 0x80 forces little endian even for big endian processors
/// \return fpvalue_error_t

idaman THREAD_SAFE fpvalue_error_t ida_export ieee_realcvt(void *m, fpvalue_t *out, uint16 swt);

// Helper functions. Better use members of fpvalue_t, they are nicer.
idaman THREAD_SAFE void ida_export realtoasc(char *buf, size_t bufsize, const fpvalue_t &x, uint mode);
idaman THREAD_SAFE fpvalue_error_t ida_export asctoreal(const char **sss, fpvalue_t *out);
idaman THREAD_SAFE void ida_export eltoe(sval_t l, fpvalue_t *vout);
idaman THREAD_SAFE void ida_export eltoe64(int64 l, fpvalue_t *vout);
idaman THREAD_SAFE void ida_export eltoe64u(uint64 l, fpvalue_t *vout);
idaman THREAD_SAFE fpvalue_error_t ida_export eetol(sval_t *out, const fpvalue_t &a, bool roundflg);
idaman THREAD_SAFE fpvalue_error_t ida_export eetol64(int64 *out, const fpvalue_t &a, bool roundflg);
idaman THREAD_SAFE fpvalue_error_t ida_export eetol64u(uint64 *out, const fpvalue_t &a, bool roundflg);
idaman THREAD_SAFE fpvalue_error_t ida_export eldexp(const fpvalue_t &a, int32 pwr2, fpvalue_t *zout);
idaman THREAD_SAFE fpvalue_error_t ida_export eadd(const fpvalue_t &a, const fpvalue_t &b, fpvalue_t *zout, bool subflg);
idaman THREAD_SAFE fpvalue_error_t ida_export emul(const fpvalue_t &a, const fpvalue_t &b, fpvalue_t *zout);
idaman THREAD_SAFE fpvalue_error_t ida_export ediv(const fpvalue_t &a, const fpvalue_t &b, fpvalue_t *zout);
idaman THREAD_SAFE int ida_export ecmp(const fpvalue_t &a, const fpvalue_t &b);
idaman THREAD_SAFE fpvalue_kind_t ida_export get_fpvalue_kind(const fpvalue_t &a, uint16 reserved = 0);

//------------------------------------------------------------------------
/// Processor-independent representation of a floating point value.
/// IDA uses this structure to store and manipulate floating point values.
struct fpvalue_t
{
  uint16 w[FPVAL_NWORDS];

  void clear(void) { memset(this, 0, sizeof(*this)); }
  DECLARE_COMPARISONS(fpvalue_t) { return ecmp(*this, r); }

  /// Convert to the processor-independent representation.
  fpvalue_error_t from_half(uint16 fpval) { return ieee_realcvt(&fpval, this, sizeof(fpval)/2-1); }
  fpvalue_error_t from_float(float fpval) { return ieee_realcvt(&fpval, this, sizeof(fpval)/2-1); }
  fpvalue_error_t from_double(double fpval) { return ieee_realcvt(&fpval, this, sizeof(fpval)/2-1); }

  /// Convert from the processor-independent representation.
  fpvalue_error_t to_half(uint16 *fpval) const { return ieee_realcvt(fpval, (fpvalue_t*)this, 8|(sizeof(*fpval)/2-1)); }
  fpvalue_error_t to_float(float *fpval) const { return ieee_realcvt(fpval, (fpvalue_t*)this, 8|(sizeof(*fpval)/2-1)); }
  fpvalue_error_t to_double(double *fpval) const { return ieee_realcvt(fpval, (fpvalue_t*)this, 8|(sizeof(*fpval)/2-1)); }

  /// Conversions for 10-byte floating point values.
  fpvalue_error_t from_10bytes(const void *fpval) { return ieee_realcvt((void *)fpval, this, 4); }
  fpvalue_error_t to_10bytes(void *fpval) const { return ieee_realcvt(fpval, (fpvalue_t*)this, 8|4); }

  /// Conversions for 12-byte floating point values.
  fpvalue_error_t from_12bytes(const void *fpval) { return ieee_realcvt((void*)fpval, this, 5); }
  fpvalue_error_t to_12bytes(void *fpval) const { return ieee_realcvt(fpval, (fpvalue_t*)this, 8|5); }

  /// Convert string to IEEE.
  /// \param p_str pointer to pointer to string. it will advanced.
  fpvalue_error_t from_str(const char **p_str) { return asctoreal(p_str, this); }

  /// Convert IEEE to string.
  /// \param buf the output buffer
  /// \param bufsize the size of the output buffer
  /// \param mode  broken down into:
  ///                - low byte: number of digits after '.'
  ///                - second byte: FPNUM_LENGTH
  ///                - third byte: FPNUM_DIGITS
  void to_str(char *buf, size_t bufsize, uint mode) const { realtoasc(buf, bufsize, *this, mode); }

  /// Convert integer to IEEE
  void from_sval(sval_t x) { eltoe(x, this); }
  void from_int64(int64 x) { eltoe64(x, this); }
  void from_uint64(uint64 x) { eltoe64u(x, this); }

  /// Convert IEEE to integer (+-0.5 if round)
  fpvalue_error_t to_sval(sval_t *out, bool round=false) const { return eetol(out, *this, round); }
  fpvalue_error_t to_int64(int64 *out, bool round=false) const { return eetol64(out, *this, round); }
  fpvalue_error_t to_uint64(uint64 *out, bool round=false) const { return eetol64u(out, *this, round); }

  /// Arithmetic operations
  fpvalue_error_t fadd(const fpvalue_t &y) { return eadd(*this, y, this, false); }
  fpvalue_error_t fsub(const fpvalue_t &y) { return eadd(*this, y, this, true); }
  fpvalue_error_t fmul(const fpvalue_t &y) { return emul(*this, y, this); }
  fpvalue_error_t fdiv(const fpvalue_t &y) { return ediv(*this, y, this); }

  /// Multiply by a power of 2.
  fpvalue_error_t mul_pow2(int32 power_of_2) { return eldexp(*this, power_of_2, this); }

  /// Calculate absolute value.
  void eabs() { w[FPVAL_NWORDS-1] &= 0x7fff; }

  /// Is negative value?
  bool is_negative() const { return (w[FPVAL_NWORDS-1] & 0x8000) != 0; }

  /// Negate.
  void negate()
  {
    if ( w[FPVAL_NWORDS-1] != 0 )
      w[FPVAL_NWORDS-1] ^= 0x8000;
  }

  /// Get value kind.
  fpvalue_kind_t get_kind() const { return get_fpvalue_kind(*this, 0); }
};

//------------------------------------------------------------------------
/// The exponent of 1.0
#define IEEE_EXONE (0x3fff)
/// Exponent in fpvalue_t for NaN and Inf
#define E_SPECIAL_EXP 0x7fff
#if !defined(NO_OBSOLETE_FUNCS) || defined(IEEE_SOURCE)
#define IEEE_NI (FPVAL_NWORDS+3) // Number of 16 bit words in ::eNI
#define IEEE_E 1        // Array offset to exponent
#define IEEE_M 2        // Array offset to high guard word
/// There is one more internal format used by IDA to store intermediate values.
///  - 0 : sign (0/1)
///  - 1 : exponent (based of #IEEE_EXONE). If exp = 0, value = 0.
///  - 2 : high word of mantissa (always zero after normalize)
typedef uint16 eNI[IEEE_NI];

#ifdef IEEE_SOURCE
#  define IEEE_DEPRECATED
#else
#  define IEEE_DEPRECATED DEPRECATED
#endif
inline IEEE_DEPRECATED void ecleaz(eNI x)
{
  if ( x != nullptr )
    memset(x, 0, sizeof(eNI));
}
idaman IEEE_DEPRECATED THREAD_SAFE void ida_export emovo(const eNI a, fpvalue_t *vout); /// Move eNI => eNE
idaman IEEE_DEPRECATED THREAD_SAFE void ida_export emovi(const fpvalue_t &a, eNI vout); /// Move eNE => eNI
idaman IEEE_DEPRECATED THREAD_SAFE int  ida_export eshift(eNI x, int sc);        /// Shift NI format up (+) or down
/// Normalize and round off.
/// \param s         the internal format number to be rounded
/// \param lost      indicates whether or not the number is exact.
///                  this is the so-called sticky bit.
/// \param subflg    indicates whether the number was obtained
///                  by a subtraction operation.  In that case if lost is nonzero
///                  then the number is slightly smaller than indicated.
/// \param exp       the biased exponent, which may be negative.
///                  the exponent field of "s" is ignored but is replaced by
///                  "exp" as adjusted by normalization and rounding.
/// \param rndbase   if 0 => is the rounding control.
///                  else    is processor defined base (rndprc)
/// \return success
idaman IEEE_DEPRECATED THREAD_SAFE bool ida_export emdnorm(eNI s, bool lost, bool subflg, int32 exp, int rndbase);

#endif

#endif
