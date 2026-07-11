/*
 *      Interactive disassembler (IDA)
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      Type Information.
 *
 */

#ifndef _TYPEINF_HPP
#define _TYPEINF_HPP
#include <idp.hpp>
#include <name.hpp>

/*! \file typeinf.hpp

  \brief Describes the type information records in IDA.

  The recommended way of using type info is to use the ::tinfo_t class.
  The type information is internally kept as an array of bytes terminated by 0.

  Items in brackets [] are optional and sometimes are omitted.
  ::type_t... means a sequence of ::type_t bytes which defines a type.

  \note to work with the types of instructions or data in the database,
  use get_tinfo()/set_tinfo() and similar functions.
*/

/// byte sequence used to describe a type in IDA (see \ref tf)
typedef uchar type_t;
/// pascal-like string: dt length, characters
typedef uchar p_string;
/// several ::p_string's
typedef uchar p_list;

struct til_t;             // type information library
class lexer_t;            // lexical analyzer
class argloc_t;           // argument location
class tinfo_t;            // type info object

struct func_type_data_t;
struct til_bucket_t;
struct til_stream_t;

//------------------------------------------------------------------------
#define RESERVED_BYTE 0xFF  ///< multifunctional purpose
//------------------------------------------------------------------------
/// \defgroup tf Type flags
/// Here we describe the byte arrays used to describe type information
//@{

/// \defgroup tf_mask Masks
//@{
const type_t TYPE_BASE_MASK  = 0x0F;  ///< the low 4 bits define the basic type
const type_t TYPE_FLAGS_MASK = 0x30;  ///< type flags - they have different
                                      ///< meaning depending on the basic type
const type_t TYPE_MODIF_MASK = 0xC0;  ///< modifiers.
                                      ///<  - for ::BT_ARRAY see \ref tf_array
                                      ///<  - ::BT_VOID can have them ONLY in 'void *'

const type_t TYPE_FULL_MASK = (TYPE_BASE_MASK | TYPE_FLAGS_MASK); ///< basic type with type flags
//@}

/*! \defgroup tf_unk Basic type: unknown & void
  ::BT_UNK and ::BT_VOID with non-zero type flags can be used in function
  (and struct) declarations to describe the function arguments or structure
  fields if only their size is known. They may be used in ida to describe
  the user input.

  In general BT_... bits should not be used alone to describe types.
  Use BTF_... constants instead.

  For struct used also as 'single-field-alignment-suffix'
  [__declspec(align(x))] with ::TYPE_MODIF_MASK == ::TYPE_FULL_MASK.
*/
//@{
const type_t  BT_UNK         = 0x00;    ///< unknown
const type_t  BT_VOID        = 0x01;    ///< void
const type_t    BTMT_SIZE0   = 0x00;    ///< ::BT_VOID - normal void; ::BT_UNK - don't use
const type_t    BTMT_SIZE12  = 0x10;    ///< size = 1  byte  if ::BT_VOID; 2 if ::BT_UNK
const type_t    BTMT_SIZE48  = 0x20;    ///< size = 4  bytes if ::BT_VOID; 8 if ::BT_UNK
const type_t    BTMT_SIZE128 = 0x30;    ///< size = 16 bytes if ::BT_VOID; unknown if ::BT_UNK
                                        ///< (IN struct alignment - see below)
//@}

/// \defgroup tf_int Basic type: integer
//@{
const type_t  BT_INT8        = 0x02;    ///< __int8
const type_t  BT_INT16       = 0x03;    ///< __int16
const type_t  BT_INT32       = 0x04;    ///< __int32
const type_t  BT_INT64       = 0x05;    ///< __int64
const type_t  BT_INT128      = 0x06;    ///< __int128 (for alpha & future use)
const type_t  BT_INT         = 0x07;    ///< natural int. (size provided by idp module)
const type_t    BTMT_UNKSIGN = 0x00;    ///< unknown signedness
const type_t    BTMT_SIGNED  = 0x10;    ///< signed
const type_t    BTMT_USIGNED = 0x20;    ///< unsigned
const type_t    BTMT_UNSIGNED = BTMT_USIGNED;
const type_t    BTMT_CHAR    = 0x30;    ///< specify char or segment register
                                        ///< - ::BT_INT8         - char
                                        ///< - ::BT_INT          - segment register
                                        ///< - other BT_INT...   - don't use
//@}

/// \defgroup tf_bool Basic type: bool
//@{
const type_t    BT_BOOL      = 0x08;    ///< bool
const type_t    BTMT_DEFBOOL = 0x00;    ///< size is model specific or unknown(?)
const type_t    BTMT_BOOL1   = 0x10;    ///< size 1byte
const type_t    BTMT_BOOL2   = 0x20;    ///< size 2bytes - !inf_is_64bit()
const type_t    BTMT_BOOL8   = 0x20;    ///< size 8bytes - inf_is_64bit()
const type_t    BTMT_BOOL4   = 0x30;    ///< size 4bytes
//@}

/// \defgroup tf_float Basic type: float
//@{
const type_t    BT_FLOAT     = 0x09;    ///< float
const type_t    BTMT_FLOAT   = 0x00;    ///< float (4 bytes)
const type_t    BTMT_DOUBLE  = 0x10;    ///< double (8 bytes)
const type_t    BTMT_LNGDBL  = 0x20;    ///< long double (compiler specific)
const type_t    BTMT_SPECFLT = 0x30;    ///< float (variable size).
                                        ///< if \ph{use_tbyte()} then use \ph{tbyte_size},
                                        ///< otherwise 2 bytes
//@}

/// \defgroup tf_last_basic Basic type: last
//@{
const type_t _BT_LAST_BASIC  = BT_FLOAT; ///< the last basic type,
                                         ///< all basic types may be followed by
                                         ///< [tah-typeattrs]
//@}

/*! \defgroup tf_ptr Derived type: pointer
  Pointers to undeclared yet ::BT_COMPLEX types are prohibited
*/
//@{
const type_t    BT_PTR       = 0x0A;    ///< pointer.
                                        ///< has the following format:
                                        ///< [db sizeof(ptr)]; [tah-typeattrs]; type_t...
const type_t    BTMT_DEFPTR  = 0x00;    ///< default for model
const type_t    BTMT_NEAR    = 0x10;    ///< near
const type_t    BTMT_FAR     = 0x20;    ///< far
const type_t    BTMT_CLOSURE = 0x30;    ///< closure.
                                        ///< - if ptr to ::BT_FUNC - __closure.
                                        ///<   in this case next byte MUST be
                                        ///<   #RESERVED_BYTE, and after it ::BT_FUNC
                                        ///< - else the next byte contains sizeof(ptr)
                                        ///<   allowed values are 1 - \varmem{ph,processor_t,max_ptr_size}
                                        ///< - if value is bigger than \varmem{ph,processor_t,max_ptr_size},
                                        ///<   based_ptr_name_and_size() is called to
                                        ///<   find out the typeinfo
//@}

/*! \defgroup tf_array Derived type: array
  For ::BT_ARRAY, the BTMT_... flags must be equivalent to the BTMT_... flags of its elements
*/
//@{
const type_t  BT_ARRAY       = 0x0B;    ///< array
const type_t  BTMT_NONBASED  = 0x10;    ///< \code
                                        /// if set
                                        ///    array base==0
                                        ///    format: dt num_elem; [tah-typeattrs]; type_t...
                                        ///    if num_elem==0 then the array size is unknown
                                        /// else
                                        ///    format: da num_elem, base; [tah-typeattrs]; type_t... \endcode
                                        /// used only for serialization
const type_t  BTMT_ARRESERV  = 0x20;    ///< reserved bit
//@}

/*! \defgroup tf_func Derived type: function
  Ellipsis is not taken into account in the number of parameters
  The return type cannot be ::BT_ARRAY or ::BT_FUNC.
*/
//@{
const type_t  BT_FUNC        = 0x0C;    ///< function.
                                        ///< format: <pre>
                                        ///  optional: ::CM_CC_SPOILED | num_of_spoiled_regs
                                        ///            if num_of_spoiled_reg == BFA_FUNC_MARKER:
                                        ///              ::bfa_byte
                                        ///              if (bfa_byte & BFA_FUNC_EXT_FORMAT) != 0
                                        ///               ::fti_bits (only low bits: FTI_SPOILED,...,FTI_VIRTUAL)
                                        ///               num_of_spoiled_reg times: spoiled reg info (see extract_spoiledreg)
                                        ///              else
                                        ///                bfa_byte is function attribute byte (see \ref BFA_...)
                                        ///            else:
                                        ///              num_of_spoiled_reg times: spoiled reg info (see extract_spoiledreg)
                                        ///  ::cm_t ... calling convention and memory model
                                        ///  [tah-typeattrs];
                                        ///  ::type_t ... return type;
                                        ///  [serialized argloc_t of returned value (if ::CM_CC_SPECIAL{PE} && !return void);
                                        ///  if !::CM_CC_VOIDARG:
                                        ///    dt N (N=number of parameters)
                                        ///    if ( N == 0 )
                                        ///    if ::CM_CC_ELLIPSIS or ::CM_CC_SPECIALE
                                        ///        func(...)
                                        ///      else
                                        ///        parameters are unknown
                                        ///    else
                                        ///      N records:
                                        ///        ::type_t ... (i.e. type of each parameter)
                                        ///        [serialized argloc_t (if ::CM_CC_SPECIAL{PE})] (i.e. place of each parameter)
                                        ///        [#FAH_BYTE + de( \ref funcarg_t::flags )] </pre>

const type_t    BTMT_DEFCALL  = 0x00;   ///< call method - default for model or unknown
const type_t    BTMT_NEARCALL = 0x10;   ///< function returns by retn
const type_t    BTMT_FARCALL  = 0x20;   ///< function returns by retf
const type_t    BTMT_INTCALL  = 0x30;   ///< function returns by iret
                                        ///< in this case cc MUST be 'unknown'
//@}

/// \defgroup tf_complex Derived type: complex
//@{
const type_t    BT_COMPLEX   = 0x0D;    ///< struct/union/enum/typedef.
                                        ///< format: <pre>
                                        ///   [dt N (N=field count) if !::BTMT_TYPEDEF]
                                        ///   if N == 0:
                                        ///     p_string name (unnamed types have names "anon_...")
                                        ///     [sdacl-typeattrs];
                                        ///   else, for struct & union:
                                        ///     if N == 0x7FFE   // Support for high (i.e., > 4095) members count
                                        ///       N = deserialize_de()
                                        ///     ALPOW = N & 0x7
                                        ///     MCNT = N >> 3
                                        ///     if MCNT == 0
                                        ///       empty struct
                                        ///     if ALPOW == 0
                                        ///       ALIGN = get_default_align()
                                        ///     else
                                        ///       ALIGN = (1 << (ALPOW - 1))
                                        ///     [sdacl-typeattrs];
                                        ///   else, for enums:
                                        ///     if N == 0x7FFE   // Support for high enum entries count.
                                        ///       N = deserialize_de()
                                        ///     [tah-typeattrs]; </pre>
                                        ///
const type_t    BTMT_STRUCT  = 0x00;    ///<     struct:
                                        ///<       MCNT records: type_t; [sdacl-typeattrs];
const type_t    BTMT_UNION   = 0x10;    ///<     union:
                                        ///<       MCNT records: type_t...
const type_t    BTMT_ENUM    = 0x20;    ///<     enum:
                                        ///<       next byte bte_t (see below)
                                        ///<       N records: de delta(s)
                                        ///<                  OR
                                        ///<                  blocks (see below)
const type_t    BTMT_TYPEDEF = 0x30;    ///< named reference
                                        ///<   always p_string name

const type_t BT_BITFIELD     = 0x0E;    ///< bitfield (only in struct)
                                        ///< ['bitmasked' enum see below]
                                        ///< next byte is dt
                                        ///<  ((size in bits << 1) | (unsigned ? 1 : 0))
const type_t BTMT_BFLDI8    = 0x00;     ///< __int8
const type_t BTMT_BFLDI16   = 0x10;     ///< __int16
const type_t BTMT_BFLDI32   = 0x20;     ///< __int32
const type_t BTMT_BFLDI64   = 0x30;     ///< __int64
//@}

const type_t BT_RESERVED     = 0x0F;        ///< RESERVED


//------------------------------------------------------------------------
/*! \defgroup tf_modifiers Type modifiers
  "const volatile" types are forbidden
*/
//@{
const type_t  BTM_CONST      = 0x40;    ///< const
const type_t  BTM_VOLATILE   = 0x80;    ///< volatile
//@}

//------------------------------------------------------------------------
/// \defgroup tf_enum Special enum definitions
//@{
typedef uchar bte_t; ///< Enum type flags

const bte_t   BTE_SIZE_MASK = 0x07;   ///< storage size.
                                      ///<   - if == 0 then inf_get_cc_size_e()
                                      ///<   - else 1 << (n -1) = 1,2,4...64
const bte_t   BTE_RESERVED    = 0x08; ///< must be 0, in order to distinguish
                                      ///< from a tah-byte
const bte_t   BTE_BITFIELD    = 0x10; ///< 'subarrays'. In this case ANY record
                                      ///< has the following format:
                                      ///<   - 'de' mask (has name)
                                      ///<   - 'dt' cnt
                                      ///<   - cnt records of 'de' values
                                      ///<      (cnt CAN be 0)
                                      ///< \note delta for ALL subsegment is ONE
const bte_t   BTE_OUT_MASK    = 0x60; ///< output style mask
const bte_t   BTE_HEX         = 0x00; ///< hex
const bte_t   BTE_CHAR        = 0x20; ///< char or hex
const bte_t   BTE_SDEC        = 0x40; ///< signed decimal
const bte_t   BTE_UDEC        = 0x60; ///< unsigned decimal
const bte_t   BTE_ALWAYS      = 0x80; ///< this bit MUST be present
//@}

/// \defgroup tf_conv_segreg Convenience definitions: segment register
//@{
const type_t BT_SEGREG    = (BT_INT | BTMT_CHAR);      ///< segment register
//@}

/// \defgroup tf_conv_unk Convenience definitions: unknown types
//@{
const type_t BT_UNK_BYTE  = (BT_VOID | BTMT_SIZE12);   ///< 1 byte
const type_t BT_UNK_WORD  = (BT_UNK  | BTMT_SIZE12);   ///< 2 bytes
const type_t BT_UNK_DWORD = (BT_VOID | BTMT_SIZE48);   ///< 4 bytes
const type_t BT_UNK_QWORD = (BT_UNK  | BTMT_SIZE48);   ///< 8 bytes
const type_t BT_UNK_OWORD = (BT_VOID | BTMT_SIZE128);  ///< 16 bytes
const type_t BT_UNKNOWN   = (BT_UNK  | BTMT_SIZE128);  ///< unknown size - for parameters
//@}

//------------------------------------------------------------------------
/// \defgroup tf_shortcuts Convenience definitions: shortcuts
//@{
const type_t BTF_BYTE    = BT_UNK_BYTE;                 ///< byte
const type_t BTF_UNK     = BT_UNKNOWN;                  ///< unknown
const type_t BTF_VOID    = BT_VOID | BTMT_SIZE0;        ///< void

const type_t BTF_INT8    = BT_INT8 | BTMT_SIGNED;       ///< signed byte
const type_t BTF_CHAR    = BT_INT8 | BTMT_CHAR;         ///< signed char
const type_t BTF_UCHAR   = BT_INT8 | BTMT_USIGNED;      ///< unsigned char
const type_t BTF_UINT8   = BT_INT8 | BTMT_USIGNED;      ///< unsigned byte

const type_t BTF_INT16   = BT_INT16 | BTMT_SIGNED;      ///< signed short
const type_t BTF_UINT16  = BT_INT16 | BTMT_USIGNED;     ///< unsigned short

const type_t BTF_INT32   = BT_INT32 | BTMT_SIGNED;      ///< signed int
const type_t BTF_UINT32  = BT_INT32 | BTMT_USIGNED;     ///< unsigned int

const type_t BTF_INT64   = BT_INT64 | BTMT_SIGNED;      ///< signed long
const type_t BTF_UINT64  = BT_INT64 | BTMT_USIGNED;     ///< unsigned long

const type_t BTF_INT128   = BT_INT128 | BTMT_SIGNED;    ///< signed 128-bit value
const type_t BTF_UINT128  = BT_INT128 | BTMT_USIGNED;   ///< unsigned 128-bit value

const type_t BTF_INT     = BT_INT | BTMT_UNKSIGN;       ///< int, unknown signedness
const type_t BTF_UINT    = BT_INT | BTMT_USIGNED;       ///< unsigned int
const type_t BTF_SINT    = BT_INT | BTMT_SIGNED;        ///< singed int

const type_t BTF_BOOL    = BT_BOOL;                     ///< boolean

const type_t BTF_FLOAT   = BT_FLOAT | BTMT_FLOAT;       ///< float
const type_t BTF_DOUBLE  = BT_FLOAT | BTMT_DOUBLE;      ///< double
const type_t BTF_LDOUBLE = BT_FLOAT | BTMT_LNGDBL;      ///< long double
const type_t BTF_TBYTE   = BT_FLOAT | BTMT_SPECFLT;     ///< see ::BTMT_SPECFLT

const type_t BTF_STRUCT  = BT_COMPLEX | BTMT_STRUCT;    ///< struct
const type_t BTF_UNION   = BT_COMPLEX | BTMT_UNION;     ///< union
const type_t BTF_ENUM    = BT_COMPLEX | BTMT_ENUM;      ///< enum
const type_t BTF_TYPEDEF = BT_COMPLEX | BTMT_TYPEDEF;   ///< typedef
//@}

//@} tf

//------------------------------------------------------------------------
// convenience functions:

inline THREAD_SAFE bool is_type_const(type_t t)    { return (t & BTM_CONST) != 0; }                      ///< See ::BTM_CONST
inline THREAD_SAFE bool is_type_volatile(type_t t) { return (t & BTM_VOLATILE) != 0; }                   ///< See ::BTM_VOLATILE

inline THREAD_SAFE type_t get_base_type(type_t t)  { return (t & TYPE_BASE_MASK); }                      ///< Get get basic type bits (::TYPE_BASE_MASK)
inline THREAD_SAFE type_t get_type_flags(type_t t) { return (t & TYPE_FLAGS_MASK); }                     ///< Get type flags (::TYPE_FLAGS_MASK)
inline THREAD_SAFE type_t get_full_type(type_t t)  { return (t & TYPE_FULL_MASK); }                      ///< Get basic type bits + type flags (::TYPE_FULL_MASK)

/// Is the type_t the last byte of type declaration?
/// (there are no additional bytes after a basic type, see ::_BT_LAST_BASIC)
inline THREAD_SAFE bool is_typeid_last(type_t t)   { return(get_base_type(t) <= _BT_LAST_BASIC); }

/// Identifies an unknown or void type with a known size (see \ref tf_unk)
inline THREAD_SAFE bool is_type_partial(type_t t)  { return(get_base_type(t) <= BT_VOID) && get_type_flags(t) != 0; }

inline THREAD_SAFE bool is_type_void(type_t t)     { return(get_full_type(t) == BTF_VOID); }             ///< See ::BTF_VOID
inline THREAD_SAFE bool is_type_unknown(type_t t)  { return(get_full_type(t) == BT_UNKNOWN); }           ///< See ::BT_UNKNOWN

inline THREAD_SAFE bool is_type_ptr(type_t t)      { return(get_base_type(t) == BT_PTR); }               ///< See ::BT_PTR
inline THREAD_SAFE bool is_type_complex(type_t t)  { return(get_base_type(t) == BT_COMPLEX); }           ///< See ::BT_COMPLEX
inline THREAD_SAFE bool is_type_func(type_t t)     { return(get_base_type(t) == BT_FUNC); }              ///< See ::BT_FUNC
inline THREAD_SAFE bool is_type_array(type_t t)    { return(get_base_type(t) == BT_ARRAY); }             ///< See ::BT_ARRAY

inline THREAD_SAFE bool is_type_typedef(type_t t)  { return(get_full_type(t) == BTF_TYPEDEF); }          ///< See ::BTF_TYPEDEF
inline THREAD_SAFE bool is_type_sue(type_t t)      { return is_type_complex(t) && !is_type_typedef(t); } ///< Is the type a struct/union/enum?
inline THREAD_SAFE bool is_type_struct(type_t t)   { return(get_full_type(t) == BTF_STRUCT); }           ///< See ::BTF_STRUCT
inline THREAD_SAFE bool is_type_union(type_t t)    { return(get_full_type(t) == BTF_UNION); }            ///< See ::BTF_UNION
inline THREAD_SAFE bool is_type_struni(type_t t)   { return(is_type_struct(t) || is_type_union(t)); }    ///< Is the type a struct or union?
inline THREAD_SAFE bool is_type_enum(type_t t)     { return(get_full_type(t) == BTF_ENUM); }             ///< See ::BTF_ENUM

inline THREAD_SAFE bool is_type_bitfld(type_t t)   { return(get_base_type(t) == BT_BITFIELD); }          ///< See ::BT_BITFIELD


/// Does the type_t specify one of the basic types in \ref tf_int?
inline THREAD_SAFE bool is_type_int(type_t bt) { bt = get_base_type(bt); return bt >= BT_INT8 && bt <= BT_INT; }

/// Does the type specify a 128-bit value? (signed or unsigned, see \ref tf_int)
inline THREAD_SAFE bool is_type_int128(type_t t)
{
  return get_full_type(t) == (BT_INT128|BTMT_UNKSIGN)
      || get_full_type(t) == (BT_INT128|BTMT_SIGNED);
}

/// Does the type specify a 64-bit value? (signed or unsigned, see \ref tf_int)
inline THREAD_SAFE bool is_type_int64(type_t t)
{
  return get_full_type(t) == (BT_INT64|BTMT_UNKSIGN)
      || get_full_type(t) == (BT_INT64|BTMT_SIGNED);
}

/// Does the type specify a 32-bit value? (signed or unsigned, see \ref tf_int)
inline THREAD_SAFE bool is_type_int32(type_t t)
{
  return get_full_type(t) == (BT_INT32|BTMT_UNKSIGN)
      || get_full_type(t) == (BT_INT32|BTMT_SIGNED);
}

/// Does the type specify a 16-bit value? (signed or unsigned, see \ref tf_int)
inline THREAD_SAFE bool is_type_int16(type_t t)
{
  return get_full_type(t) == (BT_INT16|BTMT_UNKSIGN)
      || get_full_type(t) == (BT_INT16|BTMT_SIGNED);
}

/// Does the type specify a char value? (signed or unsigned, see \ref tf_int)
inline THREAD_SAFE bool is_type_char(type_t t) // chars are signed by default(?)
{
  return get_full_type(t) == (BT_INT8|BTMT_CHAR)
      || get_full_type(t) == (BT_INT8|BTMT_SIGNED);
}

/// Is the type a pointer, array, or function type?
inline THREAD_SAFE bool is_type_paf(type_t t)
{
  t = get_base_type(t);
  return t >= BT_PTR && t <= BT_FUNC;
}

/// Is the type a pointer or array type?
inline THREAD_SAFE bool is_type_ptr_or_array(type_t t) { t = get_base_type(t); return t == BT_PTR || t == BT_ARRAY; }
/// Is the type a floating point type?
inline THREAD_SAFE bool is_type_floating(type_t t) { return get_base_type(t) == BT_FLOAT; } // any floating type
/// Is the type an integral type (char/short/int/long/bool)?
inline THREAD_SAFE bool is_type_integral(type_t t) { return get_full_type(t) > BT_VOID && get_base_type(t) <= BT_BOOL; }
/// Is the type an extended integral type? (integral or enum)
inline THREAD_SAFE bool is_type_ext_integral(type_t t) { return is_type_integral(t) || is_type_enum(t); }
/// Is the type an arithmetic type? (floating or integral)
inline THREAD_SAFE bool is_type_arithmetic(type_t t) { return get_full_type(t) > BT_VOID && get_base_type(t) <= BT_FLOAT; }
/// Is the type an extended arithmetic type? (arithmetic or enum)
inline THREAD_SAFE bool is_type_ext_arithmetic(type_t t) { return is_type_arithmetic(t) || is_type_enum(t); }

inline THREAD_SAFE bool is_type_uint(type_t t)    { return get_full_type(t) == BTF_UINT; }     ///< See ::BTF_UINT
inline THREAD_SAFE bool is_type_uchar(type_t t)   { return get_full_type(t) == BTF_UCHAR; }    ///< See ::BTF_UCHAR
inline THREAD_SAFE bool is_type_uint16(type_t t)  { return get_full_type(t) == BTF_UINT16; }   ///< See ::BTF_UINT16
inline THREAD_SAFE bool is_type_uint32(type_t t)  { return get_full_type(t) == BTF_UINT32; }   ///< See ::BTF_UINT32
inline THREAD_SAFE bool is_type_uint64(type_t t)  { return get_full_type(t) == BTF_UINT64; }   ///< See ::BTF_UINT64
inline THREAD_SAFE bool is_type_uint128(type_t t) { return get_full_type(t) == BTF_UINT128; }  ///< See ::BTF_UINT128
inline THREAD_SAFE bool is_type_ldouble(type_t t) { return get_full_type(t) == BTF_LDOUBLE; }  ///< See ::BTF_LDOUBLE
inline THREAD_SAFE bool is_type_double(type_t t)  { return get_full_type(t) == BTF_DOUBLE; }   ///< See ::BTF_DOUBLE
inline THREAD_SAFE bool is_type_float(type_t t)   { return get_full_type(t) == BTF_FLOAT; }    ///< See ::BTF_FLOAT
inline THREAD_SAFE bool is_type_tbyte(type_t t)   { return get_full_type(t) == BTF_TBYTE; }    ///< See ::BTF_FLOAT
inline THREAD_SAFE bool is_type_bool(type_t t)    { return get_base_type(t) == BT_BOOL; }      ///< See ::BTF_BOOL

/*! \defgroup tattr Type attributes
  \ingroup tf
  The type attributes start with the type attribute header byte (::TAH_BYTE),
  followed by attribute bytes
*/
//@{
#define TAH_BYTE        0xFE    ///< type attribute header byte
#define FAH_BYTE        0xFF    ///< function argument attribute header byte

#define MAX_DECL_ALIGN  0x000F

/// \defgroup tattr_ext Extended type attributes
//@{
#define TAH_HASATTRS    0x0010  ///< has extended attributes
//@}

/// \defgroup tattr_udt Type attributes for udts
//@{
#define TAUDT_UNALIGNED 0x0040  ///< struct: unaligned struct
#define TAUDT_MSSTRUCT  0x0020  ///< struct: gcc msstruct attribute
#define TAUDT_CPPOBJ    0x0080  ///< struct: a c++ object, not simple pod type
#define TAUDT_VFTABLE   0x0100  ///< struct: is virtual function table
//@}

/// \defgroup tattr_field Type attributes for udt fields
//@{
#define TAFLD_BASECLASS 0x0020  ///< field: do not include but inherit from the current field
#define TAFLD_UNALIGNED 0x0040  ///< field: unaligned field
#define TAFLD_VIRTBASE  0x0080  ///< field: virtual base (not supported yet)
#define TAFLD_VFTABLE   0x0100  ///< field: ptr to virtual function table
#define TAFLD_METHOD    0x0200  ///< denotes a udt member function
//@}

/// \defgroup tattr_ptr Type attributes for pointers
//@{
#define TAPTR_PTR32     0x0020  ///< ptr: __ptr32
#define TAPTR_PTR64     0x0040  ///< ptr: __ptr64
#define TAPTR_RESTRICT  0x0060  ///< ptr: __restrict
#define TAPTR_SHIFTED   0x0080  ///< ptr: __shifted(parent_struct, delta)
//@}

/// \defgroup tattr_enum Type attributes for enums
//@{
#define TAENUM_64BIT    0x0020  ///< enum: store 64-bit values
#define TAENUM_UNSIGNED 0x0040  ///< enum: unsigned
#define TAENUM_SIGNED   0x0080  ///< enum: signed
//@}

#define TAH_ALL         0x03F0  ///< all defined bits

//@} tattr


/// The TAH byte (type attribute header byte) denotes the start of type attributes.
/// (see "tah-typeattrs" in the type bit definitions)

inline THREAD_SAFE bool is_tah_byte(type_t t)
{
  return t == TAH_BYTE;
}


/// Identify an sdacl byte.
/// The first sdacl byte has the following format: 11xx000x.
/// The sdacl bytes are appended to udt fields. They indicate the start of type
/// attributes (as the tah-bytes do). The sdacl bytes are used in the udt
/// headers instead of the tah-byte. This is done for compatibility with old
/// databases, they were already using sdacl bytes in udt headers and as udt
/// field postfixes.
/// (see "sdacl-typeattrs" in the type bit definitions)

inline THREAD_SAFE bool is_sdacl_byte(type_t t)
{
  return ((t & ~TYPE_FLAGS_MASK) ^ TYPE_MODIF_MASK) <= BT_VOID;
}

#ifndef SWIG
/// Compare two bytevecs with '<'.
/// v1 is considered less than v2 if either:
///   - v1.size() < v2.size()
///   - there is some i such that v1[i] < v2[i]

inline THREAD_SAFE bool operator <(const bytevec_t &v1, const bytevec_t &v2)
{
  size_t n = qmin(v1.size(), v2.size());
  for ( size_t i=0; i < n; i++ )
  {
    uchar k1 = v1[i];
    uchar k2 = v2[i];
    if ( k1 < k2 )
      return true;
    if ( k1 > k2 )
      return false;
  }
  return v1.size() < v2.size();
}
#endif

/// \addtogroup tattr_ext Extended type attributes
//@{
/// Extended type attributes.
struct type_attr_t
{
  qstring key;          ///< one symbol keys are reserved to be used by the kernel
                        ///< the ones starting with an underscore are reserved too
  bytevec_t value;      ///< attribute bytes
  bool operator < (const type_attr_t &r) const { return key < r.key; }
  bool operator >= (const type_attr_t &r) const { return !(*this < r); }
};
DECLARE_TYPE_AS_MOVABLE(type_attr_t);

/// this vector must be sorted by keys
typedef qvector<type_attr_t> type_attrs_t;

typedef int type_sign_t; ///< type signedness
const type_sign_t
  no_sign       = 0,     ///< no sign, or unknown
  type_signed   = 1,     ///< signed type
  type_unsigned = 2;     ///< unsigned type
//@}

//---------------------------------------------------------------------------
idaman bool ida_export append_argloc(qtype *out, const argloc_t &vloc); ///< Serialize argument location
/// Deserialize an argument location.
/// Argument FORBID_STKOFF checks location type.
/// It can be used, for example, to check the return location of a function that cannot return a value in the stack
idaman bool ida_export extract_argloc(argloc_t *vloc, const type_t **ptype, bool forbid_stkoff);

idaman const type_t *ida_export resolve_typedef(const til_t *til, const type_t *type);

// low level functions to be used in predicate_t::should_display()
// in other places please use tinfo_t
inline bool is_restype_void(const til_t *til, const type_t *type)
{
  type = resolve_typedef(til, type);
  return type != nullptr && is_type_void(*type);
}

inline bool is_restype_enum(const til_t *til, const type_t *type)
{
  type = resolve_typedef(til, type);
  return type != nullptr && is_type_enum(*type);
}

inline bool is_restype_struni(const til_t *til, const type_t *type)
{
  type = resolve_typedef(til, type);
  return type != nullptr && is_type_struni(*type);
}

inline bool is_restype_struct(const til_t *til, const type_t *type)
{
  type = resolve_typedef(til, type);
  return type != nullptr && is_type_struct(*type);
}

// Get a base type for the specified size.
// This function prefers to return integer types
// \param size size in bytes; should be 1,2,4,8,16 or sizeof(floating point)
// \return BT_INT.. or BT_FLOAT... or BT_UNK

idaman type_t ida_export get_scalar_bt(int size);


//------------------------------------------------------------------------
/// Type Information Library
//------------------------------------------------------------------------
struct til_t
{
  char *name = nullptr;     ///< short file name (without path and extension)
  char *desc = nullptr;     ///< human readable til description
  int nbases = 0;           ///< number of base tils
  til_t **base = nullptr;   ///< tils that our til is based on
  uint32 flags = 0;         ///< \ref TIL_
/// \defgroup TIL_ Type info library property bits
/// used by til_t::flags
//@{
#define TIL_ZIP 0x0001  ///< pack buckets using zip
#define TIL_MAC 0x0002  ///< til has macro table
#define TIL_ESI 0x0004  ///< extended sizeof info (short, long, longlong)
#define TIL_UNI 0x0008  ///< universal til for any compiler
#define TIL_ORD 0x0010  ///< type ordinal numbers are present
#define TIL_ALI 0x0020  ///< type aliases are present (this bit is used only on the disk)
#define TIL_MOD 0x0040  ///< til has been modified, should be saved
#define TIL_STM 0x0080  ///< til has extra streams
#define TIL_SLD 0x0100  ///< sizeof(long double)
//@}
  /// Has the til been modified? (#TIL_MOD)
  inline bool is_dirty(void) const { return (flags & TIL_MOD) != 0; }
  /// Mark the til as modified (#TIL_MOD)
  inline void set_dirty(void) { flags |= TIL_MOD; }
  compiler_info_t cc;               ///< information about the target compiler
  til_bucket_t *syms = nullptr;     ///< symbols
  til_bucket_t *types = nullptr;    ///< types
  til_bucket_t *macros = nullptr;   ///< macros
  int nrefs = 0;                    ///< number of references to the til
  int nstreams = 0;                 ///< number of extra streams
  til_stream_t **streams = nullptr; ///< symbol stream storage
};


/// Initialize a til

idaman til_t *ida_export new_til(const char *name, const char *desc);


/// Add multiple base tils.
/// \param[out] errbuf  error message
/// \param ti           target til
/// \param tildir       directory where specified tils can be found.
///                     nullptr means all default til subdirectories.
/// \param bases        comma separated list of til names
/// \param gen_events   generate corresponding IDB events
/// \return one of \ref TIL_ADD_

idaman int ida_export add_base_tils(qstring *errbuf, til_t *ti, const char *tildir, const char *bases, bool gen_events);

/// \defgroup TIL_ADD_ Add TIL result codes
/// returned by add_base_tils()
//@{
#define TIL_ADD_FAILED  0       ///< see errbuf
#define TIL_ADD_OK      1       ///< some tils were added
#define TIL_ADD_ALREADY 2       ///< the base til was already added
//@}


/// Load til from a file without adding it to the database list (see also \ref add_til).
/// Failure to load base tils are reported into 'errbuf'. They do not prevent
/// loading of the main til.
/// \param name         filename of the til. If it's an absolute path, tildir is ignored.
///                       - NB: the file extension is forced to .til
/// \param[out] errbuf  error message
/// \param tildir       directory where to load the til from.
///                     nullptr means default til subdirectories.
/// \return pointer to resulting til, nullptr if failed and error message is in errbuf

idaman til_t *ida_export load_til(const char *name, qstring *errbuf, const char *tildir=nullptr);


/// Sort til (use after modifying it).
/// \return false if no memory or bad parameter

idaman bool ida_export sort_til(til_t *ti);


/// Collect garbage in til.
/// Must be called before storing the til.
/// \return true if any memory was freed

idaman bool ida_export compact_til(til_t *ti);


/// Store til to a file.
/// If the til contains garbage, it will be collected before storing the til.
/// Your plugin should call compact_til() before calling store_til().
/// \param ti      type library to store
/// \param tildir  directory where to store the til. nullptr means current directory.
/// \param name    filename of the til. If it's an absolute path, tildir is ignored.
///                  - NB: the file extension is forced to .til
/// \return success

idaman bool ida_export store_til(til_t *ti, const char *tildir, const char *name);


/// Free memory allocated by til

idaman void ida_export free_til(til_t *ti);


/// Get human-readable til description

idaman til_t *ida_export load_til_header(const char *tildir, const char *name, qstring *errbuf);


//------------------------------------------------------------------------
/// \defgroup CM_ CM
/// Calling convention & Model
//@{

/// \defgroup CM_ptr Default pointer size
//@{
const cm_t CM_MASK = 0x03;
const cm_t  CM_UNKNOWN   = 0x00;  ///< unknown
const cm_t  CM_N8_F16    = 0x01;  ///< if sizeof(int)<=2: near 1 byte, far 2 bytes
const cm_t  CM_N64       = 0x01;  ///< if sizeof(int)>2: near 8 bytes, far 8 bytes
const cm_t  CM_N16_F32   = 0x02;  ///< near 2 bytes, far 4 bytes
const cm_t  CM_N32_F48   = 0x03;  ///< near 4 bytes, far 6 bytes
//@}
/// \defgroup CM_M_ Model
//@{
const cm_t CM_M_MASK = 0x0C;
const cm_t  CM_M_NN      = 0x00;  ///< small:   code=near, data=near (or unknown if CM_UNKNOWN)
const cm_t  CM_M_FF      = 0x04;  ///< large:   code=far, data=far
const cm_t  CM_M_NF      = 0x08;  ///< compact: code=near, data=far
const cm_t  CM_M_FN      = 0x0C;  ///< medium:  code=far, data=near

/// Does the given model specify far code?.
inline THREAD_SAFE bool is_code_far(cm_t cm) { return((cm & 4) != 0); }
/// Does the given model specify far data?.
inline THREAD_SAFE bool is_data_far(cm_t cm) { return((cm &= CM_M_MASK) && cm != CM_M_FN); }
//@}

/// \defgroup CM_CC_ Calling convention
//@{
const cm_t CM_CC_MASK = 0xF0;
const cm_t  CM_CC_INVALID  = 0x00;  ///< this value is invalid
const cm_t  CM_CC_UNKNOWN  = 0x10;  ///< unknown calling convention
const cm_t  CM_CC_VOIDARG  = 0x20;  ///< function without arguments
                                    ///< if has other cc and argnum == 0,
                                    ///< represent as f() - unknown list
const cm_t  CM_CC_CDECL    = 0x30;  ///< stack
const cm_t  CM_CC_ELLIPSIS = 0x40;  ///< cdecl + ellipsis
const cm_t  CM_CC_STDCALL  = 0x50;  ///< stack, purged
const cm_t  CM_CC_PASCAL   = 0x60;  ///< stack, purged, reverse order of args
const cm_t  CM_CC_FASTCALL = 0x70;  ///< stack, purged (x86), first args are in regs (compiler-dependent)
const cm_t  CM_CC_THISCALL = 0x80;  ///< stack, purged (x86), first arg is in reg (compiler-dependent)
const cm_t  CM_CC_SWIFT    = 0x90;  ///< (Swift) arguments and return values in registers (compiler-dependent)
const cm_t  CM_CC_SPOILED  = 0xA0;  ///< This is NOT a cc! Mark of __spoil record
                                    ///< the low nibble is count and after n {spoilreg_t}
                                    ///< present real cm_t byte. if n == BFA_FUNC_MARKER,
                                    ///< the next byte is the function attribute byte.
const cm_t  CM_CC_GOLANG   = 0xB0;  ///< (Go) arguments and return value in stack
const cm_t  CM_CC_RESERVE3 = 0xC0;
const cm_t  CM_CC_SPECIALE = 0xD0;  ///< ::CM_CC_SPECIAL with ellipsis
const cm_t  CM_CC_SPECIALP = 0xE0;  ///< Equal to ::CM_CC_SPECIAL, but with purged stack
const cm_t  CM_CC_SPECIAL  = 0xF0;  ///< usercall: locations of all arguments
                                    ///< and the return value are explicitly specified
//@} CM_CC_

//@} CM_

/*! \defgroup BFA_ Function attribute byte
  \ingroup tf_func
  Zero attribute byte is forbidden.
*/
//@{
const type_t BFA_NORET   = 0x01;    ///< __noreturn
const type_t BFA_PURE    = 0x02;    ///< __pure
const type_t BFA_HIGH    = 0x04;    ///< high level prototype (with possibly hidden args)
const type_t BFA_STATIC  = 0x08;    ///< static
const type_t BFA_VIRTUAL = 0x10;    ///< virtual

const cm_t   BFA_FUNC_MARKER     = 0x0F; ///< This is NOT a cc! (used internally as a marker)
const type_t BFA_FUNC_EXT_FORMAT = 0x80; ///< This is NOT a real attribute (used internally as marker for extended format)
//@}

#ifndef SWIG
/// Helper to declare common ::argloc_t related functions
#define ARGLOC_HELPER_DEFINITIONS(decl) \
decl void ida_export copy_argloc(argloc_t *dst, const argloc_t *src); \
decl void ida_export cleanup_argloc(argloc_t *vloc);\
decl int ida_export compare_arglocs(const argloc_t &a, const argloc_t &b);
#else
#define ARGLOC_HELPER_DEFINITIONS(decl)
#endif // SWIG
ARGLOC_HELPER_DEFINITIONS(idaman)

/// \defgroup argloc Argument locations
/// \ingroup CM_
//@{

/// Specifies the location type of a function argument - see \ref ALOC_
typedef int argloc_type_t;
/// \defgroup ALOC_ Argument location types
//@{
const argloc_type_t
  ALOC_NONE   = 0,  ///< none
  ALOC_STACK  = 1,  ///< stack offset
  ALOC_DIST   = 2,  ///< distributed (scattered)
  ALOC_REG1   = 3,  ///< one register (and offset within it)
  ALOC_REG2   = 4,  ///< register pair
  ALOC_RREL   = 5,  ///< register relative
  ALOC_STATIC = 6,  ///< global address
  ALOC_CUSTOM = 7;  ///< custom argloc (7 or higher)
//@}

/// Register-relative argument location
struct rrel_t
{
  sval_t off; ///< displacement from the address pointed by the register
  int reg;    ///< register index (into \varmem{ph,processor_t,reg_names})
};

class scattered_aloc_t;

/// Description of a custom argloc. Custom arglocs can be added by plugins in order
/// to describe the locations unsupported by the ida kernel.
struct custloc_desc_t
{
  size_t cbsize;     ///< size of this structure
  const char *name;  ///< name of the custom argloc type. must be unique

  /// Copy src into empty_dst
  void (idaapi *copy)(argloc_t *empty_dst, const argloc_t &src);

  /// Clear contents of loc before it is modified (may be nullptr)
  void (idaapi *cleanup)(argloc_t *loc);

  /// May be nullptr
  bool (idaapi *verify)(
        const argloc_t &loc,
        int size,
        const rangeset_t *gaps,
        bool part_of_scattered);

  /// Lexical comparison of two arglocs
  int (idaapi *compare)(const argloc_t &a, const argloc_t &b);

  /// Get textual description of the location (not the value at the location!)
  size_t (idaapi *print)(
        char *buf,
        size_t bufsize,
        const argloc_t &loc,
        asize_t size,
        int praloc_flags); // PRALOC_...

  /// Dereference the struct/union pointed by 'strloc': take member at offset 'off'
  /// (or use the field name), improve member 'tif' if necessary
  bool (idaapi *deref_field)(
        argloc_t *out,
        tinfo_t *tif,
        const argloc_t &strloc,
        const tinfo_t &struct_tif,
        asize_t off,
        const qstring &name);

  /// Dereference the array pointed by 'arrloc': take member number 'n'
  /// (element size is 'elsize'), improve member 'tif' if necessary
  bool (idaapi *deref_array)(
        argloc_t *out,
        tinfo_t *tif,
        const argloc_t &arrloc,
        const tinfo_t &array_tif,
        asize_t n,
        asize_t elsize);

  /// Dereference the pointer at 'loc': retrieve location of the pointed object,
  /// improve 'tif' of the pointed object if necessary
  bool (idaapi *deref_ptr)(
        argloc_t *out,
        tinfo_t *tif,
        const argloc_t &ptrloc);

  /// Read the pointer at 'loc': retrieve value of a simple object.
  /// the object value must fit value_u.
  bool (idaapi *read_value)(
        value_u *value,
        const argloc_t &loc,
        int size,
        const tinfo_t &tif);

  /// Update value at 'loc'. if idcv is VT_LONG/VT_INT64/VT_FLOAT, the value
  /// in native format is copied to 'scalar_value' for your convenience. otherwise
  /// please use 'idcv' and not 'scalar_value'.
  bool (idaapi *write_value)(
        const argloc_t &loc,
        const idc_value_t &idcv,
        const value_u &scalar_value,
        int size,
        qstring *errbuf);

  /// Calc max natural string length at 'loc' in the debugged process memory
  asize_t (idaapi *calc_string_length)(
        const argloc_t &loc,
        const tinfo_t &string_tif);

  /// Retrieve string at 'loc' from the debugged process memory,
  /// returns quoted string value
  bool (idaapi *get_string)(
        qstring *out,
        tinfo_t *elem_tif,
        const argloc_t &loc,
        const tinfo_t &string_tif,
        size_t len);

  /// Retrieve size of array at 'loc' (number of elements)
  asize_t (idaapi *guess_array_size)(
        const argloc_t &loc,
        const tinfo_t &array_tif);

  /// Retrieve type of the object at 'loc'
  bool (idaapi *get_tinfo)(
        tinfo_t *out,
        const argloc_t &loc);

  /// Calculate the number of children for the given location.
  /// (arrays, structs, ptrs may have children and therefore be expanded)
  int (idaapi *calc_number_of_children)(const argloc_t &loc, const tinfo_t &tif);

  /// Get string containing a printable representation of the pointer at 'loc'.
  /// Returns the number of characters printed.
  /// May be nullptr.
  size_t (idaapi *print_ptr_value)(
        char *buf,
        size_t bufsize,
        bool *is_valid_ptr,
        const argloc_t &loc,
        const tinfo_t &tif);
};


/// Save a custom argloc
idaman int ida_export install_custom_argloc(const custloc_desc_t *custloc);
/// Delete the custom argloc at the given index
idaman bool ida_export remove_custom_argloc(int idx);
/// Retrieve the custom argloc at the given index
idaman const custloc_desc_t *ida_export retrieve_custom_argloc(int idx);

/// Describes an argument location.
/// A typical argument is stored in one location, either a register or a stack slot.    \n
/// However, some arguments can be stored in multiple locations, for example in a pair  \n
/// of registers. In some really complex cases an argument can be located in multiple   \n
/// registers and some stack slots. This class can describe all these cases.
class argloc_t // #argloc
{
public:
  typedef size_t biggest_t;

private:
  argloc_type_t type;
  union
  {
    sval_t sval;                // ::ALOC_STACK, ::ALOC_STATIC
    uint32 reginfo;             // ::ALOC_REG1, ::ALOC_REG2
    rrel_t *rrel;               // ::ALOC_RREL
    scattered_aloc_t *dist;     // ::ALOC_DIST
    void *custom;               // ::ALOC_CUSTOM
    biggest_t biggest;          // to facilitate manipulation of this union
  };
  ARGLOC_HELPER_DEFINITIONS(friend)

public:
  argloc_t(void) : type(ALOC_NONE), biggest(0) {}                                  ///< Constructor
  argloc_t(const argloc_t &r) : type(ALOC_NONE) { copy_argloc(this, &r); }         ///< Constructor
  ~argloc_t(void) { cleanup_argloc(this); }                                        ///< Destructor
  argloc_t &operator=(const argloc_t &r) { copy_argloc(this, &r); return *this; }  ///< Constructor
  DEFINE_MEMORY_ALLOCATION_FUNCS()

  /// Assign this == r and r == this
  void swap(argloc_t &r)
  {
    biggest_t tmp = biggest; biggest = r.biggest; r.biggest = tmp;
    argloc_type_t t = type; type = r.type; r.type = t;
  }

  const char *dstr(void) const;

  argloc_type_t atype(void) const { return type; }               ///< Get type (\ref ALOC_)
  bool is_reg1(void)       const { return type == ALOC_REG1; }   ///< See ::ALOC_REG1
  bool is_reg2(void)       const { return type == ALOC_REG2; }   ///< See ::ALOC_REG2
  bool is_reg(void)        const { return type == ALOC_REG1 || type == ALOC_REG2; } ///< is_reg1() || is_reg2()
  bool is_rrel(void)       const { return type == ALOC_RREL; }   ///< See ::ALOC_RREL
  bool is_ea(void)         const { return type == ALOC_STATIC; } ///< See ::ALOC_STATIC
  bool is_stkoff(void)     const { return type == ALOC_STACK; }  ///< See ::ALOC_STACK
  bool is_scattered(void)  const { return type == ALOC_DIST; }   ///< See ::ALOC_DIST
  inline bool has_reg() const;                                   ///< TRUE if argloc has a register part
  inline bool has_stkoff() const;                                ///< TRUE if argloc has a stack part
  inline bool is_mixed_scattered() const;                        ///< mixed scattered: consists of register and stack parts
  inline bool in_stack() const;                                  ///< TRUE if argloc is in stack entirely
  bool is_fragmented(void) const { return type == ALOC_DIST || type == ALOC_REG2; } ///< is_scattered() || is_reg2()
  bool is_custom(void)     const { return type >= ALOC_CUSTOM; } ///< See ::ALOC_CUSTOM
  bool is_badloc(void)     const { return type == ALOC_NONE; }   ///< See ::ALOC_NONE

  /// Get the register info.
  /// Use when atype() == ::ALOC_REG1 or ::ALOC_REG2
  int reg1(void) const { return uint16(reginfo); }

  /// Get offset from the beginning of the register in bytes.
  /// Use when atype() == ::ALOC_REG1
  int regoff(void) const { return uint16(reginfo >> 16); }

  /// Get info for the second register.
  /// Use when atype() == ::ALOC_REG2
  int reg2(void) const { return uint16(reginfo >> 16); }

  /// Get all register info.
  /// Use when atype() == ::ALOC_REG1 or ::ALOC_REG2
  uint32 get_reginfo(void) const { return reginfo; }

  /// Get the stack offset.
  /// Use if atype() == ::ALOC_STACK
  sval_t stkoff(void) const { return sval; }

  /// Get the global address.
  /// Use when atype() == ::ALOC_STATIC
  ea_t get_ea(void) const { return sval; }

  /// Get scattered argument info.
  /// Use when atype() == ::ALOC_DIST
        scattered_aloc_t &scattered(void)       { return *dist; }
  const scattered_aloc_t &scattered(void) const { return *dist; } ///< \copydoc scattered()

  /// Get register-relative info.
  /// Use when atype() == ::ALOC_RREL
        rrel_t &get_rrel(void)       { return *rrel; }
  const rrel_t &get_rrel(void) const { return *rrel; } ///< \copydoc get_rrel()

  /// Get custom argloc info.
  /// Use if atype() == ::ALOC_CUSTOM
  void *get_custom(void) const { return custom; }

  /// Get largest element in internal union
  biggest_t get_biggest(void) const { return biggest; }

  // be careful with these functions, they do not cleanup!
  void _set_badloc(void) { type = ALOC_NONE; }                                                ///< Use set_badloc()
  void _set_reg1(int reg, int off=0) { type = ALOC_REG1; reginfo = reg | (off << 16); }       ///< Use set_reg1()
  void _set_reg2(int _reg1, int _reg2) { type = ALOC_REG2; reginfo = _reg1 | (_reg2 << 16); } ///< Use set_reg2()
  void _set_stkoff(sval_t off) { type = ALOC_STACK; sval = off; }                             ///< Use set_stkoff()
  void _set_ea(ea_t _ea) { type = ALOC_STATIC; sval = _ea; }                                  ///< Use set_ea
  /// Use consume_rrel()
  bool _consume_rrel(rrel_t *p) //lint -sem(argloc_t::_consume_rrel, custodial(1))
  {
    if ( p == nullptr )
      return false;
    type = ALOC_RREL;
    rrel = p;
    return true;
  }
  /// Use consume_scattered()
  bool _consume_scattered(scattered_aloc_t *p)
  {
    if ( p == nullptr )
      return false;
    type = ALOC_DIST;
    dist = p;
    return true;
  }

  /// Set custom argument location (careful - this function does not clean up!)
  void _set_custom(argloc_type_t ct, void *pdata) { type = ct; custom = pdata; }

  /// Set biggest element in internal union (careful - this function does not clean up!)
  void _set_biggest(argloc_type_t ct, biggest_t data) { type = ct; biggest = data; }

  /// Set register location
  void set_reg1(int reg, int off=0) { cleanup_argloc(this); _set_reg1(reg, off); }

  /// Set secondary register location
  void set_reg2(int _reg1, int _reg2) { cleanup_argloc(this); _set_reg2(_reg1, _reg2); }

  /// Set stack offset location
  void set_stkoff(sval_t off) { cleanup_argloc(this); _set_stkoff(off); }

  /// Set static ea location
  void set_ea(ea_t _ea) { cleanup_argloc(this); _set_ea(_ea); }

  /// Set register-relative location - can't be nullptr
  void consume_rrel(rrel_t *p) { cleanup_argloc(this); _consume_rrel(p); }

  /// Set distributed argument location
  void consume_scattered(scattered_aloc_t *p) { cleanup_argloc(this); _consume_scattered(p); }

  /// Set to invalid location
  void set_badloc(void) { cleanup_argloc(this); }

  /// Calculate offset that can be used to compare 2 similar arglocs
  sval_t calc_offset(void) const
  {
    switch ( type )
    {
      default:
      case ALOC_NONE:
      case ALOC_DIST:
      case ALOC_REG2:
        return -1;
      case ALOC_RREL:
        return rrel->off;
      case ALOC_STACK:
      case ALOC_STATIC:
        return sval;
      case ALOC_REG1:
        return reg1();
    }
  }

  /// Move the location to point 'delta' bytes further
  bool advance(int delta)
  {
    switch ( type )
    {
      case ALOC_REG1:
        _set_reg1(reg1()+delta, regoff());
        break;
      case ALOC_STACK:
      case ALOC_STATIC:
        sval += delta;
        break;
      case ALOC_RREL:
        rrel->off += delta;
        break;
      default:
        return false;
    }
    return true;
  }

  /// Set register offset to align it to the upper part of _SLOTSIZE
  void align_reg_high(size_t size, size_t _slotsize)
  {
    if ( is_reg1() )
      _set_reg1(reg1(), size < _slotsize ? _slotsize - size : 0);
  }

  /// Set stack offset to align to the upper part of _SLOTSIZE
  void align_stkoff_high(size_t size, size_t _slotsize)
  {
    if ( is_stkoff() )
    {
      sval_t off = align_down(stkoff(), _slotsize);
      if ( size < _slotsize )
        off += _slotsize - size;
      _set_stkoff(off);
    }
  }

  DECLARE_COMPARISONS(argloc_t)
  {
    return compare_arglocs(*this, r);
  }
};
DECLARE_TYPE_AS_MOVABLE(argloc_t);
typedef qvector<argloc_t> arglocs_t; ///< vector of argument locations

/// Subsection of an argument location
struct argpart_t : public argloc_t
{
  ushort off;  ///< offset from the beginning of the argument
  ushort size; ///< the number of bytes
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  argpart_t(const argloc_t &a) : argloc_t(a), off(0xFFFF), size(0) {} ///< Constructor
  argpart_t(void) : off(0xFFFF), size(0) {} ///< Constructor
  argpart_t &copy_from(const argloc_t &a) { *(argloc_t*)this = a; return *this; }

  /// Does this argpart have a valid offset?
  bool bad_offset(void) const { return off == 0xFFFF; }

  /// Does this argpart have a valid size?
  bool bad_size(void) const { return size == 0; }

  /// Compare two argparts, based on their offset
  bool operator < (const argpart_t &r) const { return off < r.off; }

  /// Assign this = r and r = this
  void swap(argpart_t &r)
  {
    argloc_t::swap(r);
    qswap(off, r.off);
    qswap(size, r.size);
  }
};
DECLARE_TYPE_AS_MOVABLE(argpart_t);
typedef qvector<argpart_t> argpartvec_t;

/// Used to manage arguments that are described by multiple locations (also see ::ALOC_DIST)
class scattered_aloc_t : public argpartvec_t
{
public:
  DEFINE_MEMORY_ALLOCATION_FUNCS()
};
DECLARE_TYPE_AS_MOVABLE(scattered_aloc_t);


/// Verify argloc_t.
/// \param vloc  argloc to verify
/// \param size  total size of the variable
/// \param gaps  if not nullptr, specifies gaps in structure definition.
///              these gaps should not map to any argloc, but everything else must be covered
/// \return 0 if ok, otherwise an interr code.

idaman int ida_export verify_argloc(const argloc_t &vloc, int size, const rangeset_t *gaps);


/// Verify and optimize scattered argloc into simple form.
/// All new arglocs must be processed by this function.
/// \retval true   success
/// \retval false  the input argloc was illegal

idaman bool ida_export optimize_argloc(argloc_t *vloc, int size, const rangeset_t *gaps);


/// Convert an argloc to human readable form

idaman size_t ida_export print_argloc(
        char *buf,
        size_t bufsize,
        const argloc_t &vloc,
        int size=0,
        int vflags=0);
#define PRALOC_VERIFY 0x01    ///< interr if illegal argloc
#define PRALOC_STKOFF 0x02    ///< print stack offsets


/// Visit all argument locations. The callback will not receive ::ALOC_DIST/::ALOC_REG2 types,
/// they will be converted into smaller argloc types (::ALOC_REG1 or other)
struct aloc_visitor_t
{
  virtual int idaapi visit_location(argloc_t &v, int off, int size) = 0;
  virtual ~aloc_visitor_t() {}
};

/// Compress larger argloc types and initiate the aloc visitor
idaman int ida_export for_all_arglocs(aloc_visitor_t &vv, argloc_t &vloc, int size, int off=0);

/// Same as ::aloc_visitor_t, but may not modify the argloc
struct const_aloc_visitor_t
{
  virtual int idaapi visit_location(const argloc_t &v, int off, int size) = 0;
  virtual ~const_aloc_visitor_t() {}
};

/// See for_all_arglocs()
inline int idaapi for_all_const_arglocs(const_aloc_visitor_t &vv, const argloc_t &vloc, int size, int off=0)
{
  return for_all_arglocs(*(aloc_visitor_t*)(&vv),
                         CONST_CAST(argloc_t&)(vloc),
                         size,
                         off);
}

//--------------------------------------------------------------------------
/// \defgroup C_PC_ Standard C-language models for x86
/// \ingroup CM_
//@{
const cm_t C_PC_TINY    = (CM_N16_F32 | CM_M_NN);
const cm_t C_PC_SMALL   = (CM_N16_F32 | CM_M_NN);
const cm_t C_PC_COMPACT = (CM_N16_F32 | CM_M_NF);
const cm_t C_PC_MEDIUM  = (CM_N16_F32 | CM_M_FN);
const cm_t C_PC_LARGE   = (CM_N16_F32 | CM_M_FF);
const cm_t C_PC_HUGE    = (CM_N16_F32 | CM_M_FF);
const cm_t C_PC_FLAT    = (CM_N32_F48 | CM_M_NN);
//@}


/// Get the calling convention

inline constexpr THREAD_SAFE cm_t get_cc(cm_t cm) { return(cm & CM_CC_MASK); }


/// Get effective calling convention (with respect to default CC)
inline cm_t get_effective_cc(cm_t cm)
{
  cm_t ret = get_cc(cm);
  // if the calling convention is not specified, use the default one
  if ( ret <= CM_CC_UNKNOWN )
    ret = get_cc(inf_get_cc_cm());
  return ret;
}

/// Does the calling convention specify argument locations explicitly?

inline constexpr THREAD_SAFE bool is_user_cc(cm_t cm)
{
  return get_cc(cm) >= CM_CC_SPECIALE;
}


/// Does the calling convention use ellipsis?

inline constexpr THREAD_SAFE bool is_vararg_cc(cm_t cm)
{
  return get_cc(cm) == CM_CC_ELLIPSIS || get_cc(cm) == CM_CC_SPECIALE;
}


/// Does the calling convention clean the stack arguments upon return?.
/// \note this function is valid only for x86 code

inline constexpr THREAD_SAFE bool is_purging_cc(cm_t cm)
{
  return get_cc(cm) == CM_CC_STDCALL
      || get_cc(cm) == CM_CC_PASCAL
      || get_cc(cm) == CM_CC_SPECIALP
      || get_cc(cm) == CM_CC_FASTCALL
      || get_cc(cm) == CM_CC_THISCALL
      || get_cc(cm) == CM_CC_SWIFT;
}


/// GO language calling convention (return value in stack)?

inline constexpr bool is_golang_cc(cm_t cc)
{
  return get_cc(cc) == CM_CC_GOLANG;
}


/// Swift calling convention (arguments and return values in registers)?

inline constexpr bool is_swift_cc(cm_t cc)
{
  return get_cc(cc) == CM_CC_SWIFT;
}


//--------------------------------------------------------------------------
/// Function argument passing: how GP & FP registers cooperate with each other
enum argreg_policy_t
{
  ARGREGS_POLICY_UNDEFINED,
  ARGREGS_GP_ONLY,       ///< GP registers used for all arguments
  ARGREGS_INDEPENDENT,   ///< FP/GP registers used separately (like gcc64)
  ARGREGS_BY_SLOTS,      ///< fixed FP/GP register per each slot (like vc64)
  ARGREGS_FP_CONSUME_GP, ///< FP register also consumes one or more GP regs but not vice versa (aix ppc ABI)
  ARGREGS_MIPS_O32,      ///< MIPS ABI o32
};

//@} argloc

class callregs_t;

/// Register allocation calling convention.
/// (allocation policy, arrays of GP and FP registers)
class callregs_t
{
  bool set_inds(int *p_ind1, int *p_ind2, int ind) const
  {
    if ( ind == -1 )
      return false;
    *p_ind1 = ind;
    *p_ind2 = by_slots() ? ind : -1;
    return true;
  }

  // copy -1-terminated array to a vector
  static void set_regarray(intvec_t *regvec, const int *regarray)
  {
    regvec->clear();
    if ( regarray != nullptr )
      while ( *regarray != -1 )
        regvec->push_back(*regarray++);
  }
  void calc_nregs()
  {
    nregs = gpregs.size();
    if ( policy == ARGREGS_INDEPENDENT || policy == ARGREGS_FP_CONSUME_GP )
      nregs += int(fpregs.size());
  }

public:
  argreg_policy_t policy;   ///< argument policy
  int nregs;                ///< max number of registers that can be used in a call
  intvec_t gpregs;          ///< array of gp registers
  intvec_t fpregs;          ///< array of fp registers

  /// Constructor
  callregs_t():  policy(ARGREGS_POLICY_UNDEFINED), nregs(0) {}

  /// Constructor - initialize with the given request (see init_regs())
  callregs_t(cm_t cc): policy(ARGREGS_POLICY_UNDEFINED), nregs(0)
  {
    init_regs(cc);
  }

  /// swap two instances
  void swap(callregs_t &r)
  {
    std::swap(policy, r.policy);
    std::swap(nregs, r.nregs);
    gpregs.swap(r.gpregs);
    fpregs.swap(r.fpregs);
  }

  /// Init policy & registers for given CC.
  void init_regs(cm_t cc)
  {
    processor_t::get_cc_regs(this, get_cc(cc));
  }

  // policy-specific options
  bool by_slots() const { return policy == ARGREGS_BY_SLOTS; }

  /// Init policy & registers (arrays are -1-terminated)
  void set(argreg_policy_t _policy, const int *gprs, const int *fprs)
  {
    policy = _policy;
    set_regarray(&gpregs, gprs);
    set_regarray(&fpregs, fprs);
    calc_nregs();
  }

  /// Set policy and registers to invalid values
  void reset()
  {
    set(ARGREGS_POLICY_UNDEFINED, nullptr, nullptr);
  }

  /// Get max number of registers may be used in a function call.
  static int regcount(cm_t cc)
  {
    callregs_t vr(cc); return vr.nregs;
  }

  // return index of register, -1 else
  static int findreg(const intvec_t &regs, int r)
  {
    intvec_t::const_iterator p = regs.find(r);
    return p == regs.end() ? -1 : (p-regs.begin());
  }

  /// Get register indexes within GP/FP arrays.
  /// (-1 -> is not present in the corresponding array)
  bool reginds(int *gp_ind, int *fp_ind, int r) const
  {
    return findregs(gp_ind, fp_ind, r, gpregs, fpregs);
  }

protected:
  /// Search for register r in gprs and fprs.
  /// If found, fill gp_ind and fp_ind based on #policy
  bool findregs(int *gp_ind, int *fp_ind, int r, const intvec_t &gprs, const intvec_t &fprs) const
  {
    *gp_ind = *fp_ind = -1;
    return set_inds(gp_ind, fp_ind, findreg(gprs, r))
        || set_inds(fp_ind, gp_ind, findreg(fprs, r));
  }
};

//--------------------------------------------------------------------------
/// \defgroup CC
/// Target compiler
//@{

/// \defgroup COMP_ Compiler IDs
//@{
const comp_t  COMP_MASK    = 0x0F;
const comp_t  COMP_UNK     = 0x00;      ///< Unknown
const comp_t  COMP_MS      = 0x01;      ///< Visual C++
const comp_t  COMP_BC      = 0x02;      ///< Borland C++
const comp_t  COMP_WATCOM  = 0x03;      ///< Watcom C++
// const comp_t  COMP_         = 0x04
// const comp_t  COMP_         = 0x05
const comp_t  COMP_GNU     = 0x06;      ///< GNU C++
const comp_t  COMP_VISAGE  = 0x07;      ///< Visual Age C++
const comp_t  COMP_BP      = 0x08;      ///< Delphi
//----
const comp_t  COMP_UNSURE  = 0x80;      ///< uncertain compiler id
//@}


/// \defgroup CC_funcs Functions: work with compiler IDs
//@{

/// Get compiler bits

inline THREAD_SAFE comp_t get_comp(comp_t comp) { return(comp & COMP_MASK); }


/// Get full compiler name

idaman const char *ida_export get_compiler_name(comp_t id);


/// Get abbreviated compiler name

idaman const char *ida_export get_compiler_abbr(comp_t id);

/// Collection of compiler descriptions
typedef qvector<comp_t> compvec_t;


/// Get names of all built-in compilers

idaman void ida_export get_compilers(compvec_t *ids, qstrvec_t *names, qstrvec_t *abbrs);


/// See ::COMP_UNSURE

inline THREAD_SAFE comp_t is_comp_unsure(comp_t comp) { return (comp & COMP_UNSURE); }


/// Get compiler specified by \varmem{inf,idainfo,cc}

inline comp_t default_compiler(void) { return get_comp(inf_get_cc_id()); }


/// Is the target compiler ::COMP_GNU?

inline bool is_gcc(void) { return default_compiler() == COMP_GNU; }


/// Is the target compiler 32 bit gcc?

inline bool is_gcc32(void) { return is_gcc() && !inf_is_64bit(); }


/// Is the target compiler 64 bit gcc?

inline bool is_gcc64(void) { return is_gcc() && inf_is_64bit(); }


/// Should use the struct/union layout as done by gcc?

inline bool gcc_layout(void) { return is_gcc() || (inf_get_abibits() & ABI_GCC_LAYOUT) != 0; }


/// Change current compiler.
/// \param cc       compiler to switch to
/// \param flags    \ref SETCOMP_
/// \param abiname  ABI name
/// \return success

idaman bool ida_export set_compiler(
        const compiler_info_t &cc,
        int flags,
        const char *abiname=nullptr);

/// \defgroup SETCOMP_ Set compiler flags
//@{
#define SETCOMP_OVERRIDE 0x0001         ///< may override old compiler info
#define SETCOMP_ONLY_ID  0x0002         ///< cc has only 'id' field;
                                        ///< the rest will be set to defaults
                                        ///< corresponding to the program bitness
#define SETCOMP_ONLY_ABI 0x0004         ///< ignore cc field complete, use only abiname
#define SETCOMP_BY_USER  0x0008         ///< invoked by user, cannot be replaced by module/loader
//@}


/// Set the compiler id (see \ref COMP_)

inline bool idaapi set_compiler_id(comp_t id, const char *abiname=nullptr)
{
  compiler_info_t cc;
  cc.id = id;
  return set_compiler(cc, SETCOMP_ONLY_ID, abiname);
}

/// Set abi name (see \ref COMP_)

inline bool idaapi set_abi_name(const char *abiname, bool user_level = false)
{
  compiler_info_t cc;
  cc.id = 0;
  int flags = SETCOMP_ONLY_ABI | (user_level ? SETCOMP_BY_USER : 0);
  return set_compiler(cc, flags, abiname);
}

/// Get ABI name.
/// \return length of the name (>=0)

idaman ssize_t ida_export get_abi_name(qstring *out);


/// Add/remove/check ABI option
/// General form of full abi name: abiname-opt1-opt2-... or -opt1-opt2-...
/// \param abi_opts   - ABI options to add/remove in form opt1-opt2-...
/// \param user_level - initiated by user if TRUE (==SETCOMP_BY_USER)
/// \return success
idaman bool ida_export append_abi_opts(const char *abi_opts, bool user_level = false);
idaman bool ida_export remove_abi_opts(const char *abi_opts, bool user_level = false);

/// \param compstr - compiler description in form <abbr>:<abiname>
/// \param user_level - initiated by user if TRUE
/// \return success
idaman bool ida_export set_compiler_string(const char *compstr, bool user_level);


/// is GOLANG calling convention used by default?
inline bool use_golang_cc(void)
{
  return is_golang_cc(inf_get_cc_cm());
}


/// switch to GOLANG calling convention (to be used as default CC)
inline void switch_to_golang(void)
{
  cm_t cm = inf_get_cc_cm() & ~CM_CC_MASK;
  inf_set_cc_cm(cm | CM_CC_GOLANG);
  if ( default_compiler() == COMP_UNK )
    set_compiler_id(COMP_GNU);
}

//@} CC_funcs
//@} CC

//--------------------------------------------------------------------------
const size_t BADSIZE = size_t(-1);      ///< bad type size
#define MAX_FUNC_ARGS   256             ///< max number of function arguments

//--------------------------------------------------------------------------
/// abstractness of declaration (see h2ti())
enum abs_t { abs_unk, abs_no, abs_yes };
enum sclass_t   ///< storage class
{
  sc_unk,       ///< unknown
  sc_type,      ///< typedef
  sc_ext,       ///< extern
  sc_stat,      ///< static
  sc_reg,       ///< register
  sc_auto,      ///< auto
  sc_friend,    ///< friend
  sc_virt       ///< virtual
};

/// \defgroup parse_tinfo Type parsing
/// Format/Parse/Print type information
//@{

/// \defgroup HTI_ Type formatting flags
//@{
#define HTI_CPP    0x00000001          ///< C++ mode (not implemented)
#define HTI_INT    0x00000002          ///< debug: print internal representation of types
#define HTI_EXT    0x00000004          ///< debug: print external representation of types
#define HTI_LEX    0x00000008          ///< debug: print tokens
#define HTI_UNP    0x00000010          ///< debug: check the result by unpacking it
#define HTI_TST    0x00000020          ///< test mode: discard the result
#define HTI_FIL    0x00000040          ///< "input" is file name,
                                       ///< otherwise "input" contains a C declaration
#define HTI_MAC    0x00000080          ///< define macros from the base tils
#define HTI_NWR    0x00000100          ///< no warning messages
#define HTI_NER    0x00000200          ///< ignore all errors but display them
#define HTI_DCL    0x00000400          ///< don't complain about redeclarations
#define HTI_NDC    0x00000800          ///< don't decorate names
#define HTI_PAK    0x00007000          ///< explicit structure pack value (#pragma pack)
#define HTI_PAK_SHIFT 12               ///< shift for #HTI_PAK. This field should
                                       ///< be used if you want to remember an explicit
                                       ///< pack value for each structure/union type.
                                       ///< See #HTI_PAK... definitions
#define HTI_PAKDEF  0x00000000         ///<   default pack value
#define HTI_PAK1    0x00001000         ///<   #pragma pack(1)
#define HTI_PAK2    0x00002000         ///<   #pragma pack(2)
#define HTI_PAK4    0x00003000         ///<   #pragma pack(4)
#define HTI_PAK8    0x00004000         ///<   #pragma pack(8)
#define HTI_PAK16   0x00005000         ///<   #pragma pack(16)

#define HTI_HIGH    0x00008000         ///< assume high level prototypes
                                       ///< (with hidden args, etc)
#define HTI_LOWER   0x00010000         ///< lower the function prototypes
#define HTI_RAWARGS 0x00020000         ///< leave argument names unchanged (do not remove underscores)
//@}


/// This callback will be called for each type/variable declaration.
/// \param name     var/func/type name
/// \param tif      type info
/// \param cmt      main comment
/// \param value    symbol value
/// \param cb_data  data passed to callback
/// \retval T_CBBRKDEF  the type declaration won't be saved in the til

typedef int idaapi h2ti_type_cb(
        const char *name,
        const tinfo_t &tif,
        const char *cmt,
        const uint64 *value,
        void *cb_data);


/// Specify a printing callback when parsing types.
/// See h2ti() and parse_decls().
typedef AS_PRINTF(1, 2) int printer_t(const char *format, ...);


/// Convert declarations to type_t*.
/// This is a low level function - use parse_decls() or parse_decl()
/// \param ti        type info library
/// \param lx        input lexer. may be nullptr. always destroyed by h2ti()
/// \param input     file name or C declaration
/// \param flags     combination of \ref HTI_
/// \param type_cb   callback - for each type
/// \param var_cb    callback - for each var
/// \param print_cb  may pass msg() here
/// \param _cb_data  data passed to callbacks
/// \param _isabs    the expected abstracness of the type declaration(s)
/// \return number of errors (they are displayed using print_cb). zero means ok

idaman int ida_export h2ti(
        til_t *ti,
        lexer_t *lx,
        const char *input,
        int flags=HTI_HIGH,
        h2ti_type_cb *type_cb=nullptr,
        h2ti_type_cb *var_cb=nullptr,
        printer_t *print_cb=nullptr,
        void *_cb_data=nullptr,
        abs_t _isabs=abs_unk);


/// Parse ONE declaration.
/// If the input string contains more than one declaration, the first complete
/// type declaration (#PT_TYP) or the last variable declaration (#PT_VAR) will be used.
/// \note name & tif may be empty after the call!
/// \param[out] tif     type info
/// \param[out] out     declared name
/// \param til          type library to use. may be nullptr
/// \param decl         C declaration to parse
/// \param flags        combination of \ref PT_ bits
/// \retval true   ok
/// \retval false  declaration is bad, the error message is displayed if !PT_SIL

idaman bool ida_export parse_decl(
        tinfo_t *tif,
        qstring *out,
        til_t *til,
        const char *decl,
        int flags);


/// \defgroup PT_ Type parsing flags
//@{
#define PT_SIL       0x0001  ///< silent, no messages
#define PT_NDC       0x0002  ///< don't decorate names
#define PT_TYP       0x0004  ///< return declared type information
#define PT_VAR       0x0008  ///< return declared object information
#define PT_PACKMASK  0x0070  ///< mask for pack alignment values
#define PT_HIGH      0x0080  ///< assume high level prototypes
                             ///< (with hidden args, etc)
#define PT_LOWER     0x0100  ///< lower the function prototypes
#define PT_REPLACE   0x0200  ///< replace the old type (used in idc)
#define PT_RAWARGS   0x0400  ///< leave argument names unchanged (do not remove underscores)
//@}


/// Convert \ref PT_ to \ref HTI_.
/// Type parsing flags lesser than 0x10 don't have stable meaning and will be ignored
/// (more on these flags can be seen in idc.idc)

inline THREAD_SAFE int convert_pt_flags_to_hti(int pt_flags)
{
  return ((pt_flags >> 4) & 0x1f) << HTI_PAK_SHIFT;
}


/// Parse many declarations and store them in a til.
/// If there are any errors, they will be printed using 'printer'.
/// This function uses default include path and predefined macros from the
/// database settings. It always uses the #HTI_DCL bit.
/// \param til        type library to store the result
/// \param input      input string or file name (see hti_flags)
/// \param printer    function to output error messages (use msg or nullptr or your own callback)
/// \param hti_flags  combination of \ref HTI_
/// \return number of errors, 0 means ok.

idaman int ida_export parse_decls(
        til_t *til,
        const char *input,
        printer_t *printer,
        int hti_flags);


/// Get type declaration for the specified address.
/// \param out           output buffer
/// \param ea            address
/// \param prtype_flags  combination of \ref PRTYPE_
/// \return success

idaman bool ida_export print_type(qstring *out, ea_t ea, int prtype_flags);


/// \defgroup PRTYPE_ Type printing flags
//@{
#define PRTYPE_1LINE   0x0000 ///< print to one line
#define PRTYPE_MULTI   0x0001 ///< print to many lines
#define PRTYPE_TYPE    0x0002 ///< print type declaration (not variable declaration)
#define PRTYPE_PRAGMA  0x0004 ///< print pragmas for alignment
#define PRTYPE_SEMI    0x0008 ///< append ; to the end
#define PRTYPE_CPP     0x0010 ///< use c++ name (only for print_type())
#define PRTYPE_DEF     0x0020 ///< tinfo_t: print definition, if available
#define PRTYPE_NOARGS  0x0040 ///< tinfo_t: do not print function argument names
#define PRTYPE_NOARRS  0x0080 ///< tinfo_t: print arguments with #FAI_ARRAY as pointers
#define PRTYPE_NORES   0x0100 ///< tinfo_t: never resolve types (meaningful with PRTYPE_DEF)
#define PRTYPE_RESTORE 0x0200 ///< tinfo_t: print restored types for #FAI_ARRAY and #FAI_STRUCT
#define PRTYPE_NOREGEX 0x0400 ///< do not apply regular expressions to beautify name
#define PRTYPE_COLORED 0x0800 ///< add color tag COLOR_SYMBOL for any parentheses, commas and colons
#define PRTYPE_METHODS 0x1000 ///< tinfo_t: print udt methods
#define PRTYPE_1LINCMT 0x2000 ///< print comments in one line mode
//@}

//@} parse_tinfo


/// \defgroup named_types Named types
/// functions to work with named types
//@{


/// Get named typeinfo.
/// The returned pointers are pointers to static storage.                  \n
/// They are valid until free_til(), set_named_type(), del_named_type(),   \n
/// rename_named_type(), set_numbered_type(), del_numbered_type(),         \n
/// and idb structure/enum manipulation (in other words, until ::til_t is changed).
/// \param ti         pointer to type information library
/// \param name       name of type
/// \param ntf_flags  combination of \ref NTF_
/// \param type       ptr to ptr to output buffer for the type info
/// \param fields     ptr to ptr to the field/args names. may be nullptr
/// \param cmt        ptr to ptr to the main comment. may be nullptr
/// \param fieldcmts  ptr to ptr to the field/args comments. may be nullptr
/// \param sclass     ptr to storage class
/// \param value      ptr to symbol value. for types, ptr to the ordinal number
/// \retval 0  can't find the named type (or name==nullptr)
/// \retval 1  ok, the buffers are filled with information (if not nullptr)
/// \retval 2  ok, found it in a base til

idaman int ida_export get_named_type(
        const til_t *ti,
        const char *name,
        int ntf_flags,
        const type_t **type=nullptr,
        const p_list **fields=nullptr,
        const char **cmt=nullptr,
        const p_list **fieldcmts=nullptr,
        sclass_t *sclass=nullptr,
        uint32 *value=nullptr);

/// \defgroup NTF_  Flags for named types
//@{
#define NTF_TYPE     0x0001     ///< type name
#define NTF_SYMU     0x0008     ///< symbol, name is unmangled ('func')
#define NTF_SYMM     0x0000     ///< symbol, name is mangled ('_func');
                                ///< only one of #NTF_TYPE and #NTF_SYMU, #NTF_SYMM can be used
#define NTF_NOBASE   0x0002     ///< don't inspect base tils (for get_named_type)
#define NTF_REPLACE  0x0004     ///< replace original type (for set_named_type)
#define NTF_UMANGLED 0x0008     ///< name is unmangled (don't use this flag)
#define NTF_NOCUR    0x0020     ///< don't inspect current til file (for get_named_type)
#define NTF_64BIT    0x0040     ///< value is 64bit
#define NTF_FIXNAME  0x0080     ///< force-validate the name of the type when setting
                                ///< (set_named_type, set_numbered_type only)
#define NTF_IDBENC   0x0100     ///< the name is given in the IDB encoding;
                                ///< non-ASCII bytes will be decoded accordingly
                                ///< (set_named_type, set_numbered_type only)
#define NTF_CHKSYNC  0x0200     ///< check that synchronization to IDB passed OK
                                ///< (set_numbered_type, set_named_type)
//@}


/// See get_named_type() above.
/// \note If the value in the 'ti' library is 32-bit, it will
/// be sign-extended before being stored in the 'value' pointer.

inline int idaapi get_named_type64(
        const til_t *ti,
        const char *name,
        int ntf_flags,
        const type_t **type=nullptr,
        const p_list **fields=nullptr,
        const char **cmt=nullptr,
        const p_list **fieldcmts=nullptr,
        sclass_t *sclass=nullptr,
        uint64 *value=nullptr)
{
  return get_named_type(ti, name, ntf_flags | NTF_64BIT,
                        type, fields, cmt, fieldcmts, sclass, (uint32 *)value);
}


/// Error codes for save_tinfo functions:
enum tinfo_code_t
{
  TERR_OK = 0,          ///< ok
  TERR_SAVE = -1,       ///< failed to save
  TERR_SERIALIZE = -2,  ///< failed to serialize
  TERR_WRONGNAME = -3,  ///< name is not acceptable
  TERR_BADSYNC = -4,    ///< failed to synchronize with IDB
};


/// Delete information about a symbol.
/// \param ti         type library
/// \param name       name of symbol
/// \param ntf_flags  combination of \ref NTF_
/// \return success

idaman bool ida_export del_named_type(til_t *ti, const char *name, int ntf_flags);


/// Enumerate types.
/// \param ti type library. nullptr means the local type library for the current database.
/// \param ntf_flags combination of \ref NTF_
/// \return Type or symbol names, depending of ntf_flags. Returns mangled names.
/// Never returns anonymous types. To include them, enumerate types by ordinals.

idaman const char *ida_export first_named_type(const til_t *ti, int ntf_flags);


/// \copydoc first_named_type()
/// \param name the current name. the name that follows this one will be returned.

idaman const char *ida_export next_named_type(
        const til_t *ti,
        const char *name,
        int ntf_flags);


/// Copy a named type from one til to another.
/// This function will copy the specified type and all dependent types
/// from the source type library to the destination library.
/// \param dsttil Destination til. It must have orginal types enabled
/// \param srctil Source til.
/// \param name   name of the type to copy
/// \return ordinal number of the copied type. 0 means error

idaman uint32 ida_export copy_named_type(
        til_t *dsttil,
        const til_t *srctil,
        const char *name);


/// Decorate/undecorate a C symbol name.
/// \param out     output buffer
/// \param name    name of symbol
/// \param mangle  true-mangle, false-unmangle
/// \param cc      calling convention
/// \param type    name type (nullptr-unknown)
/// \return success

idaman bool ida_export decorate_name(
        qstring *out,
        const char *name,
        bool mangle,
        cm_t cc=CM_CC_UNKNOWN,
        const tinfo_t *type = nullptr);


/// Generic function for decorate_name() (may be used in IDP modules)

idaman bool ida_export gen_decorate_name(
        qstring *out,
        const char *name,
        bool mangle,
        cm_t cc,
        const tinfo_t *type);


/// Get C or C++ form of the name.
/// \param out        output buffer
/// \param name       original (mangled or decorated) name
/// \param type       name type if known, otherwise nullptr
/// \param ccn_flags  one of \ref CCN_

idaman ssize_t ida_export calc_c_cpp_name(
        qstring *out,
        const char *name,
        const tinfo_t *type,
        int ccn_flags);
/// \defgroup CCN_ C/C++ naming flags
//@{
#define CCN_C         0x00   // prepare C name
#define CCN_CPP       0x01   // prepare C++ name
//@}

//@} named_types

//--------------------------------------------------------------------------
/// \defgroup numbered_types Numbered types
/// Functions to work with numbered (ordinal) types.
/// Numbered types may be named or anonymous.
/// They are referenced by their ordinal number. Access to them is faster because
/// there is no need to resolve their names. Also, they can stay anonymous
/// and be aliased. They can be used only in the local type library
/// created by IDA (in idati).
//@{

/// Enable the use of numbered types in til.
/// Currently it is impossible to disable numbered types once they are enabled

idaman bool ida_export enable_numbered_types(til_t *ti, bool enable);


/// Retrieve a type by its ordinal number

idaman bool ida_export get_numbered_type(
        const til_t *ti,
        uint32 ordinal,
        const type_t **type=nullptr,
        const p_list **fields=nullptr,
        const char **cmt=nullptr,
        const p_list **fieldcmts=nullptr,
        sclass_t *sclass=nullptr);


/// Allocate a range of ordinal numbers for new types.
/// \param ti   type library
/// \param qty  number of ordinals to allocate
/// \return the first ordinal. 0 means failure.

idaman uint32 ida_export alloc_type_ordinals(til_t *ti, int qty);


/// \call2{alloc_type_ordinals,ti,1}

inline uint32 alloc_type_ordinal(til_t *ti) { return alloc_type_ordinals(ti, 1); }


/// Get number of allocated ordinals.
/// \return uint32(-1) if failed

idaman uint32 ida_export get_ordinal_qty(const til_t *ti);


/// Store a type in the til.
/// 'name' may be nullptr for anonymous types.
/// The specified ordinal must be free (no other type is using it).
/// For ntf_flags, only #NTF_REPLACE is consulted.

idaman tinfo_code_t ida_export set_numbered_type(
        til_t *ti,
        uint32 ordinal,
        int ntf_flags,
        const char *name,
        const type_t *type,
        const p_list *fields=nullptr,
        const char *cmt=nullptr,
        const p_list *fldcmts=nullptr,
        const sclass_t *sclass=nullptr);


/// Delete a numbered type

idaman bool ida_export del_numbered_type(til_t *ti, uint32 ordinal);


/// Create a type alias.
/// Redirects all references to source type to the destination type.
/// This is equivalent to instantaneous replacement all reference to srctype by dsttype.

idaman bool ida_export set_type_alias(til_t *ti, uint32 src_ordinal, uint32 dst_ordinal);


/// Find the final alias destination.
/// If the ordinal has not been aliased, return the specified ordinal itself
/// If failed, returns 0.

idaman uint32 ida_export get_alias_target(const til_t *ti, uint32 ordinal);


/// Get type ordinal by its name

idaman int32 ida_export get_type_ordinal(const til_t *ti, const char *name);

/// Get type name (if exists) by its ordinal.
/// If the type is anonymous, returns "". If failed, returns nullptr

idaman const char *ida_export get_numbered_type_name(const til_t *ti, uint32 ordinal);


/// Create anonymous name for numbered type. This name can be used
/// to reference a numbered type by its ordinal
/// Ordinal names have the following format: '#' + set_de(ord)
/// Returns: -1 if error, otherwise the name length

idaman ssize_t ida_export create_numbered_type_name(qstring *buf, int32 ord);


/// Check if the name is an ordinal name.
/// Ordinal names have the following format: '#' + set_de(ord)

idaman bool ida_export is_ordinal_name(const char *name, uint32 *ord=nullptr);


/// Get ordinal number of an idb type (struct/enum).
/// The 'type' parameter is used only to determine the kind of the type (struct or enum)
/// Use this function to find out the correspondence between idb types and til types

idaman int ida_export get_ordinal_from_idb_type(const char *name, const type_t *type);


/// Is the specified idb type automatically synchronized?

inline bool idaapi is_autosync(const char *name, const type_t *type)
{
  return get_ordinal_from_idb_type(name, type) != -1;
}
inline bool idaapi is_autosync(const char *name, const tinfo_t &tif); ///< \copydoc is_autosync(const char*, const type_t *)


/// Generate a name like $hex_numbers based on the field types and names

idaman void ida_export build_anon_type_name(
        qstring *buf,
        const type_t *type,
        const p_list *fields);


const uint32 BADORD = uint32(-1); ///< invalid type ordinal


/// Compact numbered types to get rid of empty slots.
/// \param ti        type library to compact
/// \param min_ord   minimal ordinal number to start to compact. lower
///                  ordinals are not modified
/// \param p_ordmap  the resulting mapping
///                  (for example, the new ordinal of min_ord will be in ordmap[0])
/// \param flags     reserved
/// \return number of freed type slots

idaman int ida_export compact_numbered_types(
        til_t *ti,
        uint32 min_ord=0,
        intvec_t *p_ordmap=nullptr,
        int flags=0);

//@} numbered_types

//--------------------------------------------------------------------------
/// \defgroup vftable_types Link between vftable types and addresses
//@{

/// Get address of a virtual function table.
/// \param ordinal ordinal number of a vftable type.
/// \return address of the corresponding virtual function table in the current database.

idaman ea_t ida_export get_vftable_ea(uint32 ordinal);


/// Get ordinal number of the virtual function table.
/// \param vftable_ea address of a virtual function table.
/// \return ordinal number of the corresponding vftable type. 0 - failure.

idaman uint32 ida_export get_vftable_ordinal(ea_t vftable_ea);


/// Set the address of a vftable instance for a vftable type.
/// \param vftable_ea address of a virtual function table.
/// \param ordinal ordinal number of the corresponding vftable type.
/// \return success

idaman bool ida_export set_vftable_ea(uint32 ordinal, ea_t vftable_ea);


/// Delete the address of a vftable instance for a vftable type.
/// \param ordinal ordinal number of a vftable type.
/// \return success

inline bool del_vftable_ea(uint32 ordinal) { return set_vftable_ea(ordinal, BADADDR); }


//@} vftable_types

//--------------------------------------------------------------------------
// ALIGNMENT

/// Get default alignment for structure fields.
/// \return one of 1,2,4,8,...

inline size_t get_default_align(void) { return inf_get_cc_defalign(); }


/// Get alignment delta for the a structure field.
/// \param cur_tot_size  the structure size calculated so far
/// \param elem_size     size of the current field.
///                      the whole structure should be calculated
/// \param algn          the structure alignment (0,1,2,4,8...)

inline THREAD_SAFE void align_size(size_t &cur_tot_size, size_t elem_size, size_t algn)
{
  size_t al = elem_size;
  if ( algn != 0 && algn < al )
    al = algn;
  cur_tot_size = align_up(cur_tot_size, al);
}

/// Dereference a pointer.
/// \param[out] ptr_ea       in/out parameter
///                          - in: address of the pointer
///                          - out: the pointed address
/// \param tif               type of the pointer
/// \param[out] closure_obj  closure object (not used yet)
/// \return success

idaman bool ida_export deref_ptr(
        ea_t *ptr_ea,
        const tinfo_t &tif,
        ea_t *closure_obj=nullptr);


/// Remove pointer of a type.
/// (i.e. convert "char *" into "char").
/// Optionally remove the "lp" (or similar) prefix of the input name.
/// If the input type is not a pointer, then fail.

idaman bool ida_export remove_tinfo_pointer(tinfo_t *tif, const char **pname, const til_t *til=nullptr);

/// Copy a named type from til to idb.
/// \param til    type library
/// \param idx    the position of the new type in the list of types (structures or enums).
///               -1 means at the end of the list
/// \param name   the type name
/// \param flags  combination of \ref IMPTYPE_
/// \return #BADNODE on error

idaman tid_t ida_export import_type(const til_t *til, int idx, const char *name, int flags=0);

/// \defgroup IMPTYPE_ Import type flags
/// passed as 'flags' parameter to import_type()
//@{
#define IMPTYPE_VERBOSE  0x0001 ///< more verbose output (dialog boxes may appear)
#define IMPTYPE_OVERRIDE 0x0002 ///< override existing type
#define IMPTYPE_LOCAL    0x0004 ///< the type is local, the struct/enum won't be marked as til type.
                                ///< there is no need to specify this bit if til==idati,
                                ///< the kernel will set it automatically
//@}

/// Load a til file and add it the database type libraries list.
/// IDA will also apply function prototypes for matching function names.
/// \param name til name
/// \param flags  combination of \ref ADDTIL_F
/// \return one of \ref ADDTIL_R

idaman int ida_export add_til(const char *name, int flags);

/// \defgroup ADDTIL_F Load TIL flags
/// passed as 'flags' parameter to add_til()
//@{
#define ADDTIL_DEFAULT  0x0000  ///< default behavior
#define ADDTIL_INCOMP   0x0001  ///< load incompatible tils
#define ADDTIL_SILENT   0x0002  ///< do not ask any questions
//@}

/// \defgroup ADDTIL_R Load TIL result codes
/// return values for add_til()
//@{
#define ADDTIL_FAILED   0  ///< something bad, the warning is displayed
#define ADDTIL_OK       1  ///< ok, til is loaded
#define ADDTIL_COMP     2  ///< ok, but til is not compatible with the current compiler
#define ADDTIL_ABORTED  3  ///< til was not loaded (incompatible til rejected by user)
//@}


/// Unload a til file

idaman bool ida_export del_til(const char *name);


/// Apply the specified named type to the address.
/// \param ea    linear address
/// \param name  the type name, e.g. "FILE"
/// \return success

idaman bool ida_export apply_named_type(ea_t ea, const char *name);


/// Apply the specified type to the specified address.
/// This function sets the type and tries to convert the item at the specified
/// address to conform the type.
/// \param ea      linear address
/// \param tif     type string in internal format
/// \param flags   combination of \ref TINFO_
/// \returns success

idaman bool ida_export apply_tinfo(
        ea_t ea,
        const tinfo_t &tif,
        uint32 flags);

/// \defgroup TINFO_ Apply tinfo flags
/// passed as 'flags' parameter to apply_tinfo()
//@{
#define TINFO_GUESSED    0x0000 ///< this is a guessed type
#define TINFO_DEFINITE   0x0001 ///< this is a definite type
#define TINFO_DELAYFUNC  0x0002 ///< if type is a function and no function exists at ea,
                                ///< schedule its creation and argument renaming to auto-analysis,
                                ///< otherwise try to create it immediately
#define TINFO_STRICT     0x0004 ///< never convert given type to another one before applying
//@}


/// Apply the specified type to the address.
/// This function parses the declaration and calls apply_tinfo()
/// \param til    type library
/// \param ea     linear address
/// \param decl   type declaration in C form
/// \param flags  flags to pass to apply_tinfo (#TINFO_DEFINITE is always passed)
/// \return success

idaman bool ida_export apply_cdecl(til_t *til, ea_t ea, const char *decl, int flags=0);


/// Apply the type of the called function to the calling instruction.
/// This function will append parameter comments and rename the local
/// variables of the calling function. It also stores information about
/// the instructions that initialize call arguments in the database.
/// Use get_arg_addrs() to retrieve it if necessary. Alternatively it is
/// possible to hook to processor_t::arg_addrs_ready event.
/// \param caller  linear address of the calling instruction.
///                must belong to a function.
/// \param tif     type info
/// \return success

idaman bool ida_export apply_callee_tinfo(ea_t caller, const tinfo_t &tif);


/// Retrieve argument initialization addresses.
/// This function retrieves information about argument addresses.
/// This information is stored in the database by apply_callee_tinfo().
/// \param out     linear addresses of the instructions that load call arguments
/// \param caller  address of the call instruction
/// \return success

idaman bool ida_export get_arg_addrs(eavec_t *out, ea_t caller);


/// Apply the specified type and name to the address.
/// This function checks if the address already has a type. If the old type    \n
/// does not exist or the new type is 'better' than the old type, then the     \n
/// new type will be applied. A type is considered better if it has more       \n
/// information (e.g. ::BTMT_STRUCT is better than ::BT_INT).                  \n
/// The same logic is with the name: if the address already have a meaningful  \n
/// name, it will be preserved. Only if the old name does not exist or it      \n
/// is a dummy name like byte_123, it will be replaced by the new name.
/// \param dea   linear address
/// \param tif   type string in the internal format
/// \param name  new name for the address
/// \return success

idaman bool ida_export apply_once_tinfo_and_name(
        ea_t dea,
        const tinfo_t &tif,
        const char *name);


// To retrieve the type information attach to an address, use get_tinfo() function
// (see nalt.hpp)


/// Generate a type information about the id from the disassembly.
/// id can be a structure/union/enum id or an address.
/// \return one of \ref GUESS_

idaman int ida_export guess_tinfo(tinfo_t *tif, tid_t id);

/// \defgroup GUESS_ Guess tinfo codes
/// return values for guess_tinfo()
//@{
#define GUESS_FUNC_FAILED   0   ///< couldn't guess the function type
#define GUESS_FUNC_TRIVIAL  1   ///< the function type doesn't have interesting info
#define GUESS_FUNC_OK       2   ///< ok, some non-trivial information is gathered
//@}


// The following functions should eventually be replaced by exported functions
#ifndef __KERNEL__
/// Set include directory path the target compiler
inline void set_c_header_path(const char *incdir)           { setinf_buf(INF_H_PATH, incdir); }

/// Get the include directory path of the target compiler
inline ssize_t get_c_header_path(qstring *buf)              { return getinf_str(buf, INF_H_PATH); }

/// Set predefined macros for the target compiler
inline void set_c_macros(const char *macros)                { setinf_buf(INF_C_MACROS, macros); }

/// Get predefined macros for the target compiler
inline ssize_t get_c_macros(qstring *buf)                   { return getinf_str(buf, INF_C_MACROS); }
#endif

//------------------------------------------------------------------------
// HIGH LEVEL FUNCTIONS TO SUPPORT TILS IN THE IDA KERNEL

/// Pointer to the local type library - this til is private for each IDB file
/// Function that accepts til_t* uses local type library instead of nullptr.

idaman const til_t *ida_export get_idati(void);


/// Extract information from a tinfo_t.
/// \param[out] out_size   size of tif
/// \param[out] out_flags  description of type using flags_t
/// \param[out] out_mt     info for non-scalar types
/// \param      tif        the type to inspect
/// \param[out] out_alsize alignment

idaman bool ida_export get_idainfo_by_type(
        size_t *out_size,
        flags_t *out_flags,
        opinfo_t *out_mt,
        const tinfo_t &tif,
        size_t *out_alsize=nullptr);


/// Extract information from a tinfo_t.
/// \param[out] out_size   size of tif
/// \param[out] out_flags  description of type using flags64_t
/// \param[out] out_mt     info for non-scalar types
/// \param      tif        the type to inspect
/// \param[out] out_alsize alignment

idaman bool ida_export get_idainfo64_by_type(
        size_t *out_size,
        flags64_t *out_flags,
        opinfo_t *out_mt,
        const tinfo_t &tif,
        size_t *out_alsize=nullptr);

//------------------------------------------------------------------------
// Type information object: tinfo_t

struct ptr_type_data_t;
struct udt_type_data_t;
struct enum_type_data_t;
struct array_type_data_t;
struct typedef_type_data_t;
struct bitfield_type_data_t;
struct udtmembervec_t;

/// IDs for common types
enum stock_type_id_t
{
  STI_PCHAR,          ///< char *
  STI_PUCHAR,         ///< uint8 *
  STI_PCCHAR,         ///< const char *
  STI_PCUCHAR,        ///< const uint8 *
  STI_PBYTE,          ///< _BYTE *
  STI_PINT,           ///< int *
  STI_PUINT,          ///< unsigned int *
  STI_PVOID,          ///< void *
  STI_PPVOID,         ///< void **
  STI_PCVOID,         ///< const void *
  STI_ACHAR,          ///< char[]
  STI_AUCHAR,         ///< uint8[]
  STI_ACCHAR,         ///< const char[]
  STI_ACUCHAR,        ///< const uint8[]
  STI_FPURGING,       ///< void __userpurge(int)
  STI_FDELOP,         ///< void __cdecl(void *)
  STI_MSGSEND,        ///< void *(void *, const char *, ...)
  STI_AEABI_LCMP,     ///< int __fastcall(int64 x, int64 y)
  STI_AEABI_ULCMP,    ///< int __fastcall(uint64 x, uint64 y)
  STI_DONT_USE,       ///< unused stock type id; should not be used
  STI_SIZE_T,         ///< size_t
  STI_SSIZE_T,        ///< ssize_t
  STI_AEABI_MEMCPY,   ///< void __fastcall(void *, const void *, size_t)
  STI_AEABI_MEMSET,   ///< void __fastcall(void *, size_t, int)
  STI_AEABI_MEMCLR,   ///< void __fastcall(void *, size_t)
  STI_RTC_CHECK_2,    ///< int16 __fastcall(int16 x)
  STI_RTC_CHECK_4,    ///< int32 __fastcall(int32 x)
  STI_RTC_CHECK_8,    ///< int64 __fastcall(int64 x)
  STI_COMPLEX64,      ///< struct complex64_t { float real, imag; }
  STI_COMPLEX128,     ///< struct complex128_t { double real, imag; }
  STI_LAST
};

/// Constants to be used with get_udt_details()
enum gtd_udt_t
{
  GTD_CALC_LAYOUT = 0,              ///< calculate udt layout
  GTD_NO_LAYOUT   = BTM_VOLATILE,   ///< don't calculate udt layout
                                    ///< please note that udt layout may have been
                                    ///< calculated earlier
  GTD_DEL_BITFLDS = BTM_CONST,      ///< delete udt bitfields
};

/// Constants to be used with get_func_details()
enum gtd_func_t
{
  GTD_CALC_ARGLOCS = 0,             ///< calculate func arg locations
  GTD_NO_ARGLOCS = BTM_VOLATILE,    ///< don't calculate func arg locations
                                    ///< please note that the locations may have been
                                    ///< calculated earlier
};

/// Constants to be used with get_size()
enum gts_code_t
{
  GTS_NESTED = 0x01,                ///< nested type (embedded into a udt)
  GTS_BASECLASS = 0x02,             ///< is baseclass of a udt
};

/// \defgroup SUDT_ UDT serialization flags
/// passed as 'sudt_flags' parameter of helpers declared in #DECLARE_TINFO_HELPERS
//@{
#define SUDT_SORT     0x0001    ///< fields are not sorted by offset, sort them first
#define SUDT_ALIGN    0x0002    ///< recalculate field alignments, struct packing, etc
                                ///< to match the offsets and size info
#define SUDT_GAPS     0x0004    ///< allow to fill gaps with additional members (_BYTE[])
#define SUDT_UNEX     0x0008    ///< references to nonexistent member types are acceptable;
                                ///< in this case it is better to set the corresponding
                                ///< udt_member_t::fda field to the type alignment. If this
                                ///< field is not set, ida will try to guess the alignment.
#define SUDT_FAST     0x0010    ///< serialize without verifying offsets and alignments

#define SUDT_CONST    0x0040    ///< only for serialize_udt: make type const
#define SUDT_VOLATILE 0x0080    ///< only for serialize_udt: make type volatile

#define SUDT_TRUNC    0x0100    ///< serialize: truncate useless strings from fields, fldcmts
//@}

/// Macro to declare common tinfo_t related functions
#define DECLARE_TINFO_HELPERS(decl)\
decl void ida_export copy_tinfo_t(tinfo_t *_this, const tinfo_t &r); \
decl void ida_export clear_tinfo_t(tinfo_t *_this);\
decl bool ida_export create_tinfo(tinfo_t *_this, type_t bt, type_t bt2, void *ptr);\
decl int  ida_export verify_tinfo(uint32 typid);\
decl bool ida_export get_tinfo_details(uint32 typid, type_t bt2, void *buf);\
decl size_t ida_export get_tinfo_size(uint32 *p_effalign, uint32 typid, int gts_code);\
decl size_t ida_export get_tinfo_pdata(void *outptr, uint32 typid, int what);\
decl size_t ida_export get_tinfo_property(uint32 typid, int gta_prop);\
decl size_t ida_export set_tinfo_property(tinfo_t *tif, int sta_prop, size_t x);\
decl bool ida_export serialize_tinfo(qtype *type, qtype *fields, qtype *fldcmts, const tinfo_t *tif, int sudt_flags);\
decl bool ida_export deserialize_tinfo(tinfo_t *tif, const til_t *til, const type_t **ptype, const p_list **pfields, const p_list **pfldcmts);\
decl int  ida_export find_tinfo_udt_member(struct udt_member_t *udm, uint32 typid, int strmem_flags);\
decl bool ida_export print_tinfo(qstring *result, const char *prefix, int indent, int cmtindent, int flags, const tinfo_t *tif, const char *name, const char *cmt);\
decl const char *ida_export dstr_tinfo(const tinfo_t *tif);\
decl int  ida_export visit_subtypes(struct tinfo_visitor_t *visitor, struct type_mods_t *out, const tinfo_t &tif, const char *name, const char *cmt);\
decl bool ida_export compare_tinfo(uint32 t1, uint32 t2, int tcflags);\
decl int  ida_export lexcompare_tinfo(uint32 t1, uint32 t2, int);\
decl bool ida_export get_stock_tinfo(tinfo_t *tif, stock_type_id_t id);\
decl uint64 ida_export read_tinfo_bitfield_value(uint32 typid, uint64 v, int bitoff);\
decl uint64 ida_export write_tinfo_bitfield_value(uint32 typid, uint64 dst, uint64 v, int bitoff);\
decl bool ida_export get_tinfo_attr(uint32 typid, const qstring &key, bytevec_t *bv, bool all_attrs);\
decl bool ida_export set_tinfo_attr(tinfo_t *tif, const type_attr_t &ta, bool may_overwrite);\
decl bool ida_export del_tinfo_attr(tinfo_t *tif, const qstring &key, bool make_copy);\
decl bool ida_export get_tinfo_attrs(uint32 typid, type_attrs_t *tav, bool include_ref_attrs);\
decl bool ida_export set_tinfo_attrs(tinfo_t *tif, type_attrs_t *ta);\
decl uint32 ida_export score_tinfo(const tinfo_t *tif);\
decl tinfo_code_t ida_export save_tinfo(tinfo_t *tif, til_t *til, size_t ord, const char *name, int ntf_flags);\
decl tinfo_code_t ida_export save_tinfo2(tinfo_t *tif, til_t *til, size_t ord, const char *name, const char *cmt, int ntf_flags);\
decl bool ida_export append_tinfo_covered(rangeset_t *out, uint32 typid, uint64 offset);\
decl bool ida_export calc_tinfo_gaps(rangeset_t *out, uint32 typid);\
decl bool ida_export name_requires_qualifier(qstring *out, uint32 typid, const char *name, uint64 offset);\
decl bool ida_export enum_type_data_t__set_bf(enum_type_data_t *_this, bool bf);\

DECLARE_TINFO_HELPERS(idaman)

/*! \defgroup tf_nontrivial Nontrivial types
  \ingroup tf
  bits 0..5:  base type             \n
  bits 6..7:  const & volatile bits \n
  bit  8:     'is_typeref' bit      \n
  bits 9..31: type detail idx
*/
//@{
const int FIRST_NONTRIVIAL_TYPID = 0x100; ///< Denotes the first bit describing a nontrivial type
const int TYPID_ISREF = 0x100;            ///< Identifies that a type that is a typeref
const int TYPID_SHIFT = 9;                ///< First type detail bit
//@}

//-V:create_array:678 An object is used as an argument to its own method.
//-V:create_ptr:678
/// Primary mechanism for managing type information
class tinfo_t // #tinfo_t #tif
{
  uint32 typid; /// byte sequence describing the type
  bool create_type(type_t decl_type, type_t bt2, void *details)
  {
    return create_tinfo(this, decl_type, bt2, details);
  }
  /// Get the type details.
  /// The information is copied to the user-supplied buffer.
  /// Also check out convenience functions below (get_ptr_details, etc), they work faster because
  /// they do not copy the entire type info but only the desired part of it.
  bool get_type_details(type_t bt2, void *buf) const { return get_tinfo_details(typid, bt2, buf); }
  void copy(const tinfo_t &r) { copy_tinfo_t(this, r); }
  DECLARE_TINFO_HELPERS(friend)
  friend struct type_detail_t;
  friend tinfo_t remove_pointer(const tinfo_t &tif);
  /// Various type properties (properties are a 32-bit scalar values)
  enum gta_prop_t
  {
    GTA_DECLALIGN,      ///< declared alignment
    GTA_RESOLVE,        ///< real type (fully resolve eventual type references)
    GTA_REALTYPE,       ///< real type (do not fully resolve type refs)
    GTA_TYPE_SIGN,      ///< get type sign
    GTA_FROM_SUBTIL,    ///< is from a subtil (not from main til)
    GTA_IS_FORWARD,     ///< is forward declaration?
    GTA_IS_FUNCPTR,     ///< is a pointer to a function?
    GTA_ORDINAL,        ///< get initial type ordinal
    GTA_FINAL_ORDINAL,  ///< get final (resolved) type ordinal
    GTA_PTR_OBJ,        ///< ptr: pointed type
    GTA_SAFE_PTR_OBJ,   ///< ptr: pointed type or type itself
    GTA_ARRAY_ELEM,     ///< array: array element
    GTA_ARRAY_NELEMS,   ///< array: number of elements
    GTA_PTRARR_SUBTIF,  ///< ptr&array: pointed object or array element (nb: deletes current tif)
    GTA_PTRARR_SIZE,    ///< ptr&array: get size of subtype
    GTA_UNPADDED_SIZE,  ///< udt: sizeof baseclass when embedded into a derived class
    GTA_UDT_NMEMBERS,   ///< udt: get number of udt members
    GTA_IS_SMALL_UDT,   ///< udt: is small udt (can be passed in regs)
    GTA_ONEMEM_TYPE,    ///< udt&array: object consisting of one member: type of the member
    GTA_ENUM_BASE_TYPE, ///< enum: get enum base type
    GTA_FUNC_CC,        ///< func: calling convention
    GTA_PURGED_BYTES,   ///< func: number of purged bytes
    GTA_IS_HIGH_TYPE,   ///< func: is high type
    GTA_FUNC_NARGS,     ///< func: number of arguments
    GTA_FUNC_RET,       ///< func: get function return type
    GTA_FUNC_ARG,       ///< func: get type of function arg
    GTA_LAST_FUNC_ARG = GTA_FUNC_ARG + 255,
    GTA_IS_SSE_TYPE,    ///< is a SSE vector type?
    GTA_IS_ANON_UDT,    ///< is anonymous struct/union?
    GTA_IS_VFTABLE,     ///< is vftable?
    GTA_HAS_VFTABLE,    ///< has vftable?
    GTA_IS_SHIFTED_PTR, ///< is a shifted pointer?
    GTA_IS_VARSTRUCT,   ///< is a variable-size structure?
  };
  enum sta_prop_t       ///< set type property
  {
    STA_DECLALIGN,      ///< set declared alignment
    STA_TYPE_SIGN,      ///< set type sign
    STA_UDT_ALIGN,      ///< calculate udt field alignments
    STA_UDT_METHODS,    ///< set udt member functions
  };
  enum gta_pdata_t      ///< get info returned by pointer
  {
    GTP_NAME,           ///< get referenced name
    GTP_NEXT_NAME,      ///< get immediately next referenced name
    GTP_FINAL_NAME,     ///< get final referenced name
    GTP_TIL,            ///< get type library
    GTP_UDT_METHODS,    ///< get udt member functions
  };

public:
  /// Constructor
  tinfo_t(): typid(BT_UNK) {}
  /// Constructor - can only be used to initialize simple types!
  explicit tinfo_t(type_t decl_type) : typid(decl_type) {}
  /// Constructor
  tinfo_t(const tinfo_t &r) : typid(0) { copy(r); }
  /// Copy contents of given tinfo into this one
  tinfo_t &operator=(const tinfo_t &r) { copy(r); return *this; }
  /// Destructor
  ~tinfo_t(void) { clear(); }
  /// Clear contents of this tinfo, and remove from the type system
  void clear(void) { clear_tinfo_t(this); }
  /// Assign this = r and r = this
  void swap(tinfo_t &r) { uint32 tmp = typid; typid = r.typid; r.typid = tmp; }
  DEFINE_MEMORY_ALLOCATION_FUNCS()

  /// Create a tinfo_t object for an existing named type.
  /// \param til          type library to use
  /// \param name         name of the type to link to
  /// \param decl_type    if the reference was explicitly specified with the type tag         \n
  ///                     (::BTF_STRUCT/::BTF_UNION/::BTF_ENUM) you may specify it.           \n
  ///                     the kernel will accept only the specified tag after resolving       \n
  ///                     the type. If the resolved type does not correspond to the           \n
  ///                     explicitly specified tag, the type will be considered as undefined  \n
  /// \param resolve      true: immediately resolve the type and return success code.
  ///                     false: return true but do not immediately resolve the type
  /// \param try_ordinal  true: try to replace name reference by an ordinal reference
  inline bool get_named_type(
        const til_t *til,
        const char *name,
        type_t decl_type=BTF_TYPEDEF,
        bool resolve=true,
        bool try_ordinal=true);

  /// Create a tinfo_t object for an existing ordinal type.
  /// \param til        type library to use
  /// \param ordinal    number of the type to link to
  /// \param decl_type  if the reference was explicitly specified with the type tag
  ///                   (BTF_STRUCT/BTF_UNION/BTF_ENUM) you may specify it.
  ///                   the kernel will accept only the specified tag after resolving
  ///                   the type. If the resolved type does not correspond to the
  ///                   explicitly specified tag, the type will be considered as undefined
  /// \param resolve    true: immediately resolve the type and return success code
  ///                   false: return true but do not immediately resolve the type
  inline bool get_numbered_type(
        const til_t *til,
        uint32 ordinal,
        type_t decl_type=BTF_TYPEDEF,
        bool resolve=true);

  /// Serialize tinfo_t object into a type string.
  bool serialize(
        qtype *type,
        qtype *fields=nullptr,
        qtype *fldcmts=nullptr,
        int sudt_flags=SUDT_FAST|SUDT_TRUNC) const
  {
    return serialize_tinfo(type, fields, fldcmts, this, sudt_flags);
  }

  /// Deserialize a type string into a tinfo_t object
  bool deserialize(
        const til_t *til,
        const type_t **ptype,
        const p_list **pfields=nullptr,
        const p_list **pfldcmts=nullptr)
  {
    return deserialize_tinfo(this, til, ptype, pfields, pfldcmts);
  }
  /// \copydoc deserialize()
  bool deserialize(
        const til_t *til,
        const qtype *ptype,
        const qtype *pfields=nullptr,
        const qtype *pfldcmts=nullptr)
  {
    const type_t *tp = ptype->begin();
    const p_list *fp = pfields == nullptr ? nullptr : pfields->begin();
    const p_list *cp = pfldcmts == nullptr ? nullptr : pfldcmts->begin();
    return deserialize(til, &tp, fp == nullptr ? nullptr : &fp, cp == nullptr ? nullptr : &cp);
  }

  /// Is the type object correct?.
  /// It is possible to create incorrect types. For example, we can define a
  /// function that returns a enum and then delete the enum type.
  /// If this function returns false, the type should not be used in
  /// disassembly. Please note that this function does not verify all
  /// involved types: for example, pointers to undefined types are permitted.
  bool is_correct(void) const { return verify_tinfo(typid) == 0; }

  /// Get the resolved base type.
  /// Deserialization options:
  ///  - if full=true, the referenced type will be deserialized fully,
  ///                  this may not always be desirable (slows down things)
  ///  - if full=false, we just return the base type, the referenced type will be
  ///                   resolved again later if necessary
  ///                   (this may lead to multiple resolvings of the same type)
  /// imho full=false is a better approach because it does not perform
  /// unnecessary actions just in case. however, in some cases the caller knows
  /// that it is very likely that full type info will be required. in those cases
  /// full=true makes sense
  type_t get_realtype(bool full=false) const { return (type_t)get_tinfo_property(typid, full ? GTA_RESOLVE : GTA_REALTYPE); }

  /// Get declared type (without resolving type references; they are returned as is).
  /// Obviously this is a very fast function and should be used instead of get_realtype()
  /// if possible.
  THREAD_SAFE type_t get_decltype(void) const { return type_t(typid); }

  /// Was tinfo_t initialized with some type info or not?
  THREAD_SAFE bool empty(void) const { return get_decltype() == BT_UNK; }

  /// Is the type really present? (not a reference to a missing type, for example)
  bool present(void) const { return get_realtype() != BT_UNK; }

  /// Get the type size in bytes.
  /// \param p_effalign  buffer for the alignment value
  /// \param gts_code    combination of GTS_... constants
  /// \return ::BADSIZE in case of problems
  size_t get_size(uint32 *p_effalign=nullptr, int gts_code=0) const { return get_tinfo_size(p_effalign, typid, gts_code); }

  /// Get the type size in bytes without the final padding, in bytes.
  /// For some UDTs get_unpadded_size() != get_size()
  size_t get_unpadded_size(void) const { return get_tinfo_property(typid, GTA_UNPADDED_SIZE); }

  /// Get type sign
  type_sign_t get_sign(void) const { return get_tinfo_property(typid, GTA_TYPE_SIGN); }

  /// Is this a signed type?
  bool is_signed(void) const { return get_sign() == type_signed; }

  /// Is this an unsigned type?
  bool is_unsigned(void) const { return get_sign() == type_unsigned; }

  /// Get declared alignment of the type
  uchar get_declalign(void) const { return uchar(get_tinfo_property(typid, GTA_DECLALIGN)); }

  /// Set declared alignment of the type
  bool set_declalign(uchar declalign) { return set_tinfo_property(this, STA_DECLALIGN, declalign) != 0; }

  /// Is this type a type reference?.
  /// Type references cannot be modified. Once created, they do not change.
  /// Because of this, the set_... functions applied to typerefs create
  /// a new type id. Other types are modified directly.
  THREAD_SAFE bool is_typeref(void) const { return (typid & TYPID_ISREF) != 0; }

  /// Does this type refer to a nontrivial type?
  THREAD_SAFE bool has_details(void) const { return typid >= FIRST_NONTRIVIAL_TYPID; }

  /// Does a type refer to a name?.
  /// If yes, fill the provided buffer with the type name and return true.
  /// Names are returned for numbered types too: either a user-defined nice name
  /// or, if a user-provided name does not exist, an ordinal name
  /// (like #xx, see create_numbered_type_name()).
  bool get_type_name(qstring *out) const { return is_typeref() && get_tinfo_pdata(out, typid, GTP_NAME); }

  /// Use in the case of typedef chain (TYPE1 -> TYPE2 -> TYPE3...TYPEn).
  /// \return the name of the last type in the chain (TYPEn).
  ///         if there is no chain, returns TYPE1
  bool get_final_type_name(qstring *out) const { return is_typeref() && get_tinfo_pdata(out, typid, GTP_FINAL_NAME); }

  /// Use In the case of typedef chain (TYPE1 -> TYPE2 -> TYPE3...TYPEn).
  /// \return the name of the next type in the chain (TYPE2).
  ///         if there is no chain, returns failure
  bool get_next_type_name(qstring *out) const { return is_typeref() && get_tinfo_pdata(out, typid, GTP_NEXT_NAME); }

  /// Get type ordinal (only if the type was created as a numbered type, 0 if none)
  uint32 get_ordinal(void) const { return get_tinfo_property(typid, GTA_ORDINAL); }

  /// Get final type ordinal (0 is none)
  uint32 get_final_ordinal(void) const { return get_tinfo_property(typid, GTA_FINAL_ORDINAL); }

  /// Get the type library for tinfo_t
  const til_t *get_til(void) const { const til_t *til; get_tinfo_pdata(&til, typid, GTP_TIL); return til; }

  /// Was the named type found in some base type library (not the top level type library)?.
  /// If yes, it usually means that the type comes from some loaded type library,
  /// not the local type library for the database
  bool is_from_subtil(void) const { return is_typeref() && get_tinfo_property(typid, GTA_FROM_SUBTIL); }

  /// Is this a forward declaration?.
  /// Forward declarations are placeholders: the type definition does not exist
  bool is_forward_decl(void) const { return get_tinfo_property(typid, GTA_IS_FORWARD) != 0; }

  THREAD_SAFE bool is_decl_const(void) const    { return is_type_const(get_decltype());  }   ///< \isdecl{is_type_const}
  THREAD_SAFE bool is_decl_volatile(void) const { return is_type_volatile(get_decltype()); } ///< \isdecl{is_type_volatile}
  THREAD_SAFE bool is_decl_void(void) const     { return is_type_void(get_decltype());     } ///< \isdecl{is_type_void}
  THREAD_SAFE bool is_decl_partial(void) const  { return is_type_partial(get_decltype());  } ///< \isdecl{is_type_partial}
  THREAD_SAFE bool is_decl_unknown(void) const  { return is_type_unknown(get_decltype());  } ///< \isdecl{is_type_unknown}
  THREAD_SAFE bool is_decl_last(void) const     { return is_typeid_last(get_decltype());   } ///< \isdecl{is_typeid_last}
  THREAD_SAFE bool is_decl_ptr(void) const      { return is_type_ptr(get_decltype());      } ///< \isdecl{is_type_ptr}
  THREAD_SAFE bool is_decl_array(void) const    { return is_type_array(get_decltype());    } ///< \isdecl{is_type_array}
  THREAD_SAFE bool is_decl_func(void) const     { return is_type_func(get_decltype());     } ///< \isdecl{is_type_func}
  THREAD_SAFE bool is_decl_complex(void) const  { return is_type_complex(get_decltype());  } ///< \isdecl{is_type_complex}
  THREAD_SAFE bool is_decl_typedef(void) const  { return is_type_typedef(get_decltype());  } ///< \isdecl{is_type_typedef}
  THREAD_SAFE bool is_decl_sue(void) const      { return is_type_sue(get_decltype());      } ///< \isdecl{is_type_sue}
  THREAD_SAFE bool is_decl_struct(void) const   { return is_type_struct(get_decltype());   } ///< \isdecl{is_type_struct}
  THREAD_SAFE bool is_decl_union(void) const    { return is_type_union(get_decltype());    } ///< \isdecl{is_type_union}
  THREAD_SAFE bool is_decl_udt(void) const      { return is_type_struni(get_decltype());   } ///< \isdecl{is_type_struni}
  THREAD_SAFE bool is_decl_enum(void) const     { return is_type_enum(get_decltype());     } ///< \isdecl{is_type_enum}
  THREAD_SAFE bool is_decl_bitfield(void) const { return is_type_bitfld(get_decltype());   } ///< \isdecl{is_type_bitfld}
  THREAD_SAFE bool is_decl_int128(void) const   { return is_type_int128(get_decltype());   } ///< \isdecl{is_type_int128}
  THREAD_SAFE bool is_decl_int64(void) const    { return is_type_int64(get_decltype());    } ///< \isdecl{is_type_int64}
  THREAD_SAFE bool is_decl_int32(void) const    { return is_type_int32(get_decltype());    } ///< \isdecl{is_type_int32}
  THREAD_SAFE bool is_decl_int16(void) const    { return is_type_int16(get_decltype());    } ///< \isdecl{is_type_int16}
  THREAD_SAFE bool is_decl_int(void) const      { return is_type_int(get_decltype());      } ///< \isdecl{is_type_int}
  THREAD_SAFE bool is_decl_char(void) const     { return is_type_char(get_decltype());     } ///< \isdecl{is_type_char}
  THREAD_SAFE bool is_decl_uint(void) const     { return is_type_uint(get_decltype());     } ///< \isdecl{is_type_uint}
  THREAD_SAFE bool is_decl_uchar(void) const    { return is_type_uchar(get_decltype());    } ///< \isdecl{is_type_uchar}
  THREAD_SAFE bool is_decl_uint16(void) const   { return is_type_uint16(get_decltype());   } ///< \isdecl{is_type_uint16}
  THREAD_SAFE bool is_decl_uint32(void) const   { return is_type_uint32(get_decltype());   } ///< \isdecl{is_type_uint32}
  THREAD_SAFE bool is_decl_uint64(void) const   { return is_type_uint64(get_decltype());   } ///< \isdecl{is_type_uint64}
  THREAD_SAFE bool is_decl_uint128(void) const  { return is_type_uint128(get_decltype());  } ///< \isdecl{is_type_uint128}
  THREAD_SAFE bool is_decl_ldouble(void) const  { return is_type_ldouble(get_decltype());  } ///< \isdecl{is_type_ldouble}
  THREAD_SAFE bool is_decl_double(void) const   { return is_type_double(get_decltype());   } ///< \isdecl{is_type_double}
  THREAD_SAFE bool is_decl_float(void) const    { return is_type_float(get_decltype());    } ///< \isdecl{is_type_float}
  THREAD_SAFE bool is_decl_tbyte(void) const    { return is_type_tbyte(get_decltype());    } ///< \isdecl{is_type_tbyte}
  THREAD_SAFE bool is_decl_floating(void) const { return is_type_floating(get_decltype()); } ///< \isdecl{is_type_floating}
  THREAD_SAFE bool is_decl_bool(void) const     { return is_type_bool(get_decltype());     } ///< \isdecl{is_type_bool}
  THREAD_SAFE bool is_decl_paf(void) const      { return is_type_paf(get_decltype());      } ///< \isdecl{is_type_paf}
  THREAD_SAFE bool is_well_defined(void) const  { return !empty() && !is_decl_partial();   } ///< !(empty()) && !(is_decl_partial())

  // Probe the resolved type for various attributes:
  bool is_const(void) const    { return is_type_const(get_realtype());    }      ///< \isreal{is_type_const}
  bool is_volatile(void) const { return is_type_volatile(get_realtype()); }      ///< \isreal{is_type_volatile}
  bool is_void(void) const     { return is_type_void(get_realtype());     }      ///< \isreal{is_type_void}
  bool is_partial(void) const  { return is_type_partial(get_realtype());  }      ///< \isreal{is_type_partial}
  bool is_unknown(void) const  { return is_type_unknown(get_realtype());  }      ///< \isreal{is_type_unknown}
  bool is_ptr(void) const      { return is_type_ptr(get_realtype());      }      ///< \isreal{is_type_ptr}
  bool is_array(void) const    { return is_type_array(get_realtype());    }      ///< \isreal{is_type_array}
  bool is_func(void) const     { return is_type_func(get_realtype());     }      ///< \isreal{is_type_func}
  bool is_complex(void) const  { return is_type_complex(get_realtype());  }      ///< \isreal{is_type_complex}
  bool is_struct(void) const   { return is_type_struct(get_realtype());   }      ///< \isreal{is_type_struct}
  bool is_union(void) const    { return is_type_union(get_realtype());    }      ///< \isreal{is_type_union}
  bool is_udt(void) const      { return is_type_struni(get_realtype());   }      ///< \isreal{is_type_struni}
  bool is_enum(void) const     { return is_type_enum(get_realtype());     }      ///< \isreal{is_type_enum}
  bool is_sue(void) const      { return is_type_sue(get_realtype());      }      ///< \isreal{is_type_sue}
  bool is_bitfield(void) const { return is_type_bitfld(get_realtype());   }      ///< \isreal{is_type_bitfld}
  bool is_int128(void) const   { return is_type_int128(get_realtype());   }      ///< \isreal{is_type_int128}
  bool is_int64(void) const    { return is_type_int64(get_realtype());    }      ///< \isreal{is_type_int64}
  bool is_int32(void) const    { return is_type_int32(get_realtype());    }      ///< \isreal{is_type_int32}
  bool is_int16(void) const    { return is_type_int16(get_realtype());    }      ///< \isreal{is_type_int16}
  bool is_int(void) const      { return is_type_int(get_realtype());      }      ///< \isreal{is_type_int}
  bool is_char(void) const     { return is_type_char(get_realtype());     }      ///< \isreal{is_type_char}
  bool is_uint(void) const     { return is_type_uint(get_realtype());     }      ///< \isreal{is_type_uint}
  bool is_uchar(void) const    { return is_type_uchar(get_realtype());    }      ///< \isreal{is_type_uchar}
  bool is_uint16(void) const   { return is_type_uint16(get_realtype());   }      ///< \isreal{is_type_uint16}
  bool is_uint32(void) const   { return is_type_uint32(get_realtype());   }      ///< \isreal{is_type_uint32}
  bool is_uint64(void) const   { return is_type_uint64(get_realtype());   }      ///< \isreal{is_type_uint64}
  bool is_uint128(void) const  { return is_type_uint128(get_realtype());  }      ///< \isreal{is_type_uint128}
  bool is_ldouble(void) const  { return is_type_ldouble(get_realtype());  }      ///< \isreal{is_type_ldouble}
  bool is_double(void) const   { return is_type_double(get_realtype());   }      ///< \isreal{is_type_double}
  bool is_float(void) const    { return is_type_float(get_realtype());    }      ///< \isreal{is_type_float}
  bool is_tbyte(void) const    { return is_type_tbyte(get_realtype());    }      ///< \isreal{is_type_tbyte}
  bool is_bool(void) const     { return is_type_bool(get_realtype());     }      ///< \isreal{is_type_bool}
  bool is_paf(void) const      { return is_type_paf(get_realtype());      }      ///< \isreal{is_type_paf}
  bool is_ptr_or_array(void) const   { return is_type_ptr_or_array(get_realtype()); }   ///< \isreal{is_type_ptr_or_array}
  bool is_integral(void) const       { return is_type_integral(get_realtype()); }       ///< \isreal{is_type_integral}
  bool is_ext_integral(void) const   { return is_type_ext_integral(get_realtype()); }   ///< \isreal{is_type_ext_integral}
  bool is_floating(void) const       { return is_type_floating(get_realtype()); }       ///< \isreal{is_type_floating}
  bool is_arithmetic(void) const     { return is_type_arithmetic(get_realtype()); }     ///< \isreal{is_type_arithmetic}
  bool is_ext_arithmetic(void) const { return is_type_ext_arithmetic(get_realtype()); } ///< \isreal{is_type_ext_arithmetic}
  /// Does the type represent a single number?
  bool is_scalar(void) const  { type_t bt = get_realtype(); return get_base_type(bt) <= BT_PTR || is_type_enum(bt); }

  /// Get the pointer info.
  bool get_ptr_details(ptr_type_data_t *pi) const
  {
    return get_type_details(BT_PTR|BTM_VOLATILE, pi);
  }

  /// Get the array specific info
  bool get_array_details(array_type_data_t *ai) const
  {
    return get_type_details(BT_ARRAY, ai);
  }

  /// Get the enum specific info
  bool get_enum_details(enum_type_data_t *ei) const
  {
    return get_type_details(BTF_ENUM, ei);
  }

  /// Get the bitfield specific info
  bool get_bitfield_details(bitfield_type_data_t *bi) const
  {
    return get_type_details(BT_BITFIELD, bi);
  }

  /// Get the udt specific info
  bool get_udt_details(udt_type_data_t *udt, gtd_udt_t gtd=GTD_CALC_LAYOUT) const
  {
    return get_type_details(BTF_STRUCT|gtd, udt);
  }

  /// Get only the function specific info for this tinfo_t
  bool get_func_details(func_type_data_t *fi, gtd_func_t gtd=GTD_CALC_ARGLOCS) const
  {
    return get_type_details(BT_FUNC|gtd, fi);
  }

  /// Is this pointer to a function?
  bool is_funcptr(void) const { return get_tinfo_property(typid, GTA_IS_FUNCPTR) != 0; }

  /// Is a shifted pointer?
  bool is_shifted_ptr(void) const { return get_tinfo_property(typid, GTA_IS_SHIFTED_PTR) != 0; }

  /// Is a variable-size structure?
  bool is_varstruct(void) const { return get_tinfo_property(typid, GTA_IS_VARSTRUCT) != 0; }

  /// ::BT_PTR & ::BT_ARRAY: get size of pointed object or array element. On error returns -1
  int get_ptrarr_objsize(void) const { return get_tinfo_property(typid, GTA_PTRARR_SIZE); }

  /// ::BT_PTR & ::BT_ARRAY: get the pointed object or array element.
  /// If the current type is not a pointer or array, return empty type info.
  tinfo_t get_ptrarr_object(void) const { tinfo_t r; r.typid = get_tinfo_property(typid, GTA_PTRARR_SUBTIF); return r; }

  /// ::BT_PTR: get type of pointed object.
  /// If the current type is not a pointer, return empty type info.
  /// See also get_ptrarr_object() and remove_pointer()
  tinfo_t get_pointed_object(void) const { tinfo_t r; r.typid = get_tinfo_property(typid, GTA_PTR_OBJ); return r; }

  /// Is "void *"?. This function does not check the pointer attributes and type modifiers
  bool is_pvoid(void) const { return get_pointed_object().is_void(); }

  /// ::BT_ARRAY: get type of array element. See also get_ptrarr_object()
  tinfo_t get_array_element(void) const { tinfo_t r; r.typid = get_tinfo_property(typid, GTA_ARRAY_ELEM); return r; }

  /// ::BT_ARRAY: get number of elements (-1 means error)
  int get_array_nelems(void) const { return get_tinfo_property(typid, GTA_ARRAY_NELEMS); }

  /// ::BT_FUNC or ::BT_PTR ::BT_FUNC: Get type of n-th arg (-1 means return type, see get_rettype())
  tinfo_t get_nth_arg(int n) const
  {
    tinfo_t r;
    if ( n >= -1 && n < MAX_FUNC_ARGS )
      r.typid = get_tinfo_property(typid, GTA_FUNC_ARG+n);
    return r;
  }

  /// ::BT_FUNC or ::BT_PTR ::BT_FUNC: Get the function's return type
  tinfo_t get_rettype(void) const { return get_nth_arg(-1); }

  /// ::BT_FUNC or ::BT_PTR ::BT_FUNC: Calculate number of arguments (-1 - error)
  int get_nargs(void) const { return get_tinfo_property(typid, GTA_FUNC_NARGS); }

  /// ::BT_FUNC or ::BT_PTR ::BT_FUNC: Get calling convention
  cm_t get_cc(void) const { return (cm_t)get_tinfo_property(typid, GTA_FUNC_CC); }
  bool is_user_cc(void) const { return ::is_user_cc(get_cc()); }       ///< \tinfocc{is_user_cc}
  bool is_vararg_cc(void) const { return ::is_vararg_cc(get_cc()); }   ///< \tinfocc{is_vararg_cc}
  bool is_purging_cc(void) const { return ::is_purging_cc(get_cc()); } ///< \tinfocc{is_purging_cc}

  /// ::BT_FUNC: Calculate number of purged bytes
  int calc_purged_bytes(void) const { return get_tinfo_property(typid, GTA_PURGED_BYTES); }

  /// ::BT_FUNC: Is high level type?
  bool is_high_func(void) const { return get_tinfo_property(typid, GTA_IS_HIGH_TYPE) != 0; }

  /// ::BT_COMPLEX: get a list of member functions declared in this udt.
  /// \return false if no member functions exist
  bool get_methods(udtmembervec_t *methods) const { return get_tinfo_pdata(methods, typid, GTP_UDT_METHODS) != 0; }

  /// ::BT_COMPLEX: set the list of member functions. This function consumes 'methods' (makes it empty).
  /// \return false if this type is not a udt, or if the given list is empty
  bool set_methods(udtmembervec_t &methods) { return set_tinfo_property(this, STA_UDT_METHODS, size_t(&methods)) != 0; }

  /// ::BTF_STRUCT,::BTF_UNION: Find a udt member.
  ///   - at the specified offset  (#STRMEM_OFFSET)
  ///   - with the specified index (#STRMEM_INDEX)
  ///   - with the specified type  (#STRMEM_TYPE)
  ///   - with the specified name  (#STRMEM_NAME)
  /// \return the index of the found member or -1
  int find_udt_member(struct udt_member_t *udm, int strmem_flags) const { return find_tinfo_udt_member(udm, typid, strmem_flags); }
/// \defgroup STRMEM_ Find UDT member flags
/// used by 'strmem_flags' parameter to find_udt_member()
//@{
#define STRMEM_MASK    0x0007
#define   STRMEM_OFFSET 0x0000 ///<   get member by offset
                               ///<    - in:  udm->offset - is a member offset in bits
#define   STRMEM_INDEX  0x0001 ///<   get member by number
                               ///<    - in:  udm->offset - is a member number
#define   STRMEM_AUTO   0x0002 ///<   get member by offset if struct, or get member by index if union
                               ///<    - nb: union: index is stored in the udm->offset field!
                               ///<    - nb: struct: offset is in bytes (not in bits)!
#define   STRMEM_NAME   0x0003 ///<   get member by name
                               ///<    - in:  udm->name - the desired member name.
#define   STRMEM_TYPE   0x0004 ///<   get member by type.
                               ///<    - in:  udm->type - the desired member type.
                               ///<   member types are compared with tinfo_t::equals_to()
#define   STRMEM_SIZE   0x0005 ///<   get member by size.
                               ///<    - in:  udm->size - the desired member size.
#define   STRMEM_MINS   0x0006 ///<   get smallest member by size.
#define   STRMEM_MAXS   0x0007 ///<   get biggest member by size.
#define STRMEM_VFTABLE     0x10000000
                               ///<   can be combined with #STRMEM_OFFSET, #STRMEM_AUTO
                               ///<   get vftable instead of the base class
#define STRMEM_SKIP_EMPTY  0x20000000
                               ///<   can be combined with #STRMEM_OFFSET, #STRMEM_AUTO
                               ///<   skip empty members (i.e. having zero size)
                               ///<   only last empty member can be returned
#define STRMEM_CASTABLE_TO 0x40000000
                               ///< can be combined with #STRMEM_TYPE:
                               ///<   member type must be castable to the specified type
#define STRMEM_ANON        0x80000000
                               ///< can be combined with #STRMEM_NAME:
                               ///<   look inside anonymous members too.
//@}

  /// Get number of udt members. -1-error
  int get_udt_nmembers(void) const { return get_tinfo_property(typid, GTA_UDT_NMEMBERS); }

  /// Is an empty struct/union? (has no fields)
  bool is_empty_udt(void) const { return get_udt_nmembers() == 0; }

  /// Is a small udt? (can fit a register or a pair of registers)
  bool is_small_udt(void) const { return get_tinfo_property(typid, GTA_IS_SMALL_UDT) != 0; }

  /// Requires full qualifier? (name is not unique)
  /// \param out    qualifier. may be nullptr
  /// \param name   field name
  /// \param offset field offset in bits
  /// \return if the name is not unique, returns true
  bool requires_qualifier(qstring *out, const char *name, uint64 offset) const { return name_requires_qualifier(out, typid, name, offset); }

  /// Calculate set of covered bytes for the type
  /// \param out pointer to the output buffer. covered bytes will be appended to it.
  /// \param offset delta in bytes to add to all calculations. used internally during recurion.
  bool append_covered(rangeset_t *out, uint64 offset=0) const { return append_tinfo_covered(out, typid, offset); }

  /// Calculate set of padding bytes for the type
  /// \param out pointer to the output buffer; old buffer contents will be lost.
  bool calc_gaps(rangeset_t *out) const { return calc_tinfo_gaps(out, typid); }

  /// Floating value or an object  consisting of one floating member entirely
  bool is_one_fpval(void) const { return get_onemember_type().is_floating(); }

  /// Is a SSE vector type?
  bool is_sse_type(void) const { return get_tinfo_property(typid, GTA_IS_SSE_TYPE) != 0; }

  /// Is an anonymous struct/union?
  /// We assume that types with names are anonymous if the name starts with $
  bool is_anonymous_udt(void) const { return get_tinfo_property(typid, GTA_IS_ANON_UDT) != 0; }

  /// Is a vftable type?
  bool is_vftable(void) const { return get_tinfo_property(typid, GTA_IS_VFTABLE) != 0; }

  /// Has a vftable?
  bool has_vftable(void) const { return get_tinfo_property(typid, GTA_HAS_VFTABLE) != 0; }

  /// Get enum base type (convert enum to integer type)
  /// Returns ::BT_UNK if failed to convert
  type_t get_enum_base_type(void) const { return (type_t)get_tinfo_property(typid, GTA_ENUM_BASE_TYPE); }

  /// For objects consisting of one member entirely: return type of the member
  tinfo_t get_onemember_type(void) const { tinfo_t r; r.typid = get_tinfo_property(typid, GTA_ONEMEM_TYPE); return r; }

  /// Calculate the type score (the higher - the nicer is the type)
  uint32 calc_score(void) const { return score_tinfo(this); }

  /// Get a C-like string representation of the type.
  /// \param out           output string
  /// \param name          name of type
  /// \param prtype_flags  \ref PRTYPE_
  /// \param indent        structure level indent
  /// \param cmtindent     comment indent
  /// \param prefix        string prepended to each line
  /// \param cmt           comment text
  /// \return success
  bool print(
        qstring *out,
        const char *name=nullptr,
        int prtype_flags=PRTYPE_1LINE,
        int indent=0,
        int cmtindent=0,
        const char *prefix=nullptr,
        const char *cmt=nullptr) const
  {
    return print_tinfo(out, prefix, indent, cmtindent, prtype_flags, this, name, cmt);
  }

  /// Function to facilitate debugging
  const char *dstr(void) const { return dstr_tinfo(this); }

  /// Get type attributes (all_attrs: include attributes of referenced types, if any)
  bool get_attrs(type_attrs_t *tav, bool all_attrs=false) const { return get_tinfo_attrs(typid, tav, all_attrs); }

  /// Get a type attribute
  bool get_attr(const qstring &key, bytevec_t *bv, bool all_attrs=true) const { return get_tinfo_attr(typid, key, bv, all_attrs); }

  /// Set type attributes. If necessary, a new typid will be created.
  /// this function modifies tav! (returns old attributes, if any)
  /// \return false: bad attributes
  bool set_attrs(type_attrs_t *tav) { return set_tinfo_attrs(this, tav); }

  /// Set a type attribute. If necessary, a new typid will be created.
  bool set_attr(const type_attr_t &ta, bool may_overwrite=true) { return set_tinfo_attr(this, ta, may_overwrite); }

  /// Del all type attributes. typerefs cannot be modified by this function.
  void del_attrs(void) { set_tinfo_attrs(this, nullptr); }

  /// Del a type attribute. typerefs cannot be modified by this function.
  bool del_attr(const qstring &key, bool make_copy=true) { return del_tinfo_attr(this, key, make_copy); }

  bool create_simple_type(type_t decl_type) { return create_type(decl_type, BT_INT, nullptr); }
  bool create_ptr(const ptr_type_data_t &p, type_t decl_type=BT_PTR) { return create_type(decl_type, BT_PTR|BTM_VOLATILE, (void*)&p); }
  bool create_array(const array_type_data_t &p, type_t decl_type=BT_ARRAY) { return create_type(decl_type, BT_ARRAY, (void*)&p); }
  bool create_bitfield(const bitfield_type_data_t &p, type_t decl_type=BT_BITFIELD) { return create_type(decl_type, BT_BITFIELD, (void*)&p); }
  bool create_typedef(const typedef_type_data_t &p, type_t decl_type=BTF_TYPEDEF, bool try_ordinal=true)
  {
    type_t bt2 = try_ordinal ? BTF_TYPEDEF : BTF_TYPEDEF|BTM_VOLATILE;
    return create_type(decl_type, bt2, (void *)&p);
  }

  /// \name Convenience functions
  //@{
  inline bool create_ptr(const tinfo_t &tif, uchar bps=0, type_t decl_type=BT_PTR);
  inline bool create_array(const tinfo_t &tif, uint32 nelems=0, uint32 base=0, type_t decl_type=BT_ARRAY);
  inline void create_typedef(const til_t *til, const char *name, type_t decl_type=BTF_TYPEDEF, bool try_ordinal=true) { get_named_type(til, name, decl_type, false, try_ordinal); }
  inline void create_typedef(const til_t *til, uint ord, type_t decl_type=BTF_TYPEDEF) { get_numbered_type(til, ord, decl_type, false); }
  inline bool create_bitfield(uchar nbytes, uchar width, bool is_unsigned=false, type_t decl_type=BT_BITFIELD);
  //@}

  /// \name Warning
  /// These functions consume 'p' (make it empty)
  //@{
  bool create_udt(udt_type_data_t &p, type_t decl_type) { return create_type(decl_type, BTF_STRUCT, &p); }
  bool create_enum(enum_type_data_t &p, type_t decl_type=BTF_ENUM) { return create_type(decl_type, BTF_ENUM, &p); }
  bool create_func(func_type_data_t &p, type_t decl_type=BT_FUNC) { return create_type(decl_type, BT_FUNC, &p); }
  //@}

  /// \name Store type
  /// Store the type info in the type library as a named or numbered type.
  /// The tinfo_t object will be replaced by a reference to the created type.
  /// Allowed bits for ntf_flags: #NTF_NOBASE, #NTF_REPLACE
  //@{
  tinfo_code_t set_named_type(til_t *til, const char *name, int ntf_flags=0) { return save_tinfo2(this, til, 0, name, nullptr, ntf_flags|NTF_TYPE); }
  tinfo_code_t set_named_type(til_t *til, const char *name, const char *cmt, int ntf_flags=0) { return save_tinfo2(this, til, 0, name, cmt, ntf_flags|NTF_TYPE); }
  tinfo_code_t set_symbol_type(til_t *til, const char *name, int ntf_flags=0) { return save_tinfo2(this, til, 0, name, nullptr, ntf_flags); } // NTF_SYMM and NTF_SYMU are permitted
  tinfo_code_t set_symbol_type(til_t *til, const char *name, const char *cmt, int ntf_flags=0) { return save_tinfo2(this, til, 0, name, cmt, ntf_flags); } // NTF_SYMM and NTF_SYMU are permitted
  tinfo_code_t set_numbered_type(til_t *til, uint32 ord, int ntf_flags=0, const char *name=nullptr, const char *cmt=nullptr) { return save_tinfo2(this, til, ord, name, cmt, ntf_flags); }
  //@}

  /// Create a forward declaration.
  /// decl_type: ::BTF_STRUCT, ::BTF_UNION, or ::BTF_ENUM
  tinfo_code_t create_forward_decl(til_t *til, type_t decl_type, const char *name, int ntf_flags=0)
  {
    create_typedef(til, "", decl_type, false);
    return set_named_type(til, name, ntf_flags);
  }

  /// Get stock type information.
  /// This function can be used to get tinfo_t for some common types.
  /// The same tinfo_t will be returned for the same id, thus saving memory
  /// and increasing the speed
  /// Please note that retrieving the STI_SIZE_T or STI_SSIZE_T stock type,
  /// will also have the side-effect of adding that type to the 'idati' TIL,
  /// under the well-known name 'size_t' or 'ssize_t' (respectively).
  /// The same is valid for STI_COMPLEX64 and STI_COMPLEX64 stock types
  /// with names 'complex64_t' and 'complex128_t' (respectively).
  static tinfo_t get_stock(stock_type_id_t id) { tinfo_t t; get_stock_tinfo(&t, id); return t; }

  /// Convert an array into a pointer.
  /// type[] => type *
  inline bool convert_array_to_ptr(void);

  /// Replace the current type with the ptr obj or array element.
  /// This function performs one of the following conversions:
  ///  - type[] => type
  ///  - type*  => type
  /// If the conversion is performed successfully, return true
  inline bool remove_ptr_or_array(void)
  {
    tinfo_t tif = get_ptrarr_object();
    if ( tif.empty() )
      return false;
    swap(tif);
    return true;
  }

  /// Change the type sign. Works only for the types that may have sign
  bool change_sign(type_sign_t sign) { return set_tinfo_property(this, STA_TYPE_SIGN, sign) != 0; }

  /// Calculate the udt alignments using the field offsets/sizes and the total udt size
  /// This function does not work on typerefs
  bool calc_udt_aligns(int sudt_flags=SUDT_GAPS)
    { return set_tinfo_property(this, STA_UDT_ALIGN, sudt_flags) != 0; }

  /// \name Bitfields
  /// Helper functions to store/extract bitfield values
  //@{
  uint64 read_bitfield_value(uint64 v, int bitoff) const { return read_tinfo_bitfield_value(typid, v, bitoff); }
  uint64 write_bitfield_value(uint64 dst, uint64 v, int bitoff) const { return write_tinfo_bitfield_value(typid, dst, v, bitoff); }
  //@}

  /// \name Modifiers
  /// Work with type modifiers: const and volatile
  //@{
  type_t get_modifiers(void) const { return typid & TYPE_MODIF_MASK; }
  void set_modifiers(type_t mod) { if ( !empty() ) typid = (typid & ~TYPE_MODIF_MASK) | (mod & TYPE_MODIF_MASK); }
  void set_const(void) { if ( !empty() ) typid |= BTM_CONST; }
  void set_volatile(void) { if ( !empty() ) typid |= BTM_VOLATILE; }
  void clr_const(void) { typid &= ~BTM_CONST; }
  void clr_volatile(void) { typid &= ~BTM_VOLATILE; }
  void clr_const_volatile(void) { typid &= ~TYPE_MODIF_MASK; }
  //@}

  DECLARE_COMPARISONS(tinfo_t)
  { // simple comparison: good enough to organize std::map, etc
    // for this function "unsigned char" and "uchar" are different
    // for deeper comparison see compare_with()
    return lexcompare_tinfo(typid, r.typid, 0);
  }
/// \defgroup TCMP_ tinfo_t comparison flags
/// passed as 'tcflags' parameter to tinfo_t::compare_with()
//@{
#define TCMP_EQUAL    0x0000 ///< are types equal?
#define TCMP_IGNMODS  0x0001 ///< ignore const/volatile modifiers
#define TCMP_AUTOCAST 0x0002 ///< can t1 be cast into t2 automatically?
#define TCMP_MANCAST  0x0004 ///< can t1 be cast into t2 manually?
#define TCMP_CALL     0x0008 ///< can t1 be called with t2 type?
#define TCMP_DELPTR   0x0010 ///< remove pointer from types before comparing
#define TCMP_DECL     0x0020 ///< compare declarations without resolving them
#define TCMP_ANYBASE  0x0040 ///< accept any base class when casting
#define TCMP_SKIPTHIS 0x0080 ///< skip the first function argument in comparison
//@}
  /// Compare two types, based on given flags (see \ref TCMP_)
  bool compare_with(const tinfo_t &r, int tcflags=0) const { return compare_tinfo(typid, r.typid, tcflags); }
  bool equals_to(const tinfo_t &r) const { return compare_with(r, 0); }
  bool is_castable_to(const tinfo_t &target) const { return compare_with(target, TCMP_AUTOCAST); }
  bool is_manually_castable_to(const tinfo_t &target) const { return compare_with(target, TCMP_MANCAST); }
};
DECLARE_TYPE_AS_MOVABLE(tinfo_t);
typedef qvector<tinfo_t> tinfovec_t; ///< vector of tinfo objects

//------------------------------------------------------------------------
/// SIMD type info
struct simd_info_t
{
  const char *name;  ///< name of SIMD type (nullptr-undefined)
  tinfo_t tif;       ///< SIMD type (empty-undefined)
  uint16 size;       ///< SIMD type size in bytes (0-undefined)
  type_t memtype;    ///< member type
                     ///<   BTF_INT8/16/32/64/128, BTF_UINT8/16/32/64/128
                     ///<   BTF_INT - integrals of any size/sign
                     ///<   BTF_FLOAT, BTF_DOUBLE
                     ///<   BTF_TBYTE - floatings of any size
                     ///<   BTF_UNION - union of integral and floating types
                     ///<   BTF_UNK - undefined

  simd_info_t(const char *nm = nullptr, uint16 sz = 0, type_t memt = BTF_UNK)
    : name(nm), size(sz), memtype(memt) {}

  bool match_pattern(const simd_info_t *pattern)
  {
    if ( pattern == nullptr )
      return true;
    if ( pattern->size != 0 && pattern->size != size
      || pattern->name != nullptr && !streq(pattern->name, name)
      || !pattern->tif.empty() && !pattern->tif.compare_with(tif) )
    {
      return false;
    }
    if ( pattern->memtype == BTF_UNK || pattern->memtype == memtype )
      return true;
    return pattern->memtype == BTF_TBYTE && is_type_float(memtype)
        || pattern->memtype == BTF_INT   && is_type_int(memtype);
  }
};
DECLARE_TYPE_AS_MOVABLE(simd_info_t);
typedef qvector<simd_info_t> simd_info_vec_t;

//------------------------------------------------------------------------
/// Use func_type_data_t::guess_cc()
idaman cm_t ida_export guess_func_cc(
        const func_type_data_t &fti,
        int npurged,
        int cc_flags);
/// Use func_type_data_t::dump()
idaman bool ida_export dump_func_type_data(
        qstring *out,
        const func_type_data_t &fti,
        int praloc_bits);

//------------------------------------------------------------------------
/// Pointer type information (see tinfo_t::get_ptr_details())
struct ptr_type_data_t          // #ptr
{
  tinfo_t obj_type;             ///< pointed object type
  tinfo_t closure;              ///< cannot have both closure and based_ptr_size
  uchar based_ptr_size;
  uchar taptr_bits;             ///< TAH bits
  tinfo_t parent;               ///< Parent struct
  int32 delta;                  ///< Offset from the beginning of the parent struct
  ptr_type_data_t(
        tinfo_t c=tinfo_t(),
        uchar bps=0,
        tinfo_t p=tinfo_t(),
        int32 d=0)
    : closure(c), based_ptr_size(bps), taptr_bits(0), parent(p), delta(d) {}
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  void swap(ptr_type_data_t &r) { qswap(*this, r); } ///< Set this = r and r = this
  bool operator == (const ptr_type_data_t &r) const
  {
    return obj_type == r.obj_type
        && closure == r.closure
        && based_ptr_size == r.based_ptr_size;
  }
  bool operator != (const ptr_type_data_t &r) const { return !(*this == r); }
  bool is_code_ptr(void) const { return obj_type.is_func(); } ///< Are we pointing to code?
  bool is_shifted() const { return delta != 0; }
};
DECLARE_TYPE_AS_MOVABLE(ptr_type_data_t);

//------------------------------------------------------------------------
/// Array type information (see tinfo_t::get_array_details())
struct array_type_data_t // #array
{
  tinfo_t elem_type;    ///< element type
  uint32 base;          ///< array base
  uint32 nelems;        ///< number of elements
  array_type_data_t(size_t b=0, size_t n=0) : base(b), nelems(n) {} ///< Constructor
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  void swap(array_type_data_t &r) { qswap(*this, r); } ///< set this = r and r = this
};
DECLARE_TYPE_AS_MOVABLE(array_type_data_t);

//-------------------------------------------------------------------------
/// Information about a single function argument
struct funcarg_t
{
  argloc_t argloc;        ///< argument location
  qstring name;           ///< argument name (may be empty)
  qstring cmt;            ///< argument comment (may be empty)
  tinfo_t type;           ///< argument type
  uint32 flags = 0;       ///< \ref FAI_
/// \defgroup FAI_ Function argument property bits
/// used by funcarg_t::flags
//@{
#define FAI_HIDDEN  0x0001 ///< hidden argument
#define FAI_RETPTR  0x0002 ///< pointer to return value. implies hidden
#define FAI_STRUCT  0x0004 ///< was initially a structure
#define FAI_ARRAY   0x0008 ///< was initially an array;
                           ///< see "__org_typedef" or "__org_arrdim" type attributes
                           ///< to determine the original type
#define FAI_UNUSED  0x0010 ///< argument is not used by the function
#define TA_ORG_TYPEDEF "__org_typedef" ///< the original typedef name (simple string)
#define TA_ORG_ARRDIM  "__org_arrdim"  ///< the original array dimension (pack_dd)
#define TA_FORMAT      "format"        ///< info about the 'format' argument.
                                       ///< 3 times pack_dd:
                                       ///<    \ref format_functype_t,
                                       ///<    argument number of 'format',
                                       ///<    argument number of '...'
//@}
  bool operator == (const funcarg_t &r) const
  {
    return argloc == r.argloc
        && name == r.name
//        && cmt == r.cmt
        && type == r.type;
  }
  bool operator != (const funcarg_t &r) const { return !(*this == r); }
};
DECLARE_TYPE_AS_MOVABLE(funcarg_t);
typedef qvector<funcarg_t> funcargvec_t; ///< vector of function argument objects

/// Function type information (see tinfo_t::get_func_details())
struct func_type_data_t : public funcargvec_t // #func
{
  int flags = 0;            ///< \ref FTI_
/// \defgroup FTI_ Function type data property bits
/// used by func_type_data_t::flags
//@{
#define FTI_SPOILED  0x0001 ///< information about spoiled registers is present
#define FTI_NORET    0x0002 ///< noreturn
#define FTI_PURE     0x0004 ///< __pure
#define FTI_HIGH     0x0008 ///< high level prototype (with possibly hidden args)
#define FTI_STATIC   0x0010 ///< static
#define FTI_VIRTUAL  0x0020 ///< virtual
#define FTI_CALLTYPE 0x00C0 ///< mask for FTI_*CALL
#define FTI_DEFCALL  0x0000 ///<   default call
#define FTI_NEARCALL 0x0040 ///<   near call
#define FTI_FARCALL  0x0080 ///<   far call
#define FTI_INTCALL  0x00C0 ///<   interrupt call
#define FTI_ARGLOCS  0x0100 ///< info about argument locations has been calculated
                            ///< (stkargs and retloc too)
#define FTI_EXPLOCS  0x0200 ///< all arglocs are specified explicitly
#define FTI_CONST    0x0400 ///< const member function
#define FTI_CTOR     0x0800 ///< constructor
#define FTI_DTOR     0x1000 ///< destructor
#define FTI_ALL      0x1FFF ///< all defined bits
//@}
  tinfo_t rettype;          ///< return type
  argloc_t retloc;          ///< return location
  uval_t stkargs = 0;       ///< size of stack arguments (not used in build_func_type)
  reginfovec_t spoiled;     ///< spoiled register information.
                            ///< if spoiled register info is present, it overrides
                            ///< the standard spoil info (eax, edx, ecx for x86)
  cm_t cc = 0;              ///< calling convention
  void swap(func_type_data_t &r) { qswap(*this, r); }
  bool is_high(void) const { return (flags & FTI_HIGH) != 0; }
  bool is_noret(void) const { return (flags & FTI_NORET) != 0; }
  bool is_pure(void) const { return (flags & FTI_PURE) != 0; }
  bool is_static(void) const { return (flags & FTI_STATIC) != 0; }
  bool is_virtual(void) const { return (flags & FTI_VIRTUAL) != 0; }
  bool is_const(void) const { return (flags & FTI_CONST) != 0; }
  bool is_ctor(void) const { return (flags & FTI_CTOR) != 0; }
  bool is_dtor(void) const { return (flags & FTI_DTOR) != 0; }
  int get_call_method(void) const { return flags & FTI_CALLTYPE; }
  cm_t get_cc(void) const { return get_effective_cc(cc); }
  bool is_vararg_cc() const { return ::is_vararg_cc(cc); }
  bool is_golang_cc() const { return ::is_golang_cc(get_cc()); }
  bool is_swift_cc() const { return ::is_swift_cc(cc); }

  /// Guess function calling convention
  /// use the following info: argument locations and 'stkargs'
  cm_t guess_cc(int purged, int cc_flags) const
  {
    return guess_func_cc(*this, purged, cc_flags);
  }
#define CC_CDECL_OK        0x01 ///< can use __cdecl calling convention?
#define CC_ALLOW_ARGPERM   0x02 ///< disregard argument order?
#define CC_ALLOW_REGHOLES  0x04 ///< allow holes in register argument list?
#define CC_HAS_ELLIPSIS    0x08 ///< function has a variable list of arguments?
#define CC_GOLANG_OK       0x10 ///< can use __golang calling convention
  /// Dump information that is not always visible in the function prototype.
  ///   (argument locations, return location, total stkarg size)
  bool dump(qstring *out, int praloc_bits=PRALOC_STKOFF) const
  {
    return dump_func_type_data(out, *this, praloc_bits);
  }
};

//-------------------------------------------------------------------------
/// Function index for the 'format' attribute.
enum format_functype_t
{
  FMTFUNC_PRINTF,
  FMTFUNC_SCANF,
  FMTFUNC_STRFTIME,
  FMTFUNC_STRFMON,
};

//-------------------------------------------------------------------------
/// Some calling conventions foresee special areas on the stack for call arguments.
/// This structure lists their sizes.
struct stkarg_area_info_t
{
  size_t cb = sizeof(stkarg_area_info_t);

  /// Offset from the SP to the first stack argument (can include linkage area)
  /// examples: pc: 0, hppa: -0x34, ppc aix: 0x18
  sval_t stkarg_offset = 0;

  /// Size of the shadow area.
  /// explanations at: https://stackoverflow.com/questions/30190132/what-is-the-shadow-space-in-x64-assembly
  /// examples: x64 Visual Studio C++: 0x20, x64 gcc: 0, ppc aix: 0x20
  sval_t shadow_size = 0;

  /// Size of the linkage area.
  /// explanations at: https://www.ibm.com/docs/en/xl-fortran-aix/16.1.0?topic=conventions-linkage-area
  /// examples: pc: 0, hppa: 0, ppc aix: 0x18 (equal to stkarg_offset)
  sval_t linkage_area = 0;
};

//-------------------------------------------------------------------------
/// Describes an enum value
struct enum_member_t
{
  qstring name;
  qstring cmt;
  uint64 value;
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  bool operator == (const enum_member_t &r) const
  {
    return name == r.name
//        && cmt == r.cmt
        && value == r.value;
  }
  bool operator != (const enum_member_t &r) const { return !(*this == r); }
  void swap(enum_member_t &r) { qswap(*this, r); }
};
DECLARE_TYPE_AS_MOVABLE(enum_member_t);
typedef qvector<enum_member_t> enum_member_vec_t; ///< vector of enum values

/// Enum type information (see tinfo_t::get_enum_details())
struct enum_type_data_t : public enum_member_vec_t // #enum
{
  intvec_t group_sizes; ///< if present, specifies bitmask group sizes
                        ///< each group starts with a mask member
  uint32 taenum_bits;   ///< \ref tattr_enum
  bte_t bte;            ///< enum member sizes (shift amount) and style
  enum_type_data_t(bte_t _bte=BTE_ALWAYS|BTE_HEX) : taenum_bits(0), bte(_bte) {}
  DEFINE_MEMORY_ALLOCATION_FUNCS()

  bool is_64bit(void) const { return (taenum_bits & TAENUM_64BIT) != 0; }
  bool is_hex(void) const  { return (bte & BTE_OUT_MASK) == BTE_HEX;  }
  bool is_char(void) const { return (bte & BTE_OUT_MASK) == BTE_CHAR; }
  bool is_sdec(void) const { return (bte & BTE_OUT_MASK) == BTE_SDEC; }
  bool is_udec(void) const { return (bte & BTE_OUT_MASK) == BTE_UDEC; }
  bool is_bf(void) const   { return !group_sizes.empty(); }
  int calc_nbytes(void) const
  {
    int emsize = bte & BTE_SIZE_MASK;
    return emsize != 0 ? 1 << (emsize-1) : inf_get_cc_size_e();
  }
  uint64 calc_mask(void) const { return make_mask<uint64>(calc_nbytes()*8); }
  /// Convert enum to a bitmask (flag_enum)
  bool set_bf(bool bf) { return enum_type_data_t__set_bf(this, bf); }
  void swap(enum_type_data_t &r) { qswap(*this, r); } ///< swap two instances
};
DECLARE_TYPE_AS_MOVABLE(enum_type_data_t);

//-------------------------------------------------------------------------
/// Type information for typedefs
struct typedef_type_data_t // #typedef
{
  const til_t *til;     ///< type library to use when resolving
  union
  {
    const char *name;   ///< is_ordref=false: target type name. we do not own this pointer!
    uint32 ordinal;     ///< is_ordref=true: type ordinal number
  };
  bool is_ordref;       ///< is reference by ordinal?
  bool resolve;         ///< should resolve immediately?
  typedef_type_data_t(const til_t *_til, const char *_name, bool _resolve=false)
    : name(_name), is_ordref(false), resolve(_resolve) { til = _til == nullptr ? get_idati() : _til; }
  typedef_type_data_t(const til_t *_til, uint32 ord, bool _resolve=false)
    : ordinal(ord), is_ordref(true), resolve(_resolve) { til = _til == nullptr ? get_idati() : _til; }
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  void swap(typedef_type_data_t &r) { qswap(*this, r); }
};
DECLARE_TYPE_AS_MOVABLE(typedef_type_data_t);

//-------------------------------------------------------------------------
/// An object to represent struct or union members
struct udt_member_t     // #udm
{
  uint64 offset;        ///< member offset in bits
  uint64 size;          ///< size in bits
  qstring name;         ///< member name
  qstring cmt;          ///< member comment
  tinfo_t type;         ///< member type
  int effalign;         ///< effective field alignment (in bytes)
  uint32 tafld_bits;    ///< TAH bits
  uchar fda;            ///< field alignment (shift amount)
  udt_member_t(void)
    : offset(0), size(0), effalign(0), tafld_bits(0), fda(0)
  {
  }
  bool is_bitfield(void) const { return type.is_decl_bitfield(); }
  bool is_zero_bitfield(void) const { return size == 0 && is_bitfield(); }
  bool is_unaligned(void) const { return (tafld_bits & TAFLD_UNALIGNED) != 0; }
  bool is_baseclass(void) const { return (tafld_bits & TAFLD_BASECLASS) != 0; }
  bool is_virtbase(void)  const { return (tafld_bits & TAFLD_VIRTBASE) != 0; }
  bool is_vftable(void)   const { return (tafld_bits & TAFLD_VFTABLE) != 0; }
  bool is_method(void)    const { return (tafld_bits & TAFLD_METHOD) != 0; }
  void set_unaligned(void) { tafld_bits |= TAFLD_UNALIGNED; }
  void set_baseclass(void) { tafld_bits |= TAFLD_BASECLASS; }
  void set_virtbase(void)  { tafld_bits |= TAFLD_VIRTBASE; }
  void set_vftable(void)   { tafld_bits |= TAFLD_VFTABLE; }
  void set_method(void)    { tafld_bits |= TAFLD_METHOD; }
  void clr_unaligned(void) { tafld_bits &= ~TAFLD_UNALIGNED; }
  void clr_baseclass(void) { tafld_bits &= ~TAFLD_BASECLASS; }
  void clr_virtbase(void)  { tafld_bits &= ~TAFLD_VIRTBASE; }
  void clr_vftable(void)   { tafld_bits &= ~TAFLD_VFTABLE; }
  void clr_method(void)    { tafld_bits &= ~TAFLD_METHOD; }
  uint64 begin(void) const { return offset; }
  uint64 end(void) const { return offset + size; }
  bool operator < (const udt_member_t &r) const
  {
    return offset < r.offset;
  }
  bool operator == (const udt_member_t &r) const
  {
    return offset == r.offset
        && size == r.size
        && name == r.name
//        && cmt == r.cmt
        && type == r.type
        && fda == r.fda
        && tafld_bits == r.tafld_bits
        && effalign == r.effalign;
  }
  bool operator != (const udt_member_t &r) const { return !(*this == r); }
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  void swap(udt_member_t &r) { qswap(*this, r); }
  // the user cannot enter anonymous fields in ida (they can come only from tils),
  // so we use the following trick: if the field type starts with $ and the name
  // with __, then we consider the field as anonymous
  bool is_anonymous_udm() const
  {
    return name[0] == '_' && name[1] == '_' && type.is_anonymous_udt();
  }
};
DECLARE_TYPE_AS_MOVABLE(udt_member_t);
struct udtmembervec_t : public qvector<udt_member_t> {}; ///< vector of udt member objects


/// An object to represent struct or union types (see tinfo_t::get_udt_details())
struct udt_type_data_t : public udtmembervec_t // #udt
{
  size_t total_size;    ///< total structure size in bytes
  size_t unpadded_size; ///< unpadded structure size in bytes
  uint32 effalign;      ///< effective structure alignment (in bytes)
  uint32 taudt_bits;    ///< TA... and TAUDT... bits
  uchar sda;            ///< declared structure alignment (shift amount+1). 0 - unspecified
  uchar pack;           ///< #pragma pack() alignment (shift amount)
  bool is_union;        ///< is union or struct?

  udt_type_data_t(void)
    : total_size(0), unpadded_size(0), effalign(0),
      taudt_bits(0), sda(0), pack(0),
      is_union(false)
  {
  }
  void swap(udt_type_data_t &r) { qswap(*this, r); }
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  bool is_unaligned(void) const { return (taudt_bits & TAUDT_UNALIGNED) != 0; }
  bool is_msstruct(void) const { return (taudt_bits & TAUDT_MSSTRUCT) != 0; }
  bool is_cppobj(void) const { return (taudt_bits & TAUDT_CPPOBJ) != 0; }
  bool is_vftable(void) const { return (taudt_bits & TAUDT_VFTABLE) != 0; }
  void set_vftable(void) { taudt_bits |= TAUDT_VFTABLE; }

  bool is_last_baseclass(size_t idx) // we assume idx is valid
  {
    return at(idx).is_baseclass()
        && (idx+1 == size() || !at(idx+1).is_baseclass());
  }
};
DECLARE_TYPE_AS_MOVABLE(udt_type_data_t);

// The type name of a virtual function table (__vftable) of a class is
// constructed by appending the following suffix to the class name.
// In the case of multiple inheritance we append the vft offset
// to the class name (with format %04X)
// Example: CLS_0024_vtbl is used for the vft located at the offset 0x24 of CLS

#define VTBL_SUFFIX "_vtbl"

// The member name of a virtual function table
// Complex cases are not handled yet.

#define VTBL_MEMNAME "__vftable"

//-------------------------------------------------------------------------
/// Bitfield type information (see tinfo_t::get_bitfield_details())
struct bitfield_type_data_t // #bitfield
{
  uchar nbytes;         ///< enclosing type size (1,2,4,8 bytes)
  uchar width;          ///< number of bits
  bool is_unsigned;     ///< is bitfield unsigned?
  bitfield_type_data_t(uchar _nbytes=0, uchar _width=0, bool _is_unsigned=false)
    : nbytes(_nbytes), width(_width), is_unsigned(_is_unsigned)
  {
  }
  bool serialize(qtype *type, type_t mods) const;
  DECLARE_COMPARISONS(bitfield_type_data_t)
  {
    if ( nbytes != r.nbytes )
      return nbytes > r.nbytes ? 1 : -1;
    if ( width != r.width )
      return width > r.width ? 1 : -1;
    if ( is_unsigned )
    {
      if ( !r.is_unsigned )
        return 1;
    }
    else
    {
      if ( r.is_unsigned )
        return -1;
    }
    return 0;
  }
  void swap(bitfield_type_data_t &r) { qswap(*this, r); }
};
DECLARE_TYPE_AS_MOVABLE(bitfield_type_data_t);

//--------------------------------------------------------------------------
// This tag can be used at the beginning of
//   udt_member_t::cmt
//   funcarg_t::cmt
//   enum_member_t::cmt
// to specify the line number where it is defined.
// Example: "\x05123." means the line number 123
#define TPOS_LNNUM  "\x05"

//-------------------------------------------------------------------------
inline bool inf_pack_stkargs(cm_t cc)
{
  return is_golang_cc(get_effective_cc(cc)) || inf_pack_stkargs();
}

//-------------------------------------------------------------------------
inline bool inf_big_arg_align(cm_t cc)
{
  return !is_golang_cc(get_effective_cc(cc)) && inf_big_arg_align();
}

//-------------------------------------------------------------------------
inline bool inf_huge_arg_align(cm_t cc)
{
  return !is_golang_cc(get_effective_cc(cc)) && inf_huge_arg_align();
}

//-------------------------------------------------------------------------
// return argument alignment (depends on ABI, CC and natural type alignment)
inline int get_arg_align(int type_align, int slotsize, cm_t cc=CM_CC_UNKNOWN)
{
  QASSERT(2858, is_pow2(type_align));
  if ( type_align > slotsize*2 )
  {
    if ( inf_huge_arg_align(cc) )
      return type_align;
    type_align = slotsize*2;
  }
  return type_align < slotsize
       ? inf_pack_stkargs(cc)  ? type_align : slotsize
       : inf_big_arg_align(cc) ? type_align : slotsize;
}

inline int get_arg_align(const tinfo_t &tif, int slotsize, cm_t cc=CM_CC_UNKNOWN)
{
  uint32 align = 0;
  tif.get_size(&align);
  return get_arg_align(align, slotsize, cc);
}

//-------------------------------------------------------------------------
inline sval_t align_stkarg_up(sval_t spoff, int type_align, int slotsize, cm_t cc=CM_CC_UNKNOWN)
{
  uint32 align = get_arg_align(type_align, slotsize, cc);
  return align_up(spoff, align);
}

inline sval_t align_stkarg_up(sval_t spoff, const tinfo_t &tif, int slotsize, cm_t cc=CM_CC_UNKNOWN)
{
  uint32 align = get_arg_align(tif, slotsize, cc);
  return align_up(spoff, align);
}

inline bool argloc_t::has_reg() const
{
  if ( !is_scattered() )
    return is_reg();
  for ( const auto &part : scattered() )
    if ( part.is_reg() )
      return true;
  return false;
};

inline bool argloc_t::has_stkoff() const
{
  if ( !is_scattered() )
    return is_stkoff();
  for ( const auto &part : scattered() )
    if ( part.is_stkoff() )
      return true;
  return false;
};

inline bool argloc_t::in_stack() const
{
  if ( !is_scattered() )
    return is_stkoff();
  for ( const auto &part : scattered() )
    if ( !part.is_stkoff() )
      return false;
  return true;
}

inline bool argloc_t::is_mixed_scattered() const
{
  if ( !is_scattered() )
    return false;
  bool reg_found = false;
  bool stkoff_found = false;
  for ( const auto &part : scattered() )
  {
    if ( part.is_reg() )
      reg_found = true;
    if ( part.is_stkoff() )
      stkoff_found = true;
  }
  return reg_found && stkoff_found;
}

inline bool tinfo_t::get_named_type(
        const til_t *til,
        const char *name,
        type_t decl_type,
        bool resolve,
        bool try_ordinal)
{
  if ( name == nullptr )
    return false;
  typedef_type_data_t tp(til, name, resolve);
  return create_typedef(tp, decl_type, try_ordinal);
}

inline bool tinfo_t::get_numbered_type(
        const til_t *til,
        uint32 ordinal,
        type_t decl_type,
        bool resolve)
{
  typedef_type_data_t tp(til, ordinal, resolve);
  return create_typedef(tp, decl_type, false);
}

inline bool tinfo_t::create_ptr(
        const tinfo_t &tif,
        uchar bps,
        type_t decl_type)
{
  ptr_type_data_t pi(tinfo_t(), bps);
  pi.obj_type = tif;
  return create_ptr(pi, decl_type);
}

inline bool tinfo_t::create_array(
        const tinfo_t &tif,
        uint32 nelems,
        uint32 base,
        type_t decl_type)
{
  array_type_data_t ai(base, nelems);
  ai.elem_type = tif;
  return create_array(ai, decl_type);
}

inline bool tinfo_t::create_bitfield(
        uchar nbytes,
        uchar width,
        bool _is_unsigned,
        type_t decl_type)
{
  bitfield_type_data_t bi(nbytes, width, _is_unsigned);
  return create_bitfield(bi, decl_type);
}

inline bool tinfo_t::convert_array_to_ptr(void)
{
  bool ok = false;
  array_type_data_t ai;
  if ( get_array_details(&ai) )
  {
    ptr_type_data_t pi;
    pi.obj_type.swap(ai.elem_type);
    create_ptr(pi);
    ok = true;
  }
  return ok;
}

/// ::BT_PTR: If the current type is a pointer, return the pointed object.
/// If the current type is not a pointer, return the current type.
/// See also get_ptrarr_object() and get_pointed_object()
inline tinfo_t remove_pointer(const tinfo_t &tif)
{
  tinfo_t r;
  r.typid = get_tinfo_property(tif.typid, tinfo_t::GTA_SAFE_PTR_OBJ);
  return r;
}

/// Information about how to modify the current type, used by ::tinfo_visitor_t.
struct type_mods_t
{
  tinfo_t type; ///< current type
  qstring name; ///< current type name
  qstring cmt;  ///< comment for current type
  int flags;    ///< \ref TVIS_
/// \defgroup TVIS_ Type modification bits
/// used by type_mods_t::flags
//@{
#define TVIS_TYPE  0x0001       ///< new type info is present
#define TVIS_NAME  0x0002       ///< new name is present
#define TVIS_CMT   0x0004       ///< new comment is present
//@}
  type_mods_t(void) : flags(0) {}
  void clear(void) { flags = 0; }

  /// The visit_type() function may optionally save the modified type info.
  /// Use the following functions for that. The new name and comment will be applied
  /// only if the current tinfo element has storage for them.
  void set_new_type(const tinfo_t &t) { type = t; flags |= TVIS_TYPE; }
  void set_new_name(const qstring &n) { name = n; flags |= TVIS_NAME; }
  void set_new_cmt(const qstring &c)  { cmt = c;  flags |= TVIS_CMT; }

  bool has_type(void) const { return (flags & TVIS_TYPE) != 0; }
  bool has_name(void) const { return (flags & TVIS_NAME) != 0; }
  bool has_cmt(void)  const { return (flags & TVIS_CMT) != 0; }
  bool has_info(void) const { return flags != 0; }
};

/// Visit all subtypes of a type. Derive your visitor from this class and use apply_to()
struct tinfo_visitor_t
{
  int state;            ///< \ref TVST_
/// \defgroup TVST_ tinfo visitor states
/// used by tinfo_visitor_t::state
//@{
#define TVST_PRUNE 0x01 ///< don't visit children of current type
#define TVST_DEF   0x02 ///< visit type definition (meaningful for typerefs)
#define TVST_LEVEL 0x04 // has level member (internal use)
//@}
  int level;            // recursion level (internal use)
  tinfo_visitor_t(int s=0) : state(s|TVST_LEVEL), level(0) {}

  virtual ~tinfo_visitor_t() {}

  /// Visit a subtype.
  /// this function must be implemented in the derived class.
  /// it may optionally fill out with the new type info. this can be used to
  /// modify types (in this case the 'out' argument of apply_to() may not be nullptr)
  /// return 0 to continue the traversal.
  /// return !=0 to stop the traversal.
  virtual int idaapi visit_type(
        type_mods_t *out,
        const tinfo_t &tif,
        const char *name,
        const char *cmt) = 0;

  /// To refuse to visit children of the current type, use this:
  void prune_now(void) { state |= TVST_PRUNE; }

  /// Call this function to initiate the traversal
  int apply_to(const tinfo_t &tif, type_mods_t *out=nullptr, const char *name=nullptr, const char *cmt=nullptr)
  {
    return visit_subtypes(this, out, tif, name, cmt);
  }
};


//------------------------------------------------------------------------
// Definitions for packing/unpacking idc objects

/// Object that represents a register
struct regobj_t
{
  int regidx;                           ///< index into dbg->registers
  int relocate;                         ///< 0-plain num, 1-must relocate
  bytevec_t value;
  size_t size(void) const { return value.size(); }
};
DECLARE_TYPE_AS_MOVABLE(regobj_t);
typedef qvector<regobj_t> regobjvec_t;

struct regobjs_t : public regobjvec_t {}; /// Collection of register objects


/// Read a typed idc object from the database

idaman error_t ida_export unpack_idcobj_from_idb(
        idc_value_t *obj,
        const tinfo_t &tif,
        ea_t ea,
        const bytevec_t *off0,  // if !nullptr: bytevec that represents object at 'ea'
        int pio_flags=0);
#define PIO_NOATTR_FAIL 0x0004  ///< missing attributes are not ok
#define PIO_IGNORE_PTRS 0x0008  ///< do not follow pointers


/// Read a typed idc object from the byte vector

idaman error_t ida_export unpack_idcobj_from_bv(
        idc_value_t *obj,
        const tinfo_t &tif,
        const bytevec_t &bytes,
        int pio_flags=0);


/// Write a typed idc object to the database

idaman error_t ida_export pack_idcobj_to_idb(
        const idc_value_t *obj,
        const tinfo_t &tif,
        ea_t ea,
        int pio_flags=0);


/// Write a typed idc object to the byte vector.
/// Byte vector may be non-empty, this function will append data to it

idaman error_t ida_export pack_idcobj_to_bv(
        const idc_value_t *obj,
        const tinfo_t &tif,
        relobj_t *bytes,
        void *objoff,         // nullptr - append object to 'bytes'
                              // if not nullptr:
                              //   in: int32*: offset in 'bytes' for the object
                              //       -1 means 'do not store the object itself in bytes
                              //                 store only pointed objects'
                              //   out: data for object (if *(int32*)objoff == -1)
        int pio_flags=0);


/// Helper function for the processor modules.
/// to be called from \ph{use_stkarg_type}

idaman bool ida_export apply_tinfo_to_stkarg(
        const insn_t &insn,
        const op_t &x,
        uval_t v,
        const tinfo_t &tif,
        const char *name);

//------------------------------------------------------------------------
// Helper struct for the processor modules: process call arguments
struct argtinfo_helper_t
{
  size_t reserved = 0;

  virtual ~argtinfo_helper_t() {}

  /// Set the operand type as specified
  virtual bool idaapi set_op_tinfo(
        const insn_t &insn,
        const op_t &x,
        const tinfo_t &tif,
        const char *name) = 0;

  /// Is the current insn a stkarg load?.
  /// if yes:
  ///  - src: index of the source operand in \insn_t{ops}
  ///  - dst: index of the destination operand in \insn_t{ops}
  ///         \insn_t{ops}[dst].addr is expected to have the stack offset
  virtual bool idaapi is_stkarg_load(const insn_t &insn, int *src, int *dst) = 0;

  /// The call instruction with a delay slot?.
  virtual bool idaapi has_delay_slot(ea_t /*caller*/) { return false; }

  /// This function is to be called by the processor module in response
  /// to ev_use_arg_types.
  inline void use_arg_tinfos(ea_t caller, func_type_data_t *fti, funcargvec_t *rargs);
};

/// Do not call this function directly, use argtinfo_helper_t
idaman void ida_export gen_use_arg_tinfos2(
        struct argtinfo_helper_t *_this,
        ea_t caller,
        func_type_data_t *fti,
        funcargvec_t *rargs);

inline void argtinfo_helper_t::use_arg_tinfos(
        ea_t caller,
        func_type_data_t *fti,
        funcargvec_t *rargs)
{
  gen_use_arg_tinfos2(this, caller, fti, rargs);
}

//-------------------------------------------------------------------------

/// Looks for a hole at the beginning of the stack arguments. Will make use
/// of the IDB's func_t function at that place (if present) to help determine
/// the presence of such a hole.

idaman bool ida_export func_has_stkframe_hole(ea_t ea, const func_type_data_t &fti);

//-------------------------------------------------------------------------
/// Interface class - see ::ida_lowertype_helper_t
class lowertype_helper_t
{
public:
  virtual bool idaapi func_has_stkframe_hole(
        const tinfo_t &candidate,
        const func_type_data_t &candidate_data) = 0;

  virtual int idaapi get_func_purged_bytes(
        const tinfo_t &candidate,
        const func_type_data_t &candidate_data) = 0;
};

//-------------------------------------------------------------------------
/// An implementation of ::lowertype_helper_t that has access to the
/// IDB, and thus can help spot holes in the stack arguments.
class ida_lowertype_helper_t : public lowertype_helper_t
{
  const tinfo_t &tif;
  ea_t ea;
  int purged_bytes;

public:
  ida_lowertype_helper_t(const tinfo_t &_tif, ea_t _ea, int _pb)
    : tif(_tif), ea(_ea), purged_bytes(_pb) {}

  virtual bool idaapi func_has_stkframe_hole(
        const tinfo_t &candidate,
        const func_type_data_t &candidate_data) override
  {
    return candidate == tif
         ? ::func_has_stkframe_hole(ea, candidate_data)
         : false;
  }

  virtual int idaapi get_func_purged_bytes(
        const tinfo_t &candidate,
        const func_type_data_t &) override
  {
    return candidate == tif
         ? purged_bytes
         : -1;
  }
};

//-------------------------------------------------------------------------
/// Lower type.
/// Inspect the type and lower all function subtypes using lower_func_type().     \n
/// We call the prototypes usually encountered in source files "high level"       \n
/// They may have implicit arguments, array arguments, big structure retvals, etc \n
/// We introduce explicit arguments (i.e. 'this' pointer) and call the result     \n
/// "low level prototype". See #FTI_HIGH.
///
/// In order to improve heuristics for recognition of big structure retvals,      \n
/// it is recommended to pass a helper that will be used to make decisions.       \n
/// That helper will be used only for lowering 'tif', and not for the children    \n
/// types walked through by recursion.
/// \retval  1  removed #FTI_HIGH,
/// \retval  2  made substantial changes
/// \retval -1  failure

idaman int ida_export lower_type(
        til_t *til,
        tinfo_t *tif,
        const char *name=nullptr,
        lowertype_helper_t *_helper=nullptr);


/// Replace references to ordinal types by name references.
/// This function 'unties' the type from the current local type library
/// and makes it easier to export it.
/// \param til type library to use. may be nullptr.
/// \param tif type to modify (in/out)
/// \retval  number of replaced subtypes, -1 on failure

idaman int ida_export replace_ordinal_typerefs(til_t *til, tinfo_t *tif);


/// See begin_type_updating()
enum update_type_t
{
  UTP_ENUM,
  UTP_STRUCT,
};

/// Mark the beginning of a large update operation on the types.
/// Can be used with add_enum_member(), add_struc_member, etc...
/// Also see end_type_updating()

idaman void ida_export begin_type_updating(update_type_t utp);


/// Mark the end of a large update operation on the types (see begin_type_updating())

idaman void ida_export end_type_updating(update_type_t utp);


//--------------------------------------------------------------------------
/// See format_cdata()
struct format_data_info_t
{
  int ptvf;             /// \ref PTV_
/// \defgroup PTV_ C data formatting properties
/// used by format_data_info_t::ptvf
//@{
#define PTV_DEREF  0x0001  ///< take value to print from the debugged process.
                           ///< #VT_LONG: the address is specified by idc_value_t::num
                           ///< #VT_PVOID: argloc_t is pointed by idc_value_t::pvoid
#define PTV_QUEST  0x0002  ///< print '?' for uninited data
#define PTV_EMPTY  0x0004  ///< return empty string for uninited data;
                           ///< should not specify PTV_QUEST and PTV_EMPTY together
#define PTV_CSTR   0x0008  ///< print constant strings inline
#define PTV_EXPAND 0x0010  ///< print only top level on separate lines;
                           ///< max_length applies to separate lines;
                           ///< margin is ignored
#define PTV_LZHEX  0x0020  ///< print hex numbers with leading zeroes
#define PTV_STPFLT 0x0040  ///< fail on bad floating point numbers
                           ///< (if not set, just print ?flt for them)
#define PTV_SPACE  0x0080  ///< add spaces after commas and around braces
#define PTV_DEBUG  0x0100  ///< format output for debugger
#define PTV_NOPTR  0x0200  ///< prevent pointer values from appearing in the output
#define PTV_NTOP   0x40000000 ///< internal flag, do not use
#define PTV_KEEP   0x80000000 ///< internal flag, do not use
//@}
  int radix;               ///< number representation (8,10,16)
  int max_length;          ///< max length of the formatted text (0 means no limit)
                           ///< should be used to format huge arrays for the screen,
                           ///< we cannot display the whole array anyway
                           ///< if this limit is hit, the function returns false
                           ///< and qerrno is set to eMaxLengthExceeded
  int arrbase;             ///< for arrays: the first element of array to print
  int arrnelems;           ///< for arrays: number of elements to print
  int margin;              ///< length of one line (0 means to print everything on one line)
                           ///< if an item cannot be printed in a shorter way,
                           ///< some output lines can be considerably longer
                           ///< 1 means each item on its own line
  int indent;              ///< how many spaces to use to indent nested structures/arrays

  format_data_info_t(void)
    : ptvf(PTV_EMPTY|PTV_CSTR|PTV_SPACE), radix(10), max_length(0),
      arrbase(0), arrnelems(0),
      margin(80), indent(2) {}
};

/// Additional information about the output lines
struct valinfo_t
{
  argloc_t loc;
  qstring label;
  tinfo_t type;
  valinfo_t(argloc_t l=argloc_t(), const char *name=nullptr, const tinfo_t &tif=tinfo_t())
    : loc(l), label(name), type(tif) {}
  void swap(valinfo_t &r)
  {
    loc.swap(r.loc);
    label.swap(r.label);
    type.swap(r.type);
  }
  DEFINE_MEMORY_ALLOCATION_FUNCS()
};
DECLARE_TYPE_AS_MOVABLE(valinfo_t);


/// Text representation of a data value (value string).
/// This structure is used before we decide how to represent it,
/// on one line or on many lines
class valstr_t
{
public:
  qstring oneline;              ///< result if printed on one line in UTF-8 encoding
  size_t length;                ///< length if printed on one line
  struct valstrs_t *members;    ///< strings for members, each member separately
  valinfo_t *info;              ///< additional info
  int props;                    ///< temporary properties, used internally
#define VALSTR_OPEN 0x01        ///<   printed opening curly brace '{'

  valstr_t(void) : length(0), members(nullptr), info(nullptr), props(0) {}
  ~valstr_t(void);
  DEFINE_MEMORY_ALLOCATION_FUNCS()
private:
  struct flatten_args_t
  {
    const valstr_t *may_not_collapse;
    int ptvf;
    int max_length;
    int margin;
    int indent;
  };
  friend struct valstr_sink_t;
  void update_length(int ptvf);
  void set_oneline(const char *line, int len)
  {
    oneline.append(line, len);
    length = oneline.length();
  }
  void consume_oneline(const qstring &line)
  {
    oneline.append(line);
    length = oneline.length();
  }
  bool append_char(char c, int max_length);
  bool convert_to_one_line(int ptvf, int max_length);
  bool flatten(const flatten_args_t &flargs, int level);
};
DECLARE_TYPE_AS_MOVABLE(valstr_t);
typedef qvector<valstr_t> valstrvec_t;

struct valstrs_t : public valstrvec_t {}; ///< Collection of value strings

inline valstr_t::~valstr_t(void)
{
  delete members;
  delete info;
}


/// Format a data value as a C initializer.
/// \param outvec      buffer for the formatted string(s). may be nullptr
/// \param idc_value   value to format
/// \param tif         type of the data to format.
///                    if nullptr and #PTV_DEREF is specified, take tinfo from idb
/// \param vtree       more detailed output info
/// \param fdi         formatting options
/// \return success. if failed, see qerrno for more info

idaman bool ida_export format_cdata(
        qstrvec_t *outvec,
        const idc_value_t &idc_value,
        const tinfo_t *tif,
        valstr_t *vtree=nullptr,
        const format_data_info_t *fdi=nullptr);

/// Flush formatted text
struct text_sink_t
{
  /// \return 0-ok, otherwise print_cdata will stop
  virtual int idaapi print(const char *str) = 0;
};


/// The same as format_cdata(), but instead of returning the answer in a vector, print it.
/// This function can handle very huge data volume without using too much memory.
/// As soon as the output text becomes too long, the function prints it and
/// flushes its internal buffers.
/// \retval  0    ok
/// \retval -1    printing failed, check qerrno
/// \retval else  code returned by text_sink_t::print()

idaman int ida_export print_cdata(
        text_sink_t &printer,
        const idc_value_t &idc_value,
        const tinfo_t *tif,
        const format_data_info_t *fdi=nullptr);

//-------------------------------------------------------------------------
/// \defgroup PDF_ print_decls() flags
//@{
#define PDF_INCL_DEPS  0x1 ///< Include all type dependencies
#define PDF_DEF_FWD    0x2 ///< Allow forward declarations
#define PDF_DEF_BASE   0x4 ///< Include base types: __int8, __int16, etc..
#define PDF_HEADER_CMT 0x8 ///< Prepend output with a descriptive comment
//@}

typedef qvector<uint32> ordvec_t;

/// Print types (and possibly their dependencies) in a format suitable
/// for using in a header file. This is the reverse parse_decls().
/// \param printer         a handler for printing text
/// \param til             the type library holding the ordinals
/// \param ordinals        ordinals of types to export. nullptr means: all ordinals in til
/// \param pdf_flags       flags for the algorithm. A combination of PDF_ constants
/// \retval >0   the number of types exported
/// \retval 0    an error occurred
/// \retval <0   the negated number of types exported. There were minor errors
///              and the resulting output might not be compilable.

idaman int ida_export print_decls(
        text_sink_t &printer,
        til_t *til,
        const ordvec_t *ordinals,
        uint32 pdf_flags);


/// Calculate max number of lines of a formatted c data, when expanded (#PTV_EXPAND).
/// \param loc             location of the data (::ALOC_STATIC or ::ALOC_CUSTOM)
/// \param tif             type info
/// \param dont_deref_ptr  consider 'ea' as the ptr value
/// \retval  0    data is not expandable
/// \retval -1    error, see qerrno
/// \retval else  the max number of lines

idaman int ida_export calc_number_of_children(
        const argloc_t &loc,
        const tinfo_t &tif,
        bool dont_deref_ptr=false);


/// Format a C number.
/// \param buf      output buffer
/// \param bufsize  size of the output buffer
/// \param value    number to format
/// \param size     size of the number in bytes (1,2,4,8,16)
/// \param pcn      combination of \ref PCN_

idaman size_t ida_export format_c_number(
        char *buf,
        size_t bufsize,
        uint128 value,
        int size,
        int pcn=0);

/// \defgroup PCN_ C Number formatting flags
/// passed as 'pcn' parameter to format_c_number()
//@{
#define PCN_RADIX    0x07 ///< number base to use
#define PCN_DEC      0x00 ///<   decimal
#define PCN_HEX      0x01 ///<   hexadecimal
#define PCN_OCT      0x02 ///<   octal
#define PCN_CHR      0x03 ///<   character
#define PCN_UNSIGNED 0x08 ///< add 'u' suffix
#define PCN_LZHEX    0x10 ///< print leading zeroes for hexdecimal number
#define PCN_NEGSIGN  0x20 ///< print negated value (-N) for negative numbers
#define PCN_DECSEXT  0x40 ///< automatically extend sign of signed decimal numbers
//@}


/// Return a C expression that can be used to represent an enum member.
/// If the value does not correspond to any single enum member, this function tries
/// to find a bitwise combination of enum members that correspond to it.
/// If more than half of value bits do not match any enum members, it fails.
/// \param buf      output buffer
/// \param tif      enumeration type
/// \param serial   which enumeration member to use (0 means the first with the given value)
/// \param value    value to search in the enumeration type. only 32-bit number can be handled yet
/// \return success

idaman bool ida_export get_enum_member_expr(
        qstring *buf,
        const tinfo_t &tif,
        int serial,
        uint64 value);

inline bool idaapi is_autosync(const char *name, const tinfo_t &tif)
{
  type_t decl_type = tif.get_decltype();
  return get_ordinal_from_idb_type(name, &decl_type) != -1;
}

//-------------------------------------------------------------------------
// Dialogs to choose a symbol from a type library
//------------------------------------------------------------------------

/// A symbol in a type library
struct til_symbol_t
{
  const char *name;         ///< symbol name
  const til_t *til;         ///< pointer to til
  til_symbol_t(const char *n = nullptr, const til_t *t = nullptr): name(n), til(t) {}
};
DECLARE_TYPE_AS_MOVABLE(til_symbol_t);


/// Helper class for choose_named_type().
/// Controls which types are displayed when choosing types.

struct predicate_t
{
  virtual bool idaapi should_display(
        const til_t *til,
        const char *name,
        const type_t *type,
        const p_list *fields) = 0;
  virtual ~predicate_t() {}
};


/// Choose a type from a type library.
/// \param out_sym    pointer to be filled with the chosen type
/// \param root_til   pointer to starting til (the function will inspect the base tils if allowed by flags)
/// \param title      title of listbox to display
/// \param ntf_flags  combination of \ref NTF_
/// \param predicate  predicate to select types to display (maybe nullptr)
/// \return false if nothing is chosen, otherwise true

idaman bool ida_export choose_named_type(
        til_symbol_t *out_sym,
        const til_t *root_til,
        const char *title,
        int ntf_flags,
        predicate_t *predicate=nullptr);


/// Controls which types are displayed/selected when choosing local types.
/// \retval 0  skip type
/// \retval 1  include

typedef int idaapi local_tinfo_predicate_t(uint32 ord, const tinfo_t &type, void *ud);


/// Choose a type from the local type library.
/// \param ti        pointer to til
/// \param title     title of listbox to display
/// \param func      predicate to select types to display (maybe nullptr)
/// \param def_ord   ordinal to position cursor before choose
/// \param ud        user data
/// \return == 0 means nothing is chosen, otherwise an ordinal number

idaman uint32 ida_export choose_local_tinfo(
        const til_t *ti,
        const char *title,
        local_tinfo_predicate_t *func = nullptr,
        uint32 def_ord = 0,
        void *ud = nullptr);


/// Choose a type from the local type library and specify the pointer shift value.
/// \param delta     pointer shift value
/// \param ti        pointer to til
/// \param title     title of listbox to display
/// \param func      predicate to select types to display (maybe nullptr)
/// \param def_ord   ordinal to position cursor before choose
/// \param ud        user data
/// \return == 0 means nothing is chosen, otherwise an ordinal number

idaman uint32 ida_export choose_local_tinfo_and_delta(
        int32 *delta,
        const til_t *ti,
        const char *title,
        local_tinfo_predicate_t *func = nullptr,
        uint32 def_ord = 0,
        void *ud = nullptr);

//-------------------------------------------------------------------------
inline ssize_t processor_t::equal_reglocs(const argloc_t &a1, const argloc_t &a2)
{
  if ( PH.ti() )
    return notify(ev_equal_reglocs, &a1, &a2);
  else
    return a1.compare(a2);
}

//-------------------------------------------------------------------------
inline ssize_t processor_t::decorate_name(qstring *outbuf, const char *name, bool mangle, cm_t cc, const tinfo_t &type)
{
  ssize_t code = notify(ev_decorate_name, outbuf, name, mangle, cc, &type);
  if ( code == 0 )
    code = gen_decorate_name(outbuf, name, mangle, cc, &type);
  return code;
}

//-------------------------------------------------------------------------
inline ssize_t processor_t::get_stkarg_area_info(stkarg_area_info_t *out, cm_t cc)
{
  return notify(ev_get_stkarg_area_info, out, get_effective_cc(cc));
}


#ifndef NO_OBSOLETE_FUNCS
typedef bool idaapi set_op_tinfo_t(const insn_t &insn, const op_t &x, const tinfo_t &type, const char *name);
typedef bool idaapi is_stkarg_load_t(const insn_t &insn, int *src, int *dst);
typedef bool idaapi has_delay_slot_t(ea_t caller);
idaman DEPRECATED void ida_export gen_use_arg_tinfos(ea_t caller, func_type_data_t *fti, funcargvec_t *rargs, set_op_tinfo_t *set_optype, is_stkarg_load_t *is_stkarg_load, has_delay_slot_t *has_delay_slot); // gen_use_arg_tinfos2
#endif

#endif // _TYPEINF_HPP
