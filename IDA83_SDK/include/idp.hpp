/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _IDP_HPP
#define _IDP_HPP

#include <fpro.h>
#include <ieee.h>
#include <nalt.hpp>
#include <segment.hpp>
#include <funcs.hpp>
#include <ua.hpp>
#include <bitrange.hpp>
#include <config.hpp>

/*! \file idp.hpp

  \brief Contains definition of the interface to IDP modules.

  The interface consists of two structures:
    - definition of target assembler: ::ash
    - definition of current processor: ::ph

  These structures contain information about target processor and assembler features.

  It also defines two groups of kernel events:
     - processor_t::event_t    processor related events
     - idb_event:event_code_t  database related events

  The processor related events are used to communicate with the processor module.
  The database related events are used to inform any interested parties, like
  plugins or processor modules, about the changes in the database.

*/

typedef int help_t; ///< message id from ida.hlp

struct outctx_t;
struct regval_t;
struct stkpnts_t;
struct simd_info_t;
struct reg_accesses_t;
struct call_stack_t;
struct stkarg_area_info_t;
class merge_data_t;

/// The interface version number.
/// \note see also #IDA_SDK_VERSION from pro.h

#define IDP_INTERFACE_VERSION 700

//-----------------------------------------------------------------------
/// Structure used to describe byte streams
/// (for "ret" instruction and empirics)
struct bytes_t
{
  uchar len;
  const uchar *bytes;
};

//-------------------------------------------------------------------------
/// \defgroup CF_ Instruction feature bits
/// Used by instruc_t::feature
//@{
#define CF_STOP 0x00001   ///< Instruction doesn't pass execution to the
                          ///< next instruction
#define CF_CALL 0x00002   ///< CALL instruction (should make a procedure here)
#define CF_CHG1 0x00004   ///< The instruction modifies the first operand
#define CF_CHG2 0x00008   ///< The instruction modifies the second operand
#define CF_CHG3 0x00010   ///< The instruction modifies the third operand
#define CF_CHG4 0x00020   ///< The instruction modifies the fourth operand
#define CF_CHG5 0x00040   ///< The instruction modifies the fifth operand
#define CF_CHG6 0x00080   ///< The instruction modifies the sixth operand
#define CF_USE1 0x00100   ///< The instruction uses value of the first operand
#define CF_USE2 0x00200   ///< The instruction uses value of the second operand
#define CF_USE3 0x00400   ///< The instruction uses value of the third operand
#define CF_USE4 0x00800   ///< The instruction uses value of the fourth operand
#define CF_USE5 0x01000   ///< The instruction uses value of the fifth operand
#define CF_USE6 0x02000   ///< The instruction uses value of the sixth operand
#define CF_JUMP 0x04000   ///< The instruction passes execution using indirect
                          ///< jump or call (thus needs additional analysis)
#define CF_SHFT 0x08000   ///< Bit-shift instruction (shl,shr...)
#define CF_HLL  0x10000   ///< Instruction may be present in a high level
                          ///< language function
#define CF_CHG7 0x020000  ///< The instruction modifies the seventh operand
#define CF_CHG8 0x040000  ///< The instruction modifies the eighth operand
#define CF_USE7 0x080000  ///< The instruction uses value of the seventh operand
#define CF_USE8 0x100000  ///< The instruction uses value of the eighth operand
//@}

//-----------------------------------------------------------------------
/// Internal representation of processor instructions.
/// Definition of all internal instructions are kept in special arrays.
/// One of such arrays describes instruction names and features.
struct instruc_t
{
  const char *name;       ///< instruction name
  uint32 feature;         ///< combination of \ref CF_
};


/// Does an instruction with the specified feature modify the i-th operand?

inline THREAD_SAFE bool has_cf_chg(uint32 feature, uint opnum)
{
  static const int bits[] =
  {
    CF_CHG1, CF_CHG2, CF_CHG3, CF_CHG4,
    CF_CHG5, CF_CHG6, CF_CHG7, CF_CHG8,
  };
  CASSERT(qnumber(bits) == UA_MAXOP);
  return opnum < UA_MAXOP && (feature & bits[opnum]) != 0;
}


/// Does an instruction with the specified feature use a value of the i-th operand?

inline THREAD_SAFE bool has_cf_use(uint32 feature, uint opnum)
{
  static const int bits[] =
  {
    CF_USE1, CF_USE2, CF_USE3, CF_USE4,
    CF_USE5, CF_USE6, CF_USE7, CF_USE8,
  };
  CASSERT(qnumber(bits) == UA_MAXOP);
  return opnum < UA_MAXOP && (feature & bits[opnum]) != 0;
}


/// Does the specified instruction have the specified feature?

idaman bool ida_export has_insn_feature(uint16 icode, uint32 bit);



/// Is the instruction a "call"?

idaman bool ida_export is_call_insn(const insn_t &insn);


/// Is the instruction a "return"?

idaman bool ida_export is_ret_insn(const insn_t &insn, bool strict=true);


/// Is the instruction an indirect jump?

idaman bool ida_export is_indirect_jump_insn(const insn_t &insn);


/// Is the instruction the end of a basic block?

idaman bool ida_export is_basic_block_end(const insn_t &insn, bool call_insn_stops_block);


//=====================================================================
/// Describes the target assembler.
/// An IDP module may have several target assemblers.
/// In this case you should create a structure for each supported
/// assembler.
struct asm_t
{
  uint32 flag;                          ///< \ref AS_
/// \defgroup AS_ Assembler feature bits
/// Used by asm_t::flag.
//@{
#define AS_OFFST      0x00000001L       ///< offsets are 'offset xxx' ?
#define AS_COLON      0x00000002L       ///< create colons after data names ?
#define AS_UDATA      0x00000004L       ///< can use '?' in data directives

#define AS_2CHRE      0x00000008L       ///< double char constants are: "xy
#define AS_NCHRE      0x00000010L       ///< char constants are: 'x
#define AS_N2CHR      0x00000020L       ///< can't have 2 byte char consts

                                        // String literals:
#define AS_1TEXT      0x00000040L       ///<   1 text per line, no bytes
#define AS_NHIAS      0x00000080L       ///<   no characters with high bit
#define AS_NCMAS      0x00000100L       ///<   no commas in ascii directives

#define AS_HEXFM      0x00000E00L       ///< mask - hex number format
#define ASH_HEXF0     0x00000000L       ///<   34h
#define ASH_HEXF1     0x00000200L       ///<   h'34
#define ASH_HEXF2     0x00000400L       ///<   34
#define ASH_HEXF3     0x00000600L       ///<   0x34
#define ASH_HEXF4     0x00000800L       ///<   $34
#define ASH_HEXF5     0x00000A00L       ///<   <^R   > (radix)
#define AS_DECFM      0x00003000L       ///< mask - decimal number format
#define ASD_DECF0     0x00000000L       ///<   34
#define ASD_DECF1     0x00001000L       ///<   #34
#define ASD_DECF2     0x00002000L       ///<   34.
#define ASD_DECF3     0x00003000L       ///<   .34
#define AS_OCTFM      0x0001C000L       ///< mask - octal number format
#define ASO_OCTF0     0x00000000L       ///<   123o
#define ASO_OCTF1     0x00004000L       ///<   0123
#define ASO_OCTF2     0x00008000L       ///<   123
#define ASO_OCTF3     0x0000C000L       ///<   @123
#define ASO_OCTF4     0x00010000L       ///<   o'123
#define ASO_OCTF5     0x00014000L       ///<   123q
#define ASO_OCTF6     0x00018000L       ///<   ~123
#define ASO_OCTF7     0x0001C000L       ///<   q'123
#define AS_BINFM      0x000E0000L       ///< mask - binary number format
#define ASB_BINF0     0x00000000L       ///<   010101b
#define ASB_BINF1     0x00020000L       ///<   ^B010101
#define ASB_BINF2     0x00040000L       ///<   %010101
#define ASB_BINF3     0x00060000L       ///<   0b1010101
#define ASB_BINF4     0x00080000L       ///<   b'1010101
#define ASB_BINF5     0x000A0000L       ///<   b'1010101'

#define AS_UNEQU      0x00100000L       ///< replace undefined data items with EQU (for ANTA's A80)
#define AS_ONEDUP     0x00200000L       ///< One array definition per line
#define AS_NOXRF      0x00400000L       ///< Disable xrefs during the output file generation
#define AS_XTRNTYPE   0x00800000L       ///< Assembler understands type of extern symbols as ":type" suffix
#define AS_RELSUP     0x01000000L       ///< Checkarg: 'and','or','xor' operations with addresses are possible
#define AS_LALIGN     0x02000000L       ///< Labels at "align" keyword are supported.
#define AS_NOCODECLN  0x04000000L       ///< don't create colons after code names
#define AS_NOSPACE    0x10000000L       ///< No spaces in expressions
#define AS_ALIGN2     0x20000000L       ///< .align directive expects an exponent rather than a power of 2
                                        ///< (.align 5 means to align at 32byte boundary)
#define AS_ASCIIC     0x40000000L       ///< ascii directive accepts C-like escape sequences
                                        ///< (\\n,\\x01 and similar)
#define AS_ASCIIZ     0x80000000L       ///< ascii directive inserts implicit zero byte at the end
//@}
  uint16 uflag;                         ///< user defined flags (local only for IDP)
                                        ///< you may define and use your own bits
  const char *name;                     ///< Assembler name (displayed in menus)
  help_t help;                          ///< Help screen number, 0 - no help
  const char *const *header;            ///< array of automatically generated header lines
                                        ///< they appear at the start of disassembled text
  const char *origin;                   ///< org directive
  const char *end;                      ///< end directive
  const char *cmnt;                     ///< comment string (see also cmnt2)
  char ascsep;                          ///< string literal delimiter
  char accsep;                          ///< char constant delimiter
  const char *esccodes;                 ///< special chars that cannot appear
                                        ///< as is in string and char literals

  // Data representation (db,dw,...):
  const char *a_ascii;                  ///< string literal directive
  const char *a_byte;                   ///< byte directive
  const char *a_word;                   ///< word directive
  const char *a_dword;                  ///< nullptr if not allowed
  const char *a_qword;                  ///< nullptr if not allowed
  const char *a_oword;                  ///< nullptr if not allowed
  const char *a_float;                  ///< float;  4bytes; nullptr if not allowed
  const char *a_double;                 ///< double; 8bytes; nullptr if not allowed
  const char *a_tbyte;                  ///< long double;    nullptr if not allowed
  const char *a_packreal;               ///< packed decimal real nullptr if not allowed
  const char *a_dups;                   ///< array keyword. the following
                                        ///< sequences may appear:
                                        ///<      - #h  header
                                        ///<      - #d  size
                                        ///<      - #v  value
                                        ///<      - #s(b,w,l,q,f,d,o)  size specifiers
                                        ///<                        for byte,word,
                                        ///<                            dword,qword,
                                        ///<                            float,double,oword
  const char *a_bss;                    ///< uninitialized data directive
                                        ///< should include '%s' for the
                                        ///< size of data
  const char *a_equ;                    ///< 'equ' Used if AS_UNEQU is set
  const char *a_seg;                    ///< 'seg ' prefix (example: push seg seg001)

  const char *a_curip;                  ///< current IP (instruction pointer) symbol in assembler

  /// Generate function header lines.
  /// If nullptr, then function headers are displayed as normal lines
  void (idaapi *out_func_header)(outctx_t &ctx, func_t *);

  /// Generate function footer lines.
  /// If nullptr, then a comment line is displayed
  void (idaapi *out_func_footer)(outctx_t &ctx, func_t *);

  const char *a_public;                 ///< "public" name keyword. nullptr-use default, ""-do not generate
  const char *a_weak;                   ///< "weak"   name keyword. nullptr-use default, ""-do not generate
  const char *a_extrn;                  ///< "extern" name keyword
  const char *a_comdef;                 ///< "comm" (communal variable)

  /// Get name of type of item at ea or id.
  /// (i.e. one of: byte,word,dword,near,far,etc...)
  ssize_t (idaapi *get_type_name)(
        qstring *buf,
        flags64_t flag,
        ea_t ea_or_id);

  const char *a_align;                  ///< "align" keyword

  char lbrace;                          ///< left brace used in complex expressions
  char rbrace;                          ///< right brace used in complex expressions

  const char *a_mod;                    ///< %  mod     assembler time operation
  const char *a_band;                   ///< &  bit and assembler time operation
  const char *a_bor;                    ///< |  bit or  assembler time operation
  const char *a_xor;                    ///< ^  bit xor assembler time operation
  const char *a_bnot;                   ///< ~  bit not assembler time operation
  const char *a_shl;                    ///< << shift left assembler time operation
  const char *a_shr;                    ///< >> shift right assembler time operation
  const char *a_sizeof_fmt;             ///< size of type (format string)

  uint32 flag2;                         ///< \ref AS2_
/// \defgroup AS2_ Secondary assembler feature bits
/// Used by asm_t::flag2
//@{
#define AS2_BRACE     0x00000001        ///< Use braces for all expressions
#define AS2_STRINV    0x00000002        ///< Invert meaning of \inf{wide_high_byte_first} for text strings
                                        ///< (for processors with bytes bigger than 8 bits)
#define AS2_BYTE1CHAR 0x00000004        ///< One symbol per processor byte.
                                        ///< Meaningful only for wide byte processors
#define AS2_IDEALDSCR 0x00000008        ///< Description of struc/union is in
                                        ///< the 'reverse' form (keyword before name),
                                        ///< the same as in borland tasm ideal
#define AS2_TERSESTR  0x00000010        ///< 'terse' structure initialization form;
                                        ///< NAME<fld,fld,...> is supported
#define AS2_COLONSUF  0x00000020        ///< addresses may have ":xx" suffix;
                                        ///< this suffix must be ignored when extracting
                                        ///< the address under the cursor
#define AS2_YWORD     0x00000040        ///< a_yword field is present and valid
#define AS2_ZWORD     0x00000080        ///< a_zword field is present and valid
//@}

  const char *cmnt2;                    ///< comment close string (usually nullptr)
                                        ///< this is used to denote a string which
                                        ///< closes comments, for example, if the
                                        ///< comments are represented with (* ... *)
                                        ///< then cmnt = "(*" and cmnt2 = "*)"
  const char *low8;                     ///< low8 operation, should contain %s for the operand
  const char *high8;                    ///< high8
  const char *low16;                    ///< low16
  const char *high16;                   ///< high16
  const char *a_include_fmt;            ///< the include directive (format string)
  const char *a_vstruc_fmt;             ///< if a named item is a structure and displayed
                                        ///< in the verbose (multiline) form then display the name
                                        ///< as printf(a_strucname_fmt, typename)
                                        ///< (for asms with type checking, e.g. tasm ideal)
  const char *a_rva;                    ///< 'rva' keyword for image based offsets
                                        ///< (see #REFINFO_RVAOFF)
  const char *a_yword;                  ///< 32-byte (256-bit) data; nullptr if not allowed
                                        ///< requires #AS2_YWORD
  const char *a_zword;                  ///< 64-byte (512-bit) data; nullptr if not allowed
                                        ///< requires #AS2_ZWORD
};
#ifndef __X86__
CASSERT(sizeof(asm_t) == 416);
#else
CASSERT(sizeof(asm_t) == 212);
#endif

// forward declarations for notification helpers
struct proc_def_t;
struct elf_loader_t;
class reader_t;
struct extlang_t;
class qflow_chart_t;
struct libfunc_t;
struct fixup_data_t;
struct idd_opinfo_t;
class argloc_t;
struct func_type_data_t;
struct regobjs_t;
class callregs_t;
struct funcarg_t;

//--------------------------------------------------------------------------
struct event_listener_t;

/// Install an event listener.
/// The installed listener will be called for all kernel events of the specified
/// type (\ref hook_type_t).
/// \param hook_type one of \ref hook_type_t constants
/// \param cb        The event listener object
/// \param owner     The listener owner. Points to an instance of: plugin_t,
///                  processor_t, or loader_t. Can be nullptr, which means
///                  undefined owner. The owner is used by the kernel for
///                  automatic removal of the event listener when the owner is
///                  unloaded from the memory.
/// \param hkcb_flags combination of \ref HKCB_ bits
/// \return success
idaman bool ida_export hook_event_listener(
        hook_type_t hook_type,
        event_listener_t *cb,
        const void *owner,
        int hkcb_flags=0);
/// \defgroup HKCB_ Hook installation bits.
//@{
#define HKCB_GLOBAL  0x0001 ///< is global event listener? if true, the listener
                            ///< will survive database closing and opening. it
                            ///< will stay in the memory until explicitly
                            ///< unhooked. otherwise the kernel will delete it
                            ///< as soon as the owner is unloaded.
                            ///< should be used only with PLUGIN_FIX plugins.
//@}

/// Uninstall an event listener.
/// \param hook_type one of \ref hook_type_t constants
/// \param cb        the listener object
/// \return success
/// A listener is uninstalled automatically when the owner module is unloaded
/// or when the listener object is being destroyed
idaman bool ida_export unhook_event_listener(
        hook_type_t hook_type,
        event_listener_t *cb);

/// remove all hooks in all databases for specified event_listener object
idaman void ida_export remove_event_listener(event_listener_t *cb);

struct event_listener_t
{
  size_t listener_flags = 0; // reserved
  /// Callback to handle events. The event code depends on the event
  /// group where the callback is attached to.
  virtual ssize_t idaapi on_event(ssize_t code, va_list va) = 0;
  virtual ~event_listener_t() { remove_event_listener(this); }
};

/// Declare listener with a context
#define DECLARE_LISTENER(listener_type, ctx_type, ctx_name)             \
  struct listener_type : public event_listener_t                        \
  {                                                                     \
    ctx_type &ctx_name;                                                 \
    listener_type(ctx_type &_ctx) : ctx_name(_ctx) {}                   \
    virtual ssize_t idaapi on_event(ssize_t code, va_list va) override; \
  }

//-------------------------------------------------------------------------
/// \defgroup PLFM_ Processor IDs
/// Used by processor_t::id.
/// Numbers above 0x8000 are reserved for the third-party modules
//@{
#define PLFM_386        0         ///< Intel 80x86
#define PLFM_Z80        1         ///< 8085, Z80
#define PLFM_I860       2         ///< Intel 860
#define PLFM_8051       3         ///< 8051
#define PLFM_TMS        4         ///< Texas Instruments TMS320C5x
#define PLFM_6502       5         ///< 6502
#define PLFM_PDP        6         ///< PDP11
#define PLFM_68K        7         ///< Motorola 680x0
#define PLFM_JAVA       8         ///< Java
#define PLFM_6800       9         ///< Motorola 68xx
#define PLFM_ST7        10        ///< SGS-Thomson ST7
#define PLFM_MC6812     11        ///< Motorola 68HC12
#define PLFM_MIPS       12        ///< MIPS
#define PLFM_ARM        13        ///< Advanced RISC Machines
#define PLFM_TMSC6      14        ///< Texas Instruments TMS320C6x
#define PLFM_PPC        15        ///< PowerPC
#define PLFM_80196      16        ///< Intel 80196
#define PLFM_Z8         17        ///< Z8
#define PLFM_SH         18        ///< Renesas (formerly Hitachi) SuperH
#define PLFM_NET        19        ///< Microsoft Visual Studio.Net
#define PLFM_AVR        20        ///< Atmel 8-bit RISC processor(s)
#define PLFM_H8         21        ///< Hitachi H8/300, H8/2000
#define PLFM_PIC        22        ///< Microchip's PIC
#define PLFM_SPARC      23        ///< SPARC
#define PLFM_ALPHA      24        ///< DEC Alpha
#define PLFM_HPPA       25        ///< Hewlett-Packard PA-RISC
#define PLFM_H8500      26        ///< Hitachi H8/500
#define PLFM_TRICORE    27        ///< Tasking Tricore
#define PLFM_DSP56K     28        ///< Motorola DSP5600x
#define PLFM_C166       29        ///< Siemens C166 family
#define PLFM_ST20       30        ///< SGS-Thomson ST20
#define PLFM_IA64       31        ///< Intel Itanium IA64
#define PLFM_I960       32        ///< Intel 960
#define PLFM_F2MC       33        ///< Fujistu F2MC-16
#define PLFM_TMS320C54  34        ///< Texas Instruments TMS320C54xx
#define PLFM_TMS320C55  35        ///< Texas Instruments TMS320C55xx
#define PLFM_TRIMEDIA   36        ///< Trimedia
#define PLFM_M32R       37        ///< Mitsubishi 32bit RISC
#define PLFM_NEC_78K0   38        ///< NEC 78K0
#define PLFM_NEC_78K0S  39        ///< NEC 78K0S
#define PLFM_M740       40        ///< Mitsubishi 8bit
#define PLFM_M7700      41        ///< Mitsubishi 16bit
#define PLFM_ST9        42        ///< ST9+
#define PLFM_FR         43        ///< Fujitsu FR Family
#define PLFM_MC6816     44        ///< Motorola 68HC16
#define PLFM_M7900      45        ///< Mitsubishi 7900
#define PLFM_TMS320C3   46        ///< Texas Instruments TMS320C3
#define PLFM_KR1878     47        ///< Angstrem KR1878
#define PLFM_AD218X     48        ///< Analog Devices ADSP 218X
#define PLFM_OAKDSP     49        ///< Atmel OAK DSP
#define PLFM_TLCS900    50        ///< Toshiba TLCS-900
#define PLFM_C39        51        ///< Rockwell C39
#define PLFM_CR16       52        ///< NSC CR16
#define PLFM_MN102L00   53        ///< Panasonic MN10200
#define PLFM_TMS320C1X  54        ///< Texas Instruments TMS320C1x
#define PLFM_NEC_V850X  55        ///< NEC V850 and V850ES/E1/E2
#define PLFM_SCR_ADPT   56        ///< Processor module adapter for processor modules written in scripting languages
#define PLFM_EBC        57        ///< EFI Bytecode
#define PLFM_MSP430     58        ///< Texas Instruments MSP430
#define PLFM_SPU        59        ///< Cell Broadband Engine Synergistic Processor Unit
#define PLFM_DALVIK     60        ///< Android Dalvik Virtual Machine
#define PLFM_65C816     61        ///< 65802/65816
#define PLFM_M16C       62        ///< Renesas M16C
#define PLFM_ARC        63        ///< Argonaut RISC Core
#define PLFM_UNSP       64        ///< SunPlus unSP
#define PLFM_TMS320C28  65        ///< Texas Instruments TMS320C28x
#define PLFM_DSP96K     66        ///< Motorola DSP96000
#define PLFM_SPC700     67        ///< Sony SPC700
#define PLFM_AD2106X    68        ///< Analog Devices ADSP 2106X
#define PLFM_PIC16      69        ///< Microchip's 16-bit PIC
#define PLFM_S390       70        ///< IBM's S390
#define PLFM_XTENSA     71        ///< Tensilica Xtensa
#define PLFM_RISCV      72        ///< RISC-V
#define PLFM_RL78       73        ///< Renesas RL78
#define PLFM_RX         74        ///< Renesas RX
//@}

//-------------------------------------------------------------------------
/// \defgroup PR_ Processor feature bits
/// Used by processor_t::flag
//@{
#define PR_SEGS       0x000001    ///< has segment registers?
#define PR_USE32      0x000002    ///< supports 32-bit addressing?
#define PR_DEFSEG32   0x000004    ///< segments are 32-bit by default
#define PR_RNAMESOK   0x000008    ///< allow user register names for location names
//#define PR_DB2CSEG    0x0010    // .byte directive in code segments
//                                // should define even number of bytes
//                                // (used by AVR processor)
#define PR_ADJSEGS    0x000020    ///< IDA may adjust segments' starting/ending addresses.
#define PR_DEFNUM     0x0000C0    ///< mask - default number representation
#define PRN_HEX       0x000000    ///<      hex
#define PRN_OCT       0x000040    ///<      octal
#define PRN_DEC       0x000080    ///<      decimal
#define PRN_BIN       0x0000C0    ///<      binary
#define PR_WORD_INS   0x000100    ///< instruction codes are grouped 2bytes in binary line prefix
#define PR_NOCHANGE   0x000200    ///< The user can't change segments and code/data attributes
                                  ///< (display only)
#define PR_ASSEMBLE   0x000400    ///< Module has a built-in assembler and will react to ev_assemble
#define PR_ALIGN      0x000800    ///< All data items should be aligned properly
#define PR_TYPEINFO   0x001000    ///< the processor module fully supports type information callbacks;
                                  ///< without full support, function argument locations and other things
                                  ///< will probably be wrong.
#define PR_USE64      0x002000    ///< supports 64-bit addressing?
#define PR_SGROTHER   0x004000    ///< the segment registers don't contain the segment selectors.
#define PR_STACK_UP   0x008000    ///< the stack grows up
#define PR_BINMEM     0x010000    ///< the processor module provides correct segmentation for binary files
                                  ///< (i.e.\ it creates additional segments).
                                  ///< The kernel will not ask the user to specify the RAM/ROM sizes
#define PR_SEGTRANS   0x020000    ///< the processor module supports the segment translation feature
                                  ///< (meaning it calculates the code
                                  ///< addresses using the map_code_ea() function)
#define PR_CHK_XREF   0x040000    ///< don't allow near xrefs between segments with different bases
#define PR_NO_SEGMOVE 0x080000    ///< the processor module doesn't support move_segm()
                                  ///< (i.e. the user can't move segments)
//#define PR_FULL_HIFXP 0x100000  // ::REF_VHIGH operand value contains full operand
//                                // (not only the high bits) Meaningful if \ph{high_fixup_bits}
#define PR_USE_ARG_TYPES 0x200000 ///< use \ph{use_arg_types} callback
#define PR_SCALE_STKVARS 0x400000 ///< use \ph{get_stkvar_scale} callback
#define PR_DELAYED    0x800000    ///< has delayed jumps and calls.
                                  ///< If this flag is set, \ph{is_basic_block_end}, \ph{delay_slot_insn}
                                  ///< should be implemented
#define PR_ALIGN_INSN 0x1000000   ///< allow ida to create alignment instructions arbitrarily.
                                  ///< Since these instructions might lead to other wrong instructions
                                  ///< and spoil the listing, IDA does not create them by default anymore
#define PR_PURGING    0x2000000   ///< there are calling conventions which may purge bytes from the stack
#define PR_CNDINSNS   0x4000000   ///< has conditional instructions
#define PR_USE_TBYTE  0x8000000   ///< ::BTMT_SPECFLT means _TBYTE type
#define PR_DEFSEG64  0x10000000   ///< segments are 64-bit by default
#define PR_OUTER     0x20000000   ///< has outer operands (currently only mc68k)
//@}

//-------------------------------------------------------------------------
/// \defgroup PR2_ Processor additional feature bits
/// Used by processor_t::flag2
//@{
#define PR2_MAPPINGS   0x000001   ///< the processor module uses memory mapping
#define PR2_IDP_OPTS   0x000002   ///< the module has processor-specific configuration options
#define PR2_REALCVT    0x000004   ///< the module has a custom 'ev_realcvt' implementation (otherwise IEEE-754 format is assumed)
#define PR2_CODE16_BIT 0x000008   ///< low bit of code addresses has special meaning
                                  ///< e.g. ARM Thumb, MIPS16
#define PR2_MACRO       0x000010  ///< processor supports macro instructions
#define PR2_USE_CALCREL 0x000020  ///< (Lumina) the module supports calcrel info
#define PR2_REL_BITS    0x000040  ///< (Lumina) calcrel info has bits granularity, not bytes - construction flag only
#define PR2_FORCE_16BIT 0x000080  ///< use 16-bit basic types despite of 32-bit segments (used by c166)
//@}

//-------------------------------------------------------------------------
/// \defgroup OP_FP_SP SP/FP operand flags
/// Return values for processor_t::is_sp_based()
//@{
#define OP_FP_BASED  0x00000000 ///< operand is FP based
#define OP_SP_BASED  0x00000001 ///< operand is SP based
#define OP_SP_ADD    0x00000000 ///< operand value is added to the pointer
#define OP_SP_SUB    0x00000002 ///< operand value is subtracted from the pointer
//@}

//-------------------------------------------------------------------------
/// Custom instruction codes defined by processor extension plugins
/// must be greater than or equal to this
#define CUSTOM_INSN_ITYPE 0x8000

//-------------------------------------------------------------------------
/// processor_t::use_regarg_type uses this bit in the return value
/// to indicate that the register value has been spoiled
#define REG_SPOIL 0x80000000L

//=====================================================================
/// Describes a processor module (IDP).
/// An IDP file may have only one such structure called LPH.
/// The kernel will copy it to ::ph structure and use ::ph.
struct processor_t
{
  int32 version;                  ///< Expected kernel version,
                                  ///<   should be #IDP_INTERFACE_VERSION
  int32 id;                       ///< one of \ref PLFM_
  uint32 flag;                    ///< an ORed combination of \ref PR_
  uint32 flag2;                   ///< an ORed combination of \ref PR2_

  bool has_idp_opts(void) const { return (flag2 & PR2_IDP_OPTS)       != 0; }  ///< #PR_IDP_OPTS
  bool has_realcvt(void) const  { return (flag2 & PR2_REALCVT)        != 0; }  ///< #PR_REALCVT
  bool has_segregs(void) const  { return (flag & PR_SEGS)             != 0; }  ///< #PR_SEGS
  bool use32(void) const        { return (flag & (PR_USE64|PR_USE32)) != 0; }  ///< #PR_USE64 or #PR_USE32
  bool use64(void) const        { return (flag & PR_USE64)            != 0; }  ///< #PR_USE64
  bool ti(void) const           { return (flag & PR_TYPEINFO)         != 0; }  ///< #PR_TYPEINFO
  bool stkup(void) const        { return (flag & PR_STACK_UP)         != 0; }  ///< #PR_STACK_UP
  bool use_tbyte(void) const    { return (flag & PR_USE_TBYTE)        != 0; }  ///< #PR_USE_TBYTE
  bool use_mappings(void) const { return (flag2 & PR2_MAPPINGS)       != 0; }  ///< #PR2_MAPPINGS
  bool has_code16_bit(void) const { return (flag2 & PR2_CODE16_BIT)   != 0; }  ///< #PR2_CODE16_BIT
  bool supports_macros(void) const { return (flag2 & PR2_MACRO)       != 0; }  ///< #PR2_MACRO
  bool supports_calcrel(void) const { return (flag2 & PR2_USE_CALCREL) != 0; } ///< #PR2_USE_CALCREL
  bool calcrel_in_bits(void)  const { return (flag2 & PR2_REL_BITS)    != 0; } ///< #PR2_REL_BITS

  /// Get default segment bitness
  /// \retval 2  #PR_DEFSEG64
  /// \retval 1  #PR_DEFSEG32
  /// \retval 0  none specified

  int get_default_segm_bitness(bool is_64bit_app) const
  {
    return is_64bit_app && (flag & PR_DEFSEG64) != 0 ? 2 : (flag & PR_DEFSEG32) != 0;
  }

  int32 cnbits;                   ///< Number of bits in a byte
                                  ///< for code segments (usually 8).
                                  ///< IDA supports values up to supported
                                  ///< address bits size
  int32 dnbits;                   ///< Number of bits in a byte
                                  ///< for non-code segments (usually 8).
                                  ///< IDA supports values up to supported
                                  ///< address bit size

  /// \name Byte size
  /// Number of 8bit bytes required to hold one byte of the target processor.
  //@{
  int cbsize(void) { return (cnbits+7)/8; }  ///< for code segments
  int dbsize(void) { return (dnbits+7)/8; }  ///< for non-code segments
  //@}

  /// \name Names
  /// IDP module may support several compatible processors.
  /// The following arrays define processor names:
  //@{
  const char *const *psnames;     ///< short processor names (nullptr terminated).
                                  ///< Each name should be shorter than 9 characters
  const char *const *plnames;     ///< long processor names (nullptr terminated).
                                  ///< No restriction on name lengths.
  //@}

  inline int get_proc_index();  ///< \retval currently selected processor subtype (index into psnames/plnames)

  const asm_t *const *assemblers; ///< pointer to array of target
                                            ///< assembler definitions. You may
                                            ///< change this array when current
                                            ///< processor is changed.
                                            ///< (nullptr terminated)

  typedef const regval_t &(idaapi regval_getter_t)(
        const char *name,
        const regval_t *regvalues);

  //<hookgen IDP>

  /// Callback notification codes.
  ///
  /// These are passed to notify() when certain events occur in the kernel,
  /// allowing the processor module to take the appropriate action.
  ///
  /// If you are not developing a processor module, you do not need to
  /// use the codes directly many of them already have a corresponding function
  /// to use instead (\idpcode{is_call_insn} vs is_call_insn(ea_t), for example).
  ///
  /// If you are developing a processor module, your notify() function
  /// must implement the desired behavior when called with a given code.
  /// Not all events need to be handled, some of them are optional.
  enum event_t
  {
    ev_init,                    ///< The IDP module is just loaded.
                                ///< \param idp_modname  (const char *) processor module name
                                ///< \retval <0 on failure

    ev_term,                    ///< The IDP module is being unloaded

    ev_newprc,                  ///< Before changing processor type.
                                ///< \param pnum  (int) processor number in the array of processor names
                                ///< \param keep_cfg (bool) true: do not modify kernel configuration
                                ///< \retval 1  ok
                                ///< \retval <0  prohibit

    ev_newasm,                  ///< Before setting a new assembler.
                                ///< \param asmnum  (int)
                                ///< See also ev_asm_installed

    ev_newfile,                 ///< A new file has been loaded.
                                ///< \param fname  (char *) input file name

    ev_oldfile,                 ///< An old file has been loaded.
                                ///< \param fname  (char *) input file name

    ev_newbinary,               ///< IDA is about to load a binary file.
                                ///< \param filename  (char *)   binary file name
                                ///< \param fileoff   (::qoff64_t) offset in the file
                                ///< \param basepara  (::ea_t)   base loading paragraph
                                ///< \param binoff    (::ea_t)   loader offset
                                ///< \param nbytes    (::uint64) number of bytes to load

    ev_endbinary,               ///< IDA has loaded a binary file.
                                ///< \param ok  (bool) file loaded successfully?

    ev_set_idp_options,         ///< Set IDP-specific configuration option
                                ///< Also see set_options_t in config.hpp
                                ///< \param keyword     (const char *)
                                ///< \param value_type  (int)
                                ///< \param value       (const void *)
                                ///< \param errbuf      (const char **) - a error message will be returned here (can be nullptr)
                                ///< \param idb_loaded  (bool) true if the ev_oldfile/ev_newfile events have been generated
                                ///< \retval  1  ok
                                ///< \retval  0  not implemented
                                ///< \retval -1  error (and message in errbuf)

    ev_set_proc_options,        ///< Called if the user specified an option string in the command line:
                                ///<  -p<processor name>:<options>.
                                ///< Can be used for setting a processor subtype.
                                ///< Also called if option string is passed to set_processor_type()
                                ///< and IDC's SetProcessorType().
                                ///< \param options     (const char *)
                                ///< \param confidence  (int)
                                ///<          0: loader's suggestion
                                ///<          1: user's decision
                                ///< \retval <0 if bad option string

    ev_ana_insn,                ///< Analyze one instruction and fill 'out' structure.
                                ///< This function shouldn't change the database, flags or anything else.
                                ///< All these actions should be performed only by emu_insn() function.
                                ///< \insn_t{ea} contains address of instruction to analyze.
                                ///< \param out           (::insn_t *)
                                ///< \return length of the instruction in bytes, 0 if instruction can't be decoded.
                                ///< \retval 0 if instruction can't be decoded.

    ev_emu_insn,                ///< Emulate instruction, create cross-references, plan to analyze
                                ///< subsequent instructions, modify flags etc. Upon entrance to this function,
                                ///< all information about the instruction is in 'insn' structure.
                                ///< \param insn          (const ::insn_t *)
                                ///< \retval  1 ok
                                ///< \retval -1 the kernel will delete the instruction

    ev_out_header,              ///< Function to produce start of disassembled text
                                ///< \param outctx        (::outctx_t *)
                                ///< \retval void

    ev_out_footer,              ///< Function to produce end of disassembled text
                                ///< \param outctx        (::outctx_t *)
                                ///< \retval void

    ev_out_segstart,            ///< Function to produce start of segment
                                ///< \param outctx        (::outctx_t *)
                                ///< \param seg           (::segment_t *)
                                ///< \retval 1 ok
                                ///< \retval 0 not implemented

    ev_out_segend,              ///< Function to produce end of segment
                                ///< \param outctx        (::outctx_t *)
                                ///< \param seg           (::segment_t *)
                                ///< \retval 1 ok
                                ///< \retval 0 not implemented

    ev_out_assumes,             ///< Function to produce assume directives
                                ///< when segment register value changes.
                                ///< \param outctx        (::outctx_t *)
                                ///< \retval 1 ok
                                ///< \retval 0 not implemented

    ev_out_insn,                ///< Generate text representation of an instruction in 'ctx.insn'
                                ///< outctx_t provides functions to output the generated text.
                                ///< This function shouldn't change the database, flags or anything else.
                                ///< All these actions should be performed only by emu_insn() function.
                                ///< \param outctx        (::outctx_t *)
                                ///< \retval void

    ev_out_mnem,                ///< Generate instruction mnemonics.
                                ///< This callback should append the colored mnemonics to ctx.outbuf
                                ///< Optional notification, if absent, out_mnem will be called.
                                ///< \param outctx        (::outctx_t *)
                                ///< \retval 1 if appended the mnemonics
                                ///< \retval 0 not implemented

    ev_out_operand,             ///< Generate text representation of an instruction operand
                                ///< outctx_t provides functions to output the generated text.
                                ///< All these actions should be performed only by emu_insn() function.
                                ///< \param outctx        (::outctx_t *)
                                ///< \param op            (const ::op_t *)
                                ///< \retval  1 ok
                                ///< \retval -1 operand is hidden

    ev_out_data,                ///< Generate text representation of data items
                                ///< This function may change the database and create cross-references
                                ///< if analyze_only is set
                                ///< \param outctx        (::outctx_t *)
                                ///< \param analyze_only  (bool)
                                ///< \retval 1 ok
                                ///< \retval 0 not implemented

    ev_out_label,               ///< The kernel is going to generate an instruction
                                ///< label line or a function header.
                                ///< \param outctx        (::outctx_t *)
                                ///< \param colored_name  (const char *)
                                ///< \retval <0 if the kernel should not generate the label
                                ///< \retval 0 not implemented or continue

    ev_out_special_item,        ///< Generate text representation of an item in a special segment
                                ///< i.e. absolute symbols, externs, communal definitions etc
                                ///< \param outctx  (::outctx_t *)
                                ///< \param segtype (uchar)
                                ///< \retval  1  ok
                                ///< \retval  0  not implemented
                                ///< \retval -1  overflow

    ev_gen_stkvar_def,          ///< Generate stack variable definition line
                                ///< Default line is
                                ///<             varname = type ptr value,
                                ///< where 'type' is one of byte,word,dword,qword,tbyte
                                ///< \param outctx   (::outctx_t *)
                                ///< \param mptr     (const ::member_t *)
                                ///< \param v        (sval_t)
                                ///< \retval 1 ok
                                ///< \retval 0 not implemented

    ev_gen_regvar_def,          ///< Generate register variable definition line.
                                ///< \param outctx  (::outctx_t *)
                                ///< \param v       (::regvar_t *)
                                ///< \retval >0  ok, generated the definition text
                                ///< \retval 0 not implemented

    ev_gen_src_file_lnnum,      ///< Callback: generate analog of:
                                ///< \code
                                ///< #line "file.c" 123
                                ///< \endcode
                                ///< directive.
                                ///< \param outctx  (::outctx_t *) output context
                                ///< \param file    (const char *) source file (may be nullptr)
                                ///< \param lnnum   (size_t) line number
                                ///< \retval 1 directive has been generated
                                ///< \retval 0 not implemented

    ev_creating_segm,           ///< A new segment is about to be created.
                                ///< \param seg  (::segment_t *)
                                ///< \retval 1  ok
                                ///< \retval <0  segment should not be created

    ev_moving_segm,             ///< May the kernel move the segment?
                                ///< \param seg    (::segment_t *) segment to move
                                ///< \param to     (::ea_t) new segment start address
                                ///< \param flags  (int) combination of \ref MSF_
                                ///< \retval 0   yes
                                ///< \retval <0  the kernel should stop

    ev_coagulate,               ///< Try to define some unexplored bytes.
                                ///< This notification will be called if the
                                ///< kernel tried all possibilities and could
                                ///< not find anything more useful than to
                                ///< convert to array of bytes.
                                ///< The module can help the kernel and convert
                                ///< the bytes into something more useful.
                                ///< \param start_ea  (::ea_t)
                                ///< \return number of converted bytes

    ev_undefine,                ///< An item in the database (insn or data) is being deleted.
                                ///< \param ea  (ea_t)
                                ///< \retval 1 do not delete srranges at the item end
                                ///< \retval 0 srranges can be deleted

    ev_treat_hindering_item,    ///< An item hinders creation of another item.
                                ///< \param hindering_item_ea  (::ea_t)
                                ///< \param new_item_flags     (::flags64_t)  (0 for code)
                                ///< \param new_item_ea        (::ea_t)
                                ///< \param new_item_length    (::asize_t)
                                ///< \retval 0   no reaction
                                ///< \retval !=0 the kernel may delete the hindering item

    ev_rename,                  ///< The kernel is going to rename a byte.
                                ///< \param ea       (::ea_t)
                                ///< \param new_name (const char *)
                                ///< \param flags    (int) \ref SN_
                                ///< \retval <0 if the kernel should not rename it.
                                ///< \retval 2 to inhibit the notification. I.e.,
                                ///<           the kernel should not rename, but
                                ///<           'set_name()' should return 'true'.
                                ///<         also see \idpcode{renamed}
                                ///< the return value is ignored when kernel is going to delete name

    ev_is_far_jump,             ///< is indirect far jump or call instruction?
                                ///< meaningful only if the processor has 'near' and 'far' reference types
                                ///< \param icode (int)
                                ///< \retval  0  not implemented
                                ///< \retval  1  yes
                                ///< \retval -1  no

    ev_is_sane_insn,            ///< Is the instruction sane for the current file type?.
                                ///< \param insn      (const ::insn_t*) the instruction
                                ///< \param no_crefs  (int)
                                ///<   1: the instruction has no code refs to it.
                                ///<      ida just tries to convert unexplored bytes
                                ///<      to an instruction (but there is no other
                                ///<      reason to convert them into an instruction)
                                ///<   0: the instruction is created because
                                ///<      of some coderef, user request or another
                                ///<      weighty reason.
                                ///< \retval >=0  ok
                                ///< \retval <0   no, the instruction isn't
                                ///<              likely to appear in the program

    ev_is_cond_insn,            ///< Is conditional instruction?
                                ///< \param insn (const ::insn_t *)    instruction address
                                ///< \retval  1 yes
                                ///< \retval -1 no
                                ///< \retval  0 not implemented or not instruction

    ev_is_call_insn,            ///< Is the instruction a "call"?
                                ///< \param insn (const ::insn_t *) instruction
                                ///< \retval 0  unknown
                                ///< \retval <0 no
                                ///< \retval 1  yes

    ev_is_ret_insn,             ///< Is the instruction a "return"?
                                ///< \param insn    (const ::insn_t *) instruction
                                ///< \param strict  (bool)
                                ///<          1: report only ret instructions
                                ///<          0: include instructions like "leave"
                                ///<             which begins the function epilog
                                ///< \retval 0  unknown
                                ///< \retval <0 no
                                ///< \retval 1  yes

    ev_may_be_func,             ///< Can a function start here?
                                ///< \param insn  (const ::insn_t*) the instruction
                                ///< \param state (int)  autoanalysis phase
                                ///<   0: creating functions
                                ///<   1: creating chunks
                                ///< \return probability 1..100
                                ///< \note Actually IDA uses 3 intervals of a probability:
                                ///<   0..50  not a function,
                                ///<   51..99 a function (IDA needs another proof),
                                ///<   100    a function (no other proofs needed)

    ev_is_basic_block_end,      ///< Is the current instruction end of a basic block?.
                                ///< This function should be defined for processors
                                ///< with delayed jump slots.
                                ///< \param insn                   (const ::insn_t*) the instruction
                                ///< \param call_insn_stops_block  (bool)
                                ///< \retval  0  unknown
                                ///< \retval <0  no
                                ///< \retval  1  yes

    ev_is_indirect_jump,        ///< Determine if instruction is an indirect jump.
                                ///< If #CF_JUMP bit cannot describe all jump types
                                ///< jumps, please define this callback.
                                ///< \param insn (const ::insn_t*) the instruction
                                ///< \retval 0  use #CF_JUMP
                                ///< \retval 1  no
                                ///< \retval 2  yes

    ev_is_insn_table_jump,      ///< Reserved

    ev_is_switch,               ///< Find 'switch' idiom or override processor module's decision.
                                ///< It will be called for instructions marked with #CF_JUMP.
                                ///< \param si   (switch_info_t *), out
                                ///< \param insn (const ::insn_t *) instruction possibly belonging to a switch
                                ///< \retval  1 switch is found, 'si' is filled.
                                ///<            IDA will create the switch using the filled 'si'
                                ///< \retval -1 no switch found.
                                ///<            This value forbids switch creation by the processor module
                                ///< \retval  0 not implemented

    ev_calc_switch_cases,       ///< Calculate case values and targets for a custom jump table.
                                ///< \param casevec  (::casevec_t *) vector of case values (may be nullptr)
                                ///< \param targets  (::eavec_t *) corresponding target addresses (my be nullptr)
                                ///< \param insn_ea  (::ea_t) address of the 'indirect jump' instruction
                                ///< \param si       (::switch_info_t *) switch information
                                ///< \retval 1    ok
                                ///< \retval <=0  failed

    ev_create_switch_xrefs,     ///< Create xrefs for a custom jump table.
                                ///< \param jumpea   (::ea_t) address of the jump insn
                                ///< \param si       (const ::switch_info_t *) switch information
                                ///< \return must return 1
                                ///< Must be implemented if module uses custom jump tables, \ref SWI_CUSTOM

    ev_is_align_insn,           ///< Is the instruction created only for alignment purposes?.
                                ///< Do not directly call this function, use ::is_align_insn()
                                ///< \param ea (ea_t) - instruction address
                                ///< \retval number of bytes in the instruction

    ev_is_alloca_probe,         ///< Does the function at 'ea' behave as __alloca_probe?
                                ///< \param ea  (::ea_t)
                                ///< \retval 1  yes
                                ///< \retval 0  no

    ev_delay_slot_insn,         ///< Get delay slot instruction
                                ///< \param ea    (::ea_t *) in: instruction address in question,
                                ///<                         out: (if the answer is positive)
                                ///<                           if the delay slot contains valid insn:
                                ///<                             the address of the delay slot insn
                                ///<                           else:
                                ///<                             BADADDR (invalid insn, e.g. a branch)
                                ///< \param bexec (bool *)   execute slot if jumping,
                                ///<                         initially set to 'true'
                                ///< \param fexec (bool *)   execute slot if not jumping,
                                ///<                         initally set to 'true'
                                ///< \retval 1   positive answer
                                ///< \retval <=0 ordinary insn
                                ///< \note Input EA may point to the instruction with a delay slot or
                                ///<       to the delay slot instruction itself.

    ev_is_sp_based,             ///< Check whether the operand is relative to stack pointer or frame pointer
                                ///< This event is used to determine how to output a stack variable
                                ///< If not implemented, then all operands are sp based by default.
                                ///< Implement this event only if some stack references use frame pointer
                                ///< instead of stack pointer.
                                ///< \param mode  (int *) out, combination of \ref OP_FP_SP
                                ///< \param insn  (const insn_t *)
                                ///< \param op    (const op_t *)
                                ///< \retval 0  not implemented
                                ///< \retval 1  ok

    ev_can_have_type,           ///< Can the operand have a type as offset, segment, decimal, etc?
                                ///< (for example, a register AX can't have a type, meaning that the user can't
                                ///< change its representation. see bytes.hpp for information about types and flags)
                                ///< \param op    (const ::op_t *)
                                ///< \retval 0  unknown
                                ///< \retval <0 no
                                ///< \retval 1  yes

    ev_cmp_operands,            ///< Compare instruction operands
                                ///< \param op1      (const ::op_t*)
                                ///< \param op2      (const ::op_t*)
                                ///< \retval  1  equal
                                ///< \retval -1  not equal
                                ///< \retval  0  not implemented

    ev_adjust_refinfo,          ///< Called from apply_fixup before converting operand to reference.
                                ///< Can be used for changing the reference info.
                                ///< (e.g. the PPC module adds REFINFO_NOBASE for some references)
                                ///< \param ri      (refinfo_t *)
                                ///< \param ea      (::ea_t) instruction address
                                ///< \param n       (int) operand number
                                ///< \param fd      (const fixup_data_t *)
                                ///< \retval <0 do not create an offset
                                ///< \retval 0  not implemented or refinfo adjusted

    ev_get_operand_string,      ///< Request text string for operand (cli, java, ...).
                                ///< \param buf    (qstring *)
                                ///< \param insn   (const ::insn_t*) the instruction
                                ///< \param opnum  (int) operand number, -1 means any string operand
                                ///< \retval  0  no string (or empty string)
                                ///< \retval >0  original string length without terminating zero

    ev_get_reg_name,            ///< Generate text representation of a register.
                                ///< Most processor modules do not need to implement this callback.
                                ///< It is useful only if \ph{reg_names}[reg] does not provide
                                ///< the correct register name.
                                ///< \param buf     (qstring *) output buffer
                                ///< \param reg     (int) internal register number as defined in the processor module
                                ///< \param width   (size_t) register width in bytes
                                ///< \param reghi   (int) if not -1 then this function will return the register pair
                                ///< \retval -1 if error
                                ///< \retval strlen(buf) if success

    ev_str2reg,                 ///< Convert a register name to a register number.
                                ///< The register number is the register index in the \ph{reg_names} array
                                ///< Most processor modules do not need to implement this callback
                                ///< It is useful only if \ph{reg_names}[reg] does not provide
                                ///< the correct register names
                                ///< \param regname  (const char *)
                                ///< \retval register number + 1
                                ///< \retval 0 not implemented or could not be decoded

    ev_get_autocmt,             ///< Callback: get dynamic auto comment.
                                ///< Will be called if the autocomments are enabled
                                ///< and the comment retrieved from ida.int starts with
                                ///< '$!'. 'insn' contains valid info.
                                ///< \param buf     (qstring *) output buffer
                                ///< \param insn    (const ::insn_t*) the instruction
                                ///< \retval 1  new comment has been generated
                                ///< \retval 0  callback has not been handled.
                                ///<            the buffer must not be changed in this case

    ev_get_bg_color,            ///< Get item background color.
                                ///< Plugins can hook this callback to color disassembly lines dynamically
                                ///< \param color  (::bgcolor_t *), out
                                ///< \param ea     (::ea_t)
                                ///< \retval 0  not implemented
                                ///< \retval 1  color set

    ev_is_jump_func,            ///< Is the function a trivial "jump" function?.
                                ///< \param pfn           (::func_t *)
                                ///< \param jump_target   (::ea_t *)
                                ///< \param func_pointer  (::ea_t *)
                                ///< \retval <0  no
                                ///< \retval 0  don't know
                                ///< \retval 1  yes, see 'jump_target' and 'func_pointer'

    ev_func_bounds,             ///< find_func_bounds() finished its work.
                                ///< The module may fine tune the function bounds
                                ///< \param possible_return_code  (int *), in/out
                                ///< \param pfn                   (::func_t *)
                                ///< \param max_func_end_ea       (::ea_t) (from the kernel's point of view)
                                ///< \retval void

    ev_verify_sp,               ///< All function instructions have been analyzed.
                                ///< Now the processor module can analyze the stack pointer
                                ///< for the whole function
                                ///< \param pfn  (::func_t *)
                                ///< \retval 0  ok
                                ///< \retval <0 bad stack pointer

    ev_verify_noreturn,         ///< The kernel wants to set 'noreturn' flags for a function.
                                ///< \param pfn  (::func_t *)
                                ///< \retval 0: ok. any other value: do not set 'noreturn' flag

    ev_create_func_frame,       ///< Create a function frame for a newly created function
                                ///< Set up frame size, its attributes etc
                                ///< \param pfn      (::func_t *)
                                ///< \retval  1  ok
                                ///< \retval  0  not implemented

    ev_get_frame_retsize,       ///< Get size of function return address in bytes
                                ///< If this event is not implemented, the kernel will assume
                                ///<  - 8 bytes for 64-bit function
                                ///<  - 4 bytes for 32-bit function
                                ///<  - 2 bytes otherwise
                                ///< \param frsize   (int *) frame size (out)
                                ///< \param pfn      (const ::func_t *), can't be nullptr
                                ///< \retval  1  ok
                                ///< \retval  0  not implemented

    ev_get_stkvar_scale_factor, ///< Should stack variable references be multiplied by
                                ///< a coefficient before being used in the stack frame?.
                                ///< Currently used by TMS320C55 because the references into
                                ///< the stack should be multiplied by 2
                                ///< \return scaling factor
                                ///< \retval 0 not implemented
                                ///< \note #PR_SCALE_STKVARS should be set to use this callback

    ev_demangle_name,           ///< Demangle a C++ (or another language) name into a user-readable string.
                                ///< This event is called by ::demangle_name()
                                ///< \param res     (int32 *) value to return from ::demangle_name()
                                ///< \param out     (::qstring *) output buffer. may be nullptr
                                ///< \param name    (const char *) mangled name
                                ///< \param disable_mask  (uint32) flags to inhibit parts of output or compiler info/other (see MNG_)
                                ///< \param demreq  (demreq_type_t) operation to perform
                                ///< \retval 1 if success
                                ///< \retval 0 not implemented
                                ///< \note if you call ::demangle_name() from the handler, protect against recursion!

    // the following 5 events are very low level
    // take care of possible recursion
    ev_add_cref,                ///< A code reference is being created.
                                ///< \param from  (::ea_t)
                                ///< \param to    (::ea_t)
                                ///< \param type  (::cref_t)
                                ///< \retval <0 cancel cref creation
                                ///< \retval 0 not implemented or continue

    ev_add_dref,                ///< A data reference is being created.
                                ///< \param from  (::ea_t)
                                ///< \param to    (::ea_t)
                                ///< \param type  (::dref_t)
                                ///< \retval <0 cancel dref creation
                                ///< \retval 0 not implemented or continue

    ev_del_cref,                ///< A code reference is being deleted.
                                ///< \param from    (::ea_t)
                                ///< \param to      (::ea_t)
                                ///< \param expand  (bool)
                                ///< \retval <0 cancel cref deletion
                                ///< \retval 0 not implemented or continue

    ev_del_dref,                ///< A data reference is being deleted.
                                ///< \param from    (::ea_t)
                                ///< \param to      (::ea_t)
                                ///< \retval <0 cancel dref deletion
                                ///< \retval 0 not implemented or continue

    ev_coagulate_dref,          ///< Data reference is being analyzed.
                                ///< plugin may correct 'code_ea' (e.g. for thumb mode refs, we clear the last bit)
                                ///< \param from        (::ea_t)
                                ///< \param to          (::ea_t)
                                ///< \param may_define  (bool)
                                ///< \param code_ea     (::ea_t *)
                                ///< \retval <0 failed dref analysis, >0 done dref analysis
                                ///< \retval 0 not implemented or continue

    ev_may_show_sreg,           ///< The kernel wants to display the segment registers
                                ///< in the messages window.
                                ///< \param current_ea  (::ea_t)
                                ///< \retval <0 if the kernel should not show the segment registers.
                                ///< (assuming that the module has done it)
                                ///< \retval 0 not implemented

    ev_loader_elf_machine,      ///< ELF loader machine type checkpoint.
                                ///< A plugin check of the 'machine_type'. If it is the desired one,
                                ///< the the plugin fills 'p_procname' with the processor name
                                ///< (one of the names present in \ph{psnames}).
                                ///< 'p_pd' is used to handle relocations, otherwise can be left untouched.
                                ///< This event occurs for each newly loaded ELF file
                                ///< \param li            (linput_t *)
                                ///< \param machine_type  (int)
                                ///< \param p_procname    (const char **)
                                ///< \param p_pd          (proc_def_t **) (see ldr\elf.h)
                                ///< \param loader        (elf_loader_t *) (see ldr\elf.h)
                                ///< \param reader        (reader_t *) (see ldr\elf.h)
                                ///< \retval  e_machine value (if it is different from the
                                ///<          original e_machine value, procname and 'p_pd' will be ignored
                                ///<          and the new value will be used)
                                ///< before replacing pd it is a good idea to delete the previous instance
                                ///< using 'delete pd;'
                                ///< The 'loader' and 'reader' arguments are available starting from IDA v7.7.

    ev_auto_queue_empty,        ///< One analysis queue is empty.
                                ///< \param type  (::atype_t)
                                ///< \retval void
                                ///< see also \ref idb_event::auto_empty_finally

    ev_validate_flirt_func,     ///< Flirt has recognized a library function.
                                ///< This callback can be used by a plugin or proc module
                                ///< to intercept it and validate such a function.
                                ///< \param start_ea  (::ea_t)
                                ///< \param funcname  (const char *)
                                ///< \retval -1  do not create a function,
                                ///< \retval  0  function is validated

    ev_adjust_libfunc_ea,       ///< Called when a signature module has been matched against
                                ///< bytes in the database. This is used to compute the
                                ///< offset at which a particular module's libfunc should
                                ///< be applied.
                                ///< \param sig     (const idasgn_t *)
                                ///< \param libfun  (const libfunc_t *)
                                ///< \param ea      (::ea_t *) \note 'ea' initially contains the ea_t of the
                                ///<                                 start of the pattern match
                                ///< \retval 1   the ea_t pointed to by the third argument was modified.
                                ///< \retval <=0 not modified. use default algorithm.

    ev_assemble,                ///< Assemble an instruction.
                                ///< (display a warning if an error is found).
                                ///< \param bin    (::uchar *) pointer to output opcode buffer
                                ///< \param ea     (::ea_t) linear address of instruction
                                ///< \param cs     (::ea_t) cs of instruction
                                ///< \param ip     (::ea_t) ip of instruction
                                ///< \param use32  (bool) is 32bit segment?
                                ///< \param line   (const char *) line to assemble
                                ///< \return size of the instruction in bytes

    ev_extract_address,         ///< Extract address from a string.
                                ///< \param  out_ea    (ea_t *), out
                                ///< \param  screen_ea (ea_t)
                                ///< \param  string    (const char *)
                                ///< \param  position  (size_t)
                                ///< \retval  1 ok
                                ///< \retval  0 kernel should use the standard algorithm
                                ///< \retval -1 error

    ev_realcvt,                 ///< Floating point -> IEEE conversion
                                ///< \param m    (void *)      ptr to processor-specific floating point value
                                ///< \param e    (fpvalue_t *) IDA representation of a floating point value
                                ///< \param swt  (uint16)      operation (see realcvt() in ieee.h)
                                ///< \retval  0  not implemented
                                ///< \retval  1  ok
                                ///< \retval  \ref REAL_ERROR_ on error

    ev_gen_asm_or_lst,          ///< Callback: generating asm or lst file.
                                ///< The kernel calls this callback twice, at the beginning
                                ///< and at the end of listing generation. The processor
                                ///< module can intercept this event and adjust its output
                                ///< \param starting  (bool) beginning listing generation
                                ///< \param fp        (FILE *) output file
                                ///< \param is_asm    (bool) true:assembler, false:listing
                                ///< \param flags     (int) flags passed to gen_file()
                                ///< \param outline   (html_line_cb_t **) ptr to ptr to outline callback.
                                ///<                  if this callback is defined for this code, it will be
                                ///<                  used by the kernel to output the generated lines
                                ///< \retval void

    ev_gen_map_file,            ///< Generate map file. If not implemented
                                ///< the kernel itself will create the map file.
                                ///< \param nlines (int *) number of lines in map file (-1 means write error)
                                ///< \param fp     (FILE *) output file
                                ///< \retval  0  not implemented
                                ///< \retval  1  ok
                                ///< \retval -1  write error

    ev_create_flat_group,       ///< Create special segment representing the flat group.
                                ///< \param image_base  (::ea_t)
                                ///< \param bitness     (int)
                                ///< \param dataseg_sel (::sel_t)
                                ///< return value is ignored

    ev_getreg,                  ///< IBM PC only internal request,
                                ///< should never be used for other purpose
                                ///< Get register value by internal index
                                ///< \param regval   (uval_t *), out
                                ///< \param regnum   (int)
                                ///< \retval  1 ok
                                ///< \retval  0 not implemented
                                ///< \retval -1 failed (undefined value or bad regnum)

    ev_analyze_prolog,          ///< Analyzes function prolog, epilog, and updates
                                ///< purge, and function attributes
                                ///< \param ea (::ea_t) start of function
                                ///< \retval  1  ok
                                ///< \retval  0  not implemented

    ev_calc_spdelta,            ///< Calculate amount of change to sp for the given insn.
                                ///< This event is required to decompile code snippets.
                                ///< \param spdelta (::sval_t *)
                                ///< \param insn (const ::insn_t *)
                                ///< \retval  1  ok
                                ///< \retval  0  not implemented

    ev_calcrel,                 ///< Reserved
    ev_find_reg_value,          ///< Find register value via a register tracker.
                                ///< The returned value in 'out' is valid
                                ///< before executing the instruction.
                                ///< \param out     (uval_t *) pointer to the found value
                                ///< \param pinsn   (const ::insn_t *) instruction
                                ///< \param reg     (int) register index
                                ///< \retval 1 if implemented, and value was found
                                ///< \retval 0 not implemented, -1 decoding failed, or no value found

    ev_find_op_value,           ///< Find operand value via a register tracker.
                                ///< The returned value in 'out' is valid
                                ///< before executing the instruction.
                                ///< \param out     (uval_t *) pointer to the found value
                                ///< \param pinsn   (const ::insn_t *) instruction
                                ///< \param opn     (int) operand index
                                ///< \retval 1 if implemented, and value was found
                                ///< \retval 0 not implemented, -1 decoding failed, or no value found

    ev_replaying_undo,          ///< Replaying an undo/redo buffer
                                ///< \param action_name (const char *) action that we perform undo/redo for. may be nullptr for intermediary buffers.
                                ///< \param vec     (const undo_records_t *)
                                ///< \param is_undo (bool) true if performing undo, false if performing redo
                                ///< This event may be generated multiple times per undo/redo
    ev_ending_undo,             ///< Ended undoing/redoing an action
                                ///< \param action_name (const char *) action that we finished undoing/redoing. is not nullptr.
                                ///< \param is_undo (bool) true if performing undo, false if performing redo

    ev_set_code16_mode,         ///< Some processors have ISA 16-bit mode
                                ///< e.g. ARM Thumb mode, PPC VLE, MIPS16
                                ///< Set ISA 16-bit mode
                                ///< \param ea (ea_t) address to set new ISA mode
                                ///< \param code16 (bool) true for 16-bit mode, false for 32-bit mode
    ev_get_code16_mode,         ///< Get ISA 16-bit mode
                                ///< \param ea (ea_t) address to get the ISA mode
                                ///< \retval 1 16-bit mode
                                ///< \retval 0 not implemented or 32-bit mode

    ev_get_procmod,             ///< Get pointer to the processor module object.
                                ///< All processor modules must implement this.
                                ///< The pointer is returned as size_t.

    ev_asm_installed,           ///< After setting a new assembler
                                ///< \param asmnum  (int)
                                ///< See also ev_newasm

    ev_get_reg_accesses,        ///< Get info about the registers that are used/changed by an instruction.
                                ///< \param accvec (::reg_accesses_t*) out: info about accessed registers
                                ///< \param insn   (const ::insn_t *) instruction in question
                                ///< \param flags  (int) reserved, must be 0
                                ///< \retval -1 if accvec is nullptr
                                ///< \retval 1 found the requested access (and filled accvec)
                                ///< \retval 0 not implemented

    ev_is_control_flow_guard,   ///< Detect if an instruction is a "thunk call" to a flow guard function (equivalent to call reg/return/nop)
                                ///< \param p_reg (int *) indirect register number, may be -1
                                ///< \param insn  (const ::insn_t *) call/jump instruction
                                ///< \retval -1 no thunk detected
                                ///< \retval 1 indirect call
                                ///< \retval 2 security check routine call (NOP)
                                ///< \retval 3 return thunk
                                ///< \retval 0 not implemented

    ev_broadcast,               ///< Broadcast call
                                ///< \param magic (::int64) a magic number
                                ///< Other parameters and the return value depend on the magic

    ev_create_merge_handlers,   ///< Create merge handlers, if needed
                                ///< \param md (::merge_data_t *)
                                ///< This event is generated immediately after
                                ///< opening idbs.
                                ///< \return must be 0

    ev_privrange_changed,       ///< Privrange interval has been moved to
                                ///< a new location. Most common actions
                                ///< to be done by module in this case:
                                ///< fix indices of netnodes used by module
                                ///< \param old_privrange (const ::range_t *) - old privrange interval
                                ///< \param delta (::adiff_t)
                                ///< \param errbuf (::qstring *) - a error message will be returned here (can be nullptr)
                                ///< \return 0 Ok
                                ///< \return -1 error (and message in errbuf)


    ev_cvt64_supval,            ///< perform 32-64 conversion for a netnode array element
                                ///< \param node   (::nodeidx_t)
                                ///< \param tag    (::uchar)
                                ///< \param idx    (::nodeidx_t)
                                ///< \param data   (const ::uchar *)
                                ///< \param datlen (::size_t)
                                ///< \param errbuf (::qstring *) - a error message will be returned here (can be nullptr)
                                ///< \return 0 nothing was done
                                ///< \return 1 converted successfully
                                ///< \return -1 error (and message in errbuf)

    ev_cvt64_hashval,           ///< perform 32-64 conversion for a hash value
                                ///< \param node   (::nodeidx_t)
                                ///< \param tag    (::uchar)
                                ///< \param name   (const ::char *)
                                ///< \param data   (const ::uchar *)
                                ///< \param datlen (::size_t)
                                ///< \param errbuf (::qstring *) - a error message will be returned here (can be nullptr)
                                ///< \return 0 nothing was done
                                ///< \return 1 converted successfully
                                ///< \return -1 error (and message in errbuf)

    ev_last_cb_before_debugger, ///< START OF DEBUGGER CALLBACKS

    ev_next_exec_insn = 1000,   ///< Get next address to be executed
                                ///< This function must return the next address to be executed.
                                ///< If the instruction following the current one is executed, then it must return #BADADDR
                                ///< Usually the instructions to consider are: jumps, branches, calls, returns.
                                ///< This function is essential if the 'single step' is not supported in hardware.
                                ///< \param target     (::ea_t *), out: pointer to the answer
                                ///< \param ea         (::ea_t) instruction address
                                ///< \param tid        (int) current therad id
                                ///< \param getreg     (::processor_t::regval_getter_t *) function to get register values
                                ///< \param regvalues  (const ::regval_t *) register values array
                                ///< \retval 0 unimplemented
                                ///< \retval 1 implemented

    ev_calc_step_over,          ///< Calculate the address of the instruction which will be
                                ///< executed after "step over". The kernel will put a breakpoint there.
                                ///< If the step over is equal to step into or we cannot calculate
                                ///< the address, return #BADADDR.
                                ///< \param target  (::ea_t *) pointer to the answer
                                ///< \param ip      (::ea_t) instruction address
                                ///< \retval 0 unimplemented
                                ///< \retval 1 implemented

    ev_calc_next_eas,           ///< Calculate list of addresses the instruction in 'insn'
                                ///< may pass control to.
                                ///< This callback is required for source level debugging.
                                ///< \param res       (::eavec_t *), out: array for the results.
                                ///< \param insn      (const ::insn_t*) the instruction
                                ///< \param over      (bool) calculate for step over (ignore call targets)
                                ///< \retval  <0 incalculable (indirect jumps, for example)
                                ///< \retval >=0 number of addresses of called functions in the array.
                                ///<             They must be put at the beginning of the array (0 if over=true)

    ev_get_macro_insn_head,     ///< Calculate the start of a macro instruction.
                                ///< This notification is called if IP points to the middle of an instruction
                                ///< \param head  (::ea_t *), out: answer, #BADADDR means normal instruction
                                ///< \param ip    (::ea_t) instruction address
                                ///< \retval 0 unimplemented
                                ///< \retval 1 implemented

    ev_get_dbr_opnum,           ///< Get the number of the operand to be displayed in the
                                ///< debugger reference view (text mode).
                                ///< \param opnum  (int *) operand number (out, -1 means no such operand)
                                ///< \param insn   (const ::insn_t*) the instruction
                                ///< \retval 0 unimplemented
                                ///< \retval 1 implemented

    ev_insn_reads_tbit,         ///< Check if insn will read the TF bit.
                                ///< \param insn       (const ::insn_t*) the instruction
                                ///< \param getreg     (::processor_t::regval_getter_t *) function to get register values
                                ///< \param regvalues  (const ::regval_t *) register values array
                                ///< \retval 2  yes, will generate 'step' exception
                                ///< \retval 1  yes, will store the TF bit in memory
                                ///< \retval 0  no

    ev_clean_tbit,              ///< Clear the TF bit after an insn like pushf stored it in memory.
                                ///< \param ea  (::ea_t) instruction address
                                ///< \param getreg     (::processor_t::regval_getter_t *) function to get register values
                                ///< \param regvalues  (const ::regval_t *) register values array
                                ///< \retval 1  ok
                                ///< \retval 0  failed

    ev_get_idd_opinfo,          ///< Get operand information.
                                ///< This callback is used to calculate the operand
                                ///< value for double clicking on it, hints, etc.
                                ///< \param opinf      (::idd_opinfo_t *) the output buffer
                                ///< \param ea         (::ea_t) instruction address
                                ///< \param n          (int) operand number
                                ///< \param thread_id  (int) current thread id
                                ///< \param getreg     (::processor_t::regval_getter_t *) function to get register values
                                ///< \param regvalues  (const ::regval_t *) register values array
                                ///< \retval 1 ok
                                ///< \retval 0 failed

    ev_get_reg_info,            ///< Get register information by its name.
                                ///< example: "ah" returns:
                                ///<   - main_regname="eax"
                                ///<   - bitrange_t = { offset==8, nbits==8 }
                                ///<
                                ///< This callback may be unimplemented if the register
                                ///< names are all present in \ph{reg_names} and they all have
                                ///< the same size
                                ///< \param main_regname  (const char **), out
                                ///< \param bitrange      (::bitrange_t *), out: position and size of the value within 'main_regname' (empty bitrange == whole register)
                                ///< \param regname       (const char *)
                                ///< \retval  1  ok
                                ///< \retval -1  failed (not found)
                                ///< \retval  0  unimplemented

    ev_update_call_stack,       ///< Calculate the call stack trace for the given thread.
                                ///< This callback is invoked when the process is suspended and should fill
                                ///< the 'trace' object with the information about the current call stack.
                                ///< Note that this callback is NOT invoked if the current debugger backend
                                ///< implements stack tracing via debugger_t::event_t::ev_update_call_stack.
                                ///< The debugger-specific algorithm takes priority. Implementing this callback
                                ///< in the processor module is useful when multiple debugging platforms follow
                                ///< similar patterns, and thus the same processor-specific algorithm can be
                                ///< used for different platforms.
                                ///< \param stack      (::call_stack_t *) result
                                ///< \param tid        (int) thread id
                                ///< \param getreg     (::processor_t::regval_getter_t *) function to get register values
                                ///< \param regvalues  (const ::regval_t *) register values array
                                ///< \retval  1  ok
                                ///< \retval -1  failed
                                ///< \retval  0  unimplemented

    // END OF DEBUGGER CALLBACKS

    // START OF TYPEINFO CALLBACKS TODO: get this into doxygen output
    // The codes below will be called only if #PR_TYPEINFO is set.
    // Please note that some codes are optional but the more codes
    // are implemented, the better the analysis.

    ev_last_cb_before_type_callbacks,

    ev_setup_til = 2000,        ///< Setup default type libraries. (called after loading
                                ///< a new file into the database).
                                ///< The processor module may load tils, setup memory
                                ///< model and perform other actions required to set up
                                ///< the type system.
                                ///< This is an optional callback.
                                ///< \param none
                                ///< \retval void

    ev_get_abi_info,            ///< Get all possible ABI names and optional extensions for given compiler
                                ///< abiname/option is a string entirely consisting of letters, digits and underscore
                                ///< \param abi_names (qstrvec_t *) - all possible ABis each in form abiname-opt1-opt2-...
                                ///< \param abi_opts  (qstrvec_t *) - array of all possible options in form "opt:description" or opt:hint-line#description
                                ///< \param comp      (comp_t) - compiler ID
                                ///< \retval 0 not implemented
                                ///< \retval 1 ok

    ev_max_ptr_size,            ///< Get maximal size of a pointer in bytes.
                                ///< \param none
                                ///< \return max possible size of a pointer

    ev_get_default_enum_size,   ///< Get default enum size. Not generated anymore.
                                ///< inf_get_cc_size_e() is used instead

    ev_get_cc_regs,             ///< Get register allocation convention for given calling convention
                                ///< \param regs  (::callregs_t *), out
                                ///< \param cc    (::cm_t)
                                ///< \retval 1
                                ///< \retval 0 not implemented

    ev_obsolete1,               ///< ev_get_stkarg_offset is obsolete.
                                ///< See ev_get_stkarg_area_info

    ev_obsolete2,               ///< ev_shadow_args_size is obsolete.
                                ///< See ev_get_stkarg_area_info

    ev_get_simd_types,          ///< Get SIMD-related types according to given attributes ant/or argument location
                                ///< \param out (::simd_info_vec_t *)
                                ///< \param simd_attrs (const ::simd_info_t *), may be nullptr
                                ///< \param argloc (const ::argloc_t *), may be nullptr
                                ///< \param create_tifs (bool) return valid tinfo_t objects, create if neccessary
                                ///< \retval number of found types
                                ///< \retval -1 error
                                ///< If name==nullptr, initialize all SIMD types

    ev_calc_cdecl_purged_bytes,
                                ///< Calculate number of purged bytes after call.
                                ///< \param ea  (::ea_t) address of the call instruction
                                ///< \return number of purged bytes (usually add sp, N)

    ev_calc_purged_bytes,       ///< Calculate number of purged bytes by the given function type.
                                ///< \param[out] p_purged_bytes  (int *) ptr to output
                                ///< \param fti                  (const ::func_type_data_t *) func type details
                                ///< \retval 1
                                ///< \retval 0 not implemented

    ev_calc_retloc,             ///< Calculate return value location.
                                ///< \param[out] retloc  (::argloc_t *)
                                ///< \param rettype      (const tinfo_t *)
                                ///< \param cc           (::cm_t)
                                ///< \retval  0  not implemented
                                ///< \retval  1  ok,
                                ///< \retval -1  error

    ev_calc_arglocs,            ///< Calculate function argument locations.
                                ///< This callback should fill retloc, all arglocs, and stkargs.
                                ///< This callback is never called for ::CM_CC_SPECIAL functions.
                                ///< \param fti  (::func_type_data_t *) points to the func type info
                                ///< \retval  0  not implemented
                                ///< \retval  1  ok
                                ///< \retval -1  error

    ev_calc_varglocs,           ///< Calculate locations of the arguments that correspond to '...'.
                                ///< \param ftd              (::func_type_data_t *), inout: info about all arguments (including varargs)
                                ///< \param[out] aux_regs    (::regobjs_t *) buffer for hidden register arguments, may be nullptr
                                ///< \param[out] aux_stkargs (::relobj_t *) buffer for hidden stack arguments, may be nullptr
                                ///< \param nfixed   (int) number of fixed arguments
                                ///< \retval  0  not implemented
                                ///< \retval  1  ok
                                ///< \retval -1  error
                                ///< On some platforms variadic calls require
                                ///< passing additional information: for example,
                                ///< number of floating variadic arguments must
                                ///< be passed in rax on gcc-x64. The locations
                                ///< and values that constitute this additional
                                ///< information are returned in the buffers
                                ///< pointed by aux_regs and aux_stkargs

    ev_adjust_argloc,           ///< Adjust argloc according to its type/size
                                ///< and platform endianess
                                ///< \param argloc  (argloc_t *), inout
                                ///< \param type    (const tinfo_t *), may be nullptr
                                ///<   nullptr means primitive type of given size
                                ///< \param size    (int)
                                ///<   'size' makes no sense if type != nullptr
                                ///<   (type->get_size() should be used instead)
                                ///< \retval  0  not implemented
                                ///< \retval  1  ok
                                ///< \retval -1  error

    ev_lower_func_type,         ///< Get function arguments which should be converted to pointers when lowering function prototype.
                                ///< The processor module can also modify 'fti' in order to make non-standard conversion
                                ///< of some arguments.
                                ///< \param argnums (intvec_t *), out - numbers of arguments to be converted to pointers in acsending order
                                ///< \param fti     (::func_type_data_t *), inout func type details
                                ///< (special values -1/-2 for return value - position of hidden 'retstr' argument: -1 - at the beginning, -2 - at the end)
                                ///< \retval 0 not implemented
                                ///< \retval 1 argnums was filled
                                ///< \retval 2 argnums was filled and made substantial changes to fti

    ev_equal_reglocs,           ///< Are 2 register arglocs the same?.
                                ///< We need this callback for the pc module.
                                ///< \param a1  (::argloc_t *)
                                ///< \param a2  (::argloc_t *)
                                ///< \retval  1  yes
                                ///< \retval -1  no
                                ///< \retval  0  not implemented

    ev_use_stkarg_type,         ///< Use information about a stack argument.
                                ///< \param ea  (::ea_t) address of the push instruction which
                                ///<                     pushes the function argument into the stack
                                ///< \param arg  (const ::funcarg_t *) argument info
                                ///< \retval 1   ok
                                ///< \retval <=0 failed, the kernel will create a comment with the
                                ///<             argument name or type for the instruction

    ev_use_regarg_type,         ///< Use information about register argument.
                                ///< \param[out] idx (int *) pointer to the returned value, may contain:
                                ///<                         - idx of the used argument, if the argument is defined
                                ///<                           in the current instruction, a comment will be applied by the kernel
                                ///<                         - idx | #REG_SPOIL - argument is spoiled by the instruction
                                ///<                         - -1 if the instruction doesn't change any registers
                                ///<                         - -2 if the instruction spoils all registers
                                ///< \param ea       (::ea_t) address of the instruction
                                ///< \param rargs    (const ::funcargvec_t *) vector of register arguments
                                ///<                               (including regs extracted from scattered arguments)
                                ///< \retval 1
                                ///< \retval 0  not implemented

    ev_use_arg_types,           ///< Use information about callee arguments.
                                ///< \param ea     (::ea_t) address of the call instruction
                                ///< \param fti    (::func_type_data_t *) info about function type
                                ///< \param rargs  (::funcargvec_t *) array of register arguments
                                ///< \retval 1 (and removes handled arguments from fti and rargs)
                                ///< \retval 0  not implemented

    ev_arg_addrs_ready,         ///< Argument address info is ready.
                                ///< \param caller  (::ea_t)
                                ///< \param n       (int) number of formal arguments
                                ///< \param tif     (tinfo_t *) call prototype
                                ///< \param addrs   (::ea_t *) argument intilization addresses
                                ///< \retval <0 do not save into idb; other values mean "ok to save"

    ev_decorate_name,           ///< Decorate/undecorate a C symbol name.
                                ///< \param outbuf  (::qstring *) output buffer
                                ///< \param name    (const char *) name of symbol
                                ///< \param mangle  (bool) true-mangle, false-unmangle
                                ///< \param cc      (::cm_t) calling convention
                                ///< \param type    (const ::tinfo_t *) name type (nullptr-unknown)
                                ///< \retval 1 if success
                                ///< \retval 0 not implemented or failed

    ev_arch_changed,            ///< The loader is done parsing arch-related
                                ///< information, which the processor module
                                ///< might want to use to finish its
                                ///< initialization.
                                ///< \retval 1 if success
                                ///< \retval 0 not implemented or failed

    ev_get_stkarg_area_info,    ///< Get some metrics of the stack argument area.
                                ///< \param[out] out (::stkarg_area_info_t *) ptr to stkarg_area_info_t
                                ///< \param cc       (::cm_t) calling convention
                                ///< \retval 1 if success
                                ///< \retval 0 not implemented

    ev_last_cb_before_loader,

    // END OF TYPEINFO CALLBACKS

    ev_loader=3000,             ///< This code and higher ones are reserved
                                ///< for the loaders.
                                ///< The arguments and the return values are
                                ///< defined by the loaders
  };

  /// Event notification handler
  hook_cb_t *_notify;
  static ssize_t notify(event_t event_code, ...)
  {
    va_list va;
    va_start(va, event_code);
    ssize_t code = invoke_callbacks(HT_IDP, event_code, va);
    va_end(va);
    return code;
  }

  // Notification helpers, should be used instead of direct ph.notify(...) calls
  inline static ssize_t init(const char *idp_modname);
  inline static ssize_t term();
  inline static ssize_t newprc(int pnum, bool keep_cfg);
  inline static ssize_t newasm(int asmnum);
  inline static ssize_t asm_installed(int asmnum);
  inline static ssize_t newfile(const char *fname);
  inline static ssize_t oldfile(const char *fname);
  inline static ssize_t newbinary(const char *filename, qoff64_t fileoff, ea_t basepara, ea_t binoff, uint64 nbytes);
  inline static ssize_t endbinary(bool ok);
  inline static ssize_t creating_segm(segment_t *seg);
  inline static ssize_t assemble(uchar *_bin, ea_t ea, ea_t cs, ea_t ip, bool _use32, const char *line);
  inline static ssize_t ana_insn(insn_t *out);
  inline static ssize_t emu_insn(const insn_t &insn);
  inline static ssize_t out_header(outctx_t &ctx);
  inline static ssize_t out_footer(outctx_t &ctx);
  inline static ssize_t out_segstart(outctx_t &ctx, segment_t *seg);
  inline static ssize_t out_segend(outctx_t &ctx, segment_t *seg);
  inline static ssize_t out_assumes(outctx_t &ctx);
  inline static ssize_t out_insn(outctx_t &ctx);
  inline static ssize_t out_mnem(outctx_t &ctx);
  inline static ssize_t out_operand(outctx_t &ctx, const op_t &op);
  inline static ssize_t out_data(outctx_t &ctx, bool analyze_only);
  inline static ssize_t out_label(outctx_t &ctx, const char *colored_name);
  inline static ssize_t out_special_item(outctx_t &ctx, uchar segtype);
  inline static ssize_t gen_stkvar_def(outctx_t &ctx, const class member_t *mptr, sval_t v);
  inline static ssize_t gen_regvar_def(outctx_t &ctx, regvar_t *v);
  inline static ssize_t gen_src_file_lnnum(outctx_t &ctx, const char *file, size_t lnnum);
  inline static ssize_t rename(ea_t ea, const char *new_name, int flags);
  inline static ssize_t may_show_sreg(ea_t current_ea);
  inline static ssize_t coagulate(ea_t start_ea);
  inline static void auto_queue_empty(/*atype_t*/ int type);

  inline static ssize_t func_bounds(int *possible_return_code, func_t *pfn, ea_t max_func_end_ea);
  inline static ssize_t may_be_func(const insn_t &insn, int state);
  inline static ssize_t is_sane_insn(const insn_t &insn, int no_crefs);
  inline static ssize_t cmp_operands(const op_t &op1, const op_t &op2);
  inline static ssize_t is_jump_func(func_t *pfn, ea_t *jump_target, ea_t *func_pointer);
  inline static ssize_t is_basic_block_end(const insn_t &insn, bool call_insn_stops_block);
  inline static ssize_t getreg(uval_t *rv, int regnum);
  inline static ssize_t undefine(ea_t ea);
  inline static ssize_t moving_segm(segment_t *seg, ea_t to, int flags);
  inline static ssize_t is_sp_based(const insn_t &insn, const op_t &x);
  inline static ssize_t is_far_jump(int icode);
  inline static ssize_t is_call_insn(const insn_t &insn);
  inline static ssize_t is_ret_insn(const insn_t &insn, bool strict);
  inline static ssize_t is_align_insn(ea_t ea);
  inline static ssize_t can_have_type(const op_t &op);
  inline static ssize_t get_stkvar_scale_factor();
  inline static ssize_t demangle_name(int32 *res, qstring *out, const char *name, uint32 disable_mask, /*demreq_type_t*/ int demreq);
  inline static ssize_t create_flat_group(ea_t image_base, int bitness, sel_t dataseg_sel);
  inline static ssize_t is_alloca_probe(ea_t ea);
  inline static ssize_t get_reg_name(qstring *buf, int reg, size_t width, int reghi);
  inline static ssize_t gen_asm_or_lst(bool starting, FILE *fp, bool is_asm, int flags, /*html_line_cb_t ** */ void *outline);
  inline static ssize_t gen_map_file(int *nlines, FILE *fp);
  inline static ssize_t get_autocmt(qstring *buf, const insn_t &insn);
  inline static ssize_t loader_elf_machine(linput_t *li, int machine_type, const char **p_procname, proc_def_t **p_pd, elf_loader_t *ldr, reader_t *reader);
  inline static ssize_t is_indirect_jump(const insn_t &insn);
  inline static ssize_t verify_noreturn(func_t *pfn);
  inline static ssize_t verify_sp(func_t *pfn);
  inline static ssize_t create_func_frame(func_t *pfn);
  inline static ssize_t get_frame_retsize(int *retsize, const func_t *pfn);
  inline static ssize_t analyze_prolog(ea_t fct_ea);
  inline static ssize_t calc_spdelta(sval_t *spdelta, const insn_t &ins);
  inline static ssize_t calcrel(bytevec_t *out_relbits, size_t *out_consumed, ea_t ea);
  inline static ssize_t get_reg_accesses(reg_accesses_t *accvec, const insn_t &insn, int flags);
  inline static ssize_t is_control_flow_guard(int *p_reg, const insn_t *insn);
  inline static ssize_t find_reg_value(uval_t *out, const insn_t &insn, int reg);
  inline static ssize_t find_op_value(uval_t *out, const insn_t &insn, int op);
  inline static ssize_t treat_hindering_item(ea_t hindering_item_ea, flags64_t new_item_flags, ea_t new_item_ea, asize_t new_item_length);
  inline static ssize_t extract_address(ea_t *out_ea, ea_t screen_ea, const char *string, size_t x);
  inline static ssize_t str2reg(const char *regname);
  inline static ssize_t is_switch(switch_info_t *si, const insn_t &insn);
  inline static ssize_t create_switch_xrefs(ea_t jumpea, const switch_info_t &si);
  inline static ssize_t calc_switch_cases(/*casevec_t * */void *casevec, eavec_t *targets, ea_t insn_ea, const switch_info_t &si);
  inline static ssize_t get_bg_color(bgcolor_t *color, ea_t ea);
  inline static ssize_t validate_flirt_func(ea_t start_ea, const char *funcname);
  inline static ssize_t get_operand_string(qstring *buf, const insn_t &insn, int opnum);
  inline static ssize_t add_cref(ea_t from, ea_t to, cref_t type);
  inline static ssize_t add_dref(ea_t from, ea_t to, dref_t type);
  inline static ssize_t del_cref(ea_t from, ea_t to, bool expand);
  inline static ssize_t del_dref(ea_t from, ea_t to);
  inline static ssize_t coagulate_dref(ea_t from, ea_t to, bool may_define, ea_t *code_ea);
  inline static const char *set_idp_options(const char *keyword, int vtype, const void *value, bool idb_loaded = true);
  inline static ssize_t set_proc_options(const char *options, int confidence);
  inline static ssize_t adjust_libfunc_ea(const idasgn_t &sig, const libfunc_t &libfun, ea_t *ea);
  inline static fpvalue_error_t realcvt(void *m, fpvalue_t *e, uint16 swt);
  inline bool delay_slot_insn(ea_t *ea, bool *bexec, bool *fexec);
  inline static ssize_t adjust_refinfo(refinfo_t *ri, ea_t ea, int n, const fixup_data_t &fd);
  inline static ssize_t is_cond_insn(const insn_t &insn);
  inline static ssize_t set_code16_mode(ea_t ea, bool code16 = true);
  inline static bool get_code16_mode(ea_t ea);
  inline static ssize_t next_exec_insn(ea_t *target, ea_t ea, int tid, regval_getter_t *_getreg, const regval_t &regvalues);
  inline static ssize_t calc_step_over(ea_t *target, ea_t ip);
  inline static ssize_t get_macro_insn_head(ea_t *head, ea_t ip);
  inline static ssize_t get_dbr_opnum(int *opnum, const insn_t &insn);
  inline static ssize_t insn_reads_tbit(const insn_t &insn, regval_getter_t *_getreg, const regval_t &regvalues);
  inline static ssize_t get_idd_opinfo(idd_opinfo_t *opinf, ea_t ea, int n, int thread_id, regval_getter_t *_getreg, const regval_t &regvalues);
  inline static ssize_t calc_next_eas(eavec_t *res, const insn_t &insn, bool over);
  inline static ssize_t clean_tbit(ea_t ea, regval_getter_t *_getreg, const regval_t &regvalues);
  inline static const char *get_reg_info(const char *regname, bitrange_t *bitrange);
  inline static ssize_t update_call_stack(call_stack_t *stack, int tid, regval_getter_t *_getreg, const regval_t &regvalues);
  inline static ssize_t setup_til();
  inline static ssize_t max_ptr_size();
  inline static ssize_t calc_cdecl_purged_bytes(ea_t ea);
  inline static ssize_t equal_reglocs(const argloc_t &a1, const argloc_t &a2);
  inline static ssize_t decorate_name(qstring *outbuf, const char *name, bool mangle, cm_t cc, const tinfo_t &type);
  inline static ssize_t calc_retloc(argloc_t *retloc, const tinfo_t &rettype, cm_t cc);
  inline static ssize_t calc_varglocs(func_type_data_t *ftd, regobjs_t *regs, relobj_t *stkargs, int nfixed);
  inline static ssize_t calc_arglocs(func_type_data_t *fti);
  inline static ssize_t use_stkarg_type(ea_t ea, const funcarg_t &arg);
  inline static ssize_t use_regarg_type(int *idx, ea_t ea, /*const funcargvec_t * */void *rargs);
  inline static ssize_t use_arg_types(ea_t ea, func_type_data_t *fti, /*funcargvec_t * */void *rargs);
  inline static ssize_t calc_purged_bytes(int *p_purged_bytes, const func_type_data_t &fti);
  inline static ssize_t get_stkarg_area_info(stkarg_area_info_t *out, cm_t cc);
  inline static ssize_t get_cc_regs(callregs_t *regs, cm_t cc);
  inline static ssize_t get_simd_types(/*simd_info_vec_t * */void *out, const simd_info_t *simd_attrs, const argloc_t *argloc, bool create_tifs);
  inline static ssize_t arg_addrs_ready(ea_t caller, int n, const tinfo_t &tif, ea_t *addrs);
  inline static ssize_t adjust_argloc(argloc_t *argloc, const tinfo_t *type, int size);
  inline static ssize_t lower_func_type(intvec_t *argnums, func_type_data_t *fti);
  inline static ssize_t get_abi_info(qstrvec_t *abi_names, qstrvec_t *abi_opts, comp_t comp);
  inline static ssize_t arch_changed();
  inline static ssize_t create_merge_handlers(merge_data_t *md);
  inline ssize_t privrange_changed(const range_t &old_privrange, adiff_t delta, qstring *errbuf=nullptr);
  inline ssize_t cvt64_supval(nodeidx_t node, uchar tag, nodeidx_t idx, const uchar *data, size_t datlen, qstring *errbuf = nullptr);
  inline ssize_t cvt64_hashval(nodeidx_t node, uchar tag, const char *name, const uchar *data, size_t datlen, qstring *errbuf = nullptr);

  /// Get the stack variable scaling factor.
  /// Useful for processors who refer to the stack with implicit scaling factor.
  /// TMS320C55 for example: SP(#1) really refers to (SP+2)
  int get_stkvar_scale(void)
    {
      if ( (flag & PR_SCALE_STKVARS) == 0 )
        return 1;
      int scale = notify(ev_get_stkvar_scale_factor);
      if ( scale == 0 )
        error("Request ph.get_stkvar_scale_factor should be implemented");
      else if ( scale <= 0 )
        error("Invalid return code from ph.get_stkvar_scale_factor request");
      return scale;
    }

  //  Processor register information:
  const char *const *reg_names;         ///< array of register names
  int32 regs_num;                       ///< number of registers

  /// \name Segment registers
  /// Segment register information (use virtual CS and DS registers if your
  /// processor doesn't have segment registers):
  //@{
  int32 reg_first_sreg;                 ///< number of first segment register
  int32 reg_last_sreg;                  ///< number of last segment register
  int32 segreg_size;                    ///< size of a segment register in bytes
  //@}

  /// \name Virtual segment registers
  /// If your processor doesn't have segment registers,
  /// you should define 2 virtual segment registers for CS and DS.
  /// Let's call them rVcs and rVds.
  //@{
  int32 reg_code_sreg;                  ///< number of CS register
  int32 reg_data_sreg;                  ///< number of DS register
  //@}


  /// \name Empirics
  //@{
  const bytes_t *codestart;             ///< Array of typical code start sequences.
                                        ///< This array is used when a new file
                                        ///< is loaded to find the beginnings of code
                                        ///< sequences.
                                        ///< This array is terminated with
                                        ///< a zero length item.
  const bytes_t *retcodes;              ///< Array of 'return' instruction opcodes.
                                        ///< This array is used to determine
                                        ///< form of autogenerated locret_...
                                        ///< labels.
                                        ///< The last item of it should be { 0, nullptr }
                                        ///< This array may be nullptr
                                        ///< Better way of handling return instructions
                                        ///< is to define the \idpcode{is_ret_insn} callback in
                                        ///< the notify() function
  //@}

  /// \name Instruction set
  //@{
  int32 instruc_start;                  ///< icode of the first instruction
  int32 instruc_end;                    ///< icode of the last instruction + 1

  /// Does the given value specify a valid instruction for this instruction set?.
  /// See #instruc_start and #instruc_end
  bool is_canon_insn(uint16 itype) const { return itype >= instruc_start && itype < instruc_end; }

  const instruc_t *instruc;             ///< Array of instructions
  //@}

  /// Size of long double (tbyte) for this processor
  /// (meaningful only if \ash{a_tbyte} != nullptr)
  size_t tbyte_size;

  /// Number of digits in floating numbers after the decimal point.
  /// If an element of this array equals 0, then the corresponding
  /// floating point data is not used for the processor.
  /// This array is used to align numbers in the output.
  /// - real_width[0] - number of digits for short floats (only PDP-11 has them)
  /// - real_width[1] - number of digits for "float"
  /// - real_width[2] - number of digits for "double"
  /// - real_width[3] - number of digits for "long double"
  ///
  /// Example: IBM PC module has { 0,7,15,19 }
  char real_width[4];

  /// Icode of return instruction. It is ok to give any of possible return instructions
  int32 icode_return;

  /// Reserved, currently equals to nullptr
  void *unused_slot;

  inline void ensure_processor(void);
  inline size_t sizeof_ldbl() const;
  inline bool is_funcarg_off(const func_t *pfn, uval_t frameoff) const;
  inline sval_t lvar_off(const func_t *pfn, uval_t frameoff) const;
  inline bool is_lumina_usable() const;
};
#ifndef __X86__
CASSERT(sizeof(processor_t) == 144);
#else
CASSERT(sizeof(processor_t) == 104);
#endif

// The following two structures contain information about the current
// processor and assembler.

//-V:ph:688 local variable ph with the same name
#if !defined(NO_OBSOLETE_FUNCS) || defined(__DEFINE_PH__)
idaman processor_t ida_export_data ph;   ///< current processor
idaman asm_t ida_export_data ash;        ///< current assembler
#endif

idaman processor_t *ida_export get_ph();
#define PH (*get_ph())
idaman asm_t *ida_export get_ash();
#define ASH (*get_ash())
idaman struct modctx_t *ida_export get_modctx();
#define EAH (get_modctx()->eah)

/// Hex-Rays decompiler dispatcher.
/// All interaction with the decompiler is carried out by the intermediary of this dispatcher.
typedef void *hexdsp_t(int code, ...);
idaman hexdsp_t *ida_export get_hexdsp();
#define HEXDSP get_hexdsp()


#ifndef SWIG
// ignore_micro manager: can be used in modules/plugins as a base class
struct ignore_micro_t
{
  //--------------------------------------------------------------------------
  /// \name Ignore micro
  /// netnode to keep information about various kinds of instructions
  //@{
  netnode ignore_micro;

#define IM_NONE   0     // regular instruction
#define IM_PROLOG 1     // prolog instruction
#define IM_EPILOG 2     // epilog instruction
#define IM_SWITCH 3     // switch instruction (the indirect jump should not be marked)

  inline void init_ignore_micro(void)                  { ignore_micro.create("$ ignore micro"); }
  inline void term_ignore_micro(void)                  { ignore_micro = BADNODE; }
  inline char get_ignore_micro(ea_t ea) const          { return ignore_micro.charval_ea(ea, 0); }
  inline void set_ignore_micro(ea_t ea, uchar im_type) { ignore_micro.charset_ea(ea, im_type, 0); }
  inline void clr_ignore_micro(ea_t ea)                { ignore_micro.chardel_ea(ea, 0); }
  inline ea_t next_marked_insn(ea_t ea)                { return node2ea(ignore_micro.charnext(ea2node(ea), 0)); }
  inline void mark_prolog_insn(ea_t ea)                { set_ignore_micro(ea, IM_PROLOG); }
  inline void mark_epilog_insn(ea_t ea)                { set_ignore_micro(ea, IM_EPILOG); }
  inline void mark_switch_insn(ea_t ea)                { set_ignore_micro(ea, IM_SWITCH); }
  inline bool is_prolog_insn(ea_t ea) const            { return get_ignore_micro(ea) == IM_PROLOG; }
  inline bool is_epilog_insn(ea_t ea) const            { return get_ignore_micro(ea) == IM_EPILOG; }
  inline bool is_switch_insn(ea_t ea) const            { return get_ignore_micro(ea) == IM_SWITCH; }
  inline bool should_ignore_micro(ea_t ea) const       { return get_ignore_micro(ea) != IM_NONE; }
  //@}
};
#endif // SWIG

struct modctx_t
{
  size_t reserved[8] = { 0 };
  ea_helper_t eah;
};

// Each processor module subclasses this class and reacts to HT_IDP events
struct procmod_t : public event_listener_t, public ignore_micro_t
{
  processor_t &ph;
  asm_t &ash;
  size_t procmod_flags = 0;
  const modctx_t &mctx;

  procmod_t() : ph(PH), ash(ASH), mctx(*get_modctx()) {}

#ifndef SWIG
  DEFINE_EA_HELPER_FUNCS(mctx.eah)
#endif
};


struct plugmod_t
{
  size_t owner = 0;     // internal info used by the kernel
  const modctx_t &mctx;

  plugmod_t() : mctx(*get_modctx()) {}

  /// Invoke the plugin.
  virtual bool idaapi run(size_t arg) = 0;

  /// Helper function to hook event listeners.
  bool hook_event_listener(
        hook_type_t hook_type,
        event_listener_t *cb,
        int hkcb_flags=0)
  {
    return ::hook_event_listener(hook_type, cb, this, hkcb_flags);
  }

  /// Virtual destructor.
  virtual ~plugmod_t() {}

#ifndef SWIG
  DEFINE_EA_HELPER_FUNCS(mctx.eah)
#endif
  // this class is freed by IDA kernel on unload so must be allocated by it
  DEFINE_MEMORY_ALLOCATION_FUNCS()
};

inline ssize_t processor_t::init(const char *idp_modname)
{
  return notify(ev_init, idp_modname);
}
inline ssize_t processor_t::term()
{
  return notify(ev_term);
}
inline ssize_t processor_t::newprc(int pnum, bool keep_cfg)
{
  return notify(ev_newprc, pnum, keep_cfg);
}
inline ssize_t processor_t::newasm(int asmnum)
{
  return notify(ev_newasm, asmnum);
}
inline ssize_t processor_t::asm_installed(int asmnum)
{
  return notify(ev_asm_installed, asmnum);
}
inline ssize_t processor_t::get_reg_accesses(reg_accesses_t *accvec, const insn_t &insn, int flags)
{
  return notify(ev_get_reg_accesses, accvec, &insn, flags);
}
inline ssize_t processor_t::is_control_flow_guard(int *p_reg, const insn_t *insn)
{
  return processor_t::notify(ev_is_control_flow_guard, p_reg, insn);
}
inline ssize_t processor_t::newfile(const char *fname)
{
  return notify(ev_newfile, fname);
}
inline ssize_t processor_t::oldfile(const char *fname)
{
  return notify(ev_oldfile, fname);
}
inline ssize_t processor_t::newbinary(const char *filename, qoff64_t fileoff, ea_t basepara, ea_t binoff, uint64 nbytes)
{
  return notify(ev_newbinary, filename, fileoff, basepara, binoff, nbytes);
}
inline ssize_t processor_t::endbinary(bool ok)
{
  return notify(ev_endbinary, ok);
}
inline ssize_t processor_t::creating_segm(segment_t *seg)
{
  return notify(ev_creating_segm, seg);
}
inline ssize_t processor_t::assemble(uchar *_bin, ea_t ea, ea_t cs, ea_t ip, bool _use32, const char *line)
{
  return notify(ev_assemble, _bin, ea, cs, ip, _use32, line, _bin);
}
inline ssize_t processor_t::ana_insn(insn_t *out)
{
  return notify(ev_ana_insn, out);
}
inline ssize_t processor_t::emu_insn(const insn_t &insn)
{
  return notify(ev_emu_insn, &insn);
}
inline ssize_t processor_t::out_header(outctx_t &ctx)
{
  return notify(ev_out_header, &ctx);
}
inline ssize_t processor_t::out_footer(outctx_t &ctx)
{
  return notify(ev_out_footer, &ctx);
}
inline ssize_t processor_t::out_segstart(outctx_t &ctx, segment_t *seg)
{
  return notify(ev_out_segstart, &ctx, seg);
}
inline ssize_t processor_t::out_segend(outctx_t &ctx, segment_t *seg)
{
  return notify(ev_out_segend, &ctx, seg);
}
inline ssize_t processor_t::out_assumes(outctx_t &ctx)
{
  return notify(ev_out_assumes, &ctx);
}
inline ssize_t processor_t::out_insn(outctx_t &ctx)
{
  return notify(ev_out_insn, &ctx);
}
inline ssize_t processor_t::out_mnem(outctx_t &ctx)
{
  return notify(ev_out_mnem, &ctx);
}
inline ssize_t processor_t::out_operand(outctx_t &ctx, const op_t &op)
{
  return notify(ev_out_operand, &ctx, &op);
}
inline ssize_t processor_t::out_data(outctx_t &ctx, bool analyze_only)
{
  return notify(ev_out_data, &ctx, analyze_only);
}
inline ssize_t processor_t::out_label(outctx_t &ctx, const char *colored_name)
{
  return notify(ev_out_label, &ctx, colored_name);
}
inline ssize_t processor_t::out_special_item(outctx_t &ctx, uchar segtype)
{
  return notify(ev_out_special_item, &ctx, segtype);
}
inline ssize_t processor_t::gen_stkvar_def(outctx_t &ctx, const class member_t *mptr, sval_t v)
{
  return notify(ev_gen_stkvar_def, &ctx, mptr, v);
}
inline ssize_t processor_t::gen_regvar_def(outctx_t &ctx, regvar_t *v)
{
  return notify(ev_gen_regvar_def, &ctx, v);
}
inline ssize_t processor_t::gen_src_file_lnnum(outctx_t &ctx, const char *file, size_t lnnum)
{
  return notify(ev_gen_src_file_lnnum, &ctx, file, lnnum);
}
inline ssize_t processor_t::rename(ea_t ea, const char *new_name, int flags)
{
  return notify(ev_rename, ea, new_name, flags);
}
inline ssize_t processor_t::may_show_sreg(ea_t current_ea)
{
  return notify(ev_may_show_sreg, current_ea);
}
inline ssize_t processor_t::coagulate(ea_t start_ea)
{
  return notify(ev_coagulate, start_ea);
}
inline void processor_t::auto_queue_empty(/*atype_t*/ int type)
{
  notify(ev_auto_queue_empty, type);
}
inline ssize_t processor_t::func_bounds(int *possible_return_code, func_t *pfn, ea_t max_func_end_ea)
{
  return notify(ev_func_bounds, possible_return_code, pfn, max_func_end_ea);
}
inline ssize_t processor_t::may_be_func(const insn_t &insn, int state)
{
  return notify(ev_may_be_func, &insn, state);
}
inline ssize_t processor_t::is_sane_insn(const insn_t &insn, int no_crefs)
{
  return notify(ev_is_sane_insn, &insn, no_crefs);
}
inline ssize_t processor_t::cmp_operands(const op_t &op1, const op_t &op2)
{
  return notify(ev_cmp_operands, &op1, &op2);
}
inline ssize_t processor_t::is_jump_func(func_t *pfn, ea_t *jump_target, ea_t *func_pointer)
{
  return notify(ev_is_jump_func, pfn, jump_target, func_pointer);
}
inline ssize_t processor_t::is_basic_block_end(const insn_t &insn, bool call_insn_stops_block)
{
  return notify(ev_is_basic_block_end, &insn, call_insn_stops_block);
}
inline ssize_t processor_t::getreg(uval_t *rv, int regnum)
{
  return notify(ev_getreg, rv, regnum);
}
inline ssize_t processor_t::undefine(ea_t ea)
{
  return notify(ev_undefine, ea);
}
inline ssize_t processor_t::moving_segm(segment_t *seg, ea_t to, int flags)
{
  return notify(ev_moving_segm, seg, to, flags);
}
inline ssize_t processor_t::is_sp_based(const insn_t &insn, const op_t &x)
{
  int mode;
  int code = notify(ev_is_sp_based, &mode, &insn, &x);
  return code == 0 ? OP_SP_BASED : mode;
}
inline ssize_t processor_t::is_far_jump(int icode)
{
  return notify(ev_is_far_jump, icode);
}
inline ssize_t processor_t::is_call_insn(const insn_t &insn)
{
  return notify(ev_is_call_insn, &insn);
}
inline ssize_t processor_t::is_ret_insn(const insn_t &insn, bool strict)
{
  return notify(ev_is_ret_insn, &insn, strict);
}
inline ssize_t processor_t::is_align_insn(ea_t ea)
{
  return notify(ev_is_align_insn, ea);
}
inline ssize_t processor_t::can_have_type(const op_t &op)
{
  ssize_t code = notify(ev_can_have_type, &op);
  return code != 0                             ? code
       : op.type == o_void || op.type == o_reg ? -1
       :                                         1;
}
inline ssize_t processor_t::get_stkvar_scale_factor()
{
  return notify(ev_get_stkvar_scale_factor);
}
inline ssize_t processor_t::demangle_name(int32 *res, qstring *out, const char *name, uint32 disable_mask, /*demreq_type_t*/ int demreq)
{
  return notify(ev_demangle_name, res, out, name, disable_mask, demreq);
}
inline ssize_t processor_t::create_flat_group(ea_t image_base, int bitness, sel_t dataseg_sel)
{
  return notify(ev_create_flat_group, image_base, bitness, dataseg_sel);
}
inline ssize_t processor_t::is_alloca_probe(ea_t ea)
{
  return notify(ev_is_alloca_probe, ea);
}
inline ssize_t processor_t::get_reg_name(qstring *buf, int reg, size_t width, int reghi)
{
  return notify(ev_get_reg_name, buf, reg, width, reghi);
}
inline ssize_t processor_t::gen_asm_or_lst(bool starting, FILE *fp, bool is_asm, int flags, /*html_line_cb_t ** */ void *outline)
{
  return notify(ev_gen_asm_or_lst, starting, fp, is_asm, flags, outline);
}
inline ssize_t processor_t::gen_map_file(int *nlines, FILE *fp)
{
  return notify(ev_gen_map_file, nlines, fp);
}
inline ssize_t processor_t::get_autocmt(qstring *buf, const insn_t &insn)
{
  return notify(ev_get_autocmt, buf, &insn);
}
inline ssize_t processor_t::loader_elf_machine(linput_t *li, int machine_type, const char **p_procname, proc_def_t **p_pd, elf_loader_t *ldr, reader_t *reader)
{
  return notify(ev_loader_elf_machine, li, machine_type, p_procname, p_pd, ldr, reader);
}
inline ssize_t processor_t::is_indirect_jump(const insn_t &insn)
{
  return notify(ev_is_indirect_jump, &insn);
}
inline ssize_t processor_t::verify_noreturn(func_t *pfn)
{
  return notify(ev_verify_noreturn, pfn);
}
inline ssize_t processor_t::verify_sp(func_t *pfn)
{
  return notify(ev_verify_sp, pfn);
}
inline ssize_t processor_t::create_func_frame(func_t *pfn)
{
  return notify(ev_create_func_frame, pfn);
}
inline ssize_t processor_t::get_frame_retsize(int *retsize, const func_t *pfn)
{
  return notify(ev_get_frame_retsize, retsize, pfn);
}
inline ssize_t processor_t::analyze_prolog(ea_t fct_ea)
{
  return notify(ev_analyze_prolog, fct_ea);
}
inline ssize_t processor_t::calc_spdelta(sval_t *spdelta, const insn_t &insn)
{
  return notify(ev_calc_spdelta, spdelta, &insn);
}
inline ssize_t processor_t::calcrel(bytevec_t *out_relbits, size_t *out_consumed, ea_t ea)
{
  return notify(ev_calcrel, out_relbits, out_consumed, ea);
}
inline ssize_t processor_t::find_reg_value(uval_t *out, const insn_t &insn, int reg)
{
  return notify(ev_find_reg_value, out, &insn, reg);
}
inline ssize_t processor_t::find_op_value(uval_t *out, const insn_t &insn, int opn)
{
  return notify(ev_find_op_value, out, &insn, opn);
}
inline ssize_t processor_t::treat_hindering_item(ea_t hindering_item_ea, flags64_t new_item_flags, ea_t new_item_ea, asize_t new_item_length)
{
  return notify(ev_treat_hindering_item, hindering_item_ea, new_item_flags, new_item_ea, new_item_length);
}
inline ssize_t processor_t::extract_address(ea_t *out_ea, ea_t screen_ea, const char *string, size_t x)
{
  return notify(ev_extract_address, out_ea, screen_ea, string, x);
}
inline ssize_t processor_t::str2reg(const char *regname)
{
  return notify(ev_str2reg, regname);
}
inline ssize_t processor_t::is_switch(switch_info_t *si, const insn_t &insn)
{
  return notify(ev_is_switch, si, &insn);
}
inline ssize_t processor_t::create_switch_xrefs(ea_t jumpea, const switch_info_t &si)
{
  return notify(ev_create_switch_xrefs, jumpea, &si);
}
inline ssize_t processor_t::calc_switch_cases(/*casevec_t * */void *casevec, eavec_t *targets, ea_t insn_ea, const switch_info_t &si)
{
  return notify(ev_calc_switch_cases, casevec, targets, insn_ea, &si);
}
inline ssize_t processor_t::get_bg_color(bgcolor_t *color, ea_t ea)
{
  return notify(ev_get_bg_color, color, ea);
}
inline ssize_t processor_t::validate_flirt_func(ea_t start_ea, const char *funcname)
{
  return notify(ev_validate_flirt_func, start_ea, funcname);
}
inline ssize_t processor_t::get_operand_string(qstring *buf, const insn_t &insn, int opnum)
{
  return notify(ev_get_operand_string, buf, &insn, opnum);
}
inline ssize_t processor_t::add_cref(ea_t from, ea_t to, cref_t type)
{
  return notify(ev_add_cref, from, to, type);
}
inline ssize_t processor_t::add_dref(ea_t from, ea_t to, dref_t type)
{
  return notify(ev_add_dref, from, to, type);
}
inline ssize_t processor_t::del_cref(ea_t from, ea_t to, bool expand)
{
  return notify(ev_del_cref, from, to, expand);
}
inline ssize_t processor_t::del_dref(ea_t from, ea_t to)
{
  return notify(ev_del_dref, from, to);
}
inline ssize_t processor_t::coagulate_dref(ea_t from, ea_t to, bool may_define, ea_t *code_ea)
{
  return notify(ev_coagulate_dref, from, to, may_define, code_ea);
}
inline const char *processor_t::set_idp_options(const char *keyword, int vtype, const void *value, bool idb_loaded)
{
  const char *errmsg = IDPOPT_BADKEY;
  int code = notify(ev_set_idp_options, keyword, vtype, value, &errmsg, idb_loaded);
  return code == 1 ? IDPOPT_OK : code == 0 ? IDPOPT_BADKEY : errmsg;
}
inline ssize_t processor_t::set_proc_options(const char *options, int confidence)
{
  return notify(ev_set_proc_options, options, confidence);
}
inline ssize_t processor_t::adjust_libfunc_ea(const idasgn_t &sig, const libfunc_t &libfun, ea_t *ea)
{
  return notify(ev_adjust_libfunc_ea, &sig, &libfun, ea);
}
inline fpvalue_error_t processor_t::realcvt(void *m, fpvalue_t *e, uint16 swt)
{
  return (fpvalue_error_t)notify(ev_realcvt, m, e, swt);
}
inline ssize_t processor_t::adjust_refinfo(refinfo_t *ri, ea_t ea, int n, const fixup_data_t &fd)
{
  return notify(ev_adjust_refinfo, ri, ea, n, &fd);
}
inline ssize_t processor_t::is_cond_insn(const insn_t &insn)
{
  return notify(ev_is_cond_insn, &insn);
}
inline ssize_t processor_t::set_code16_mode(ea_t ea, bool code16)
{
  return notify(ev_set_code16_mode, ea, code16);
}
inline bool processor_t::get_code16_mode(ea_t ea)
{
  return notify(ev_get_code16_mode, ea) == 1;
}
inline ssize_t processor_t::next_exec_insn(ea_t *target, ea_t ea, int tid, regval_getter_t *_getreg, const regval_t &regvalues)
{
  return notify(ev_next_exec_insn, target, ea, tid, _getreg, &regvalues);
}
inline ssize_t processor_t::calc_step_over(ea_t *target, ea_t ip)
{
  return notify(ev_calc_step_over, target, ip);
}
inline ssize_t processor_t::get_macro_insn_head(ea_t *head, ea_t ip)
{
  return notify(ev_get_macro_insn_head, head, ip);
}
inline ssize_t processor_t::get_dbr_opnum(int *opnum, const insn_t &insn)
{
  return notify(ev_get_dbr_opnum, opnum, &insn);
}
inline ssize_t processor_t::insn_reads_tbit(const insn_t &insn, regval_getter_t *_getreg, const regval_t &regvalues)
{
  return notify(ev_insn_reads_tbit, &insn, _getreg, &regvalues);
}
inline ssize_t processor_t::get_idd_opinfo(idd_opinfo_t *opinf, ea_t ea, int n, int thread_id, regval_getter_t *_getreg, const regval_t &regvalues)
{
  return notify(ev_get_idd_opinfo, opinf, ea, n, thread_id, _getreg, &regvalues);
}
inline ssize_t processor_t::update_call_stack(call_stack_t *stack, int thread_id, regval_getter_t *_getreg, const regval_t &regvalues)
{
  return notify(ev_update_call_stack, stack, thread_id, _getreg, &regvalues);
}
inline ssize_t processor_t::calc_next_eas(eavec_t *res, const insn_t &insn, bool over)
{
  return notify(ev_calc_next_eas, res, &insn, over);
}
inline ssize_t processor_t::clean_tbit(ea_t ea, regval_getter_t *_getreg, const regval_t &regvalues)
{
  return notify(ev_clean_tbit, ea, _getreg, &regvalues);
}
inline ssize_t processor_t::setup_til()
{
  return notify(ev_setup_til);
}
inline ssize_t processor_t::max_ptr_size()
{
  ssize_t code = notify(ev_max_ptr_size);
  if ( code == 0 )
    code = 4;
  return code;
}
inline ssize_t processor_t::calc_cdecl_purged_bytes(ea_t ea)
{
  return notify(ev_calc_cdecl_purged_bytes, ea);
}
inline ssize_t processor_t::calc_retloc(argloc_t *retloc, const tinfo_t &rettype, cm_t cc)
{
  return notify(ev_calc_retloc, retloc, &rettype, cc);
}
inline ssize_t processor_t::calc_varglocs(func_type_data_t *ftd, regobjs_t *regs, relobj_t *stkargs, int nfixed)
{
  return notify(ev_calc_varglocs, ftd, regs, stkargs, nfixed);
}
inline ssize_t processor_t::calc_arglocs(func_type_data_t *fti)
{
  return notify(ev_calc_arglocs, fti);
}
inline ssize_t processor_t::use_stkarg_type(ea_t ea, const funcarg_t &arg)
{
  return notify(ev_use_stkarg_type, ea, &arg);
}
inline ssize_t processor_t::use_regarg_type(int *idx, ea_t ea, /*const funcargvec_t * */void *rargs)
{
  return notify(ev_use_regarg_type, idx, ea, rargs);
}
inline ssize_t processor_t::use_arg_types(ea_t ea, func_type_data_t *fti, /*funcargvec_t * */void *rargs)
{
  return notify(ev_use_arg_types, ea, fti, rargs);
}
inline ssize_t processor_t::calc_purged_bytes(int *p_purged_bytes, const func_type_data_t &fti)
{
  return notify(ev_calc_purged_bytes, p_purged_bytes, &fti);
}
inline ssize_t processor_t::get_cc_regs(callregs_t *regs, cm_t cc)
{
  return notify(ev_get_cc_regs, regs, cc);
}
inline ssize_t processor_t::get_simd_types(/*simd_info_vec_t * */void *out, const simd_info_t *simd_attrs, const argloc_t *argloc, bool create_tifs)
{
  return notify(ev_get_simd_types, out, simd_attrs, argloc, create_tifs);
}
inline ssize_t processor_t::arg_addrs_ready(ea_t caller, int n, const tinfo_t &tif, ea_t *addrs)
{
  return notify(ev_arg_addrs_ready, caller, n, &tif, addrs);
}
inline ssize_t processor_t::adjust_argloc(argloc_t *argloc, const tinfo_t *type, int size)
{
  return notify(ev_adjust_argloc, argloc, type, size);
}
inline ssize_t processor_t::lower_func_type(intvec_t *argnums, func_type_data_t *fti)
{
  return notify(ev_lower_func_type, argnums, fti);
}
inline ssize_t processor_t::get_abi_info(qstrvec_t *abi_names, qstrvec_t *abi_opts, comp_t comp)
{
  return notify(ev_get_abi_info, abi_names, abi_opts, comp);
}
inline ssize_t processor_t::arch_changed()
{
  return notify(ev_arch_changed);
}
inline ssize_t processor_t::create_merge_handlers(merge_data_t *md)
{
  return notify(ev_create_merge_handlers, md);
}
inline ssize_t processor_t::privrange_changed(const range_t &old_privrange, adiff_t delta, qstring *errbuf)
{
  return notify(ev_privrange_changed, &old_privrange, delta, errbuf);
}
inline ssize_t processor_t::cvt64_supval(nodeidx_t node, uchar tag, nodeidx_t idx, const uchar *data, size_t datlen, qstring *errbuf)
{
  return notify(ev_cvt64_supval, node, tag, idx, data, datlen, errbuf);
}
inline ssize_t processor_t::cvt64_hashval(nodeidx_t node, uchar tag, const char *name, const uchar *data, size_t datlen, qstring *errbuf)
{
  return notify(ev_cvt64_hashval, node, tag, name, data, datlen, errbuf);
}

idaman int ida_export str2reg(const char *p);     ///< Get any reg number (-1 on error)


/// If the instruction at 'ea' looks like an alignment instruction,
/// return its length in bytes. Otherwise return 0.

idaman int ida_export is_align_insn(ea_t ea);


/// Get text representation of a register.
/// For most processors this function will just return \ph{reg_names}[reg].
/// If the processor module has implemented processor_t::get_reg_name, it will be
/// used instead
/// \param buf      output buffer
/// \param reg      internal register number as defined in the processor module
/// \param width    register width in bytes
/// \param reghi    if specified, then this function will return the register pair
/// \return length of register name in bytes or -1 if failure

idaman ssize_t ida_export get_reg_name(qstring *buf, int reg, size_t width, int reghi = -1);


/// Get register information - useful for registers like al, ah, dil, etc.
/// Example: this function for "al" returns "eax" in 32bit mode
/// \return main register name (nullptr no such register)

inline const char *processor_t::get_reg_info(const char *regname, bitrange_t *bitrange)
{
  const char *r2;
  int code = notify(ev_get_reg_info, &r2, bitrange, regname);
  if ( code == 0 ) // not implemented?
  {
    if ( ::str2reg(regname) != -1 )
    {
      if ( bitrange != nullptr )
        bitrange->reset();
      return regname;
    }
    return nullptr;
  }
  return code == 1 ? r2 : nullptr;
}

/// Get register number and size from register name
struct reg_info_t
{
  int reg;              ///< register number
  int size;             ///< register size
  DECLARE_COMPARISONS(reg_info_t)
  {
    if ( reg != r.reg )
      return reg > r.reg ? 1 : -1;
    if ( size != r.size )
      return size > r.size ? 1 : -1;
    return 0;
  }
};
DECLARE_TYPE_AS_MOVABLE(reg_info_t);
typedef qvector<reg_info_t> reginfovec_t; ///< vector of register info objects


/// Get register info by name.
/// \param[out] ri  result
/// \param regname  name of register
/// \return success

idaman bool ida_export parse_reg_name(reg_info_t *ri, const char *regname);


/// Possible memory and register access types.
enum access_type_t ENUM_SIZE(uchar)
{
  NO_ACCESS = 0,
  WRITE_ACCESS = 1,
  READ_ACCESS = 2,
  RW_ACCESS = WRITE_ACCESS | READ_ACCESS,
};

/// Information about a register accessed by an instruction.
struct reg_access_t
{
  int regnum = 0;        ///< register number (only entire registers)
  bitrange_t range;      ///< bitrange inside the register
  access_type_t access_type = NO_ACCESS;
  uchar opnum = 0;       ///< operand number

  bool have_common_bits(const reg_access_t &r) const
  {
    return regnum == r.regnum && range.has_common(r.range);
  }

  bool operator==(const reg_access_t &r) const
  {
    return regnum == r.regnum
        && range == r.range
        && access_type == r.access_type
        && opnum == r.opnum;
  }

  bool operator!=(const reg_access_t &r) const
  {
    return !(*this == r);
  }
};
DECLARE_TYPE_AS_MOVABLE(reg_access_t);
typedef qvector<reg_access_t> reg_access_vec_t;

struct reg_accesses_t : public reg_access_vec_t {};


inline bool insn_t::is_canon_insn(const processor_t &_ph) const // see ::insn_t in ua.hpp
{
  return _ph.is_canon_insn(itype);
}

inline const char *insn_t::get_canon_mnem(const processor_t &_ph) const // see ::insn_t in ua.hpp
{
  return is_canon_insn(_ph) ? _ph.instruc[itype-_ph.instruc_start].name : nullptr;
}

inline uint32 insn_t::get_canon_feature(const processor_t &_ph) const // ::insn_t in ua.hpp
{
  return is_canon_insn(_ph) ? _ph.instruc[itype-_ph.instruc_start].feature : 0;
}


/// Get size of long double
inline size_t processor_t::sizeof_ldbl() const
{
  return inf_get_cc_size_ldbl() ? inf_get_cc_size_ldbl() : tbyte_size;
}

/// Flags passed as 'level' parameter to set_processor_type()
enum setproc_level_t
{
  SETPROC_IDB = 0,    ///< set processor type for old idb
  SETPROC_LOADER = 1, ///< set processor type for new idb;
                      ///< if the user has specified a compatible processor,
                      ///< return success without changing it.
                      ///< if failure, call loader_failure()
  SETPROC_LOADER_NON_FATAL = 2, ///< the same as SETPROC_LOADER but non-fatal failures.
  SETPROC_USER = 3,   ///< set user-specified processor
                      ///< used for -p and manual processor change at later time
};

/// Set target processor type.
/// Once a processor module is loaded, it cannot be replaced until we close the idb.
/// \param procname  name of processor type (one of names present in \ph{psnames})
/// \param level     \ref SETPROC_
/// \return success

idaman bool ida_export set_processor_type(
        const char *procname,
        setproc_level_t level);


/// Get name of the current processor module.
/// The name is derived from the file name.
/// For example, for IBM PC the module is named "pc.w32" (windows version),
/// then the module name is "PC" (uppercase).
/// If no processor module is loaded, this function will return nullptr
/// \param buf          the output buffer, should be at least #QMAXFILE length
/// \param bufsize      size of output buffer

idaman char *ida_export get_idp_name(char *buf, size_t bufsize);


/// Set target assembler.
/// \param asmnum  number of assembler in the current processor module
/// \return success

idaman bool ida_export set_target_assembler(int asmnum);


/// Helper function to get the delay slot instruction
inline bool processor_t::delay_slot_insn(ea_t *ea, bool *bexec, bool *fexec)
{
  bool ok = (flag & PR_DELAYED) != 0;
  if ( ok )
  {
    bool be = true;
    bool fe = true;
    ok = notify(ev_delay_slot_insn, ea, &be, &fe) == 1;
    if ( ok )
    {
      if ( bexec != nullptr )
        *bexec = be;
      if ( fexec != nullptr )
        *fexec = fe;
    }
  }
  return ok;
}

/// IDB event group. Some events are still in the processor group, so you will
/// need to hook to both groups. These events do not return anything.
///
/// The callback function should return 0 but the kernel won't check it.
/// Use the hook_to_notification_point() function to install your callback.
namespace idb_event
{
  //<hookgen IDB>

  /// IDB event codes
  enum event_code_t
  {
    closebase,              ///< The database will be closed now

    savebase,               ///< The database is being saved

    upgraded,               ///< The database has been upgraded
                            ///< and the receiver can upgrade its info as well
                            ///< \param from (int) - old IDB version

    auto_empty,             ///< Info: all analysis queues are empty.
                            ///< This callback is called once when the
                            ///< initial analysis is finished. If the queue is
                            ///< not empty upon the return from this callback,
                            ///< it will be called later again.

    auto_empty_finally,     ///< Info: all analysis queues are empty definitively.
                            ///< This callback is called only once.

    determined_main,        ///< The main() function has been determined.
                            ///< \param main (::ea_t) address of the main() function
    local_types_changed,    ///< Local types have been changed

    extlang_changed,        ///< The list of extlangs or the default extlang was changed.
                            ///< \param kind  (int)
                            ///<          0: extlang installed
                            ///<          1: extlang removed
                            ///<          2: default extlang changed
                            ///< \param el (::extlang_t *) pointer to the extlang affected
                            ///< \param idx (int) extlang index

    idasgn_loaded,          ///< FLIRT signature has been loaded
                            ///< for normal processing (not for
                            ///< recognition of startup sequences).
                            ///< \param short_sig_name  (const char *)

    kernel_config_loaded,   ///< This event is issued when ida.cfg is parsed.
                            ///< \param pass_number (int)

    loader_finished,        ///< External file loader finished its work.
                            ///< Use this event to augment the existing loader functionality.
                            ///< \param li            (linput_t *)
                            ///< \param neflags       (::uint16) \ref NEF_
                            ///< \param filetypename  (const char *)

    flow_chart_created,     ///< Gui has retrieved a function flow chart.
                            ///< Plugins may modify the flow chart in this callback.
                            ///< \param fc  (qflow_chart_t *)

    compiler_changed,       ///< The kernel has changed the compiler information.
                            ///< (\inf{cc} structure; \ref get_abi_name)
                            ///< \param adjust_inf_fields  (::bool) may change inf fields?

    changing_ti,            ///< An item typestring (c/c++ prototype) is to be changed.
                            ///< \param ea          (::ea_t)
                            ///< \param new_type    (const ::type_t *)
                            ///< \param new_fnames  (const ::p_list *)

    ti_changed,             ///< An item typestring (c/c++ prototype) has been changed.
                            ///< \param ea      (::ea_t)
                            ///< \param type    (const ::type_t *)
                            ///< \param fnames  (const ::p_list *)

    changing_op_ti,         ///< An operand typestring (c/c++ prototype) is to be changed.
                            ///< \param ea          (::ea_t)
                            ///< \param n           (int)
                            ///< \param new_type    (const ::type_t *)
                            ///< \param new_fnames  (const ::p_list *)
    op_ti_changed,          ///< An operand typestring (c/c++ prototype) has been changed.
                            ///< \param ea (::ea_t)
                            ///< \param n  (int)
                            ///< \param type (const ::type_t *)
                            ///< \param fnames (const ::p_list *)

    changing_op_type,       ///< An operand type (offset, hex, etc...) is to be changed.
                            ///< \param ea  (::ea_t)
                            ///< \param n   (int) eventually or'ed with OPND_OUTER or OPND_ALL
                            ///< \param opinfo (const opinfo_t *) additional operand info
    op_type_changed,        ///< An operand type (offset, hex, etc...) has been set or deleted.
                            ///< \param ea  (::ea_t)
                            ///< \param n   (int) eventually or'ed with OPND_OUTER or OPND_ALL

    enum_created,           ///< An enum type has been created.
                            ///< \param id  (::enum_t)

    deleting_enum,          ///< An enum type is to be deleted.
                            ///< \param id  (::enum_t)
    enum_deleted,           ///< An enum type has been deleted.
                            ///< \param id  (::enum_t)

    renaming_enum,          ///< An enum or enum member is to be renamed.
                            ///< \param id       (::tid_t)
                            ///< \param is_enum  (bool)
                            ///< \param newname  (const char *)
    enum_renamed,           ///< An enum or member has been renamed.
                            ///< \param id  (::tid_t)

    changing_enum_bf,       ///< An enum type 'bitfield' attribute is to be changed.
                            ///< \param id      (::enum_t)
                            ///< \param new_bf  (bool)
    enum_bf_changed,        ///< An enum type 'bitfield' attribute has been changed.
                            ///< \param id  (::enum_t)

    changing_enum_cmt,      ///< An enum or member type comment is to be changed.
                            ///< \param id          (::tid_t)
                            ///< \param repeatable  (bool)
                            ///< \param newcmt      (const char *)
    enum_cmt_changed,       ///< An enum or member type comment has been changed.
                            ///< \param id          (::tid_t)
                            ///< \param repeatable  (bool)

    enum_member_created,    ///< An enum member has been created.
                            ///< \param id   (::enum_t)
                            ///< \param cid  (::const_t)

    deleting_enum_member,   ///< An enum member is to be deleted.
                            ///< \param id   (::enum_t)
                            ///< \param cid  (::const_t)
    enum_member_deleted,    ///< An enum member has been deleted.
                            ///< \param id   (::enum_t)
                            ///< \param cid  (::const_t)

    struc_created,          ///< A new structure type has been created.
                            ///< \param struc_id  (::tid_t)

    deleting_struc,         ///< A structure type is to be deleted.
                            ///< \param sptr  (::struc_t *)
    struc_deleted,          ///< A structure type has been deleted.
                            ///< \param struc_id  (::tid_t)

    changing_struc_align,   ///< A structure type is being changed (the struct alignment).
                            ///< \param sptr  (::struc_t *)
    struc_align_changed,    ///< A structure type has been changed (the struct alignment).
                            ///< \param sptr  (::struc_t *)

    renaming_struc,         ///< A structure type is to be renamed.
                            ///< \param id       (::tid_t)
                            ///< \param oldname  (const char *)
                            ///< \param newname  (const char *)
    struc_renamed,          ///< A structure type has been renamed.
                            ///< \param sptr (::struc_t *)
                            ///< \param success (::bool) the structure was successfully renamed

    expanding_struc,        ///< A structure type is to be expanded/shrunk.
                            ///< \param sptr    (::struc_t *)
                            ///< \param offset  (::ea_t)
                            ///< \param delta   (::adiff_t)
    struc_expanded,         ///< A structure type has been expanded/shrank.
                            ///< \param sptr (::struc_t *)

    struc_member_created,   ///< A structure member has been created.
                            ///< \param sptr  (::struc_t *)
                            ///< \param mptr  (::member_t *)

    deleting_struc_member,  ///< A structure member is to be deleted.
                            ///< \param sptr  (::struc_t *)
                            ///< \param mptr  (::member_t *)
    struc_member_deleted,   ///< A structure member has been deleted.
                            ///< \param sptr       (::struc_t *)
                            ///< \param member_id  (::tid_t)
                            ///< \param offset     (::ea_t)

    renaming_struc_member,  ///< A structure member is to be renamed.
                            ///< \param sptr     (::struc_t *)
                            ///< \param mptr     (::member_t *)
                            ///< \param newname  (const char *)
    struc_member_renamed,   ///< A structure member has been renamed.
                            ///< \param sptr  (::struc_t *)
                            ///< \param mptr  (::member_t *)

    changing_struc_member,  ///< A structure member is to be changed.
                            ///< \param sptr    (::struc_t *)
                            ///< \param mptr    (::member_t *)
                            ///< \param flag    (::flags64_t)
                            ///< \param ti      (const ::opinfo_t *)
                            ///< \param nbytes  (::asize_t)
    struc_member_changed,   ///< A structure member has been changed.
                            ///< \param sptr  (::struc_t *)
                            ///< \param mptr  (::member_t *)

    changing_struc_cmt,     ///< A structure type comment is to be changed.
                            ///< \param struc_id    (::tid_t)
                            ///< \param repeatable  (bool)
                            ///< \param newcmt      (const char *)
    struc_cmt_changed,      ///< A structure type comment has been changed.
                            ///< \param struc_id        (::tid_t)
                            ///< \param repeatable_cmt  (bool)

    segm_added,             ///< A new segment has been created.
                            ///< \param s  (::segment_t *)
                            ///< See also adding_segm

    deleting_segm,          ///< A segment is to be deleted.
                            ///< \param start_ea  (::ea_t)
    segm_deleted,           ///< A segment has been deleted.
                            ///< \param start_ea  (::ea_t)
                            ///< \param end_ea    (::ea_t)
                            ///< \param flags     (int)

    changing_segm_start,    ///< Segment start address is to be changed.
                            ///< \param s             (::segment_t *)
                            ///< \param new_start     (::ea_t)
                            ///< \param segmod_flags  (int)
    segm_start_changed,     ///< Segment start address has been changed.
                            ///< \param s        (::segment_t *)
                            ///< \param oldstart (::ea_t)

    changing_segm_end,      ///< Segment end address is to be changed.
                            ///< \param s             (::segment_t *)
                            ///< \param new_end       (::ea_t)
                            ///< \param segmod_flags  (int)
    segm_end_changed,       ///< Segment end address has been changed.
                            ///< \param s      (::segment_t *)
                            ///< \param oldend (::ea_t)

    changing_segm_name,     ///< Segment name is being changed.
                            ///< \param s        (::segment_t *)
                            ///< \param oldname  (const char *)
    segm_name_changed,      ///< Segment name has been changed.
                            ///< \param s        (::segment_t *)
                            ///< \param name     (const char *)

    changing_segm_class,    ///< Segment class is being changed.
                            ///< \param s  (::segment_t *)
    segm_class_changed,     ///< Segment class has been changed.
                            ///< \param s        (::segment_t *)
                            ///< \param sclass   (const char *)

    segm_attrs_updated,     ///< Segment attributes has been changed.
                            ///< \param s        (::segment_t *)
                            ///< This event is generated for secondary segment
                            ///< attributes (examples: color, permissions, etc)

    segm_moved,             ///< Segment has been moved.
                            ///< \param from    (::ea_t)
                            ///< \param to      (::ea_t)
                            ///< \param size    (::asize_t)
                            ///< \param changed_netmap (bool)
                            ///< See also \ref idb_event::allsegs_moved

    allsegs_moved,          ///< Program rebasing is complete.
                            ///< This event is generated after series of
                            ///< segm_moved events
                            ///< \param info     (::segm_move_infos_t *)

    func_added,             ///< The kernel has added a function.
                            ///< \param pfn  (::func_t *)

    func_updated,           ///< The kernel has updated a function.
                            ///< \param pfn  (::func_t *)

    set_func_start,         ///< Function chunk start address will be changed.
                            ///< \param pfn        (::func_t *)
                            ///< \param new_start  (::ea_t)

    set_func_end,           ///< Function chunk end address will be changed.
                            ///< \param pfn      (::func_t *)
                            ///< \param new_end  (::ea_t)

    deleting_func,          ///< The kernel is about to delete a function.
                            ///< \param pfn  (::func_t *)
                            //
    frame_deleted,          ///< The kernel has deleted a function frame.
                            ///< \param pfn  (::func_t *)

    thunk_func_created,     ///< A thunk bit has been set for a function.
                            ///< \param pfn  (::func_t *)

    func_tail_appended,     ///< A function tail chunk has been appended.
                            ///< \param pfn   (::func_t *)
                            ///< \param tail  (::func_t *)

    deleting_func_tail,     ///< A function tail chunk is to be removed.
                            ///< \param pfn   (::func_t *)
                            ///< \param tail  (const ::range_t *)

    func_tail_deleted,      ///< A function tail chunk has been removed.
                            ///< \param pfn      (::func_t *)
                            ///< \param tail_ea  (::ea_t)

    tail_owner_changed,     ///< A tail chunk owner has been changed.
                            ///< \param tail        (::func_t *)
                            ///< \param owner_func  (::ea_t)
                            ///< \param old_owner   (::ea_t)

    func_noret_changed,     ///< #FUNC_NORET bit has been changed.
                            ///< \param pfn  (::func_t *)

    stkpnts_changed,        ///< Stack change points have been modified.
                            ///< \param pfn  (::func_t *)

    updating_tryblks,       ///< About to update tryblk information
                            ///< \param tbv      (const ::tryblks_t *)
    tryblks_updated,        ///< Updated tryblk information
                            ///< \param tbv      (const ::tryblks_t *)

    deleting_tryblks,       ///< About to delete tryblk information in given range
                            ///< \param range    (const ::range_t *)
                            //
    sgr_changed,            ///< The kernel has changed a segment register value.
                            ///< \param start_ea    (::ea_t)
                            ///< \param end_ea      (::ea_t)
                            ///< \param regnum     (int)
                            ///< \param value      (::sel_t)
                            ///< \param old_value  (::sel_t)
                            ///< \param tag        (::uchar) \ref SR_

    make_code,              ///< An instruction is being created.
                            ///< \param insn    (const ::insn_t*)

    make_data,              ///< A data item is being created.
                            ///< \param ea     (::ea_t)
                            ///< \param flags  (::flags64_t)
                            ///< \param tid    (::tid_t)
                            ///< \param len    (::asize_t)

    destroyed_items,        ///< Instructions/data have been destroyed in [ea1,ea2).
                            ///< \param ea1                 (::ea_t)
                            ///< \param ea2                 (::ea_t)
                            ///< \param will_disable_range  (bool)

    renamed,                ///< The kernel has renamed a byte.
                            ///< See also the \idpcode{rename} event
                            ///< \param ea          (::ea_t)
                            ///< \param new_name    (const char *) can be nullptr
                            ///< \param local_name  (bool)
                            ///< \param old_name    (const char *) can be nullptr

    byte_patched,           ///< A byte has been patched.
                            ///< \param ea         (::ea_t)
                            ///< \param old_value  (::uint32)

    changing_cmt,           ///< An item comment is to be changed.
                            ///< \param ea              (::ea_t)
                            ///< \param repeatable_cmt  (bool)
                            ///< \param newcmt          (const char *)
    cmt_changed,            ///< An item comment has been changed.
                            ///< \param ea              (::ea_t)
                            ///< \param repeatable_cmt  (bool)

    changing_range_cmt,     ///< Range comment is to be changed.
                            ///< \param kind        (::range_kind_t)
                            ///< \param a           (const ::range_t *)
                            ///< \param cmt         (const char *)
                            ///< \param repeatable  (bool)
    range_cmt_changed,      ///< Range comment has been changed.
                            ///< \param kind        (::range_kind_t)
                            ///< \param a           (const ::range_t *)
                            ///< \param cmt         (const char *)
                            ///< \param repeatable  (bool)

    extra_cmt_changed,      ///< An extra comment has been changed.
                            ///< \param ea        (::ea_t)
                            ///< \param line_idx  (int)
                            ///< \param cmt       (const char *)

    item_color_changed,     ///< An item color has been changed.
                            ///< \param ea        (::ea_t)
                            ///< \param color     (::bgcolor_t)
                            ///< if color==DEFCOLOR, the the color is deleted.

    callee_addr_changed,    ///< Callee address has been updated by the user.
                            ///< \param ea        (::ea_t)
                            ///< \param callee    (::ea_t)

    bookmark_changed,       ///< Boomarked position changed.
                            ///< \param index     (::uint32)
                            ///< \param pos       (::const lochist_entry_t *)
                            ///< \param desc      (::const char *)
                            ///< \param operation (int) 0-added, 1-updated, 2-deleted
                            ///< if desc==nullptr, then the bookmark was deleted.

    sgr_deleted,            ///< The kernel has deleted a segment register value.
                            ///< \param start_ea   (::ea_t)
                            ///< \param end_ea     (::ea_t)
                            ///< \param regnum     (int)

    adding_segm,            ///< A segment is being created.
                            ///< \param s  (::segment_t *)

    func_deleted,           ///< A function has been deleted.
                            ///< \param func_ea (::ea_t)

    dirtree_mkdir,          ///< Dirtree: a directory has been created.
                            ///< \param dt   (::dirtree_t *)
                            ///< \param path (::const char *)

    dirtree_rmdir,          ///< Dirtree: a directory has been deleted.
                            ///< \param dt   (::dirtree_t *)
                            ///< \param path (::const char *)

    dirtree_link,           ///< Dirtree: an item has been linked/unlinked.
                            ///< \param dt   (::dirtree_t *)
                            ///< \param path (::const char *)
                            ///< \param link (::bool)

    dirtree_move,           ///< Dirtree: a directory or item has been moved.
                            ///< \param dt   (::dirtree_t *)
                            ///< \param from (::const char *)
                            ///< \param to   (::const char *)

    dirtree_rank,           ///< Dirtree: a directory or item rank has been changed.
                            ///< \param dt   (::dirtree_t *)
                            ///< \param path (::const char *)
                            ///< \param rank (::size_t)

    dirtree_rminode,        ///< Dirtree: an inode became unavailable.
                            ///< \param dt    (::dirtree_t *)
                            ///< \param inode (::inode_t)

    dirtree_segm_moved,     ///< Dirtree: inodes were changed due to
                            ///<          a segment movement or a program rebasing
                            ///< \param dt   (::dirtree_t *)

    enum_width_changed,     ///< Enum width has been changed.
                            ///< \param id    (::enum_t)
                            ///< \param width (int)

    enum_flag_changed,      ///< Enum flags have been changed.
                            ///< \param id (::enum_t)
                            ///< \param F  (::flags64_t)

    enum_ordinal_changed,   ///< Enum mapping to a local type has been changed.
                            ///< \param id  (::enum_t)
                            ///< \param ord (int)
  };
}


/// the kernel will use this function to generate idb_events

inline void gen_idb_event(idb_event::event_code_t code, ...)
{
  va_list va;
  va_start(va, code);
  invoke_callbacks(HT_IDB, code, va);
  va_end(va);
}

inline int processor_t::get_proc_index(void)
{
  qstring curproc = inf_get_procname();
  for ( size_t i = 0; psnames[i] != nullptr; ++i )
  {
    const char *p = psnames[i];
    if ( p[0] == '-' ) // obsolete processor names start with a '-'
      ++p;
    if ( curproc == p )
      return i;
  }
  // should not reach here
  INTERR(10336);
}

/// Starting from IDA v7.5 all modules should use the following 3 functions
/// to handle idb specific static data because now the kernel supports
/// opening and working with multiple idbs files simultaneously.
/// See the source code of the processor modules in the SDK for the usage examples.

/// Register pointer to database specific module data.
/// \param data_id  initially the pointed-to value must be 0, the kernel will fill
///                 it with a unique id. once assigned, the data_id does not change.
/// \param data_ptr pointer to the data to register
/// \return data_ptr.
/// The registered pointer can later be retrieved using get_module_data()

idaman void *ida_export set_module_data(int *data_id, void *data_ptr);


/// Unregister pointer to database specific module data.
/// \param data_id  an data_id that was assigned by set_module_data()
/// \return previously registered pointer for the current database.
///         it can be deallocated now.
/// Multiple calls to this function with the same id are forbidden.

idaman void *ida_export clr_module_data(int data_id);



/// Get pointer to the database specific module data.
/// \param data_id  data id that was initialized by set_module_data()
/// \return previously registered pointer for the current database

idaman void *ida_export get_module_data(int data_id);

// Convenience macros to handle the module data.
// They assume the existence of a global variable "int data_id"
#define SET_MODULE_DATA(type) (type *)set_module_data(&data_id, new type)
#define GET_MODULE_DATA(type) ((type *)get_module_data(data_id))


#endif // _IDP_HPP
