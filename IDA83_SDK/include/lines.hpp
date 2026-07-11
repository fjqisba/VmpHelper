/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _LINES_HPP
#define _LINES_HPP

#include <ida.hpp>

/*! \file lines.hpp

  \brief High level functions that deal with the generation
  of the disassembled text lines.

  This file also contains definitions for the syntax highlighting.

  Finally there are functions that deal with anterior/posterior
  user-defined lines.
*/

struct range_t;

//---------------------------------------------------------------------------
//      C O L O R   D E F I N I T I O N S
//---------------------------------------------------------------------------

/// \defgroup color_def Color definitions
///
/// Here we describe the structure of embedded escape sequences used to
/// implement syntax highlighting.
///
/// IDP module should insert appropriate escape characters into the
/// output lines as necessary. This approach allows to create an IDP
/// module without the syntax highlighting too - just don't use
/// escape sequences.
///
/// A typical color sequence looks like this:
///
/// #COLOR_ON COLOR_xxx text #COLOR_OFF COLOR_xxx
///
/// The first 2 items turn color 'xxx' on, then the text follows,
/// and the color is turned off by two last items.
///
/// For the convenience we've defined a set of macro definitions
/// and functions to deal with colors.
//@{

/// \defgroup color_esc Color escape characters
/// Initiate/Terminate a color tag
//@{
#define COLOR_ON        '\1'     ///< Escape character (ON).
                                 ///< Followed by a color code (::color_t).
#define COLOR_OFF       '\2'     ///< Escape character (OFF).
                                 ///< Followed by a color code (::color_t).
#define COLOR_ESC       '\3'     ///< Escape character (Quote next character).
                                 ///< This is needed to output '\1' and '\2'
                                 ///< characters.
#define COLOR_INV       '\4'     ///< Escape character (Inverse foreground and background colors).
                                 ///< This escape character has no corresponding #COLOR_OFF.
                                 ///< Its action continues until the next #COLOR_INV or end of line.

#define SCOLOR_ON       "\1"     ///< Escape character (ON)
#define SCOLOR_OFF      "\2"     ///< Escape character (OFF)
#define SCOLOR_ESC      "\3"     ///< Escape character (Quote next character)
#define SCOLOR_INV      "\4"     ///< Escape character (Inverse colors)

/// Is the given char a color escape character?
inline THREAD_SAFE bool requires_color_esc(char c) { return c >= COLOR_ON && c <= COLOR_INV; }
//@}

typedef uchar color_t;           ///< color tag - see \ref COLOR_
/// \defgroup COLOR_ Color tags
/// Specify a color for a syntax item
//@{
const color_t
  COLOR_DEFAULT  = 0x01,         ///< Default
  COLOR_REGCMT   = 0x02,         ///< Regular comment
  COLOR_RPTCMT   = 0x03,         ///< Repeatable comment (comment defined somewhere else)
  COLOR_AUTOCMT  = 0x04,         ///< Automatic comment
  COLOR_INSN     = 0x05,         ///< Instruction
  COLOR_DATNAME  = 0x06,         ///< Dummy Data Name
  COLOR_DNAME    = 0x07,         ///< Regular Data Name
  COLOR_DEMNAME  = 0x08,         ///< Demangled Name
  COLOR_SYMBOL   = 0x09,         ///< Punctuation
  COLOR_CHAR     = 0x0A,         ///< Char constant in instruction
  COLOR_STRING   = 0x0B,         ///< String constant in instruction
  COLOR_NUMBER   = 0x0C,         ///< Numeric constant in instruction
  COLOR_VOIDOP   = 0x0D,         ///< Void operand
  COLOR_CREF     = 0x0E,         ///< Code reference
  COLOR_DREF     = 0x0F,         ///< Data reference
  COLOR_CREFTAIL = 0x10,         ///< Code reference to tail byte
  COLOR_DREFTAIL = 0x11,         ///< Data reference to tail byte
  COLOR_ERROR    = 0x12,         ///< Error or problem
  COLOR_PREFIX   = 0x13,         ///< Line prefix
  COLOR_BINPREF  = 0x14,         ///< Binary line prefix bytes
  COLOR_EXTRA    = 0x15,         ///< Extra line
  COLOR_ALTOP    = 0x16,         ///< Alternative operand
  COLOR_HIDNAME  = 0x17,         ///< Hidden name
  COLOR_LIBNAME  = 0x18,         ///< Library function name
  COLOR_LOCNAME  = 0x19,         ///< Local variable name
  COLOR_CODNAME  = 0x1A,         ///< Dummy code name
  COLOR_ASMDIR   = 0x1B,         ///< Assembler directive
  COLOR_MACRO    = 0x1C,         ///< Macro
  COLOR_DSTR     = 0x1D,         ///< String constant in data directive
  COLOR_DCHAR    = 0x1E,         ///< Char constant in data directive
  COLOR_DNUM     = 0x1F,         ///< Numeric constant in data directive
  COLOR_KEYWORD  = 0x20,         ///< Keywords
  COLOR_REG      = 0x21,         ///< Register name
  COLOR_IMPNAME  = 0x22,         ///< Imported name
  COLOR_SEGNAME  = 0x23,         ///< Segment name
  COLOR_UNKNAME  = 0x24,         ///< Dummy unknown name
  COLOR_CNAME    = 0x25,         ///< Regular code name
  COLOR_UNAME    = 0x26,         ///< Regular unknown name
  COLOR_COLLAPSED= 0x27,         ///< Collapsed line
  COLOR_FG_MAX   = 0x28,         ///< Max color number

  // Fictive colors

  COLOR_ADDR     = COLOR_FG_MAX, ///< hidden address marks.
                                 ///< the address is represented as 8digit
                                 ///< hex number: 01234567.
                                 ///< it doesn't have #COLOR_OFF pair.
                                 ///< NB: for 64-bit IDA, the address is 16digit.

  COLOR_OPND1    = COLOR_ADDR+1, ///< Instruction operand 1
  COLOR_OPND2    = COLOR_ADDR+2, ///< Instruction operand 2
  COLOR_OPND3    = COLOR_ADDR+3, ///< Instruction operand 3
  COLOR_OPND4    = COLOR_ADDR+4, ///< Instruction operand 4
  COLOR_OPND5    = COLOR_ADDR+5, ///< Instruction operand 5
  COLOR_OPND6    = COLOR_ADDR+6, ///< Instruction operand 6
  COLOR_OPND7    = COLOR_ADDR+7, ///< Instruction operand 7
  COLOR_OPND8    = COLOR_ADDR+8, ///< Instruction operand 8


  COLOR_RESERVED1= COLOR_ADDR+11,///< This tag is reserved for internal IDA use
  COLOR_LUMINA   = COLOR_ADDR+12;///< Lumina-related, only for the navigation band
//@}

/// Size of a tagged address (see ::COLOR_ADDR)
#define COLOR_ADDR_SIZE (sizeof(ea_t)*2)

/// \defgroup SCOLOR_ Color string constants
/// These definitions are used with the #COLSTR macro
//@{
#define SCOLOR_DEFAULT   "\x01"  ///< Default
#define SCOLOR_REGCMT    "\x02"  ///< Regular comment
#define SCOLOR_RPTCMT    "\x03"  ///< Repeatable comment (defined not here)
#define SCOLOR_AUTOCMT   "\x04"  ///< Automatic comment
#define SCOLOR_INSN      "\x05"  ///< Instruction
#define SCOLOR_DATNAME   "\x06"  ///< Dummy Data Name
#define SCOLOR_DNAME     "\x07"  ///< Regular Data Name
#define SCOLOR_DEMNAME   "\x08"  ///< Demangled Name
#define SCOLOR_SYMBOL    "\x09"  ///< Punctuation
#define SCOLOR_CHAR      "\x0A"  ///< Char constant in instruction
#define SCOLOR_STRING    "\x0B"  ///< String constant in instruction
#define SCOLOR_NUMBER    "\x0C"  ///< Numeric constant in instruction
#define SCOLOR_VOIDOP    "\x0D"  ///< Void operand
#define SCOLOR_CREF      "\x0E"  ///< Code reference
#define SCOLOR_DREF      "\x0F"  ///< Data reference
#define SCOLOR_CREFTAIL  "\x10"  ///< Code reference to tail byte
#define SCOLOR_DREFTAIL  "\x11"  ///< Data reference to tail byte
#define SCOLOR_ERROR     "\x12"  ///< Error or problem
#define SCOLOR_PREFIX    "\x13"  ///< Line prefix
#define SCOLOR_BINPREF   "\x14"  ///< Binary line prefix bytes
#define SCOLOR_EXTRA     "\x15"  ///< Extra line
#define SCOLOR_ALTOP     "\x16"  ///< Alternative operand
#define SCOLOR_HIDNAME   "\x17"  ///< Hidden name
#define SCOLOR_LIBNAME   "\x18"  ///< Library function name
#define SCOLOR_LOCNAME   "\x19"  ///< Local variable name
#define SCOLOR_CODNAME   "\x1A"  ///< Dummy code name
#define SCOLOR_ASMDIR    "\x1B"  ///< Assembler directive
#define SCOLOR_MACRO     "\x1C"  ///< Macro
#define SCOLOR_DSTR      "\x1D"  ///< String constant in data directive
#define SCOLOR_DCHAR     "\x1E"  ///< Char constant in data directive
#define SCOLOR_DNUM      "\x1F"  ///< Numeric constant in data directive
#define SCOLOR_KEYWORD   "\x20"  ///< Keywords
#define SCOLOR_REG       "\x21"  ///< Register name
#define SCOLOR_IMPNAME   "\x22"  ///< Imported name
#define SCOLOR_SEGNAME   "\x23"  ///< Segment name
#define SCOLOR_UNKNAME   "\x24"  ///< Dummy unknown name
#define SCOLOR_CNAME     "\x25"  ///< Regular code name
#define SCOLOR_UNAME     "\x26"  ///< Regular unknown name
#define SCOLOR_COLLAPSED "\x27"  ///< Collapsed line
#define SCOLOR_ADDR      "\x28"  ///< Hidden address mark
//@}

//----------------- Line prefix colors --------------------------------------
/// \defgroup COLOR_PFX Line prefix colors
/// Note: line prefix colors are not used in processor modules
//@{
#define COLOR_DEFAULT    0x01   ///< Default
#define COLOR_SELECTED   0x02   ///< Selected
#define COLOR_LIBFUNC    0x03   ///< Library function
#define COLOR_REGFUNC    0x04   ///< Regular function
#define COLOR_CODE       0x05   ///< Single instruction
#define COLOR_DATA       0x06   ///< Data bytes
#define COLOR_UNKNOWN    0x07   ///< Unexplored byte
#define COLOR_EXTERN     0x08   ///< External name definition segment
#define COLOR_CURITEM    0x09   ///< Current item
#define COLOR_CURLINE    0x0A   ///< Current line
#define COLOR_HIDLINE    0x0B   ///< Hidden line
#define COLOR_LUMFUNC    0x0C   ///< Lumina function
#define COLOR_BG_MAX     0x0D   ///< Max color number

#define PALETTE_SIZE       (COLOR_FG_MAX+COLOR_BG_MAX)
//@}


/// This macro is used to build colored string constants (e.g. for format strings)
/// \param str string literal to surround with color tags
/// \param tag  one of SCOLOR_xxx constants
#define COLSTR(str,tag) SCOLOR_ON tag str SCOLOR_OFF tag


//------------------------------------------------------------------------

/// \defgroup color_conv Convenience functions
/// Higher level convenience functions are defined in ua.hpp.
/// Please use the following functions only if functions from ua.hpp
/// are not useful in your case.
//@{

/// Insert an address mark into a string.
/// \param buf  pointer to the output buffer; the tag will be appended or inserted into it
/// \param ea   address to include
/// \param ins  if true, the tag will be inserted at the beginning of the buffer

idaman THREAD_SAFE void ida_export tag_addr(qstring *buf, ea_t ea, bool ins=false);


/// Move pointer to a 'line' to 'cnt' positions right.
/// Take into account escape sequences.
/// \param line  pointer to string
/// \param cnt   number of positions to move right
/// \return moved pointer

idaman THREAD_SAFE const char *ida_export tag_advance(const char *line, int cnt);


/// Move the pointer past all color codes.
/// \param line  can't be nullptr
/// \return moved pointer, can't be nullptr

idaman THREAD_SAFE const char *ida_export tag_skipcodes(const char *line);


/// Skip one color code.
/// This function should be used if you are interested in color codes
/// and want to analyze all of them.
/// Otherwise tag_skipcodes() function is better since it will skip all colors at once.
/// This function will skip the current color code if there is one.
/// If the current symbol is not a color code, it will return the input.
/// \return moved pointer

idaman THREAD_SAFE const char *ida_export tag_skipcode(const char *line);


/// Calculate length of a colored string
/// This function computes the length in unicode codepoints of a line
/// \return the number of codepoints in the line, or -1 on error

idaman THREAD_SAFE ssize_t ida_export tag_strlen(const char *line);


/// Remove color escape sequences from a string.
/// \param buf        output buffer with the string, cannot be nullptr.
/// \param str        input string, cannot be nullptr.
/// \param init_level used to verify that COLOR_ON and COLOR_OFF tags are balanced
/// \return length of resulting string, -1 if error

idaman THREAD_SAFE ssize_t ida_export tag_remove(qstring *buf, const char *str, int init_level=0);

inline THREAD_SAFE ssize_t idaapi tag_remove(qstring *buf, const qstring &str, int init_level=0)
{
  return tag_remove(buf, str.c_str(), init_level);
}

inline THREAD_SAFE ssize_t idaapi tag_remove(qstring *buf, int init_level=0)
{
  if ( buf->empty() )
    return 0;
  return tag_remove(buf, buf->begin(), init_level);
}

//@} color_conv

//@} color_def


/// Get prefix color for line at 'ea'
/// \return \ref COLOR_PFX
idaman color_t   ida_export calc_prefix_color(ea_t ea);

/// Get background color for line at 'ea'
/// \return RGB color
idaman bgcolor_t ida_export calc_bg_color(ea_t ea);


//------------------------------------------------------------------------
//      S O U R C E   F I L E S
//------------------------------------------------------------------------

/// \name Source files
/// IDA can keep information about source files used to create the program.
/// Each source file is represented by a range of addresses.
/// A source file may contain several address ranges.
//@{

/// Mark a range of address as belonging to a source file.
/// An address range may belong only to one source file.
/// A source file may be represented by several address ranges.
/// \param ea1       linear address of start of the address range
/// \param ea2       linear address of end of the address range (excluded)
/// \param filename  name of source file.
/// \return success

idaman bool ida_export add_sourcefile(ea_t ea1, ea_t ea2, const char *filename);


/// Get name of source file occupying the given address.
/// \param ea      linear address
/// \param bounds  pointer to the output buffer with the address range
///                for the current file. May be nullptr.
/// \return nullptr if source file information is not found,
///          otherwise returns pointer to file name

idaman const char *ida_export get_sourcefile(ea_t ea, range_t *bounds=nullptr);


/// Delete information about the source file.
/// \param ea  linear address
/// \return success

idaman bool ida_export del_sourcefile(ea_t ea);
//@}

//------------------------------------------------------------------------
//      G E N E R A T I O N   O F   D I S A S S E M B L E D   T E X T
//------------------------------------------------------------------------

/// \name Generation of disassembled text
//@{

/// User-defined line-prefixes are displayed just after the autogenerated
/// line prefixes in the disassembly listing.
/// There is no need to call this function explicitly.
/// Use the user_defined_prefix_t class.
/// \param prefix_len prefixed length. if 0, then uninstall UDP
/// \param udp     object to generate user-defined prefix
/// \param owner   pointer to the plugin_t that owns UDP
///                if non-nullptr, then the object will be uninstalled and destroyed
///                when the plugin gets unloaded
idaman bool ida_export install_user_defined_prefix(
        size_t prefix_len,
        struct user_defined_prefix_t *udp,
        const void *owner);

/// Class to generate user-defined prefixes in the disassembly listing.
struct user_defined_prefix_t
{
  /// Creating a user-defined prefix object installs it.
  user_defined_prefix_t(size_t prefix_len, const void *owner)
  {
    install_user_defined_prefix(prefix_len, this, owner);
  }

  /// Destroying a user-defined prefix object uninstalls it.
  virtual idaapi ~user_defined_prefix_t()
  {
    install_user_defined_prefix(0, this, nullptr);
  }

  // Get a user-defined prefix.
  /// This callback must be overridden by the derived class.
  /// \param vout     the output buffer
  /// \param ea       the current address
  /// \param insn     the current instruction. if the current item is not
  ///                 an instruction, then insn.itype is zero.
  /// \param lnnum    number of the current line (each address may have several
  ///                 listing lines for it). 0 means the very first line for
  ///                 the current address.
  /// \param indent   see explanations for \ref gen_printf()
  /// \param line     the line to be generated.
  ///                 the line usually contains color tags.
  ///                 this argument can be examined to decide
  ///                 whether to generate the prefix.
  virtual void idaapi get_user_defined_prefix(
        qstring *vout,
        ea_t ea,
        const class insn_t &insn,
        int lnnum,
        int indent,
        const char *line) = 0;
};

//@}

//------------------------------------------------------------------------
//      A N T E R I O R / P O S T E R I O R   L I N E S
//------------------------------------------------------------------------

/// \name Anterior/Posterior lines
//@{

/// See higher level functions below

idaman AS_PRINTF(3, 0) bool ida_export vadd_extra_line(
        ea_t ea,
        int vel_flags,     // see VEL_...
        const char *format,
        va_list va);

#define VEL_POST 0x01      // append posterior line
#define VEL_CMT  0x02      // append comment line


/// Add anterior/posterior non-comment line(s).
/// \param ea      linear address
/// \param isprev  do we add anterior lines? (0-no, posterior)
/// \param format  printf() style format string. may contain \\n to denote new lines.
/// \return true if success

AS_PRINTF(3, 4) inline bool add_extra_line(ea_t ea, bool isprev, const char *format, ...)
{
  va_list va;
  va_start(va,format);
  int vel_flags = (isprev ? 0 : VEL_POST);
  bool ok = vadd_extra_line(ea, vel_flags, format, va);
  va_end(va);
  return ok;
}


/// Add anterior/posterior comment line(s).
/// \param ea      linear address
/// \param isprev  do we add anterior lines? (0-no, posterior)
/// \param format  printf() style format string. may contain \\n to denote
///                new lines. The resulting string should not contain comment
///                characters (;), the kernel will add them automatically.
/// \return true if success

AS_PRINTF(3, 4) inline bool add_extra_cmt(ea_t ea, bool isprev, const char *format, ...)
{
  va_list va;
  va_start(va,format);
  int vel_flags = (isprev ? 0 : VEL_POST) | VEL_CMT;
  bool ok = vadd_extra_line(ea, vel_flags, format, va);
  va_end(va);
  return ok;
}


/// Add anterior comment line(s) at the start of program.
/// \param format  printf() style format string. may contain \\n to denote
///                new lines. The resulting string should not contain comment
///                characters (;), the kernel will add them automatically.
/// \return true if success

AS_PRINTF(1, 2) inline bool add_pgm_cmt(const char *format, ...)
{
  va_list va;
  va_start(va,format);
  bool ok = vadd_extra_line(inf_get_min_ea(), VEL_CMT, format, va);
  va_end(va);
  return ok;
}

//@}

///---------------------------------------------------------------------\cond
///         The following functions are used in kernel only:

// Generate disassembly (many lines) and put them into a buffer
// Returns number of generated lines
idaman int ida_export generate_disassembly(
        qstrvec_t *out,         // buffer to hold generated lines
        int *lnnum,             // number of "the most interesting" line
        ea_t ea,                // address to generate disassembly for
        int maxsize,            // maximum number of lines
        int flags = 0);

#define GDISMF_AS_STACK (1 << 0) // Display undefined items as 2/4/8 bytes
#define GDISMF_ADDR_TAG (1 << 1) // To generate an hidden addr tag at the beginning of the line

// Generate one line of disassembly
// This function discards all "non-interesting" lines
// It is designed to generate one-line descriptions
// of addresses for lists, etc.
idaman bool ida_export generate_disasm_line(
        qstring *buf,           // output buffer
        ea_t ea,                // address to generate disassembly for
        int flags=0);
#define GENDSM_FORCE_CODE  (1 << 0)     // generate a disassembly line as if
                                        // there is an instruction at 'ea'
#define GENDSM_MULTI_LINE  (1 << 1)     // if the instruction consists of several lines,
                                        // produce all of them (useful for parallel instructions)
#define GENDSM_REMOVE_TAGS (1 << 2)     // remove tags from output buffer

/// Get length of the line prefix that was used for the last generated line

idaman int ida_export get_last_pfxlen(void);


// Get pointer to the sequence of characters denoting 'close comment'
// empty string means no comment (the current assembler has no open-comment close-comment pairs)
// This function uses ash.cmnt2

idaman const char *ida_export closing_comment(void);


// Every anterior/posterior line has its number.
// Anterior  lines have numbers from E_PREV
// Posterior lines have numbers from E_NEXT

const int E_PREV = 1000;
const int E_NEXT = 2000;

idaman int ida_export get_first_free_extra_cmtidx(ea_t ea, int start);
idaman void ida_export update_extra_cmt(ea_t ea, int what, const char *str);
idaman void ida_export del_extra_cmt(ea_t ea, int what);
idaman ssize_t ida_export get_extra_cmt(qstring *buf, ea_t ea, int what);
idaman void ida_export delete_extra_cmts(ea_t ea, int what);

idaman ea_t ida_export align_down_to_stack(ea_t newea);
idaman ea_t ida_export align_up_to_stack(ea_t ea1, ea_t ea2=BADADDR);

// A helper class, to encode from UTF-8, -> into the target encoding.
// This is typically used when generating listings (or any kind of
// output file.)
struct encoder_t
{
  // whether or not a message should be printed, letting the
  // user know that some text couldn't be recoded properly
  enum notify_recerr_t
  {
    nr_none,
    nr_once,
  };

  virtual ~encoder_t() {}
  virtual bool idaapi get_bom(bytevec_t *out) const = 0;
  // returns true if conversion was entirely successful, false otherwise.
  // codepoints that couldn't be converted, will be output as C
  // literal-escaped UTF-8 sequences (e.g., "\xC3\xD9"), and if
  // 'nr_once' was passed at creation-time, a one-time notification
  // well be output in the messages window.
  virtual bool idaapi encode(qstring *s) const = 0;
  // encode()s the UTF-8 string composed by format + args, and
  // returns true if all the resulting bytes could be written to
  // the output file.
  AS_PRINTF(3, 4) virtual bool idaapi print(FILE *out, const char *format, ...) const = 0;
  // should a file be opened as binary, or should it rather be opened
  // in text mode? This will have an importance in how '\n' characters
  // are possibly converted into '\x0A\x0D' on windows, which is most
  // inappropriate when output'ing e.g., UTF-16, UTF-32..
  virtual bool idaapi requires_binary_mode() const = 0;
};

// Create the encoder with the given target encoding. If -1 is passed
// then the effective target encoding will be computed like so:
// if ( encidx < 0 )
// {
//   encidx = get_outfile_encoding_idx();
//   if ( encidx == STRENC_DEFAULT )
//     encidx = get_default_encoding_idx(BPU_1B);
// }
idaman encoder_t *ida_export create_encoding_helper(
        int encidx=-1,
        encoder_t::notify_recerr_t nr=encoder_t::nr_once);

/// Callback functions to output lines:
//@{
typedef int idaapi html_header_cb_t(FILE *fp);
typedef int idaapi html_footer_cb_t(FILE *fp);
typedef int idaapi html_line_cb_t(
        FILE *fp,
        const qstring &line,
        bgcolor_t prefix_color,
        bgcolor_t bg_color);
#define gen_outline_t html_line_cb_t
//@}

///-------------------------------------------------------------------\endcond


#ifndef NO_OBSOLETE_FUNCS
idaman DEPRECATED void ida_export set_user_defined_prefix( // use install_user_defined_prefix()
        size_t width,
        void (idaapi *get_user_defined_prefix)(
          qstring *buf,
          ea_t ea,
          int lnnum,
          int indent,
          const char *line));
#endif

#endif
