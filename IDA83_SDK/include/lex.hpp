/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef LEX_HPP
#define LEX_HPP

#include <ieee.h>

/*! \file lex.hpp

  \brief Tools for parsing C-like input

  Functions in this file use objects of opaque type lexer_t.
  To create a lexer_t instance, use create_lexer().
*/

typedef ushort lxtype;  ///< see \ref lx_

/// \defgroup lx_ Parser token types
/// See token_t::type
/// \note All separators have their ASCII codes as lxtype
//@{
const lxtype
  lx_end      = 1,      ///< no more tokens
  lx_ident    = 2,      ///< ident
  lx_number   = 3,      ///< long constant
  lx_string   = 4,      ///< string constant (token_t.chr != 0 => unicode string)
  lx_char     = 5,      ///< char constant
  lx_typename = 6,      ///< user-defined type
  lx_float    = 7,      ///< IEEE floating point constant
  lx_int64    = 8,      ///< int64 constant
  lx_key      = 128;    ///< keywords start. All keys are lx_key + keynum. \n
                        ///< Two-char separators are: (c1 + (c2 << 8)).    \n
                        ///< Three-char separators:
                        ///<   - "<<=" = ('<' + ('<'<<8)) + '='
                        ///<   - ">>=" = ('>' + ('>'<<8)) + '='
//@}


/// Parser token
struct token_t
{
  qstring str;          ///< idents & strings
  lxtype type = 0;      ///< see \ref lx_
  sval_t num = 0;       ///< long & char constants
  union
  {
    bool unicode = false; ///< (::lx_string: != 0 => unicode string)
    bool is_unsigned;     ///< (::lx_number, ::lx_int64: != 0 => unsigned value)
  };
  union
  {
    fpvalue_t fnum;     ///< floating point constant
    int64 i64;          ///< ::lx_int64
  };
  token_t() : fnum() {}
};
DECLARE_TYPE_AS_MOVABLE(token_t);

class lexer_t;          // lexical analyzer, opaque structure


/// Preprocessor callback for unknown tokens.
/// Will be called when preprocessor calculates the value of #if expression.

typedef error_t lx_resolver_t(lexer_t *lx, void *ud, token_t *curtok, sval_t *res);

// Conversion from 'type1 ' to 'type_2' is sign-extended. This may cause unexpected runtime behavior.
// We want this sign-extension to happen, since it comes mostly from HANDLEs.
// (see https://msdn.microsoft.com/en-us/library/ms235307.aspx )
MSC_DIAG_OFF(4826)

/// Preprocessor cast
struct cast_t
{
  bool is_unsigned;
  int size;

  cast_t()
  {
    reset();
  }
  void reset(void)
  {
    is_unsigned = false;
    size = 0;
  }
};

struct lex_value_t
{
  bool is_unsigned;
  union
  {
    int64 val;
    uint64 uval;
  };

  lex_value_t()
  {
    reset();
  }
  void set(const lex_value_t &v)
  {
    set_val(v.val, v.is_unsigned);
  }
  void reset(void)
  {
    set_val(0, true);
  }
  void set_val(int64 v, bool _is_unsigned)
  {
    is_unsigned = _is_unsigned;
    val = v;
  }

  uint64 get_uval(void) const
  {
    return val;
  }
  int64 get_val(void) const
  {
    return val;
  }

  bool is_zero(void) const
  {
    return get_val() == 0;
  }

  void perform_cast(const cast_t &cast);

  void unary_minus(const lex_value_t &v);
  void unary_plus(const lex_value_t &v);
  void unary_not(const lex_value_t &v);
  void bitwise_not(const lex_value_t &v);

  void mul(const lex_value_t &v);
  void div(const lex_value_t &v);
  void mod(const lex_value_t &v);
  void add(const lex_value_t &v);
  void sub(const lex_value_t &v);

  void shift_right(const lex_value_t &v);
  void shift_left(const lex_value_t &v);
  void bitwise_and(const lex_value_t &v);
  void bitwise_xor(const lex_value_t &v);
  void bitwise_or(const lex_value_t &v);
  void logical_and(const lex_value_t &v);
  void logical_or(const lex_value_t &v);

  void cmpge(const lex_value_t &v);
  void cmple(const lex_value_t &v);
  void cmplt(const lex_value_t &v);
  void cmpgt(const lex_value_t &v);
  void cmpeq(const lex_value_t &v);
  void cmpneq(const lex_value_t &v);
};

MSC_DIAG_ON(4826)

/// Preprocessor callbacks for casts.
/// Will be called when preprocessor calculates the value of #if expression.

typedef error_t lx_parse_cast_t(lexer_t *lx, cast_t *cast, token_t *ct);

/// Preprocessor callback.
/// It will be called for each input line.
/// \return an error code (0-ok)

typedef int idaapi lx_preprocessor_cb(void *ud, const char *fname, int nl, const char *line);


/// Callback for #pragma directives.
/// \return an error code (0-ok)

typedef int idaapi lx_pragma_cb(void *ud, const char *line);


/// Callback for #warning directives.
/// \return an error code (0-ok)

typedef int idaapi lx_warning_cb(void *ud, const char *line);


/// Callback for #define directives
/// \return an error code (0-ok)

typedef int idaapi lx_macro_cb(
        void *ud,
        const char *name,
        const char *body,
        int nargs,
        bool isfunc,
        bool is_new_macro);


/// Callback for #undef directives
/// \return an error code (0-ok)

typedef int idaapi lx_undef_cb(void *ud, const char *name);


/// Create new lexical analyzer and set its keyword table.
/// If keys==nullptr, then set the default C keyword table

idaman lexer_t *ida_export create_lexer(
        const char *const *keys,
        size_t size,
        void *ud=nullptr);


/// Destroy a lexical analyzer

idaman void ida_export destroy_lexer(lexer_t *lx);


/// Define a macro

idaman error_t ida_export lex_define_macro(
        lexer_t *lx,
        const char *macro,
        const char *body,
        int nargs=0,
        bool isfunc=false);

/// Undefine a macro
/// \param lx the lexer object
/// \param macro macro to undefine

idaman void ida_export lex_undefine_macro(
        lexer_t *lx,
        const char *macro);

/// Set lexer options.
/// \param lx the lexer object
/// \param options  \ref LXOPT_
/// \return the old options

idaman int ida_export lex_set_options(lexer_t *lx, int options);

/// \defgroup LXOPT_ Lexer options
/// Passed as 'options' parameter to lex_set_options().
/// By default all options are on.
//@{
#define LXOPT_PARSE_FLOATS  0x0001 ///< enable floating point constants
#define LXOPT_REQ_SEPARATOR 0x0002 ///< require a separator between a number and an ident or a character/string constant or dot
#define LXOPT_NOCASE_FILES  0x0004 ///< case-insensitive file search
#define LXOPT_C99_CONSTANTS 0x0008 ///< the size and sign of constants depend on the value itself and the 'U', 'L', and 'LL'
                                   ///< modifier suffixes. Otherwise the constant is always considered as signed and the size
                                   ///< depends only on the number of bytes in the value
//@}


/// Get next token
/// \param lx the lexer object
/// \param t the output buffer for the token
/// \param p_lnnum the line number where the token starts

idaman error_t ida_export lex_get_token(lexer_t *lx, token_t *t);
idaman error_t ida_export lex_get_token2(lexer_t *lx, token_t *t, int32 *p_lnnum);


/// Enumerate all macros.
/// Do so until 'cb' returns non-zero.

idaman int ida_export lex_enum_macros(
        const lexer_t *lx,
        int idaapi cb(const char *name, const char *body, int nargs, bool isfunc, void *ud),
        void *ud=nullptr);


/// Debug: get text representation of token

idaman const char *ida_export lex_print_token(qstring *buf, const token_t *t);


//-------------------------------------------------------------------------
/// \name String oriented functions
//@{

/// Set the input line and the macro table.
/// if macros==nullptr, the macro table will not be changed.

idaman error_t ida_export lex_init_string(
        lexer_t *lx,
        const char *line,
        void *macros=nullptr);
//@}

//-------------------------------------------------------------------------
/// \name File oriented functions
//@{

/// Initialization: file may be nullptr.
/// Also see lex_term_file().

idaman error_t ida_export lex_init_file(lexer_t *lx, const char *file);


/// Error handling.
/// if level > 0, then return information about the enclosing file which
/// included the current one.

idaman const char *ida_export lex_get_file_line(
        lexer_t *lx,
        int32 *linenum,
        const char **lineptr,
        int level=0);


/// Termination: also see lex_init_file()

idaman void ida_export lex_term_file(lexer_t *lx, bool del_macros);
//@}

//-------------------------------------------------------------------------
/// \name Token stack
//@{
typedef qstack<token_t> tokenstack_t; ///< see get_token(), unget_token()


/// Retrieve token from a stack or lexer.
/// If buf is not empty then get the token on top of the stack.
/// If buf is empty then gen the next token from the lexer.
/// \return success

inline bool get_token(token_t *t, lexer_t *lx, tokenstack_t &buf)
{
  if ( !buf.empty() )
    *t = buf.pop();
  else if ( lex_get_token(lx, t) != eOk )
    return false;
  return true;
}


/// Push a token back onto the token stack

inline void unget_token(const token_t &t, tokenstack_t &buf)
{
  buf.push(t);
}
//@}


#endif  //  LEX_HPP
