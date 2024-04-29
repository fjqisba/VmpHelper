/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _CONFIG_HPP
#define _CONFIG_HPP

//-----------------------------------------------------------------------
/// \defgroup IDPOPT_T Option value types
/// Passed as 'value_type' parameter to ::set_options_t callbacks
//@{
#define IDPOPT_STR 1    ///< string constant (char *)
#define IDPOPT_NUM 2    ///< number (uval_t *)
#define IDPOPT_BIT 3    ///< bit, yes/no (int *)
#define IDPOPT_I64 5    ///< 64bit number (int64 *)
#define IDPOPT_CST 6    ///< lexer (lexer_t*)
                        ///< Custom type, starting with a '{'
                        ///< Values of this type should be handled by
                        ///< ::set_options_t callbacks. E.g.,:
                        ///< \code
                        ///< ERROR_STRINGS =
                        ///< {
                        ///<   {0, "Unknown error"},
                        ///<   {1, "Missing filename"},
                        ///<   {5, "Out-of-memory"}
                        ///< }
                        ///< \endcode
                        ///< For values of this type, the data that will
                        ///< be passed as the callback's 'value' parameter
                        ///< is the lexer instance that is being used
                        ///< to parse the configuration file.
                        ///< You can use \ref parse_json() (see parsejson.hpp)
                        ///< to parse JSON-format data
                        ///< NB: the '{' is already consumed by the parser,
                        ///< so you need to push it again if it's a part of the JSON object
#define IDPOPT_JVL 7    ///< json value (jvalue_t *)
//@}

/// \defgroup IDPOPT_RET Option result codes
/// Predefined return values for ::set_options_t callbacks
//@{
#define IDPOPT_OK       nullptr         ///< ok
#define IDPOPT_BADKEY   ((char*)1)      ///< illegal keyword
#define IDPOPT_BADTYPE  ((char*)2)      ///< illegal type of value
#define IDPOPT_BADVALUE ((char*)3)      ///< illegal value (bad range, for example)
//@}


/// Callback - called when a config directive is processed in IDA.
/// Also see read_config_file() and processor_t::set_idp_options
/// \param keyword     keyword encountered in IDA.CFG/user config file.
///                    if nullptr, then an interactive dialog form should be displayed
/// \param value_type  type of value of the keyword - one of \ref IDPOPT_T
/// \param value       pointer to value
/// \param idb_loaded  true if the ev_oldfile/ev_newfile events have been generated?
/// \return one of \ref IDPOPT_RET, otherwise a pointer to an error message

typedef const char *(idaapi set_options_t)(
        const char *keyword,
        int value_type,
        const void *value,
        bool idb_loaded);

/// \defgroup IDAOPT_PRIO Option priority
/// Specifies the priority of a configuration option. Since options may
/// be specified in different way, and applied in various orders, we need
/// option priorities.
/// Normally the default priority option does not overwrite the existing value
/// whereas the high priority one does.
/// High priority options may be stored in the database to be available
/// in the next session.
//@{
#define IDPOPT_PRI_DEFAULT 1  ///< default priority - taken from config file
#define IDPOPT_PRI_HIGH    2  ///< high priority - received from UI or a script function
//@}


//-------------------------------------------------------------------------
/// Parse the value type for the value token 'value'.
/// This is mostly used for converting from values that a cfgopt_handler_t
/// receives, into data that callbacks
///  - processor_t::set_idp_options
///  - debugger_t::set_dbg_options
/// expect.
///
/// Plugins that wish to use options shouldn't rely on this,
/// and use the cfgopt_t utility instead.
///
/// \param out parsed data
/// \param lx the lexer in use
/// \param value the value token
/// \return true if guessing didn't lead to an error, false otherwise.
///         note that even if 'true' is returned, it doesn't mean the
///         type could be guessed: merely that no syntax error occurred.
class lexer_t;
struct token_t;
class idc_value_t;
idaman bool ida_export parse_config_value(
        idc_value_t *out,
        lexer_t *lx,
        const token_t &value);

//-------------------------------------------------------------------------
typedef const char *(idaapi cfgopt_handler_t)(
        lexer_t *lx,
        const token_t &keyword,
        const token_t &value);

//-------------------------------------------------------------------------
typedef const char *(idaapi cfgopt_handler2_t)(
        lexer_t *lx,
        const token_t &keyword,
        const token_t &value,
        int64 param1,
        int64 param2);

//-------------------------------------------------------------------------
typedef const char *(idaapi cfgopt_handler3_t)(
        lexer_t *lx,
        const token_t &keyword,
        const token_t &value,
        int64 param1,
        int64 param2,
        void *obj);

//-----------------------------------------------------------------------
/// used by cfgopt_t. You shouldn't have to deal with those directly.
#define IDPOPT_NUM_INT     (0)
#define IDPOPT_NUM_CHAR    (1 << 24)
#define IDPOPT_NUM_SHORT   (2 << 24)
#define IDPOPT_NUM_RANGE   (1 << 26)
#define IDPOPT_NUM_UNS     (1 << 27)

#define IDPOPT_BIT_UINT    0
#define IDPOPT_BIT_UCHAR   (1 << 24)
#define IDPOPT_BIT_USHORT  (2 << 24)
#define IDPOPT_BIT_BOOL    (3 << 24)

#define IDPOPT_STR_QSTRING (1 << 24)
#define IDPOPT_STR_LONG    (1 << 25)

#define IDPOPT_I64_RANGE   (1 << 24)
#define IDPOPT_I64_UNS     (1 << 25)

#define IDPOPT_CST_PARAMS  (1 << 24)

#define IDPOPT_MBROFF      (1 << 18)

//-------------------------------------------------------------------------
struct cfgopt_t;
idaman const char *ida_export cfgopt_t__apply(
        const cfgopt_t *_this,
        int vtype,
        const void *vdata);
idaman const char *ida_export cfgopt_t__apply2(
        const cfgopt_t *_this,
        int vtype,
        const void *vdata,
        void *obj);
idaman const char *ida_export cfgopt_t__apply3(
        const cfgopt_t *_this,
        lexer_t *lx,
        int vtype,
        const void *vdata,
        void *obj);

struct jvalue_t;
//-------------------------------------------------------------------------
// cfgopt_t objects are suitable for being statically initialized, and
// passed to 'read_config_file'.
//
// E.g.,
// ---
// static const cfgopt_t g_opts[] =
// {
//   cfgopt_t("AUTO_UNDEFINE", &auto_undefine, -1, 1),
//   cfgopt_t("NOVICE", &novice, true),
//   cfgopt_t("EDITOR", editor_buf, sizeof(editor_buf)),
//   cfgopt_t("SCREEN_PALETTE", set_screen_palette), // specific handler for SCREEN_PALETTE
// };
//
// ...
//
// read_config_file("myfile", g_opts, qnumber(g_opts), other_handler)
// ---
//
// NOTES:
//   * so-called 'long' strings (the default) can span on multiple lines,
//     and are terminated by a ';'
struct cfgopt_t
{
  const char *name;
  union
  {
    void *ptr;
    size_t mbroff;            // offset of a structure member
    cfgopt_handler_t *hnd;    // to avoid reinterpret_cast and gcc's error:
    cfgopt_handler2_t *hnd2;  // "a reinterpret_cast is not a constant expression"
    cfgopt_handler3_t *hnd3;  //
  };
  int flags;
  struct num_range_t
  {
    constexpr num_range_t(int64 _min, int64 _max) : minval(_min), maxval(_max) {}
    int64 minval;
    int64 maxval;
  };
  struct params_t
  {
    constexpr params_t(int64 _p1, int64 _p2) : p1(_p1), p2(_p2) {}
    int64 p1;
    int64 p2;
  };
  union
  {
    size_t buf_size;
    num_range_t num_range;
    uint32 bit_flags;
    params_t params;
    void *mbroff_obj;
  };

  // IDPOPT_STR
  constexpr cfgopt_t(const char *_n, char *_p, size_t _sz, bool _long = true)
    : name(_n), ptr(_p), flags(IDPOPT_STR | (_long ? IDPOPT_STR_LONG : 0)), buf_size(_sz)
  {}
  constexpr cfgopt_t(const char *_n, qstring *_p, bool _long = true)
    : name(_n), ptr(_p), flags(IDPOPT_STR | IDPOPT_STR_QSTRING | (_long ? IDPOPT_STR_LONG : 0)), buf_size(0)
  {}

  // IDPOPT_NUM
  constexpr cfgopt_t(const char *_n, int *_p)
    : name(_n), ptr(_p), flags(IDPOPT_NUM), buf_size(0) {}
  constexpr cfgopt_t(const char *_n, uint *_p)
    : name(_n), ptr(_p), flags(IDPOPT_NUM | IDPOPT_NUM_UNS), buf_size(0) {}
  constexpr cfgopt_t(const char *_n, char *_p)
    : name(_n), ptr(_p), flags(IDPOPT_NUM | IDPOPT_NUM_CHAR), buf_size(0) {}
  constexpr cfgopt_t(const char *_n, uchar *_p)
    : name(_n), ptr(_p), flags(IDPOPT_NUM | IDPOPT_NUM_UNS | IDPOPT_NUM_CHAR), buf_size(0) {}
  constexpr cfgopt_t(const char *_n, short *_p)
    : name(_n), ptr(_p), flags(IDPOPT_NUM | IDPOPT_NUM_SHORT), buf_size(0) {}
  constexpr cfgopt_t(const char *_n, ushort *_p)
    : name(_n), ptr(_p), flags(IDPOPT_NUM | IDPOPT_NUM_UNS | IDPOPT_NUM_SHORT), buf_size(0) {}
  // IDPOPT_NUM + ranges
  constexpr cfgopt_t(const char *_n, int *_p, int _min, int _max)
    : name(_n), ptr(_p), flags(IDPOPT_NUM | IDPOPT_NUM_RANGE), num_range(_min, _max) {}
  constexpr cfgopt_t(const char *_n, uint *_p, uint _min, uint _max)
    : name(_n), ptr(_p), flags(IDPOPT_NUM | IDPOPT_NUM_UNS | IDPOPT_NUM_RANGE), num_range(_min, _max) {}
  constexpr cfgopt_t(const char *_n, char *_p, char _min, char _max)
    : name(_n), ptr(_p), flags(IDPOPT_NUM | IDPOPT_NUM_CHAR | IDPOPT_NUM_RANGE), num_range(_min, _max) {}
  constexpr cfgopt_t(const char *_n, uchar *_p, uchar _min, uchar _max)
    : name(_n), ptr(_p), flags(IDPOPT_NUM | IDPOPT_NUM_UNS | IDPOPT_NUM_CHAR | IDPOPT_NUM_RANGE), num_range(_min, _max) {}
  constexpr cfgopt_t(const char *_n, short *_p, short _min, short _max)
    : name(_n), ptr(_p), flags(IDPOPT_NUM | IDPOPT_NUM_RANGE | IDPOPT_NUM_SHORT), num_range(_min, _max) {}
  constexpr cfgopt_t(const char *_n, ushort *_p, ushort _min, ushort _max)
    : name(_n), ptr(_p), flags(IDPOPT_NUM | IDPOPT_NUM_UNS | IDPOPT_NUM_RANGE | IDPOPT_NUM_SHORT), num_range(_min, _max) {}

  // IDPOPT_BIT
  constexpr cfgopt_t(const char *_n, bool *_p, bool _flags) : name(_n), ptr(_p), flags(IDPOPT_BIT | IDPOPT_BIT_BOOL), bit_flags(_flags) {}
  constexpr cfgopt_t(const char *_n, uchar *_p, uchar _flags) : name(_n), ptr(_p), flags(IDPOPT_BIT | IDPOPT_BIT_UCHAR), bit_flags(_flags) {}
  constexpr cfgopt_t(const char *_n, ushort *_p, ushort _flags) : name(_n), ptr(_p), flags(IDPOPT_BIT | IDPOPT_BIT_USHORT), bit_flags(_flags) {}
  constexpr cfgopt_t(const char *_n, uint32 *_p, uint32 _flags) : name(_n), ptr(_p), flags(IDPOPT_BIT), bit_flags(_flags) {}

  // IDPOPT_I64
  constexpr cfgopt_t(const char *_n, int64 *_p) : name(_n), ptr(_p), flags(IDPOPT_I64), buf_size(0) {}
  constexpr cfgopt_t(const char *_n, uint64 *_p) : name(_n), ptr(_p), flags(IDPOPT_I64 | IDPOPT_NUM_UNS), buf_size(0) {}
  // IDPOPT_I64 + ranges
  constexpr cfgopt_t(const char *_n, int64 *_p, int64 _min, int64 _max)
    : name(_n), ptr(_p), flags(IDPOPT_I64 | IDPOPT_I64_RANGE), num_range(_min, _max) {}
  constexpr cfgopt_t(const char *_n, uint64 *_p, uint64 _min, uint64 _max)
    : name(_n), ptr(_p), flags(IDPOPT_I64 | IDPOPT_I64_UNS | IDPOPT_I64_RANGE), num_range(int64(_min), int64(_max)) {}

  // IDPOPT_CST
  constexpr cfgopt_t(const char *_n, cfgopt_handler_t *_p)
    : name(_n), hnd(_p), flags(IDPOPT_CST), buf_size(0) {}
  // IDPOPT_CST + params
  constexpr cfgopt_t(const char *_n, cfgopt_handler2_t *_p, int64 _p1=0, int64 _p2=0)
    : name(_n), hnd2(_p), flags(IDPOPT_CST | IDPOPT_CST_PARAMS), params(_p1, _p2) {}

  // IDPOPT_JVL
  constexpr cfgopt_t(const char *_n, jvalue_t *_p)
    : name(_n), ptr(_p), flags(IDPOPT_JVL), buf_size(0) {}

  // configuration option based on the offset of a structure member

  // IDPOPT_STR
  template<class T>
  constexpr cfgopt_t(const char *_n, qstring T:: *, size_t _mbroff, bool _long = true)
    : name(_n),
      mbroff(_mbroff),
      flags(IDPOPT_MBROFF | IDPOPT_STR | IDPOPT_STR_QSTRING | (_long ? IDPOPT_STR_LONG : 0)),
      buf_size(0)
  {}
#define CFGOPT_QS(nm, cfgt, cfgm, _long) \
  cfgopt_t(nm, &cfgt::cfgm, qoffsetof(cfgt, cfgm), _long)

#define CFGOPT_INNER_QS(nm, cfgt, cfgm, mt, mf, _long) \
  cfgopt_t(nm, &mt::mf, qoffsetof(cfgt, cfgm) + qoffsetof(mt, mf), _long)

  // IDPOPT_STR
  template<class T>
  constexpr cfgopt_t(const char *_n, char * T:: *, size_t _mbroff, bool _long = true)
    : name(_n),
    mbroff(_mbroff),
    flags(IDPOPT_MBROFF | IDPOPT_STR | (_long ? IDPOPT_STR_LONG : 0)),
    buf_size(0)
  {}


  // IDPOPT_NUM
#define CTR_CFGOPT(ctrtype, ctrflags)                               \
  template<class T>                                                 \
  constexpr cfgopt_t(const char *_n, ctrtype T:: *, size_t _mbroff) \
    : name(_n),                                                     \
      mbroff(_mbroff),                                              \
      flags(IDPOPT_MBROFF|IDPOPT_NUM|ctrflags),                     \
      buf_size(0)                                                   \
  {}
  CTR_CFGOPT(int, 0)
  CTR_CFGOPT(uint, IDPOPT_NUM_UNS)
  CTR_CFGOPT(char, IDPOPT_NUM_CHAR)
  CTR_CFGOPT(uchar, IDPOPT_NUM_UNS|IDPOPT_NUM_CHAR)
  CTR_CFGOPT(short, IDPOPT_NUM_SHORT)
  CTR_CFGOPT(ushort, IDPOPT_NUM_SHORT|IDPOPT_NUM_UNS)
#undef CTR_CFGOPT

#define CFGOPT_N(nm, cfgt, cfgm) \
  cfgopt_t(nm, &cfgt::cfgm, qoffsetof(cfgt, cfgm))

#define CFGOPT_INNER_N(nm, cfgt, cfgm, mt, mf) \
  cfgopt_t(nm, &mt::mf, qoffsetof(cfgt, cfgm) + qoffsetof(mt, mf))


  // IDPOPT_NUM + ranges
#define CTR_CFGOPT(ctrtype, ctrflags)                                                       \
  template<class T>                                                                         \
  constexpr cfgopt_t(const char *_n, ctrtype T:: *, size_t _mbroff, int64 _min, int64 _max) \
    : name(_n),                                                                             \
      mbroff(_mbroff),                                                                      \
      flags(IDPOPT_MBROFF|IDPOPT_NUM|IDPOPT_NUM_RANGE|ctrflags),                            \
      num_range(_min, _max)                                                                 \
  {}
  CTR_CFGOPT(int, 0)
  CTR_CFGOPT(uint, IDPOPT_NUM_UNS)
  CTR_CFGOPT(char, IDPOPT_NUM_CHAR)
  CTR_CFGOPT(uchar, IDPOPT_NUM_UNS|IDPOPT_NUM_CHAR)
  CTR_CFGOPT(short, IDPOPT_NUM_SHORT)
  CTR_CFGOPT(ushort, IDPOPT_NUM_SHORT|IDPOPT_NUM_UNS)
#undef CTR_CFGOPT

#define CFGOPT_R(nm, cfgt, cfgm, min, max) \
  cfgopt_t(nm, &cfgt::cfgm, qoffsetof(cfgt, cfgm), min, max)

#define CFGOPT_INNER_R(nm, cfgt, cfgm, mt, mf, min, max) \
  cfgopt_t(nm, &mt::mf, qoffsetof(cfgt, cfgm) + qoffsetof(mt, mf), min, max)


  // IDPOPT_BIT
#define CTR_CFGOPT(ctrtype, ctrflags)                                   \
  template<class T>                                                     \
  constexpr cfgopt_t(const char *_n, ctrtype T:: *, size_t _mbroff, ctrtype _flags) \
    : name(_n),                                                         \
      mbroff(_mbroff),                                                  \
      flags(IDPOPT_MBROFF|IDPOPT_BIT|ctrflags),                         \
      bit_flags(_flags)                                                 \
  {}
  CTR_CFGOPT(bool, IDPOPT_BIT_BOOL);
  CTR_CFGOPT(uchar, IDPOPT_BIT_UCHAR);
  CTR_CFGOPT(ushort, IDPOPT_BIT_USHORT);
  CTR_CFGOPT(uint32, 0);
#undef CTR_CFGOPT
#define CFGOPT_B(nm, cfgt, cfgm, _flags) \
  cfgopt_t(nm, &cfgt::cfgm, qoffsetof(cfgt, cfgm), _flags)

#define CFGOPT_INNER_B(nm, cfgt, cfgm, mt, mf, _flags) \
  cfgopt_t(nm, &mt::mf, qoffsetof(cfgt, cfgm) + qoffsetof(mt, mf), _flags)


  // IDPOPT_I64
  template<class T>
  constexpr cfgopt_t(const char *_n, int64 T:: *, size_t _mbroff)
  : name(_n),
    mbroff(_mbroff),
    flags(IDPOPT_MBROFF|IDPOPT_I64),
    buf_size(0)
  {}
  template<class T>
  constexpr cfgopt_t(const char *_n, uint64 T:: *, size_t _mbroff)
  : name(_n),
    mbroff(_mbroff),
    flags(IDPOPT_MBROFF|IDPOPT_I64|IDPOPT_NUM_UNS),
    buf_size(0)
  {}

  // IDPOPT_JVL
  template<class T>
  constexpr cfgopt_t(const char *_n, jvalue_t T:: *, size_t _mbroff)
    : name(_n),
    mbroff(_mbroff),
    flags(IDPOPT_MBROFF | IDPOPT_JVL),
    buf_size(0)
  {}

#define CFGOPT_J(nm, cfgt, cfgm) \
  cfgopt_t(nm, &cfgt::cfgm, qoffsetof(cfgt, cfgm))

  // IDPOPT_I64 + ranges
  template<class T>
  constexpr cfgopt_t(const char *_n, int64 T:: *, size_t _mbroff, int64 _min, int64 _max)
    : name(_n),
      mbroff(_mbroff),
      flags(IDPOPT_MBROFF|IDPOPT_I64|IDPOPT_I64_RANGE),
      num_range(_min, _max)
  {}
  template<class T>
  constexpr cfgopt_t(const char *_n, uint64 T:: *, size_t _mbroff, uint64 _min, uint64 _max)
    : name(_n),
      mbroff(_mbroff),
      flags(IDPOPT_MBROFF|IDPOPT_I64|IDPOPT_I64_UNS|IDPOPT_I64_RANGE),
      num_range(int64(_min), int64(_max))
  {}

  // IDPOPT_CST + params
  constexpr cfgopt_t(const char *_n, cfgopt_handler3_t *_p, int64 _p1=0, int64 _p2=0)
    : name(_n), hnd3(_p), flags(IDPOPT_MBROFF|IDPOPT_CST), params(_p1, _p2) {}

  int type() const { return flags & 0xf; }
  int qualifier() const { return flags & 0xf000000; }
  bool is_mbroff() const { return (flags & IDPOPT_MBROFF) != 0; }
  bool get_number(
        int64 *out,
        lexer_t *lx,
        const token_t &_t,
        int range_bit,
        int usign_bit) const;
  const char *apply(int vtype, const void *vdata, void *obj=nullptr) const
  {
    return cfgopt_t__apply3(this, nullptr, vtype, vdata, obj);
  }
  const char *apply(lexer_t *lx, int vtype, const void *vdata, void *obj=nullptr) const
  {
    return cfgopt_t__apply3(this, lx, vtype, vdata, obj);
  }
};

enum cfg_input_kind_t
{
  cik_string = 0,
  cik_filename,
  cik_path,
};

/// Parse the input, and apply options.
///
/// \param input      input file name, or string
/// \param input_kind is input a string, filename or file path
/// \param opts       options destcriptions
/// \param nopts      the number of entries present in the 'opts' array
/// \param defhdlr    a handler to be called, if a directive couldn't be found in 'opts'
/// \param defines    a list of preprocessor identifiers to define (so it is
///                   possible to use #ifdef checks in the file.)
///                   NB: the actual identifier defined by the parser will be
///                   surrounded with double underscores (e.g., passing 'FOO'
///                   will result in '__FOO__' being defined)
///                   Additionally, the parser will also define a similar macro
///                   with the current processor name (e.g., __ARM__)
/// \param ndefines   the number of defines in the list
/// \param obj        see cfgopt_t constructor based on the offset of a structure member
/// \return true if parsing finished without errors, false if there was a
///         syntax error, callback returned an error, or no file was found
///         at all.

idaman bool ida_export read_config(
        const char *input,
        cfg_input_kind_t input_kind,
        const cfgopt_t opts[],
        size_t nopts,
        cfgopt_handler_t *defhdlr,
        const char *const *defines = nullptr,
        size_t ndefines = 0);

idaman bool ida_export read_config2(
        const char *input,
        cfg_input_kind_t input_kind,
        const cfgopt_t opts[],
        size_t nopts,
        cfgopt_handler_t *defhdlr,
        const char *const *defines = nullptr,
        size_t ndefines = 0,
        void *obj = nullptr);

inline bool read_config_file2(
        const char *filename,
        const cfgopt_t opts[],
        size_t nopts,
        cfgopt_handler_t *defhdlr,
        const char *const *defines = nullptr,
        size_t ndefines = 0,
        void *obj = nullptr)
{
  return read_config2(filename, cik_filename, opts, nopts, defhdlr, defines, ndefines, obj);
}

/// Search for all IDA system files with the given name.
/// This function will search, in that order, for the following files:
///   -# %IDADIR%/cfg/<file>
///   -# for each directory 'ONEDIR' in %IDAUSR%: %ONEDIR%/cfg/<file>
///
/// For each directive in each of those files, the same processing as
/// that of read_config will be performed.

inline bool read_config_file(
        const char *filename,
        const cfgopt_t opts[],
        size_t nopts,
        cfgopt_handler_t *defhdlr,
        const char *const *defines = nullptr,
        size_t ndefines = 0)
{
  return read_config(filename, cik_filename, opts, nopts, defhdlr, defines, ndefines);
}


/// For each directive in 'string', the same processing as that of
/// read_config will be performed.
inline bool read_config_string(
        const char *string,
        const cfgopt_t opts[],
        size_t nopts,
        cfgopt_handler_t *defhdlr,
        const char *const *defines = nullptr,
        size_t ndefines = 0)
{
  return read_config(string, cik_string, opts, nopts, defhdlr, defines, ndefines);
}


typedef void idaapi config_changed_cb_t(const cfgopt_t &opt, int vtype, const void *vdata);

/// Register array of config options.
/// This function can be used by a plugin to register the config options.
/// After registering an option, it becomes usable by the
/// process_config_directive() function.
/// \param opts array of config options
/// \param nopts number of options to install. 0 means uninstall
/// \param cb callback that will be invoked upon changing a config option
/// \param obj see cfgopt_t constructor based on the offset of a structure member
/// \return success

idaman bool ida_export register_cfgopts(
        const cfgopt_t opts[],
        size_t nopts,
        config_changed_cb_t cb=nullptr,
        void *obj=nullptr);

/// Get json value from ida.cfg
/// \param out returned json value
/// \param key configuration key
/// \return success

idaman bool ida_export get_config_value(jvalue_t *out, const char *key);

//-------------------------------------------------------------------------
// A set of (static const) config options
struct cfgopt_set_t
{
  const cfgopt_t *opts = nullptr;
  size_t nopts = 0;
  config_changed_cb_t *cb = nullptr;
  void *obj = nullptr;
};
struct cfgopt_set_vec_t : public qvector<cfgopt_set_t> {};


#endif // _CONFIG_HPP
