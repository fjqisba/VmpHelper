/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _PRO_H
#define _PRO_H

/*! \file pro.h

  \brief This is the first header included in the IDA project.

  It defines the most common types, functions and data.
  Also, it tries to make system dependent definitions.

  The following preprocessor macros are used in the project
  (the list may be incomplete)

  Platform must be specified as one of:

   __NT__      - MS Windows (all platforms)                  \n
   __LINUX__   - Linux                                       \n
   __MAC__     - MAC OS X

   __EA64__    - 64-bit address size (sizeof(ea_t)==8)       \n

   __X86__     - 32-bit debug servers (sizeof(void*)==4)     \n
   __X64__     - x64 processor (sizeof(void*)==8) default    \n
   __PPC__     - PowerPC                                     \n
   __ARM__     - ARM
*/

/// IDA SDK v8.3
#define IDA_SDK_VERSION      830

//---------------------------------------------------------------------------
#if !defined(__NT__) && !defined(__LINUX__) && !defined(__MAC__)
#  if defined(_MSC_VER)
#    define __NT__
#  elif defined(__APPLE__)
#    define __MAC__
#  elif defined(__linux__)
#    define __LINUX__
#  else
#    error "Please define one of: __NT__, __LINUX__, __MAC__"
#  endif
#endif

// Linux or Mac imply Unix
#if defined(__LINUX__) || defined(__MAC__)
#define __UNIX__
#endif

/// \def{BADMEMSIZE, Invalid memory size}
#ifndef __X86__
#define BADMEMSIZE 0x7FFFFFFFFFFFFFFFull
#else
#define BADMEMSIZE 0x7FFFFFFFul
#endif

/// \def{ENUM_SIZE, Specify size of enum values}
#define ENUM_SIZE(t) : t

// this is necessary to have S_IFMT, S_IFREG and S_IFDIR defined in windows
// in order to define S_ISDIR and S_ISREG
#define _CRT_DECLARE_NONSTDC_NAMES 1
#ifndef SWIG
#include <stdlib.h>     /* size_t, nullptr, memory */
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <assert.h>
#include <limits.h>
#include <ctype.h>
#include <time.h>
#include <stdint.h>
#ifdef __cplusplus
#include <new>
#include <string>
#endif
#if defined(__NT__)
#  include <malloc.h>
#endif

/// \def{WIN32_LEAN_AND_MEAN, compile faster}
#if defined(_MSC_VER)
#  define WIN32_LEAN_AND_MEAN
#  include <string.h>
#  include <io.h>
#  include <direct.h>
#else
#  include <wchar.h>
#  include <string.h>
#  include <unistd.h>
#  include <sys/stat.h>
#  include <errno.h>
#endif
#ifdef __cplusplus
#  include <set>
#  include <map>
#  include <algorithm>
#endif
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#endif // SWIG

#define STL_SUPPORT_PRESENT

//---------------------------------------------------------------------------
/// \def{EXTERNC,       specify C linkage}
/// \def{C_INCLUDE,     helper for 'extern "C" {}' statements}
/// \def{C_INCLUDE_END, \copydoc C_INCLUDE}
/// \def{INLINE,        inline keyword for c++}
#if defined(__cplusplus) || defined(SWIG)
#define EXTERNC         extern "C"
#define C_INCLUDE       EXTERNC \
   {

#define C_INCLUDE_END   }
#define INLINE          inline
#else
#define EXTERNC
#define C_INCLUDE
#define C_INCLUDE_END
#define INLINE          __inline
#endif

//---------------------------------------------------------------------------
#ifndef MAXSTR
#define MAXSTR 1024                ///< maximum string size
#endif

#define SMAXSTR QSTRINGIZE(MAXSTR) ///< get #MAXSTR as a string

/// \def{NT_CDECL, Some NT functions require __cdecl calling convention}
#ifdef __NT__
#define NT_CDECL __cdecl
#else
#define NT_CDECL
#endif

/// \def{DEPRECATED, identifies parts of the IDA API that are considered deprecated}
/// \def{NORETURN,   function does not return}
/// \def{PACKED,     type is packed}
/// \def{PACKED_ALIGNED, type is packed but its start address is aligned}
/// \def{AS_PRINTF,  function accepts printf-style format and args}
/// \def{AS_SCANF,   function accepts scanf-style format and args}
/// \def{WARN_UNUSED_RESULT, warn if a function returns a result that is never used}
#if defined(SWIG)
#define constexpr
#define DEPRECATED
#define NORETURN
#define PACKED
#define PACKED_ALIGNED(al)
#define AS_STRFTIME(format_idx)
#define AS_PRINTF(format_idx, varg_idx)
#define AS_SCANF(format_idx, varg_idx)
#define WARN_UNUSED_RESULT
#elif defined(__GNUC__)
#define DEPRECATED __attribute__((deprecated))
#define NORETURN  __attribute__((noreturn))
#define PACKED __attribute__((__packed__))
#define PACKED_ALIGNED(al) __attribute__((__packed__)) __attribute__((__aligned__(al)))
#define AS_STRFTIME(format_idx) __attribute__((format(strftime, format_idx, 0)))
#define AS_PRINTF(format_idx, varg_idx) __attribute__((format(printf, format_idx, varg_idx)))
#define AS_SCANF(format_idx, varg_idx)  __attribute__((format(scanf, format_idx, varg_idx)))
#define WARN_UNUSED_RESULT __attribute__((__warn_unused_result__))
#else
#define DEPRECATED __declspec(deprecated)
#define NORETURN  __declspec(noreturn)
#define PACKED
#define PACKED_ALIGNED(al)
#define AS_STRFTIME(format_idx)
#define AS_PRINTF(format_idx, varg_idx)
#define AS_SCANF(format_idx, varg_idx)
#define WARN_UNUSED_RESULT _Check_return_
#endif

/// \def{GCC_DIAG_OFF, disable a specific GCC warning for the following code}
/// \def{GCC_DIAG_ON,  enable or restore a specific GCC warning for the following code}
#if defined(__GNUC__) && !defined(SWIG) && ((__GNUC__ * 100) + __GNUC_MINOR__) >= 402
#define GCC_DIAG_JOINSTR(x,y) _QSTRINGIZE(x ## y)
#  define GCC_DIAG_DO_PRAGMA(x) _Pragma (#x)
#  define GCC_DIAG_PRAGMA(x) GCC_DIAG_DO_PRAGMA(GCC diagnostic x)
#  if (((__GNUC__ * 100) + __GNUC_MINOR__) >= 406) || defined(__clang__)
#    define GCC_DIAG_OFF(x) GCC_DIAG_PRAGMA(push) \
                            GCC_DIAG_PRAGMA(ignored GCC_DIAG_JOINSTR(-W,x))
#    define GCC_DIAG_ON(x)  GCC_DIAG_PRAGMA(pop)
#  else
#    define GCC_DIAG_OFF(x) GCC_DIAG_PRAGMA(ignored GCC_DIAG_JOINSTR(-W,x))
#    define GCC_DIAG_ON(x)  GCC_DIAG_PRAGMA(warning GCC_DIAG_JOINSTR(-W,x))
#  endif
#else
#  define GCC_DIAG_OFF(x)
#  define GCC_DIAG_ON(x)
#endif

#if defined(_MSC_VER)
#  define MSC_DIAG_OFF(x) __pragma(warning(push)) \
                          __pragma(warning(disable : x))
#  define MSC_DIAG_ON(x)  __pragma(warning(pop))
#else
#  define MSC_DIAG_OFF(x)
#  define MSC_DIAG_ON(x)
#endif

// A function attribute to disable ASAN
#if defined(__clang__) || defined (__GNUC__)
# define DISABLE_ASAN __attribute__((no_sanitize_address))
#else
# define DISABLE_ASAN
#endif

#if defined(DONT_DEPRECATE)
#undef DEPRECATED
#define DEPRECATED
#endif

//---------------------------------------------------------------------------

#define __MF__  0             ///< byte sex of our platform (Most significant byte First).
                              ///<   0: little endian (Intel 80x86).
                              ///<   1: big endian (PowerPC).

//---------------------------------------------------------------------------
/// Macro to avoid of message 'Parameter x is never used'
#define qnotused(x)   (void)x

#ifdef __clang__
#  define NONNULL _Nonnull
#else
#  define NONNULL
#endif

// this macro can be used as a suffix for declarations/definitions instead of qnotused()
#if defined(__clang__) || defined(__GNUC__)
# define QUNUSED  __attribute__((unused))
#else
# define QUNUSED
#endif

/// \def{va_argi, GNU C complains about some data types in va_arg because they are promoted to int and proposes to replace them by int}
#ifdef __GNUC__
#define va_argi(va, type)  ((type)va_arg(va, int))
#else
#define va_argi(va, type)  va_arg(va, type)
#endif

//---------------------------------------------------------------------------
#define CONST_CAST(x)   const_cast<x>   ///< cast a const to non-const
#define _QSTRINGIZE(x)  #x              ///< return x as a string. See #SMAXSTR for example
#define QSTRINGIZE(x)   _QSTRINGIZE(x)  ///< see #_QSTRINGIZE

//---------------------------------------------------------------------------

/// \def{idaapi,          specifies __stdcall calling convention}
/// \def{ida_export,      functions marked with this keyword are available as part of the IDA SDK}
/// \def{idaman,          specifies c linkage}
/// \def{ida_export_data, data items marked with this keyword are available as part of the IDA SDK}
/// \def{ida_module_data, identifies a data item that will be exported}
/// \def{ida_local,       identifies a non-public type definition}
#if defined(SWIG)                       // for SWIG
  #define idaapi
  #define idaman
  #define ida_export
  #define ida_export_data
  #define ida_module_data
  #define __fastcall
  #define ida_local
#elif defined(APIDEF)                   // for API DEF files
  #define idaapi
  #define idaman
  #define ida_export      ida_export
  #define ida_export_data ida_export_data
  #define ida_module_data
  #define __fastcall
  #define ida_local
#elif defined(__NT__)                   // MS Windows
  #define idaapi            __stdcall
  #define ida_export        idaapi
  #ifdef __CODE_CHECKER__
    // tell lint that this function will be exported
    #define idaman EXTERNC __declspec(dllexport)
  #else
    #define idaman EXTERNC
  #endif
  #if defined(__KERNEL__)               // kernel
    #define ida_export_data
    #define ida_module_data
  #else                                 // modules
    #define ida_export_data __declspec(dllimport)
    #define ida_module_data __declspec(dllexport)
  #endif
  #define ida_local
#elif defined(__UNIX__)                 // for unix
  #define idaapi
  #if defined(__MAC__)
    #define idaman            EXTERNC __attribute__((visibility("default")))
    #define ida_local         __attribute__((visibility("hidden")))
  #else
    #if __GNUC__ >= 4
      #define idaman          EXTERNC __attribute__ ((visibility("default")))
      #define ida_local       __attribute__((visibility("hidden")))
    #else
      #define idaman          EXTERNC
      #define ida_local
    #endif
  #endif
  #define ida_export
  #define ida_export_data
  #define ida_module_data
  #define __fastcall
#endif

/// Functions callable from any thread are marked with this keyword
#define THREAD_SAFE

/// This keyword is used to introduce new virtual functions that do not override
/// any existing virtual function
#define newapi

//---------------------------------------------------------------------------
#ifndef __cplusplus
typedef int bool;   //-V607 Ownerless typedef
#define false 0
#define true 1
#endif

//---------------------------------------------------------------------------
// Linux C mode compiler already has these types defined
#if !defined(__LINUX__) || defined(__cplusplus)
typedef unsigned char  uchar;   ///< unsigned 8 bit value
typedef unsigned short ushort;  ///< unsigned 16 bit value
typedef unsigned int   uint;    ///< unsigned 32 bit value
#endif

typedef          char   int8;   ///< signed 8 bit value
typedef signed   char   sint8;  ///< signed 8 bit value
typedef unsigned char   uint8;  ///< unsigned 8 bit value
typedef          short  int16;  ///< signed 16 bit value
typedef unsigned short  uint16; ///< unsigned 16 bit value
typedef          int    int32;  ///< signed 32 bit value
typedef unsigned int    uint32; ///< unsigned 32 bit value

#include <llong.hpp>


/// \fn{int64 qatoll(const char *nptr), Convert string to 64 bit integer}
#if defined(__UNIX__)
INLINE int64 qatoll(const char *nptr) { return nptr != nullptr ? atoll(nptr) :0; }
#elif defined(_MSC_VER)
INLINE int64 qatoll(const char *nptr) { return nptr != nullptr ? _atoi64(nptr) :0; }
#else
INLINE int64 qatoll(const char *nptr) { return nptr != nullptr ? atol(nptr) : 0; }
#endif

// VS2010 lacks strtoull
#ifdef _MSC_VER
#define strtoull _strtoui64
#endif

/// \typedef{wchar16_t, 2-byte char}
/// \typedef{wchar32_t, 4-byte char}
#if defined(_MSC_VER)
typedef wchar_t         wchar16_t;
typedef uint32          wchar32_t;
#elif defined(__GNUC__)
typedef uint16          wchar16_t;
typedef uint32          wchar32_t;
#endif

/// Signed size_t - used to check for size overflows when the counter becomes
/// negative. Also signed size_t allows us to signal an error condition using
/// a negative value, for example, as a function return value.
#if !defined(_SSIZE_T_DEFINED) && !defined(__ssize_t_defined) && !defined(__GNUC__)
typedef ptrdiff_t ssize_t;
#endif

/// \def{FMT_64, compiler-specific printf format specifier for 64-bit numbers}
/// \def{FMT_Z,  compiler-specific printf format specifier for size_t}
/// \def{FMT_ZX, compiler-specific printf format specifier for size_t, hex}
/// \def{FMT_ZS, compiler-specific printf format specifier for ssize_t}
#if defined(__GNUC__) && !defined(__MINGW32__)
  #define FMT_64 "ll"
  #define FMT_Z  "zu"
  #define FMT_ZX "zX"
  #define FMT_ZS "zd"
#elif defined(_MSC_VER) && _MSC_VER >= 1900
  #define FMT_64 "I64"
  #define FMT_Z  "zu"
  #define FMT_ZX "zX"
  #define FMT_ZS "td"
#elif defined(_MSC_VER) || defined(__MINGW32__)
  #define FMT_64 "I64"
  #ifndef __X86__
    #define FMT_Z  "I64u"
    #define FMT_ZX "I64X"
    #define FMT_ZS "I64d"
  #else
    #define FMT_Z  "u"
    #define FMT_ZX "X"
    #define FMT_ZS "d"
  #endif
#elif !defined(SWIG)
  #error "unknown compiler"
#endif

/// \typedef{ea_t,    effective address}
/// \typedef{sel_t,   segment selector}
/// \typedef{asize_t, memory chunk size}
/// \typedef{adiff_t, address difference}
/// \def{SVAL_MIN, minimum value for an object of type int}
/// \def{SVAL_MAX, maximum value for an object of type int}
/// \def{FMT_EA,   format specifier for ::ea_t values}
#ifdef __EA64__
  typedef uint64 ea_t;
  typedef uint64 sel_t;
  typedef uint64 asize_t;
  typedef int64 adiff_t;
  #define FMT_EA FMT_64
  #ifdef __GNUC__
    #define SVAL_MIN LLONG_MIN
    #define SVAL_MAX LLONG_MAX
  #else
    #define SVAL_MIN _I64_MIN
    #define SVAL_MAX _I64_MAX
  #endif
#else
  typedef uint32 ea_t;
  typedef uint32 sel_t;
  typedef uint32 asize_t;
  typedef int32 adiff_t;
  #define SVAL_MIN INT_MIN
  #define SVAL_MAX INT_MAX
  #define FMT_EA ""
#endif

typedef asize_t uval_t;   ///< unsigned value used by the processor.
                          ///<  - for 32-bit ::ea_t - ::uint32
                          ///<  - for 64-bit ::ea_t - ::uint64
typedef adiff_t sval_t;   ///< signed value used by the processor.
                          ///<  - for 32-bit ::ea_t - ::int32
                          ///<  - for 64-bit ::ea_t - ::int64

typedef uint32 ea32_t;    ///< 32-bit address, regardless of IDA bitness.
                          ///< this type can be used when we know in advance
                          ///< that 32 bits are enough to hold an address.
typedef uint64 ea64_t;    ///< 64-bit address, regardless of IDA bitness.
                          ///< we need this type for interoperability with
                          ///< debug servers, lumina, etc

/// Error code (errno)
typedef int error_t;

typedef uint8 op_dtype_t;

/// The inode_t type is the specialization specific inode number.
/// For example, it can represent a local type ordinal or a structure id.
typedef uval_t inode_t;

// A position in the difference source.
// This is an abstract value that depends on the difference source.
// It should be something that can be used to conveniently retrieve information
// from a difference source. For example, for the name list it can be the index
// in the name list. For structure view it can be the position in the list of structs.
// Please note that this is not necessarily an address. However, for the purpose
// of comparing the contents of the disassembly listing it can be an address.
//
// diffpos_t instances must have the following property: adding or removing
// items to diff_source_t should not invalidate the existing diffpos_t instances.
// They must stay valid after adding or removing items to diff_source_t.
// Naturally, deleting an item pointed by diffpos_t may render it incorrect,
// this is acceptable and expected.
typedef size_t diffpos_t;
constexpr diffpos_t BADDIFF = diffpos_t(-1);

#ifdef __cplusplus
#define DEFARG(decl, val) decl = val
#else
#define DEFARG(decl, val) decl
#endif

#ifndef SWIG
#define BADADDR ea_t(-1)  ///< this value is used for 'bad address'
#define BADSEL  sel_t(-1) ///< 'bad selector' value
#define BADADDR32 ea32_t(-1ULL)
#define BADADDR64 ea64_t(-1ULL)

//-------------------------------------------------------------------------
// Time related functions

typedef int32 qtime32_t;  ///< we use our own time type because time_t
                          ///< can be 32-bit or 64-bit depending on the compiler
typedef uint64 qtime64_t; ///< 64-bit time value expressed as seconds and
                          ///< microseconds since the Epoch

/// Get the 'seconds since the epoch' part of a qtime64_t

INLINE THREAD_SAFE uint32 get_secs(qtime64_t t)
{
  return (uint32)(t>>32);
}


/// Get the microseconds part of a qtime64_t

INLINE THREAD_SAFE uint32 get_usecs(qtime64_t t)
{
  return (uint32)(t);
}


/// Get a ::qtime64_t instance from a seconds value and microseconds value.
/// \param secs   seconds
/// \param usecs  microseconds

INLINE THREAD_SAFE qtime64_t make_qtime64(uint32 secs, DEFARG(int32 usecs, 0))
{
  return ((qtime64_t)(secs) << 32) | usecs;
}


/// Converts calendar time into a string.
/// Puts 'wrong timestamp\\n' into the buffer if failed
/// \param buf      output buffer
/// \param bufsize  size of the output buffer
/// \param t        calendar time
/// \return success
/// See also qstrftime()

idaman THREAD_SAFE bool ida_export qctime(char *buf, size_t bufsize, qtime32_t t);


/// Converts calendar time into a string using Coordinated Universal Time (UTC).
/// Function is equivalent to asctime(gmtime(t)).
/// Puts 'wrong timestamp\\n' into the buffer if failed.
/// \param buf      output buffer
/// \param bufsize  of the output buffer
/// \param t        calendar time
/// \return success

idaman THREAD_SAFE bool ida_export qctime_utc(char *buf, size_t bufsize, qtime32_t t);


/// Converts a time value to a tm structure (local time)
/// \param[out] _tm  result
/// \param t         calendar time
/// \returns success

idaman THREAD_SAFE bool ida_export qlocaltime(struct tm *_tm, qtime32_t t);


/// Same as qlocaltime(struct tm *, qtime32_t), but accepts a 64-bit time value

INLINE THREAD_SAFE bool qlocaltime64(struct tm *_tm, qtime64_t t)
{
  return qlocaltime(_tm, get_secs(t));
}


/// Converts a time value to a tm structure (UTC time)
/// \param[out] _tm  result
/// \param t         calendar time
/// \returns success

idaman bool ida_export qgmtime(struct tm *_tm, qtime32_t t);


/// Same as qgmtime(struct tm *, qtime32_t), but accepts a 64-bit time value

INLINE THREAD_SAFE bool qgmtime64(struct tm *_tm, qtime64_t t)
{
  return qgmtime(_tm, get_secs(t));
}


// Inverse of qgmtime()

idaman qtime32_t ida_export qtimegm(const struct tm *ptm);


/// Get string representation of a qtime32_t (local time)
/// Copies into 'buf' the content of 'format', expanding its format specifiers into the
/// corresponding values that represent the time described in 't', with a limit of 'bufsize' characters
/// see http://www.cplusplus.com/reference/ctime/strftime/ for more
/// \param buf      output buffer
/// \param bufsize  of the output buffer
/// \param format   format string
/// \param t        calendar time value
/// \return length of the resulting string
/// See also qctime()

idaman AS_STRFTIME(3) THREAD_SAFE size_t ida_export qstrftime(
        char *buf,
        size_t bufsize,
        const char *format,
        qtime32_t t);


/// Same as qstrftime(), but accepts a 64-bit time value

idaman AS_STRFTIME(3) THREAD_SAFE size_t ida_export qstrftime64(
        char *buf,
        size_t bufsize,
        const char *format,
        qtime64_t t);


/// Suspend execution for given number of milliseconds

idaman THREAD_SAFE void ida_export qsleep(int milliseconds);


/// High resolution timer.
/// On Unix systems, returns current time in nanoseconds.
/// On Windows, returns a high resolution counter (QueryPerformanceCounter)
/// \return stamp in nanoseconds

idaman THREAD_SAFE uint64 ida_export get_nsec_stamp(void);

/// Get the current time with microsecond resolution (in fact the resolution
/// is worse on windows)

idaman THREAD_SAFE qtime64_t ida_export qtime64(void);


/// Generate a random buffer.
/// \param[out] buffer  pointer to result
/// \param bufsz        size of buffer
/// \return success

idaman THREAD_SAFE bool ida_export gen_rand_buf(void *buffer, size_t bufsz);


#define qoff64_t int64        ///< file offset

/// Describes miscellaneous file attributes
struct qstatbuf
{
  uint64    qst_dev;     ///< ID of device containing file
  uint32    qst_ino;     ///< inode number
  uint32    qst_mode;    ///< protection
  uint32    qst_nlink;   ///< number of hard links
  uint32    qst_uid;     ///< user ID of owner
  uint32    qst_gid;     ///< group ID of owner
  uint64    qst_rdev;    ///< device ID (if special file)
  qoff64_t  qst_size;    ///< total size, in bytes
  int32     qst_blksize; ///< blocksize for file system I/O
  int32     qst_blocks;  ///< number of 512B blocks allocated
  qtime64_t qst_atime;   ///< time of last access
  qtime64_t qst_mtime;   ///< time of last modification
  qtime64_t qst_ctime;   ///< time of last status change
};

// non standard functions are missing:
#ifdef _MSC_VER
#if _MSC_VER <= 1200
#  define for if(0); else for    ///< MSVC <= 1200 is not compliant to the ANSI standard
#else
#  pragma warning(disable : 4200) ///< zero-sized array in structure (non accept from cmdline)
#  if _MSC_VER >= 1921 && _MSC_VER < 1924 // avoid compiler bug:
#    pragma function(memmove) // https://developercommunity.visualstudio.com/content/problem/583227/vs-2019-cl-1921277022-memmove-instrinsic-optimizat.html
#  endif
#endif
/// \name VS posix names
/// Shut up Visual Studio (VS deprecated posix names but there seems to be no good reason for that)
//@{
#define chdir  _chdir
#define fileno _fileno
#define getcwd _getcwd
#define memicmp _memicmp
#  define  F_OK   0
#  define  W_OK   2
#  define  R_OK   4
//@}
#endif

/// Is this IDA kernel? If not, we are executing a standalone application
idaman bool ida_export_data is_ida_kernel;

//---------------------------------------------------------------------------
/* error codes */
/*--------------------------------------------------*/

#define eOk           0    ///< no error
#define eOS           1    ///< os error, see errno
#define eDiskFull     2    ///< disk full
#define eReadError    3    ///< read error
#define eFileTooLarge 4    ///< file too large


/// Set qerrno

idaman THREAD_SAFE error_t ida_export set_qerrno(error_t code);


/// Get qerrno

idaman THREAD_SAFE error_t ida_export get_qerrno(void);

//---------------------------------------------------------------------------
// debugging macros
/// \def{ZZZ, debug print}
/// \def{BPT, trigger a breakpoint from IDA. also see #INTERR}
#define ZZZ msg("%s:%d\n", __FILE__, __LINE__)
#if defined(__GNUC__)
#  define BPT __builtin_trap()
#elif defined(_MSC_VER) // Visual C++
#  define BPT __debugbreak()
#  ifdef __CODE_CHECKER__
     NORETURN void __debugbreak(void);
#  endif
#endif

/// \def{CASSERT, results in a compile error if the cnd is not true}
#ifdef __CODE_CHECKER__
#define CASSERT(cnd) extern int pclint_cassert_dummy_var
#else
#define CASSERT(cnd) static_assert((cnd), QSTRINGIZE(cnd))
#endif

/// \def{INTERR, Show internal error message and terminate execution abnormally.
///              When IDA is being run under a debugger this will ensure that
///              the debugger will break immediately.}
#ifdef __CODE_CHECKER__
#define INTERR(code) interr(code)
#else
#define INTERR(code) do { if ( under_debugger ) BPT; interr(code); } while(1)
#endif

#define QASSERT(code, cond) do if ( !(cond) ) INTERR(code); while (0)                 ///< run time assertion
#define QBUFCHECK(buf, size, src) ida_fill_buffer(buf, size, src, __FILE__, __LINE__) ///< run time assertion
idaman bool ida_export_data under_debugger;                                           ///< is IDA running under a debugger?

#define INTERR_EXC_FMT "Internal error %d occurred when running a script. Either\n" \
  "  - the script misused the IDA API, or\n"                            \
  "  - there is a logic error in IDA\n"                                 \
  "Please check the script first.\n"                                    \
  "If it appears correct, send a bug report to <support@hex-rays.com>.\n" \
  "In any case we strongly recommend you to restart IDA as soon as possible."

#ifdef __cplusplus
struct interr_exc_t : public std::exception
{
  int code;
  interr_exc_t(int _code) : code(_code) {}
};
#endif // __cplusplus
idaman THREAD_SAFE NORETURN void ida_export interr(int code);                         ///< Show internal error message and terminate execution

// set the behavior of 'interr()'
/// \param enable  if true, interr() throws interr_exc_t
///                otherwise it terminates IDA after showing an error message
/// \return previous setting
idaman THREAD_SAFE bool ida_export set_interr_throws(bool enable);

//---------------------------------------------------------------------------
idaman THREAD_SAFE void *ida_export qalloc(size_t size);                              ///< System independent malloc
idaman THREAD_SAFE void *ida_export qrealloc(void *alloc, size_t newsize);            ///< System independent realloc
idaman THREAD_SAFE void *ida_export qcalloc(size_t nitems, size_t itemsize);          ///< System independent calloc
idaman THREAD_SAFE void  ida_export qfree(void *alloc);                               ///< System independent free
idaman THREAD_SAFE char *ida_export qstrdup(const char *string);                      ///< System independent strdup
#define qnew(t)        ((t*)qalloc(sizeof(t)))  ///< create a new object in memory
/// \def{qnewarray, qalloc_array() is safer than qnewarray}
#define qnewarray(t,n)  use_qalloc_array

/// Use this class to avoid integer overflows when allocating arrays
#ifdef __cplusplus
template <class T>
T *qalloc_array(size_t n)
{
  return (T *)qcalloc(n, sizeof(T));
}

/// Use this class to avoid integer overflows when allocating arrays
template <class T>
T *qrealloc_array(T *ptr, size_t n)
{
  size_t nbytes = n * sizeof(T);
  if ( nbytes < n )
    return nullptr; // integer overflow
  return (T *)qrealloc(ptr, nbytes);
}

/// \def{qnumber, determine capacity of an array}
#ifdef __GNUC__
#  define qnumber(arr) ( \
    0 * sizeof(reinterpret_cast<const ::qnumber_check_type *>(arr)) \
  + 0 * sizeof(::qnumber_check_type::check_type((arr), &(arr))) \
  + sizeof(arr) / sizeof((arr)[0]) )
  struct qnumber_check_type
  {
    struct is_pointer;
    struct is_array {};
    template <typename T>
    static is_pointer check_type(const T *, const T *const *);
    static is_array check_type(const void *, const void *);
  };
#elif defined(_MSC_VER) && !defined(__CODE_CHECKER__)
#  define qnumber(array) _countof(array)
#else // poor man's implementation for other compilers and lint
#  define qnumber(array) (sizeof(array)/sizeof(array[0]))
#endif
#endif // __cplusplus

#define qoffsetof offsetof

/// \def{set_vva, extracts a va_list passed as a variadic function argument}
/// \def{va_copy, copy a va_list}
#if defined(__GNUC__) && !defined(__X86__) && !(defined(__clang__) && defined(__ARM__))
  // gcc64 and clang x86_64 use special array-type va_list, so we have to resort to tricks like these
  #define set_vva(va2, vp) va_copy(va2, *(va_list*)va_arg(vp, void*))
#else
  #ifndef va_copy
    #define va_copy(dst, src) dst = src
  #endif
  #if defined(__clang__)
    #define set_vva(va2, vp) va2 = va_arg(vp, va_list)
  #else
    #define set_vva(va2, vp) va_copy(va2, va_arg(vp, va_list))
  #endif
#endif


/// Reverse memory block.
/// Analog of strrev() function
/// \param buf   pointer to buffer to reverse
/// \param size  size of buffer
/// \return pointer to buffer

idaman THREAD_SAFE void *ida_export memrev(void *buf, ssize_t size);

#if defined(__GNUC__) && !defined(_WIN32)
idaman THREAD_SAFE int ida_export memicmp(const void *x, const void *y, size_t size);
#endif

//---------------------------------------------------------------------------
/* strings */
/// \def{strnicmp, see 'VS posix names'}
/// \def{stricmp,  see 'VS posix names'}
#ifdef __GNUC__
#define strnicmp strncasecmp
#define stricmp  strcasecmp
#elif defined(_MSC_VER)
#define strnicmp _strnicmp
#define stricmp  _stricmp
#endif


/// Replace all occurrences of a character within a string.
/// \param str     to modify
/// \param char1   char to be replaced
/// \param char2   replacement char
/// \return pointer to resulting string

idaman THREAD_SAFE char *ida_export strrpl(char *str, int char1, int char2);


/// Get tail of a string
INLINE THREAD_SAFE char *tail(char *str) { return strchr(str, '\0'); }
#ifdef __cplusplus
/// \copydoc tail(char *)
inline THREAD_SAFE const char *tail(const char *str) { return strchr(str, '\0'); }
#endif


/// A safer strncpy - makes sure that there is a terminating zero.
/// nb: this function doesn't fill the whole buffer zeroes as strncpy does
/// nb: ssize_t(dstsize) must be > 0

idaman THREAD_SAFE char *ida_export qstrncpy(char *dst, const char *src, size_t dstsize);


/// A safer stpncpy - returns pointer to the end of the destination
/// nb: ssize_t(dstsize) must be > 0

idaman THREAD_SAFE char *ida_export qstpncpy(char *dst, const char *src, size_t dstsize);


/// A safer strncat - accepts the size of the 'dst' as 'dstsize' and returns dst
/// nb: ssize_t(dstsize) must be > 0

idaman THREAD_SAFE char *ida_export qstrncat(char *dst, const char *src, size_t dstsize);


/// Thread-safe version of strtok

idaman THREAD_SAFE char *ida_export qstrtok(char *s, const char *delim, char **save_ptr);


/// Convert the string to lowercase

idaman THREAD_SAFE char *ida_export qstrlwr(char *str);


/// Convert the string to uppercase

idaman THREAD_SAFE char *ida_export qstrupr(char *str);


/// Find one string in another (Case insensitive analog of strstr()).
/// \param s1  string to be searched
/// \param s2  string to search for
/// \return a pointer to the first occurrence of s2 within s1, nullptr if none exists

idaman THREAD_SAFE const char *ida_export stristr(const char *s1, const char *s2);


#ifdef __cplusplus
/// Same as stristr(const char *, const char *) but returns a non-const result
inline char *idaapi stristr(char *s1, const char *s2) { return CONST_CAST(char *)(stristr((const char *)s1, s2)); }
#endif

/// \defgroup ctype Functions to test ASCII char attributes
/// The is...() functions in ctype.h will misbehave with 'char' argument. We introduce more robust functions.
/// These functions only operate on ascii chars and are intended to be locale-independent.
//@{
INLINE THREAD_SAFE bool ida_local qisascii(char c)  { return (c & ~0x7f) == 0; }
INLINE THREAD_SAFE bool ida_local qisspace(char c)  { return qisascii(c) && isspace((uchar)(c)) != 0; }
INLINE THREAD_SAFE bool ida_local qisalpha(char c)  { return qisascii(c) && isalpha((uchar)(c)) != 0; }
INLINE THREAD_SAFE bool ida_local qisalnum(char c)  { return qisascii(c) && isalnum((uchar)(c)) != 0; }
INLINE THREAD_SAFE bool ida_local qispunct(char c)  { return qisascii(c) && ispunct((uchar)(c)) != 0; }
INLINE THREAD_SAFE bool ida_local qislower(char c)  { return qisascii(c) && islower((uchar)(c)) != 0; }
INLINE THREAD_SAFE bool ida_local qisupper(char c)  { return qisascii(c) && isupper((uchar)(c)) != 0; }
INLINE THREAD_SAFE bool ida_local qisprint(char c)  { return qisascii(c) && isprint((uchar)(c)) != 0; }
INLINE THREAD_SAFE bool ida_local qisdigit(char c)  { return qisascii(c) && isdigit((uchar)(c)) != 0; }
INLINE THREAD_SAFE bool ida_local qisxdigit(char c) { return qisascii(c) && isxdigit((uchar)(c)) != 0; }
//@}

/// Get lowercase equivalent of given char
INLINE THREAD_SAFE int ida_local qtolower(char c) { return tolower((uchar)(c)); }
/// Get uppercase equivalent of given char
INLINE THREAD_SAFE int ida_local qtoupper(char c) { return toupper((uchar)(c)); }

// We forbid using dangerous functions in IDA
#if !defined(USE_DANGEROUS_FUNCTIONS) && !defined(__CODE_CHECKER__)
#undef strcpy
#define strcpy          dont_use_strcpy            ///< use qstrncpy()
#define stpcpy          dont_use_stpcpy            ///< use qstpncpy()
#define strncpy         dont_use_strncpy           ///< use qstrncpy()
#define strcat          dont_use_strcat            ///< use qstrncat()
#define strncat         dont_use_strncat           ///< use qstrncat()
#define gets            dont_use_gets              ///< use qfgets()
#define sprintf         dont_use_sprintf           ///< use qsnprintf()
#define snprintf        dont_use_snprintf          ///< use qsnprintf()
#define wsprintfA       dont_use_wsprintf          ///< use qsnprintf()
#undef strcmpi
#undef strncmpi
#define strcmpi         dont_use_strcmpi           ///< use stricmp()
#define strncmpi        dont_use_strncmpi          ///< use strnicmp()
#define getenv          dont_use_getenv            ///< use qgetenv()
#define setenv          dont_use_setenv            ///< use qsetenv()
#define putenv          dont_use_putenv            ///< use qsetenv()
#define strtok          dont_use_strrok            ///< use qstrtok()
#undef strlwr
#undef strupr
#define strlwr          dont_use_strlwr            ///< use qstrlwr()
#define strupr          dont_use_strupr            ///< use qstrupr()
#define waitid          dont_use_waitid            ///< use qwait()
#define waitpid         dont_use_waitpid           ///< use qwait()
#define wait            dont_use_wait              ///< use qwait()
#endif

//---------------------------------------------------------------------------
#define streq(s1, s2)          (strcmp((s1), (s2))  == 0)           ///< convenient check for string equality
#define strieq(s1, s2)         (stricmp((s1), (s2)) == 0)           ///< see #streq
#define strneq(s1, s2, count)  (strncmp((s1), (s2), (count))  == 0) ///< see #streq
#define strnieq(s1, s2, count) (strnicmp((s1), (s2), (count)) == 0) ///< see #streq

//---------------------------------------------------------------------------
/// \defgroup qsnprintf qsnprintf/qsscanf
/// safer versions of sprintf/sscanf
///
/// Our definitions of sprintf-like functions support one additional format specifier
///
///      "%a"              which corresponds to ::ea_t
///
/// Usual optional fields like the width can be used too: %04a.
/// The width specifier will be doubled for 64-bit version.
/// These function return the number of characters _actually written_ to the output string.
/// excluding the terminating zero. (which is different from the snprintf).
/// They always terminate the output with a zero byte (if n > 0).
//@{
idaman AS_PRINTF(3, 4) THREAD_SAFE int ida_export qsnprintf(char *buffer, size_t n, const char *format, ...);           ///< A safer snprintf
idaman AS_SCANF (2, 3) THREAD_SAFE int ida_export qsscanf(const char *input, const char *format, ...);                  ///< A safer sscanf
idaman AS_PRINTF(3, 0) THREAD_SAFE int ida_export qvsnprintf(char *buffer, size_t n, const char *format, va_list va);   ///< See qsnprintf()
idaman AS_SCANF (2, 0) THREAD_SAFE int ida_export qvsscanf(const char *input, const char *format, va_list va);          ///< See qsscanf()
idaman AS_PRINTF(3, 4) THREAD_SAFE int ida_export append_snprintf(char *buf, const char *end, const char *format, ...); ///< Append result of sprintf to 'buf'
//@}

//---------------------------------------------------------------------------
/// qsnprintf that does not check its arguments.
/// Normally gcc complains about the non-literal formats. However, sometimes we
/// still need to call qsnprintf with a dynamically built format string.
/// OTOH, there are absolutely no checks of the input arguments, so be careful!
GCC_DIAG_OFF(format-nonliteral);
INLINE int nowarn_qsnprintf(char *buf, size_t size, const char *format, ...)
{
  va_list va;
  int code;
  va_start(va, format);
#ifdef __cplusplus
  code = ::qvsnprintf(buf, size, format, va);
#else
  code = qvsnprintf(buf, size, format, va);
#endif
  va_end(va);
  return code;
}
GCC_DIAG_ON(format-nonliteral);

//---------------------------------------------------------------------------
/// \def{QMAXPATH, maximum number of characters in a path specification}
/// \def{QMAXFILE, maximum number of characters in a filename specification}
#if defined(__NT__)
#define QMAXPATH        260
#define QMAXFILE        260
#else
#define QMAXPATH        PATH_MAX
#define QMAXFILE        PATH_MAX
#endif

idaman THREAD_SAFE char *ida_export vqmakepath(char *buf, size_t bufsize, const char *s1, va_list); ///< See qmakepath()


/// Construct a path from a null-terminated sequence of strings.
/// \param buf      output buffer. Can be == s1, but must not be nullptr
/// \param bufsize  size of buffer
/// \param s1       the first path component. it may be followed by more components.
///                 the argument list must end with nullptr.
/// \return pointer to result

idaman THREAD_SAFE char *ida_export qmakepath(char *buf, size_t bufsize, const char *s1, ...);


/// Get the current working directory.
/// \param buf      output buffer
/// \param bufsize  size of buffer
/// This function calls error() if any problem occurs.

idaman void ida_export qgetcwd(char *buf, size_t bufsize);


/// Change the current working directory.
/// \param path     the new directory
/// The possible return values are the same as those of the POSIX 'chdir'

idaman int ida_export qchdir(const char *path);


/// Get the directory part of the path.
/// path and buf may point to the same buffer
/// \param[out] buf      buffer for the directory part. can be nullptr.
/// \param[out] bufsize  size of this buffer
/// \param path          path to split
/// \retval true   ok
/// \retval false  input buffer did not have the directory part.
///                In this case the buffer is filled with "."

idaman THREAD_SAFE bool ida_export qdirname(char *buf, size_t bufsize, const char *path);


/// Construct filename from base name and extension.
/// \param buf      output buffer. Can be == base, but must not be nullptr
/// \param bufsize  size of buffer
/// \param base     base name
/// \param ext      extension
/// \return pointer to result

idaman THREAD_SAFE char *ida_export qmakefile(
        char *buf,
        size_t bufsize,
        const char *base,
        const char *ext);


/// Split filename into base name and extension.
/// \param file  filename, may be changed
/// \param base  filled with base part, can be nullptr
/// \param ext   filled with extension part, can be nullptr
/// \return the base part

idaman THREAD_SAFE char *ida_export qsplitfile(char *file, char **base, char **ext);


/// Is the file name absolute (not relative to the current dir?)

idaman THREAD_SAFE bool ida_export qisabspath(const char *file);


/// Get the file name part of the given path.
/// \return nullptr if path is nullptr

idaman THREAD_SAFE const char *ida_export qbasename(const char *path);

#ifdef __cplusplus
/// Same as qbasename(const char *), but accepts and returns non-const char pointers
inline char *qbasename(char *path) { return CONST_CAST(char *)(qbasename((const char *)path)); }
#endif


/// Convert relative path to absolute path

idaman THREAD_SAFE char *ida_export qmake_full_path(char *dst, size_t dstsize, const char *src);


/// Search for a file in the PATH environment variable or the current directory.
/// \param buf         output buffer to hold the full file path
/// \param bufsize     output buffer size
/// \param file        the file name to look for. If the file is an absolute path
///                    then buf will return the file value.
/// \param search_cwd  search the current directory if file was not found in the PATH
/// \return true if the file was found and false otherwise

idaman THREAD_SAFE bool ida_export search_path(
        char *buf,
        size_t bufsize,
        const char *file,
        bool search_cwd);

/// Delimiter of directory lists
#if defined(__UNIX__)
#define DELIMITER       ":"     ///< for Unix - ';' for Windows
#else
#define DELIMITER       ";"     ///< for MS DOS, Windows, other systems - ':' for Unix
#endif


/// Set file name extension unconditionally.
/// \param outbuf   buffer to hold the answer. may be the same
///                 as the file name.
/// \param bufsize  output buffer size
/// \param file     the file name
/// \param ext      new extension (with or without '.')
/// \return pointer to the new file name

idaman THREAD_SAFE char *ida_export set_file_ext(
        char *outbuf,
        size_t bufsize,
        const char *file,
        const char *ext);


/// Get pointer to extension of file name.
/// \param file  filename
/// \return pointer to the file extension or nullptr if extension doesn't exist

idaman THREAD_SAFE const char *ida_export get_file_ext(const char *file);

/// Does the given file name have an extension?
#ifdef __cplusplus
inline THREAD_SAFE bool idaapi has_file_ext(const char *file)
  { return get_file_ext(file) != nullptr; }
#endif


/// Set file name extension if none exists.
/// This function appends the extension to a file name.
/// It won't change file name if extension already exists
/// \param buf      output buffer
/// \param bufsize  size of the output buffer
/// \param file     file name
/// \param ext      extension (with or without '.')
/// \return pointer to the new file name

#ifdef __cplusplus
inline THREAD_SAFE char *idaapi make_file_ext(
        char *buf,
        size_t bufsize,
        const char *file,
        const char *ext)
{
  if ( has_file_ext(file) )
    return ::qstrncpy(buf, file, bufsize);
  else
    return set_file_ext(buf, bufsize, file, ext);
}
#endif


/// Sanitize the file name.
/// Remove the directory path, and replace wildcards ? * and chars<' ' with _.
/// If the file name is empty, then:
///      - namesize != 0: generate a new temporary name, return true
///      - namesize == 0: return false

idaman THREAD_SAFE bool ida_export sanitize_file_name(char *name, size_t namesize);


/// Match a name against a pattern.
/// Only * and ? wildcards are supported.
/// \param name name to match
/// \param pattern pattern to match against
/// \return true is matched

bool wildcard_match(const char *name, const char *pattern);


/// Match a path against a pattern.
/// **, *, ?, and ranges like [a-zA-Z] are supported.
/// \param name name to match
/// \param _pattern pattern to match against
/// \param flags combination of WPM_... bits
/// \return true is matched

bool wildcard_path_match(const char *name, const char *_pattern, int flags=0);

#define WPM_EXPLICIT_DOT 0x01   // match dots at the beginning of a path component explicitly
                                // example: with this bit set,
                                //   * does not match .hidden
                                //  .* matches .hidden
                                //   * matches file.ext

/// Match a string with a regular expression.
/// \retval 0  no match
/// \retval 1  match
/// \retval -1 error

idaman int ida_export regex_match(const char *str, const char *pattern, bool sense_case);


//---------------------------------------------------------------------------
/* input/output */
/*--------------------------------------------------*/
#if !defined(__NT__) && !defined(_MSC_VER)
#define O_BINARY        0
#endif

#ifndef SEEK_SET
#  define SEEK_SET        0   ///< beginning of file
#  define SEEK_CUR        1   ///< current position of the file *
#  define SEEK_END        2   ///< end of file *
#endif

#if !defined(S_ISREG) && defined(S_IFMT) && defined(S_IFREG)
  #define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#endif
#if !defined(S_ISDIR) && defined(S_IFMT) && defined(S_IFDIR)
  #define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif

/*--------------------------------------------------*/
/*   you should use these functions for file i/o    */

/// Works the same as it's counterpart from Clib.
/// The only difference is that it sets 'qerrno' variable too

idaman THREAD_SAFE int   ida_export qopen(const char *file, int mode);


/// Open file with given sharing_mode (use O_RDONLY, O_WRONLY, O_RDWR flags), sets qerrno

idaman THREAD_SAFE int   ida_export qopen_shared(const char *file, int mode, int share_mode);


/// Create new file with O_RDWR, sets qerrno

idaman THREAD_SAFE int   ida_export qcreate(const char *file, int stat);

idaman THREAD_SAFE int   ida_export qread(int h, void *buf, size_t n);                        ///< \copydoc qopen
idaman THREAD_SAFE int   ida_export qwrite(int h, const void *buf, size_t n);                 ///< \copydoc qopen
idaman THREAD_SAFE qoff64_t ida_export qtell(int h);                                          ///< \copydoc qopen
idaman THREAD_SAFE qoff64_t ida_export qseek(int h, int64 offset, int whence);              ///< \copydoc qopen
idaman THREAD_SAFE int   ida_export qclose(int h);                                            ///< \copydoc qopen
idaman THREAD_SAFE int   ida_export qdup(int h);                                              ///< \copydoc qopen
idaman THREAD_SAFE int   ida_export qfsync(int h);                                            ///< \copydoc qopen


/// Get the file size.
/// This function may return 0 if the file is not found.

idaman THREAD_SAFE uint64 ida_export qfilesize(const char *fname);

/// Get file length in bytes.
/// \param h  file descriptor
/// \return file length in bytes, -1 if error

idaman THREAD_SAFE uint64 ida_export qfilelength(int h);

/// Change file size.
/// \param h      file descriptor
/// \param fsize  desired size
/// \retval 0     on success
/// \retval -1    otherwise and qerrno is set

idaman THREAD_SAFE int ida_export qchsize(int h, uint64 fsize);

/// Create an empty directory.
/// \param file  name (or full path) of directory to be created
/// \param mode  permissions (only used on unix systems)
/// \return 0    success
/// \return -1   otherwise and qerrno is set

idaman THREAD_SAFE int ida_export qmkdir(const char *file, int mode);

/// Delete a directory.
/// \param file  name (or full path) of directory to be removed
/// \return 0    success
/// \return -1   otherwise and qerrno is set

idaman THREAD_SAFE int ida_export qrmdir(const char *file);

/// Does the given file exist?

idaman THREAD_SAFE bool ida_export qfileexist(const char *file);


/// Does the given path specify a directory?

idaman THREAD_SAFE bool ida_export qisdir(const char *file);

/// Get file status
idaman THREAD_SAFE int ida_export qstat(const char *path, struct qstatbuf *buf);
idaman THREAD_SAFE int ida_export qfstat(int fd, struct qstatbuf *buf);

//---------------------------------------------------------------------------
/// Add a function to be called at exit time

idaman THREAD_SAFE void ida_export qatexit(void (idaapi *func)(void));


/// Remove a previously added exit-time function

idaman THREAD_SAFE void ida_export del_qatexit(void (idaapi*func)(void));

#endif // SWIG


/// Call qatexit functions, shut down UI and kernel, and exit.
/// \param code  exit code

idaman THREAD_SAFE NORETURN void ida_export qexit(int code);

//---------------------------------------------------------------------------
#define qmin(a,b) ((a) < (b)? (a): (b)) ///< universal min
#define qmax(a,b) ((a) > (b)? (a): (b)) ///< universal max
#ifdef __cplusplus
template <class T> T qabs(T x) { return x < 0 ? -x : x; }
#else
int qabs(int x) { return x < 0 ? -x : x; }
#endif

//----------------------------------------------------------------------
/// Test if 'bit' is set in 'bitmap'
INLINE THREAD_SAFE bool idaapi test_bit(const uchar *bitmap, size_t bit)
{
  return (bitmap[bit/8] & (1<<(bit&7))) != 0;
}
/// Set 'bit' in 'bitmap'
INLINE THREAD_SAFE void idaapi set_bit(uchar *bitmap, size_t bit)
{
  uchar *p = bitmap + bit/8;
  *p = (uchar)(*p | (1<<(bit&7)));
}
/// Clear 'bit' in 'bitmap'
INLINE THREAD_SAFE void idaapi clear_bit(uchar *bitmap, size_t bit)
{
  uchar *p = bitmap + bit/8;
  *p = (uchar)(*p & ~(1<<(bit&7)));
}
/// Set bits between [low, high) in 'bitmap'
INLINE THREAD_SAFE void idaapi set_bits(uchar *bitmap, size_t low, size_t high)
{
  size_t bit;
  for ( bit = low; bit < high; ++bit )
    set_bit(bitmap, bit);
}
/// Clear bits between [low, high) in 'bitmap'
INLINE THREAD_SAFE void idaapi clear_bits(uchar *bitmap, size_t low, size_t high)
{
  size_t bit;
  for ( bit = low; bit < high; ++bit )
    clear_bit(bitmap, bit);
}
/// Set first 'nbits' of 'bitmap'
INLINE THREAD_SAFE void idaapi set_all_bits(uchar *bitmap, size_t nbits)
{
  memset(bitmap, 0xFF, (nbits+7)/8);
  if ( (nbits & 7) != 0 )
  {
    uchar *p = bitmap + nbits/8;
    *p = (uchar)(*p & ~((1 << (nbits&7))-1));
  }
}
/// Clear first 'nbits' of 'bitmap'
INLINE THREAD_SAFE void idaapi clear_all_bits(uchar *bitmap, size_t nbits)
{
  memset(bitmap, 0, (nbits+7)/8);
}

/// calculate ceil(log2(d64)) or floor(log2(d64)),
/// it returns 0 if d64 == 0
idaman int ida_export log2ceil(uint64 d64);
idaman int ida_export log2floor(uint64 d64);

/// calculate number of set bits (the population count)
idaman int ida_export bitcount(uint64 x);

/// round up or down to a power of 2
idaman uint32 ida_export round_up_power2(uint32 x);
idaman uint32 ida_export round_down_power2(uint32 x);

/// is power of 2? (or zero)
template <class T> constexpr bool is_pow2(T val)
{
  return ((val - 1) & val) == 0;
}

/// round up or down to an arbitrary number
template <class T> T round_up(T val, T base)
{
  T r = val % base;
  return r != 0 ? val + base - r : val;
}
template <class T> T round_down(T val, T base)
{
  return val - val % base;
}

#ifdef __cplusplus
//----------------------------------------------------------------------
/// Functions to work with intervals
namespace interval
{
  /// max offset of the interval (assume s != 0)
  inline THREAD_SAFE constexpr uval_t last(uval_t off, asize_t s)
  {
    return off + s - 1;
  }
  /// Do (off1,s1) and (off2,s2) overlap?
  inline THREAD_SAFE constexpr bool overlap(uval_t off1, asize_t s1, uval_t off2, asize_t s2)
  {
    return s1 != 0 && s2 != 0 && off2 <= last(off1, s1) && off1 <= last(off2, s2);
  }
  /// Does (off1,s1) include (off2,s2)?
  inline THREAD_SAFE constexpr bool includes(uval_t off1, asize_t s1, uval_t off2, asize_t s2)
  {
    return s1 != 0 && off2 >= off1 && last(off2, s2) <= last(off1, s1);
  }
  /// Does (off1,s1) contain off?
  inline THREAD_SAFE constexpr bool contains(uval_t off1, asize_t s1, uval_t off)
  {
    return s1 != 0 && off >= off1 && off <= last(off1, s1);
  }
}
#endif

//----------------------------------------------------------------------
#ifdef __cplusplus
/// Shift by the amount exceeding the operand size*8 is undefined by the standard.
/// Indeed, GNUC may decide not to rotate the operand in some cases.
/// We have to check this manually.
template <class T> constexpr T left_shift(const T &value, int shift)
{
  return shift >= sizeof(T)*8 ? 0 : (value << shift);
}
/// \copydoc left_shift
template <class T> constexpr T right_ushift(const T &value, int shift)
{
  return shift >= sizeof(T)*8 ? 0 : (value >> shift);
}
/// \copydoc left_shift
template <class T> constexpr T right_sshift(const T &value, int shift)
{
  return shift >= sizeof(T)*8 ? (value >= 0 ? 0 : -1) : (value >> shift);
}

/// Rotate left
template<class T> T qrotl(T value, size_t count)
{
  const size_t nbits = sizeof(T) * 8;
  count %= nbits;

  T high = value >> (nbits - count);
  value <<= count;
  value |= high;
  return value;
}

/// Rotate right
template<class T> T qrotr(T value, size_t count)
{
  const size_t nbits = sizeof(T) * 8;
  count %= nbits;

  T low = value << (nbits - count);
  value >>= count;
  value |= low;
  return value;
}

/// Make a mask of 'count' bits
template <class T> constexpr T make_mask(int count)
{
  return left_shift<T>(1, count) - 1;
}

/// Set a 'bit' in 'where' if 'value' if not zero
template<class T, class U> void idaapi setflag(T &where, U bit, bool cnd)
{
  if ( cnd )
    where = T(where | bit);
  else
    where = T(where & ~T(bit));
}

/// Check that unsigned multiplication does not overflow
template<class T> bool is_mul_ok(T count, T elsize)
{
  CASSERT((T)(-1) > 0); // make sure T is unsigned
  if ( elsize == 0 || count == 0 )
    return true;
  return count <= ((T)(-1)) / elsize;
}

/// Check that unsigned or unsigned+signed addition does not overflow
template<class U, class T> bool is_add_ok(U x, T y)
{
  CASSERT((U)(-1) > 0); // make sure U is unsigned
  return y >= 0 ? y <= ((U)(-1)) - x : -y <= x;
}

/// Check that unsigned division is permissible
template <class T> bool is_udiv_ok(T, T b)
{
  CASSERT((T)(-1) > 0); // make sure T is unsigned
  return b != 0;        // forbid x/0
}

/// Check that signed division is permissible
template <class T> bool is_sdiv_ok(T a, T b)
{
  CASSERT((T)(-1) < 0); // make sure T is signed
  T minval = left_shift((T)1, sizeof(T)*8-1);
  return b != 0 && !(a == minval && b == -1); // forbid x/0, MINVAL/-1
}

/// \def{OPERATOR_NEW, GCC does not check for an integer overflow in 'operator new[]'. We have to do it
///                    ourselves. Please note that 'char' arrays can still be allocated with
///                    plain 'operator new'.}
#ifdef __GNUC__
#  define OPERATOR_NEW(type, count) (is_mul_ok(size_t(count), sizeof(type)) \
                                     ? new type[count] \
                                     : (type *)qalloc_or_throw(BADMEMSIZE))
#else
#  define OPERATOR_NEW(type, count) new type[count]
#endif

#endif // __cplusplus

//-------------------------------------------------------------------------
/// Sign-, or zero-extend the value 'v' to occupy 64 bits.
/// The value 'v' is considered to be of size 'nbytes'.

idaman uint64 ida_export extend_sign(uint64 v, int nbytes, bool sign_extend);


/// We cannot use multi-character constants because they are not portable - use this macro instead
#define MC2(c1, c2)          ushort(((c2)<<8)|c1)
#define MC3(c1, c2, c3)      uint32(((((c3)<<8)|(c2))<<8)|c1)              ///< \copydoc MC2
#define MC4(c1, c2, c3, c4)  uint32(((((((c4)<<8)|(c3))<<8)|(c2))<<8)|c1)  ///< \copydoc MC2


//---------------------------------------------------------------------------
/// Read at most 4 bytes from file.
/// \param h     file handle
/// \param res   value read from file
/// \param size  size of value in bytes (1,2,4)
/// \param mf    is MSB first?
/// \return 0 on success, nonzero otherwise

idaman THREAD_SAFE int ida_export readbytes(int h, uint32 *res, int size, bool mf);


/// Write at most 4 bytes to file.
/// \param h     file handle
/// \param l     value to write
/// \param size  size of value in bytes (1,2,4)
/// \param mf    is MSB first?
/// \return 0 on success, nonzero otherwise

idaman THREAD_SAFE int ida_export writebytes(int h, uint32 l, int size, bool mf);


/// Read a 2 byte entity from a file.
/// \param h    file handle
/// \param res  value read from file
/// \param mf   is MSB first?
/// \return 0 on success, nonzero otherwise

idaman THREAD_SAFE int ida_export read2bytes(int h, uint16 *res, bool mf);

#define read4bytes(h, res, mf)  readbytes(h, res, 4, mf) ///< see readbytes()
#define write2bytes(h, l, mf)   writebytes(h, l, 2, mf)  ///< see writebytes()
#define write4bytes(h, l, mf)   writebytes(h, l, 4, mf)  ///< see writebytes()

//---------------------------------------------------------------------------
/// \fn{uint32 swap32(uint32 x), Switch endianness of given value}
/// \fn{ushort swap16(ushort x), \copydoc swap32}
/// \def{swap32, Switch endianness of given value}
/// \def{swap16, \copydoc swap32}
#ifdef __cplusplus
#  ifndef swap32
inline THREAD_SAFE constexpr uint32 swap32(uint32 x)
  { return (x>>24) | (x<<24) | ((x>>8) & 0x0000FF00L) | ((x<<8) & 0x00FF0000L); }
#  endif
#  ifndef swap16
inline THREAD_SAFE constexpr ushort swap16(ushort x)
  { return ushort((x<<8) | (x>>8)); }
#  endif
#else
#  ifndef swap32
#    define swap32(x) uint32((x>>24) | (x<<24) | ((x>>8) & 0x0000FF00L) | ((x<<8) & 0x00FF0000L))
#  endif
#  ifndef swap16
#    define swap16(x) ushort((x<<8) | (x>>8))
#  endif
#endif

/// \def{swapea, Switch endianness of an ::ea_t value}
#ifdef __EA64__
#define swapea  swap64
#else
#define swapea  swap32
#endif

/// \def{qhtons, \copydoc swap32}
/// \def{qntohs, \copydoc swap32}
/// \def{qhtonl, \copydoc swap32}
/// \def{qntohl, \copydoc swap32}
#if __MF__
#define qhtonl(x) (x)
#define qntohl(x) (x)
#define qhtons(x) (x)
#define qntohs(x) (x)
#else
#define qhtons(x) swap16(x)
#define qntohs(x) swap16(x)
#define qhtonl(x) swap32(x)
#define qntohl(x) swap32(x)
#endif


/// Swap endianness of a given value in memory.
/// \param dst   result of swap
/// \param src   value to be swapped
/// \param size  size of value: can be 1, 2, 4, 8, or 16.
///              For any other values of size this function does nothing

idaman THREAD_SAFE void ida_export swap_value(void *dst, const void *src, int size);


idaman THREAD_SAFE void ida_export reloc_value(void *value, int size, adiff_t delta, bool mf);


/// Rotate left - can be used to rotate a value to the right if the count is negative.
/// \param x       value to rotate
/// \param count   shift amount
/// \param bits    number of bits to rotate (32 will rotate a dword)
/// \param offset  number of first bit to rotate.
///                (bits=8 offset=16 will rotate the third byte of the value)
/// \return the rotated value

idaman THREAD_SAFE uval_t ida_export rotate_left(uval_t x, int count, size_t bits, size_t offset);


#ifdef __cplusplus
/// Swap 2 objects of the same type using memory copies
template <class T> inline THREAD_SAFE void qswap(T &a, T &b)
{
  char temp[sizeof(T)];
  memcpy(&temp, &a, sizeof(T));
  memcpy(&a, &b, sizeof(T));
  memcpy(&b, &temp, sizeof(T));
}

//---------------------------------------------------------------------------
#ifndef SWIG
//-V:unpack_db:656 Variables are initialized through the call to the same function
//-V:unpack_dw:656
//-V:unpack_dd:656
//-V:unpack_ea:656
//-V:unpack_ea64:656
//-V:unpack_str:656
//-V:unpack_ds:656

/// \defgroup pack Pack/Unpack
/// Functions for packing and unpacking values
//{

/// Pack a byte into a character string.
/// This function encodes numbers using an encoding similar to UTF.
/// The smaller the number, the better the packing.
/// \param ptr  pointer to output buffer
/// \param end  pointer to end of output buffer
/// \param x    value to pack
/// \return pointer to end of resulting string

THREAD_SAFE inline uchar *idaapi pack_db(uchar *ptr, uchar *end, uchar x)
{
  if ( ptr < end )
    *ptr++ = x;
  return ptr;
}


/// Unpack a byte from a character string, pack_db()

THREAD_SAFE inline uchar idaapi unpack_db(const uchar **pptr, const uchar *end)
{
  const uchar *ptr = *pptr;
  uchar x = 0;
  if ( ptr < end )
    x = *ptr++;
  *pptr = ptr;
  return x;
}

idaman THREAD_SAFE uchar *ida_export pack_dw(uchar *ptr, uchar *end, uint16 x); ///< pack a word, see pack_db()
idaman THREAD_SAFE uchar *ida_export pack_dd(uchar *ptr, uchar *end, uint32 x); ///< pack a double word, see pack_db()
idaman THREAD_SAFE uchar *ida_export pack_dq(uchar *ptr, uchar *end, uint64 x); ///< pack a quadword, see pack_db()
idaman THREAD_SAFE ushort ida_export unpack_dw(const uchar **pptr, const uchar *end); ///< unpack a word, see unpack_db()
idaman THREAD_SAFE uint32 ida_export unpack_dd(const uchar **pptr, const uchar *end); ///< unpack a double word, see unpack_db()
idaman THREAD_SAFE uint64 ida_export unpack_dq(const uchar **pptr, const uchar *end); ///< unpack a quadword, see unpack_db()

/// Pack an ea value into a character string, see pack_dd()/pack_dq()

THREAD_SAFE inline uchar *pack_ea(uchar *ptr, uchar *end, ea_t ea)
{
#ifdef __EA64__
  return pack_dq(ptr, end, ea);
#else
  return pack_dd(ptr, end, ea);
#endif
}

/// Unpack an ea value, see unpack_dd()/unpack_dq()

THREAD_SAFE inline ea_t unpack_ea(const uchar **ptr, const uchar *end)
{
#ifdef __EA64__
  return unpack_dq(ptr, end);
#else
  return unpack_dd(ptr, end);
#endif
}

/// Unpack an ea value (always use 64bit, use delta 1)
THREAD_SAFE inline ea64_t unpack_ea64(const uchar **ptr, const uchar *end)
{
  return unpack_dq(ptr, end) - 1;
}


/// Unpack an object of a known size.
/// \param destbuf   output buffer
/// \param destsize  size of output buffer
/// \param pptr      pointer to packed object
/// \param end       pointer to end of packed object
/// \return pointer to the destination buffer.
///         if any error, returns nullptr.

THREAD_SAFE inline void *idaapi unpack_obj(
        void *destbuf,
        size_t destsize,
        const uchar **pptr,
        const uchar *end)
{
  const uchar *src = *pptr;
  const uchar *send = src + destsize;
  if ( send < src || send > end )
    return nullptr;
  *pptr = send;
  return memcpy(destbuf, src, destsize);
}


/// Unpack an object of an unknown size (packed with append_buf()).
/// \param pptr     pointer to packed object
/// \param end      pointer to end of packed object
/// \return pointer to the destination buffer, which is allocated in the dynamic memory.  \n
///         the caller should use qfree() to deallocate it.                               \n
///         if any error, returns nullptr.                                                   \n
///         NB: zero size objects will return nullptr too.

THREAD_SAFE inline void *idaapi unpack_buf(const uchar **pptr, const uchar *end)
{
  size_t size = unpack_dd(pptr, end);
  if ( size == 0 )
    return nullptr;
  const uchar *src = *pptr;
  const uchar *srcend = src + size;
  if ( srcend < src || srcend > end )
    return nullptr;
  void *dst = qalloc(size);
  if ( dst != nullptr )
  {
    memcpy(dst, src, size);
    *pptr = srcend;
  }
  return dst;
}


/// In-place version of unpack_obj().
/// It does not copy any data. It just returns a pointer to the object in the packed string.
/// If any error, it returns nullptr.

THREAD_SAFE inline const void *idaapi unpack_obj_inplace(
        const uchar **pptr,
        const uchar *end,
        size_t objsize)
{
  const uchar *ret = *pptr;
  const uchar *rend = ret + objsize;
  if ( rend < ret || rend > end )
    return nullptr;
  *pptr = rend;
  return ret;
}


/// In-place version of unpack_buf().
/// It does not copy any data. It just returns a pointer to the object in the packed string.
/// If any error, it returns nullptr.

THREAD_SAFE inline const void *idaapi unpack_buf_inplace(
        const uchar **pptr,
        const uchar *end)
{
  size_t objsize = unpack_dd(pptr, end);
  return unpack_obj_inplace(pptr, end, objsize);
}


/// Pack a string.
/// \param ptr  pointer to output buffer
/// \param end  pointer to end of output buffer
/// \param x    string to pack. If nullptr, empty string is packed
/// \param len  number of chars to pack. If 0, the length of given string is used
/// \return pointer to end of packed string

idaman THREAD_SAFE uchar *ida_export pack_ds(
        uchar *ptr,
        uchar *end,
        const char *x,
        size_t len=0);


/// Unpack a string.
/// \param pptr        pointer to packed string
/// \param end         pointer to end of packed string
/// \param empty_null  if true, then return nullptr for empty strings.   \n
///                    otherwise return an empty string (not nullptr).
/// \return pointer to unpacked string.                               \n
///         this string will be allocated in dynamic memory.          \n
///         the caller should use qfree() to deallocate it.

idaman THREAD_SAFE char *ida_export unpack_ds(
        const uchar **pptr,
        const uchar *end,
        bool empty_null);

/// Unpack a string.
/// \param dst         pointer to buffer string will be copied to
/// \param dstsize     buffer size
/// \param pptr        pointer to packed string
/// \param end         pointer to end of packed string
/// \return success
THREAD_SAFE inline bool unpack_ds_to_buf(
        char *dst,
        size_t dstsize,
        const uchar **pptr,
        const uchar *end)
{
  const void *buf = unpack_buf_inplace(pptr, end);
  if ( buf == nullptr )
    return false;
  size_t size = *pptr - (const uchar *)buf;
  if ( size >= dstsize )
    size = dstsize - 1;
  memcpy(dst, buf, size);
  dst[size] = '\0';
  return true;
}


/// Unpack an LEB128 encoded (DWARF-3 style) signed/unsigned value.
/// Do not use this function directly - see \ref unp_templates

idaman THREAD_SAFE bool ida_export unpack_xleb128(
        void *res,
        int nbits,
        bool is_signed,
        const uchar **pptr,
        const uchar *end);

/// \defgroup unp_templates Template unpacking
/// Template functions that can unpack values
//@{

template <class T>
inline THREAD_SAFE bool unpack_uleb128(T *res, const uchar **pptr, const uchar *end)
{
  CASSERT((T)(-1) > 0); // make sure T is unsigned
  return unpack_xleb128(res, sizeof(T)*8, false, pptr, end);
}

template <class T>
inline THREAD_SAFE bool unpack_sleb128(T *res, const uchar **pptr, const uchar *end)
{
  CASSERT((T)(-1) < 0); // make sure T is signed
  return unpack_xleb128(res, sizeof(T)*8, true, pptr, end);
}

//@} Template unpacking functions

// packed sizes
/// \cond
static constexpr int ea_packed_size = sizeof(ea_t) + sizeof(ea_t)/4; // 5 or 10 bytes
static constexpr int dq_packed_size = 10;
static constexpr int dd_packed_size = 5;
static constexpr int dw_packed_size = 3;
/// \endcond

inline THREAD_SAFE int ds_packed_size(const char *s) { return s ? int(strlen(s)+dd_packed_size) : 1; }

//----------------------------------------------------------------------------
inline THREAD_SAFE constexpr int dw_size(uchar first_byte)
{
  return (first_byte & 0x80) == 0    ? 1
       : (first_byte & 0xC0) == 0xC0 ? 3
       :                               2;
}

//----------------------------------------------------------------------------
inline THREAD_SAFE constexpr int dd_size(uchar first_byte)
{
  return (first_byte & 0x80) == 0x00 ? 1
       : (first_byte & 0xC0) != 0xC0 ? 2
       : (first_byte & 0xE0) == 0xE0 ? 5
       :                               4;
}

//----------------------------------------------------------------------------
// unpack data from an object which must have the following functions:
//   ssize_t read(void *buf, size_t count)
//   bool eof() - return true if there is no more data to read
template <class T>
inline THREAD_SAFE uchar extract_db(T &v)
{
  uchar x = 0;
  v.read(&x, 1);
  return x;
}

template <class T>
inline THREAD_SAFE void *extract_obj(T &v, void *destbuf, size_t destsize)
{
  if ( destsize == 0 )
    return nullptr;
  return v.read(destbuf, destsize) == destsize ? destbuf : nullptr;
}

template <class T>
inline THREAD_SAFE uint16 extract_dw(T &v)
{
  uchar packed[dw_packed_size];
  packed[0] = extract_db(v);
  int psize = dw_size(packed[0]);
  extract_obj(v, &packed[1], psize-1);
  const uchar *ptr = packed;
  return unpack_dw(&ptr, packed + psize);
}

template <class T>
inline THREAD_SAFE uint32 extract_dd(T &v)
{
  uchar packed[dd_packed_size];
  packed[0] = extract_db(v);
  int psize = dd_size(packed[0]);
  extract_obj(v, &packed[1], psize-1);
  const uchar *ptr = packed;
  return unpack_dd(&ptr, packed + psize);
}

template <class T>
inline THREAD_SAFE uint64 extract_dq(T &v)
{
  uint32 l = extract_dd(v);
  uint32 h = extract_dd(v);
  return make_uint64(l, h);
}

template <class T>
inline THREAD_SAFE ea_t extract_ea(T &v)
{
#ifdef __EA64__
  return extract_dq(v);
#else
  return extract_dd(v);
#endif
}

template <class T>
inline THREAD_SAFE void *extract_buf(T &v, size_t size)
{
  void *buf = qalloc(size);
  if ( buf == nullptr )
    return nullptr;
  return extract_obj(v, buf, size);
}

template <class T>
inline THREAD_SAFE void *extract_array(T &v, size_t *sz, size_t maxsize)
{
  size_t size = extract_dd(v);
  if ( size == 0 || size > maxsize )
    return nullptr;
  *sz = size;
  return extract_buf(v, size);
}

inline const char *unpack_str(const uchar **pptr, const uchar *end)
{ // zero terminated string, return inplace ptr
  const uchar *ptr = *pptr;
  const uchar *str = ptr;
  do
    if ( ptr >= end )
      return nullptr; // no terminating zero?
  while ( *ptr++ != '\0' );
  *pptr = ptr;
  return (char*)str;
}

//@} Packing functions
#endif // SWIG
#endif // cplusplus

/// \name Safe buffer append
/// In the following macros, 'buf' must be always less than 'end'.
/// When we run up to the end, we put a 0 there and don't increase buf anymore
//@{
/// Append a character to the buffer checking the buffer size
#define APPCHAR(buf, end, chr)              \
  do                                        \
  {                                         \
    char __chr = (chr);                     \
    QASSERT(518, (buf) < (end));            \
    *(buf)++ = __chr;                       \
    if ( (buf) >= (end) )                   \
    {                                       \
      (buf) = (end)-1;                      \
      (buf)[0] = '\0';                      \
    }                                       \
  } while (0)

/// Put a zero byte at buffer.
/// NB: does not increase buf pointer!
#define APPZERO(buf, end)                   \
  do                                        \
  {                                         \
    QASSERT(519, (buf) < (end));            \
    *(buf) = '\0';                          \
  } while (0)

/// Append a string to the buffer checking the buffer size
#define APPEND(buf, end, name)              \
  do                                        \
  {                                         \
    QASSERT(520, (buf) < (end));            \
    const char *__ida_in = (name);          \
    while ( true )                          \
    {                                       \
      if ( (buf) == (end)-1 )               \
      {                                     \
        (buf)[0] = '\0';                    \
        break;                              \
      }                                     \
      if ( (*(buf) = *__ida_in++) == '\0' ) \
        break;                              \
      (buf)++;                              \
    }                                       \
  } while ( 0 )
//@}

/// qalloc() 'size' bytes, and throw a "not enough memory" error if failed

idaman THREAD_SAFE void *ida_export qalloc_or_throw(size_t size);


/// qrealloc() 'ptr' by 'size', and throw a "not enough memory" error if failed

idaman THREAD_SAFE void *ida_export qrealloc_or_throw(void *ptr, size_t size);


/// Change capacity of given qvector.
/// \param vec     a pointer to a qvector
/// \param old     a pointer to the qvector's array
/// \param cnt     number of elements to reserve
/// \param elsize  size of each element
/// \return a pointer to the newly allocated array

idaman THREAD_SAFE void *ida_export qvector_reserve(void *vec, void *old, size_t cnt, size_t elsize);

#if defined(__cplusplus)
  /// \def{PLACEMENT_DELETE, bcc complains about placement delete}
  /// \def{DEFINE_MEMORY_ALLOCATION_FUNCS,
  ///      Convenience macro to declare memory allocation functions.
  ///      It must be used for all classes that can be allocated/freed by the IDA kernel.}
  #if defined(SWIG)
    #define DEFINE_MEMORY_ALLOCATION_FUNCS()
  #else
    #define PLACEMENT_DELETE void operator delete(void *, void *) {}
    #define DEFINE_MEMORY_ALLOCATION_FUNCS()                          \
      void *operator new  (size_t _s) { return qalloc_or_throw(_s); } \
      void *operator new[](size_t _s) { return qalloc_or_throw(_s); } \
      void *operator new(size_t /*size*/, void *_v) { return _v; }    \
      void operator delete  (void *_blk) { qfree(_blk); }             \
      void operator delete[](void *_blk) { qfree(_blk); }             \
      PLACEMENT_DELETE
  #endif

/// Macro to declare standard inline comparison operators
#define DECLARE_COMPARISON_OPERATORS(type)                              \
  bool operator==(const type &r) const { return compare(r) == 0; }      \
  bool operator!=(const type &r) const { return compare(r) != 0; }      \
  bool operator< (const type &r) const { return compare(r) <  0; }      \
  bool operator> (const type &r) const { return compare(r) >  0; }      \
  bool operator<=(const type &r) const { return compare(r) <= 0; }      \
  bool operator>=(const type &r) const { return compare(r) >= 0; }

/// Macro to declare comparisons for our classes.
/// All comparison operators call the compare() function which returns -1/0/1
#define DECLARE_COMPARISONS(type)    \
  DECLARE_COMPARISON_OPERATORS(type) \
  int compare(const type &r) const

// Internal declarations to detect movable types
/// \cond
// Can we move around objects of type T using simple memcpy/memmove?.
// This class can be specialized for any type T to improve qvector's behavior.
template <class T> struct ida_movable_type
{
  static constexpr bool value = std::is_pod<T>::value;
};
#define DECLARE_TYPE_AS_MOVABLE(T) template <> struct ida_movable_type<T> { static constexpr bool value = true; }
template <class T> inline constexpr THREAD_SAFE bool may_move_bytes(void)
{
  return ida_movable_type<T>::value;
}
/// \endcond

/// Move data down in memory.
/// \param dst  destination ptr
/// \param src  source ptr
/// \param cnt  number of elements to move
template<class T>
inline void shift_down(T *dst, T *src, size_t cnt)
{
  if ( may_move_bytes<T>() )
  {
    memmove(dst, src, cnt*sizeof(T));
  }
  else
  {
    ssize_t s = cnt;
    while ( --s >= 0 )
    {
      new(dst) T(std::move(*src));
      src->~T();
      ++src;
      ++dst;
    }
  }
}
/// Move data up in memory.
/// \param dst  destination ptr
/// \param src  source ptr
/// \param cnt  number of elements to move
template<class T>
inline void shift_up(T *dst, T *src, size_t cnt)
{
  if ( may_move_bytes<T>() )
  {
    memmove(dst, src, cnt*sizeof(T));
  }
  else
  {
    ssize_t s = cnt;
    dst += s;
    src += s;
    while ( --s >= 0 )
    {
      --src;
      --dst;
      new(dst) T(std::move(*src));
      src->~T();
    }
  }
}


//---------------------------------------------------------------------------
/// Reimplementation of vector class from STL.
/// Only the most essential functions are implemented.                          \n
/// The vector container accepts objects agnostic to their positions
/// in the memory because it will move them arbitrarily (realloc and memmove).  \n
/// The reason why we have it is because it is not compiler dependent
/// (hopefully) and therefore can be used in IDA API.
template <class T> class qvector
{
  T *array;
  size_t n, alloc;
  friend void *ida_export qvector_reserve(void *vec, void *old, size_t cnt, size_t elsize);
  /// Copy contents of given qvector into this one
  qvector<T> &assign(const qvector<T> &x)
  {
    size_t _newsize = x.n;
    if ( _newsize > 0 )
    {
      array = (T*)qalloc_or_throw(_newsize * sizeof(T));
      alloc = _newsize;
      copy_range(x, 0, _newsize);
    }
    return *this;
  }
  /// Copies a range of elements from another qvector.
  void copy_range(const qvector<T> &x, size_t from, size_t _newsize)
  {
    if ( std::is_trivially_copyable<T>::value )
    {
      memcpy(array + from, x.array + from, (_newsize-from)*sizeof(T));
    }
    else
    {
      for ( size_t i = from; i < _newsize; i++ )
        new(array+i) T(x.array[i]);
    }
    n = _newsize;
  }
  /// Resizes to a smaller size, destroying elements if needed.
  void resize_less(size_t _newsize)
  {
    if ( !std::is_trivially_destructible<T>::value )
    {
      size_t _size = n;
      for ( size_t i = _newsize; i < _size; i++ )
        array[i].~T();
    }
    n = _newsize;
  }
  /// Resizes to a bigger size, and zeroes the new elements (they
  /// should be of a std::is_trivially_constructible type).
  void resize_more_trivial(size_t _newsize)
  {
    reserve(_newsize);
    memset(array+n, 0, (_newsize-n)*sizeof(T));
    n = _newsize;
  }
  /// Resizes to a bigger size with a given element.
  void resize_more(size_t _newsize, const T &x)
  {
    reserve(_newsize);
    for ( size_t i = n; i < _newsize; i++ )
      new(array+i) T(x);
    n = _newsize;
  }

  bool ref_within_range(const T &x) const
  {
    const T *const p = &x;
    return p >= array && p < array + alloc;
  }

public:
  typedef T value_type; ///< the type of objects contained in this qvector
  /// Constructor
  qvector(void) : array(nullptr), n(0), alloc(0) {}
  /// Constructor - creates a new qvector identical to 'x'
  qvector(const qvector<T> &x) : array(nullptr), n(0), alloc(0) { assign(x); }
#ifndef SWIG
  /// Move constructor
  qvector(qvector<T> &&x) noexcept
  {
    array = x.array; x.array = nullptr;
    n = x.n; x.n = 0;
    alloc = x.alloc; x.alloc = 0;
  }
#endif
  /// Destructor
  ~qvector(void)
  {
    if ( std::is_trivially_destructible<T>::value )
      qfree(array);
    else
      clear();
  }
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  /// Append a new element to the end the qvector.
  void push_back(const T &x)
  {
#ifdef TESTABLE_BUILD
    QASSERT(1907, !ref_within_range(x));
#endif
    reserve(n+1);
    new (array+n) T(x);
    ++n;
  }
#ifndef SWIG
  /// Append a new element to the end the qvector with a move semantics.
  void push_back(T &&x)
  {
#ifdef TESTABLE_BUILD
    QASSERT(1977, !ref_within_range(x));
#endif
    reserve(n+1);
    new (array+n) T(x);
    ++n;
  }
#endif
  /// Append a new empty element to the end of the qvector.
  /// \return a reference to this new element
  T &push_back(void)
  {
    reserve(n+1);
    T *ptr = array + n;
    new (ptr) T;
    ++n;
    return *ptr;
  }
  /// Remove the last element in the qvector
  void pop_back(void)
  {
    if ( n > 0 )
      array[--n].~T();
  }
  size_t size(void) const { return n; }                           ///< Get the number of elements in the qvector
  bool empty(void) const { return n == 0; }                       ///< Does the qvector have 0 elements?
  const T &operator[](size_t _idx) const { return array[_idx]; }  ///< Allows use of typical c-style array indexing for qvectors
        T &operator[](size_t _idx)       { return array[_idx]; }  ///< Allows use of typical c-style array indexing for qvectors
  const T &at(size_t _idx) const { return array[_idx]; }          ///< Get element at index '_idx'
        T &at(size_t _idx)       { return array[_idx]; }          ///< Get element at index '_idx'
  const T &front(void) const { return array[0]; }                 ///< Get the first element in the qvector
        T &front(void)       { return array[0]; }                 ///< Get the first element in the qvector
  const T &back(void) const { return array[n-1]; }                ///< Get the last element in the qvector
        T &back(void)       { return array[n-1]; }                ///< Get the last element in the qvector
  /// Destroy all elements but do not free memory
  void qclear(void)
  {
    resize_less(0);
  }
  /// Destroy all elements and free memory
  void clear(void)
  {
    if ( array != nullptr )
    {
      qclear();
      qfree(array);
      array = nullptr;
      alloc = 0;
    }
  }
  /// Allow assignment of one qvector to another using '='
  qvector<T> &operator=(const qvector<T> &x)
  {
    if ( this != &x )
    {
      clear();
      assign(x);
    }
    return *this;
  }
#ifndef SWIG
  /// Move assignment operator
  qvector<T> &operator=(qvector<T> &&x) noexcept
  {
    if ( this != &x )
    {
      clear();
      array = x.array; x.array = nullptr;
      n = x.n; x.n = 0;
      alloc = x.alloc; x.alloc = 0;
    }
    return *this;
  }
#endif
  /// Resize to the given size.
  /// If the given size (_newsize) is less than the current size (n) of the qvector, then the last n - _newsize elements are simply deleted.                      \n
  /// If the given size is greater than the current size, the qvector is grown to _newsize, and the last _newsize - n elements will be filled with copies of 'x'. \n
  /// If the given size is equal to the current size, this function does nothing.
  void resize(size_t _newsize, const T &x)
  {
#ifdef TESTABLE_BUILD
    QASSERT(1908, !ref_within_range(x));
#endif
    if ( _newsize < n )
      resize_less(_newsize);
    else if ( _newsize > n )
      resize_more(_newsize, x);
  }
  /// Same as resize(size_t, const T &), but extra space is filled with empty elements
  void resize(size_t _newsize)
  {
    if ( std::is_trivially_constructible<T>::value && _newsize > n )
      resize_more_trivial(_newsize);
    else
      resize(_newsize, T());
  }
#ifndef SWIG
  // Resize the array but do not initialize elements
  void resize_noinit(size_t _newsize)
  {
    CASSERT(std::is_trivially_constructible<T>::value);
    CASSERT(std::is_trivially_destructible<T>::value);
    reserve(_newsize);
    n = _newsize;
  }
#endif
  /// Add an element to the end of the qvector, which will be a new T() if x is not given
  void grow(const T &x=T())
  {
#ifdef TESTABLE_BUILD
    QASSERT(1909, !ref_within_range(x));
#endif
    reserve(n+1);
    new(array+n) T(x);
    ++n;
  }
  /// Get the number of elements that this qvector can contain - not the same
  /// as the number of elements currently in the qvector (size())
  size_t capacity(void) const { return alloc; }
  /// Increase the capacity of the qvector. If cnt is not greater than the current capacity
  /// this function does nothing.
  void reserve(size_t cnt)
  {
    if ( cnt > alloc )
    {
      if ( may_move_bytes<T>() )
      {
        array = (T *)qvector_reserve(this, array, cnt, sizeof(T));
      }
      else
      {
        size_t old_alloc = alloc;
        T *new_array = (T *)qvector_reserve(this, nullptr, cnt, sizeof(T));
        size_t new_alloc = alloc;
        alloc = old_alloc;
        shift_down(new_array, array, n);
        qfree(array);
        array = new_array;
        alloc = new_alloc;
      }
    }
  }
  /// Shrink the capacity down to the current number of elements
  void truncate(void)
  {
    if ( alloc > n )
    {
      array = (T*)qrealloc(array, n*sizeof(T)); // should not fail
      alloc = n;
    }
  }
  /// Replace all attributes of this qvector with that of 'r', and vice versa.
  /// Effectively sets this = r and r = this without copying/allocating any memory.
  void swap(qvector<T> &r) noexcept
  {
    T *array2     = array;
    size_t n2     = n;
    size_t alloc2 = alloc;

    array = r.array;
    n     = r.n;
    alloc = r.alloc;

    r.array = array2;
    r.n     = n2;
    r.alloc = alloc2;
  }
  /// Empty the qvector and return a pointer to it's contents.
  /// The caller must free the result of this function
  T *extract(void)
  {
    truncate();
    alloc = 0;
    n = 0;
    T *res = array;
    array = nullptr;
    return res;
  }
  /// Populate the qvector with dynamic memory.
  /// The qvector must be empty before calling this method!
  void inject(T *s, size_t len)
  {
    array = s;
    alloc = len;
    n = len;
  }
  /// Allow ability to test the equality of two qvectors using '=='.
  bool operator == (const qvector<T> &r) const
  {
    if ( n != r.n )
      return false;
    for ( size_t i=0; i < n; i++ )
      if ( array[i] != r[i] )
        return false;
    return true;
  }
  /// Allow ability to test equality of two qvectors using '!='
  bool operator != (const qvector<T> &r) const { return !(*this == r); }

  typedef T *iterator;
  typedef const T *const_iterator;

  iterator begin(void) { return array; }                ///< Get an iterator that points to the first element in the qvector
  iterator end(void) { return array + n; }              ///< Get an iterator that points to the end of the qvector (NOT the last element)
  const_iterator begin(void) const { return array; }    ///< Get a const iterator that points to the first element in the qvector
  const_iterator end(void) const { return array + n; }  ///< Get a const iterator that points to the end of the qvector (NOT the last element)
  /// Insert an element into the qvector at a specified position.
  /// \param it  an iterator that points to the desired position of the new element
  /// \param x  the element to insert
  /// \return an iterator that points to the newly inserted element
  iterator insert(iterator it, const T &x)
  {
#ifdef TESTABLE_BUILD
    QASSERT(1910, !ref_within_range(x));
#endif
    size_t idx = it - array;
    reserve(n+1);
    T *p = array + idx;
    size_t rest = end() - p;
    shift_up(p+1, p, rest);
    new(p) T(x);
    n++;
    return iterator(p);
  }
#ifndef SWIG
  /// Insert an element into the qvector with a move semantics.
  iterator insert(iterator it, T &&x)
  {
#ifdef TESTABLE_BUILD
    QASSERT(1978, !ref_within_range(x));
#endif
    size_t idx = it - array;
    reserve(n+1);
    T *p = array + idx;
    size_t rest = end() - p;
    shift_up(p+1, p, rest);
    new(p) T(x);
    n++;
    return iterator(p);
  }
#endif
  /// Insert a several elements to the qvector at a specified position.
  /// \param it     position at which new elements will be inserted
  /// \param first  pointer to first element to be inserted
  /// \param last   pointer to end of elements to be inserted (the element pointed to by 'last' will not be included)
  /// \return an iterator that points to the first newly inserted element.
  template <class it2> iterator insert(iterator it, it2 first, it2 last)
  {
    size_t cnt = last - first;
    if ( cnt == 0 )
      return it;

    size_t idx = it - array;
    reserve(n+cnt);
    T *p = array + idx;
    size_t rest = end() - p;
    shift_up(p+cnt, p, rest);
    while ( first != last )
    {
      new(p) T(*first);
      ++p;
      ++first;
    }
    n += cnt;
    return iterator(array+idx);
  }
  /// Remove an element from the qvector.
  /// \param it  pointer to element to be removed
  /// \return pointer to the element that took its place
  iterator erase(iterator it)
  {
    it->~T();
    size_t rest = end() - it - 1;
    shift_down(it, it+1, rest);
    n--;
    return it;
  }
  /// Remove a subset of the qvector.
  /// \param first  pointer to head of subset to be removed
  /// \param last   pointer to end of subset to be removed (element pointed to by last will not be removed)
  /// \return a pointer to the element that took the place of 'first'
  iterator erase(iterator first, iterator last)
  {
    for ( T *p=first; p != last; ++p )
      p->~T();
    size_t rest = end() - last;
    shift_down(first, last, rest);
    n -= last - first;
    return first;
  }
  // non-standard extensions:
  /// Find an element in the qvector.
  /// \param x  element to find
  /// \return an iterator that points to the first occurrence of 'x'
  iterator find(const T &x)
  {
    iterator p;
    const_iterator e;
    for ( p=begin(), e=end(); p != e; ++p )
      if ( x == *p )
        break;
    return p;
  }
  /// \copydoc find
  const_iterator find(const T &x) const
  {
    const_iterator p, e;
    for ( p=begin(), e=end(); p != e; ++p )
      if ( x == *p )
        break;
    return p;
  }
#ifndef SWIG
  /// Find index of the specified value or return -1
  ssize_t index(const T &x) const
  {
    for ( const_iterator p=begin(), e=end(); p != e; ++p )
      if ( x == *p )
        return p - begin();
    return -1;
  }
  /// Add an element to the end of the qvector
  void add(const T &x) { push_back(x); }
  void add(T &&x) { push_back(x); }
#endif
  /// Does the qvector contain x?
  bool has(const T &x) const { return find(x) != end(); }
  /// Add an element to the end of the qvector - only if it isn't already present.
  /// \param x  the element to add
  /// \return false if 'x' is already in the qvector, true otherwise
  bool add_unique(const T &x)
  {
    if ( has(x) )
      return false;
    push_back(x);
    return true;
  }
  /// Find an element and remove it.
  /// \param x  the element to remove
  /// \return false if 'x' was not found, true otherwise
  bool del(const T &x)
  {
    iterator p = find(x);
    if ( p == end() )
      return false;
    erase(p);
    return true;
  }
#ifndef SWIG
  const char *dstr(void) const; // debug print
#endif
};

typedef qvector<uval_t> uvalvec_t;    ///< vector of unsigned values
typedef qvector<sval_t> svalvec_t;    ///< vector of signed values
typedef qvector<ea_t> eavec_t;        ///< vector of addresses
typedef qvector<int> intvec_t;        ///< vector of integers
typedef qvector<bool> boolvec_t;      ///< vector of bools
typedef qvector<size_t> sizevec_t;    ///< vector of sizes

/// Reimplementation of stack class from STL.
/// The reason why we have it is because it is not compiler dependent
/// (hopefully) and therefore can be used in IDA API
template<class T>
class qstack : public qvector<T>
{
  typedef qvector<T> inherited;
public:
  T pop(void)
  {
    T v = inherited::back();
    inherited::pop_back();
    return v;
  }
  const T &top(void) const
  {
    return inherited::back();
  }
  T &top(void) { return CONST_CAST(T&)(CONST_CAST(const qstack<T>*)(this)->top()); }
  void push(const T &v)
  {
    inherited::push_back(v);
  }
};

//---------------------------------------------------------------------------
/// A custom allocator for containers.
/// May be useful for std::map and std::set, when the objects are small in size.
template<typename T>
class pool_allocator_t
{
  // allocate 4MB at once. this way for 16GB we would use 4096 pools.
  enum
  {
    pool_size = 4*1024*1024,
    pool_nelems = pool_size / sizeof(T),
  };
  // we will reuse the freed space to maintain a list of free slots.
  // for this we need the slot size to be big enough to hold a pointer.
  // also, pool elements must be smaller than the pool size.
  CASSERT(sizeof(T) >= sizeof(void *) && pool_nelems > 0);

  qvector<T *> pools;
  T *free_list = nullptr;      // singly linked list
  T *pool_ptr = nullptr;
  T *pool_end = nullptr;
  size_t live_objects = 0;

  //---------------------------------------------------------------------------
  void free_entire_pool()
  {
    for ( T *p : pools )
      qfree(p);
    pools.clear();
    free_list = nullptr;
    pool_ptr = nullptr;
    pool_end = nullptr;
  }

public:
  // boilerplate definitions that are required for allocators:
  typedef T value_type;
  typedef T *pointer;
  typedef const T *const_pointer;
  typedef T &reference;
  typedef const T &const_reference;
  typedef size_t size_type;
  typedef ptrdiff_t difference_type;
  pool_allocator_t() {} //-V730
  template<typename U> pool_allocator_t(const pool_allocator_t<U> &) {}
  pool_allocator_t(const pool_allocator_t &) {} //-V730
  pool_allocator_t &operator=(const pool_allocator_t &) { return *this; }
  pool_allocator_t(pool_allocator_t && ) = default;
  pool_allocator_t &operator=(pool_allocator_t && ) = default;
  bool operator==(const pool_allocator_t &r) const { return this == &r; }

  //---------------------------------------------------------------------------
  T *allocate(size_t n)
  {
    if ( n != 1 )
      return (T*)qalloc_or_throw(n*sizeof(T));

    live_objects++;
    if ( free_list != nullptr )
    {
      T *ptr = free_list;
      free_list = *(T**)ptr;
      return ptr;
    }

    if ( pool_ptr == pool_end )
    {
      pool_ptr = (T*)qalloc_or_throw(pool_nelems*sizeof(T));
      pool_end = pool_ptr + pool_nelems;
      pools.push_back(pool_ptr);
    }
    return pool_ptr++;
  }

  //---------------------------------------------------------------------------
  void deallocate(T *ptr, size_t n)
  {
    if ( n != 1 )
    {
      qfree(ptr);
    }
    else
    {
      *(T**)ptr = free_list;
      free_list = ptr;
      if ( --live_objects == 0 )
        free_entire_pool();
    }
  }
};

//---------------------------------------------------------------------------
/// Standard lexical comparison.
/// \return -1 if a < b, 1 if a > b, and 0 if a == b
template <class T> int lexcompare(const T &a, const T &b)
{
  if ( a < b )
    return -1;
  if ( a > b )
    return 1;
  return 0;
}

//---------------------------------------------------------------------------
/// Lexical comparison of two vectors. Also see lexcompare().
/// \return 0 if the two vectors are identical
///         1 if 'a' is larger than 'b'
///        -1 if 'a' is smaller than 'b'
///        otherwise return the first nonzero lexical comparison between each element in 'a' and 'b'
template <class T> int lexcompare_vectors(const T &a, const T &b)
{
  if ( a.size() != b.size() )
    return a.size() > b.size() ? 1 : -1;
  for ( int i=0; i < a.size(); i++ )
  {
    int code = lexcompare(a[i], b[i]);
    if ( code != 0 )
      return code;
  }
  return 0;
}

//---------------------------------------------------------------------------
/// Smart pointer to objects derived from ::qrefcnt_obj_t
template <class T>
class qrefcnt_t
{
  T *ptr;
  void delref(void)
  {
    if ( ptr != nullptr && --ptr->refcnt == 0 )
      ptr->release();
  }
public:
  explicit qrefcnt_t(T *p) : ptr(p) {}
  qrefcnt_t(const qrefcnt_t &r) : ptr(r.ptr)
  {
    if ( ptr != nullptr )
      ptr->refcnt++;
  }
  qrefcnt_t &operator=(const qrefcnt_t &r)
  {
    delref();
    ptr = r.ptr;
    if ( ptr != nullptr )
      ptr->refcnt++;
    return *this;
  }
  ~qrefcnt_t(void)
  {
    delref();
  }
  void reset(void)
  {
    delref();
    ptr = nullptr;
  }
  operator T *() const
  {
    return ptr;
  }
  T *operator ->() const
  {
    return ptr;
  }
  T &operator *() const
  {
    return *ptr;
  }
};

//---------------------------------------------------------------------------
/// Base class for reference count objects
class qrefcnt_obj_t
{
public:
  int refcnt; ///< counter
  /// Constructor
  qrefcnt_obj_t(void) : refcnt(1) {}
  /// Call destructor.
  /// We use release() instead of operator delete() to maintain binary
  /// compatibility with all compilers (vc and gcc use different vtable layouts
  /// for operator delete)
  virtual void idaapi release(void) = 0;
};

//---------------------------------------------------------------------------
/// Interface class for iterator types.
template <class T>
class qiterator : public qrefcnt_obj_t
{
public:
  typedef T value_type;
  virtual bool idaapi first(void) = 0;
  virtual bool idaapi next(void) = 0;
  virtual T idaapi operator *(void) = 0;
  virtual T get(void) newapi { return this->operator*(); }
};


//---------------------------------------------------------------------------
/// \name strlen
/// Get the length of the given string
//@{
inline THREAD_SAFE size_t idaapi qstrlen(const char *s) { return strlen(s); }
inline THREAD_SAFE size_t idaapi qstrlen(const uchar *s) { return strlen((const char *)s); }
idaman THREAD_SAFE size_t ida_export qstrlen(const wchar16_t *s);
//@}

/// \name strcmp
/// Lexical comparison of strings.
/// \return 0 if two strings are identical
///         > 0 if 's1' is larger than 's2'
///         < 0 if 's2' is larger than 's1'
///         otherwise return first nonzero comparison between chars in 's1' and 's2'
//@{
inline THREAD_SAFE int idaapi qstrcmp(const char *s1, const char *s2) { return strcmp(s1, s2); }
inline THREAD_SAFE int idaapi qstrcmp(const uchar *s1, const uchar *s2) { return strcmp((const char *)s1, (const char *)s2); }
idaman THREAD_SAFE int ida_export qstrcmp(const wchar16_t *s1, const wchar16_t *s2);
//@}

/// \name strstr
/// Find a string within another string.
/// \return a pointer to the first occurrence of 's2' within 's1', nullptr if s2 is not found in s1
//@{
inline THREAD_SAFE const char *idaapi qstrstr(const char *s1, const char *s2) { return strstr(s1, s2); }
inline THREAD_SAFE const uchar *idaapi qstrstr(const uchar *s1, const uchar *s2) { return (const uchar *)strstr((const char *)s1, (const char *)s2); }
//@}

/// \name strchr
/// Find a character within a string.
/// \return a pointer to the first occurrence of 'c' within 's1', nullptr if c is not found in s1
//@{
inline THREAD_SAFE char *idaapi qstrchr(char *s1, char c) { return strchr(s1, c); }
inline THREAD_SAFE const char *idaapi qstrchr(const char *s1, char c) { return strchr(s1, c); }
inline THREAD_SAFE uchar *idaapi qstrchr(uchar *s1, uchar c) { return (uchar *)strchr((char *)s1, c); }
inline THREAD_SAFE const uchar *idaapi qstrchr(const uchar *s1, uchar c) { return (const uchar *)strchr((const char *)s1, c); }
idaman THREAD_SAFE const wchar16_t *ida_export qstrchr(const wchar16_t *s1, wchar16_t c);
inline THREAD_SAFE wchar16_t *idaapi qstrchr(wchar16_t *s1, wchar16_t c)
  { return (wchar16_t *)qstrchr((const wchar16_t *)s1, c); }
//@}

/// \name qstrrchr
/// Find a last occurrence of a character within a string.
/// \return a pointer to the last occurrence of 'c' within 's1', nullptr if c is not found in s1
//@{
inline THREAD_SAFE const char *idaapi qstrrchr(const char *s1, char c) { return strrchr(s1, c); }
inline THREAD_SAFE char *idaapi qstrrchr(char *s1, char c) { return strrchr(s1, c); }
inline THREAD_SAFE const uchar *idaapi qstrrchr(const uchar *s1, uchar c) { return (const uchar *)strrchr((const char *)s1, c); }
inline THREAD_SAFE uchar *idaapi qstrrchr(uchar *s1, uchar c) { return (uchar *)strrchr((const char *)s1, c); }
idaman THREAD_SAFE const wchar16_t *ida_export qstrrchr(const wchar16_t *s1, wchar16_t c);
inline THREAD_SAFE wchar16_t *idaapi qstrrchr(wchar16_t *s1, wchar16_t c)
  { return (wchar16_t *)qstrrchr((const wchar16_t *)s1, c); }
//@}

/// \defgroup qstring_split_flags Flags for _qstring::split
//@{
#define SSF_DROP_EMPTY 0x1 ///< drop empty parts
//@}

//---------------------------------------------------------------------------
/// Reimplementation of the string class from STL.
/// Only the most essential functions are implemented.
/// The reason why we have this is because it is not compiler dependent
/// (hopefully) and therefore can be used in IDA API
template<class qchar>
class _qstring
{
  qvector<qchar> body;
  void assign(const qchar *ptr, size_t len)
  {
    body.resize_noinit(len+1);
    memmove(body.begin(), ptr, len*sizeof(qchar));
    body[len] = '\0';
  }
public:
  /// Constructor
  _qstring(void) {}
  /// Constructor - creates a new qstring from an existing char *
  _qstring(const qchar *ptr)
  {
    if ( ptr != nullptr )
      assign(ptr, ::qstrlen(ptr));
  }
  /// Constructor - creates a new qstring using first 'len' chars from 'ptr'
  _qstring(const qchar *ptr, size_t len)
  {
    if ( len > 0 )
      assign(ptr, len);
  }
  /// Constructor - constructs the string with 'count' copies of character 'ch'
  _qstring(size_t count, qchar ch)
  {
    if ( count > 0 )
    {
      body.resize(count+1, ch);
      body[count] = 0; // ensure the terminating zero
    }
  }
#ifndef SWIG
  /// Move constructor
  _qstring(_qstring &&x) : body(std::move(x.body)) {}
  /// Copy constructor (if not declared, move constructor causes it to be deleted)
  _qstring(const _qstring &r) : body(r.body) {}
#endif
  void swap(_qstring<qchar> &r) { body.swap(r.body); }                        ///< Swap contents of two qstrings. see qvector::swap()
  size_t length(void) const { size_t l = body.size(); return l ? l - 1 : 0; } ///< Get number of chars in this qstring (not including terminating zero)
  size_t size(void) const { return body.size(); }                             ///< Get number of chars in this qstring (including terminating zero)
  size_t capacity(void) const { return body.capacity(); }                     ///< Get number of chars this qstring can contain (including terminating zero)

  /// Resize to the given size.
  /// The resulting qstring will have length() = s, and size() = s+1                   \n
  /// if 's' is greater than the current size then the extra space is filled with 'c'. \n
  /// if 's' is less than the current size then the trailing chars are removed
  void resize(size_t s, qchar c)
  {
    size_t oldsize = body.size();
    if ( oldsize != 0 && s >= oldsize )
      body[oldsize-1] = c; // erase the terminating zero
    body.resize(s+1, c);
    body[s] = 0; // ensure the terminating zero
  }
  /// Similar to resize(size_t, qchar) - but any extra space is filled with zeroes
  void resize(size_t s)
  {
    if ( s == 0 )
    {
      body.clear();
    }
    else
    {
      body.resize(s+1);
      body[s] = 0; // ensure the terminating zero
    }
  }
  void remove_last(int cnt=1)
  {
    ssize_t len = body.size() - cnt;
    if ( len <= 1 )
    {
      body.clear();
    }
    else
    {
      body.resize_noinit(len);
      body[len-1] = 0;
    }
  }
  void reserve(size_t cnt) { body.reserve(cnt); }     ///< Increase capacity the qstring. see qvector::reserve()
  void clear(void) { body.clear(); }                  ///< Clear qstring and free memory
  void qclear(void) { body.qclear(); }                ///< Clear qstring but do not free memory yet
  bool empty(void) const { return body.size() <= 1; } ///< Does the qstring have 0 non-null elements?
  /// Convert the qstring to a char *
  const qchar *c_str(void) const
  {
    static const qchar nullstr[] = { 0 };
    return body.empty() ? nullstr : &body[0];
  }
  typedef qchar *iterator;
  typedef const qchar *const_iterator;
        iterator begin(void)       { return body.begin(); } ///< Get a pointer to the beginning of the qstring
  const_iterator begin(void) const { return body.begin(); } ///< Get a const pointer to the beginning of the qstring
        iterator end(void)       { return body.end(); }     ///< Get a pointer to the end of the qstring (this is not the terminating zero)
  const_iterator end(void) const { return body.end(); }     ///< Get a const pointer to the end of the qstring (this is not the terminating zero)
  /// Allow assignment of qstrings using '='
  _qstring &operator=(const qchar *str)
  {
    size_t len = str == nullptr ? 0 : ::qstrlen(str);
    if ( len > 0 )
      assign(str, len);
    else
      qclear();
    return *this;
  }
  _qstring &operator=(const _qstring &qstr)
  {
    if ( this != &qstr )
    {
      size_t len = qstr.length();
      if ( len > 0 )
        assign(qstr.begin(), len);
      else
        qclear();
    }
    return *this;
  }
#ifndef SWIG
  /// Move assignment operator
  _qstring &operator=(_qstring &&x) noexcept
  {
    body = std::move(x.body);
    return *this;
  }
#endif
  /// Append a char using '+='
  _qstring &operator+=(qchar c)
  {
    return append(c);
  }
  /// Append another qstring using '+='
  _qstring &operator+=(const _qstring &r)
  {
    return append(r);
  }
  /// Get result of appending two qstrings using '+'
  _qstring operator+(const _qstring &r) const
  {
    _qstring s = *this;
    s += r;
    return s;
  }
  DECLARE_COMPARISONS(_qstring)
  {
    return ::qstrcmp(c_str(), r.c_str());
  }
  /// Test equality of a qstring and a const char* using '=='
  bool operator==(const qchar *r) const
  {
    return ::qstrcmp(c_str(), r) == 0;
  }
  bool operator!=(const qchar *r) const { return !(*this == r); }     ///< Test equality of a qstring and a const char* with '!='
  /// Compare two qstrings using '<'. see qstrcmp()
  bool operator<(const qchar *r) const
  {
    return ::qstrcmp(c_str(), r) < 0;
  }
  /// Does the string start with the specified prefix?
  bool starts_with(const _qstring &str) const
  {
    return starts_with(str.begin(), str.length());
  }
  bool starts_with(const qchar *ptr, ssize_t len = -1) const
  {
    if ( ptr == nullptr )
      return true;
    if ( len == -1 )
      len = ::qstrlen(ptr);
    if ( len == 0 )
      return true;
    if ( length() < len )
      return false;
    return strneq(begin(), ptr, len);
  }
  /// Does the string end with the specified suffix?
  bool ends_with(const _qstring &str) const
  {
    return ends_with(str.begin(), str.length());
  }
  bool ends_with(const qchar *ptr, ssize_t len = -1) const
  {
    if ( ptr == nullptr )
      return true;
    if ( len == -1 )
      len = ::qstrlen(ptr);
    if ( len == 0 )
      return true;
    size_t l = length();
    if ( l < len )
      return false;
    return strneq(begin() + l - len, ptr, len);
  }
  /// Retrieve char at index 'idx' using '[]'
  const qchar &operator[](size_t idx) const
  {
    if ( !body.empty() || idx )
      return body[idx];
    static const qchar nullstr[] = { 0 };
    return nullstr[0];
  }
  /// Retrieve char at index 'idx' using '[]'
  qchar &operator[](size_t idx)
  {
    if ( !body.empty() || idx )
      return body[idx];
    static qchar nullstr[] = { 0 };
    return nullstr[0];
  }
  const qchar &at(size_t idx) const { return body.at(idx); } ///< Retrieve const char at index 'idx'
  qchar &at(size_t idx) { return body.at(idx); }             ///< Retrieve char at index 'idx'
  /// Extract C string from _qstring. Must qfree() it.
  qchar *extract(void) { return body.extract(); }
  /// Assign this qstring to an existing char *.
  /// See qvector::inject(T *, size_t)
  void inject(qchar *s, size_t len)
  {
    body.inject(s, len);
  }
  /// Same as to inject(qchar *, size_t), with len = strlen(s)
  void inject(qchar *s)
  {
    if ( s != nullptr )
    {
      size_t len = ::qstrlen(s) + 1;
      body.inject(s, len);
    }
  }
  /// Get the last qchar in the string (for concatenation checks)
  qchar last(void) const
  {
    size_t len = length();
    return len == 0 ? '\0' : body[len-1];
  }
  /// Find a substring.
  /// \param str  the substring to look for
  /// \param pos  starting position
  /// \return the position of the beginning of the first occurrence of str, _qstring::npos of none exists
  size_t find(const qchar *str, size_t pos=0) const
  {
    if ( pos <= length() )
    {
      const qchar *beg = c_str();
      const qchar *ptr = ::qstrstr(beg+pos, str);
      if ( ptr != nullptr )
        return ptr - beg;
    }
    return npos;
  }
  /// Replace all occurrences of 'what' with 'with'.
  /// \return false if 'what' is not found in the qstring, true otherwise
  bool replace(const qchar *what, const qchar *with)
  {
    _qstring result;
    size_t len_what = ::qstrlen(what);
    const qchar *_start = c_str();
    const qchar *last_pos = _start;
    while ( true )
    {
      const qchar *pos = ::qstrstr(last_pos, what);
      if ( pos == nullptr )
        break;
      size_t n = pos - last_pos;
      if ( n > 0 )
        result.append(last_pos, n);
      result.append(with);
      last_pos = pos + len_what;
    }
    // no match at all?
    if ( last_pos == _start )
      return false;
    // any pending characters?
    if ( *last_pos )
      result.append(last_pos);
    swap(result);
    return true;
  }
  /// Same as find(const qchar *, size_t), but takes a qstring parameter
  size_t find(const _qstring &str, size_t pos=0) const { return find(str.c_str(), pos); }
  /// Find a character in the qstring.
  /// \param c    the character to look for
  /// \param pos  starting position
  /// \return index of first occurrence of 'c' if c is found, _qstring::npos otherwise
  size_t find(qchar c, size_t pos=0) const
  {
    if ( pos <= length() )
    {
      const qchar *beg = c_str();
      const qchar *ptr = qstrchr(beg+pos, c);
      if ( ptr != nullptr )
        return ptr - beg;
    }
    return npos;
  }
  /// Search backwards for a character in the qstring.
  /// \param c    the char to look for
  /// \param pos  starting position
  /// \return index of first occurrence of 'c' if c is found, _qstring::npos otherwise
  size_t rfind(qchar c, size_t pos=0) const
  {
    if ( pos <= length() )
    {
      const qchar *beg = c_str();
      const qchar *ptr = qstrrchr(beg+pos, c);
      if ( ptr != nullptr )
        return ptr - beg;
    }
    return npos;
  }
  /// Get a substring.
  /// \param pos   starting position
  /// \param n     ending position (non-inclusive)
  /// \return the resulting substring
  _qstring<qchar> substr(size_t pos=0, size_t n=npos) const
  {
    size_t endp = qmin(length(), n);
    if ( pos >= endp )
      pos = endp;
    return _qstring<qchar>(c_str()+pos, endp-pos);
  }
  /// Remove characters from the qstring.
  /// \param idx  starting position
  /// \param cnt  number of characters to remove
  _qstring &remove(size_t idx, size_t cnt)
  {
    size_t len = length();
    if ( idx < len && cnt != 0 )
    {
      cnt += idx;
      if ( cnt < len )
      {
        iterator p1 = body.begin() + cnt;
        iterator p2 = body.begin() + idx;
        memmove(p2, p1, (len-cnt)*sizeof(qchar));
        idx += len - cnt;
      }
      body.resize_noinit(idx+1);
      body[idx] = '\0';
    }
    return *this;
  }
  /// Insert a character into the qstring.
  /// \param idx  position of insertion (if idx >= length(), the effect is the same as append)
  /// \param c    char to insert
  _qstring &insert(size_t idx, qchar c)
  {
    size_t len = length();
    body.resize_noinit(len+2);
    body[len+1] = '\0';
    if ( idx < len )
    {
      iterator p1 = body.begin() + idx;
      memmove(p1+1, p1, (len-idx)*sizeof(qchar));
      len = idx;
    }
    body[len] = c;
    return *this;
  }
  /// Insert a string into the qstring.
  /// \param idx     position of insertion (if idx >= length(), the effect is the same as append)
  /// \param str     the string to insert
  /// \param addlen  number of chars from 'str' to insert
  _qstring &insert(size_t idx, const qchar *str, size_t addlen)
  {
    size_t len = length();
    body.resize_noinit(len+addlen+1);
    body[len+addlen] = '\0';
    if ( idx < len )
    {
      iterator p1 = body.begin() + idx;
      iterator p2 = p1 + addlen;
      memmove(p2, p1, (len-idx)*sizeof(qchar));
      len = idx;
    }
    memmove(body.begin()+len, str, addlen*sizeof(qchar));
    return *this;
  }
  /// Same as insert(size_t, const qchar *, size_t), but all chars in str are inserted
  _qstring &insert(size_t idx, const qchar *str)
  {
    if ( str != nullptr )
    {
      size_t addlen = ::qstrlen(str);
      insert(idx, str, addlen);
    }
    return *this;
  }
  /// Same as insert(size_t, const qchar *), but takes a qstring parameter
  _qstring &insert(size_t idx, const _qstring &qstr)
  {
    size_t len = length();
    size_t add = qstr.length();
    body.resize_noinit(len+add+1);
    body[len+add] = '\0';
    if ( idx < len )
    {
      iterator p1 = body.begin() + idx;
      iterator p2 = p1 + add;
      memmove(p2, p1, (len-idx)*sizeof(qchar));
      len = idx;
    }
    memcpy(body.begin()+len, qstr.begin(), add*sizeof(qchar));
    return *this;
  }
  _qstring &insert(qchar c)               { return insert(0, c);    } ///< Prepend the qstring with 'c'
  _qstring &insert(const qchar *str)      { return insert(0, str);  } ///< Prepend the qstring with 'str'
  _qstring &insert(const _qstring &qstr)  { return insert(0, qstr); } ///< Prepend the qstring with 'qstr'
  /// Append c to the end of the qstring
  _qstring &append(qchar c)
  {
    size_t len = length();
    body.resize_noinit(len+2);
    body[len] = c;
    body[len+1] = '\0';
    return *this;
  }
  /// Append a string to the qstring.
  /// \param str     the string to append
  /// \param addlen  number of characters from 'str' to append
  _qstring &append(const qchar *str, size_t addlen)
  {
    size_t len = length();
    body.resize_noinit(len+addlen+1);
    body[len+addlen] = '\0';
    memmove(body.begin()+len, str, addlen*sizeof(qchar));
    return *this;
  }
  /// Same as append(const qchar *, size_t), but all chars in 'str' are appended
  _qstring &append(const qchar *str)
  {
    if ( str != nullptr )
    {
      size_t addlen = ::qstrlen(str);
      append(str, addlen);
    }
    return *this;
  }
  /// Same as append(const qchar *), but takes a qstring argument
  _qstring &append(const _qstring &qstr)
  {
    size_t add = qstr.length();
    if ( add != 0 )
    {
      size_t len = length();
      body.resize_noinit(len+add+1);
      body[len+add] = '\0';
      memcpy(body.begin()+len, qstr.begin(), add*sizeof(qchar));
    }
    return *this;
  }
  /// Append result of qvsnprintf() to qstring
  AS_PRINTF(2, 0) _qstring &cat_vsprnt(const char *format, va_list va)
  { // since gcc64 forbids reuse of va_list, we make a copy for the second call:
    va_list copy;
    va_copy(copy, va);
    size_t add = ::qvsnprintf(nullptr, 0, format, va);
    if ( add != 0 )
    {
      size_t len = length();
      body.resize_noinit(len+add+1);
      ::qvsnprintf(body.begin()+len, add+1, format, copy);
    }
    va_end(copy);
    return *this;
  }
  /// Replace qstring with the result of qvsnprintf()
  AS_PRINTF(2, 0) _qstring &vsprnt(const char *format, va_list va)
  { // since gcc64 forbids reuse of va_list, we make a copy for the second call:
    va_list copy;
    va_copy(copy, va);
    body.clear();
    size_t add = ::qvsnprintf(nullptr, 0, format, va);
    if ( add != 0 )
    {
      body.resize_noinit(add+1);
      ::qvsnprintf(body.begin(), add+1, format, copy);
    }
    va_end(copy);
    return *this;
  }
  /// Append result of qsnprintf() to qstring
  AS_PRINTF(2, 3) _qstring &cat_sprnt(const char *format, ...)
  {
    va_list va;
    va_start(va, format);
    cat_vsprnt(format, va);
    va_end(va);
    return *this;
  }
  /// Replace qstring with the result of qsnprintf()
  AS_PRINTF(2, 3) _qstring &sprnt(const char *format, ...)
  {
    va_list va;
    va_start(va, format);
    vsprnt(format, va);
    va_end(va);
    return *this;
  }
  /// Replace qstring with the result of qsnprintf()
  /// \sa inline int nowarn_qsnprintf(char *buf, size_t size, const char *format, ...)
  GCC_DIAG_OFF(format-nonliteral);
  _qstring &nowarn_sprnt(const char *format, ...) //-V524 body is equal to sprnt
  {
    va_list va;
    va_start(va, format);
    vsprnt(format, va);
    va_end(va);
    return *this;
  }
  GCC_DIAG_ON(format-nonliteral);
  /// Fill qstring with a character.
  /// The qstring is resized if necessary until 'len' chars have been filled
  /// \param pos  starting position
  /// \param c    the character to fill
  /// \param len  number of positions to fill with 'c'
  _qstring &fill(size_t pos, qchar c, size_t len)
  {
    size_t endp = pos + len + 1;
    if ( body.size() < endp )
    {
      body.resize_noinit(endp);
      body[endp-1] = '\0';
    }
    memset(body.begin()+pos, c, len);
    return *this;
  }
  /// Clear contents of qstring and fill with 'c'
  _qstring &fill(qchar c, size_t len)
  {
    body.qclear();
    if ( len > 0 )
      resize(len, c);
    return *this;
  }
  /// Remove all instances of the specified char from the beginning of the qstring
  _qstring &ltrim(qchar blank = ' ')
  {
    if ( !empty() )
    {
      iterator b = body.begin();
      iterator e = body.end()-1;
      while ( b < e && *b == blank )
        b++;
      if ( b > body.begin() )
      {
        memmove(body.begin(), b, sizeof(qchar)*(e-b+1));
        resize(e-b);
      }
    }
    return *this;
  }
  /// Remove all instances of the specified char from the end of the qstring
  _qstring &rtrim(qchar blank, size_t minlen = 0)
  {
    if ( size() > minlen + 1 )
    {
      iterator b = body.begin() + minlen;
      iterator e = body.end() - 1;
      // assert: e > b
      while ( e > b && *(e-1) == blank )
        e--;
      resize(e - body.begin());
    }
    return *this;
  }
  /// Remove all whitespace from the end of the qstring
  _qstring &rtrim()
  {
    if ( !empty() )
    {
      iterator b = body.begin();
      iterator e = body.end() - 1;
      while ( e > b && qisspace(e[-1]) )
        --e;
      resize(e - b);
    }
    return *this;
  }
  /// Remove all instances of the specified char from both ends of the qstring
  _qstring &trim2(qchar blank = ' ')
  {
    rtrim(blank);
    ltrim(blank);
    return *this;
  }

  /// Split a string on SEP, appending the parts to OUT
  /// \param out storage
  /// \param sep the separator to split on
  /// \param flags a combination of \ref qstring_split_flags
  void split(qvector<_qstring<qchar> > *out, const qchar *sep, uint32 flags=0) const;

  /// Join the provided parts into a single string with each element
  /// separated by SEP
  /// \param parts the parts to join
  /// \param sep the separator to join on (it can be an empty string)
  /// \return the combined string
  static _qstring<qchar> join(const qvector<_qstring<qchar> > &parts, const qchar *sep);

  /// Invalid position
  static constexpr size_t npos = (size_t) -1;
};
typedef _qstring<char> qstring;       ///< regular string
typedef _qstring<uchar> qtype;        ///< type string
typedef _qstring<wchar16_t> qwstring; ///< unicode string
typedef qvector<qstring> qstrvec_t;   ///< vector of strings
typedef qvector<qwstring> qwstrvec_t; ///< vector of unicode strings

#ifndef SWIG // avoid "Warning 317: Specialization of non-template 'hash'."

// allow qstring in hashed containers
namespace std
{
  template<class T>
  struct hash<_qstring<T>>
  {
    size_t operator()(const _qstring<T> &str) const noexcept
    {
      // FNV-1a, as per Wikipedia
#ifdef __X86__
      const size_t FNV_BASIS = 0x811c9dc5;
      const size_t FNV_PRIME = 0x01000193;
#else
      const size_t FNV_BASIS = 0xcbf29ce484222325;
      const size_t FNV_PRIME = 0x100000001b3;
#endif
      size_t sum = FNV_BASIS;
      for ( T c : str )
      {
        sum ^= c;
        sum *= FNV_PRIME;
      }
      return sum;
    }
  };
}
#endif

template <> inline
void qstring::split(qstrvec_t *out, const char *sep, uint32 flags) const
{
  size_t seplen = ::qstrlen(sep);
  const char *p = begin();
  const char *const end = p + length();
  while ( p < end )
  {
    const char *psep = ::qstrstr(p, sep);
    size_t rem = (psep != nullptr ? psep : end) - p;
    if ( rem > 0 || (flags & SSF_DROP_EMPTY) == 0 )
      out->push_back().append(p, rem);
    p = psep != nullptr ? psep + seplen : end;
  }
}

template <> inline
qstring qstring::join(const qstrvec_t &parts, const char *sep)
{
  qstring buf;
  size_t nparts = parts.size();
  if ( nparts > 0 )
  {
    size_t seplen = ::qstrlen(sep);
    size_t total = (nparts - 1) * seplen; // separators
    for ( const auto &one : parts )
      total += one.length();
    buf.reserve(total);
    for ( const auto &one : parts )
    {
      if ( !buf.empty() )
        buf.append(sep, seplen);
      buf.append(one);
    }
  }
  return buf;
}

/// Vector of bytes (use for dynamic memory)
class bytevec_t: public qvector<uchar>
{
public:
  /// Constructor
  bytevec_t() {}
  /// Constructor - fill bytevec with 'sz' bytes from 'buf'
  bytevec_t(const void *buf, size_t sz) { append(buf, sz); }
  /// Append bytes to the bytevec
  /// \param buf   pointer to buffer that will be appended
  /// \param sz    size of buffer
  bytevec_t &append(const void *buf, size_t sz)
  {
    if ( sz > 0 )
    {
      size_t cur_sz = size();
      size_t new_sz = cur_sz + sz;
      if ( new_sz < cur_sz )
        new_sz = BADMEMSIZE; // integer overflow, ask too much and it will throw
      resize(new_sz);
      memcpy(begin() + cur_sz, buf, sz);
    }
    return *this;
  }
  /// Pack a byte and append the result to the bytevec
  void pack_db(uint8 x) { push_back(x); }
  /// Pack a word and append the result to the bytevec
  void pack_dw(uint16 x)
  {
    uchar packed[dw_packed_size];
    size_t len = ::pack_dw(packed, packed+sizeof(packed), x) - packed;
    append(packed, len);
  }
  /// Pack a dword and append the result to the bytevec
  void pack_dd(uint32 x)
  {
    uchar packed[dd_packed_size];
    size_t len = ::pack_dd(packed, packed+sizeof(packed), x) - packed;
    append(packed, len);
  }
  /// Pack a quadword and append the result to the bytevec
  void pack_dq(uint64 x)
  {
    uchar packed[dq_packed_size];
    size_t len = ::pack_dq(packed, packed+sizeof(packed), x) - packed;
    append(packed, len);
  }
  /// Pack an ea value and append the result to the bytevec
  void pack_ea(ea_t x)
  {
    uchar packed[ea_packed_size];
    size_t len = ::pack_ea(packed, packed+sizeof(packed), x) - packed;
    append(packed, len);
  }
  /// Pack an ea value (64bits) and append the result to the bytevec
  /// We pass ea_t as a 64-bit quantity (to be able to debug 32-bit programs with ida64)
  /// adding 1 to the address ensures that BADADDR is passed correctly.
  /// without it, 32-bit server would return 0xffffffff and ida64 would not consider it
  /// as a BADADDR.
  void pack_ea64(ea64_t ea)
  {
#ifdef __X86__
    if ( ea == BADADDR )
      ea = 0xFFFFFFFFFFFFFFFFULL;
#endif
    return pack_dq(ea+1);
  }
  /// Pack a string (length+contents) and append the result to the bytevec
  void pack_ds(const char *x)
  {
    if ( x == nullptr )
      x = "";
    size_t len = strlen(x);
#ifndef __X86__
    QASSERT(4, len <= 0xFFFFFFFF);
#endif
    pack_dd(len);
    append(x, len);
  }
  /// Pack a string (zero-terminated) and append the result to the bytevec
  void pack_str(const char *str)
  {
    if ( str == nullptr )
      str = "";
    size_t len = strlen(str) + 1;
    append(str, len);
  }
  /// Pack a string (zero-terminated) and append the result to the bytevec
  void pack_str(const qstring &s)
  {
    // the opposite operation is 'unpack_str()' which gets the length
    // when it encounters a terminating '\0'. Since we don't store the
    // string length, we cannot store zeroes that 's' might contain
    // and thus we cannot rely on its length().
    pack_str(s.c_str());
  }
  /// Pack an object of size 'len' and append the result to the bytevec
  void pack_buf(const void *buf, size_t len)
  {
#ifndef __X86__
    QASSERT(5, len <= 0xFFFFFFFF);
#endif
    pack_dd(len);
    append(buf, len);
  }
  /// Pack an object of size 'len' and append the result to the bytevec
  void pack_bytevec(const bytevec_t &b)
  {
    pack_buf(b.begin(), b.size());
  }
  /// Pack an eavec and append the result to the bytevec.
  /// Also see unpack_eavec().
  /// \param ea     when we pack an eavec, we only store the differences between each
  ///               value and this parameter.                                                  \n
  ///               This is because groups of ea values will likely be similar, and therefore
  ///               the differences will usually be small.                                     \n
  ///               A good example is packing the addresses of a function prologue.            \n
  ///               One can pass the start ea of the function as this parameter,
  ///               which results in a quick and efficient packing/unpacking.                  \n
  ///               (Just be sure to use the func's start ea when unpacking, of course)
  /// \param vec  eavec to pack
  void pack_eavec(ea_t ea, const eavec_t &vec)
  {
    int nelems = vec.size();
    pack_dw(nelems); // 16bits, fixme!
    ea_t old = ea;
    for ( int i=0; i < nelems; i++ )
    {
      ea_t nea = vec[i];
      pack_ea(nea-old);
      old = nea;
    }
  }

  /// Grow the bytevec and fill with a value
  /// \param sz      number of bytes to add to bytevec
  /// \param filler  filler value
  bytevec_t &growfill(size_t sz, uchar filler=0)
  {
    if ( sz > 0 )
    {
      size_t cur_sz = size();
      size_t new_sz = cur_sz + sz;
      if ( new_sz < cur_sz )
        new_sz = BADMEMSIZE; // integer overflow, ask too much and it will throw
      resize(new_sz, filler);
    }
    return *this;
  }
  /// See qvector::inject(T *, size_t)
  void inject(void *buf, size_t len)
  {
    qvector<uchar>::inject((uchar *)buf, len);
  }

  /// Append the hexadecimal representation of bytes to the string
  void tohex(qstring *out, bool upper_case=true) const
  {
    size_t len = out->length();
    out->resize(len + size() * 2);
    char *p = out->begin() + len;
    char *end = out->end();
    for ( uchar c: *this )
    {
      ::qsnprintf(p, end - p, upper_case ? "%02X" : "%02x", c);
      p += 2;
    }
  }
  /// Initialize from a hexadecimal string
  /// It returns 'false' if the string is invalid
  bool fromhex(const qstring &str)
  {
    resize(str.length() / 2);
    const char *p = str.begin();
    for ( uchar &c: *this )
    {
      uint b = 0;
      if ( ::qsscanf(p, "%02X", &b) != 1 || b > 0xFF )
        break;
      c = uchar(b);
      p += 2;
    }
    return p == str.begin() + str.length();
  }

  /// Is the specified bit set in the bytevec?
  bool test_bit(size_t bit) const   { return ::test_bit(begin(), bit); }
  /// Set the specified bit
  void set_bit(size_t bit)          { ::set_bit(begin(), bit); }
  /// Clear the specified bit
  void clear_bit(size_t bit)        { ::clear_bit(begin(), bit); }
  /// See set_all_bits(uchar *, size_t)
  void set_all_bits(size_t nbits)   { resize_noinit((nbits+7)/8); ::set_all_bits(begin(), nbits); }
  /// See clear_all_bits(uchar *, size_t)
  void clear_all_bits(size_t nbits) { ::clear_all_bits(begin(), nbits); }
  /// Are all bits cleared?
  bool all_zeros() const
  {
    for ( size_t i = 0; i < size(); ++i )
      if ( at(i) != 0 )
        return false;
    return true;
  }
  /// For each bit that is set in 'b', set the corresponding bit in this bytevec
  void set_bits(const bytevec_t &b)
  {
    size_t nbytes = b.size();
    if ( size() < nbytes )
      resize(nbytes);
    for ( size_t i=0; i < nbytes; i++ )
      at(i) |= b[i];
  }
  /// Set each bit between [low, high)
  void set_bits(size_t low, size_t high) { ::set_bits(begin(), low, high); }
  /// For each bit that is set in 'b', the clear the corresponding bit in this bytevec
  void clear_bits(const bytevec_t &b)
  {
    size_t nbytes = qmin(size(), b.size());
    iterator p = begin();
    for ( size_t i=0; i < nbytes; i++, ++p )
      *p = (uchar)(*p & ~b[i]);
  }
  /// Clear each bit between [low, high)
  void clear_bits(size_t low, size_t high) { ::clear_bits(begin(), low, high); }
};

/// Relocation information (relocatable objects - see ::relobj_t)
struct reloc_info_t : public bytevec_t
{
/// \defgroup RELOBJ_ Relocatable object info flags
/// used by relobj_t::ri
//@{
#define RELOBJ_MASK 0xF    ///< the first byte describes the relocation entry types
#define   RELSIZE_1     0  ///< 8-bit relocations
#define   RELSIZE_2     1  ///< 16-bit relocations
#define   RELSIZE_4     2  ///< 32-bit relocations
#define   RELSIZE_8     3  ///< 64-bit relocations
#define   RELSIZE_CUST 15  ///< custom relocations, should be handled internally
#define RELOBJ_CNT 0x80    ///< counter present (not used yet)
//@}
};

idaman THREAD_SAFE bool ida_export relocate_relobj(struct relobj_t *_relobj, ea_t ea, bool mf);

/// Relocatable object
struct relobj_t : public bytevec_t
{
  ea_t base;                            ///< current base
  reloc_info_t ri;                      ///< relocation info

  relobj_t(void) : base(0) {}
  bool relocate(ea_t ea, bool mf) { return relocate_relobj(this, ea, mf); } ///< mf=1:big endian
};

#define QLIST_DEFINED ///< signal that the qlist class has been defined
/// Linked list
/// Note: linked list is not movable!
template <class T> class qlist
{
  struct listnode_t
  {
    listnode_t *next;
    listnode_t *prev;
    void fix_links(size_t len)
    {
      if ( len == 0 )
      {
        next = this;
        prev = this;
      }
      else
      {
        next->prev = this;
        prev->next = this;
      }
    }
  };

  struct datanode_t : public listnode_t
  {
    T data;
  };

  listnode_t node;
  size_t length;

  void init(void)
  {
    node.next = &node;
    node.prev = &node;
    length = 0;
  }

public:
  typedef T value_type;
  class const_iterator;
/// Used for defining the 'iterator' and 'const_iterator' classes for qlist
#define DEFINE_LIST_ITERATOR(iter, constness, cstr)                     \
  class iter                                                            \
  {                                                                     \
    friend class qlist<T>;                                              \
    constness listnode_t *cur;                                          \
    iter(constness listnode_t *x) : cur(x) {}                           \
  public:                                                               \
    typedef constness T value_type;                                     \
    iter(void) : cur(nullptr) {}                                           \
    iter(const iter &x) : cur(x.cur) {}                                 \
    cstr                                                                \
    iter &operator=(const iter &x) { cur = x.cur; return *this; }       \
    bool operator==(const iter &x) const { return cur == x.cur; }       \
    bool operator!=(const iter &x) const { return cur != x.cur; }       \
    constness T &operator*(void) const { return ((datanode_t*)cur)->data; }  \
    constness T *operator->(void) const { return &(operator*()); } \
    iter &operator++(void)       /* prefix ++  */                       \
    {                                                                   \
      cur = cur->next;                                                  \
      return *this;                                                     \
    }                                                                   \
    iter operator++(int)         /* postfix ++ */                       \
    {                                                                   \
      iter tmp = *this;                                                 \
      ++(*this);                                                        \
      return tmp;                                                       \
    }                                                                   \
    iter &operator--(void)       /* prefix --  */                       \
    {                                                                   \
      cur = cur->prev;                                                  \
      return *this;                                                     \
    }                                                                   \
    iter operator--(int)         /* postfix -- */                       \
    {                                                                   \
      iter tmp = *this;                                                 \
      --(*this);                                                        \
      return tmp;                                                       \
    }                                                                   \
  };
  DEFINE_LIST_ITERATOR(iterator,, friend class const_iterator; )
  DEFINE_LIST_ITERATOR(const_iterator, const, const_iterator(const iterator &x) : cur(x.cur) {} )

/// Used to define qlist::reverse_iterator and qlist::const_reverse_iterator
#define DEFINE_REVERSE_ITERATOR(riter, iter)                            \
  class riter                                                           \
  {                                                                     \
    iter p;                                                             \
  public:                                                               \
    riter(void) {}                                                      \
    riter(const iter &x) : p(x) {}                                      \
    typename iter::value_type &operator*(void) const { iter q=p; return *--q; }  \
    typename iter::value_type *operator->(void) const { return &(operator*()); } \
    riter &operator++(void) { --p; return *this; }                      \
    riter  operator++(int) { iter q=p; --p; return q; }                 \
    riter &operator--(void) { ++p; return *this; }                      \
    riter  operator--(int) { iter q=p; ++p; return q; }                 \
    bool operator==(const riter &x) const { return p == x.p; }          \
    bool operator!=(const riter &x) const { return p != x.p; }          \
  };
  DEFINE_REVERSE_ITERATOR(reverse_iterator, iterator)
  DEFINE_REVERSE_ITERATOR(const_reverse_iterator, const_iterator)
#undef DEFINE_LIST_ITERATOR
#undef DEFINE_REVERSE_ITERATOR
  /// Constructor
  qlist(void) { init(); }
  /// Constructor - creates a qlist identical to 'x'
  qlist(const qlist<T> &x)
  {
    init();
    insert(begin(), x.begin(), x.end());
  }
  /// Destructor
  ~qlist(void)
  {
    clear();
  }
  DEFINE_MEMORY_ALLOCATION_FUNCS()

  /// Construct a new qlist using '='
  qlist<T> &operator=(const qlist<T> &x)
  {
    if ( this != &x )
    {
      iterator first1 = begin();
      iterator last1 = end();
      const_iterator first2 = x.begin();
      const_iterator last2 = x.end();
      while ( first1 != last1 && first2 != last2 )
        *first1++ = *first2++;
      if ( first2 == last2 )
        erase(first1, last1);
      else
        insert(last1, first2, last2);
    }
    return *this;
  }
  /// Set this = x and x = this, without copying any memory
  void swap(qlist<T> &x)
  {
    std::swap(node, x.node);
    std::swap(length, x.length);
    node.fix_links(length);
    x.node.fix_links(x.length);
  }

  iterator begin(void) { return node.next; }      ///< Get a pointer to the head of the list
  iterator end(void) { return &node; }            ///< Get a pointer to the end of the list
  bool empty(void) const { return length == 0; }  ///< Get true if the list has 0 elements
  size_t size(void) const { return length; }      ///< Get the number of elements in the list
  T &front(void) { return *begin(); }             ///< Get the first element in the list
  T &back(void) { return *(--end()); }            ///< Get the last element in the list

  const_iterator begin(void) const { return node.next; } ///< \copydoc begin
  const_iterator end(void) const { return &node; }       ///< \copydoc end
  const T&front(void) const { return *begin(); }         ///< \copydoc front
  const T&back(void) const { return *(--end()); }        ///< \copydoc end

  reverse_iterator rbegin() { return reverse_iterator(end()); }                   ///< Get a reverse iterator that points to end of list. See DEFINE_REVERSE_ITERATOR
  reverse_iterator rend() { return reverse_iterator(begin()); }                   ///< Get a reverse iterator that points to beginning of list. See DEFINE_REVERSE_ITERATOR
  const_reverse_iterator rbegin() const { return const_reverse_iterator(end()); } ///< See rbegin()
  const_reverse_iterator rend() const { return const_reverse_iterator(begin()); } ///< See rend()

  /// Insert an element into the qlist.
  /// \param p  the position to insert the element
  /// \param x  the element to be inserted
  /// \return position of newly inserted element
  iterator insert(iterator p, const T &x)
  {
    datanode_t *tmp = (datanode_t*)qalloc_or_throw(sizeof(datanode_t));
    new (&(tmp->data)) T(x);
    linkin(p, tmp);
    return tmp;
  }
  /// Insert an empty element into the qlist.
  /// \param p  position to insert the element
  /// \return reference to this new element
  iterator insert(iterator p)
  {
    datanode_t *tmp = (datanode_t*)qalloc_or_throw(sizeof(datanode_t));
    new (&(tmp->data)) T();
    linkin(p, tmp);
    return tmp;
  }
  /// Insert all elements between 'first' and 'last' (non-inclusive)
  /// at position pointed to by 'p'
  template <class it2> void insert(iterator p, it2 first, it2 last)
  {
    while ( first != last )
      insert(p, *first++);
  }
  /// Insert at beginning of list
  void push_front(const T &x) { insert(begin(), x); }
  /// Insert at end of list
  void push_back(const T &x) { insert(end(), x); }
  /// Insert empty element at end of list
  T &push_back(void)
  {
    iterator p = insert(end());
    return ((datanode_t *)p.cur)->data;
  }
  /// Erase element at position pointed to by 'p'
  iterator erase(iterator p)
  {
    listnode_t *q = p.cur->next;
    p.cur->prev->next = p.cur->next;
    p.cur->next->prev = p.cur->prev;
    ((datanode_t*)p.cur)->data.~T();
    qfree(p.cur);
    --length;
    return q;
  }
  /// Erase all elements between 'p1' and 'p2'
  void erase(iterator p1, iterator p2)
  {
    while ( p1 != p2 )
      p1 = erase(p1);
  }
  /// Erase all elements in the qlist
  void clear(void) { erase(begin(), end()); }
  /// Erase first element of the qlist
  void pop_front(void) { erase(begin()); }
  /// Erase last element of the qlist
  void pop_back(void) { iterator tmp = end(); erase(--tmp); }
  /// Compare two qlists with '=='
  bool operator==(const qlist<T> &x) const
  {
    if ( length != x.length )
      return false;
    const_iterator q=x.begin();
    for ( const_iterator p=begin(), e=end(); p != e; ++p,++q )
      if ( *p != *q )
        return false;
    return true;
  }
  /// Compare two qlists with !=
  bool operator!=(const qlist<T> &x) const { return !(*this == x); }
private:
  void linkin(iterator p, listnode_t *tmp)
  {
    tmp->next = p.cur;
    tmp->prev = p.cur->prev;
    p.cur->prev->next = tmp;
    p.cur->prev = tmp;
    ++length;
  }
};

// Our containers do not care about their addresses. They can be moved around with simple memcpy
/// \cond
template <class T> struct ida_movable_type<qvector<T> >   { static constexpr bool value = true; };
template <class T> struct ida_movable_type<_qstring<T> >  { static constexpr bool value = true; };
template <class T> struct ida_movable_type<qlist<T> >     { static constexpr bool value = false; };
template <class T> struct ida_movable_type<qiterator<T> > { static constexpr bool value = true; };
/// \endcond

//----------------------------------------------------------------------------
#ifndef SWIG
/// Unpack a vector of ea values.
/// \param[out] vec    resulting vector
/// \param ea          base value that was used to pack the eavec (see pack_eavec())
/// \param ptr         pointer to packed eavec
/// \param end         pointer to end of packed eavec

THREAD_SAFE inline void unpack_eavec(
        eavec_t *vec,
        ea_t ea,
        const uchar **ptr,
        const uchar *end)
{
  ea_t old = ea;
  int n = unpack_dw(ptr, end);
  vec->resize_noinit(n);
  for ( int i=0; i < n; i++ )
  {
    old += unpack_ea(ptr, end);
    vec->at(i) = old;
  }
}

THREAD_SAFE inline bool unpack_bytevec(
        bytevec_t *out,
        const uchar **pptr,
        const uchar *end)
{
  uint32 nbytes = unpack_dd(pptr, end);
  if ( nbytes == 0 )
    return true;
  const size_t old_size = out->size();
  out->resize_noinit(old_size + nbytes);
  return unpack_obj(out->begin() + old_size, nbytes, pptr, end) != nullptr;
}

inline bool unpack_str(qstring *out, const uchar **pptr, const uchar *end)
{ // zero terminated string, append to qstring
  const char *str = unpack_str(pptr, end);
  if ( str == nullptr )
    return false;
  out->append(str, ((char*)*pptr-str) - 1);
  return true;
}

// Convenience struct for unpacking a data stream
THREAD_SAFE struct memory_deserializer_t
{
  const uchar *ptr;
  const uchar *end;

  memory_deserializer_t(const qstring &s) : ptr((uchar*)s.begin()), end(ptr+s.size()) {}
  memory_deserializer_t(const bytevec_t &b) : ptr(b.begin()), end(b.end()) {}
  memory_deserializer_t(const uchar *p, const uchar *e) : ptr(p), end(e) {}
  memory_deserializer_t(const void *p, size_t s) : ptr((uchar*)p), end(ptr+s) {}
  bool empty() const { return ptr >= end; }
  size_t size() const { return end-ptr; }
  bool advance(size_t s) { if ( size() < s ) return false; ptr += s; return true; }
  uint8  unpack_db() { return ::unpack_db(&ptr, end); }
  uint16 unpack_dw() { return ::unpack_dw(&ptr, end); }
  uint32 unpack_dd() { return ::unpack_dd(&ptr, end); }
  uint64 unpack_dq() { return ::unpack_dq(&ptr, end); }
  ea_t   unpack_ea() { return ::unpack_ea(&ptr, end); }
  ea64_t unpack_ea64() { return ::unpack_ea64(&ptr, end); }
  // unpack zero terminated string
  const char *unpack_str() { return ::unpack_str(&ptr, end); }
  bool unpack_str(qstring *out) { return ::unpack_str(out, &ptr, end); }
  // string with length prefix (dd), return string allocated in the heap
  char *unpack_ds(bool empty_null=false)
  {
    return ::unpack_ds(&ptr, end, empty_null);
  }
  // string with length prefix (dd), return in the specified buffer
  bool unpack_ds_to_buf(char *buf, size_t bufsize)
  {
    return ::unpack_ds_to_buf(buf, bufsize, &ptr, end);
  }
  const void *unpack_obj_inplace(size_t objsize)
  {
    return ::unpack_obj_inplace(&ptr, end, objsize);
  }
  const void *unpack_buf_inplace()
  {
    return ::unpack_buf_inplace(&ptr, end);
  }
  const void *unpack_obj(void *obj, size_t objsize)
  {
    return ::unpack_obj(obj, objsize, &ptr, end);
  }
  const void *unpack_buf()
  {
    return ::unpack_buf(&ptr, end);
  }
  void unpack_eavec(eavec_t *vec, ea_t ea)
  {
    ::unpack_eavec(vec, ea, &ptr, end);
  }
  bool unpack_bytevec(bytevec_t *out)
  {
    return ::unpack_bytevec(out, &ptr, end);
  }
  #define SCALAR_TYPE(n) class T, typename std::enable_if<std::is_scalar<T>::value && sizeof(T) == n, int>::type = 0
  template <SCALAR_TYPE(1)> void unpack(T *out) { *out = (T)unpack_db(); }
  template <SCALAR_TYPE(2)> void unpack(T *out) { *out = unpack_dw(); }
  template <SCALAR_TYPE(4)> void unpack(T *out) { *out = unpack_dd(); }
  template <SCALAR_TYPE(8)> void unpack(T *out) { *out = unpack_dq(); }
  #undef SCALAR_TYPE
  void unpack(qstring *out) { *out = unpack_str(); }
  template <class T>
  void unpack(qvector<T> *out)
  {
    uint32 cnt = unpack_dd();
    out->qclear();
    out->reserve(cnt);
    for ( size_t i = 0; i < cnt; i++ )
      unpack(&out->push_back());
  }
  // linput_t like interface
  ssize_t read(void *obj, size_t objsize) { return unpack_obj(obj, objsize) ? objsize : -1; }
  bool eof() const { return empty(); }
};
#define DECLARE_MEMORY_DESERIALIZER(name)                              \
  name(const void *p, size_t s) : memory_deserializer_t(p, s) {}       \
  using memory_deserializer_t::unpack;                                 \

#endif // SWIG

//-------------------------------------------------------------------------
/// Resource janitor to facilitate use of the RAII idiom
template <typename T>
struct janitor_t
{
  janitor_t(T &r) : resource(r) {} ///< Constructor
  ~janitor_t(); ///< We provide no implementation for this function, you should
                ///< provide specialized implementation yourself
protected:
  T &resource;
};

#ifndef SWIG
//-------------------------------------------------------------------------
/// Template to compare any 2 values of the same type. Returns -1/0/1
template <typename, typename = void>
struct has_compare_method : std::false_type {};
// std::void_t is from c++17, so we declare it ourselves
template< class... > using qvoid_t = void;
template <typename T>
struct has_compare_method<T, qvoid_t<decltype(std::declval<T>().compare(std::declval<T>()))>>
  : std::true_type {};
template <class T, typename std::enable_if<has_compare_method<T>::value, int>::type = 0>
int compare(const T &a, const T &b)
{
  return a.compare(b);
}
template <class T, typename std::enable_if<!has_compare_method<T>::value, int>::type = 0>
int compare(const T &a, const T &b)
{
  if ( a < b )
    return -1;
  if ( a > b )
    return 1;
  return 0;
}

//-------------------------------------------------------------------------
template <class T>
int compare(const qvector<T> &a, const qvector<T> &b)
{
  return compare_containers(a, b);
}

//-------------------------------------------------------------------------
template <class T>
int compare(const qlist<T> &a, const qlist<T> &b)
{
  return compare_containers(a, b);
}

//-------------------------------------------------------------------------
template <class T, class U>
int compare(const std::pair<T, U> &a, const std::pair<T, U> &b)
{
  int code = compare(a.first, b.first);
  if ( code != 0 )
    return code;
  return compare(a.second, b.second);
}

//-------------------------------------------------------------------------
/// Template to compare any 2 containers of the same type. Returns -1/0/1
template <class T>
int compare_containers(const T &l, const T &r)
{
  auto p = std::begin(l);
  auto pe = std::end(l);
  auto q = std::begin(r);
  auto qe = std::end(r);
  for ( ; p != pe && q != qe; ++p,++q )
  {
    int code = compare(*p, *q);
    if ( code != 0 )
      return code;
  }
  if ( p == pe && q != qe )
    return -1;
  if ( p != pe && q == qe )
    return 1;
  return 0;
}

#define COMPARE_POINTERS2(ptr, cmp)       \
  do                                      \
  {                                       \
    if ( ptr != nullptr && r.ptr != nullptr )   \
    {                                     \
      int _code = cmp(*ptr, *r.ptr);      \
      if ( _code != 0 )                   \
        return _code;                     \
    }                                     \
    else if ( r.ptr != nullptr )             \
    {                                     \
      return -1;                          \
    }                                     \
    else if ( ptr != nullptr )               \
    {                                     \
      return 1;                           \
    }                                     \
  } while (0)

#define COMPARE_POINTERS(ptr) COMPARE_POINTERS2(ptr, ::compare)

#define COMPARE_FIELDS(fld)            \
  do                                   \
  {                                    \
    int _code = ::compare(fld, r.fld); \
    if ( _code != 0 )                  \
      return _code;                    \
  } while (0)

// reverse order
#define COMPARE_FIELDS_REV(fld)        \
  do                                   \
  {                                    \
    int _code = ::compare(r.fld, fld); \
    if ( _code != 0 )                  \
      return _code;                    \
  } while (0)

template <class T, class U>
int compare(const std::map<T, U> &a, const std::map<T, U> &b)
{
  return compare_containers(a, b);
}

template <class T>
int compare(const std::set<T> &a, const std::set<T> &b)
{
  return compare_containers(a, b);
}

#endif

//-------------------------------------------------------------------------
/// Align element up to nearest boundary
template <class T> T align_up(T val, int elsize)
{
  int mask = elsize - 1;
  val += mask;
  val &= ~mask;
  return val;
}

//-------------------------------------------------------------------------
/// Align element down to nearest boundary
template <class T> T align_down(T val, int elsize)
{
  int mask = elsize - 1;
  val &= ~mask;
  return val;
}

//-------------------------------------------------------------------------
/// Declare class as uncopyable.
/// (copy assignment and copy ctr are undefined, so if anyone calls them,
///  there will be a compilation or link error)
#define DECLARE_UNCOPYABLE(T) T &operator=(const T &); T(const T &);

#ifndef SWIG
//-------------------------------------------------------------------------
// check the variable type
/// \cond
#define IS_QSTRING(v)   (std::is_base_of<qstring, std::remove_reference<decltype(v)>::type>::value)
#define IS_SIZEVEC_T(v) (std::is_base_of<sizevec_t, std::remove_reference<decltype(v)>::type>::value)
#define IS_QSTRVEC_T(v) (std::is_base_of<qstrvec_t, std::remove_reference<decltype(v)>::type>::value)

/// \endcond
#endif

#endif // __cplusplus

#ifndef __cplusplus
typedef struct bytevec_tag bytevec_t;
typedef struct qstring_tag qstring;
typedef struct qwstring_tag qwstring;
#endif

//----------------------------------------------------------------------------

/// Calculate CRC32 (polynom 0xEDB88320, zlib compatible).
/// \note in IDA versions before 6.0 a different, incompatible algorithm was used

idaman THREAD_SAFE uint32 ida_export calc_crc32(uint32 crc, const void *buf, size_t len);


/// Calculate an input source CRC32

idaman THREAD_SAFE uint32 ida_export calc_file_crc32(class linput_t *fp);


/// Encode base64

idaman THREAD_SAFE bool ida_export base64_encode(qstring *output, const void *input, size_t size);

/// Decode base64

idaman THREAD_SAFE bool ida_export base64_decode(bytevec_t *output, const char *input, size_t size); ///< Decode base64


/// Convert tabulations to spaces
/// \param out      output buffer to append to
/// \param str      input string. cannot be equal to out->c_str()
/// \param tabsize  tabulation size
/// \returns true-replaced some tabs

idaman THREAD_SAFE bool ida_export replace_tabs(qstring *out, const char *str, int tabsize);


/// \defgroup c_str_conv Functions: c strings
/// String C-style conversions (convert \\n to a newline and vice versa)
//@{
idaman THREAD_SAFE char *ida_export str2user(char *dst, const char *src, size_t dstsize); ///< Make a user representation
idaman THREAD_SAFE char *ida_export user2str(char *dst, const char *src, size_t dstsize); ///< Make an internal representation
idaman THREAD_SAFE char ida_export back_char(const char **p);                             ///< Translate char after '\\'
#ifdef __cplusplus
idaman THREAD_SAFE void ida_export qstr2user(qstring *dst, const char *src, int nsyms=-1);///< see str2user()
inline THREAD_SAFE void qstr2user(qstring *dst, const qstring &src) { qstr2user(dst, src.c_str(), src.length()); }
idaman THREAD_SAFE void ida_export user2qstr(qstring *dst, const qstring &src);           ///< see user2str()
#else
idaman THREAD_SAFE void ida_export qstr2user(qstring *dst, const qstring *src);           ///< see str2user()
idaman THREAD_SAFE void ida_export user2qstr(qstring *dst, const qstring *src);           ///< see user2str()
#endif
//@}


/// Does byte sequence consist of valid UTF-8-encoded codepoints?
/// \param in the byte sequence
/// \returns success

idaman THREAD_SAFE bool ida_export is_valid_utf8(const char *in);


#ifdef __cplusplus

/// UTF-8 -> UTF-16
/// \param out the output buffer
/// \param in the input UTF-8 byte stream
/// \param nsyms the number of UTF-8-encoded codepoints in the byte stream
/// \returns success
idaman THREAD_SAFE bool ida_export utf8_utf16(qwstring *out, const char *in, int nsyms=-1);


/// UTF-16 -> UTF-8
/// \param out the output buffer
/// \param in the input UTF-16 stream
/// \param nsyms the number of 16-bit items in 'in'. This does not necessarily
///              correspond to the number of codepoints: each surrogate pair
///              will take 2 items.
/// \returns success
idaman THREAD_SAFE bool ida_export utf16_utf8(qstring *out, const wchar16_t *in, int nsyms=-1);


inline constexpr bool is_lead_surrogate(wchar32_t wch) { return 0xD800 <= wch && wch < 0xDC00; }
inline constexpr bool is_tail_surrogate(wchar32_t wch) { return 0xDC00 <= wch && wch <= 0xDFFF; }
inline constexpr wchar32_t utf16_surrogates_to_cp(wchar16_t lead_surrogate, wchar16_t tail_surrogate)
{
  return (0x10000 + (wchar32_t(lead_surrogate & 0x3FF) << 10)) | (tail_surrogate & 0x3FF);
}


/// \defgroup IDBDEC_ IDB default encoding -> UTF-8 encoding flags
/// used by idb_utf8
//@{
#define IDBDEC_ESCAPE  0x00000001 ///< convert non-printable characters to C escapes (\n, \xNN, \uNNNN)
//@}

/// IDB default C string encoding -> UTF-8
/// \returns success (i.e., all bytes converted)

idaman THREAD_SAFE bool ida_export idb_utf8(qstring *out, const char *in, int nsyms=-1, int flags=0);


#ifdef __NT__
// These are typically used in the text UI (TUI), and
// also to convert argv to UTF-8 at startup.
idaman THREAD_SAFE bool ida_export change_codepage(
        qstring *out,
        const char *in,
        int incp,
        int outcp);
#ifndef CP_ACP
#define CP_ACP   0
#endif
#ifndef CP_OEM
#define CP_OEM   1
#endif
#ifndef CP_UTF8
#define CP_UTF8  65001
#endif
INLINE THREAD_SAFE bool acp_utf8(qstring *out, const char *in)
{
  return change_codepage(out, in, CP_ACP, CP_UTF8);
}
#else  // !__NT__
INLINE THREAD_SAFE bool idaapi change_codepage(qstring *, const char *, int, int) { return false; }
#endif // __NT__


//-------------------------------------------------------------------------
// helpers to compose 16/32-bit wchar's from [M]UTF-8-encoded data
inline THREAD_SAFE constexpr wchar16_t utf8_wchar16(uchar b0, uchar b1)
{
  return (wchar16_t(b0 & 0x1f) << 6) | (b1 & 0x3f);
}

//-------------------------------------------------------------------------
inline THREAD_SAFE constexpr wchar16_t utf8_wchar16(uchar b0, uchar b1, uchar b2)
{
  return (wchar16_t(b0 & 0x0f) << 12)
       | (wchar16_t(b1 & 0x3f) << 6)
       | (b2 & 0x3f);
}

//-------------------------------------------------------------------------
inline THREAD_SAFE constexpr wchar32_t utf8_wchar32(uchar b0, uchar b1, uchar b2, uchar b3)
{
  return (wchar32_t(b0 & 0x07) << 18)
       | (wchar32_t(b1 & 0x3f) << 12)
       | (wchar32_t(b2 & 0x3f) << 6)
       | (b3 & 0x3f);
}

#endif // __cplusplus


#define BADCP wchar32_t(-1)

/// Read one UTF-8 character from string. if error, return BADCP

idaman THREAD_SAFE wchar32_t ida_export get_utf8_char(const char **pptr);


/// Get the UTF-8 character from string, before 'p'.
///
/// \param out_cp the output codepoint storage. May be nullptr.
/// \param p      the pointer, pointing in the 'begin' string right after the UTF-8-encoded codepoint we want to retrieve
/// \param begin  the beginning of the string
/// \returns success

idaman THREAD_SAFE bool ida_export prev_utf8_char(wchar32_t *out_cp, const char **p, const char *begin);


/// Advance by n codepoints into the UTF-8 buffer.
///
/// Each bad byte (i.e., can't be decoded as UTF-8) will count as 1 codepoint.
/// In addition, encountering an unexpected end-of-string (i.e., '\0') will
/// cause this function to stop and return a non-zero value.
///
/// \param putf8 a pointer to the UTF-8 bytes buffer to advance into
/// \param n     the number of codepoints to advance into the buffer
/// \returns the number of codepoints that we failed to decode, thus:
///          0 - success, >0 - a terminating zero was encountered.

idaman THREAD_SAFE size_t ida_export skip_utf8(const char **putf8, size_t n);


/// Encode the codepoint into a UTF-8 byte sequence, and add terminating zero
/// \param out  output buffer (must be at least MAX_UTF8_SEQ_LEN bytes wide)
/// \param cp   the codepoint to encode
/// \returns how many bytes were put into the output buffer
///          (without the terminating zero), or size_t(-1) on failure

idaman THREAD_SAFE ssize_t ida_export put_utf8_char(char *out, wchar32_t cp);


/// Is the provided codepoint graphical?

idaman THREAD_SAFE bool ida_export is_cp_graphical(wchar32_t cp);


// Get number of codepoints in UTF-8 string. Any 'bad' byte
// (i.e., can't be decoded) counts for 1 codepoint.

idaman THREAD_SAFE size_t ida_export qustrlen(const char *utf8);


/// A safer strncpy - makes sure that there is a terminating zero.
/// nb: this function doesn't truncate the last UTF-8 character.
/// \sa qstrncpy()
/// \retval false  if the input buffer was truncated

idaman THREAD_SAFE bool ida_export qustrncpy(char *dst, const char *utf8, size_t dstsize);


// A few Unicode-related helpful defines

#define CP_BOM 0xFEFF
#define UTF8_BOM "\xEF\xBB\xBF"
#define UTF8_BOM_SZ (sizeof(UTF8_BOM) - 1)

#define UTF16LE_BOM "\xFF\xFE"
#define UTF16BE_BOM "\xFE\xFF"
#define UTF16_BOM_SZ (sizeof(UTF16LE_BOM) - 1)

#define UTF32LE_BOM "\xFF\xFE\x00\x00"
#define UTF32BE_BOM "\x00\x00\xFE\xFF"
#define UTF32_BOM_SZ (sizeof(UTF32LE_BOM) - 1)

#define CP_ELLIPSIS 0x2026
#define UTF8_ELLIPSIS "\xE2\x80\xA6"
#define UTF8_ELLIPSIS_SZ (sizeof(UTF8_ELLIPSIS) - 1)

#define CP_REPLCHAR 0xFFFD
#define UTF8_REPLCHAR "\xEF\xBF\xBD"
#define UTF8_REPLCHAR_SZ (sizeof(UTF8_REPLCHAR) - 1)


// To cover unicode, 4 bytes is enough. Still, from the UTF-8 spec at
// https://tools.ietf.org/html/rfc3629:
// "Another security issue occurs when encoding to UTF-8: the ISO/IEC
//  10646 description of UTF-8 allows encoding character numbers up to
//  U+7FFFFFFF, yielding sequences of up to 6 bytes.  There is therefore
//  a risk of buffer overflow if the range of character numbers is not
//  explicitly limited to U+10FFFF or if buffer sizing doesn't take into
//  account the possibility of 5- and 6-byte sequences."
// Furthermore, since buffers holding UTF-8 sequences are usually placed
// onto the stack, it's probably not a bad thing to make them 8-bytes
// aligned -- and keep room for a terminating zero, too.
#define MAX_UTF8_SEQ_LEN (6 + 1 + 1)

//------------------------------------------------------------------------
/// is IDA converting IDB into I64?
idaman bool ida_export is_cvt64();



/// \defgroup CEF_ Convert encoding flags
/// used by convert_encoding
//@{
#define CEF_RETERR 0x1 // return -1 if iconv() returns -1
//@}

/// Convert data from encoding fromcode into tocode.
/// \param out the output buffer
/// \param fromcode the encoding of the input data
/// \param tocode the encoding of the output data
/// \param indata the input data
/// \param insize size of input data in bytes
/// \param flags \ref CEF_*
/// \return number of input bytes converted (can be less than actual size if there was an invalid character)
/// -1 if source or target encoding is not supported
/// possible encoding names: windows codepages ("CP1251" etc), charset names ("Shift-JIS"), and many encodings supported by iconv

idaman ssize_t ida_export convert_encoding(
        bytevec_t *out,
        const char *fromcode,
        const char *tocode,
        const uchar *indata,
        ssize_t insize,
        DEFARG(int flags,0));

#ifdef __cplusplus
inline ssize_t convert_encoding(
        bytevec_t *out,
        const char *fromcode,
        const char *tocode,
        const bytevec_t *indata,
        DEFARG(int flags,0))
{
  QASSERT(1451, ssize_t(indata->size()) >= 0);
  return convert_encoding(out, fromcode, tocode, indata->begin(), indata->size(), flags);
}
#endif

#define ENC_WIN1252 "windows-1252"
#define ENC_UTF8    "UTF-8"
#define ENC_MUTF8   "MUTF-8" // modified UTF-8, used by Dalvik and Java (https://en.wikipedia.org/wiki/UTF-8#Modified_UTF-8)
#define ENC_UTF16   "UTF-16"
#define ENC_UTF16LE "UTF-16LE"
#define ENC_UTF16BE "UTF-16BE"
#define ENC_UTF32   "UTF-32"
#define ENC_UTF32LE "UTF-32LE"
#define ENC_UTF32BE "UTF-32BE"



#ifndef CP_UTF8
#define CP_UTF8 65001 ///< UTF-8 codepage
#endif

#ifndef CP_UTF16
#define CP_UTF16 1200 ///< UTF-16 codepage
#endif

#ifdef __NT__
#  ifndef INVALID_FILE_ATTRIBUTES
#    define INVALID_FILE_ATTRIBUTES ((DWORD)-1) ///< old Visual C++ compilers were not defining this
#  endif
#  ifndef BELOW_NORMAL_PRIORITY_CLASS
#    define BELOW_NORMAL_PRIORITY_CLASS       0x00004000 ///< \copydoc INVALID_FILE_ATTRIBUTES
#  endif
#endif

#define SUBSTCHAR '_'     ///< default char, used if a char cannot be represented in a codepage

typedef uint32 flags_t;   ///< 32-bit flags for each address
typedef uint64 flags64_t; ///< 64-bit flags for each address
typedef ea_t tid_t;       ///< type id (for enums, structs, etc)

typedef uint32 bgcolor_t;       ///< background color in RGB
#define DEFCOLOR bgcolor_t(-1)  ///< default color (used in function, segment definitions)

//-------------------------------------------------------------------------
// Command line
//-------------------------------------------------------------------------

#ifdef __cplusplus
/// Tools for command line parsing
struct channel_redir_t
{
  int fd;                     ///< channel number
  qstring file;               ///< file name to redirect to/from.
                              ///< if empty, the channel must be closed.
  int flags;                  ///< \ref IOREDIR_
/// \defgroup IOREDIR_ i/o redirection flags
/// used by channel_redir_t::flags
//@{
#define IOREDIR_INPUT  0x01   ///< input redirection
#define IOREDIR_OUTPUT 0x02   ///< output redirection
#define IOREDIR_APPEND 0x04   ///< append, do not overwrite the output file
#define IOREDIR_QUOTED 0x08   ///< the file name was quoted
//@}
  bool is_input(void) const { return (flags & IOREDIR_INPUT) != 0; }
  bool is_output(void) const { return (flags & IOREDIR_OUTPUT) != 0; }
  bool is_append(void) const { return (flags & IOREDIR_APPEND) != 0; }
  bool is_quoted(void) const { return (flags & IOREDIR_QUOTED) != 0; }
  int start;                   ///< begin of the redirection string in the command line
  int length;                  ///< length of the redirection string in the command line
};
typedef qvector<channel_redir_t> channel_redirs_t; ///< vector of channel_redir_t objects
#else
typedef struct channel_redirs_tag channel_redirs_t;
typedef struct qstrvec_tag qstrvec_t;
#endif

/// Parse a space separated string (escaping with backslash is supported).
/// \param[out] args    a string vector to hold the results
/// \param[out] redirs  map of channel redirections found in cmdline
///                        - if nullptr, redirections won't be parsed
///                        - if there are syntax errors in redirections, consider them as arguments
/// \param cmdline      the string to be parsed
/// \param flags        #LP_PATH_WITH_ARGS or 0
/// \return the number of parsed arguments

idaman THREAD_SAFE size_t ida_export parse_command_line(
        qstrvec_t *args,
        channel_redirs_t *redirs,
        const char *cmdline,
        int flags);


/// Copy and expand command line arguments.
/// For '@filename' arguments the file contents are inserted into the resulting argv.
/// Format of the file: one switch per line, ';' for comment lines
/// On windows, argv will also be interpreted as OEM codepage, and
/// will be decoded as such and re-encoded into UTF-8.
/// \param[out] p_argc  size of the returned argv array
/// \param argc         number of entries in argv array
/// \param argv         array of strings
/// \return new argv (terminated by nullptr).
///          It must be freed with free_argv()

char **expand_argv(int *p_argc, int argc, const char *const argv[]);


/// Free 'argc' elements of 'argv'

INLINE void free_argv(int argc, char **argv)
{
  int i;
  if ( argv != nullptr )
  {
    for ( i = 0; i < argc; i++ )
      qfree(argv[i]);
    qfree(argv);
  }
}


/// Quote a command line argument if it contains escape characters.
/// For example, *.c will be converted into "*.c" because * may be inadvertently
/// expanded by the shell
/// \return true: modified 'arg'

idaman bool ida_export quote_cmdline_arg(qstring *arg);

//-------------------------------------------------------------------------
// Command-line tools
//-------------------------------------------------------------------------
typedef void cliopt_handler_t(const char *value, void *ud);
typedef void cliopt_poly_handler_t(int argc, const char **argv, void *ud);
struct cliopt_t
{
  char shortname;
  const char *longname;
  const char *help;
  cliopt_handler_t *handler;
  int nargs; // number of arguments. Can be 0, 1 or -1.
             // If '-1', it means 'poly_handler' will be used
};
DECLARE_TYPE_AS_MOVABLE(cliopt_t);

struct cliopts_t;
#ifndef SWIG
#  define DEFINE_CLIOPTS_T_HELPERS(decl)                                \
  decl void ida_export cliopts_t_add(cliopts_t &, const cliopt_t *, size_t); \
  decl int ida_export cliopts_t_apply(cliopts_t &, int, const char *[], void *); \
  decl const cliopt_t *ida_export cliopts_t_find_short(const cliopts_t &, char); \
  decl const cliopt_t *ida_export cliopts_t_find_long(const cliopts_t &, const char *); \
  decl NORETURN void ida_export cliopts_t_usage(const cliopts_t &, bool);
#else
#  define DEFINE_CLIOPTS_T_HELPERS(decl)
#endif // SWIG
DEFINE_CLIOPTS_T_HELPERS(idaman)

struct cliopts_t : public qvector<cliopt_t>
{
  qstring prog_name;
  qstring epilog;
  typedef AS_PRINTF(1, 2) int usage_printer_t(const char *format, ...);
  usage_printer_t *printer;
  bool print_usage;

  cliopts_t(usage_printer_t *_printer, bool _print_usage = true)
    : printer(_printer)
    , print_usage(_print_usage)
  {}

  void add(const cliopt_t *opts, size_t nopts) { cliopts_t_add(*this, opts, nopts); }
  int apply(int argc, const char *argv[], void *ud=nullptr) { return cliopts_t_apply(*this, argc, argv, ud); }
  const cliopt_t *find_short(char shortname) const { return cliopts_t_find_short(*this, shortname); }
  const cliopt_t *find_long(const char *longname) const { return cliopts_t_find_long(*this, longname); }
  void usage(bool is_error=true) const { return cliopts_t_usage(*this, is_error); }

private:
  DEFINE_CLIOPTS_T_HELPERS(friend);
};

struct plugin_option_t;
#ifndef SWIG
#  define DEFINE_PLUGIN_OPTION_T_HELPERS(decl) \
  decl bool ida_export plugin_option_t_get_bool(const plugin_option_t *, bool *, const char *, bool);
#else
#  define DEFINE_PLUGIN_OPTION_T_HELPERS(decl)
#endif // SWIG

DEFINE_PLUGIN_OPTION_T_HELPERS(idaman)
/// Named option, supports two kinds of options:
///   string option: <name>=<value>
///   bool option:   <name>=[on|off]
struct plugin_option_t
{
  qstring name;
  qstring value;
  const char *get_value(const char *default_value) const
  {
    return value.empty() ? default_value : value.c_str();
  }
  bool get_string(qstring *out, const char *desired_name, const char *default_value) const
  {
    if ( name != desired_name )
      return false;
    if ( out != nullptr )
      *out = get_value(default_value);
    return true;
  }
  bool get_bool(bool *out, const char *desired_name, bool default_value) const
  {
    return plugin_option_t_get_bool(this, out, desired_name, default_value);
  }

private:
  DEFINE_PLUGIN_OPTION_T_HELPERS(friend);
};
DECLARE_TYPE_AS_MOVABLE(plugin_option_t);

using plugin_options_t = qvector<plugin_option_t>;

/// Parse plugin options from IDA command line specified by -O<plugin_name>:<optstring>
/// Note such options can be used not only for plugins, for example,
/// currently we use them for merge (-Omerge:...)
/// and vault server credentials (-Ovault:...)
/// \param[out] opts  pointer to vector for parsed options
/// \param optstring  option string <name1>=<value1>:...
idaman bool ida_export parse_plugin_options(plugin_options_t *opts, const char *optstring);

//-------------------------------------------------------------------------
// INSTANT DEBUGGING
//-------------------------------------------------------------------------

#ifdef __cplusplus
/// Options for instant debugging
struct instant_dbgopts_t
{
  qstring debmod;       ///< name of debugger module
  qstring env;          ///< config variables for debmod. example: DEFAULT_CPU=13;MAXPACKETSIZE=-1
  qstring host;         ///< remote hostname (if remote debugging)
  qstring pass;         ///< password for the remote debugger server
  int port = 0;         ///< port number for the remote debugger server
  int pid = -1;         ///< process to attach to (-1: ask the user)
  int event_id = -1;    ///< event to trigger upon attaching
  bool attach = false;  ///< should attach to a process?
};
#else
struct instant_dbgopts_t;
#endif

/// Parse the -r command line switch (for instant debugging).
/// r_switch points to the value of the -r switch. Example: win32@localhost+
/// \return true-ok, false-parse error

idaman bool ida_export parse_dbgopts(struct instant_dbgopts_t *ido, const char *r_switch);


//-------------------------------------------------------------------------
// PROCESSES
//-------------------------------------------------------------------------

/// Information for launching a process with IDA API
/// Note: all string data such as paths (e.g., 'path', 'args' & 'startdir')
/// or 'env' should be UTF-8 encoded.
struct launch_process_params_t
{
  size_t cb;                     ///< size of this structure
  int flags;                     ///< \ref LP_
/// \defgroup LP_ Launch process flags
/// used by launch_process_params_t::flags
//@{
#define LP_NEW_CONSOLE    0x0001 ///< create new console (only ms windows)
#define LP_TRACE          0x0002 ///< debug: unix: ptrace(TRACEME), windows: DEBUG_PROCESS
#define LP_PATH_WITH_ARGS 0x0004 ///< 'args' contains executable path too
#define LP_USE_SHELL      0x0008 ///< use shell to launch the command.
                                 ///< 'path' is ignored in this case.
#define LP_LAUNCH_32_BIT  0x0010 ///< prefer to launch 32-bit part of file (only mac)
#define LP_LAUNCH_64_BIT  0x0020 ///< prefer to launch 64-bit part of file (only mac);
                                 ///< only one of LP_LAUNCH_*_BIT bits can be specified
#define LP_NO_ASLR        0x0040 ///< disable ASLR (only mac)
#define LP_DETACH_TTY     0x0080 ///< detach the current tty (unix)
#define LP_HIDE_WINDOW    0x0100 ///< tries to hide new window on startup (only windows)
#define LP_SUSPENDED      0x0200 ///< suspends the process on startup (only mac)
#define LP_DETACHED       0x0400 ///< no need to reap the child (this bit is ignored on windows)
//@}
  const char *path;              ///< file to run
  const char *args;              ///< command line arguments
  ssize_t in_handle;             ///< handle for stdin or -1
  ssize_t out_handle;            ///< handle for stdout or -1
  ssize_t err_handle;            ///< handle for stderr or -1
  char *env;                     ///< zero separated environment variables that will be appended
                                 ///< to the existing environment block (existing variables will be updated).
                                 ///< each variable has the following form: var=value\0
                                 ///< must be terminated with two zero bytes!
  const char *startdir;          ///< current directory for the new process
  void *info;                    ///< os specific info (on windows it points to PROCESS_INFORMATION)
                                 ///< on unix, not used
#ifdef __cplusplus
  launch_process_params_t(void)  ///< constructor
    : cb(sizeof(*this)), flags(0), path(nullptr), args(nullptr),
      in_handle(-1), out_handle(-1), err_handle(-1),
      env(nullptr), startdir(nullptr), info(nullptr) {}
#endif
};

/// Launch the specified process in parallel.
/// \return handle (unix: child pid), nullptr - error

#ifdef __cplusplus
idaman THREAD_SAFE void *ida_export launch_process(
        const launch_process_params_t &lpp,
        qstring *errbuf=nullptr);
#else
idaman THREAD_SAFE void *ida_export launch_process(
        const struct launch_process_params_t *lpp,
        qstring *errbuf);
#endif


/// Forcibly terminate a running process.
/// \returns 0-ok, otherwise an error code that can be passed to winerr()

idaman THREAD_SAFE int ida_export term_process(void *handle);


/// Wait for state changes in a child process (UNIX only).
/// Here: child, status, flags - the same as in system call waitpid()
/// Param 'timeout_ms' is a timeout in milliseconds
/// \return PID of the process with the changed status

idaman THREAD_SAFE int ida_export qwait_timed(int *status, int child, int flags, int timeout_ms);

#if defined(__UNIX__)
#  ifdef WCONTINUED
#    define QWCONTINUED WCONTINUED
#  else
#    define QWCONTINUED 8
#  endif
#  ifdef WNOHANG
#    define QWNOHANG WNOHANG
#  else
#    define QWNOHANG 1
#  endif
inline THREAD_SAFE int qwait(int *status, int child, int flags)
{
  return qwait_timed(status, child, flags, (flags & QWNOHANG) != 0 ? 0 : -1);
}
#endif


/// Check whether process has terminated or not.
/// \param handle          process handle to wait for
/// \param[out] exit_code  pointer to the buffer for the exit code
/// \param msecs           how long to wait. special values:
///                          - 0: do not wait
///                          - 1 or -1: wait infinitely
///                          - other values: timeout in milliseconds
/// \retval 0   process has exited, and the exit code is available.
///             if *exit_code < 0: the process was killed with a signal -*exit_code
/// \retval 1   process has not exited yet
/// \retval -1  error happened, see error code for winerr() in *exit_code

idaman THREAD_SAFE int ida_export check_process_exit(
        void *handle,
        int *exit_code,
        DEFARG(int msecs,-1));

/// Teletype control
enum tty_control_t
{
  TCT_UNKNOWN = 0,
  TCT_OWNER,
  TCT_NOT_OWNER
};


/// Check if the current process is the owner of the TTY specified
/// by 'fd' (typically an opened descriptor to /dev/tty).

idaman THREAD_SAFE enum tty_control_t ida_export is_control_tty(int fd);


/// If the current terminal is the controlling terminal of the calling
/// process, give up this controlling terminal.
/// \note The current terminal is supposed to be /dev/tty

idaman THREAD_SAFE void ida_export qdetach_tty(void);


/// Make the current terminal the controlling terminal of the calling
/// process.
/// \note The current terminal is supposed to be /dev/tty

idaman THREAD_SAFE void ida_export qcontrol_tty(void);

//-------------------------------------------------------------------------
/// THREADS
//-------------------------------------------------------------------------

/// Thread callback function
typedef int idaapi qthread_cb_t(void *ud);

/// Thread opaque handle
#ifdef __cplusplus
#define OPAQUE_HANDLE(n) typedef struct __ ## n {} *n
#else
#define OPAQUE_HANDLE(n) typedef struct __ ## n  { char __dummy; } *n
#endif
OPAQUE_HANDLE(qthread_t);


/// Create a thread and return a thread handle

idaman THREAD_SAFE qthread_t ida_export qthread_create(qthread_cb_t *thread_cb, void *ud);


/// Free a thread resource (does not kill the thread)
/// (calls pthread_detach under unix)

idaman THREAD_SAFE void ida_export qthread_free(qthread_t q);


/// Wait a thread until it terminates

idaman THREAD_SAFE bool ida_export qthread_join(qthread_t q);


/// Forcefully kill a thread (calls pthread_cancel under unix)

idaman THREAD_SAFE bool ida_export qthread_kill(qthread_t q);


/// Get current thread. Must call qthread_free() to free it!

idaman THREAD_SAFE qthread_t ida_export qthread_self(void);


/// Is the current thread the same as 'q'?

idaman THREAD_SAFE bool ida_export qthread_same(qthread_t q);


/// Are two threads equal?

idaman THREAD_SAFE bool ida_export qthread_equal(qthread_t q1, qthread_t q2);


/// Are we running in the main thread?

idaman THREAD_SAFE bool ida_export is_main_thread(void);


/// Thread safe function to work with the environment

idaman THREAD_SAFE bool ida_export qsetenv(const char *varname, const char *value);
idaman THREAD_SAFE bool ida_export qgetenv(const char *varname, DEFARG(qstring *buf, nullptr)); ///< \copydoc qsetenv


//-------------------------------------------------------------------------
/// Semaphore.
/// Named semaphores are public, nameless ones are local to the process
//-------------------------------------------------------------------------
OPAQUE_HANDLE(qsemaphore_t);

idaman THREAD_SAFE qsemaphore_t ida_export qsem_create(const char *name, int init_count);   ///< Create a new semaphore
idaman THREAD_SAFE bool ida_export qsem_free(qsemaphore_t sem);                             ///< Free a semaphore
idaman THREAD_SAFE bool ida_export qsem_post(qsemaphore_t sem);                             ///< Unlock a semaphore
idaman THREAD_SAFE bool ida_export qsem_wait(qsemaphore_t sem, int timeout_ms);             ///< Lock and decrement a semaphore. timeout = -1 means block indefinitely

//-------------------------------------------------------------------------
/// Mutex
//-------------------------------------------------------------------------
OPAQUE_HANDLE(qmutex_t);
idaman THREAD_SAFE bool ida_export qmutex_free(qmutex_t m);      ///< Free a mutex
idaman THREAD_SAFE qmutex_t ida_export qmutex_create(void);          ///< Create a new mutex
idaman THREAD_SAFE bool ida_export qmutex_lock(qmutex_t m);      ///< Lock a mutex
idaman THREAD_SAFE bool ida_export qmutex_unlock(qmutex_t m);    ///< Unlock a mutex


#ifdef __cplusplus
/// Mutex locker object. Will lock a given mutex upon creation and unlock it when the object is destroyed
class qmutex_locker_t
{
  qmutex_t lock;
public:
  qmutex_locker_t(qmutex_t _lock) : lock(_lock) { qmutex_lock(lock); }
  ~qmutex_locker_t(void) { qmutex_unlock(lock); }
};
#endif

//-------------------------------------------------------------------------
//  PIPES
//-------------------------------------------------------------------------
#ifdef __NT__
typedef void *qhandle_t;        ///< MS Windows HANDLE
const qhandle_t NULL_PIPE_HANDLE = nullptr;
#else
typedef int qhandle_t;          ///< file handle in Unix
const qhandle_t NULL_PIPE_HANDLE = -1;
#endif


/// Create a pipe.
/// \param[out] handles
///               - handles[0] : read handle
///               - handles[1] : write handle
/// \return error code (0-ok)

idaman THREAD_SAFE int ida_export qpipe_create(qhandle_t handles[2]);


/// Read from a pipe. \return number of read bytes. -1-error

idaman THREAD_SAFE ssize_t ida_export qpipe_read(qhandle_t handle, void *buf, size_t size);

/// Read a specific amount of bytes from a pipe.
/// \param handle         pipe handle to read from
/// \param[out] out_bytes byte vector to which the bytes will be appended
/// \param n              number of bytes to read
/// \return success

idaman THREAD_SAFE bool ida_export qpipe_read_n(qhandle_t handle, bytevec_t *out_bytes, size_t n);

/// Write to a pipe. \return number of written bytes. -1-error

idaman THREAD_SAFE ssize_t ida_export qpipe_write(qhandle_t handle, const void *buf, size_t size);


/// Close a pipe. \return error code (0-ok)

idaman THREAD_SAFE int ida_export qpipe_close(qhandle_t handle);


/// Wait for file/socket/pipe handles.
/// \note On Windows this function just calls WaitForMultipleObjects().
///       So it cannot wait for file/socket/pipe handles.
///       It simply returns 0 and sets idx to 0 for such handles.
/// \param[out] idx       handle index
/// \param handles        handles to wait for
/// \param n              number of handles
/// \param write_bitmask  bitmask of indexes of handles opened for writing
/// \param timeout_ms     timeout value in milliseconds
/// \return error code. on timeout, returns 0 and sets idx to -1

idaman THREAD_SAFE int ida_export qwait_for_handles(
        int *idx,
        const qhandle_t *handles,
        int n,
        uint32 write_bitmask,
        int timeout_ms);


#ifndef NO_OBSOLETE_FUNCS
idaman DEPRECATED THREAD_SAFE bool ida_export unpack_memory(void *buf, size_t size, const uchar **pptr, const uchar *end); // use unpack_obj
#endif // NO_OBSOLETE_FUNCS

#endif /* _PRO_H */
