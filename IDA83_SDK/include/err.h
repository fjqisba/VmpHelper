/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _ERR_H
#define _ERR_H

#include <errno.h>

/*! \file err.h

  \brief Thread safe functions that deal with error codes

*/

/// Print error message to stderr (analog of perror)

idaman THREAD_SAFE AS_PRINTF(1, 0) void ida_export vqperror(const char *format, va_list va);


/// Get error description string.
/// if _qerrno=-1, get_qerrno() will be used

idaman THREAD_SAFE const char *ida_export qstrerror(error_t _qerrno);


/// A convenience function to generate error messages (returns "header: error message")

idaman THREAD_SAFE char *ida_export get_errdesc(const char *header, error_t _qerrno=-1);


/// Get error message for MS Windows error codes
/// \param code errno or GetLastError() depending on the system.

idaman THREAD_SAFE char *ida_export winerr(int code);


/// Get error string.
/// if errno_code == -1, then errno will be used.

idaman const char *ida_export qerrstr(int errno_code=-1);


#ifdef __cplusplus

/// See vqperror()

THREAD_SAFE AS_PRINTF(1, 2) inline void qperror(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  vqperror(format, va);
  va_end(va);
}


/// See set_qerrno()

THREAD_SAFE inline void set_errno(int code)
{
  errno = code;
  set_qerrno(eOS);
}
#endif

// Internal functions
/// \cond

// n=0..3
idaman THREAD_SAFE void ida_export set_error_data(int n, size_t data);
idaman THREAD_SAFE void ida_export set_error_string(int n, const char *str);
idaman THREAD_SAFE size_t ida_export get_error_data(int n);
idaman THREAD_SAFE const char *ida_export get_error_string(int n);

#define QPRM_TYPE(t,n,x)        set_error_data(n-1, t(x))
#define QPRM_CHAR(n,x)          QPRM_TYPE(char,n,x)
#define QPRM_SHORT(n,x)         QPRM_TYPE(short,n,x)
#define QPRM_INT(n,x)           QPRM_TYPE(int,n,x)
#define QPRM_INT32(n,x)         QPRM_TYPE(int32,n,x)
#define QPRM_UCHAR(n,x)         QPRM_TYPE(uchar,n,x)
#define QPRM_USHORT(n,x)        QPRM_TYPE(ushort,n,x)
#define QPRM_UINT(n,x)          QPRM_TYPE(uint,n,x)
#define QPRM_UINT32(n,x)        QPRM_TYPE(uint32,n,x)
#define QPRM(n,x)               set_error_string(n-1, x)

/// \endcond

#ifndef NO_OBSOLETE_FUNCS

/// Get errno and optionally set its new value.
/// \param new_code if not -1, specifies the new value. The old value will be returned.

idaman DEPRECATED THREAD_SAFE int ida_export qerrcode(int new_code=-1);

#endif

#endif

