/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _HELP_H
#define _HELP_H

typedef int help_t;     /* Help messages are referred by ints         */

// Get pointer to message text by its message id
// The message texts are read from ida.hlp at the beginning
// Returns: pointer to message text (nullptr is never returned by IDA)

idaman THREAD_SAFE const char *ida_export itext(help_t msg_id);

#ifdef __KERNWIN_HPP
GCC_DIAG_OFF(format-nonliteral);
NORETURN inline void Err(help_t format, ...)
{
  va_list va;
  va_start(va, format);
  verror(itext(format), va);
  // NOTREACHED
}

inline void Warn(help_t format, ...)
{
  va_list va;
  va_start(va, format);
  vwarning(itext(format), va);
  va_end(va);
}

inline void Info(help_t format, ...)
{
  va_list va;
  va_start(va, format);
  vinfo(itext(format), va);
  va_end(va);
}

inline int Message(help_t format, ...)
{
  va_list va;
  va_start(va, format);
  int nbytes = vmsg(itext(format), va);
  va_end(va);
  return nbytes;
}

inline int vask_yn(int deflt, help_t format, va_list va)
{
  return vask_yn(deflt, itext(format), va);
}

inline int ask_yn(int deflt, help_t format, ...)
{
  va_list va;
  va_start(va, format);
  int code = vask_yn(deflt, itext(format), va);
  va_end(va);
  return code;
}
GCC_DIAG_ON(format-nonliteral);
#endif

#ifndef NO_OBSOLETE_FUNCS
#endif

#endif /* _HELP_H */
