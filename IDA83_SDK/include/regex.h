/*************************************************
*      Perl-Compatible Regular Expressions       *
*************************************************/

/* PCRE2 is a library of functions to support regular expressions whose syntax
and semantics are as close as possible to those of the Perl 5 language.

                       Written by Philip Hazel
     Original API code Copyright (c) 1997-2012 University of Cambridge
         New API code Copyright (c) 2016 University of Cambridge

-----------------------------------------------------------------------------
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

    * Neither the name of the University of Cambridge nor the names of its
      contributors may be used to endorse or promote products derived from
      this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
-----------------------------------------------------------------------------
*/


#ifndef _REGEX_H_
#define _REGEX_H_
#ifdef __cplusplus
#include <kernwin.hpp>
#endif

#include <pro.h>

#ifdef __GNUC__
#undef __P
#endif

typedef off_t regoff_t;
/* The structure representing a compiled regular expression. */

struct regex_t
{
  int re_magic;
  size_t re_nsub;         /* number of parenthesized subexpressions */
  const char *re_endp;    /* end pointer for REG_PEND */
  void *re_g;   /* none of your business :-) */
};

/* The structure in which a captured offset is returned. */

struct regmatch_t
{
  regoff_t rm_so;         /* start of match */
  regoff_t rm_eo;         /* end of match */
};
#ifndef REG_ICASE
/* Options, mostly defined by POSIX, but with some extras. */

#define REG_ICASE     0x0001  /* Maps to PCRE2_CASELESS */
#define REG_NEWLINE   0x0002  /* Maps to PCRE2_MULTILINE */
#define REG_NOTBOL    0x0004  /* Maps to PCRE2_NOTBOL */
#define REG_NOTEOL    0x0008  /* Maps to PCRE2_NOTEOL */
#define REG_DOTALL    0x0010  /* NOT defined by POSIX; maps to PCRE2_DOTALL */
#define REG_NOSUB     0x0020  /* Maps to PCRE2_NO_AUTO_CAPTURE */
#define REG_UTF       0x0040  /* NOT defined by POSIX; maps to PCRE2_UTF */
#define REG_STARTEND  0x0080  /* BSD feature: pass subject string by so,eo */
#define REG_NOTEMPTY  0x0100  /* NOT defined by POSIX; maps to PCRE2_NOTEMPTY */
#define REG_UNGREEDY  0x0200  /* NOT defined by POSIX; maps to PCRE2_UNGREEDY */
#define REG_UCP       0x0400  /* NOT defined by POSIX; maps to PCRE2_UCP */

/* This is not used by PCRE2, but by defining it we make it easier
to slot PCRE2 into existing programs that make POSIX calls. */

#define REG_EXTENDED  0
#define REG_TRACE 0   // unsupported by PCRE2

/* Error values. Not all these are relevant or used by the wrapper. */


enum
{
  REG_ASSERT = 1,  /* internal error ? */
  REG_BADBR,       /* invalid repeat counts in {} */
  REG_BADPAT,      /* pattern error */
  REG_BADRPT,      /* ? * + invalid */
  REG_EBRACE,      /* unbalanced {} */
  REG_EBRACK,      /* unbalanced [] */
  REG_ECOLLATE,    /* collation error - not relevant */
  REG_ECTYPE,      /* bad class */
  REG_EESCAPE,     /* bad escape sequence */
  REG_EMPTY,       /* empty expression */
  REG_EPAREN,      /* unbalanced () */
  REG_ERANGE,      /* bad range inside [] */
  REG_ESIZE,       /* expression too big */
  REG_ESPACE,      /* failed to get memory */
  REG_ESUBREG,     /* bad back reference */
  REG_INVARG,      /* bad argument */
  REG_NOMATCH      /* match failed */
};
#endif //REG_ICASE

/* The functions */

// compile the regular expression
idaman THREAD_SAFE int ida_export qregcomp(
        struct regex_t *preg,
        const char *pattern,
        int cflags);

// mapping from error codes returned by qregcomp() and qregexec() to a string
idaman THREAD_SAFE size_t ida_export qregerror(
        int errcode,
        const struct regex_t *preg,
        char *errbuf,
        size_t errbuf_size);

// match regex against a string
idaman THREAD_SAFE int ida_export qregexec(
        const struct regex_t *preg,
        const char *str,
        size_t nmatch,
        struct regmatch_t pmatch[],
        int eflags);

// free any memory allocated by qregcomp
idaman THREAD_SAFE void ida_export qregfree(struct regex_t *preg);


#ifdef __cplusplus

//-------------------------------------------------------------------------
class refcnted_regex_t : public qrefcnt_obj_t
{
  regex_t regex;

  refcnted_regex_t()
  {
    regex = {};
  }
  virtual ~refcnted_regex_t()
  {
    qregfree(&regex);
  }
public:
  virtual void idaapi release(void) override
  {
    delete this;
  }
  int exec(const char *string, size_t nmatch, regmatch_t pmatch[], int eflags)
  {
    return qregexec(&regex, string, nmatch, pmatch, eflags);
  }
  int process_errors(int code, qstring *errmsg)
  {
    if ( code != 0 && errmsg != nullptr )
    {
      char errbuf[MAXSTR];
      qregerror(code, &regex, errbuf, sizeof(errbuf));
      *errmsg = errbuf;
    }
    return code;
  }
  static refcnted_regex_t *create(
        const qstring &text,
        bool case_insensitive,
        qstring *errmsg)
  {
    if ( text.empty() )
      return nullptr;
    refcnted_regex_t *p = new refcnted_regex_t();
    int rflags = REG_EXTENDED;
    if ( case_insensitive )
      rflags |= REG_ICASE;
    int code = qregcomp(&p->regex, text.begin(), rflags);
    if ( p->process_errors(code, errmsg) != 0 )
    {
      // It is unnecessary to qregfree() here: the deletion of 'p' will
      // call qregfree (but anyway, even that is unnecessary, because
      // if we end up here, it means qregcomp() failed, and when that
      // happens, qregcomp() frees the regex itself.)
      delete p;
      p = nullptr;
    }
    return p;
  }
  size_t nsub(void)
  {
    /* number of parenthesized subexpressions */
    return regex.re_nsub;
  }
  DECLARE_UNCOPYABLE(refcnted_regex_t);
};
typedef qrefcnt_t<refcnted_regex_t> regex_ptr_t;

//---------------------------------------------------------------------------
struct regex_cache_t
{
  bool _find_or_create(regex_ptr_t **out, const qstring &str, qstring *errbuf=nullptr)
  {
    regex_cache_map_t::iterator it = cache.find(str);
    if ( it == cache.end() )
    {
      qstring errmsg;
      regex_ptr_t rx = regex_ptr_t(refcnted_regex_t::create(str, false, errbuf));
      if ( rx == nullptr )
        return false;
      it = cache.insert(regex_cache_map_t::value_type(str, rx)).first;
    }
    *out = &it->second;
    return true;
  }
  regex_ptr_t &find_or_create(const qstring &str)
  {
    regex_ptr_t *ptr;
    qstring errbuf;
    if ( !_find_or_create(&ptr, str, &errbuf) )
      error("%s", errbuf.c_str());
    return *ptr;
  }

private:
  typedef std::map<qstring, regex_ptr_t> regex_cache_map_t;
  regex_cache_map_t cache;
};

#endif //__cplusplus

#ifndef NO_OBSOLETE_FUNCS
idaman DEPRECATED THREAD_SAFE int ida_export regcomp(struct regex_t *preg, const char *pattern, int cflags);
idaman DEPRECATED THREAD_SAFE size_t ida_export regerror(int errcode, const struct regex_t *preg, char *errbuf, size_t errbuf_size);
idaman DEPRECATED THREAD_SAFE int ida_export regexec(const struct regex_t *preg, const char *str, size_t nmatch, struct regmatch_t pmatch[], int eflags);
idaman DEPRECATED THREAD_SAFE void ida_export regfree(struct regex_t *preg);
#endif

#endif /* !_REGEX_H_ */
