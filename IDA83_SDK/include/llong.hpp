/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _LLONG_HPP
#define _LLONG_HPP

//---------------------------------------------------------------------------
#if defined(_MSC_VER)
typedef unsigned __int64 uint64;
typedef          __int64 int64;
#elif defined(__GNUC__)
typedef unsigned long long uint64;
typedef          long long int64;
#endif

//---------------------------------------------------------------------------
#ifdef __cplusplus
inline constexpr int64 make_int64(uint32 ll, int32 hh) { return ll | (int64(hh) << 32); }
inline constexpr uint64 make_uint64(uint32 ll, int32 hh) { return ll | (uint64(hh) << 32); }
inline constexpr uint32 low(const uint64 &x)  { return uint32(x); }
inline constexpr uint32 high(const uint64 &x) { return uint32(x>>32); }
inline constexpr uint32 low(const int64 &x)   { return uint32(x); }
inline constexpr int32  high(const int64 &x)  { return uint32(x>>32); }
#else
#define make_int64(ll,hh)   (ll | (int64(hh) << 32))
#define make_uint64(ll,hh)  (ll | (uint64(hh) << 32))
#endif

idaman THREAD_SAFE int64 ida_export llong_scan(
        const char *buf,
        int radix,
        const char **end);
#ifndef swap64
   idaman THREAD_SAFE uint64 ida_export swap64(uint64);
#  ifdef __cplusplus
     inline int64 swap64(int64 x)
     {
       return int64(swap64(uint64(x)));
     }
#  endif
#endif

//---------------------------------------------------------------------------
//      128 BIT NUMBERS
//---------------------------------------------------------------------------
#ifdef __HAS_INT128__

typedef unsigned __int128 uint128;
typedef          __int128 int128;

inline int128 make_int128(uint64 ll, int64 hh) { return ll | (int128(hh) << 64); }
inline uint128 make_uint128(uint64 ll, uint64 hh) { return ll | (uint128(hh) << 64); }
inline uint64 low(const uint128 &x)  { return uint64(x); }
inline uint64 high(const uint128 &x) { return uint64(x>>64); }
inline uint64 low(const int128 &x)   { return uint64(x); }
inline int64  high(const int128 &x)  { return uint64(x>>64); }

#else
#ifdef __cplusplus
//-V:uint128:730 not all members of a class are initialized inside the constructor
class uint128
{
  uint64 l;
  uint64 h;
  friend class int128;
public:
  uint128(void)  {}
  uint128(uint x) { l = x; h = 0; }
  uint128(int x)  { l = x; h = (x < 0)? -1 : 0; }
  uint128(uint64 x) { l = x; h = 0; }
  uint128(int64 x)  { l = x; h = (x < 0) ? -1 : 0; }
  uint128(uint64 ll, uint64 hh) { l = ll; h = hh; }
  friend uint64 low (const uint128 &x) { return x.l; }
  friend uint64 high(const uint128 &x) { return x.h; }
  friend uint128 operator+(const uint128 &x, const uint128 &y);
  friend uint128 operator-(const uint128 &x, const uint128 &y);
  friend uint128 operator/(const uint128 &x, const uint128 &y);
  friend uint128 operator%(const uint128 &x, const uint128 &y);
  friend uint128 operator*(const uint128 &x, const uint128 &y);
  friend uint128 operator|(const uint128 &x, const uint128 &y);
  friend uint128 operator&(const uint128 &x, const uint128 &y);
  friend uint128 operator^(const uint128 &x, const uint128 &y);
  friend uint128 operator>>(const uint128 &x, int cnt);
  friend uint128 operator<<(const uint128 &x, int cnt);
  uint128 &operator+=(const uint128 &y);
  uint128 &operator-=(const uint128 &y);
  uint128 &operator/=(const uint128 &y);
  uint128 &operator%=(const uint128 &y);
  uint128 &operator*=(const uint128 &y);
  uint128 &operator|=(const uint128 &y);
  uint128 &operator&=(const uint128 &y);
  uint128 &operator^=(const uint128 &y);
  uint128 &operator>>=(int cnt);
  uint128 &operator<<=(int cnt);
  uint128 &operator++(void);
  uint128 &operator--(void);
  friend uint128 operator+(const uint128 &x) { return x; }
  friend uint128 operator-(const uint128 &x);
  friend uint128 operator~(const uint128 &x) { return uint128(~x.l,~x.h); }
  friend bool operator==(const uint128 &x, const uint128 &y) { return x.l == y.l && x.h == y.h; }
  friend bool operator!=(const uint128 &x, const uint128 &y) { return x.l != y.l || x.h != y.h; }
  friend bool operator> (const uint128 &x, const uint128 &y) { return x.h > y.h || (x.h == y.h && x.l >  y.l); }
  friend bool operator< (const uint128 &x, const uint128 &y) { return x.h < y.h || (x.h == y.h && x.l <  y.l); }
  friend bool operator>=(const uint128 &x, const uint128 &y) { return x.h > y.h || (x.h == y.h && x.l >= y.l); }
  friend bool operator<=(const uint128 &x, const uint128 &y) { return x.h < y.h || (x.h == y.h && x.l <= y.l); }
};

//-V:int128:730 not all members of a class are initialized inside the constructor
class int128
{
  uint64 l;
   int64 h;
  friend class uint128;
public:
  int128(void)  {}
  int128(uint x) { l = x; h = 0; }
  int128(int x)  { l = x; h = (x < 0) ? -1 : 0; }
  int128(uint64 x) { l = x; h = 0; }
  int128(int64 x)  { l = x; h = (x < 0) ? -1 : 0; }
  int128(uint64 ll, uint64 hh) { l=ll; h=hh; }
  int128(const uint128 &x) { l=x.l; h=x.h; }
  friend uint64 low (const int128 &x) { return x.l; }
  friend uint64 high(const int128 &x) { return x.h; }
  friend int128 operator+(const int128 &x, const int128 &y);
  friend int128 operator-(const int128 &x, const int128 &y);
  friend int128 operator/(const int128 &x, const int128 &y);
  friend int128 operator%(const int128 &x, const int128 &y);
  friend int128 operator*(const int128 &x, const int128 &y);
  friend int128 operator|(const int128 &x, const int128 &y);
  friend int128 operator&(const int128 &x, const int128 &y);
  friend int128 operator^(const int128 &x, const int128 &y);
  friend int128 operator>>(const int128 &x, int cnt);
  friend int128 operator<<(const int128 &x, int cnt);
  int128 &operator+=(const int128 &y);
  int128 &operator-=(const int128 &y);
  int128 &operator/=(const int128 &y);
  int128 &operator%=(const int128 &y);
  int128 &operator*=(const int128 &y);
  int128 &operator|=(const int128 &y);
  int128 &operator&=(const int128 &y);
  int128 &operator^=(const int128 &y);
  int128 &operator>>=(int cnt);
  int128 &operator<<=(int cnt);
  int128 &operator++(void);
  int128 &operator--(void);
  friend int128 operator+(const int128 &x) { return x; }
  friend int128 operator-(const int128 &x);
  friend int128 operator~(const int128 &x) { return int128(~x.l,~x.h); }
  friend bool operator==(const int128 &x, const int128 &y) { return x.l == y.l && x.h == y.h; }
  friend bool operator!=(const int128 &x, const int128 &y) { return x.l != y.l || x.h != y.h; }
  friend bool operator> (const int128 &x, const int128 &y) { return x.h > y.h || (x.h == y.h && x.l >  y.l); }
  friend bool operator< (const int128 &x, const int128 &y) { return x.h < y.h || (x.h == y.h && x.l <  y.l); }
  friend bool operator>=(const int128 &x, const int128 &y) { return x.h > y.h || (x.h == y.h && x.l >= y.l); }
  friend bool operator<=(const int128 &x, const int128 &y) { return x.h < y.h || (x.h == y.h && x.l <= y.l); }
};

inline int128  make_int128(uint64 ll, int64 hh) { return int128(ll, hh); }
inline uint128 make_uint128(uint64 ll, int64 hh) { return uint128(ll, hh); }
idaman THREAD_SAFE void ida_export swap128(uint128 *x);

//---------------------------------------------------------------------------
inline uint128 operator+(const uint128 &x, const uint128 &y)
{
  uint64 h = x.h + y.h;
  uint64 l = x.l + y.l;
  if ( l < x.l )
    h = h + 1;
  return uint128(l,h);
}

//---------------------------------------------------------------------------
inline uint128 operator-(const uint128 &x, const uint128 &y)
{
  uint64 h = x.h - y.h;
  uint64 l = x.l - y.l;
  if ( l > x.l )
    h = h - 1;
  return uint128(l,h);
}

//---------------------------------------------------------------------------
inline uint128 operator|(const uint128 &x, const uint128 &y)
{
  return uint128(x.l | y.l, x.h | y.h);
}

//---------------------------------------------------------------------------
inline uint128 operator&(const uint128 &x, const uint128 &y)
{
  return uint128(x.l & y.l, x.h & y.h);
}

//---------------------------------------------------------------------------
inline uint128 operator^(const uint128 &x, const uint128 &y)
{
  return uint128(x.l ^ y.l, x.h ^ y.h);
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator+=(const uint128 &y)
{
  return *this = *this + y;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator-=(const uint128 &y)
{
  return *this = *this - y;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator|=(const uint128 &y)
{
  return *this = *this | y;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator&=(const uint128 &y)
{
  return *this = *this & y;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator^=(const uint128 &y)
{
  return *this = *this ^ y;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator/=(const uint128 &y)
{
  return *this = *this / y;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator%=(const uint128 &y)
{
  return *this = *this % y;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator*=(const uint128 &y)
{
  return *this = *this * y;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator<<=(int cnt)
{
  return *this = *this << cnt;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator>>=(int cnt)
{
  return *this = *this >> cnt;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator++(void)
{
  if ( ++l == 0 )
    ++h;
  return *this;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator--(void)
{
  if ( l == 0 )
    --h;
  --l;
  return *this;
}

//---------------------------------------------------------------------------
inline uint128 operator-(const uint128 &x)
{
  return ~x + 1;
}

#ifndef NO_OBSOLETE_FUNCS
typedef uint64 ulonglong;
typedef int64 longlong;
#endif

#endif // ifdef __cplusplus
#endif // ifdef __HAS_INT128__

#endif // define _LLONG_HPP
