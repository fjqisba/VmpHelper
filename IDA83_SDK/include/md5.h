#ifndef MD5_H
#define MD5_H

struct MD5Context
{
  uint32 buf[4];
  uint32 bits[2];
  unsigned char in[64];

  MD5Context() { memset(this, 0, sizeof(*this)); }
};

idaman THREAD_SAFE void ida_export MD5Init(MD5Context *context);
idaman THREAD_SAFE void ida_export MD5Update(MD5Context *context, const void *buf, size_t len);
idaman THREAD_SAFE void ida_export MD5Final(uchar digest[16], MD5Context *context);
idaman THREAD_SAFE void ida_export MD5Transform(uint32 buf[4], uint32 const in[16]);

//---------------------------------------------------------------------------
struct md5_t
{
  uchar hash[16];

  md5_t()               { clear(); }
  md5_t(const md5_t &r) { assign(r); }

  const uchar &operator[](size_t i) const { return hash[i]; }
  uchar &operator[](size_t i)             { return hash[i]; }

  void clear() { memset(hash, 0, sizeof(hash)); }
  void swap(md5_t &other) { std::swap(*this, other); }

  md5_t &operator=(const md5_t &r)
  {
    if ( this != &r )
      assign(r);
    return *this;
  }

  DECLARE_COMPARISONS(md5_t)
  {
    return memcmp(hash, r.hash, sizeof(hash));
  }


protected:
  void assign(const md5_t &r) { memmove(hash, r.hash, sizeof(hash)); }
};
DECLARE_TYPE_AS_MOVABLE(md5_t);
typedef qvector<md5_t> md5_vec_t;

#endif /* !MD5_H */
