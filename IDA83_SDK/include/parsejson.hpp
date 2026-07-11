/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef PARSEJSON_HPP
#define PARSEJSON_HPP

/*! \file parsejson.hpp

  \brief Tools for parsing JSON-formatted input

  See also lex.hpp/parse.hpp for finer-grained functions & documentation.
*/
#include <lex.hpp>

//---------------------------------------------------------------------------
enum jtype_t
{
  JT_UNKNOWN = 0,
  JT_NUM,
  JT_STR,
  JT_OBJ,
  JT_ARR,
  JT_BOOL,
  JT_NULL,
};

//---------------------------------------------------------------------------
struct jobj_t;
struct jarr_t;

#define DECLARE_JVALUE_HELPERS(decl)                                    \
  decl void ida_export jvalue_t_clear(jvalue_t *);                      \
  decl void ida_export jvalue_t_copy(jvalue_t *, const jvalue_t &);


struct jvalue_t;
DECLARE_JVALUE_HELPERS(idaman)

//-------------------------------------------------------------------------
struct jvalue_t
{
  jvalue_t() : _type(JT_UNKNOWN), _num(0) {}
  jvalue_t(const jvalue_t &o) : _type(JT_UNKNOWN) { jvalue_t_copy(this, o); }
  ~jvalue_t() { clear(); }

  void clear() { jvalue_t_clear(this); }

  jvalue_t &operator=(const jvalue_t &o) { jvalue_t_copy(this, o); return *this; }

  jtype_t type() const { return _type; }
  int64 num() const { QASSERT(1277, _type == JT_NUM); return _num; }
  const char *str() const { QASSERT(1278, _type == JT_STR); return _str->c_str(); }
  const qstring &qstr() const { QASSERT(1623, _type == JT_STR); return *_str; }
  const jobj_t &obj() const { QASSERT(1279, _type == JT_OBJ); return *_obj; }
  const jarr_t &arr() const { QASSERT(1280, _type == JT_ARR); return *_arr; }
  bool vbool() const { QASSERT(1281, _type == JT_BOOL); return _bool; }
  jobj_t &obj() { QASSERT(1282, _type == JT_OBJ); return *_obj; }
  jarr_t &arr() { QASSERT(1283, _type == JT_ARR); return *_arr; }

  bool is_null() const { QASSERT(0, _type == JT_NULL); return true; }

  //lint -sem(jvalue_t::set_str, custodial(1)) function takes ownership of its argument
  //lint -sem(jvalue_t::set_obj, custodial(1)) function takes ownership of its argument
  //lint -sem(jvalue_t::set_arr, custodial(1)) function takes ownership of its argument
  void set_num(int64 i) { if ( _type != JT_UNKNOWN ) clear(); _type = JT_NUM; _num = i; }
  void set_str(qstring *s) { if ( _type != JT_UNKNOWN ) clear(); _type = JT_STR; _str = s; }
  void set_obj(jobj_t *o) { if ( _type != JT_UNKNOWN ) clear(); _type = JT_OBJ; _obj = o; }
  void set_arr(jarr_t *a) { if ( _type != JT_UNKNOWN ) clear(); _type = JT_ARR; _arr = a; }
  void set_bool(bool b) { if ( _type != JT_UNKNOWN ) clear(); _type = JT_BOOL; _bool = b; }
  void set_null() { if ( _type != JT_UNKNOWN ) clear(); _type = JT_NULL; }

  jobj_t *extract_obj() { QASSERT(1624, _type == JT_OBJ); jobj_t *o = _obj; _obj = nullptr; _type = JT_UNKNOWN; return o; }
  jarr_t *extract_arr() { QASSERT(1625, _type == JT_ARR); jarr_t *a = _arr; _arr = nullptr; _type = JT_UNKNOWN; return a; }

  void swap(jvalue_t &r)
  {
    qswap(_type, r._type);
    qswap(_str, r._str);
  }

private:
  DECLARE_JVALUE_HELPERS(friend)

  jtype_t _type;

  union
  {
    int64 _num;
    qstring *_str;
    jobj_t *_obj;
    jarr_t *_arr;
    bool _bool;
  };
};
DECLARE_TYPE_AS_MOVABLE(jvalue_t);
typedef qvector<jvalue_t> jvalues_t;

//---------------------------------------------------------------------------
struct kvp_t
{
  qstring key;
  jvalue_t value;
};
DECLARE_TYPE_AS_MOVABLE(kvp_t);

//-------------------------------------------------------------------------
struct jobj_t : public qvector<kvp_t>
{
  bool has_value(const char *k) const { return get_value(k) != nullptr; }
  jvalue_t *get_value(const char *k, jtype_t t=JT_UNKNOWN)
  {
    jvalue_t *v = nullptr;
    for ( size_t i = 0, _n = size(); i < _n; ++i )
    {
      if ( at(i).key == k )
      {
        if ( t == JT_UNKNOWN || at(i).value.type() == t )
          v = &at(i).value;
        break;
      }
    }
    return v;
  }

  const jvalue_t *get_value(const char *k, jtype_t t=JT_UNKNOWN) const
  {
    return ((jobj_t *) this)->get_value(k, t);
  }

  const jvalue_t *get_value_or_fail(const char *k, jtype_t t=JT_UNKNOWN) const
  {
    const jvalue_t *v = get_value(k, t);
    QASSERT(1289, v != nullptr);
    return v;
  }

  jvalue_t *get_value_or_new(const char *key)
  {
    jvalue_t *v = get_value(key);
    if ( v == nullptr )
    {
      kvp_t &kvp = push_back();
      kvp.key = key;
      v = &kvp.value;
    }
    return v;
  }

  int64 get_num(const char *k) const { return get_value_or_fail(k)->num(); }
  bool get_bool(const char *k) const { return get_value_or_fail(k)->vbool(); }
  const char *get_str(const char *k) const { return get_value_or_fail(k)->str(); }
  const jobj_t &get_obj(const char *k) const { return get_value_or_fail(k)->obj(); }
  const jarr_t &get_arr(const char *k) const { return get_value_or_fail(k)->arr(); }

#define DEFINE_FLAG_GETTER(Type, JType, GetExpr)        \
  bool get(Type *out, const char *k) const              \
  {                                                     \
    const jvalue_t *v = get_value(k, JType);            \
    bool ok = v != nullptr;                             \
    if ( ok )                                           \
      *out = GetExpr;                                   \
    return ok;                                          \
  }
#define DEFINE_DFLT_GETTER(Type, JType, GetExpr)  \
  Type get(const char *k, Type dflt) const        \
  {                                               \
    const jvalue_t *v = get_value(k, JType);      \
    return v != nullptr ? GetExpr : dflt;         \
  }
#define DEFINE_SETTER(Type, SetExpr)            \
  void put(const char *key, Type value)         \
  {                                             \
    jvalue_t *v = get_value_or_new(key);        \
    SetExpr;                                    \
  }
#define DEFINE_ACCESSORS(Type, ConstType, JType, GetExpr, SetExpr)      \
  DEFINE_FLAG_GETTER(ConstType, JType, GetExpr)                          \
  DEFINE_DFLT_GETTER(ConstType, JType, GetExpr)                         \
  DEFINE_SETTER(Type, SetExpr)

  DEFINE_ACCESSORS(int, int, JT_NUM, v->num(), v->set_num(value));
  DEFINE_ACCESSORS(int64, int64, JT_NUM, v->num(), v->set_num(value));
  DEFINE_ACCESSORS(bool, bool, JT_BOOL, v->vbool(), v->set_bool(value));
  //lint -sem(jobj_t::put(const char *, struct jarr_t *), custodial(2)) function takes ownership of its argument
  DEFINE_ACCESSORS(jarr_t *, const jarr_t *, JT_ARR, &v->arr(), v->set_arr(value));
  //lint -sem(jobj_t::put(const char *, struct jobj_t *), custodial(2)) function takes ownership of its argument
  DEFINE_ACCESSORS(jobj_t *, const jobj_t *, JT_OBJ, &v->obj(), v->set_obj(value));
  DEFINE_ACCESSORS(const char *, const char *, JT_STR, v->str(), v->set_str(new qstring(value)));
#undef DEFINE_ACCESSORS
#undef DEFINE_SETTER
#undef DEFINE_DFLT_GETTER
#undef DEFINE_FLAG_GETTER

  bool get(qstring *out, const char *k) const
  {
    const jvalue_t *v = get_value(k, JT_STR);
    bool ok = v != nullptr;
    if ( ok )
      *out = v->qstr();
    return ok;
  }

  const qstring &get(const char *k, const qstring &dflt) const
  {
    const jvalue_t *v = get_value(k, JT_STR);
    return v != nullptr ? v->qstr() : dflt;
  }

  void put(const char *key, const qstring &value)
  {
    jvalue_t *v = get_value_or_new(key);
    v->set_str(new qstring(value));
  }
};
DECLARE_TYPE_AS_MOVABLE(jobj_t);

//---------------------------------------------------------------------------
struct jarr_t
{
  jvalues_t values;

  size_t count_items_with_type(jtype_t t) const
  {
    size_t cnt = 0;
    for ( size_t i = 0, n = values.size(); i < n; ++i )
      if ( values[i].type() == t )
        ++cnt;
    return cnt;
  }

  bool is_homogeneous(jtype_t t) const
  {
    return count_items_with_type(t) == values.size();
  }
};
DECLARE_TYPE_AS_MOVABLE(jarr_t);

//---------------------------------------------------------------------------
// Note: If 'ungot_tokens' is not nullptr, its contents will be used before fetching tokens from the lexer
idaman THREAD_SAFE error_t ida_export parse_json(jvalue_t *out, lexer_t *lx, tokenstack_t *ungot_tokens = nullptr);
idaman THREAD_SAFE error_t ida_export parse_json_string(jvalue_t *out, const char *s);

//-------------------------------------------------------------------------
#define SJF_PRETTY 0x1
idaman THREAD_SAFE bool ida_export serialize_json(
        qstring *out,
        const jvalue_t &v,
        uint32 flags=0);

inline THREAD_SAFE bool serialize_json(
        qstring *out,
        const jobj_t *o,
        uint32 flags=0)
{
  jvalue_t v;
  v.set_obj((jobj_t *) o);
  bool rc = serialize_json(out, v, flags);
  v.extract_obj();
  return rc;
}

#endif // PARSEJSON_HPP
