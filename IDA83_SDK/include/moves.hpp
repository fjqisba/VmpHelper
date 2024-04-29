/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef __MOVES_HPP
#define __MOVES_HPP

#include <dirtree.hpp>

//-------------------------------------------------------------------------
struct graph_location_info_t
{
  double zoom;          // zoom level, 1.0 == 100%, 0 means auto position
  double orgx;          // graph origin, x coord
  double orgy;          // graph origin, y coord
  graph_location_info_t(void) : zoom(0), orgx(0), orgy(0) {}
  bool operator == (const graph_location_info_t &r) const
    { return zoom == r.zoom && orgx == r.orgx && orgy == r.orgy; }  //-V550 An odd precise comparison: zoom == r.zoom
  bool operator != (const graph_location_info_t &r) const
    { return !(*this == r); }
  void serialize(bytevec_t *out) const;
  bool deserialize(memory_deserializer_t &mmdsr);
};

//-------------------------------------------------------------------------
inline void graph_location_info_t::serialize(bytevec_t *out) const
{
  CASSERT(sizeof(graph_location_info_t) == 3*8);
  out->append(this, sizeof(graph_location_info_t));
}

//-------------------------------------------------------------------------
inline bool graph_location_info_t::deserialize(memory_deserializer_t &mmdsr)
{
  return mmdsr.unpack_obj(this, sizeof(graph_location_info_t)) != nullptr;
}

//-------------------------------------------------------------------------
struct segm_move_info_t
{
  segm_move_info_t(ea_t _from = 0, ea_t _to = 0, size_t _sz = 0)
    : from(_from), to(_to), size(_sz) {}
  ea_t from, to;
  size_t size;

  bool operator == (const segm_move_info_t &r) const
    { return from == r.from && to == r.to && size == r.size; }
  bool operator != (const segm_move_info_t &r) const
    { return !(*this == r); }
};
DECLARE_TYPE_AS_MOVABLE(segm_move_info_t);
typedef qvector<segm_move_info_t> segm_move_info_vec_t;

struct segm_move_infos_t : public segm_move_info_vec_t
{
  const segm_move_info_t *find(ea_t ea) const
  {
    for ( size_t i = 0; i < size(); ++i )
    {
      const segm_move_info_t &cur = at(i);
      if ( ea >= cur.from && ea < cur.from + cur.size )
        return &cur;
    }
    return nullptr;
  }
};

//-------------------------------------------------------------------------
class place_t;

//-------------------------------------------------------------------------
struct renderer_info_pos_t // out of renderer_info_t, to enable SWiG parsing
{
  int node;
  short cx;
  short cy;

  renderer_info_pos_t() : node(-1), cx(-1), cy(-1) {}
  bool operator == (const renderer_info_pos_t &r) const
  { return node == r.node && cx == r.cx && cy == r.cy; }
  bool operator != (const renderer_info_pos_t &r) const
  { return !(*this == r); }
  void serialize(bytevec_t *out) const;
  bool deserialize(memory_deserializer_t &mmdsr);
};

//-------------------------------------------------------------------------
inline void renderer_info_pos_t::serialize(bytevec_t *out) const
{
  out->pack_dd(node);
  out->pack_dw(cx);
  out->pack_dw(cy);
}

//-------------------------------------------------------------------------
inline bool renderer_info_pos_t::deserialize(memory_deserializer_t &mmdsr)
{
  node = mmdsr.unpack_dd();
  cx   = mmdsr.unpack_dw();
  if ( mmdsr.empty() )
    return false;
  cy = mmdsr.unpack_dw();
  return true;
}

//-------------------------------------------------------------------------
struct renderer_info_t
{
  graph_location_info_t gli;
  typedef renderer_info_pos_t pos_t;
  pos_t pos;
  tcc_renderer_type_t rtype = TCCRT_INVALID;

  renderer_info_t() {}
  renderer_info_t(tcc_renderer_type_t _rtype, short cx, short cy) : rtype(_rtype)
  {
    pos.cx = cx;
    pos.cy = cy;
  }
  bool operator == (const renderer_info_t &r) const
    { return rtype == r.rtype && pos == r.pos && gli == r.gli; }
  bool operator != (const renderer_info_t &r) const
    { return !(*this == r); }
};


//-------------------------------------------------------------------------
class lochist_t;
struct lochist_entry_t;
struct expanded_area_t;

#define LSEF_PLACE (1 << 0)
#define LSEF_RINFO (1 << 1)
#define LSEF_PTYPE (1 << 2)
#define LSEF_ALL   (LSEF_PLACE|LSEF_RINFO|LSEF_PTYPE)

#ifndef SWIG
#define DEFINE_LOCHIST_T_HELPERS(decl) \
  decl void ida_export lochist_t_register_live(lochist_t &);            \
  decl void ida_export lochist_t_deregister_live(lochist_t &);          \
  decl bool ida_export lochist_t_init     (lochist_t &, const char *, const place_t &, void *, uint32); \
  decl void ida_export lochist_t_jump     (lochist_t &, bool try_to_unhide, const lochist_entry_t &e); \
  decl bool ida_export lochist_t_fwd      (lochist_t &, uint32 cnt, bool try_to_unhide);   \
  decl bool ida_export lochist_t_back     (lochist_t &, uint32 cnt, bool try_to_unhide);   \
  decl bool ida_export lochist_t_seek     (lochist_t &, uint32 index, bool try_to_unhide, bool apply_cur); \
  decl const lochist_entry_t *ida_export lochist_t_get_current(const lochist_t &);                  \
  decl uint32 ida_export lochist_t_current_index(const lochist_t &);        \
  decl void ida_export lochist_t_set      (lochist_t &, uint32, const lochist_entry_t &); \
  decl bool ida_export lochist_t_get      (lochist_entry_t *, const lochist_t &, uint32); \
  decl uint32 ida_export lochist_t_size   (const lochist_t &);\
  decl void ida_export lochist_t_save     (const lochist_t &); \
  decl void ida_export lochist_t_clear    (lochist_t &);
#else
#define DEFINE_LOCHIST_T_HELPERS(decl)
#endif // SWIG
DEFINE_LOCHIST_T_HELPERS(idaman)

#ifndef SWIG
#define DEFINE_LOCHIST_ENTRY_T_HELPERS(decl) \
  decl void ida_export lochist_entry_t_serialize(bytevec_t *, const lochist_entry_t &); \
  decl bool ida_export lochist_entry_t_deserialize(lochist_entry_t *, const uchar **, const uchar *const, const place_t *);
#else
#define DEFINE_LOCHIST_ENTRY_T_HELPERS(decl)
#endif // SWIG
DEFINE_LOCHIST_ENTRY_T_HELPERS(idaman)

//-------------------------------------------------------------------------
struct lochist_entry_t
{
  renderer_info_t rinfo;
  place_t *plce;

  lochist_entry_t() : plce(nullptr) {}
  lochist_entry_t(const place_t *p, const renderer_info_t &r)
    : rinfo(r), plce((place_t *) p)
  {
    if ( plce != nullptr )
      plce = plce->clone();
  }
#ifndef SWIG
  lochist_entry_t(const lochist_t &s);
#endif // SWIG
  lochist_entry_t(const lochist_entry_t &other) : plce(nullptr) { *this = other; }
  ~lochist_entry_t() { clear(); }
  const renderer_info_t &renderer_info() const { return rinfo; }
  const place_t *place() const { return plce; }

  renderer_info_t &renderer_info() { return rinfo; }
  place_t *place() { return plce; }

  void set_place(const place_t *p) { clear(); if ( p != nullptr ) plce = p->clone(); }
  void set_place(const place_t &p) { set_place(&p); }

  bool is_valid() const { return plce != nullptr; }

  lochist_entry_t &operator=(const lochist_entry_t &r)
  {
    clear();
    (*this).rinfo = r.rinfo;
    if ( r.plce != nullptr )
      plce = r.plce->clone();
    return *this;
  }

  void acquire_place(place_t *in_p)
  { clear(); plce = in_p; }

  void serialize(bytevec_t *out) const { lochist_entry_t_serialize(out, *this); }
  bool deserialize(const uchar **ptr, const uchar *const end, const place_t *tmplate)
  { return lochist_entry_t_deserialize(this, ptr, end, tmplate); }

private:
  void clear()
  {
    if ( plce != nullptr )
      qfree(plce);
    plce = nullptr;
  }

  friend class lochist_t;
  DEFINE_LOCHIST_T_HELPERS(friend)
  DEFINE_LOCHIST_ENTRY_T_HELPERS(friend)
};
DECLARE_TYPE_AS_MOVABLE(lochist_entry_t);
typedef qvector<lochist_entry_t> lochist_entry_vec_t;

#define UNHID_SEGM 0x0001  // unhid a segment at 'target'
#define UNHID_FUNC 0x0002  // unhid a function at 'target'
#define UNHID_RANGE 0x0004 // unhid an range at 'target'

#define DEFAULT_CURSOR_Y 0xFFFF
#define DEFAULT_LNNUM -1
#define CURLOC_LIST "$ curlocs"
#define MAX_MARK_SLOT   1024     // Max number of marked locations

//-------------------------------------------------------------------------
class lochist_t
{
  void *ud;

  DEFINE_LOCHIST_T_HELPERS(friend)

  lochist_entry_t cur;
  netnode node;

#define LHF_HISTORY_DISABLED (1 << 0) // enable history?
  uint32 flags;

public:
  lochist_t() : flags(0) { lochist_t_register_live(*this); }
  ~lochist_t() { lochist_t_deregister_live(*this); }
  bool is_history_enabled() const { return (flags & LHF_HISTORY_DISABLED) == 0; }
  int get_place_id() const
  {
    const place_t *p = cur.place();
    return p == nullptr ? -1 : p->id();
  }
  bool init(const char *stream_name, const place_t *_defpos, void *_ud, uint32 _flags)
  { return lochist_t_init(*this, stream_name, *_defpos, _ud, _flags); }

  nodeidx_t netcode() const
  { return node; }


  void jump(bool try_to_unhide, const lochist_entry_t &e)
  { lochist_t_jump(*this, try_to_unhide, e); }

  uint32 current_index() const
  { return lochist_t_current_index(*this); }

  bool seek(uint32 index, bool try_to_unhide)
  { return lochist_t_seek(*this, index, try_to_unhide, true); }

  bool fwd(uint32 cnt, bool try_to_unhide)
  { return lochist_t_fwd(*this, cnt, try_to_unhide); }

  bool back(uint32 cnt, bool try_to_unhide)
  { return lochist_t_back(*this, cnt, try_to_unhide); }

  void save() const
  { lochist_t_save(*this); }

  void clear()
  { lochist_t_clear(*this); }

  const lochist_entry_t &get_current() const
  { return *lochist_t_get_current(*this); }

  void set_current(const lochist_entry_t &e)
  { return set(current_index(), e); }

  void set(uint32 index, const lochist_entry_t &e)
  { lochist_t_set(*this, index, e); }

  bool get(lochist_entry_t *out, uint32 index) const
  { return lochist_t_get(out, *this, index); }

  uint32 size(void) const
  { return lochist_t_size(*this); }

  const place_t *get_template_place() const
  { return cur.place(); }
};
DECLARE_TYPE_AS_MOVABLE(lochist_t);

//-------------------------------------------------------------------------
#ifndef SWIG
idaman uint32 ida_export bookmarks_t_mark(const lochist_entry_t &, uint32, const char *, const char *, void *);
idaman bool ida_export bookmarks_t_get(lochist_entry_t *, qstring *, uint32 *, void *);
idaman bool ida_export bookmarks_t_get_desc(qstring *, const lochist_entry_t &, uint32, void *);
idaman bool ida_export bookmarks_t_set_desc(qstring, const lochist_entry_t &, uint32, void *);
idaman uint32 ida_export bookmarks_t_find_index(const lochist_entry_t &, void *);
idaman uint32 ida_export bookmarks_t_size(const lochist_entry_t &, void *);
idaman bool ida_export bookmarks_t_erase(const lochist_entry_t &, uint32, void *);
idaman dirtree_id_t ida_export bookmarks_t_get_dirtree_id(const lochist_entry_t &, void *);
#endif // SWIG

//-------------------------------------------------------------------------
class bookmarks_t
{
  bookmarks_t(); // No.
  ~bookmarks_t() {}
public:
#define BOOKMARKS_CHOOSE_INDEX (uint32(-1))
#define BOOKMARKS_BAD_INDEX (uint32(-1))
#define BOOKMARKS_PROMPT_WITH_HINT_PREFIX '\x01'

  // Mark/unmark position
  // index  - the marked position number (0..MAX_MARK_SLOT)
  //          if specified as BOOKMARKS_CHOOSE_INDEX: ask the user to select the mark slot.
  // title  - if index == BOOKMARKS_CHOOSE_INDEX, then the window caption of
  //          the dialog which will appear on the screen. title==nullptr will
  //          lead to the default caption: "please select a mark slot"
  // desc   - description of the marked position. If nullptr, IDA will show a
  //          dialog box asking the user to enter the description.
  //          If non-nullptr but starts with BOOKMARKS_PROMPT_WITH_HINT_PREFIX,
  //          IDA will also prompt the user, but with a pre-filled value
  //          starting at &desc[1].
  // returns used marker number (BOOKMARKS_BAD_INDEX - none)
  static uint32 mark(
        const lochist_entry_t &e,
        uint32 index,
        const char *title,
        const char *desc,
        void *ud)
  { return bookmarks_t_mark(e, index, title, desc, ud); }

  // 'out_entry' MUST:
  //  - contain a valid place_t*; data will be deserialized into it
  //  - have a valid, corresponding tcc_place_type_t
  static bool get(
        lochist_entry_t *out_entry,
        qstring *out_desc,
        uint32 *index, // index==BOOKMARKS_CHOOSE_INDEX? let the user choose
        void *ud)
  { return bookmarks_t_get(out_entry, out_desc, index, ud); }

  static bool get_desc(
        qstring *out,
        const lochist_entry_t &e,
        uint32 index,
        void *ud)
  { return bookmarks_t_get_desc(out, e, index, ud); }

  static uint32 find_index(
        const lochist_entry_t &e,
        void *ud)
  { return bookmarks_t_find_index(e, ud); }

  static uint32 size(
        const lochist_entry_t &e,
        void *ud)
  { return bookmarks_t_size(e, ud); }

  static bool erase(
        const lochist_entry_t &e,
        uint32 index,
        void *ud)
  { return bookmarks_t_erase(e, index, ud); }

  static dirtree_id_t get_dirtree_id(
        const lochist_entry_t &e,
        void *ud)
  { return bookmarks_t_get_dirtree_id(e, ud); }
};

//-------------------------------------------------------------------------
inline lochist_entry_t::lochist_entry_t(const lochist_t &lh)
  : plce(nullptr)
{
  *this = lh.get_current();
}


#endif // __MOVES_HPP
