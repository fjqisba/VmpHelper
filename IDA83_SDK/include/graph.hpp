/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2023 Hex-Rays
 *      Graph type definitions
 *
 *      Due to the use of STL and virtual functions, some parts of this
 *      interface might be incompatible with compilers other than Visual Studio
 *      on Windows and gcc on Unix systems
 */

#ifndef __GRAPH_DEF_HPP
#define __GRAPH_DEF_HPP

#include <math.h>
#include <pro.h>
#include <gdl.hpp>
#include <idp.hpp>
#include <kernwin.hpp>

/*! \file graph.hpp

  \brief Graph view management

*/

class func_t;
class abstract_graph_t;

//-------------------------------------------------------------------------
/// \defgroup NIF_ Node info flags
/// Passed as 'flags' parameter to set_node_info().
/// Also see node_info_t::get_flags_for_valid().
//@{
#define NIF_BG_COLOR    (1 << 0)  ///< node_info_t::bg_color
#define NIF_FRAME_COLOR (1 << 1)  ///< node_info_t::frame_color
#define NIF_EA          (1 << 2)  ///< node_info_t::ea
#define NIF_TEXT        (1 << 3)  ///< node_info_t::text
#define NIF_FLAGS       (1 << 4)  ///< node_info_t::flags
#define NIF_ALL         (NIF_BG_COLOR | NIF_FRAME_COLOR | NIF_EA | NIF_TEXT | NIF_FLAGS)
//@}

//-------------------------------------------------------------------------
/// \defgroup GLICTL_ graph_location_info_t control flags
/// Passed as 'flags' parameter to viewer_set_gli() and viewer_get_gli().
//@{
#define GLICTL_CENTER   (1 << 0)  ///< the gli should be set/get as center
//@}

/// Information about a node in a graph
struct node_info_t
{
private:
  size_t cb = sizeof(node_info_t);  ///< size of this structure
public:
  bgcolor_t bg_color = DEFCOLOR;    ///< background color
  bgcolor_t frame_color = DEFCOLOR; ///< color of enclosing frame
#define NIFF_SHOW_CONTENTS (1 << 0) // force show contents of huge node
  uint32 flags = 0;                 ///< flags
  ea_t ea = BADADDR;                ///< address
  qstring text;                     ///< node contents

  /// Has valid #bg_color?
  inline bool valid_bg_color() const { return bg_color != DEFCOLOR; }
  /// Has valid #frame_color?
  inline bool valid_frame_color() const { return frame_color != DEFCOLOR; }
  /// Has valid #ea?
  inline bool valid_ea() const { return ea != BADADDR; }
  /// Has non-empty #text?
  inline bool valid_text() const { return !text.empty(); }
  /// Has valid #flags?
  inline bool valid_flags() const { return flags != 0; }

  /// Get combination of \ref NIF_ describing which attributes are valid
  inline uint32 get_flags_for_valid() const
  {
    uint32 F = 0;
    if ( valid_bg_color() )
      F |= NIF_BG_COLOR;
    if ( valid_frame_color() )
      F |= NIF_FRAME_COLOR;
    if ( valid_ea() )
      F |= NIF_EA;
    if ( valid_text() )
      F |= NIF_TEXT;
    if ( valid_flags() )
      F |= NIF_FLAGS;
    return F;
  }
};

/// Graph instances have a unique id (see mutable_graph_t::gid)
typedef ea_t graph_id_t;


/// Get node info.
/// \param out   result
/// \param gid   id of desired graph
/// \param node  node number
/// \return success

idaman bool ida_export get_node_info(node_info_t *out, graph_id_t gid, int node);


/// Set node info.
/// \param gid    id of desired graph
/// \param node   node number
/// \param ni     node info to use
/// \param flags  combination of \ref NIF_,
///               identifying which fields of 'ni' will be used

idaman void ida_export set_node_info(graph_id_t gid, int node, const node_info_t &ni, uint32 flags);


/// Delete the ::node_info_t for the given node

idaman void ida_export del_node_info(graph_id_t gid, int node);


/// Clear node info for the given node.
/// \param gid    id of desired graph
/// \param node   node number
/// \param flags  combination of \ref NIF_,
///               identifying which fields of ::node_info_t
///               will be cleared

idaman void ida_export clr_node_info(graph_id_t gid, int node, uint32 flags);


//-------------------------------------------------------------------------
/// Node ordering in a graph.
/// Maps a node number to a number describing its
/// order in the graph (and vice versa).
class node_ordering_t
{
  intvec_t node_by_order;           ///< ordered sequence of node numbers
  intvec_t order_by_node;           ///< node number => index in #node_by_order

  void ensure_order_by_node()
  {
    if ( order_by_node.empty() )
    {
      size_t n = size();
      order_by_node.resize(n, -1);
      for ( size_t i = 0; i < n; i++ )
      {
        int idx = node_by_order[i];
        if ( idx != -1 )
          order_by_node[idx] = i;
      }
    }
  }

public:
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  void idaapi clear(void)
  {
    node_by_order.clear();
    order_by_node.clear();
  }

  void idaapi resize(int n)
  {
    clear();
    if ( n >= 0 )
      node_by_order.resize(n, -1);
  }

  size_t idaapi size(void) const
  {
    return node_by_order.size();
  }

  void idaapi set(int _node, int num)
  {
    ensure_order_by_node();
    if ( num >= 0 && num < node_by_order.size()
      && _node >= 0 && _node < order_by_node.size() )
    {
      node_by_order[num] = _node;
      order_by_node[_node] = num;
    }
  }

  bool idaapi clr(int _node)
  {
    if ( _node < 0 )
      return false;
    ensure_order_by_node();
    if ( _node >= order_by_node.size() )
      return false;
    int old = order_by_node[_node];
    if ( old < 0 || old >= node_by_order.size() )
      return false;
    order_by_node[_node] = -1;
    node_by_order[old] = -1;
    // shift all order numbers higher than the deleted order number by one
    size_t n = size();
    for ( size_t i = 0; i < n; i++ )
      if ( order_by_node[i] > old )
        order_by_node[i]--;
    int rest = n - old - 1;
    if ( rest > 0 )
      memmove(&node_by_order[old], &node_by_order[old+1], rest*sizeof(int));
    return true;
  }

  int idaapi node(size_t _order) const
  {
    return _order < node_by_order.size() ? node_by_order[_order] : -1;
  }

  int idaapi order(int _node)
  {
    ensure_order_by_node();
    return (_node >= 0 && _node < order_by_node.size()) ? order_by_node[_node] : -1;
  }
};

//-------------------------------------------------------------------------
/// Edge connecting two graph nodes
struct edge_t
{
  int src = 0;  ///< source node number
  int dst = 0;  ///< destination node number
  idaapi edge_t() {}
  idaapi edge_t(int x, int y) : src(x), dst(y) {}
  bool idaapi operator < (const edge_t &y) const
    { return src < y.src || (src == y.src && dst < y.dst); }
  bool idaapi operator == (const edge_t &y) const
    { return src == y.src && dst == y.dst; }
  bool idaapi operator != (const edge_t &y) const
    { return src != y.src || dst != y.dst; }
};
DECLARE_TYPE_AS_MOVABLE(edge_t);

typedef qvector<edge_t> edgevec_t; ///< vector of graph edges
struct edgeset_t;
struct edge_segs_vec_t;
struct edge_infos_t;
struct destset_t;

enum edge_type_t
{
  edge_error    = 0,
  edge_tree     = 1,
  edge_forward  = 2,
  edge_back     = 3,
  edge_cross    = 4,
  edge_subgraph = 5   // edge of a subgraph (used in collapse)
};

//-------------------------------------------------------------------------
class edge_typer_t;

//-------------------------------------------------------------------------
/// Node visitor - see abstract_graph_t::visit_nodes()
class graph_node_visitor_t
{
  node_set_t visited; ///< set of previously visited nodes
public:
  /// Reset visited nodes
  void idaapi reinit(void) { visited.clear(); }
  /// Mark node as visited
  void idaapi set_visited(int n) { visited.add(n); }
  /// Have we already visited the given node?
  bool idaapi is_visited(int n) const { return visited.has(n); }

  /// Implements action to take when a node is visited
  virtual int  idaapi visit_node(int /*node*/) { return 0; }
  /// Should the edge between 'n' and 'm' be ignored?
  virtual bool idaapi is_forbidden_edge(int /*n*/, int /*m*/) const { return false; }

  virtual ~graph_node_visitor_t() {}
};

//-------------------------------------------------------------------------
/// Path visitor - see abstract_graph_t::visit_paths()
struct graph_path_visitor_t
{
  intvec_t path;                ///< current path
  bool prune = false;           ///< walk_forward(): prune := true
                                ///< means to stop the current path


  virtual int idaapi walk_forward(int /*node*/) { return 0; }
  virtual int idaapi walk_backward(int /*node*/) { return 0; }

  virtual ~graph_path_visitor_t() {}
};

//-------------------------------------------------------------------------
/// Coordinate in a graph view
struct point_t
{
  int x = 0;
  int y = 0;
  point_t() {}
  point_t(int _x, int _y) : x(_x), y(_y) {}
  point_t &add(const point_t &r)
  {
    x += r.x;
    y += r.y;
    return *this;
  }
  point_t &sub(const point_t &r)
  {
    x -= r.x;
    y -= r.y;
    return *this;
  }
  template <class T> void div(T d)
  {
    x /= d;
    y /= d;
  }
  void negate(void)
  {
    x = -x;
    y = -y;
  }
#ifdef VCL_H
  point_t(const TPoint &p) : x(p.x), y(p.y) {}
#endif
  bool operator ==(const point_t &r) const { return x == r.x && y == r.y; }
  bool operator !=(const point_t &r) const { return !(*this == r); }
  const char *idaapi dstr(void) const;
  size_t idaapi print(char *buf, size_t bufsize) const;
};
DECLARE_TYPE_AS_MOVABLE(point_t);
typedef qvector<point_t> pointvec_t;

/// Calculate distance between p and q
inline THREAD_SAFE double calc_dist(point_t p, point_t q)
{
  double dx = q.x - p.x;
  double dy = q.y - p.y;
  return sqrt(dx*dx+dy*dy);
}

/// Ordered sequence of points
class pointseq_t : public pointvec_t
{
public:
  const char *idaapi dstr(void) const;
  size_t idaapi print(char *buf, size_t bufsize) const;
};

/// A rectangle in a graph view.
/// Please note that a correct rectangle has left < right and top < bottom.
/// NB: top less than bottom, which means that the vertical axis grows to the
/// bottom, a bigger value means verically lower.
struct rect_t
{
  int left = 0;
  int top = 0;
  int right = 0;
  int bottom = 0;
  rect_t() {}
  rect_t(int l, int t, int r, int b) : left(l), top(t), right(r), bottom(b) {}
  rect_t(const point_t &p0, const point_t &p1)
    : left  (qmin(p0.x, p1.x)),
      top   (qmin(p0.y, p1.y)),
      right (qmax(p0.x, p1.x)),
      bottom(qmax(p0.y, p1.y))  {}
  int width(void) const { return right - left; }
  int height(void) const { return bottom - top; }
  void move_to(const point_t &p)
  {
    int dx  = p.x - left;
    int dy  = p.y - top;
    move_by(point_t(dx, dy));
  }
  void move_by(const point_t &p)
  {
    left   += p.x;
    right  += p.x;
    top    += p.y;
    bottom += p.y;
  }
  point_t center(void) const
  {
    return point_t((left+right)/2, (top+bottom)/2);
  }
  point_t topleft(void) const
  {
    return point_t(left, top);
  }
  point_t bottomright(void) const
  {
    return point_t(right, bottom);
  }
  void grow(int delta)
  {
    left   -= delta;
    right  += delta;
    top    -= delta;
    bottom += delta;
  }
  void intersect(const rect_t &r)
  {
    if ( left < r.left )
      left = r.left;
    if ( right > r.right )
      right = r.right;
    if ( top < r.top )
      top = r.top;
    if ( bottom > r.bottom )
      bottom = r.bottom;
  }
  void make_union(const rect_t &r)
  {
    if ( left > r.left )
      left = r.left;
    if ( right < r.right )
      right = r.right;
    if ( top > r.top )
      top = r.top;
    if ( bottom < r.bottom )
      bottom = r.bottom;
  }
  bool empty(void) const
  {
    return left >= right || top >= bottom;
  }
  bool is_intersection_empty(const rect_t &r) const
  {
    return left   >= r.right
        || right  <= r.left
        || top    >= r.bottom
        || bottom <= r.top;
  }
  bool contains(const point_t &p) const
  {
    return left <= p.x
        && right > p.x
        && top <= p.y
        && bottom > p.y;
  }
  int area(void) const { return width()*height(); }
  bool idaapi operator == (const rect_t &r) const
  {
    return left   == r.left
        && right  == r.right
        && top    == r.top
        && bottom == r.bottom;
  }
  bool idaapi operator != (const rect_t &r) const { return !(*this == r); }
  bool idaapi operator < (const rect_t &r) const;
#ifdef VCL_H
  const TRect &operator()(void) const { return *(TRect *)this; }
        TRect &operator()(void)       { return *(TRect *)this; }
  rect_t(const TRect &r) : left(r.left), top(r.top), right(r.right), bottom(r.bottom) {}
#endif
};
DECLARE_TYPE_AS_MOVABLE(rect_t);

//---------------------------------------------------------------------------
/// Coordinate in a graph view (double precision)
struct TPointDouble
{
  double x = 0.0;
  double y = 0.0;
  TPointDouble() {}
  TPointDouble(double a, double b) : x(a), y(b) {}
  TPointDouble(const point_t &r) : x(r.x), y(r.y) {}
  void add(const TPointDouble &r)
  {
    x += r.x;
    y += r.y;
  }
  void sub(const TPointDouble &r)
  {
    x -= r.x;
    y -= r.y;
  }
  void negate(void)
  {
    x = -x;
    y = -y;
  }
  template <class T> void div(T d)
  {
    x /= d;
    y /= d;
  }
  bool operator ==(const TPointDouble &r) const { return x == r.x && y == r.y; }  //-V550 An odd precise comparison: x == r.x
  bool operator !=(const TPointDouble &r) const { return !(*this == r); }
};

//---------------------------------------------------------------------------
typedef int layout_type_t; ///< see \ref layout_
/// \defgroup layout_ Proximity view layouts
//@{
const layout_type_t
  layout_none        = 0,
  layout_digraph     = 1,
  layout_tree        = 2,
  layout_circle      = 3,
  layout_polar_tree  = 4,
  layout_orthogonal  = 5,
  layout_radial_tree = 6;
//@}

/// Attributes of a graph edge
struct edge_info_t
{
  bgcolor_t color = DEFCOLOR; ///< edge color
  int width = 1;              ///< edge width
  int srcoff = -1;            ///< source: edge port offset from the left
  int dstoff = -1;            ///< destination: edge port offset from the left
  pointseq_t layout;  ///< describes geometry of edge
#if !defined(_MSC_VER) || _MSC_VER >= 1600
  void idaapi reverse_layout(void) { std::reverse(layout.begin(), layout.end()); }
#endif
  void idaapi add_layout_point(point_t p);
};

/// Edge layout point
struct edge_layout_point_t
{
  int pidx = -1;              ///< index into edge_info_t::layout
  edge_t e = edge_t(-1, -1);  ///< parent edge
  idaapi edge_layout_point_t() {}
  idaapi edge_layout_point_t(const edge_t &_e, int _pidx) : pidx(_pidx), e(_e) {}
  int idaapi compare(const edge_layout_point_t &r) const
  {
    if ( e < r.e )
      return -1;
    if ( r.e < e )
      return 1;
    return ::compare(pidx, r.pidx);
  }
  bool idaapi operator == (const edge_layout_point_t &r) const
  {
    return pidx == r.pidx && e == r.e;
  }
  bool idaapi operator != (const edge_layout_point_t &r) const
  {
    return !(*this == r);
  }
};

/// Element of a graph selection - could be a node or edge layout point.
/// See ::screen_graph_selection_t.
struct selection_item_t
{
  bool is_node = false;    ///< represents a selected node?
  int node = -1;           ///< node number (is_node = true)
  edge_layout_point_t elp; ///< edge layout point (is_node = false)
  idaapi selection_item_t() {}
  idaapi selection_item_t(int n) : is_node(true), node(n) {}
  idaapi selection_item_t(edge_layout_point_t &_elp)
    : is_node(false), node(-1), elp(_elp) {}
  idaapi selection_item_t(edge_t e, int idx)
    : is_node(false), node(-1), elp(e, idx) {}
  idaapi selection_item_t(class graph_item_t &);
  int idaapi compare(const selection_item_t &r) const
  {
    if ( is_node != r.is_node )
      return is_node - r.is_node;
    if ( is_node )
      return ::compare(node, r.node);
    return elp.compare(r.elp);
  }
  bool idaapi operator == (const selection_item_t &r) const
    { return compare(r) == 0; }
  bool idaapi operator != (const selection_item_t &r) const
    { return compare(r) != 0; }
  bool idaapi operator < (const selection_item_t &r) const
    { return compare(r) < 0; }
};


/// Selection in a graph.
/// (A list of nodes and edge layout points).
/// This selection is used to move a subgraph on the screen.
typedef qvector<selection_item_t> screen_graph_selection_base_t;

struct screen_graph_selection_t : public screen_graph_selection_base_t
{
  bool idaapi has(const selection_item_t &item) const
    { return (const_iterator)find(item) != end(); }
  void idaapi add(const screen_graph_selection_t &s)
  {
    for ( screen_graph_selection_t::const_iterator p=s.begin(); p != s.end(); ++p )
      add_unique(*p);
  }
  void idaapi sub(const screen_graph_selection_t &s)
  {
    for ( screen_graph_selection_t::const_iterator p=s.begin(); p != s.end(); ++p )
      del(*p);
  }
  void idaapi add_node(int node) { add_unique(selection_item_t(node)); }
  void idaapi del_node(int node) { del(selection_item_t(node)); }
  void idaapi add_point(edge_t e, int idx) { add_unique(selection_item_t(e, idx)); }
  void idaapi del_point(edge_t e, int idx) { del(selection_item_t(e, idx)); }

  size_t idaapi nodes_count() const { return items_count(true); }
  size_t idaapi points_count() const { return items_count(false); }
  size_t idaapi items_count(bool look_for_nodes) const
  {
    size_t cnt = 0;
    for ( size_t i = 0, sz = size(); i < sz; ++i )
      if ( at(i).is_node == look_for_nodes )
        ++cnt;
    return cnt;
  }
};

/// Sub-segment of a graph edge
struct edge_segment_t
{
  edge_t e;
  int nseg;
  int x0, x1;
  size_t idaapi length() const { return abs(x1-x0); }
  bool idaapi toright() const { return x1 > x0; } // horizontal segment to the right
  bool idaapi operator < (const edge_segment_t &r) const
  {
    return e < r.e;
/*    // longest edges first
    int ll =   x1 -   x0; if ( ll < 0 ) ll = -ll;
    int rl = r.x1 - r.x0; if ( rl < 0 ) rl = -rl;
    if ( rl < ll )
      return true;
    if ( rl == ll )
      return e < r.e;
    return false;*/
  }
};

//---------------------------------------------------------------------------
/// See ::graph_item_t
enum graph_item_type_t
{           //                     valid graph_item_t fields:
  git_none, ///< nothing
  git_edge, ///< edge              (graph_item_t::e, graph_item_t::n. n is farthest edge endpoint)
  git_node, ///< node title        (graph_item_t::n)
  git_tool, ///< node title button (graph_item_t::n, graph_item_t::b)
  git_text, ///< node text         (graph_item_t::n, graph_item_t::p)
  git_elp,  ///< edge layout point (graph_item_t::elp)
};

/// Describes a sub-item of a graph
class graph_item_t
{
public:
  graph_item_type_t type;  ///< type
  edge_t e;                ///< edge source and destination
  int n;                   ///< node number
  int b;                   ///< button number
  point_t p;               ///< text coordinates in the node
  edge_layout_point_t elp; ///< edge layout point
  bool operator == (const graph_item_t &r) const;
  bool is_node(void) const { return type >= git_node && type <= git_text; }
  bool is_edge(void) const { return type == git_edge || type == git_elp; }
};

//-------------------------------------------------------------------------
/// One dimensional range
struct interval_t
{
  int x0 = 0, x1 = 0; // x0 always <= x1, otherwise the interval is empty
  bool empty(void) const { return x0 < x1; }
  void intersect(const interval_t &r)
  {
    if ( x0 < r.x0 )
      x0 = r.x0;
    if ( x1 > r.x1 )
      x1 = r.x1;
  }
  void make_union(const interval_t &r)
  {
    if ( x0 > r.x0 )
      x0 = r.x0;
    if ( x1 < r.x1 )
      x1 = r.x1;
  }
  void move_by(int shift)
  {
    x0 += shift;
    x1 += shift;
  }
  interval_t() {}
  interval_t(int y0, int y1)
  {
    x0 = qmin(y0, y1);
    x1 = qmax(y0, y1);
  }
  interval_t(const edge_segment_t &s)
  {
    x0 = qmin(s.x0, s.x1);
    x1 = qmax(s.x0, s.x1);
  }
  int length(void) const { return x1 - x0; }
  bool contains(int x) const { return x0 <= x && x <= x1; }
  bool operator ==(const interval_t &r) const { return x0 == r.x0 && x1 == r.x1; }
  bool operator !=(const interval_t &r) const { return !(*this == r); }
};

//-------------------------------------------------------------------------
/// Organize graph nodes by row
struct row_info_t
{
  intvec_t nodes;  ///< list of nodes at the row
  int top = 0;     ///< top y coord of the row
  int bottom = 0;  ///< bottom y coord of the row

  int height(void) const { return bottom - top; }
};
typedef qvector<row_info_t> graph_row_info_t; ///< vector of row infos

static const int ygap = 30;
static const int xgap = 10;
static const int arrow_height = 10;
static const int arrow_width = 8;

struct graph_location_info_t;
class graph_visitor_t;

//-------------------------------------------------------------------------
/// Abstract graph interface
class abstract_graph_t : public gdl_graph_t
{
  void idaapi find_entries(node_set_t &entries) const;
  void idaapi depth_first(int root, struct depth_first_info_t &di) const;
  size_t idaapi remove_reachable(int n, node_set_t *s) const;
  int    idaapi longest_path(int n, intvec_t &tops, int row_height) const;
  size_t idaapi sort_layer_nodes(
        const row_info_t &r1,
        const intmap_t &lpi1,
        row_info_t &r2,
        intmap_t &lpi2,
        bool ispred) const;
  size_t idaapi calc_cross_num(
        const intvec_t &r1,
        const intvec_t &r2,
        const intmap_t &lpi1,
        bool ispred) const;
  size_t idaapi num_crossings(const graph_row_info_t &gri, const array_of_intmap_t &nodepi) const;
  int    idaapi calc_x_coord(const row_info_t &ri, int idx, bool ispred, int first_added_node) const;
  void   idaapi try_move_down(intvec_t &tops, int n, int row_height) const;

protected:
  /// Returns one entry point for each connected component
  void idaapi get_connected_components(intvec_t &entries) const;

  /// Find longest paths from the entries. take into account node heights.
  /// if row_height > 0, then use it instead of real node heights.
  /// return max distance found
  int idaapi calc_longest_pathes(
        const node_set_t &entries,
        intvec_t &tops,
        int row_height) const;

  /// Move entry nodes down as much as possible
  void idaapi move_nodes_down(
        intvec_t &tops,
        const node_ordering_t &post,
        int first_reverser_node,
        int row_height) const;

  /// Create graph row info from 'tops'
  void idaapi create_graph_row_info(
        const intvec_t &tops,
        graph_row_info_t &gri,
        int graph_height) const;

  /// Calculate height of each row
  void idaapi calc_row_heights(graph_row_info_t &gri) const;

  /// Minimize crossings
  void idaapi minimize_crossings(graph_row_info_t &gri) const;

  /// Calculate x coords of all nodes
  void idaapi set_x_coords(
        const graph_row_info_t &gri,
        const node_set_t &selfrefs,
        int first_added_node);

  /// Gather information about all edge segments
  void idaapi gather_edge_segments(
        const graph_row_info_t &gri,
        edge_segs_vec_t &ges) const;

  /// Make all edges rectangular
  void idaapi make_rect_edges(
        graph_row_info_t &gri,
        const edge_segs_vec_t &ges,
        int first_reverser_node);

  /// Assign ports to edges
  void idaapi assign_edge_ports(
        const graph_row_info_t &gri,
        const node_set_t &selfrefs);

  /// Recalculate width of all edges
  void idaapi recalc_edge_widths(
        const edgeset_t &back_edges,
        const edge_infos_t &self_edges);

  /// Clear layout information in the graph
  void idaapi clear_layout_info(void);

  void idaapi depth_first(
        node_ordering_t *pre,
        node_ordering_t *post,
        edge_typer_t *et) const;

  void idaapi create_spanning_tree(
        edge_typer_t *et,
        node_set_t *entries,
        edgeset_t *back_edges,
        node_ordering_t *pre,
        node_ordering_t *post) const;

  void idaapi tree_layout(edge_typer_t &et, const node_set_t &entries);

  /// Is there a path from M to N which terminates with a back edge to N?
  bool idaapi path_back(const array_of_node_set_t &domin, int m, int n) const;
  bool idaapi path_back(edge_typer_t &et, int m, int n) const;

  /// Visit nodes starting from 'node', depth first
  int idaapi visit_nodes(int node, graph_node_visitor_t &gv) const;

  /// Visit all possible paths starting from 'node'.
  /// A path cannot contain the same node twice.
  int idaapi visit_paths(int node, graph_path_visitor_t &gv) const;

public:
  qstring title;                        ///< graph title
  bool rect_edges_made;                 ///< have create rectangular edges?
  layout_type_t current_layout;         ///< see \ref layout_
  point_t circle_center;                ///< for layout_circle
  int circle_radius;                    ///< for layout_circle
  hook_cb_t *callback;                  ///< user-defined callback
  void *callback_ud;                    ///< user data for #callback

  idaapi abstract_graph_t(void)
    : rect_edges_made(false),
      current_layout(layout_none),
      circle_radius(0),
      callback(nullptr),
      callback_ud(nullptr)
  {}
  virtual ~abstract_graph_t() {}
  void idaapi clear(void);
  void idaapi dump_graph(const char *header) const;
  bool idaapi calc_bounds(rect_t *r);
  void idaapi calc_fitting_params(
        const rect_t &area,
        const rect_t &r,
        graph_location_info_t *gli,
        double max_zoom);
  bool idaapi calc_fitting_params(
        const rect_t &area,
        graph_location_info_t *gli,
        double max_zoom);
  int idaapi for_all_nodes_edges(graph_visitor_t &nev, bool visit_nodes=true);
  // get edge ports - fills s, d arguments and returns edge_info_t
  const edge_info_t *idaapi get_edge_ports(
        edge_t e,
        point_t &s,
        point_t &d) const;
  // add edges from/to the node
  void idaapi add_node_edges(edgevec_t &dlist, int node);
  const rect_t &idaapi nrect(int n) const
    { return (CONST_CAST(abstract_graph_t *)(this))->nrect(n); }
  const edge_info_t *idaapi get_edge(edge_t e) const
    { return (CONST_CAST(abstract_graph_t *)(this))->get_edge(e); }
  virtual rect_t &idaapi nrect(int n) = 0;
  virtual edge_info_t *idaapi get_edge(edge_t e) = 0;
  virtual abstract_graph_t *idaapi clone(void) const = 0;

  bool idaapi create_tree_layout(void);
  bool idaapi create_circle_layout(point_t p, int radius);
  bool idaapi create_polar_tree_layout(point_t p, int radius);
  bool idaapi create_radial_tree_layout(point_t p, int radius);
  bool idaapi create_orthogonal_layout(void);

  void set_callback(hook_cb_t *_callback, void *_ud)
  {
    callback = _callback;
    callback_ud = _ud;
  }
  ssize_t vgrcall(int code, va_list va)
  {
    if ( callback != nullptr )
      return callback(callback_ud, code, va);
    return 0;
  }
  ssize_t grcall(int code, ...)
  {
    va_list va;
    va_start(va, code);
    ssize_t result = vgrcall(code, va);
    va_end(va);
    return result;
  }
};

/// For some reason GCC insists on putting the vtable into object files,
/// even though we only use ::mutable_graph_t by pointer.
/// This looks like a linker bug. We fix it by declaring functions as pure virtual
/// when plugins are compiled.
#if defined(__GNUC__) && (defined(__KERNEL__) || !defined(__UI__))  // compiling a plugin or the kernel with gcc?
#define GCC_PUREVIRT = 0
#else
#define GCC_PUREVIRT
#endif

//-------------------------------------------------------------------------
struct edge_infos_wrapper_t
{
  edge_infos_wrapper_t();
  edge_infos_wrapper_t(const edge_infos_wrapper_t &other);
  edge_infos_wrapper_t &idaapi operator=(const edge_infos_wrapper_t &other);
  ~edge_infos_wrapper_t() { clear(); }
  void clear();

  edge_infos_t *ptr;
};

#ifdef _DEBUG
#define CHKNODEIDX(n) QASSERT(1385, int(n) >= 0)
#else
#define CHKNODEIDX(n)
#endif

/// The base class used to display graphs in IDA.
///
/// The mutable_graph_t introduces the following notions on top of
/// the ones that parent classes already provide:
///  * ability to add/remove nodes
///  * ability to add/remove edges
///  * grouping/ungrouping nodes
///  * expanding/collapsing existing groups
///
/// While the adding/removing of nodes & edges is, in itself, a fairly
/// straightforward notion, 'groups' can be a bit more tricky to
/// figure out.
///
/// For the purpose of illustrating what 'groups' are, and how they
/// are handled, let's assume that we are analyzing a binary that
/// contains multiple bits of connected information scattered all over
/// the place in a read-only '.rodata' segment.
///
/// In order to simplify analysis that scattered-but-connected data,
/// the user might choose to write a small plugin that represents the
/// data in a graph form:
///
/// +-----------------------------+
/// | Driver object #1            |
/// | address: 0x400100           |
/// | size: 0x200 bytes           |
/// +-------------+---------------+
///               |
///               +------------------------+
///                                        |
///                            +-----------+-----------------+
///                            | Driver object #2            |
///                            | address: 0x407380           |
///                            | size: 0x180 bytes           |
///                            | (seems to maintain state of |
///                            |  the I/O ports)             |
///                            +----+-------+----------------+
///                                 |       |
///                 +---------------+       +----------------+
///                 |                                        |
///   +-------------+-----------+                    +-------+-------------+
///   | Unknown object #1       |                    | Driver object #3    |
///   | address: 0x404100       |                    | address: 0x402000   |
///   | size: 0x80 bytes        |                    | size: 4KB           |
///   | (credentials?)          |                    | (mostly mutexes)    |
///   +-------------------------+                    +---------------------+
///
/// In this case, the graph has 4 nodes, each showing some information
/// that is relevant to the analyst.
/// In order to implement this, the plugin must keep, somewhere in
/// memory, the relevant information about the nodes. In this case, it
/// would have a set of 4 items, from which the nodes texts can be
/// generated and provided back to IDA's UI.
///
/// If one was to call the following methods on the mutable_graph_t
/// instance that is being displayed by IDA, one would get:
///
///   mutable_graph_t::size() -> 4
///   mutable_graph_t::node_qty() -> 4
///
/// Let's now assume the user decides the 2 first nodes are not
/// that interesting after all, and groups them together, in a node
/// labeled "irrelevant".
///
/// Then, IDA will modify the mutable_graph_t by adding it a 5th node,
/// which represents that group
/// It's worth pointing out that, it's the mutable_graph_t itself
/// that's doing all the bookkeeping about the groups: the user plugin
/// doesn't need to do anything at all
///
/// In addition, calling the methods above now yields:
//
///   mutable_graph_t::size() -> 5
///   mutable_graph_t::node_qty() -> 3
///
class mutable_graph_t : public abstract_graph_t
{
  typedef abstract_graph_t inherited;
  friend ssize_t idaapi graph_dispatcher(void *, int code, va_list va);
  int idaapi _find_subgraph_node(int group, int n) const;
  void idaapi collapse_edges(const intvec_t &nodes, int group);
  void idaapi del_node_keep_edges(int n);
  void idaapi add_dest(destset_t &ne, edge_t e, int g);
  void idaapi reverse_edges(
        const edgeset_t &back_edges,
        edge_infos_t &self_edges,
        node_set_t &entries);
  void idaapi layout_self_reference_edges(const edge_infos_t &selfrefs);
  void idaapi restore_edges(int first_reserver_node, bool failed);

  void idaapi add_layer_nodes(graph_row_info_t &gri, intvec_t &tops);
  void idaapi del_layer_nodes(graph_row_info_t &gri, int first_added_node);
  void idaapi fix_collapsed_group_edges(void);

public:
  uval_t gid;                         ///< graph id - unique for the database
                                      ///< for flowcharts it is equal to the function start_ea
  intvec_t belongs;                   ///< the subgraph the node belongs to
                                      ///< INT_MAX means that the node doesn't exist
                                      ///< sign bit means collapsed node
  bytevec_t node_flags;               ///< node flags
#define MTG_GROUP_NODE           0x01 ///< is group node?
#define MTG_DOT_NODE             0x02 ///< is dot node?
#define MTG_NON_DISPLAYABLE_NODE 0x08 ///< for disassembly graphs - non-displayable nodes have a visible
                                      ///< area that is too large to generate disassembly lines for without
                                      ///< IDA slowing down significantly (see MAX_VISIBLE_NODE_AREA)

  // groups: original edges without considering any group info
  array_of_intvec_t org_succs;
  array_of_intvec_t org_preds;

  array_of_intvec_t succs;
  array_of_intvec_t preds;
  typedef qvector<rect_t> node_layout_t;
  node_layout_t nodes;
  edge_infos_wrapper_t edges;

  idaapi mutable_graph_t(uval_t id);
  idaapi mutable_graph_t(const abstract_graph_t &g, uval_t id);
  virtual ~mutable_graph_t() {}

  /// Get the total number of nodes (including group nodes, and
  /// including hidden nodes.)
  ///
  /// See also node_qty()
  ///
  /// \return the total number of nodes in the graph
  virtual int  idaapi size(void) const override { return int(succs.size()); }

  /// Get the number of visible nodes (the list can be retrieved using
  /// gdl.hpp's node_iterator)
  ///
  /// See also size()
  ///
  /// \return the number of visible nodes
  virtual int  idaapi node_qty(void) const override;

  /// Clears all nodes & edges information in this instance
  /// (does not remove node_info_t stored in the database.)
  void idaapi clear(void);

  /// Is the graph (visually) empty?
  /// \return true if there are no visible nodes
  virtual bool idaapi empty(void) const override;

  /// Is the node visible?
  ///
  /// \param node the node number
  /// \return success
  virtual bool idaapi exists(int node) const override { return is_visible_node(node); }
#define COLLAPSED_NODE 0x80000000

  /// Get the node that currently visually represents 'node'.
  /// This will find the "closest" parent group node that's visible,
  /// by attempting to walk up the group nodes that contain
  /// 'node', and will stop when it finds a node that is currently
  /// visible.
  ///
  /// See also get_group_node()
  //
  /// \param node the node
  /// \return the node that represents 'node', or 'node' if it's not
  /// part of any group
  int  idaapi get_node_representative(int node);

  int  idaapi get_node_group(int node) const { CHKNODEIDX(node); return (belongs[node] & ~COLLAPSED_NODE); }
  void idaapi set_node_group(int node, int group) { CHKNODEIDX(node); belongs[node] = group | (belongs[node] & COLLAPSED_NODE); }
  bool idaapi is_deleted_node(int node) const { CHKNODEIDX(node); return belongs[node] == INT_MAX; }
  void idaapi set_deleted_node(int node) { CHKNODEIDX(node); belongs[node] = INT_MAX; }
  bool idaapi is_subgraph_node(int node) const { return get_node_group(node) != node; }
  bool idaapi is_dot_node(int node) const { CHKNODEIDX(node); return (node_flags[node] & MTG_DOT_NODE) != 0; }
  bool idaapi is_group_node(int node) const { CHKNODEIDX(node); return (node_flags[node] & MTG_GROUP_NODE) != 0; }
  bool idaapi is_displayable_node(int node) const { CHKNODEIDX(node); return (node_flags[node] & MTG_NON_DISPLAYABLE_NODE) == 0; }
  bool idaapi is_simple_node(int node) const { return !is_group_node(node); }
  bool idaapi is_collapsed_node(int node) const { CHKNODEIDX(node); return (belongs[node] & COLLAPSED_NODE) != 0; }
  bool idaapi is_uncollapsed_node(int node) const { return is_group_node(node) && !is_collapsed_node(node); }

  /// Is the node currently visible?
  ///
  /// An invisible node is a node that's part of a group that's
  /// currently collapsed.
  ///
  /// \param node the node
  /// \return success
  bool idaapi is_visible_node(int node) const;

  /// Is there any group node in the graph?
  ///
  /// \return success
  bool idaapi groups_are_present(void) const;

  // iterate subgraph nodes, return -1 at the end
  int  idaapi get_first_subgraph_node(int group) const { return _find_subgraph_node(group, 0); }
  int  idaapi get_next_subgraph_node(int group, int current) const { return _find_subgraph_node(group, current+1); }
  void idaapi insert_visible_nodes(intvec_t &nodes, int group) const;
  void idaapi insert_simple_nodes(intvec_t &nodes, int group) const;
  bool idaapi check_new_group(const intvec_t &nodes, intvec_t &refined);

  /// Create a new group node, that will contain all the nodes in
  /// 'nodes'.
  ///
  /// \param nodes the nodes that will be part of the group
  /// \return the group node, or -1 in case of error
  int  idaapi create_group(const intvec_t &nodes);

  /// Delete a group node.
  ///
  /// This deletes the group node only; it does not delete nodes that
  /// are part of the group.
  ///
  /// \param group the group node
  /// \return success
  bool idaapi delete_group(int group);

  /// Expand/collapse a group node
  ///
  /// \param group the group node
  /// \param expand whether to expand or collapse
  /// \return success
  bool idaapi change_group_visibility(int group, bool expand);

  /// Change visibility of multiple group nodes
  ///
  /// \param nodes the group nodes
  /// \param expand whether to expand or collapse
  /// \return success (true if any group node was modified)
  bool idaapi change_visibility(const intvec_t &nodes, bool expand);

  virtual int  idaapi nsucc(int b) const override { CHKNODEIDX(b); return (int)succs[b].size(); }
  virtual int  idaapi npred(int b) const override { CHKNODEIDX(b); return (int)preds[b].size(); }
  virtual int  idaapi succ(int b, int i) const override { CHKNODEIDX(b); return succs[b][i]; }
  virtual int  idaapi pred(int b, int i) const override { CHKNODEIDX(b); return preds[b][i]; }
  const intvec_t &idaapi succset(int b) const { CHKNODEIDX(b); return succs[b]; }
  const intvec_t &idaapi predset(int b) const { CHKNODEIDX(b); return preds[b]; }

  void idaapi reset(void) { resize(0); }

  /// Recompute the layout, according to the value of
  /// 'current_layout'.
  ///
  /// \return success
  virtual bool idaapi redo_layout(void) GCC_PUREVIRT;

  /// Resize the graph to 'n' nodes
  ///
  /// \param n the new size
  virtual void idaapi resize(int n) GCC_PUREVIRT;

  /// Add a node, possibly with a specific geometry
  ///
  /// \param r the node geometry (can be nullptr)
  /// \return the new node
  virtual int  idaapi add_node(const rect_t *r) GCC_PUREVIRT;

  /// Delete a node
  ///
  /// \param n the node to delete
  /// \return the number of deleted edges
  virtual ssize_t idaapi del_node(int n) GCC_PUREVIRT;  // returns number of deleted edges

  virtual bool idaapi add_edge(int i, int j, const edge_info_t *ei) GCC_PUREVIRT;
  virtual bool idaapi del_edge(int i, int j) GCC_PUREVIRT;  // true: found and deleted the edge
  virtual bool idaapi replace_edge(int i, int j, int x, int y) GCC_PUREVIRT;

  /// Refresh the graph
  ///
  /// A graph needs refreshing when it's "backing data". E.g., if the
  /// number (or contents) of the objects in the above example,
  /// change.
  ///
  /// Let's say the user's plugin ends up finding a 5th piece of
  /// scattered data. It should then add it to its internal list
  /// of known objects, and tell IDA that the graph needs to be
  /// refreshed, using refresh_viewer().
  /// This will cause IDA to:
  ///   - discard all its internal rendering information,
  ///   - call mutable_graph_t::refresh() on the graph so that the
  ///     user's plugin has a chance to "sync" the number of nodes &
  ///     edges that this graph contains, to the information that the
  ///     plugin has collected so far
  ///   - re-create internal rendering information, and
  ///   - repaint the view
  ///
  /// \return success
  virtual bool idaapi refresh(void) GCC_PUREVIRT;

  virtual mutable_graph_t *idaapi clone(void) const override GCC_PUREVIRT;

  // get node rectangle
  const rect_t &idaapi nrect(int n) const
    { return (CONST_CAST(mutable_graph_t *)(this))->nrect(n); }
  virtual rect_t &idaapi nrect(int n) override;
  virtual edge_info_t *idaapi get_edge(edge_t e) override GCC_PUREVIRT;

  virtual bool idaapi set_nrect(int n, const rect_t &r) GCC_PUREVIRT;
  virtual bool idaapi set_edge(edge_t e, const edge_info_t *ei) GCC_PUREVIRT;

  bool idaapi create_digraph_layout(void);

  void idaapi del_custom_layout(void);
  bool idaapi get_custom_layout(void);
  void idaapi set_custom_layout(void) const;
  bool idaapi get_graph_groups(void);
  void idaapi set_graph_groups(void) const;
  virtual ea_t idaapi calc_group_ea(const intvec_t & /*nodes*/) newapi { return BADADDR; }

  point_t idaapi calc_center_of(const intvec_t &nodes) const;
  void idaapi move_to_same_place(const intvec_t &collapsing_nodes, point_t p);
  void idaapi move_grouped_nodes(const intvec_t &groups, const mutable_graph_t *ng);

  virtual bool idaapi is_user_graph() newapi { return false; }
};

//-------------------------------------------------------------------------
/// Visit all nodes and edges in a graph
class graph_visitor_t
{
protected:
  abstract_graph_t *g;
  virtual int idaapi visit_node(int n, rect_t &r) = 0;
  virtual int idaapi visit_edge(edge_t e, edge_info_t *ei) = 0;
  friend int idaapi abstract_graph_t::for_all_nodes_edges(graph_visitor_t &nev, bool visit_nodes);
};

//-------------------------------------------------------------------------
/// Graph notification codes
enum graph_notification_t
{
  // Callbacks called by IDA (plugins can hook to them):

  grcode_calculating_layout,  ///< calculating user-defined graph layout.
                              ///< \param g  (::mutable_graph_t *)
                              ///< \retval 0  not implemented
                              ///< \retval 1  graph layout calculated by the plugin

  grcode_layout_calculated,   ///< graph layout calculated.
                              ///< \param g                 (::mutable_graph_t *)
                              ///< \param layout_succeeded  (bool)
                              ///< \retval 0  must return 0

  grcode_changed_graph,       ///< new graph has been set.
                              ///< \param g  (::mutable_graph_t *)
                              ///< \retval 0  must return 0

  grcode_reserved,

  grcode_clicked,             ///< graph is being clicked.
                              ///< this callback allows you to ignore some clicks.
                              ///< it occurs too early, internal graph variables are not updated yet.
                              ///< current_item1, current_item2 point to the same thing.
                              ///< item2 has more information.
                              ///< see also: ::custom_viewer_click_t
                              ///< \param gv             (::graph_viewer_t *)
                              ///< \param current_item1  (::selection_item_t *)
                              ///< \param current_item2  (::graph_item_t *)
                              ///< \retval 0  ok
                              ///< \retval 1  ignore click

  grcode_dblclicked,          ///< a graph node has been double clicked.
                              ///< \param gv            (::graph_viewer_t *)
                              ///< \param current_item  (::selection_item_t *)
                              ///< \retval 0  ok
                              ///< \retval 1  ignore click

  grcode_creating_group,      ///< a group is being created.
                              ///< this provides an opportunity for the
                              ///< graph to forbid creation of the group.
                              ///< Note that groups management is done by the
                              ///< mutable_graph_t instance itself: there is
                              ///< no need to modify the graph in this callback.
                              ///< \param g      (::mutable_graph_t *)
                              ///< \param nodes  (::intvec_t *)
                              ///< \retval 0  ok
                              ///< \retval 1  forbid group creation

  grcode_deleting_group,      ///< a group is being deleted.
                              ///< this provides an opportunity for the
                              ///< graph to forbid deletion of the group.
                              ///< Note that groups management is done by the
                              ///< mutable_graph_t instance itself: there is
                              ///< no need to modify the graph in this callback.
                              ///< \param g          (::mutable_graph_t *)
                              ///< \param old_group  (int)
                              ///< \retval 0  ok
                              ///< \retval 1  forbid group deletion

  grcode_group_visibility,    ///< a group is being collapsed/uncollapsed
                              ///< this provides an opportunity for the graph
                              ///< to forbid changing the visibility of the group.
                              ///< Note that groups management is done by the
                              ///< mutable_graph_t instance itself: there is
                              ///< no need to modify the graph in this callback.
                              ///< \param g       (::mutable_graph_t *)
                              ///< \param group   (int)
                              ///< \param expand  (bool)
                              ///< \retval 0  ok
                              ///< \retval 1  forbid group modification

  grcode_gotfocus,            ///< a graph viewer got focus.
                              ///< \param gv  (::graph_viewer_t *)
                              ///< \retval 0  must return 0

  grcode_lostfocus,           ///< a graph viewer lost focus.
                              ///< \param gv  (::graph_viewer_t *)
                              ///< \retval 0  must return 0

  grcode_user_refresh,        ///< refresh user-defined graph nodes and edges
                              ///< This is called when the UI considers that it is
                              ///< necessary to recreate the graph layout, and thus
                              ///< has to ensure that the 'mutable_graph_t' instance
                              ///< it is using, is up-to-date.
                              ///< For example:
                              ///<   - at graph creation-time
                              ///<   - if a refresh_viewer() call was made
                              ///< \param g  (::mutable_graph_t *)
                              ///< \return success

  grcode_reserved2,

  grcode_user_text,           ///< retrieve text for user-defined graph node.
                              ///< NB: do not use anything calling GDI!
                              ///< \param g         (::mutable_graph_t *)
                              ///< \param node      (int)
                              ///< \param result    (const char **)
                              ///< \param bg_color  (::bgcolor_t *) may be nullptr
                              ///< \return success, result must be filled

  grcode_user_size,           ///< calculate node size for user-defined graph.
                              ///< \param g     (::mutable_graph_t *)
                              ///< \param node  (int)
                              ///< \param cx    (int *)
                              ///< \param cy    (int *)
                              ///< \retval 0  did not calculate. ida will use node text size
                              ///< \retval 1  calculated. ida will add node title to the size

  grcode_user_title,          ///< render node title of a user-defined graph.
                              ///< \param g               (::mutable_graph_t *)
                              ///< \param node            (int)
                              ///< \param title_rect      (::rect_t *)
                              ///< \param title_bg_color  (int)
                              ///< \param dc              (HDC)
                              ///< \retval 0  did not render, ida will fill it with title_bg_color
                              ///< \retval 1  rendered node title

  grcode_user_draw,           ///< render node of a user-defined graph.
                              ///< NB: draw only on the specified DC and nowhere else!
                              ///< \param g          (::mutable_graph_t *)
                              ///< \param node       (int)
                              ///< \param node_rect  (::rect_t *)
                              ///< \param dc         (HDC)
                              ///< \retval 0  not rendered
                              ///< \retval 1  rendered

  grcode_user_hint,           ///< retrieve hint for the user-defined graph.
                              ///< \param g              (::mutable_graph_t *)
                              ///< \param mousenode      (int)
                              ///< \param mouseedge_src  (int)
                              ///< \param mouseedge_dst  (int)
                              ///< \param hint           (char **) must be allocated by qalloc() or qstrdup()
                              ///< \retval 0  use default hint
                              ///< \retval 1  use proposed hint

  grcode_destroyed,           ///< graph is being destroyed. Note that this doesn't mean
                              ///< the graph viewer is being destroyed; this only means
                              ///< that the graph that is being displayed by it is being
                              ///< destroyed, and that, e.g., any possibly cached data should
                              ///< be invalidated (this event can happen when, for example,
                              ///< the user decides to group nodes together: that operation
                              ///< will effectively create a new graph, that will replace
                              ///< the old one.)
                              ///< To be notified when the graph viewer itself is being destroyed,
                              ///< please see notification 'view_close', in kernwin.hpp
                              ///< \param g   (::mutable_graph_t *)
                              ///< \retval 0  must return 0

  //-------------------------------------------------------------------------
  // Callbacks callable from plugins (see inline functions below):
  //-------------------------------------------------------------------------

  // graph_viewer_t (or IDA View graph) manipulation.
  grcode_create_graph_viewer = 256,   ///< use create_graph_viewer()
  grcode_get_graph_viewer,            ///< use get_graph_viewer()
  grcode_get_viewer_graph,            ///< use get_viewer_graph()
  grcode_create_mutable_graph,        ///< use create_mutable_graph()
  grcode_set_viewer_graph,            ///< use set_viewer_graph()
  grcode_refresh_viewer,              ///< use refresh_viewer()
  grcode_fit_window,                  ///< use viewer_fit_window()
  grcode_get_curnode,                 ///< use viewer_get_curnode()
  grcode_center_on,                   ///< use viewer_center_on()
  grcode_get_selection,               ///< use viewer_get_selection()

  // mutable_graph_t (and abstract_graph_t) manipulation.
  grcode_del_custom_layout,           ///< use mutable_graph_t::del_custom_layout()
  grcode_set_custom_layout,           ///< use mutable_graph_t::set_custom_layout()
  grcode_set_graph_groups,            ///< use mutable_graph_t::set_graph_groups()
  grcode_clear,                       ///< use mutable_graph_t::clear()
  grcode_create_digraph_layout,       ///< use mutable_graph_t::create_digraph_layout()
  grcode_create_tree_layout,          ///< use abstract_graph_t::create_tree_layout()
  grcode_create_circle_layout,        ///< use abstract_graph_t::create_circle_layout()
  grcode_get_node_representative,     ///< use mutable_graph_t::get_node_representative()
  grcode_find_subgraph_node,          ///< use mutable_graph_t::_find_subgraph_node()
  grcode_create_group,                ///< use mutable_graph_t::create_group()
  grcode_get_custom_layout,           ///< use mutable_graph_t::get_custom_layout()
  grcode_get_graph_groups,            ///< use mutable_graph_t::get_graph_groups()
  grcode_empty,                       ///< use mutable_graph_t::empty()
  grcode_is_visible_node,             ///< use mutable_graph_t::is_visible_node()
  grcode_delete_group,                ///< use mutable_graph_t::delete_group()
  grcode_change_group_visibility,     ///< use mutable_graph_t::change_group_visibility()
  grcode_set_edge,                    ///< use mutable_graph_t::set_edge()
  grcode_node_qty,                    ///< use mutable_graph_t::node_qty()
  grcode_nrect,                       ///< use mutable_graph_t::nrect()

  // More graph_viewer_t manipulation.
  grcode_set_titlebar_height,         ///< use viewer_set_titlebar_height()
  grcode_create_user_graph_place,     ///< use create_user_graph_place()
  grcode_create_disasm_graph1,        ///< use create_disasm_graph(ea_t ea)
  grcode_create_disasm_graph2,        ///< use create_disasm_graph(const rangevec_t &ranges)
  grcode_set_node_info,               ///< use viewer_set_node_info()
  grcode_get_node_info,               ///< use viewer_get_node_info()
  grcode_del_node_info,               ///< use viewer_del_node_info()

  // Deprecated. Those were meant to work with intset_t, that we now got rid of.
  grcode_viewer_create_groups,
  grcode_viewer_delete_groups,
  grcode_viewer_groups_visibility,

  //
  grcode_viewer_create_groups_vec,    ///< use viewer_create_groups()
  grcode_viewer_delete_groups_vec,    ///< use viewer_delete_groups()
  grcode_viewer_groups_visibility_vec,///< use viewer_set_groups_visibility()
  grcode_delete_mutable_graph,        ///< use delete_mutable_graph()
  grcode_edge_infos_wrapper_copy,     ///< use edge_infos_wrapper_t::operator=()
  grcode_edge_infos_wrapper_clear,    ///< use edge_infos_wrapper_t::clear()

  //
  grcode_attach_menu_item,

  //
  grcode_set_gli,                     ///< use viewer_set_gli()
  grcode_get_gli,                     ///< use viewer_get_gli()
};


//-------------------------------------------------------------------------
#ifndef SWIG
/// \name grentry
/// IDA designates a function for handling graph operations (::grentry).
/// This function accepts a notification code (::graph_notification_t),
/// along with a list of relevant arguments, and handles the action appropriately
/// (similar to ::callui in kernwin.hpp).
//@{


inline ssize_t grentry(graph_notification_t event_code, ...)
{
  va_list va;
  va_start(va, event_code);
  ssize_t code = invoke_callbacks(HT_GRAPH, event_code, va);
  va_end(va);
  return code;
}
//@}
#endif


//-------------------------------------------------------------------------
struct group_crinfo_t
{
  intvec_t nodes;
  qstring text;
};
typedef qvector<group_crinfo_t> groups_crinfos_t;

#ifndef __UI__

typedef TWidget graph_viewer_t; ///< graph view opaque structure


/// Create a custom graph viewer.
/// \param title         the widget title
/// \param id            graph id
/// \param callback      callback to handle graph notifications
///                      (::graph_notification_t)
/// \param ud            user data passed to callback
/// \param title_height  node title height
/// \param parent        the parent widget of the graph viewer
/// \return new viewer

inline graph_viewer_t *idaapi create_graph_viewer(
        const char *title,
        uval_t id,
        hook_cb_t *callback,
        void *ud,
        int title_height,
        TWidget *parent=nullptr)
{
  graph_viewer_t *gv = nullptr;
  grentry(grcode_create_graph_viewer, title, &gv, id, callback, ud, title_height, parent);
  return gv;
}


/// Get custom graph viewer for given form

inline graph_viewer_t *idaapi get_graph_viewer(TWidget *parent)              { graph_viewer_t *gv = nullptr; grentry(grcode_get_graph_viewer, parent, &gv); return gv; }


/// Create a new empty graph with given id

inline mutable_graph_t *idaapi create_mutable_graph(uval_t id)               { mutable_graph_t *g = nullptr; grentry(grcode_create_mutable_graph, id, &g); return g; }


/// Create a graph for the function that contains 'ea'

inline mutable_graph_t *idaapi create_disasm_graph(ea_t ea)                  { mutable_graph_t *g = nullptr; grentry(grcode_create_disasm_graph1, ea, &g); return g; }


/// Create a graph using an arbitrary set of ranges

inline mutable_graph_t *idaapi create_disasm_graph(const rangevec_t &ranges) { mutable_graph_t *g = nullptr; grentry(grcode_create_disasm_graph2, &ranges, &g); return g; }


/// Get graph object for given custom graph viewer

inline mutable_graph_t *idaapi get_viewer_graph(graph_viewer_t *gv)          { mutable_graph_t *g = nullptr; grentry(grcode_get_viewer_graph, gv, &g); return g; }


/// Set the underlying graph object for the given viewer

inline void idaapi set_viewer_graph(graph_viewer_t *gv, mutable_graph_t *g)  {        grentry(grcode_set_viewer_graph, gv, g); }


/// Redraw the graph in the given view

inline void idaapi refresh_viewer(graph_viewer_t *gv)                        {        grentry(grcode_refresh_viewer, gv); }


/// Fit graph viewer to its parent form

inline void idaapi viewer_fit_window(graph_viewer_t *gv)                     {        grentry(grcode_fit_window, gv); }


/// Get number of currently selected node (-1 if none)

inline int  idaapi viewer_get_curnode(graph_viewer_t *gv)                    { return grentry(grcode_get_curnode, gv); }


/// Center the graph view on the given node

inline void idaapi viewer_center_on(graph_viewer_t *gv, int node)            {        grentry(grcode_center_on, gv, node); }

/// Set location info for given graph view
/// If flags contains GLICTL_CENTER, then the gli will be set to be
/// the center of the view. Otherwise it will be the top-left.

inline void idaapi viewer_set_gli(
        graph_viewer_t *gv,
        const graph_location_info_t *gli,
        uint32 flags = 0)
{
  grentry(grcode_set_gli, gv, gli, flags);
}


/// Get location info for given graph view
/// If flags contains GLICTL_CENTER, then the gli that will be retrieved, will
/// be the one at the center of the view. Otherwise it will be the top-left.

inline bool idaapi viewer_get_gli(
        graph_location_info_t *out,
        graph_viewer_t *gv,
        uint32 flags = 0)
{
  return grentry(grcode_get_gli, out, gv, flags) == 0;
}


/// Set node info for node in given viewer (see set_node_info())

inline void idaapi viewer_set_node_info(
        graph_viewer_t *gv,
        int n,
        const node_info_t &ni,
        uint32 flags)
{
  grentry(grcode_set_node_info, gv, n, &ni, flags);
}


/// Get node info for node in given viewer (see get_node_info())

inline bool idaapi viewer_get_node_info(
        graph_viewer_t *gv,
        node_info_t *out,
        int n)
{
  return grentry(grcode_get_node_info, gv, out, n) == 1;
}


/// Delete node info for node in given viewer (see del_node_info())

inline void idaapi viewer_del_node_info(graph_viewer_t *gv, int n)
{
  grentry(grcode_del_node_info, gv, n);
}


/// This will perform an operation similar to what happens when
/// a user manually selects a set of nodes, right-clicks and selects
/// "Create group". This is a wrapper around mutable_graph_t::create_group
/// that will, in essence:
///  - clone the current graph
///  - for each group_crinfo_t, attempt creating group in that new graph
///  - if all were successful, animate to that new graph.
/// \note this accepts parameters that allow creating
/// of multiple groups at once; which means only one graph
/// animation will be triggered.

inline bool idaapi viewer_create_groups(
        graph_viewer_t *gv,
        intvec_t *out_group_nodes,
        const groups_crinfos_t &gi)
{
  return grentry(grcode_viewer_create_groups_vec, gv, out_group_nodes, &gi) == 1;
}


/// Wrapper around mutable_graph_t::delete_group.
/// This function will:
///  - clone the current graph
///  - attempt deleting the groups in that new graph
///  - if successful, animate to that new graph.

inline bool idaapi viewer_delete_groups(
        graph_viewer_t *gv,
        const intvec_t &groups,
        int new_current = -1)
{
  return grentry(grcode_viewer_delete_groups_vec, gv, &groups, new_current) == 1;
}


/// Wrapper around mutable_graph_t::change_visibility.
/// This function will:
///  - clone the current graph
///  - attempt changing visibility of the groups in that new graph
///  - if successful, animate to that new graph.

inline bool idaapi viewer_set_groups_visibility(
        graph_viewer_t *gv,
        const intvec_t &groups,
        bool expand,
        int new_current = -1)
{
  return grentry(grcode_viewer_groups_visibility_vec, gv, &groups,
                 expand, new_current) == 1;
}


/// Attach a previously-registered action to the view's context menu.
/// See kernwin.hpp for how to register actions.
/// \param g     graph viewer
/// \param name  action name
/// \return success

inline bool idaapi viewer_attach_menu_item(graph_viewer_t *g, const char *name)
{
  return grentry(grcode_attach_menu_item, g, name) != 0;
}


/// Get currently selected items for graph viewer

inline bool idaapi viewer_get_selection(
        graph_viewer_t *gv,
        screen_graph_selection_t *sgs)
{
  return grentry(grcode_get_selection, gv, sgs) != 0;
}


/// Set height of node title bars (::grcode_set_titlebar_height)

inline int idaapi viewer_set_titlebar_height(graph_viewer_t *gv, int height)
{
  return grentry(grcode_set_titlebar_height, gv, height);
}


/// Delete graph object.
/// \warning use this only if you are dealing with ::mutable_graph_t instances
/// that have not been used together with a ::graph_viewer_t.
/// If you have called set_viewer_graph() with your graph, the graph's
/// lifecycle will be managed by the viewer, and you shouldn't
/// interfere with it

inline void idaapi delete_mutable_graph(mutable_graph_t *g)
{
  grentry(grcode_delete_mutable_graph, g);
}


inline void idaapi mutable_graph_t::del_custom_layout(void)                   {        grentry(grcode_del_custom_layout, this); }
inline void idaapi mutable_graph_t::set_custom_layout(void) const             {        grentry(grcode_set_custom_layout, this); }
inline void idaapi mutable_graph_t::set_graph_groups(void) const              {        grentry(grcode_set_graph_groups, this); }
inline void idaapi mutable_graph_t::clear(void)                               {        grentry(grcode_clear, this); }
inline bool idaapi mutable_graph_t::create_digraph_layout(void)               { return grentry(grcode_create_digraph_layout, this) != 0; }
inline bool idaapi abstract_graph_t::create_tree_layout(void)                 { return grentry(grcode_create_tree_layout, this) != 0; }
inline bool idaapi abstract_graph_t::create_circle_layout(point_t c, int radius) { return grentry(grcode_create_circle_layout, this, c.x, c.y, radius) != 0; }
inline int  idaapi mutable_graph_t::get_node_representative(int node)         { return grentry(grcode_get_node_representative, this, node); }
inline int  idaapi mutable_graph_t::_find_subgraph_node(int gr, int n) const  { return grentry(grcode_find_subgraph_node, this, gr, n); }
inline int  idaapi mutable_graph_t::create_group(const intvec_t &_nodes)      { return grentry(grcode_create_group, this, &_nodes); }
inline bool idaapi mutable_graph_t::get_custom_layout(void)                   { return grentry(grcode_get_custom_layout, this) != 0; }
inline bool idaapi mutable_graph_t::get_graph_groups(void)                    { return grentry(grcode_get_graph_groups, this) != 0; }
inline bool idaapi mutable_graph_t::empty(void) const                         { return grentry(grcode_empty, this) != 0; }
inline bool idaapi mutable_graph_t::is_visible_node(int node) const           { return grentry(grcode_is_visible_node, this, node) != 0; }
inline bool idaapi mutable_graph_t::delete_group(int group)                   { return grentry(grcode_delete_group, this, group) != 0; }
inline bool idaapi mutable_graph_t::change_group_visibility(int gr, bool exp) { return grentry(grcode_change_group_visibility, this, gr, exp) != 0; }
inline bool idaapi mutable_graph_t::set_edge(edge_t e, const edge_info_t *ei) { return grentry(grcode_set_edge, this, e.src, e.dst, ei) != 0; }
inline int  idaapi mutable_graph_t::node_qty(void) const                      { return grentry(grcode_node_qty, this); }
inline rect_t &idaapi mutable_graph_t::nrect(int n)                           { rect_t *r; grentry(grcode_nrect, this, n, &r); return *r; }

inline edge_infos_wrapper_t &idaapi edge_infos_wrapper_t::operator=(
        const edge_infos_wrapper_t &other)
{
  grentry(grcode_edge_infos_wrapper_copy, this, &other); return *this;
}

inline void edge_infos_wrapper_t::clear()
{
  grentry(grcode_edge_infos_wrapper_clear, this);
}


/// Structure returned by get_custom_viewer_place() if the first
/// parameter is a graph viewer.
struct user_graph_place_t : public place_t
{
  int node;
};


/// Get a copy of a ::user_graph_place_t (returns a pointer to static storage)

inline user_graph_place_t *create_user_graph_place(int node, int lnnum)      { user_graph_place_t *r; grentry(grcode_create_user_graph_place, node, lnnum, &r); return r; }

#endif  // UI

#endif // __GRAPH_DEF_HPP
