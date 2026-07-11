/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _RANGE_HPP
#define _RANGE_HPP

/*! \file range.hpp

   \brief Contains the definition of ::range_t.

   A range is a non-empty continuous range of addresses (specified by
   its start and end addresses, the end address is excluded from the
   range).

   Ranges are stored in the Btree part of the IDA database.
   To learn more about Btrees (Balanced Trees):
    http://www.bluerwhite.org/btree/
*/

#ifndef SWIG
struct range_t;
/// Helper function. Should not be called directly!
idaman size_t ida_export range_t_print(const range_t *, char *buf, size_t bufsize);
#endif

//--------------------------------------------------------------------------
/// Base class for an range. This class is used as a base class for
/// a class with real information - see segment.hpp for example.
/// The end address points beyond the range.
struct range_t
{
  friend size_t ida_export range_t_print(const range_t *cb, char *buf, size_t bufsize);
  ea_t start_ea;     ///< start_ea included
  ea_t end_ea;       ///< end_ea excluded
  /// Constructor
  range_t(void) : start_ea(0), end_ea(0) {}
  /// Constructor
  range_t(ea_t ea1, ea_t ea2) : start_ea(ea1), end_ea(ea2) {}

  /// Compare two range_t instances, based on the start_ea
  int compare(const range_t &r) const { return start_ea > r.start_ea ? 1 : start_ea < r.start_ea ? -1 : 0; }

  bool operator ==(const range_t &r) const { return compare(r) == 0; }  ///< Compare two range_t's with '=='
  bool operator !=(const range_t &r) const { return compare(r) != 0; }  ///< Compare two range_t's with '!='
  bool operator > (const range_t &r) const { return compare(r) >  0; }  ///< Compare two range_t's with '<'
  bool operator < (const range_t &r) const { return compare(r) <  0; }  ///< Compare two range_t's with '>'

  /// Is 'ea' in the address range?
  bool contains(ea_t ea) const { return start_ea <= ea && end_ea > ea; }

  /// Is every ea in 'r' also in this range_t?
  bool contains(const range_t &r) const { return r.start_ea >= start_ea && r.end_ea <= end_ea; }

  /// Is there an ea in 'r' that is also in this range_t?
  bool overlaps(const range_t &r) const { return r.start_ea < end_ea && start_ea < r.end_ea; }

  /// Set #start_ea, #end_ea to 0
  void clear(void) { start_ea = end_ea = 0; }

  /// Is the size of the range_t <= 0?
  bool empty(void) const { return start_ea >= end_ea; }

  /// Get #end_ea - #start_ea
  asize_t size(void) const { return end_ea - start_ea; }

  /// Assign the range_t to the intersection between the range_t and 'r'
  void intersect(const range_t &r)
  {
    if ( start_ea < r.start_ea )
      start_ea = r.start_ea;
    if ( end_ea > r.end_ea )
      end_ea = r.end_ea;
    if ( end_ea < start_ea )
      end_ea = start_ea;
  }

  /// Ensure that the range_t includes 'ea'
  void extend(ea_t ea)
  {
    if ( start_ea > ea )
      start_ea = ea;
    if ( end_ea < ea )
      end_ea = ea;
  }

  /// Print the range_t.
  /// \param buf the output buffer
  /// \param bufsize the size of the buffer
  size_t print(char *buf, size_t bufsize) const { return range_t_print(this, buf, bufsize); }
};
DECLARE_TYPE_AS_MOVABLE(range_t);
typedef qvector<range_t> rangevec_base_t;
struct rangevec_t : public rangevec_base_t /// Vector of range_t instances
{
};

//--------------------------------------------------------------------------
// Various kinds of ranges, see
// \ref idb_event::changing_range_cmt
// \ref idb_event::range_cmt_changed
enum range_kind_t
{
  RANGE_KIND_UNKNOWN,
  RANGE_KIND_FUNC,          ///< \ref func_t
  RANGE_KIND_SEGMENT,       ///< \ref segment_t
  RANGE_KIND_HIDDEN_RANGE,  ///< \ref hidden_range_t
};

//--------------------------------------------------------------------------
/// Helper functions. Should not be called directly!
#ifndef SWIG
#define RANGESET_HELPER_DEFINITIONS(decl) \
decl bool ida_export rangeset_t_add(rangeset_t *, const range_t &range);\
decl bool ida_export rangeset_t_sub(rangeset_t *, const range_t &range);\
decl bool ida_export rangeset_t_add2(rangeset_t *, const rangeset_t &aset);\
decl bool ida_export rangeset_t_sub2(rangeset_t *, const rangeset_t &aset);\
decl bool ida_export rangeset_t_has_common(const rangeset_t *, const range_t &range, bool strict);\
decl bool ida_export rangeset_t_has_common2(const rangeset_t *, const rangeset_t &aset);\
decl bool ida_export rangeset_t_contains(const rangeset_t *, const rangeset_t &aset);\
decl size_t ida_export rangeset_t_print(const rangeset_t *, char *buf, size_t bufsize);\
decl bool ida_export rangeset_t_intersect(rangeset_t *, const rangeset_t &aset);\
decl const range_t *ida_export rangeset_t_find_range(const rangeset_t *, ea_t ea);\
decl ea_t ida_export rangeset_t_next_addr(const rangeset_t *, ea_t ea);\
decl ea_t ida_export rangeset_t_prev_addr(const rangeset_t *, ea_t ea);\
decl ea_t ida_export rangeset_t_next_range(const rangeset_t *, ea_t ea);\
decl ea_t ida_export rangeset_t_prev_range(const rangeset_t *, ea_t ea);\
decl rangevec_t::const_iterator ida_export rangeset_t_lower_bound(const rangeset_t *, ea_t ea);\
decl rangevec_t::const_iterator ida_export rangeset_t_upper_bound(const rangeset_t *, ea_t ea);\
decl void ida_export rangeset_t_swap(rangeset_t *, rangeset_t &r);
#else
#define RANGESET_HELPER_DEFINITIONS(decl)
#endif // SWIG

class rangeset_t;

RANGESET_HELPER_DEFINITIONS(idaman)

/// An ordered set of non-overlapping address ranges
class rangeset_t
{
  rangevec_t bag;
  mutable const range_t *cache;
  int undo_code = -1;

  RANGESET_HELPER_DEFINITIONS(friend)
  bool verify(void) const;
public:
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  /// Constructor
  rangeset_t(void) : cache(nullptr) {}
  /// Constructor - Initialize set with 'range'
  rangeset_t(const range_t &range): cache(nullptr) { if ( !range.empty() ) bag.push_back(range); }
  /// Constructor - Initialize set with 'ivs'
  rangeset_t(const rangeset_t &ivs) : bag(ivs.bag), cache(nullptr) {}
  rangeset_t &operator=(const rangeset_t &ivs) { bag = ivs.bag; cache = nullptr; return *this; }
  /// Set this = 'r' and 'r' = this. See qvector::swap()
  void swap(rangeset_t &r) { rangeset_t_swap(this, r); }

  /// Add an address range to the set.
  /// If 'range' intersects an existing element e, then e is extended
  /// to include 'range', and any superfluous elements (subsets of e) are removed.
  /// \param range  address range to add. cannot be empty
  /// \return false if 'range' was not added (the set was unchanged)
  bool add(const range_t &range)    { return rangeset_t_add(this, range); }

  /// Create a new range_t from 'start' and 'end' and add it to the set
  bool add(ea_t start, ea_t _end) { return add(range_t(start, _end)); }

  /// Add each element of 'aset' to the set.
  /// \return false if no elements were added (the set was unchanged)
  bool add(const rangeset_t &aset) { return rangeset_t_add2(this, aset); }

  /// Subtract an address range from the set.
  /// All subsets of 'range' will be removed, and all elements that intersect
  /// 'range' will be truncated/split so they do not include 'range'.
  /// \param range  address range to subtract. cannot be empty.
  /// \return false if 'range' was not subtracted (the set was unchanged)
  bool sub(const range_t &range)    { return rangeset_t_sub(this, range); }

  /// Subtract an ea (an range of size 1) from the set. See sub(const range_t &)
  bool sub(ea_t ea)               { return sub(range_t(ea, ea+1)); }

  /// Subtract each range in 'aset' from the set
  /// \return false if nothing was subtracted (the set was unchanged)
  bool sub(const rangeset_t &aset) { return rangeset_t_sub2(this, aset); }

  /// Is there an ea in 'range' that is also in the rangeset?
  bool has_common(const range_t &range) const
    { return rangeset_t_has_common(this, range, false); }

  /// Is every ea in 'range' contained in the rangeset?
  bool includes(const range_t &range) const
    { return rangeset_t_has_common(this, range, true); }

  /// Print each range_t in the rangeset
  size_t print(char *buf, size_t bufsize) const
    { return rangeset_t_print(this, buf, bufsize); }

  /// Size in bytes
  asize_t count(void) const;

  /// Get the range_t at index 'idx'
  const range_t &getrange(int idx) const { return bag[idx]; }

  /// Get the last range_t in the set
  const range_t &lastrange(void) const { return bag.back(); }

  /// Get the number of range_t elements in the set
  size_t nranges(void) const { return bag.size(); }

  /// Does the set have zero elements
  bool empty(void) const { return bag.empty(); }

  /// Delete all elements from the set. See qvector::clear()
  void clear(void) { bag.clear(); cache = nullptr; }

  /// Does any element of 'aset' overlap with an element in this rangeset?. See range_t::overlaps()
  bool has_common(const rangeset_t &aset) const
    { return rangeset_t_has_common2(this, aset); }

  /// Does an element of the rangeset contain 'ea'? See range_t::contains(ea_t)
  bool contains(ea_t ea) const { return !empty() && find_range(ea) != nullptr; }

  /// Is every element in 'aset' contained in an element of this rangeset?. See range_t::contains(range_t)
  bool contains(const rangeset_t &aset) const
     { return rangeset_t_contains(this, aset); }

  /// Set the rangeset to its intersection with 'aset'.
  /// \return false if the set was unchanged
  bool intersect(const rangeset_t &aset)
     { return rangeset_t_intersect(this, aset); }

  /// Is every element in the rangeset contained in an element of 'aset'?
  bool is_subset_of(const rangeset_t &aset) const { return aset.contains(*this); }

  /// Do this rangeset and 'aset' have identical elements?
  bool is_equal(const rangeset_t &aset)   const { return bag == aset.bag; }

  bool operator==(const rangeset_t &aset) const { return is_equal(aset); }   ///< Compare two rangesets with '=='
  bool operator!=(const rangeset_t &aset) const { return !is_equal(aset); }  ///< Compare two rangesets with '!='

  typedef rangevec_t::iterator iterator;                     ///< Iterator for rangesets
  typedef rangevec_t::const_iterator const_iterator;         ///< Const iterator for rangesets
  const_iterator begin(void) const { return bag.begin(); }  ///< Get an iterator that points to the first element in the set
  const_iterator end(void)   const { return bag.end(); }    ///< Get an iterator that points to the end of the set. (This is NOT the last element)
  iterator begin(void) { return bag.begin(); }              ///< \copydoc begin
  iterator end(void)   { return bag.end(); }                ///< \copydoc end

  /// Get the first range that contains at least one ea_t value greater than 'ea'
  const_iterator lower_bound(ea_t ea) const { return rangeset_t_lower_bound(this, ea); }

  /// Get the first range such that every ea_t value in this range is strictly greater than 'ea'
  const_iterator upper_bound(ea_t ea) const { return rangeset_t_upper_bound(this, ea); }

  /// Get the element from the set that contains 'ea'.
  /// \return nullptr if there is no such element
  const range_t *find_range(ea_t ea) const
     { return rangeset_t_find_range(this, ea); }

  /// When searching the rangeset, we keep a cached element to help speed up searches.
  /// \return a pointer to the cached element
  const range_t *cached_range(void) const { return cache; }

  /// Get the smallest ea_t value greater than 'ea' contained in the rangeset
  ea_t next_addr(ea_t ea) const { return rangeset_t_next_addr(this, ea); }

  /// Get the largest ea_t value less than 'ea' contained in the rangeset
  ea_t prev_addr(ea_t ea) const { return rangeset_t_prev_addr(this, ea); }

  /// Get the smallest ea_t value greater than 'ea' that is not in the same range as 'ea'
  ea_t next_range(ea_t ea) const { return rangeset_t_next_range(this, ea); }

  /// Get the largest ea_t value less than 'ea' that is not in the same range as 'ea'
  ea_t prev_range(ea_t ea) const { return rangeset_t_prev_range(this, ea); }

  /// Subtract the address range (from, from+size) and add the range (to, to+size)
  int move_chunk(ea_t from, ea_t to, asize_t size);

  /// Check if the intended move_chunk() arguments are correct.
  int check_move_args(ea_t from, ea_t to, asize_t size); // returns VAMOVE_...
};
DECLARE_TYPE_AS_MOVABLE(rangeset_t);
typedef qvector<rangeset_t> array_of_rangesets; ///< Array of rangeset_t objects
typedef qvector<const rangeset_t*> rangeset_crefvec_t;

#endif  // _RANGE_HPP
