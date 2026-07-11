/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _NETNODE_HPP
#define _NETNODE_HPP

/*! \file netnode.hpp

  \brief Functions that provide the lowest level public interface to the database.
  Namely, we use Btree. To learn more about BTree:

  https://en.wikipedia.org/wiki/B-tree

  We do not use Btree directly. Instead, we have another layer built on the top
  of Btree. Here is a brief explanation of this layer.

  An object called "netnode" is modeled on the top of Btree.
  Each netnode has a unique id: a 32-bit value (64-bit for ida64).
  Initially there is a trivial mapping of the linear addresses used in
  the program to netnodes (later this mapping may be modified using ea2node
  and node2ea functions; this is used for fast database rebasings).
  If we have additional information about an address (for example, a comment is
  attached to it), this information is stored in the corresponding netnode.
  See nalt.hpp to see how the kernel uses netnodes.
  Also, some netnodes have no corresponding linear address (however, they still
  have an id). They are used to store information not related to a particular
  address.

  Each netnode _may_ have the following attributes:

    - a name: an arbitrary non-empty string, up to 255KB-1 bytes

    - a value: arbitrary sized object, max size is MAXSPECSIZE

    - altvals: a sparse array of 32-bit values.
      indexes in this array may be 8-bit or 32-bit values

    - supvals: an array of arbitrary sized objects. (size of each
      object is limited by MAXSPECSIZE)
      indexes in this array may be 8-bit or 32-bit values

    - charvals: a sparse array of 8-bit values.
      indexes in this array may be 8-bit or 32-bit values

    - hashvals: a hash (an associative array).
      indexes in this array are strings
      values are arbitrary sized (max size is MAXSPECSIZE)

  Initially a new netnode contains no information at all so no disk space
  is used for it. As you add new information, the netnode grows.

  All arrays that are attached to the netnode behave in the same manner.
  Initially:
    - all members of altvals/charvals array are zeroes
    - all members of supvals/hashvals array are undefined

  If you need to store objects bigger that MAXSPECSIZE, please note that
  there are high-level functions to store arbitrary sized objects in supvals.
  See setblob/getblob and other blob-related functions.

  You may use netnodes to store additional information about the program.
  Limitations on the use of netnodes are the following:

    - use netnodes only if you could not find a kernel service to
      store your type of information

    - do not create netnodes with valid identifier names.
      Use the "$ " prefix (or any other prefix with characters not allowed
      in the identifiers for the names of your netnodes.
      Although you will probably not destroy anything by
      accident, using already defined names for the names of your
      netnodes is still discouraged.

    - you may create as many netnodes as you want (creation of an unnamed
      netnode does not increase the size of the database).
      however, since each netnode has a number, creating too many netnodes
      could lead to the exhaustion of the netnode numbers (the numbering
      starts at 0xFF000000)

    - remember that netnodes are automatically saved to the disk
      by the kernel.

  Advanced info:

  In fact a netnode may contain up to 256 arrays of arbitrary sized
  objects (not only the 4 listed above). Each array has an 8-bit tag.
  Usually tags are represented by character constants. For example, altvals
  and supvals are simply 2 of 256 arrays, with the tags 'A' and 'S' respectively.

*/

#include <range.hpp>

//--------------------------------------------------------------------------
/// Maximum length of a netnode name. WILL BE REMOVED IN THE FUTURE
const int MAXNAMESIZE = 512;

/// Maximum length of a name. We permit names up to 32KB-1 bytes.
const int MAX_NODENAME_SIZE = 32*1024;

/// Maximum length of strings or objects stored in a supval array element
const int MAXSPECSIZE = 1024;

/// \typedef{nodeidx_t, numbers are 64 bit for 64 bit IDA}
typedef uint64 nodeidx64_t;
typedef uint32 nodeidx32_t;
#ifdef __EA64__
typedef nodeidx64_t nodeidx_t;
#else
typedef nodeidx32_t nodeidx_t;
#endif

/// A number to represent a bad netnode reference
#define BADNODE nodeidx_t(-1)

/// \defgroup nn_res Reserved netnode tags
/// Tags internally used in netnodes. You should not use them
/// for your tagged alt/sup/char/hash arrays.
//@{
const uchar atag = 'A';                 ///< Array of altvals
const uchar stag = 'S';                 ///< Array of supvals
const uchar htag = 'H';                 ///< Array of hashvals
const uchar vtag = 'V';                 ///< Value of netnode
const uchar ntag = 'N';                 ///< Name of netnode
const uchar ltag = 'L';                 ///< Links between netnodes
//@}

// Internal bit used to request ea2node() mapping of alt and sup indexes
const int NETMAP_IDX = 0x100;
// Internal bit used to request ea2node() mapping of alt values.
// Such values are stored after being incremented by one.
const int NETMAP_VAL = 0x200;
// Internal bit used to make sure a string obtained with getblob() is
// null-terminated.
const int NETMAP_STR = 0x400;
// Internal bit: use 8-bit indexes.
const int NETMAP_X8 = 0x800;
// Internal bit: use 8-bit values.
const int NETMAP_V8 = 0x1000;
// Internal bit: value is a netnode index
const int NETMAP_VAL_NDX = 0x2000;

/// visitor to be used by altadjust2 to skip the adjustment of some altvals
struct altadjust_visitor_t
{
  virtual bool should_skip(nodeidx_t ea) = 0;
};

/// \name Helper functions
/// They should not be called directly! See ::netnode
//@{
class netnode;
class linput_t;
idaman bool ida_export netnode_check(netnode *, const char *name, size_t namlen, bool create);
idaman void ida_export netnode_kill(netnode *);
idaman bool ida_export netnode_start(netnode *);
idaman bool ida_export netnode_end(netnode *);
idaman bool ida_export netnode_next(netnode *);
idaman bool ida_export netnode_prev(netnode *);
idaman ssize_t ida_export netnode_get_name(nodeidx_t num, qstring *out);
idaman bool ida_export netnode_rename(nodeidx_t num, const char *newname, size_t namlen);
idaman ssize_t ida_export netnode_valobj(nodeidx_t num, void *buf, size_t bufsize);
idaman ssize_t ida_export netnode_valstr(nodeidx_t num, char *buf, size_t bufsize);
idaman ssize_t ida_export netnode_qvalstr(nodeidx_t num, qstring *buf);
idaman bool ida_export netnode_set(nodeidx_t num, const void *value, size_t length);
idaman bool ida_export netnode_delvalue(nodeidx_t num);
idaman nodeidx_t ida_export netnode_altval(nodeidx_t num, nodeidx_t alt, int tag);
idaman uchar ida_export netnode_charval(nodeidx_t num, nodeidx_t alt, int tag);
idaman nodeidx_t ida_export netnode_altval_idx8(nodeidx_t num, uchar alt, int tag);
idaman uchar ida_export netnode_charval_idx8(nodeidx_t num, uchar alt, int tag);
idaman ssize_t ida_export netnode_supval(nodeidx_t num, nodeidx_t alt, void *buf, size_t bufsize, int tag);
idaman ssize_t ida_export netnode_supstr(nodeidx_t num, nodeidx_t alt, char *buf, size_t bufsize, int tag);
idaman ssize_t ida_export netnode_qsupstr(nodeidx_t num, qstring *buf, nodeidx_t alt, int tag);
idaman bool ida_export netnode_supset(nodeidx_t num, nodeidx_t alt, const void *value, size_t length, int tag);
idaman bool ida_export netnode_supdel(nodeidx_t num, nodeidx_t alt, int tag);
idaman nodeidx_t ida_export netnode_lower_bound(nodeidx_t num, nodeidx_t cur, int tag);
idaman nodeidx_t ida_export netnode_supfirst(nodeidx_t num, int tag);
idaman nodeidx_t ida_export netnode_supnext(nodeidx_t num, nodeidx_t cur, int tag);
idaman nodeidx_t ida_export netnode_suplast(nodeidx_t num, int tag);
idaman nodeidx_t ida_export netnode_supprev(nodeidx_t num, nodeidx_t cur, int tag);
idaman ssize_t ida_export netnode_supval_idx8(nodeidx_t num, uchar alt, void *buf, size_t bufsize, int tag);
idaman ssize_t ida_export netnode_supstr_idx8(nodeidx_t num, uchar alt, char *buf, size_t bufsize, int tag);
idaman ssize_t ida_export netnode_qsupstr_idx8(nodeidx_t num, qstring *buf, uchar alt, int tag);
idaman bool ida_export netnode_supset_idx8(nodeidx_t num, uchar alt, const void *value, size_t length, int tag);
idaman bool ida_export netnode_supdel_idx8(nodeidx_t num, uchar alt, int tag);
idaman nodeidx_t ida_export netnode_lower_bound_idx8(nodeidx_t num, uchar alt, int tag);
idaman nodeidx_t ida_export netnode_supfirst_idx8(nodeidx_t num, int tag);
idaman nodeidx_t ida_export netnode_supnext_idx8(nodeidx_t num, uchar alt, int tag);
idaman nodeidx_t ida_export netnode_suplast_idx8(nodeidx_t num, int tag);
idaman nodeidx_t ida_export netnode_supprev_idx8(nodeidx_t num, uchar alt, int tag);
idaman bool ida_export netnode_supdel_all(nodeidx_t num, int tag);
idaman int ida_export netnode_supdel_range(nodeidx_t num, nodeidx_t idx1, nodeidx_t idx2, int tag);
idaman int ida_export netnode_supdel_range_idx8(nodeidx_t num, nodeidx_t idx1, nodeidx_t idx2, int tag);
idaman ssize_t ida_export netnode_hashval(nodeidx_t num, const char *idx, void *buf, size_t bufsize, int tag);
idaman ssize_t ida_export netnode_hashstr(nodeidx_t num, const char *idx, char *buf, size_t bufsize, int tag);
idaman ssize_t ida_export netnode_qhashstr(nodeidx_t num, qstring *buf, const char *idx, int tag);
idaman nodeidx_t ida_export netnode_hashval_long(nodeidx_t num, const char *idx, int tag);
idaman bool ida_export netnode_hashset(nodeidx_t num, const char *idx, const void *value, size_t length, int tag);
idaman bool ida_export netnode_hashdel(nodeidx_t num, const char *idx, int tag);
idaman ssize_t ida_export netnode_hashfirst(nodeidx_t num, char *buf, size_t bufsize, int tag);
idaman ssize_t ida_export netnode_qhashfirst(nodeidx_t num, qstring *buf, int tag);
idaman ssize_t ida_export netnode_hashnext(nodeidx_t num, const char *idx, char *buf, size_t bufsize, int tag);
idaman ssize_t ida_export netnode_qhashnext(nodeidx_t num, qstring *buf, const char *idx, int tag);
idaman ssize_t ida_export netnode_hashlast(nodeidx_t num, char *buf, size_t bufsize, int tag);
idaman ssize_t ida_export netnode_qhashlast(nodeidx_t num, qstring *buf, int tag);
idaman ssize_t ida_export netnode_hashprev(nodeidx_t num, const char *idx, char *buf, size_t bufsize, int tag);
idaman ssize_t ida_export netnode_qhashprev(nodeidx_t num, qstring *buf, const char *idx, int tag);
idaman size_t ida_export netnode_blobsize(nodeidx_t num, nodeidx_t start, int tag);
idaman void *ida_export netnode_getblob(nodeidx_t num, void *buf, size_t *bufsize, nodeidx_t start, int tag);
idaman ssize_t ida_export netnode_qgetblob(nodeidx_t num, bytevec_t *buf, size_t elsize, nodeidx_t start, int tag);
idaman bool ida_export netnode_setblob(nodeidx_t num, const void *buf, size_t size, nodeidx_t start, int tag);
idaman int ida_export netnode_delblob(nodeidx_t num, nodeidx_t start, int tag);
idaman bool ida_export netnode_inited(void);
idaman bool ida_export netnode_is_available(void);
idaman size_t ida_export netnode_copy(nodeidx_t num, nodeidx_t count, nodeidx_t target, bool move);
idaman size_t ida_export netnode_altshift(nodeidx_t num, nodeidx_t from, nodeidx_t to, nodeidx_t size, int tag);
idaman size_t ida_export netnode_charshift(nodeidx_t num, nodeidx_t from, nodeidx_t to, nodeidx_t size, int tag);
idaman size_t ida_export netnode_supshift(nodeidx_t num, nodeidx_t from, nodeidx_t to, nodeidx_t size, int tag);
idaman size_t ida_export netnode_blobshift(nodeidx_t num, nodeidx_t from, nodeidx_t to, nodeidx_t size, int tag);
idaman void ida_export netnode_altadjust(nodeidx_t num, nodeidx_t from, nodeidx_t to, nodeidx_t size, bool (idaapi *should_skip)(nodeidx_t ea));
idaman void ida_export netnode_altadjust2(nodeidx_t num, nodeidx_t from, nodeidx_t to, nodeidx_t size, altadjust_visitor_t &av);
idaman bool ida_export netnode_exist(const netnode &n);
//@}

//--------------------------------------------------------------------------
//      N E T N O D E
//--------------------------------------------------------------------------

/// Definition of the IDA database node.
/// Note that the size of the 'netnode' class is 4 bytes and it can be
/// freely casted to 'uint32' and back. This makes it easy to store
/// information about the program location in the netnodes.
/// Please pass netnodes to functions by value.
class netnode
{
  /// \cond
  friend class netlink;
  /// \endcond
public:

  //--------------------------------------------------------------------------
  /// \name Constructors, conversions and assignments
  //@{

  /// Constructor to create a netnode to access information about the
  /// specified linear address (possibly missing)
  netnode(nodeidx_t num=BADNODE) { netnodenumber = num; }

  /// Conversion from netnode to a linear address
  operator nodeidx_t() const { return netnodenumber; }

  /// Construct an instance of netnode class to access the specified netnode.
  /// \param _name      name of netnode
  /// \param namlen     length of the name. may be omitted, in this
  ///                   case the length will be calculated with strlen()
  /// \param do_create  true:  create the netnode if it doesn't exist yet.
  ///                   false: don't create the netnode, set netnumber to #BADNODE if
  ///                         it doesn't exist
  netnode(const char *_name, size_t namlen=0, bool do_create=false)
  {
    netnode_check(this, _name, namlen, do_create);
  }

  //@}

  /// Does the specified netnode exist?.
  /// \retval true   there is some information attached to the netnode.
  /// \retval false  unnamed netnode without any information
  friend bool exist(const netnode &n) { return netnode_exist(n); }

  /// Does the netnode with the specified name exist?
  static bool exist(const char *_name) { return netnode(_name) != BADNODE; }

  //--------------------------------------------------------------------------
  /// \name Create/Delete
  /// \note You can check if a netnode already exists with exist()
  //@{

  /// Create a named netnode.
  /// \param _name   name of netnode to create.
  ///                names of user-defined netnodes must have the "$ " prefix
  ///                in order to avoid clashes with program byte names.
  /// \param namlen  length of the name. if not specified, it will be
  ///                calculated using strlen()
  /// \retval 1  ok, the node is created
  /// \retval 0  the node already exists. you may use the netnode class to access it.
  bool create(const char *_name, size_t namlen=0)
  {
    return netnode_check(this, _name, namlen, true);
  }

  /// Create unnamed netnode.
  /// \retval 1  ok
  /// \retval 0  should not happen, indicates internal error
  bool create(void) { return create(nullptr); }

  /// Delete a netnode with all information attached to it
  void kill(void) { netnode_kill(this); }

  //@}

  //--------------------------------------------------------------------------
  /// \name Netnode names
  //@{

  /// Get the netnode name.
  /// \return -1 if netnode is unnamed (buf is untouched in this case),
  ///            otherwise the name length
  ssize_t get_name(qstring *buf) const
  {
    return netnode_get_name(*this, buf);
  }

  /// Rename a netnode.
  /// \param newname  new name of netnode. nullptr or "" means to delete name.
  ///                 names of user-defined netnodes must have the "$ " prefix
  ///                 in order to avoid clashes with program byte names.
  /// \param namlen   length of new name. if not specified, it will be
  ///                 calculated using strlen()
  /// \retval 1  ok
  /// \retval 0  failed, newname is already used
  bool rename(const char *newname, size_t namlen=0)
  {
    return netnode_rename(*this, newname, namlen);
  }

  //@}

  //--------------------------------------------------------------------------
  /// \name Value of netnode
  //@{

  /// Get value of netnode.
  /// Netnode values are arbitrary sized objects with max size is #MAXSPECSIZE.
  /// NB: do not use this function for strings - see valstr().
  /// \return length of value, -1 if no value present
  ssize_t valobj(void *buf, size_t bufsize) const
  {
    return netnode_valobj(*this, buf, bufsize);
  }

  /// Get string value of netnode.
  /// See explanations for supstr() function about the differences between valobj()
  /// and valstr()
  /// \return length of value, -1 if no value present
  ssize_t valstr(qstring *buf) const
  {
    return netnode_qvalstr(*this, buf);
  }

  /// \sa valstr(qstring *buf) const
  ssize_t valstr(char *buf, size_t bufsize) const
  {
    return netnode_valstr(*this, buf, bufsize);
  }

  /// Set value of netnode.
  /// \param value   pointer to value
  /// \param length  length of value. if not specified, it will be calculated
  ///                using strlen()
  /// \returns 1 - ok
  bool set(const void *value, size_t length=0)
  {
    return netnode_set(*this, value, length);
  }

  /// Delete value of netnode.
  /// \retval 1  ok
  /// \retval 0  failed, netnode is bad or other error
  bool delvalue(void)
  {
    return netnode_delvalue(*this);
  }

  /// Value of netnode as a long number:
  bool set_long(nodeidx_t x) { return set(&x, sizeof(x)); }
  bool value_exists(void) const { return valobj(nullptr, 0) >= 0; }
  nodeidx_t long_value(void) const
  {
    nodeidx_t v = 0;
    if ( valobj(&v, sizeof(v)) > 0 )
      return v;
    return BADNODE;
  }

  //@}

  //--------------------------------------------------------------------------
  /// \name Arrays of altvals.
  /// altvals: a sparse array of 32-bit values.
  /// indexes in this array may be 8-bit or 32-bit values
  //@{

  /// Get altval element of the specified array.
  /// \param alt  index into array of altvals
  /// \param tag  tag of array. may be omitted
  /// \return value of altval element. nonexistent altval members are returned
  ///          as zeroes
  nodeidx_t altval(nodeidx_t alt, uchar tag=atag) const
  {
    return netnode_altval(*this, alt, tag);
  }
  nodeidx_t altval_ea(ea_t ea, uchar tag=atag) const
  {
    return netnode_altval(*this, ea, tag|NETMAP_IDX);
  }

  /// Set value of altval array.
  /// \param alt    index into array of altvals
  /// \param value  new value of altval element
  /// \param tag    tag of array
  /// \retval 1  ok
  /// \retval 0  failed, normally should not occur
  bool altset(nodeidx_t alt, nodeidx_t value, uchar tag=atag)
  {
    return netnode_supset(*this, alt, &value, sizeof(value), tag);
  }
  bool altset_ea(ea_t ea, nodeidx_t value, uchar tag=atag)
  {
    return netnode_supset(*this, ea, &value, sizeof(value), tag|NETMAP_IDX);
  }

  /// Delete element of altval array.
  /// \param alt  index into array of altvals
  /// \param tag  tag of array
  /// \retval 1  ok
  /// \retval 0  failed, element doesn't exist
  bool altdel(nodeidx_t alt, uchar tag=atag)
  {
    return netnode_supdel(*this, alt, tag);
  }
  bool altdel_ea(ea_t ea, uchar tag=atag)
  {
    return netnode_supdel(*this, ea, tag|NETMAP_IDX);
  }

  /// Store/retrieve/delete an address value in the netnode that corresponds
  /// to an address.
  bool easet(ea_t ea, ea_t addr, uchar tag)
  {
    return netnode_supset(*this, ea, &addr, sizeof(addr), tag|NETMAP_IDX|NETMAP_VAL);
  }
  ea_t eaget(ea_t ea, uchar tag) const
  {
    return netnode_altval(*this, ea, tag|NETMAP_IDX|NETMAP_VAL);
  }
  bool eadel(ea_t ea, uchar tag)
  {
    return netnode_supdel(*this, ea, tag|NETMAP_IDX);
  }

  bool easet_idx(nodeidx_t idx, ea_t addr, uchar tag)
  {
    return netnode_supset(*this, idx, &addr, sizeof(addr), tag|NETMAP_VAL);
  }
  ea_t eaget_idx(nodeidx_t idx, uchar tag)
  {
    return netnode_altval(*this, idx, tag|NETMAP_VAL);
  }

  bool easet_idx8(uchar idx, ea_t addr, uchar tag)
  {
    return netnode_supset_idx8(*this, idx, &addr, sizeof(addr), tag|NETMAP_VAL);
  }
  ea_t eaget_idx8(uchar idx, uchar tag) const
  {
    return netnode_altval_idx8(*this, idx, tag|NETMAP_VAL);
  }
  bool eadel_idx8(uchar idx, uchar tag)
  {
    return netnode_supdel_idx8(*this, idx, tag);
  }

  /// Get first existing element of altval array.
  /// \param tag  tag of array
  /// \return index of first existing element of altval array,
  ///          #BADNODE if altval array is empty
  nodeidx_t altfirst(uchar tag=atag) const
  {
    return supfirst(tag);
  }

  /// Get next existing element of altval array.
  /// \param cur  current index
  /// \param tag  tag of array
  /// \return index of the next existing element of altval array,
  ///          #BADNODE if no more altval array elements exist
  nodeidx_t altnext(nodeidx_t cur, uchar tag=atag) const
  {
    return supnext(cur, tag);
  }

  /// Get last element of altval array.
  /// \param tag  tag of array
  /// \return index of last existing element of altval array,
  ///          #BADNODE if altval array is empty
  nodeidx_t altlast(uchar tag=atag) const
  {
    return suplast(tag);
  }

  /// Get previous existing element of altval array.
  /// \param cur  current index
  /// \param tag  tag of array
  /// \return index of the previous existing element of altval array,
  ///          #BADNODE if no more altval array elements exist
  nodeidx_t altprev(nodeidx_t cur, uchar tag=atag) const
  {
    return supprev(cur, tag);
  }

  /// Shift the altval array elements.
  /// Moves the array elements at (from..from+size) to (to..to+size)
  /// \return number of shifted elements
  size_t altshift(nodeidx_t from, nodeidx_t to, nodeidx_t size, uchar tag=atag)
  {
    return netnode_altshift(*this, from, to, size, tag);
  }

  /// Adjust values of altval arrays elements.
  /// All altvals in the range from+1..from+size+1 and adjusted to have
  /// values in the range to+1..to+size+1.
  /// The parameter should_skip() can be used to skip the adjustment of some altvals
  void altadjust(nodeidx_t from, nodeidx_t to, nodeidx_t size, bool (idaapi *should_skip)(nodeidx_t ea)=nullptr)
  {
    netnode_altadjust(*this, from, to, size, should_skip);
  }
  void altadjust2(nodeidx_t from, nodeidx_t to, nodeidx_t size, altadjust_visitor_t &av)
  {
    netnode_altadjust2(*this, from, to, size, av);
  }


  //@}

  /// \name Arrays of altvals: 8-bit values
  /// The following functions behave in the same manner as the functions
  /// described above. The only difference is that the array value is 8-bits.
  ///   - index: 32 bits
  ///   - value: 8  bits
  //@{
  uchar charval(nodeidx_t alt, uchar tag) const      { return netnode_charval(*this, alt, tag); }
  bool charset(nodeidx_t alt, uchar val, uchar tag)  { return supset(alt, &val, sizeof(val), tag); }
  bool chardel(nodeidx_t alt, uchar tag)             { return supdel(alt, tag); }
  uchar charval_ea(ea_t ea, uchar tag) const         { return netnode_charval(*this, ea, tag|NETMAP_IDX); }
  bool charset_ea(ea_t ea, uchar val, uchar tag)     { return netnode_supset(*this, ea, &val, sizeof(val), tag|NETMAP_IDX); }
  bool chardel_ea(ea_t ea, uchar tag)                { return netnode_supdel(*this, ea, tag|NETMAP_IDX); }
  nodeidx_t charfirst(uchar tag) const               { return supfirst(tag); }
  nodeidx_t charnext(nodeidx_t cur, uchar tag) const { return supnext(cur, tag); }
  nodeidx_t charlast(uchar tag) const                { return suplast(tag); }
  nodeidx_t charprev(nodeidx_t cur, uchar tag) const { return supprev(cur, tag); }
  size_t charshift(nodeidx_t from, nodeidx_t to, nodeidx_t size, uchar tag)
    { return netnode_charshift(*this, from, to, size, tag); }
  //@}

  /// \name Arrays of altvals: 8-bit indexes
  /// Another set of functions to work with altvals.
  /// The only difference is that the array index is 8-bits,
  /// and therefore the array may contain up to 256 elements only.
  ///   - index: 8  bits
  ///   - value: 32 bits
  //@{
  nodeidx_t altval_idx8(uchar alt, uchar tag) const   { return netnode_altval_idx8(*this, alt, tag); }
  bool altset_idx8(uchar alt, nodeidx_t val, uchar tag) { return supset_idx8(alt, &val, sizeof(val), tag); }
  bool altdel_idx8(uchar alt, uchar tag)              { return supdel_idx8(alt, tag); }
  nodeidx_t altfirst_idx8(uchar tag) const            { return supfirst_idx8(tag); }
  nodeidx_t altnext_idx8(uchar cur, uchar tag) const  { return supnext_idx8(cur, tag); }
  nodeidx_t altlast_idx8(uchar tag) const             { return suplast_idx8(tag); }
  nodeidx_t altprev_idx8(uchar cur, uchar tag) const  { return supprev_idx8(cur, tag); }
  //@}

  /// \name More altvals
  /// Another set of functions to work with altvals.
  ///   - index: 8 bits
  ///   - value: 8 bits
  //@{
  uchar charval_idx8(uchar alt, uchar tag) const     { return netnode_charval_idx8(*this, alt, tag); }
  bool charset_idx8(uchar alt, uchar val, uchar tag) { return supset_idx8(alt, &val, sizeof(val), tag); }
  //-V::524 equivalent functions
  bool chardel_idx8(uchar alt, uchar tag)            { return supdel_idx8(alt, tag); }
  nodeidx_t charfirst_idx8(uchar tag) const          { return supfirst_idx8(tag); }
  nodeidx_t charnext_idx8(uchar cur, uchar tag) const { return supnext_idx8(cur, tag); }
  nodeidx_t charlast_idx8(uchar tag) const           { return suplast_idx8(tag); }
  nodeidx_t charprev_idx8(uchar cur, uchar tag) const { return supprev_idx8(cur, tag); }
  //@}

  /// \name Delete altvals
  /// \note To delete range of elements in an altval array, see supdel_range()
  //@{

  /// Delete all elements of altval array.
  /// This function may be applied to 32-bit and 8-bit altval arrays.
  /// This function deletes the whole altval array.
  /// \return success
  bool altdel(void)
  {
    return supdel_all(atag);
  }

  /// Delete all elements of the specified altval array.
  /// This function may be applied to 32-bit and 8-bit altval arrays.
  /// This function deletes the whole altval array.
  /// \param tag  tag of array
  /// \return success
  bool altdel_all(uchar tag=atag)
  {
    return supdel_all(tag);
  }

  //@}

  //--------------------------------------------------------------------------
  /// \name Arrays of supvals
  /// supvals: an array of arbitrary sized objects.
  /// (size of each object is limited by #MAXSPECSIZE).
  /// indexes in this array may be 8-bit or 32-bit values.
  //@{

  /// Get value of the specified supval array element.
  /// NB: do not use this function to retrieve strings, see supstr()!
  /// \param alt      index into array of supvals
  /// \param buf      output buffer, may be nullptr
  /// \param bufsize  size of output buffer
  /// \param tag      tag of array. Default: stag
  /// \return size of value, -1 if element doesn't exist
  ssize_t supval(nodeidx_t alt, void *buf, size_t bufsize, uchar tag=stag) const
        { return netnode_supval(*this, alt, buf, bufsize, tag); }
  ssize_t supval_ea(ea_t ea, void *buf, size_t bufsize, uchar tag=stag) const
        { return netnode_supval(*this, ea, buf, bufsize, tag|NETMAP_IDX); }

  /// Get string value of the specified supval array element.
  /// The differences between supval() and supstr() are the following:
  ///  -# Strings are stored with the terminating zero in the old databases.
  ///     supval() returns the exact size of the stored object (with
  ///     the terminating zero) but supstr returns the string length without
  ///     the terminating zero. supstr() can handle strings stored with or
  ///     without the terminating zero.
  ///  -# supstr() makes sure that the string is terminated with 0 even if
  ///     the string was stored in the database without it or the output
  ///     buffer is too small to hold the entire string. In the latter case
  ///     the string will be truncated but still will have the terminating zero.
  ///
  /// If you do not use the string length returned by supval/supstr() functions
  /// and you are sure that the output buffer is big enough to hold the entire
  /// string and the string has been stored in the database with the terminating
  /// zero, then you can continue to use supval() instead of supstr().
  ///
  /// \param buf      output buffer, may be nullptr
  /// \param alt      index into array of supvals
  /// \param tag      tag of array. Default: stag
  /// \return length of the output string, -1 if element doesn't exist
  ssize_t supstr(qstring *buf, nodeidx_t alt, uchar tag=stag) const
        { return netnode_qsupstr(*this, buf, alt, tag); }
  ssize_t supstr_ea(qstring *buf, ea_t ea, uchar tag=stag) const
        { return netnode_qsupstr(*this, buf, ea, tag|NETMAP_IDX); }

  /// \sa supstr(qstring *buf, nodeidx_t alt, uchar tag=stag) const
  ssize_t supstr(nodeidx_t alt, char *buf, size_t bufsize, uchar tag=stag) const
        { return netnode_supstr(*this, alt, buf, bufsize, tag); }
  ssize_t supstr_ea(ea_t ea, char *buf, size_t bufsize, uchar tag=stag) const
        { return netnode_supstr(*this, ea, buf, bufsize, tag|NETMAP_IDX); }

  /// Set value of supval array element.
  /// \param alt     index into array of supvals
  /// \param value   pointer to supval value
  /// \param length  length of 'value'. If not specified, the length is calculated
  ///                using strlen()+1.
  /// \param tag     tag of array
  /// \retval 1  ok
  /// \retval 0  should not occur - indicates internal error
  bool supset(nodeidx_t alt, const void *value, size_t length=0, uchar tag=stag)
        { return netnode_supset(*this, alt, value, length, tag); }
  bool supset_ea(ea_t ea, const void *value, size_t length=0, uchar tag=stag)
        { return netnode_supset(*this, ea, value, length, tag|NETMAP_IDX); }

  /// Delete supval element.
  /// \param alt  index into array of supvals
  /// \param tag  tag of array
  /// \retval true   deleted
  /// \retval false  element does not exist
  bool supdel(nodeidx_t alt, uchar tag=stag)
        { return netnode_supdel(*this, alt, tag); }
  bool supdel_ea(ea_t ea, uchar tag=stag)
        { return netnode_supdel(*this, ea, tag|NETMAP_IDX); }

  /// Get lower bound of existing elements of supval array.
  /// \param cur  current index
  /// \param tag  tag of array
  /// \return index of first existing element of supval array >= cur
  ///          #BADNODE if supval array is empty
  nodeidx_t lower_bound(nodeidx_t cur, uchar tag=stag) const
        { return netnode_lower_bound(*this, cur, tag); }
  nodeidx_t lower_bound_ea(ea_t ea, uchar tag=stag) const
        { return netnode_lower_bound(*this, ea, tag|NETMAP_IDX); }

  /// Get first existing element of supval array.
  /// \param tag  tag of array
  /// \return index of first existing element of supval array,
  ///          #BADNODE if supval array is empty
  nodeidx_t supfirst(uchar tag=stag) const
        { return netnode_supfirst(*this, tag); }

  /// Get next existing element of supval array.
  /// \param cur  current index
  /// \param tag  tag of array
  /// \return index of the next existing element of supval array,
  ///          #BADNODE if no more supval array elements exist
  nodeidx_t supnext(nodeidx_t cur, uchar tag=stag) const
        { return netnode_supnext(*this, cur, tag); }

  /// Get last existing element of supval array.
  /// \param tag  tag of array
  /// \return index of last existing element of supval array,
  ///          #BADNODE if supval array is empty
  nodeidx_t suplast(uchar tag=stag) const
        { return netnode_suplast(*this, tag); }

  /// Get previous existing element of supval array.
  /// \param cur  current index
  /// \param tag  tag of array
  /// \return index of the previous existing element of supval array
  ///          #BADNODE if no more supval array elements exist
  nodeidx_t supprev(nodeidx_t cur, uchar tag=stag) const
        { return netnode_supprev(*this, cur, tag); }


  /// Shift the supval array elements.
  /// Moves the array elements at (from..from+size) to (to..to+size)
  /// \return number of shifted elements
  size_t supshift(nodeidx_t from, nodeidx_t to, nodeidx_t size, uchar tag=stag)
    { return netnode_supshift(*this, from, to, size, tag); }

  //@}

  /// \name Arrays of supvals: 8-bit indexes
  /// The following functions behave in the same manner as the functions
  /// described above. The only difference is that the array index is 8-bits
  /// and therefore the array may contains up to 256 elements only.
  //@{
  ssize_t   supval_idx8(uchar alt, void *buf, size_t bufsize, uchar tag) const { return netnode_supval_idx8(*this, alt, buf, bufsize, tag); }
  ssize_t   supstr_idx8(uchar alt, char *buf, size_t bufsize, uchar tag) const { return netnode_supstr_idx8(*this, alt, buf, bufsize, tag); }
  ssize_t   supstr_idx8(qstring *buf, uchar alt, uchar tag) const { return netnode_qsupstr_idx8(*this, buf, alt, tag); }
  bool     supset_idx8(uchar alt, const void *value, size_t length, uchar tag) { return netnode_supset_idx8(*this, alt, value, length, tag); }
  bool     supdel_idx8(uchar alt, uchar tag)        { return netnode_supdel_idx8(*this, alt, tag); }
  nodeidx_t lower_bound_idx8(uchar alt, uchar tag) const { return netnode_lower_bound_idx8(*this, alt, tag); }
  nodeidx_t supfirst_idx8(uchar tag) const           { return netnode_supfirst_idx8(*this, tag); }
  nodeidx_t supnext_idx8(uchar alt, uchar tag) const { return netnode_supnext_idx8(*this, alt, tag); }
  nodeidx_t suplast_idx8(uchar tag) const            { return netnode_suplast_idx8(*this, tag); }
  nodeidx_t supprev_idx8(uchar alt, uchar tag) const { return netnode_supprev_idx8(*this, alt, tag); }
  //@}

  /// \name Delete supvals
  //@{

  /// Delete all elements of supval array.
  /// This function may be applied to 32-bit and 8-bit supval arrays.
  /// This function deletes the whole supval array.
  /// \return success
  bool supdel(void)
  {
    return supdel_all(stag);
  }

  /// Delete all elements of the specified supval array.
  /// This function may be applied to 32-bit and 8-bit supval arrays.
  /// This function deletes the whole supval array.
  /// \return success
  bool supdel_all(uchar tag)
  {
    return netnode_supdel_all(*this, tag);
  }

  /// Delete range of elements in the specified supval array.
  /// Elements in range [idx1, idx2) will be deleted.
  /// \note This function can also be used to delete a range of altval elements
  /// \param idx1  first element to delete
  /// \param idx2  last element to delete + 1
  /// \param tag   tag of array
  /// \return number of deleted elements
  int supdel_range(nodeidx_t idx1, nodeidx_t idx2, uchar tag)
  {
    return netnode_supdel_range(*this, idx1, idx2, tag);
  }
  /// Same as above, but accepts 8-bit indexes
  int supdel_range_idx8(uchar idx1, uchar idx2, uchar tag)
  {
    return netnode_supdel_range_idx8(*this, idx1, idx2, tag);
  }

  //@}

  //--------------------------------------------------------------------------
  /// \name Hashes
  /// Associative arrays indexed by strings.
  /// hashvals: Indexes in this array are strings.
  /// Values are arbitrary sized (max size is #MAXSPECSIZE)
  //@{

  /// Get value of the specified hash element.
  /// \param idx      index into hash
  /// \param buf      output buffer, may be nullptr
  /// \param bufsize  output buffer size
  /// \param tag      tag of hash. Default: htag
  /// \return -1 if element doesn't exist or idx is nullptr.
  ///          otherwise returns the value size in bytes
  ssize_t hashval(const char *idx, void *buf, size_t bufsize, uchar tag=htag) const
        { return netnode_hashval(*this, idx, buf, bufsize, tag); }

  /// Similar to supstr(), but accepts a hash index
  ssize_t hashstr(qstring *buf, const char *idx, uchar tag=htag) const
        { return netnode_qhashstr(*this, buf, idx, tag); }

  /// \sa hashstr(qstring *buf, const char *idx, uchar tag=htag) const
  ssize_t hashstr(const char *idx, char *buf, size_t bufsize, uchar tag=htag) const
        { return netnode_hashstr(*this, idx, buf, bufsize, tag); }

  /// Get value of the specified hash element.
  /// \param idx  index into hash
  /// \param tag  tag of hash. Default: htag
  /// \return value of hash element (it should be set using hashset(nodeidx_t)),
  ///          0 if the element does not exist
  nodeidx_t hashval_long(const char *idx, uchar tag=htag) const
        { return netnode_hashval_long(*this, idx, tag); }

  /// Set value of hash element.
  /// \param idx     index into hash
  /// \param value   pointer to value
  /// \param length  length of 'value'. If not specified, the length is calculated
  ///                using strlen()+1.
  /// \param tag     tag of hash. Default: htag
  /// \retval 1  ok
  /// \retval 0  should not occur - indicates internal error
  bool hashset(const char *idx, const void *value, size_t length=0, uchar tag=htag)
        { return netnode_hashset(*this, idx, value, length, tag); }

  /// Set value of hash element to long value.
  /// \param idx    index into hash
  /// \param value  new value of hash element
  /// \param tag    tag of hash. Default: htag
  /// \retval 1  ok
  /// \retval 0  should not occur - indicates internal error
  bool hashset(const char *idx, nodeidx_t value, uchar tag=htag)
        { return hashset(idx, &value, sizeof(value), tag); }

  /// Delete hash element.
  /// \param idx  index into hash
  /// \param tag  tag of hash. Default: htag
  /// \retval true   deleted
  /// \retval false  element does not exist
  bool hashdel(const char *idx, uchar tag=htag)
        { return netnode_hashdel(*this, idx, tag); }

  /// Get first existing element of hash.
  /// \note elements of hash are kept sorted in lexical order
  /// \param buf      output buffer, may be nullptr
  /// \param tag      tag of hash. Default: htag
  /// \return size of index of first existing element of hash,
  ///          -1 if hash is empty
  ssize_t hashfirst(qstring *buf, uchar tag=htag) const
        { return netnode_qhashfirst(*this, buf, tag); }

  /// \sa hashfirst(qstring *buf, uchar tag=htag) const
  ssize_t hashfirst(char *buf, size_t bufsize, uchar tag=htag) const
        { return netnode_hashfirst(*this, buf, bufsize, tag); }

  /// Get next existing element of hash.
  /// \note elements of hash are kept sorted in lexical order
  /// \param buf      output buffer, may be nullptr
  /// \param idx      current index into hash
  /// \param tag      tag of hash. Default: htag
  /// \return size of index of the next existing element of hash,
  ///          -1 if no more hash elements exist
  ssize_t hashnext(qstring *buf, const char *idx, uchar tag=htag) const
        { return netnode_qhashnext(*this, buf, idx, tag); }

  /// \sa hashnext(qstring *buf, const char *idx, uchar tag=htag) const
  ssize_t hashnext(const char *idx, char *buf, size_t bufsize, uchar tag=htag) const
        { return netnode_hashnext(*this, idx, buf, bufsize, tag); }

  /// Get last existing element of hash.
  /// \note elements of hash are kept sorted in lexical order
  /// \param buf      output buffer, may be nullptr
  /// \param tag      tag of hash. Default: htag
  /// \return size of index of last existing element of hash,
  ///          -1 if hash is empty
  ssize_t hashlast(qstring *buf, uchar tag=htag) const
        { return netnode_qhashlast(*this, buf, tag); }

  /// \sa hashlast(qstring *buf, uchar tag=htag) const
  ssize_t hashlast(char *buf, size_t bufsize, uchar tag=htag) const
        { return netnode_hashlast(*this, buf, bufsize, tag); }

  /// Get previous existing element of supval array.
  /// \note elements of hash are kept sorted in lexical order
  /// \param buf      output buffer, may be nullptr
  /// \param idx      current index into hash
  /// \param tag      tag of hash. Default: htag
  /// \return size of index of the previous existing element of hash,
  ///          -1 if no more hash elements exist
  ssize_t hashprev(qstring *buf, const char *idx, uchar tag=htag) const
        { return netnode_qhashprev(*this, buf, idx, tag); }

  /// \sa hashprev(qstring *buf, const char *idx, uchar tag=htag) const
  ssize_t hashprev(const char *idx, char *buf, size_t bufsize, uchar tag=htag) const
        { return netnode_hashprev(*this, idx, buf, bufsize, tag); }

  /// Delete all elements of hash.
  /// This function deletes the whole hash.
  /// \param tag  tag of hash. Default: htag
  /// \return success
  bool hashdel_all(uchar tag=htag)
  {
    return supdel_all(tag);
  }

  //@}

  //--------------------------------------------------------------------------
  /// \name Blobs
  /// Virtually unlimited size binary objects.
  /// Blobs are stored in several supval array elements.
  //@{

  /// Get size of blob.
  /// \param _start  index of the first supval element used to store blob
  /// \param tag     tag of supval array
  /// \return number of bytes required to store a blob
  size_t blobsize(nodeidx_t _start, uchar tag)
  {
    return netnode_blobsize(*this, _start, tag);
  }
  size_t blobsize_ea(ea_t ea, uchar tag)
  {
    return netnode_blobsize(*this, ea, tag|NETMAP_IDX);
  }

  /// Get blob from a netnode.
  /// \param buf              buffer to read into. if nullptr, the buffer will be
  ///                         allocated using qalloc()
  /// \param[in, out] bufsize in:  size of 'buf' in bytes (if buf == nullptr then meaningless).
  ///                         out: size of the blob if it exists.
  ///                         bufsize may be nullptr
  /// \param _start           index of the first supval element used to store blob
  /// \param tag              tag of supval array
  /// \return nullptr if blob doesn't exist,
  ///          otherwise returns pointer to blob
  void *getblob(
        void *buf,
        size_t *bufsize,
        nodeidx_t _start,
        uchar tag)
  {
    return netnode_getblob(*this, buf, bufsize, _start, tag);
  }
  void *getblob_ea(
        void *buf,
        size_t *bufsize,
        ea_t ea,
        uchar tag)
  {
    return netnode_getblob(*this, buf, bufsize, ea, tag|NETMAP_IDX);
  }

  /// Get blob from a netnode.
  /// \param blob   output ::qvector buffer
  /// \param _start index of the first supval element used to store blob
  /// \param tag    tag of supval array
  /// \return -1 if blob doesn't exist, size of blob otherwise
  template <class T>
  ssize_t getblob(
        qvector<T> *blob,
        nodeidx_t _start,
        uchar tag)
  {
    return netnode_qgetblob(*this, (bytevec_t *)blob, sizeof(T), _start, tag);
  }
  template <class T>
  ssize_t getblob_ea(
        qvector<T> *blob,
        ea_t ea,
        uchar tag)
  {
    return netnode_qgetblob(*this, (bytevec_t *)blob, sizeof(T), nodeidx_t(ea), tag|NETMAP_IDX);
  }

  /// Get blob from a netnode into a qstring* and make sure the string is
  /// null-terminated.
  /// \param buf    output ::qstring buffer
  /// \param _start index of the first supval element used to store blob
  /// \param tag    tag of supval array
  /// \return -1 if blob doesn't exist
  ///         size of string (including terminating null) otherwise
  ssize_t getblob(
        qstring *buf,
        nodeidx_t _start,
        uchar tag)
  {
    return netnode_qgetblob(*this, (bytevec_t *)buf, 1, _start, tag|NETMAP_STR);
  }

  /// Store a blob in a netnode.
  /// \param buf      pointer to blob to save
  /// \param size     size of blob in bytes
  /// \param _start   index of the first supval element used to store blob
  /// \param tag      tag of supval array
  /// \return success
  bool setblob(
        const void *buf,
        size_t size,
        nodeidx_t _start,
        uchar tag)
  {
    return netnode_setblob(*this, buf, size, _start, tag);
  }
  bool setblob_ea(
        const void *buf,
        size_t size,
        ea_t ea,
        uchar tag)
  {
    return netnode_setblob(*this, buf, size, ea, tag|NETMAP_IDX);
  }

  /// Delete a blob.
  /// \param _start  index of the first supval element used to store blob
  /// \param tag     tag of supval array
  /// \return number of deleted supvals
  int delblob(nodeidx_t _start, uchar tag)
  {
    return netnode_delblob(*this, _start, tag);
  }
  int delblob_ea(ea_t ea, uchar tag)
  {
    return netnode_delblob(*this, ea, tag|NETMAP_IDX);
  }

  /// Shift the blob array elements.
  /// Moves the array elements at (from..from+size) to (to..to+size)
  /// \return number of shifted elements
  size_t blobshift(nodeidx_t from, nodeidx_t to, nodeidx_t size, uchar tag)
  {
    return netnode_blobshift(*this, from, to, size, tag);
  }

  //@}

  //--------------------------------------------------------------------------
  /// \name Enumerate all netnodes
  //@{

  /// Get first netnode in the graph.
  /// Sets netnodenumber to the lowest existing number.
  /// \retval true  ok
  /// \retval false graph is empty
  bool start(void)
  {
    return netnode_start(this);
  }

  /// Get last netnode in the graph.
  /// Sets netnodenumber to the highest existing number.
  /// \retval true  ok
  /// \retval false graph is empty
  bool end(void)
  {
    return netnode_end(this);
  }

  /// Get next netnode in the graph.
  /// Sets netnodenumber to the next existing number
  /// \retval true  ok
  /// \retval false no more netnodes
  bool next(void)
  {
    return netnode_next(this);
  }

  /// Get prev netnode in the graph.
  /// Sets netnodenumber to the previous existing number
  /// \retval true  ok
  /// \retval false no more netnodes
  bool prev(void)
  {
    return netnode_prev(this);
  }

  //@}

  //--------------------------------------------------------------------------
  /// \name Move and copy netnodes
  /// \param destnode  the destination netnode
  /// \param count   how many netnodes to copy
  /// \return number of copied/moved keys, #BADNODE if failure or not enough memory
  //@{
  size_t copyto(netnode destnode, nodeidx_t count=1) { return netnode_copy(netnodenumber, count, destnode.netnodenumber, false); }
  size_t moveto(netnode destnode, nodeidx_t count=1) { return netnode_copy(netnodenumber, count, destnode.netnodenumber, true); }
  //@}

  //--------------------------------------------------------------------------
  /// \name Netnode comparisons
  //@{
  bool operator==(netnode &n) const { return netnodenumber == n.netnodenumber; }
  bool operator!=(netnode &n) const { return netnodenumber != n.netnodenumber; }
  bool operator==(nodeidx_t x) const { return netnodenumber == x; }
  bool operator!=(nodeidx_t x) const { return netnodenumber != x; }
  //@}


  static bool inited(void)       { return netnode_inited(); }
  static bool is_available(void) { return netnode_is_available(); }

private:
  // The netnode number.
  // Usually this is the linear address that the netnode keeps information about.
  nodeidx_t netnodenumber;
};
#ifdef __EA64__
CASSERT(sizeof(netnode) == 8);
#else
CASSERT(sizeof(netnode) == 4);
#endif

//-----------------------------------------------------------------------

/// The root node is used by the kernel, do not use it directly in your modules.
/// Its name: "Root Node"
#if !defined(NO_OBSOLETE_FUNCS) || defined(__DEFINE_ROOT_NODE__)
idaman netnode ida_export_data root_node;
#endif


#endif // _NETNODE_HPP
