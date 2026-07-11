
/*! \file dirtree.hpp

  \brief Types involved in grouping of item into folders

  The dirtree_t class is used to organize a directory tree on top of any
  collection that allows for accessing its elements by an id (inode).

  No requirements are imposed on the inodes apart from the forbidden
  value -1 (it is used ot denote a bad inode).

  The dirspec_t class is used to specialize the dirtree.
  It can be used to introduce a directory structure for:
    - local types
    - structs
    - enums
    - functions
    - names
    - etc

  \note you should be manipulating \ref dirtree_t (and, if implementing a
        new tree backend, \ref dirspec_t) instances, not calling top-level
        functions in this file directly.
*/

#ifndef DIRTREE_HPP
#define DIRTREE_HPP

//------------------------------------------------------------------------
typedef qvector<inode_t> inodevec_t; // sequence of inodes

/// Directory indexes are simple numbers like 0,1,2,3...
/// They are independent of inode numbers.
/// The root directory always exists and has the index 0 (\ref direntry_t::ROOTIDX).
typedef uval_t diridx_t;
typedef qvector<diridx_t> dirvec_t; // sequence of directory indexes

/// Blob index, used for storing/restoring dirtree_t information
typedef ea_t blob_idx_t;
#define BAD_BLOB_IDX blob_idx_t(-1)

// We use PACKED to save memory, without it we would spend 64 bits instead of
// 8 bits to store a 1-bit value on ida64.
#pragma pack(push, 1)

/// Directory entry: either a file or directory
struct PACKED direntry_t
{
  uval_t idx;   ///< diridx_t or inode_t
  bool isdir;   ///< is 'idx' a diridx_t, or an inode_t

  static const uval_t BADIDX = uval_t(-1);
  static const uval_t ROOTIDX = 0;

  direntry_t(uval_t i=BADIDX, bool d=false) : idx(i), isdir(d) {}
  bool valid() const { return idx != BADIDX; }

  bool operator==(const direntry_t &r) const
  {
    return idx == r.idx && isdir == r.isdir;
  }
  bool operator!=(const direntry_t &r) const
  {
    return !(*this == r);
  }
  bool operator<(const direntry_t &r) const
  {
    if ( !isdir && r.isdir )
      return true;
    if ( isdir && !r.isdir )
      return false;
    return idx < r.idx;
  }
};
#pragma pack(pop)
DECLARE_TYPE_AS_MOVABLE(direntry_t);
typedef qvector<direntry_t> direntry_vec_t;

/// \defgroup DTN_ bits for get_...name() methods
//@{
enum
{
  DTN_FULL_NAME    = 0x00,  ///< use long form of the entry name.
                            ///< That name is unique.
  DTN_DISPLAY_NAME = 0x01,  ///< use short, displayable form of the entry name.
                            ///< for example, 'std::string' instead of
                            ///< 'std::basic_string<char, ...>'. Note that more
                            ///< than one "full name" can have the same
                            ///< displayable name.
};
//@}

//------------------------------------------------------------------------
/// Directory tree specialization. This is an abstract base class that
/// represents 'file items' of our directory structure.
struct dirspec_t
{
  uint32 flags;
  enum
  {
    DSF_INODE_EA  = 0x01,  // inode is EA, will be handled during segment moving
    DSF_PRIVRANGE = 0x02,  // inode is tid_t, structure or enum id, will be handled during segment moving
  };
  // netnode name to load/save directory tree
  // if not specified the loading/storing operations are not supported
  qstring id;

  dirspec_t(const char *nm=nullptr, uint32 f=0) : flags(f), id(nm) {}

  virtual ~dirspec_t() {}

  /// get the entry name. for example, the structure name
  /// \param[out] out may be nullptr; in this case get_name can be used to validate an inode.
  /// \param inode inode number of the entry
  /// \param name_flags how exactly the name should be retrieved.
  ///                   combination of \ref DTN_ bits
  /// \return false if the entry does not exist.
  virtual bool get_name(
        qstring *out,
        inode_t inode,
        uint32 name_flags=DTN_FULL_NAME) = 0;

  /// get the entry inode in the specified directory
  /// \param dirpath  the absolute directory path with trailing slash
  /// \param name     the entry name in the directory
  /// \return the entry inode
  virtual inode_t get_inode(const char *dirpath, const char *name) = 0;

  // print additional attributes of the entry. for example, is union? is mapped?
  virtual qstring get_attrs(inode_t inode) const = 0;

  /// rename the entry
  /// \param inode
  /// \param newname
  /// \return success
  virtual bool rename_inode(inode_t inode, const char *newname) = 0;

  /// event: unlinked an inode
  /// \param inode
  virtual void unlink_inode(inode_t inode) { qnotused(inode); }
};

//------------------------------------------------------------------------
/// Position in the directory tree
struct dirtree_cursor_t
{
  diridx_t parent; ///< the parent directory
  size_t rank;     ///< the index into the parent directory
  dirtree_cursor_t(diridx_t _parent=direntry_t::BADIDX, size_t _rank=size_t(-1))
    : parent(_parent), rank(_rank) {}
  bool valid() const { return parent != direntry_t::BADIDX || rank == 0; }
  bool is_root_cursor() const { return parent == direntry_t::BADIDX && rank == 0; }
  void set_root_cursor(void) { parent = direntry_t::BADIDX; rank = 0; }

  static dirtree_cursor_t root_cursor()
  {
    dirtree_cursor_t c;
    c.set_root_cursor();
    return c;
  }

  DECLARE_COMPARISONS(dirtree_cursor_t)
  {
    if ( parent < r.parent ) return -1;
    if ( parent > r.parent ) return 1;
    if ( rank < r.rank ) return -1;
    if ( rank > r.rank ) return 1;
    return 0;
  }
};
DECLARE_TYPE_AS_MOVABLE(dirtree_cursor_t);
typedef qvector<dirtree_cursor_t> dirtree_cursor_vec_t;

//-------------------------------------------------------------------------
struct dirtree_selection_t : public dirtree_cursor_vec_t {};

//------------------------------------------------------------------------
/// Helper class to iterate over files
struct dirtree_iterator_t
{
  qstring pattern;
  dirtree_cursor_t cursor;
};

//------------------------------------------------------------------------
/// Directory tree: error codes
enum dterr_t
{
  DTE_OK,               // ok
  DTE_ALREADY_EXISTS,   // item already exists
  DTE_NOT_FOUND,        // item not found
  DTE_NOT_DIRECTORY,    // item is not a directory
  DTE_NOT_EMPTY,        // directory is not empty
  DTE_BAD_PATH,         // invalid path
  DTE_CANT_RENAME,      // failed to rename an item
  DTE_OWN_CHILD,        // moving inside subdirectory of itself
  DTE_MAX_DIR,          // maximum directory count achieved
  DTE_LAST,
};

class dirtree_t;
class dirtree_impl_t;
struct segm_move_infos_t;

//-------------------------------------------------------------------------
/// A visitor, for use with dirtree_t::traverse
struct dirtree_visitor_t
{
  /// Will be called for each entry in the dirtree_t
  /// If something other than 0 is returned, iteration
  /// will stop.
  /// \param c the current cursor
  /// \param de the current entry
  /// \return 0 to keep iterating, or anything else to stop
  virtual ssize_t visit(
        const dirtree_cursor_t &c,
        const direntry_t &de) = 0;
};


/// \cond
//------------------------------------------------------------------------
// internal functions; use dirtree_t members instead
#ifndef SWIG
idaman dirtree_impl_t *ida_export create_dirtree(dirtree_t *dt, dirspec_t *ds);
idaman void ida_export delete_dirtree(dirtree_impl_t *d);
idaman bool ida_export load_dirtree(dirtree_impl_t *d);
idaman bool ida_export save_dirtree(dirtree_impl_t *d);
void reset_dirtree(dirtree_impl_t *d);
idaman const char *ida_export dirtree_errstr(dterr_t err);
idaman dterr_t ida_export dirtree_chdir(dirtree_impl_t *d, const char *path);
idaman void ida_export dirtree_getcwd(qstring *out, const dirtree_impl_t *d);
idaman void ida_export dirtree_resolve_path(direntry_t *de, const dirtree_impl_t *d, const char *path);
idaman void ida_export dirtree_resolve_cursor(direntry_t *de, const dirtree_impl_t *d, const dirtree_cursor_t &cursor);
idaman bool ida_export dirtree_get_entry_name(qstring *out, const dirtree_impl_t *d, const direntry_t &de, uint32 name_flags);
idaman void ida_export dirtree_get_entry_attrs(qstring *out, const dirtree_impl_t *d, const direntry_t &de);
idaman ssize_t ida_export dirtree_get_dir_size(dirtree_impl_t *d, diridx_t diridx);
idaman bool ida_export dirtree_findfirst(dirtree_impl_t *d, dirtree_iterator_t *ff, const char *pattern);
idaman bool ida_export dirtree_findnext(dirtree_impl_t *d, dirtree_iterator_t *ff);
idaman bool ida_export dirtree_get_abspath_by_cursor(qstring *out, const dirtree_impl_t *d, const dirtree_cursor_t &cursor);
idaman bool ida_export dirtree_get_abspath_by_relpath(qstring *out, const dirtree_impl_t *d, const char *relpath);
idaman dterr_t ida_export dirtree_mkdir(dirtree_impl_t *d, const char *path);
idaman dterr_t ida_export dirtree_rmdir(dirtree_impl_t *d, const char *path);
idaman dterr_t ida_export dirtree_link(dirtree_impl_t *d, const char *path, bool do_link);
idaman dterr_t ida_export dirtree_link_inode(dirtree_impl_t *d, inode_t inode, bool do_link);
idaman dterr_t ida_export dirtree_rename(dirtree_impl_t *d, const char *from, const char *to);
idaman ssize_t ida_export dirtree_get_rank(const dirtree_impl_t *d, diridx_t diridx, const direntry_t &de);
idaman dterr_t ida_export dirtree_change_rank(dirtree_impl_t *d, const char *path, ssize_t rank_delta);
idaman void ida_export dirtree_get_parent_cursor(dirtree_cursor_t *out, const dirtree_impl_t *d, const dirtree_cursor_t &cursor);
idaman void ida_export notify_dirtree(dirtree_impl_t *d, bool added, inode_t inode);
idaman const char *ida_export dirtree_get_id(const dirtree_impl_t *d);
idaman void ida_export dirtree_set_id(dirtree_impl_t *d, const char *nm);
idaman const char *ida_export dirtree_get_nodename(const dirtree_impl_t *d);   // compat
idaman void ida_export dirtree_set_nodename(dirtree_impl_t *d, const char *nm);// compat
idaman ssize_t ida_export dirtree_traverse(dirtree_impl_t *d, dirtree_visitor_t &v);
idaman dterr_t ida_export dirtree_find_entry(dirtree_cursor_t *out, const dirtree_t *_dt, const direntry_t &_de);
#endif // SWIG




/// \endcond

//------------------------------------------------------------------------
/// Directory tree.
/// This class organizes a virtual directory tree over items that
/// are represented by dirspec_t.
class dirtree_t
{
  dirtree_impl_t *d;


public:
  //lint -sem(dirtree_t::dirtree_t, custodial(1))
  dirtree_t(dirspec_t *ds) { d = create_dirtree(this, ds); }
  ~dirtree_t() { delete_dirtree(d); }

  /// Get textual representation of the error code
  static const char *errstr(dterr_t err) { return dirtree_errstr(err); }

  /// Change current directory
  /// \param path new current directory
  /// \return \ref dterr_t error code
  dterr_t chdir(const char *path) { return dirtree_chdir(d, path); }

  /// Get current directory
  /// \return the current working directory
  qstring getcwd() const
  {
    qstring out;
    dirtree_getcwd(&out, d);
    return out;
  }

  /// Get absolute path pointed by the cursor
  /// \param cursor
  /// \return path; empty string if error
  /// \note see also resolve_cursor()
  qstring get_abspath(const dirtree_cursor_t &cursor) const
  {
    qstring out;
    dirtree_get_abspath_by_cursor(&out, d, cursor);
    return out;
  }

  /// Construct an absolute path from the specified relative path.
  /// This function verifies the directory part of the specified path.
  /// The last component of the specified path is not verified.
  /// \param relpath relative path
  /// \return path. empty path means wrong directory part of RELPATH
  qstring get_abspath(const char *relpath) const
  {
    qstring out;
    dirtree_get_abspath_by_relpath(&out, d, relpath);
    return out;
  }

  /// Resolve cursor
  /// \param cursor to analyze
  /// \return directory entry;
  ///         if the cursor is bad, the resolved entry will be invalid.
  /// \note see also get_abspath()
  direntry_t resolve_cursor(const dirtree_cursor_t &cursor) const
  {
    direntry_t de;
    dirtree_resolve_cursor(&de, d, cursor);
    return de;
  }

  /// Resolve path
  /// \param path to analyze
  /// \return directory entry
  direntry_t resolve_path(const char *path) const
  {
    direntry_t de;
    dirtree_resolve_path(&de, d, path);
    return de;
  }

  static bool isdir(const direntry_t &de) { return de.valid() && de.isdir; }
  static bool isfile(const direntry_t &de) { return de.valid() && !de.isdir; }

  /// Is a directory?
  /// \param path to analyze
  /// \return true if the specified path is a directory
  bool isdir(const char *path) const
  {
    direntry_t de = resolve_path(path);
    return isdir(de);
  }

  /// Is a file?
  /// \param path to analyze
  /// \return true if the specified path is a file
  bool isfile(const char *path) const
  {
    direntry_t de = resolve_path(path);
    return isfile(de);
  }

  /// Get entry name
  /// \param de         directory entry
  /// \param name_flags how exactly the name should be retrieved.
  ///                   combination of \ref DTN_ bits
  /// \return name
  qstring get_entry_name(
        const direntry_t &de,
        uint32 name_flags=DTN_FULL_NAME) const
  {
    qstring out;
    dirtree_get_entry_name(&out, d, de, name_flags);
    return out;
  }

  /// Get dir size
  /// \param diridx directory index
  /// \return number of entries under this directory;
  ///         if error, return -1
  ssize_t get_dir_size(diridx_t diridx) const { return dirtree_get_dir_size(d, diridx); }

  /// Get entry attributes
  /// \param de directory entry
  /// \return name
  qstring get_entry_attrs(const direntry_t &de) const
  {
    qstring out;
    dirtree_get_entry_attrs(&out, d, de);
    return out;
  }

  /// Start iterating over files in a directory
  /// \param ff directory iterator. it will be initialized by the function
  /// \param pattern pattern to search for
  /// \return success
  bool findfirst(dirtree_iterator_t *ff, const char *pattern) const
  {
    return dirtree_findfirst(d, ff, pattern);
  }

  /// Continue iterating over files in a directory
  /// \param ff directory iterator
  /// \return success
  bool findnext(dirtree_iterator_t *ff) const
  {
    return dirtree_findnext(d, ff);
  }

  /// Create a directory.
  /// \param path directory to create
  /// \return \ref dterr_t error code
  dterr_t mkdir(const char *path) { return dirtree_mkdir(d, path); }

  /// Remove a directory.
  /// \param path directory to delete
  /// \return \ref dterr_t error code
  dterr_t rmdir(const char *path) { return dirtree_rmdir(d, path); }

  /// Add a file item into a directory.
  /// \param path path to item to add to a directory
  /// \return \ref dterr_t error code
  dterr_t link(const char *path) { return dirtree_link(d, path, true); }

  /// Remove a file item from a directory.
  /// \param path path to item remove from a directory
  /// \return \ref dterr_t error code
  dterr_t unlink(const char *path) { return dirtree_link(d, path, false); }

  /// Add an inode into the current directory
  /// \param inode
  /// \return \ref dterr_t error code
  dterr_t link(inode_t inode) { return dirtree_link_inode(d, inode, true); }

  /// Remove an inode from the current directory
  /// \param inode
  /// \return \ref dterr_t error code
  dterr_t unlink(inode_t inode) { return dirtree_link_inode(d, inode, false); }

  /// Rename a directory entry.
  /// \param from source path
  /// \param to destination path
  /// \return \ref dterr_t error code
  /// \note This function can also rename the item
  dterr_t rename(const char *from, const char *to)
  {
    return dirtree_rename(d, from, to);
  }

  /// Get ordering rank of an item.
  /// \param diridx index of the parent directory
  /// \param de directory entry
  /// \return number in a range of [0..n) where n is the number of entries in
  ///         the parent directory. -1 if error
  ssize_t get_rank(diridx_t diridx, const direntry_t &de) const
  {
    return dirtree_get_rank(d, diridx, de);
  }

  /// Change ordering rank of an item.
  /// \param path path to the item
  /// \param rank_delta the amount of the change. positive numbers mean to
  ///              move down in the list; negative numbers mean to move up.
  /// \return \ref dterr_t error code
  /// \note All subdirectories go before all file entries.
  dterr_t change_rank(const char *path, ssize_t rank_delta)
  {
    return dirtree_change_rank(d, path, rank_delta);
  }

  /// Get parent cursor.
  /// \param cursor a valid ditree cursor
  /// \return cursor's parent
  dirtree_cursor_t get_parent_cursor(const dirtree_cursor_t &cursor) const
  {
    dirtree_cursor_t parent;
    dirtree_get_parent_cursor(&parent, d, cursor);
    return parent;
  }

  /// Load the tree structure from the netnode.
  /// If dirspec_t::id is empty, the operation will be considered a success.
  /// In addition, calling load() more than once will not do anything,
  /// and will be considered a success.
  /// \return success
  /// \see dirspec_t::id.
  bool load()
  {
    return load_dirtree(d);
  }

  /// Save the tree structure to the netnode.
  /// \return success
  /// \see dirspec_t::id.
  bool save() const
  {
    return save_dirtree(d);
  }

  /// netnode name
  const char *get_id() const
  {
    return dirtree_get_id(d);
  }

  void set_id(const char *nm)
  {
    return dirtree_set_id(d, nm);
  }

  /// Notify dirtree about a change of an inode.
  /// \param added are we adding or deleting an inode?
  /// \param inode inode in question
  void notify_dirtree(bool added, inode_t inode)
  {
    ::notify_dirtree(d, added, inode);
  }

  /// Traverse dirtree, and be notified at each entry
  /// If the the visitor returns anything other than 0,
  /// iteration will stop, and that value returned.
  /// The tree is traversed using a depth-first algorithm.
  /// It is forbidden to modify the dirtree_t during traversal;
  /// doing so will result in undefined behavior.
  /// \param v the callback
  /// \return 0, or whatever the visitor returned
  ssize_t traverse(dirtree_visitor_t &v) const
  {
    return dirtree_traverse(d, v);
  }

  /// Find the cursor corresponding to an entry of a directory
  /// \param de directory entry
  /// \return cursor corresponding to the directory entry
  dirtree_cursor_t find_entry(const direntry_t &de) const
  {
    dirtree_cursor_t c;
    dirtree_find_entry(&c, this, de);
    return c;
  }

};

/// Built-in dirtree specializations:
enum dirtree_id_t
{
  DIRTREE_LOCAL_TYPES,
  DIRTREE_STRUCTS,
  DIRTREE_ENUMS,
  DIRTREE_FUNCS,
  DIRTREE_NAMES,
  DIRTREE_IMPORTS,
  DIRTREE_IDAPLACE_BOOKMARKS,
  DIRTREE_STRUCTS_BOOKMARKS,
  DIRTREE_ENUMS_BOOKMARKS,
  DIRTREE_BPTS,
  DIRTREE_END,
};
idaman dirtree_t *ida_export get_std_dirtree(dirtree_id_t id);


#endif // define DIRTREE_HPP
