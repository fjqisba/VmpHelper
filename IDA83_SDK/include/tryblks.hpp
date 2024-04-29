/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 2016-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *  Module independent exception description
 */

#ifndef TRYBLKS_HPP
#define TRYBLKS_HPP

/*! \file tryblks.hpp
 *
 * \brief Architecture independent exception handling info.
 *
 * Try blocks have the following general properties:
 * - A try block specifies a possibly fragmented guarded code region.
 * - Each try block has always at least one catch/except block description
 * - Each catch block contains its boundaries and a filter.
 * - Additionally a catch block can hold sp adjustment and the offset to the
 *   exception object offset (C++).
 * - Try blocks can be nested. Nesting is automatically calculated at the retrieval time.
 * - There may be (nested) multiple try blocks starting at the same address.
 *
 * See examples in tests/input/src/eh_tests.
 *
 */

// We use end_ea=BADADDR if the exact boundaries are unknown of any range.

//----------------------------------------------------------------------------
// An exception handler clause (the body of __except or catch statement)
struct try_handler_t : public rangevec_t
{
  sval_t disp;    // displacement to the stack region of the guarded region.
                  // if it is valid, it is fpreg relative.
                  // -1 means unknown.
  int fpreg;      // frame register number used in handler. -1 means none.

  try_handler_t() : disp(-1), fpreg(-1) {}
  void clear(void)
  {
    rangevec_t::clear();
    disp = -1;
    fpreg = -1;
  }
};
DECLARE_TYPE_AS_MOVABLE(try_handler_t);

//----------------------------------------------------------------------------
// __except() {} statement
struct seh_t : public try_handler_t
{
  rangevec_t filter; // boundaries of the filter callback. if filter is empty,
  ea_t seh_code;    // then use seh_code
#define SEH_CONTINUE BADADDR // EXCEPTION_CONTINUE_EXECUTION (-1)
#define SEH_SEARCH   ea_t(0) // EXCEPTION_CONTINUE_SEARCH (0) (alias of __finally)
#define SEH_HANDLE   ea_t(1) // EXCEPTION_EXECUTE_HANDLER (1)
  void clear(void)
  {
    try_handler_t::clear();
    filter.clear();
    seh_code = SEH_CONTINUE;
  }
};
DECLARE_TYPE_AS_MOVABLE(seh_t);

//----------------------------------------------------------------------------
// catch() {} statement
struct catch_t : public try_handler_t
{
  sval_t obj;  // fpreg relative displacement to the exception object. -1 if unknown.
  sval_t type_id; // the type caught by this catch. -1 means "catch(...)"
#define CATCH_ID_ALL     sval_t(-1) // catch(...)
#define CATCH_ID_CLEANUP sval_t(-2) // a cleanup handler invoked if exception occures

  catch_t() : obj(-1), type_id(-1) {}
};
DECLARE_TYPE_AS_MOVABLE(catch_t);
typedef qvector<catch_t> catchvec_t;

//----------------------------------------------------------------------------
class tryblk_t : public rangevec_t // block guarded by try/__try {...} statements
{
#ifndef SWIG
  char reserve[qmax(sizeof(catchvec_t), sizeof(seh_t))]; // seh_t or catchvec_t
#endif
  uchar cb;       // size of tryblk_t
  uchar kind;     // one of the following kinds
#define TB_NONE 0 // empty
#define TB_SEH  1 // MS SEH __try/__except/__finally
#define TB_CPP  2 // C++ language try/catch

public:
  uchar level;      // nesting level, calculated by get_tryblks()

  // C++ try/catch block (TB_CPP)
  catchvec_t &cpp()             { return *((      catchvec_t *)reserve); }
  const catchvec_t &cpp() const { return *((const catchvec_t *)reserve); }

  // SEH __except/__finally case (TB_SEH)
  seh_t &seh()             { return *((      seh_t *)reserve); }
  const seh_t &seh() const { return *((const seh_t *)reserve); }

  tryblk_t() : rangevec_t(), cb(sizeof(*this)), kind(TB_NONE), level(0) { reserve[0] = '\0'; }
  ~tryblk_t() { clear(); }
  tryblk_t(const tryblk_t &r) : rangevec_t(), kind(TB_NONE) { *this = r; }
  uchar get_kind(void) const { return kind; }
  bool empty(void) const { return kind == TB_NONE || size() == 0; }
  bool is_seh(void) const { return kind == TB_SEH; }
  bool is_cpp(void) const { return kind == TB_CPP; }


  //-------------------------------------------------------------------------
  tryblk_t &operator=(const tryblk_t &r)
  {
    if ( this != &r ) // don't copy yourself
    {
      if ( kind != TB_NONE )
        clear();
      kind = r.kind;
      level = r.level;
      rangevec_t::operator=(r);

      if ( kind == TB_SEH )
        new (reserve) seh_t(r.seh());
      else if ( kind == TB_CPP )
        new (reserve) catchvec_t(r.cpp());
    }
    return *this;
  }

  //-------------------------------------------------------------------------
  void clear(void)
  {
    if ( kind == TB_CPP )
      cpp().~catchvec_t();
    else if ( kind == TB_SEH )
      seh().~seh_t();
    kind = TB_NONE;
  }

  //-------------------------------------------------------------------------
  seh_t &set_seh(void)
  {
    if ( kind != TB_SEH )
    {
      clear();
      new (reserve) seh_t;
      kind = TB_SEH;
    }
    else
    {
      seh().clear();
    }
    return seh();
  }

  //-------------------------------------------------------------------------
  catchvec_t &set_cpp(void)
  {
    if ( kind != TB_CPP )
    {
      clear();
      new (reserve) catchvec_t;
      kind = TB_CPP;
    }
    else
    {
      cpp().clear();
    }
    return cpp();
  }
};
DECLARE_TYPE_AS_MOVABLE(tryblk_t);
typedef qvector<tryblk_t> tryblks_t;

///-------------------------------------------------------------------------
/// Retrieve try block information from the specified address range.
/// Try blocks are sorted by starting address and their nest levels calculated.
/// \param tbv    output buffer; may be nullptr
/// \param range  address range to change
/// \return number of found try blocks

idaman size_t ida_export get_tryblks(tryblks_t *tbv, const range_t &range);

/// Delete try block information in the specified range.
/// \param range    the range to be cleared

idaman void ida_export del_tryblks(const range_t &range);


/// Add one try block information.
/// \param tb  try block to add.
/// \return error code; 0 means good

idaman int ida_export add_tryblk(const tryblk_t &tb);

/// \defgroup TBERR_ Try block handling error codes
//@{
#define TBERR_OK         0 ///< ok
#define TBERR_START      1 ///< bad start address
#define TBERR_END        2 ///< bad end address
#define TBERR_ORDER      3 ///< bad address order
#define TBERR_EMPTY      4 ///< empty try block
#define TBERR_KIND       5 ///< illegal try block kind
#define TBERR_NO_CATCHES 6 ///< no catch blocks at all
#define TBERR_INTERSECT  7 ///< range would intersect inner tryblk
//@}

/// Find the start address of the system eh region including the argument.
/// \param ea search address
/// \return start address of surrounding tryblk, otherwise BADADDR

idaman ea_t ida_export find_syseh(ea_t ea);


/// \defgroup TBEA_ flags for is_ea_tryblks()
//@{
#define TBEA_TRY      0x01 // is ea within a c++ try block?
#define TBEA_CATCH    0x02 // is ea start of a c++ catch/cleanup block?
#define TBEA_SEHTRY   0x04 // is ea within a seh try block
#define TBEA_SEHLPAD  0x08 // is ea start of a seh finally/except block?
#define TBEA_SEHFILT  0x10 // is ea start of a seh filter?
#define TBEA_ANY      0x1f
#define TBEA_FALLTHRU 0x20 // is there a fall through into provided ea from an unwind region
//@}

/// Check if the given address ea is part of tryblks description.
/// \param ea    address to check
/// \param flags combination of \ref TBEA_
idaman bool ida_export is_ea_tryblks(ea_t ea, uint32 flags);


#endif // TRYBLKS_HPP
