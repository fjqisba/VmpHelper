/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef BYTES_HPP
#define BYTES_HPP

#include <nalt.hpp>
#include <lines.hpp>
#include <range.hpp>

typedef tid_t enum_t;   // #include <enum.hpp>
class insn_t;

/*! \file bytes.hpp

  \brief Contains functions that deal with individual byte characteristics.

  Each byte of the disassembled program is represented by a 32-bit
  value. We will call this value 'flags'. The structure of the flags is
  here.

  You are not allowed to inspect individual bits of flags and modify them directly.
  Use special functions to inspect and/or modify flags.

  Flags are kept in a virtual array file (*.id1).
  Addresses (ea) are all 32-bit (or 64-bit) quantities.
*/

//--------------------------------------------------------------------------
/// Allocate flags for address range.
/// This function does not change the storage type of existing ranges.
/// Exit with an error message if not enough disk space.
/// \param start_ea  should be lower than end_ea.
/// \param end_ea    does not belong to the range.
/// \param stt      ::storage_type_t
/// \return 0 if ok, otherwise an error code

idaman error_t ida_export enable_flags(ea_t start_ea, ea_t end_ea, storage_type_t stt);


/// Deallocate flags for address range.
/// Exit with an error message if not enough disk space (this may occur too).
/// \param start_ea  should be lower than end_ea.
/// \param end_ea    does not belong to the range.
/// \return 0 if ok, otherwise return error code

idaman error_t ida_export disable_flags(ea_t start_ea, ea_t end_ea);


/// Change flag storage type for address range.
/// \param start_ea  should be lower than end_ea.
/// \param end_ea    does not belong to the range.
/// \param stt      ::storage_type_t
/// \return error code

idaman error_t ida_export change_storage_type(ea_t start_ea, ea_t end_ea, storage_type_t stt);


/// Get next address in the program (i.e. next address which has flags).
/// \return #BADADDR if no such address exist.

idaman ea_t ida_export next_addr(ea_t ea);


/// Get previous address in the program.
/// \return #BADADDR if no such address exist.

idaman ea_t ida_export prev_addr(ea_t ea);


/// Get the first address of next contiguous chunk in the program.
/// \return #BADADDR if next chunk doesn't exist.

idaman ea_t ida_export next_chunk(ea_t ea);


/// Get the last address of previous contiguous chunk in the program.
/// \return #BADADDR if previous chunk doesn't exist.

idaman ea_t ida_export prev_chunk(ea_t ea);


/// Get start of the contiguous address block containing 'ea'.
/// \return #BADADDR if 'ea' doesn't belong to the program.

idaman ea_t ida_export chunk_start(ea_t ea);


/// Get size of the contiguous address block containing 'ea'.
/// \return 0 if 'ea' doesn't belong to the program.

idaman asize_t ida_export chunk_size(ea_t ea);


/// Search for a hole in the addressing space of the program.
/// \param start     Address to start searching from
/// \param size      Size of the desired empty range
/// \param alignment Alignment bitmask, must be a pow2-1.
///                  (for example, 0xF would align the returned range to 16 bytes).
/// \return Start of the found empty range or #BADADDR

idaman ea_t ida_export find_free_chunk(ea_t start, asize_t size, asize_t alignment);


/// Flag tester - see next_that(), prev_that()
typedef bool idaapi testf_t(flags64_t flags, void *ud);


/// Find next address with a flag satisfying the function 'testf'.
/// \note do not pass is_unknown() to this function to find unexplored bytes.
/// It will fail under the debugger. To find unexplored bytes, use next_unknown().
/// \param ea     start searching at this address + 1
/// \param maxea  not included in the search range.
/// \param testf  test function to find next address
/// \param ud     user data - may point to anything. it will be passed to testf.
/// \return the found address or #BADADDR.

idaman ea_t ida_export next_that(
        ea_t ea,
        ea_t maxea,
        testf_t *testf,
        void *ud=nullptr);


/// Similar to next_that(), but will find the next address that is unexplored

inline ea_t idaapi next_unknown(ea_t ea, ea_t maxea)
{
  return next_that(ea, maxea, nullptr);
}


/// Find previous address with a flag satisfying the function 'testf'.
/// \note do not pass is_unknown() to this function to find unexplored bytes
/// It will fail under the debugger. To find unexplored bytes, use prev_unknown().
/// \param ea     start searching from this address - 1.
/// \param minea  included in the search range.
/// \param testf  test function to find previous address
/// \param ud     user data - may point to anything. it will be passed to testf.
/// \return the found address or #BADADDR.

idaman ea_t ida_export prev_that(
        ea_t ea,
        ea_t minea,
        testf_t *testf,
        void *ud=nullptr);


/// Similar to prev_that(), but will find the previous address that is unexplored

inline ea_t idaapi prev_unknown(ea_t ea, ea_t minea)
{
  return prev_that(ea, minea, nullptr);
}


/// Get start of previous defined item.
/// \param ea     begin search at this address
/// \param minea  included in the search range
/// \return #BADADDR if none exists.

idaman ea_t ida_export prev_head(ea_t ea, ea_t minea);


/// Get start of next defined item.
/// \param ea     begin search at this address
/// \param maxea  not included in the search range
/// \return #BADADDR if none exists.

idaman ea_t ida_export next_head(ea_t ea, ea_t maxea);


/// Get address of previous non-tail byte.
/// \return #BADADDR if none exists.

idaman ea_t ida_export prev_not_tail(ea_t ea);


/// Get address of next non-tail byte.
/// \return #BADADDR if none exists.

idaman ea_t ida_export next_not_tail(ea_t ea);


/// Adjust the address and get the nearest visible address.
/// (i.e. an address which will appear in the disassembly)
/// \return #BADADDR only if no addresses are valid

ea_t adjust_visea(ea_t ea);


/// Get previous visible address.
/// \return #BADADDR if none exists.

idaman ea_t ida_export prev_visea(ea_t ea);


/// Get next visible address.
/// \return #BADADDR if none exists.

idaman ea_t ida_export next_visea(ea_t ea);


/// Is an address the first visible address?

bool is_first_visea(ea_t ea);


/// Is an address the last visible address?

bool is_last_visea(ea_t ea);


/// Is the address visible on the screen (not hidden)?

bool is_visible_finally(ea_t ea); // do we need to show anything
                                  // at this address?



/// Get the start address of the item at 'ea'.
/// If there is no current item, then 'ea' will be returned
/// (see definition at the end of bytes.hpp source)

inline ea_t idaapi get_item_head(ea_t ea);


/// Get the end address of the item at 'ea'. The returned address
/// doesn't belong to the current item. Unexplored bytes are counted as
/// 1 byte entities.

idaman ea_t ida_export get_item_end(ea_t ea);


/// Calculate maximal reasonable end address of a new item.
/// This function will limit the item with the current segment bounds.
/// \param ea   linear address
/// \param how  when to stop the search. A combination of \ref ITEM_END_
/// \return     end of new item. If it is not possible to create an item,
///             it will return 'ea'.

idaman ea_t ida_export calc_max_item_end(ea_t ea, int how=15);
/// \defgroup ITEM_END_ Item end search flags
/// passed as 'how' parameter to calc_max_item_end()
//@{
#define ITEM_END_FIXUP  0x0001          ///< stop at the first fixup
#define ITEM_END_INITED 0x0002          ///< stop when initialization changes
                                        ///< i.e.
                                        ///<  - if  is_loaded(ea): stop if uninitialized byte is encountered
                                        ///<  - if !is_loaded(ea): stop if   initialized byte is encountered
#define ITEM_END_NAME   0x0004          ///< stop at the first named location
#define ITEM_END_XREF   0x0008          ///< stop at the first referenced location
//@}


/// Get size of item (instruction/data) in bytes.
/// Unexplored bytes have length of 1 byte. This function returns 0 only for
/// BADADDR.

inline asize_t get_item_size(ea_t ea) { return get_item_end(ea) - ea; }




/// Is the specified address 'ea' present in the program?

idaman bool ida_export is_mapped(ea_t ea);


/// Get flags for the specified address, extended form

idaman flags64_t ida_export get_flags_ex(ea_t ea, int how);

#define GFE_VALUE 0x0001      ///< get flags with #FF_IVL & #MS_VAL.
                              ///< It is much slower under remote debugging
                              ///< because the kernel needs to read
                              ///< the process memory.
#define GFE_IDB_VALUE 0x0002  ///< get flags with #FF_IVL & #MS_VAL.
                              ///< but never use the debugger memory.

/// \copydoc GFE_VALUE
inline flags64_t idaapi get_flags(ea_t ea) { return get_flags_ex(ea, 0); }


/// Get flags value for address 'ea'.
/// \return 0 if address is not present in the program

inline flags64_t idaapi get_full_flags(ea_t ea) { return get_flags_ex(ea, GFE_VALUE); }


/// Get flag of the item at 'ea' even if it is a tail byte of some
/// array or structure. This function is used to get flags of structure members
/// or array elements.
/// \param from     linear address of the instruction which refers to 'ea'
/// \param n        operand number which refers to 'ea'
///                 or OPND_ALL for one of the operands
/// \param ea       the referenced address
/// \param appzero  append a struct field name if the field offset is zero?
///                 meaningful only if the name refers to a structure.
/// \return flags or 0 (if failed)

idaman flags64_t ida_export get_item_flag(ea_t from, int n, ea_t ea, bool appzero);


//--------------------------------------------------------------------------
/// Get refinfo of the item at 'ea'.
/// This function works for a regular offset operand as well as for a tail byte
/// of a structure variable (in this case refinfo to corresponding structure
/// member will be returned)
/// \param[out] ri  refinfo holder
/// \param ea       the item address
/// \param n        operand number which refers to 'ea'
///                 or OPND_ALL for one of the operands
/// \return success
idaman bool ida_export get_item_refinfo(refinfo_t *ri, ea_t ea, int n);

//--------------------------------------------------------------------------
/// \defgroup FF_ Flags structure
/// Here we define the organization of ::flags64_t values.
/// Low 8 bits contain value of corresponding byte of the program.
/// The next bit is set if the byte is initialized.
//@{
#define MS_VAL  0x000000FFLLU             ///< Mask for byte value
#define FF_IVL  0x00000100LLU             ///< Byte has value ?
//@}

/// Do flags contain byte value?

inline THREAD_SAFE bool idaapi has_value(flags64_t F)  { return (F & FF_IVL) != 0; }


/// Delete byte value from flags. The corresponding byte becomes
/// uninitialized.

idaman void ida_export del_value(ea_t ea);


/// Does the specified address have a byte value (is initialized?)

idaman bool ida_export is_loaded(ea_t ea);


/// Get number of bits in a byte at the given address.
/// \return \ph{dnbits()} if the address doesn't
///         belong to a segment, otherwise the result depends on the
///         segment type

idaman int ida_export nbits(ea_t ea);


/// Get number of bytes required to store a byte at the given address

inline int bytesize(ea_t ea)
          { return (nbits(ea)+7)/8; }


/// Get one byte (8-bit) of the program at 'ea'.
/// This function works only for 8bit byte processors.

idaman uchar ida_export get_byte(ea_t ea);


/// Get one byte (8-bit) of the program at 'ea' from the database.
/// Works even if the debugger is active.
/// See also get_dbg_byte() to read the process memory directly.
/// This function works only for 8bit byte processors.

idaman uchar ida_export get_db_byte(ea_t ea);


/// Get one word (16-bit) of the program at 'ea'.
/// This function takes into account order of bytes specified in \inf{is_be()}
/// This function works only for 8bit byte processors.

idaman ushort ida_export get_word(ea_t ea);


/// Get one dword (32-bit) of the program at 'ea'.
/// This function takes into account order of bytes specified in \inf{is_be()}
/// This function works only for 8bit byte processors.

idaman uint32 ida_export get_dword(ea_t ea);


/// Get one qword (64-bit) of the program at 'ea'.
/// This function takes into account order of bytes specified in \inf{is_be()}
/// This function works only for 8bit byte processors.

idaman uint64 ida_export get_qword(ea_t ea);


/// Get one wide byte of the program at 'ea'.
/// Some processors may access more than 8bit quantity at an address.
/// These processors have 32-bit byte organization from the IDA's point of view.

idaman uint64 ida_export get_wide_byte(ea_t ea);


/// Get one wide word (2 'byte') of the program at 'ea'.
/// Some processors may access more than 8bit quantity at an address.
/// These processors have 32-bit byte organization from the IDA's point of view.
/// This function takes into account order of bytes specified in \inf{is_be()}

idaman uint64 ida_export get_wide_word(ea_t ea);


/// Get two wide words (4 'bytes') of the program at 'ea'.
/// Some processors may access more than 8bit quantity at an address.
/// These processors have 32-bit byte organization from the IDA's point of view.
/// This function takes into account order of bytes specified in \inf{is_be()}
/// \note this function works incorrectly if \ph{nbits} > 16

idaman uint64 ida_export get_wide_dword(ea_t ea);


/// Get 8 bits of the program at 'ea'.
/// The main usage of this function is to iterate range of bytes.
/// Here is an example:
/// \code
///      octet_generator_t ogen(ea);
///      for ( ... )
///      {
///        if ( !get_octet2(&byte, &ogen) )
///           failed to read an octet
///        else
///           success
///      }
/// \endcode

struct octet_generator_t
{
  uint64 value = 0;
  ea_t ea;
  int avail_bits = 0;
  bool high_byte_first = inf_is_wide_high_byte_first();
  octet_generator_t(ea_t _ea) : ea(_ea) {}
  void invert_byte_order() { high_byte_first = !high_byte_first; }
#ifndef SWIG
  DECLARE_COMPARISONS(octet_generator_t)
  {
    COMPARE_FIELDS(ea);
    if ( avail_bits < r.avail_bits )
      return 1; // less bits available means that we have advanced more
    if ( avail_bits > r.avail_bits )
      return -1; // more bits available means that we have advanced less
    return 0;
  }
#endif
};

idaman bool ida_export get_octet2(uchar *out, octet_generator_t *ogen);



/// Get 16bits of the program at 'ea'.
/// \return 1 byte (getFullByte()) if the current processor has 16-bit byte,
///         otherwise return get_word()

idaman uint32 ida_export get_16bit(ea_t ea);


/// Get not more than 32bits of the program at 'ea'.
/// \return 32 bit value, depending on \ph{nbits}:
///   - if ( nbits <= 8 ) return get_dword(ea);
///   - if ( nbits <= 16) return get_wide_word(ea);
///   - return get_wide_byte(ea);

idaman uint32 ida_export get_32bit(ea_t ea);


/// Get not more than 64bits of the program at 'ea'.
/// \return 64 bit value, depending on \ph{nbits}:
///   - if ( nbits <= 8 ) return get_qword(ea);
///   - if ( nbits <= 16) return get_wide_dword(ea);
///   - return get_wide_byte(ea);

idaman uint64 ida_export get_64bit(ea_t ea);


/// Get the value at of the item at 'ea'.
/// This function works with entities up to sizeof(ea_t)
/// (bytes, word, etc)
/// \param v     pointer to the result. may be nullptr
/// \param ea    linear address
/// \param size  size of data to read. If 0, then the item
///              type at 'ea' will be used
/// \return success

idaman bool ida_export get_data_value(uval_t *v, ea_t ea, asize_t size);


/// Visit all the patched bytes one byte at a time.
/// \param ea1  start linear address
/// \param ea2  end linear address
/// \param cb   callback called for each found byte.
///             if the callback returns non-zero then that value will be
///             returned to the caller and the enumeration will be interrupted.
/// \param ud   user data passed to the callback
/// \return     the return value returned by the callback (if any) or zero
///             if the enumeration was completed.

idaman int ida_export visit_patched_bytes(
        ea_t ea1,
        ea_t ea2,
        int (idaapi *cb)(ea_t ea, qoff64_t fpos, uint64 o, uint64 v, void *ud),
        void *ud = nullptr);


/// Get original byte value (that was before patching).
/// This function works for wide byte processors too.

idaman uint64 ida_export get_original_byte(ea_t ea);


/// Get original word value (that was before patching).
/// This function works for wide byte processors too.
/// This function takes into account order of bytes specified in \inf{is_be()}

idaman uint64 ida_export get_original_word(ea_t ea);


/// Get original dword (that was before patching)
/// This function works for wide byte processors too.
/// This function takes into account order of bytes specified in \inf{is_be()}

idaman uint64 ida_export get_original_dword(ea_t ea);


/// Get original qword value (that was before patching)
/// This function DOESN'T work for wide byte processors too.
/// This function takes into account order of bytes specified in \inf{is_be()}

idaman uint64 ida_export get_original_qword(ea_t ea);


/// Set value of one byte of the program.
/// This function modifies the database. If the debugger is active
/// then the debugged process memory is patched too.
/// \note The original value of the byte is completely lost and can't
/// be recovered by the get_original_byte() function.
/// See also put_dbg_byte() to write to the process memory directly when
/// the debugger is active.
/// This function can handle wide byte processors.
/// \param ea  linear address
/// \param x   byte value
/// \return true if the database has been modified

idaman bool ida_export put_byte(ea_t ea, uint64 x);


/// Set value of one word of the program.
/// This function takes into account order of bytes specified in \inf{is_be()}
/// This function works for wide byte processors too.
/// \note The original value of the word is completely lost and can't
/// be recovered by the get_original_word() function.
///      ea - linear address
///      x  - word value

idaman void ida_export put_word(ea_t ea, uint64 x);


/// Set value of one dword of the program.
/// This function takes into account order of bytes specified in \inf{is_be()}
/// This function works for wide byte processors too.
/// \param ea  linear address
/// \param x   dword value
/// \note the original value of the dword is completely lost and can't
/// be recovered by the get_original_dword() function.

idaman void ida_export put_dword(ea_t ea, uint64 x);


/// Set value of one qword (8 bytes) of the program.
/// This function takes into account order of bytes specified in \inf{is_be()}
/// This function DOESN'T works for wide byte processors.
/// \param ea  linear address
/// \param x   qword value

idaman void ida_export put_qword(ea_t ea, uint64 x);


/// Patch a byte of the program. The original value of the byte is saved
/// and can be obtained by get_original_byte().
/// This function works for wide byte processors too.
/// \retval  true   the database has been modified,
/// \retval  false  the debugger is running and the process' memory
///                 has value 'x' at address 'ea', or
///                 the debugger is not running, and the IDB
///                 has value 'x' at address 'ea already.

idaman bool ida_export patch_byte(ea_t ea, uint64 x);


/// Patch a word of the program. The original value of the word is saved
/// and can be obtained by get_original_word().
/// This function works for wide byte processors too.
/// This function takes into account order of bytes specified in \inf{is_be()}
/// \retval true   the database has been modified,
/// \retval false  the debugger is running and the process' memory
///                has value 'x' at address 'ea', or
///                the debugger is not running, and the IDB
///                has value 'x' at address 'ea already.

idaman bool ida_export patch_word(ea_t ea, uint64 x);


/// Patch a dword of the program. The original value of the dword is saved
/// and can be obtained by get_original_dword().
/// This function DOESN'T work for wide byte processors.
/// This function takes into account order of bytes specified in \inf{is_be()}
/// \retval true   the database has been modified,
/// \retval false  the debugger is running and the process' memory
///                has value 'x' at address 'ea', or
///                the debugger is not running, and the IDB
///                has value 'x' at address 'ea already.

idaman bool ida_export patch_dword(ea_t ea, uint64 x);


/// Patch a qword of the program. The original value of the qword is saved
/// and can be obtained by get_original_qword().
/// This function DOESN'T work for wide byte processors.
/// This function takes into account order of bytes specified in \inf{is_be()}
/// \retval true   the database has been modified,
/// \retval false  the debugger is running and the process' memory
///                has value 'x' at address 'ea', or
///                the debugger is not running, and the IDB
///                has value 'x' at address 'ea already.

idaman bool ida_export patch_qword(ea_t ea, uint64 x);


/// Revert patched byte
/// \retval true   byte was patched before and reverted now

idaman bool ida_export revert_byte(ea_t ea);


/// Add a value to one byte of the program.
/// This function works for wide byte processors too.
/// \param ea     linear address
/// \param value  byte value

idaman void ida_export add_byte(ea_t ea, uint32 value);


/// Add a value to one word of the program.
/// This function works for wide byte processors too.
/// This function takes into account order of bytes specified in \inf{is_be()}
/// \param ea     linear address
/// \param value  byte value

idaman void ida_export add_word(ea_t ea, uint64 value);


/// Add a value to one dword of the program.
/// This function works for wide byte processors too.
/// This function takes into account order of bytes specified in \inf{is_be()}
/// \note this function works incorrectly if \ph{nbits} > 16
/// \param ea     linear address
/// \param value  byte value

idaman void ida_export add_dword(ea_t ea, uint64 value);


/// Add a value to one qword of the program.
/// This function does not work for wide byte processors.
/// This function takes into account order of bytes specified in \inf{is_be()}
/// \param ea     linear address
/// \param value  byte value

idaman void ida_export add_qword(ea_t ea, uint64 value);


/// Return set of ranges with zero initialized bytes.
/// The returned set includes only big zero initialized ranges (at least >1KB).
/// Some zero initialized byte ranges may be not included.
/// Only zero bytes that use the sparse storage method (STT_MM) are reported.
/// \param zranges  pointer to the return value. cannot be nullptr
/// \param range   the range of addresses to verify. can be nullptr - means all ranges
/// \return true if the result is a non-empty set

idaman bool ida_export get_zero_ranges(rangeset_t *zranges, const range_t *range);


/// Get the specified number of bytes of the program into the buffer.
/// If mask was specified it will contain a bitmap of initialized / uninitialized
/// database bytes.
/// \param ea    linear address
/// \param buf   buffer to hold bytes
/// \param size  size of buffer in normal 8-bit bytes (sizeof(buf))
/// \param gmb_flags combination of \ref GMB_ bits
/// \param mask  bitmap of initialize/uninitialized bytes
///              (may be nullptr; must be at least (size+7)/8)
/// \return if the user cancelled, return -1; otherwise number of read bytes.

idaman ssize_t ida_export get_bytes(
        void *buf,
        ssize_t size,
        ea_t ea,
        int gmb_flags=0,
        void *mask=nullptr);

/// \defgroup GMB_ flags for get_bytes()
//@{
#define GMB_READALL 0x01       ///< try to read all bytes;
                               ///< if this bit is not set, fail at first uninited byte
#define GMB_WAITBOX 0x02       ///< show wait box (may return -1 in this case)
///@}


/// Modify the specified number of bytes of the program.
/// This function does not save the original values of bytes.
/// See also patch_bytes().
/// \param ea    linear address
/// \param buf   buffer with new values of bytes
/// \param size  size of buffer in normal 8-bit bytes (sizeof(buf))

idaman void ida_export put_bytes(ea_t ea, const void *buf, size_t size);


/// Patch the specified number of bytes of the program.
/// Original values of bytes are saved and are available with get_original...()
/// functions.
/// See also put_bytes().
/// \param ea    linear address
/// \param buf   buffer with new values of bytes
/// \param size  size of buffer in normal 8-bit bytes (sizeof(buf))

idaman void ida_export patch_bytes(ea_t ea, const void *buf, size_t size);

//-------------------------------------------------------------------------
/// \defgroup FF_states States
/// \ingroup FF_
/// Represent general characteristics of a byte in the program.
///
/// Each byte of the program may be in one of four states.
///     - unexplored
///     - start of instruction
///     - start of data
///     - second, third (tail) byte of instruction or data.
///
/// Initially, all bytes of the program are unexplored.
/// IDA modifies flags and doing so converts bytes to instructions
/// and data.
//@{

/// \defgroup FF_statebits Bits: byte states
//@{
#define MS_CLS  0x00000600LU             ///< Mask for typing
#define FF_CODE 0x00000600LU             ///< Code ?
#define FF_DATA 0x00000400LU             ///< Data ?
#define FF_TAIL 0x00000200LU             ///< Tail ?
#define FF_UNK  0x00000000LU             ///< Unknown ?
//@}

/// \defgroup FF_statefuncs Functions: examine byte states
//@{

/// Does flag denote start of an instruction?

inline THREAD_SAFE bool idaapi is_code(flags64_t F)  { return (F & MS_CLS) == FF_CODE; }
inline THREAD_SAFE bool idaapi f_is_code(flags64_t F, void *) { return is_code(F); }         ///< \copydoc is_code()


/// Does flag denote start of data?

inline THREAD_SAFE bool idaapi is_data(flags64_t F)  { return (F & MS_CLS) == FF_DATA; }
inline THREAD_SAFE bool idaapi f_is_data(flags64_t F, void *) { return is_data(F); }         ///< \copydoc is_data()


/// Does flag denote tail byte?

inline THREAD_SAFE bool idaapi is_tail(flags64_t F)    { return (F & MS_CLS) == FF_TAIL; }
inline THREAD_SAFE bool idaapi f_is_tail(flags64_t F, void *) { return is_tail(F); }         ///< \copydoc is_tail()
inline THREAD_SAFE bool idaapi is_not_tail(flags64_t F) { return !is_tail(F); }              ///< \copydoc is_tail()
inline THREAD_SAFE bool idaapi f_is_not_tail(flags64_t F, void *) { return is_not_tail(F); } ///< \copydoc is_tail()


/// Does flag denote unexplored byte?

inline THREAD_SAFE bool idaapi is_unknown(flags64_t F) { return (F & MS_CLS) == FF_UNK; }


/// Does flag denote start of instruction OR data?

inline THREAD_SAFE bool idaapi is_head(flags64_t F)  { return (F & FF_DATA) != 0; }
inline THREAD_SAFE bool idaapi f_is_head(flags64_t F, void *) { return is_head(F); }         ///< \copydoc is_head()

//@} FF_statefuncs
//@} FF_states

/// del_items' callback function
typedef bool idaapi may_destroy_cb_t(ea_t);

/// Convert item (instruction/data) to unexplored bytes.
/// The whole item (including the head and tail bytes) will be destroyed.
/// It is allowed to pass any address in the item to this function
/// \param ea     any address within the first item to delete
/// \param flags  combination of \ref DELIT_
/// \param nbytes number of bytes in the range to be undefined
/// \param may_destroy optional routine invoked before deleting a head
///                    item. If callback returns false then item is not to
///                    be deleted and operation fails
/// \return true on sucessful operation, otherwise false

idaman bool ida_export del_items(
        ea_t ea,
        int flags=0,
        asize_t nbytes=1,
        may_destroy_cb_t *may_destroy=nullptr);

/// \defgroup DELIT_ Unexplored byte conversion flags
/// passed as 'flags' parameter to del_items()
//@{
#define DELIT_SIMPLE    0x0000  ///< simply undefine the specified item(s)
#define DELIT_EXPAND    0x0001  ///< propagate undefined items; for example
                                ///< if removing an instruction removes all
                                ///< references to the next instruction, then
                                ///< plan to convert to unexplored the next
                                ///< instruction too.
#define DELIT_DELNAMES  0x0002  ///< delete any names at the specified
                                ///< address range (except for the starting
                                ///< address). this bit is valid if nbytes > 1
#define DELIT_NOTRUNC   0x0004  ///< don't truncate the current function
                                ///< even if #AF_TRFUNC is set
#define DELIT_NOUNAME   0x0008  ///< reject to delete if a user name is
                                ///< in address range (except for the starting
                                ///< address). this bit is valid if nbytes > 1
#define DELIT_NOCMT     0x0010  ///< reject to delete if a comment is
                                ///< in address range (except for the starting
                                ///< address). this bit is valid if nbytes > 1
#define DELIT_KEEPFUNC  0x0020  ///< do not undefine the function start.
                                ///< Just delete xrefs, ops e.t.c.
//@}


//-------------------------------------------------------------------------
// Manual instructions (they are used to completely override an automatically
// generated instruction by a user specified string).

/// Is the instruction overridden?
/// \param ea  linear address of the instruction or data item

idaman bool ida_export is_manual_insn(ea_t ea);        // Is the instruction overridden?


/// Retrieve the user-specified string for the manual instruction.
/// \param buf      output buffer
/// \param ea       linear address of the instruction or data item
/// \return size of manual instruction or -1

idaman ssize_t ida_export get_manual_insn(qstring *buf, ea_t ea);


/// Set manual instruction string.
/// \param ea           linear address of the instruction or data item
/// \param manual_insn  ""   - delete manual string.
///                     nullptr - do nothing

idaman void ida_export set_manual_insn(ea_t ea, const char *manual_insn); // Set user-specified string


//-------------------------------------------------------------------------
/*! \defgroup FF_statespecb Bits: specific state information
  \ingroup FF_states
  Flags keep information common to all four states of bytes.
  This information will not be automatically discarded during
  transitions between different states.
*/
//@{
#define MS_COMM  0x000FF800            ///< Mask of common bits
#define FF_COMM  0x00000800            ///< Has comment ?
#define FF_REF   0x00001000            ///< has references
#define FF_LINE  0x00002000            ///< Has next or prev lines ?
#define FF_NAME  0x00004000            ///< Has name ?
#define FF_LABL  0x00008000            ///< Has dummy name?
#define FF_FLOW  0x00010000            ///< Exec flow from prev instruction
#define FF_SIGN  0x00020000            ///< Inverted sign of operands
#define FF_BNOT  0x00040000            ///< Bitwise negation of operands
#define FF_UNUSED 0x00080000           ///< unused bit (was used for variable bytes)
//@}

/// \defgroup FF_statespecf Functions: examine specific state information
/// \ingroup FF_states
//@{

/// Does the previous instruction exist and pass execution flow to the current byte?

inline THREAD_SAFE bool idaapi is_flow(flags64_t F)     { return (F & FF_FLOW) != 0; }


/// Does the current byte have additional anterior or posterior lines?

inline THREAD_SAFE bool idaapi has_extra_cmts(flags64_t F)   { return (F & FF_LINE) != 0; }
inline THREAD_SAFE bool idaapi f_has_extra_cmts(flags64_t f, void *) { return has_extra_cmts(f); }

/// Does the current byte have an indented comment?

inline THREAD_SAFE bool idaapi has_cmt(flags64_t F)    { return (F & FF_COMM) != 0; }
inline THREAD_SAFE bool idaapi f_has_cmt(flags64_t f, void *) { return has_cmt(f); }

/// Does the current byte have cross-references to it?

inline THREAD_SAFE bool idaapi has_xref(flags64_t F)     { return (F & FF_REF)  != 0; }
inline THREAD_SAFE bool idaapi f_has_xref(flags64_t f, void *) { return has_xref(f); }       ///< \copydoc has_xref()


/// Does the current byte have non-trivial (non-dummy) name?

inline THREAD_SAFE bool idaapi has_name(flags64_t F)   { return (F & FF_NAME) != 0; }
inline THREAD_SAFE bool idaapi f_has_name(flags64_t f, void *) { return has_name(f); }       ///< \copydoc has_name()



#define FF_ANYNAME      (FF_LABL|FF_NAME)

/// Does the current byte have dummy (auto-generated, with special prefix) name?

inline THREAD_SAFE bool idaapi has_dummy_name(flags64_t F) { return (F & FF_ANYNAME) == FF_LABL; }
inline THREAD_SAFE bool idaapi f_has_dummy_name(flags64_t f, void *) { return has_dummy_name(f); } ///< \copydoc has_dummy_name()


/// Does the current byte have auto-generated (no special prefix) name?

inline THREAD_SAFE bool idaapi has_auto_name(flags64_t F) { return (F & FF_ANYNAME) == FF_ANYNAME; }


/// Does the current byte have any name?

inline THREAD_SAFE bool idaapi has_any_name(flags64_t F) { return (F & FF_ANYNAME) != 0; }


/// Does the current byte have user-specified name?

inline THREAD_SAFE bool idaapi has_user_name(flags64_t F) { return (F & FF_ANYNAME) == FF_NAME; }
inline THREAD_SAFE bool idaapi f_has_user_name(flags64_t F, void *) { return has_user_name(F); } ///< \copydoc has_user_name()

// signness deals with the form of operands of the current instruction/data.
// inverted sign means the following:
//    if the bit is clear       |then when the bit is set
//    and the output is         |the output should be:
//    ------------              |----------
//    unsigned                  |signed
//    signed                    |unsigned
//

/// Should sign of n-th operand inverted during output?.
/// allowed values of n: 0-first operand, 1-other operands

idaman bool ida_export is_invsign(ea_t ea, flags64_t F, int n);


/// Toggle sign of n-th operand.
/// allowed values of n: 0-first operand, 1-other operands

idaman bool ida_export toggle_sign(ea_t ea, int n);


/// Should we negate the operand?.
/// \ash{a_bnot} should be defined in the idp module in order to work
/// with this function

idaman bool ida_export is_bnot(ea_t ea, flags64_t F, int n);
idaman bool ida_export toggle_bnot(ea_t ea, int n);  ///< Toggle binary negation of operand. also see is_bnot()


/// Display leading zeroes?
/// Display leading zeroes in operands.
/// The global switch for the leading zeroes is in \inf{s_genflags}
/// Note: the leading zeroes doesn't work if for the target assembler
/// octal numbers start with 0.
/// \param ea the item (insn/data) address
/// \param n  the operand number (0-first operand, 1-other operands)
/// \return success

idaman bool ida_export is_lzero(ea_t ea, int n);

/// Set toggle lzero bit.
/// This function changes the display of leading zeroes for the specified operand.
/// If the default is not to display leading zeroes, this function will display
/// them and vice versa.
/// \param ea the item (insn/data) address
/// \param n  the operand number (0-first operand, 1-other operands)
/// \return success

idaman bool ida_export set_lzero(ea_t ea, int n);

/// Clear toggle lzero bit.
/// This function reset the display of leading zeroes for the specified operand
/// to the default. If the default is not to display leading zeroes, leading
/// zeroes will not be displayed, as vice versa.
/// \param ea the item (insn/data) address
/// \param n  the operand number (0-first operand, 1-other operands)
/// \return success

idaman bool ida_export clr_lzero(ea_t ea, int n);

/// Toggle lzero bit.
/// \param ea the item (insn/data) address
/// \param n  the operand number (0-first operand, 1-other operands)
/// \return success

inline bool idaapi toggle_lzero(ea_t ea, int n)
{
  return (is_lzero(ea, n) ? clr_lzero : set_lzero)(ea, n);
}


//@} FF_statespecf


/// Check if leading zeroes are important

idaman bool ida_export leading_zero_important(ea_t ea, int n);

//-------------------------------------------------------------------------
/// \defgroup FF_op Instruction/Data operands
/// \ingroup FF_
/// Represent instruction/data operands.
///
/// IDA keeps bitmask representations for a maximum of 8 operands:
///
/// For data bytes, only the first bitmask is used (i.e. all elements of
/// an array have the same type).
//@{

#define MS_N_TYPE 0xFLLU ///< Mask for nth arg
#define FF_N_VOID 0x0    ///< Void (unknown)?
#define FF_N_NUMH 0x1    ///< Hexadecimal number?
#define FF_N_NUMD 0x2    ///< Decimal number?
#define FF_N_CHAR 0x3    ///< Char ('x')?
#define FF_N_SEG  0x4    ///< Segment?
#define FF_N_OFF  0x5    ///< Offset?
#define FF_N_NUMB 0x6    ///< Binary number?
#define FF_N_NUMO 0x7    ///< Octal number?
#define FF_N_ENUM 0x8    ///< Enumeration?
#define FF_N_FOP  0x9    ///< Forced operand?
#define FF_N_STRO 0xA    ///< Struct offset?
#define FF_N_STK  0xB    ///< Stack variable?
#define FF_N_FLT  0xC    ///< Floating point number?
#define FF_N_CUST 0xD    ///< Custom representation?

/// Get the shift in `flags64_t` for the nibble representing
/// operand `n`'s type
///
/// Note: n must be < UA_MAXOP, and is not checked
///
/// \param n the operand number
/// \return the shift to the nibble

inline constexpr int get_operand_type_shift(uint32 n)
{
  return 20 + (4 * (n + (n > 1))); //-V602 (2) Consider inspecting the '(n > 1)' expression. '>' possibly should be replaced with '>>'.
}

/// Place operand `n`'s type flag in the right nibble of a
/// 64-bit flags set.
///
/// \param typebits the type bits (one of `FF_N_`)
/// \param n the operand number
/// \return the shift to the nibble

inline constexpr flags64_t get_operand_flag(uint8 typebits, int n)
{
  return n >= 0 && n < UA_MAXOP ? flags64_t(typebits) << get_operand_type_shift(n) : 0;
}

/// Check that the 64-bit flags set has the expected type
/// for operand `n`.
///
/// \param F the flags
/// \param typebits the type bits (one of `FF_N_`)
/// \param n the operand number
/// \return success

inline constexpr bool is_flag_for_operand(flags64_t F, uint8 typebits, int n)
{
  return n < UA_MAXOP && (F & get_operand_flag(MS_N_TYPE, n)) == get_operand_flag(typebits, n);
}

/// \defgroup FF_opfuncs1 Functions: examine operand flags (specific operands)
//@{

/// Is the first operand defined? Initially operand has no defined representation

inline THREAD_SAFE bool idaapi is_defarg0(flags64_t F) { return !is_flag_for_operand(F, FF_N_VOID, 0); }


/// Is the second operand defined? Initially operand has no defined representation

inline THREAD_SAFE bool idaapi is_defarg1(flags64_t F) { return !is_flag_for_operand(F, FF_N_VOID, 1); }


/// Is the first operand offset? (example: push offset xxx)

inline THREAD_SAFE bool idaapi is_off0(flags64_t F)    { return is_flag_for_operand(F, FF_N_OFF, 0); }


/// Is the second operand offset? (example: mov ax, offset xxx)

inline THREAD_SAFE bool idaapi is_off1(flags64_t F)    { return is_flag_for_operand(F, FF_N_OFF, 1); }


/// Is the first operand character constant? (example: push 'a')

inline THREAD_SAFE bool idaapi is_char0(flags64_t F)   { return is_flag_for_operand(F, FF_N_CHAR, 0); }


/// Is the second operand character constant? (example: mov al, 'a')

inline THREAD_SAFE bool idaapi is_char1(flags64_t F)   { return is_flag_for_operand(F, FF_N_CHAR, 1); }


/// Is the first operand segment selector? (example: push seg seg001)

inline THREAD_SAFE bool idaapi is_seg0(flags64_t F)    { return is_flag_for_operand(F, FF_N_SEG, 0); }


/// Is the second operand segment selector? (example: mov dx, seg dseg)

inline THREAD_SAFE bool idaapi is_seg1(flags64_t F)    { return is_flag_for_operand(F, FF_N_SEG, 1); }


/// Is the first operand a symbolic constant (enum member)?

inline THREAD_SAFE bool idaapi is_enum0(flags64_t F)   { return is_flag_for_operand(F, FF_N_ENUM, 0); }


/// Is the second operand a symbolic constant (enum member)?

inline THREAD_SAFE bool idaapi is_enum1(flags64_t F)   { return is_flag_for_operand(F, FF_N_ENUM, 1); }


/// Is the first operand an offset within a struct?

inline THREAD_SAFE bool idaapi is_stroff0(flags64_t F) { return is_flag_for_operand(F, FF_N_STRO, 0); }


/// Is the second operand an offset within a struct?

inline THREAD_SAFE bool idaapi is_stroff1(flags64_t F) { return is_flag_for_operand(F, FF_N_STRO, 1); }


/// Is the first operand a stack variable?

inline THREAD_SAFE bool idaapi is_stkvar0(flags64_t F) { return is_flag_for_operand(F, FF_N_STK, 0);  }


/// Is the second operand a stack variable?

inline THREAD_SAFE bool idaapi is_stkvar1(flags64_t F) { return is_flag_for_operand(F, FF_N_STK, 1); }


/// Is the first operand a floating point number?

inline THREAD_SAFE bool idaapi is_float0(flags64_t F) { return is_flag_for_operand(F, FF_N_FLT, 0); }


/// Is the second operand a floating point number?

inline THREAD_SAFE bool idaapi is_float1(flags64_t F) { return is_flag_for_operand(F, FF_N_FLT, 1); }


/// Does the first operand use a custom data representation?

inline THREAD_SAFE bool idaapi is_custfmt0(flags64_t F) { return is_flag_for_operand(F, FF_N_CUST, 0); }


/// Does the second operand use a custom data representation?

inline THREAD_SAFE bool idaapi is_custfmt1(flags64_t F) { return is_flag_for_operand(F, FF_N_CUST, 1); }


/// Is the first operand a number (i.e. binary, octal, decimal or hex?)

idaman bool ida_export is_numop0(flags64_t F);


/// Is the second operand a number (i.e. binary, octal, decimal or hex?)

idaman bool ida_export is_numop1(flags64_t F);


/// Get flags for first operand

inline THREAD_SAFE flags64_t get_optype_flags0(flags64_t F) { return F & (MS_N_TYPE << get_operand_type_shift(0)); }


/// Get flags for second operand

inline THREAD_SAFE flags64_t get_optype_flags1(flags64_t F) { return F & (MS_N_TYPE << get_operand_type_shift(1)); }

//@} FF_opfuncs1

//-------------------------------------------------------------------------
//
//      The following 2 masks are used with operand numbers
//
#define OPND_OUTER      0x80            ///< outer offset base (combined with operand number).
                                        ///< used only in set, get, del_offset() functions
#define OPND_MASK       0x0F            ///< mask for operand number
#define OPND_ALL        OPND_MASK       ///< all operands

/*! \defgroup FF_opfuncs2 Functions: examine operand flags (arbitrary operand)
  For the following functions, 'n' may be:
    - zero based operand number if in 0..UA_MAXOP-1
    - #OPND_ALL : all operands - function returns 1 if one of the 8 operands
                  satisfies the condition
*/
//@{
idaman bool ida_export is_defarg(flags64_t F, int n);          ///< is defined?
idaman bool ida_export is_off(flags64_t F, int n);             ///< is offset?
idaman bool ida_export is_char(flags64_t F, int n);            ///< is character constant?
idaman bool ida_export is_seg(flags64_t F, int n);             ///< is segment?
idaman bool ida_export is_enum(flags64_t F, int n);            ///< is enum?
idaman bool ida_export is_manual(flags64_t F, int n);          ///< is forced operand? (use is_forced_operand())
idaman bool ida_export is_stroff(flags64_t F, int n);          ///< is struct offset?
idaman bool ida_export is_stkvar(flags64_t F, int n);          ///< is stack variable?
idaman bool ida_export is_fltnum(flags64_t F, int n);          ///< is floating point number?
idaman bool ida_export is_custfmt(flags64_t F, int n);         ///< is custom data format?
idaman bool ida_export is_numop(flags64_t F, int n);           ///< is number (bin, oct, dec, hex)?
idaman bool ida_export is_suspop(ea_t ea, flags64_t F, int n); ///< is suspicious operand?
//@}


/// Should processor module create xrefs from the operand?.
/// Currently 'offset' and 'structure offset' operands create xrefs

idaman bool ida_export op_adds_xrefs(flags64_t F, int n);


/// (internal function) change representation of operand(s).
/// \param ea    linear address
/// \param type  new flag value (should be obtained from char_flag(), num_flag() and
///              similar functions)
/// \param n     0..#UA_MAXOP-1 operand number, OPND_ALL all operands
/// \retval 1 ok
/// \retval 0 failed (applied to a tail byte)

idaman bool ida_export set_op_type(ea_t ea, flags64_t type, int n);


/// Set operand representation to be 'segment'.
/// If applied to unexplored bytes, converts them to 16/32bit word data
/// \param ea  linear address
/// \param n   0..#UA_MAXOP-1 operand number, OPND_ALL all operands
/// \return success

idaman bool ida_export op_seg(ea_t ea, int n);


/// Set operand representation to be 'enum_t'.
/// If applied to unexplored bytes, converts them to 16/32bit word data
/// \param ea      linear address
/// \param n       0..#UA_MAXOP-1 operand number, OPND_ALL all operands
/// \param id      id of enum
/// \param serial  the serial number of the constant in the enumeration,
///                usually 0. the serial numbers are used if the enumeration
///                contains several constants with the same value
/// \return success

idaman bool ida_export op_enum(ea_t ea, int n, enum_t id, uchar serial);


/// Get enum id of 'enum' operand.
/// \param ea      linear address
/// \param n       0..#UA_MAXOP-1 operand number, OPND_ALL one of the operands
/// \param serial  pointer to variable to hold the serial number of the
///                constant in the enumeration
/// \return id of enum or #BADNODE

idaman enum_t ida_export get_enum_id(uchar *serial, ea_t ea, int n);


/// Set operand representation to be 'struct offset'.
/// If applied to unexplored bytes, converts them to 16/32bit word data
/// \param insn      the instruction
/// \param n         0..#UA_MAXOP-1 operand number, OPND_ALL all operands
/// \param path      structure path (strpath). see nalt.hpp for more info.
/// \param path_len  length of the structure path
/// \param delta     struct offset delta. usually 0. denotes the difference
///                  between the structure base and the pointer into the structure.
/// \return success

idaman bool ida_export op_stroff(
        const insn_t &insn,
        int n,
        const tid_t *path,
        int path_len,
        adiff_t delta);


/// Get struct path of operand.
/// \param  path   buffer for structure path (strpath). see nalt.hpp for more info.
/// \param  delta  struct offset delta
/// \param  ea     linear address
/// \param n       0..#UA_MAXOP-1 operand number, OPND_ALL one of the operands
/// \return length of strpath

idaman int ida_export get_stroff_path(tid_t *path, adiff_t *delta, ea_t ea, int n);

/// Set operand representation to be 'stack variable'.
/// Should be applied to an instruction within a function.
/// Should be applied after creating a stack var using
/// insn_t::create_stkvar().
/// \param ea  linear address
/// \param n   0..#UA_MAXOP-1 operand number, OPND_ALL all operands
/// \return success

idaman bool ida_export op_stkvar(ea_t ea, int n);


/// Set forced operand.
/// \param ea  linear address
/// \param n   0..#UA_MAXOP-1 operand number
/// \param op  text of operand
///            - nullptr: do nothing (return 0)
///            - ""     : delete forced operand
/// \return success

idaman bool ida_export set_forced_operand(ea_t ea, int n, const char *op);


/// Get forced operand.
/// \param buf      output buffer, may be nullptr
/// \param ea       linear address
/// \param n        0..#UA_MAXOP-1 operand number
/// \return size of forced operand or -1

idaman ssize_t ida_export get_forced_operand(qstring *buf, ea_t ea, int n);


/// Is operand manually defined?.
/// \param ea  linear address
/// \param n   0..#UA_MAXOP-1 operand number

idaman bool ida_export is_forced_operand(ea_t ea, int n);


//-------------------------------------------------------------------------
inline constexpr flags64_t idaapi combine_flags(flags64_t F)
{
  return (F << get_operand_type_shift(0))
       | (F << get_operand_type_shift(1))
       | (F << get_operand_type_shift(2))
       | (F << get_operand_type_shift(3))
       | (F << get_operand_type_shift(4))
       | (F << get_operand_type_shift(5))
       | (F << get_operand_type_shift(6))
       | (F << get_operand_type_shift(7));
}

//-------------------------------------------------------------------------
/*! \defgroup FF_opfuncs3 Functions: get type information bits for flags
  Values of these functions are used as input to set_op_type() function
*/
//@{
inline constexpr flags64_t idaapi char_flag(void)    { return combine_flags(FF_N_CHAR); } ///< see \ref FF_opbits
inline constexpr flags64_t idaapi off_flag(void)     { return combine_flags(FF_N_OFF); }  ///< see \ref FF_opbits
inline constexpr flags64_t idaapi enum_flag(void)    { return combine_flags(FF_N_ENUM); } ///< see \ref FF_opbits
inline constexpr flags64_t idaapi stroff_flag(void)  { return combine_flags(FF_N_STRO); } ///< see \ref FF_opbits
inline constexpr flags64_t idaapi stkvar_flag(void)  { return combine_flags(FF_N_STK); }  ///< see \ref FF_opbits
inline constexpr flags64_t idaapi flt_flag(void)     { return combine_flags(FF_N_FLT); }  ///< see \ref FF_opbits
inline constexpr flags64_t idaapi custfmt_flag(void) { return combine_flags(FF_N_CUST); } ///< see \ref FF_opbits
inline constexpr flags64_t idaapi seg_flag(void)     { return combine_flags(FF_N_SEG); }  ///< see \ref FF_opbits

idaman flags64_t ida_export num_flag(void); ///< Get number of default base (bin, oct, dec, hex)
/// Get number flag of the base, regardless of current processor - better to use num_flag()
inline constexpr flags64_t idaapi hex_flag(void)     { return combine_flags(FF_N_NUMH); }
inline constexpr flags64_t idaapi dec_flag(void)     { return combine_flags(FF_N_NUMD); } ///< \copydoc hex_flag()
inline constexpr flags64_t idaapi oct_flag(void)     { return combine_flags(FF_N_NUMO); } ///< \copydoc hex_flag()
inline constexpr flags64_t idaapi bin_flag(void)     { return combine_flags(FF_N_NUMB); } ///< \copydoc hex_flag()
//@}

/*! \defgroup FF_opfuncs4 Functions: set operand representation
  The following functions set operand representation.
  If they are applied to unexplored bytes, they convert them.
    - no segment    : fail
    - 16bit segment : to 16bit word data
    - 32bit segment : to dword
  \param ea  linear address
  \param n   0..#UA_MAXOP-1 operand number, OPND_ALL all operands
  \return success
*/
//@{
inline bool idaapi op_chr(ea_t ea, int n) { return set_op_type(ea, char_flag(), n); } ///< set op type to char_flag()
inline bool idaapi op_num(ea_t ea, int n) { return set_op_type(ea, num_flag(), n); } ///< set op type to num_flag()
inline bool idaapi op_hex(ea_t ea, int n) { return set_op_type(ea, hex_flag(), n); } ///< set op type to hex_flag()
inline bool idaapi op_dec(ea_t ea, int n) { return set_op_type(ea, dec_flag(), n); } ///< set op type to dec_flag()
inline bool idaapi op_oct(ea_t ea, int n) { return set_op_type(ea, oct_flag(), n); } ///< set op type to oct_flag()
inline bool idaapi op_bin(ea_t ea, int n) { return set_op_type(ea, bin_flag(), n); } ///< set op type to bin_flag()
inline bool idaapi op_flt(ea_t ea, int n) { return set_op_type(ea, flt_flag(), n); } ///< set op type to flt_flag()
//@}

/// Set custom data format for operand (fid-custom data format id)

idaman bool ida_export op_custfmt(ea_t ea, int n, int fid);


/// Remove operand representation information.
/// (set operand representation to be 'undefined')
/// \param  ea  linear address
/// \param  n   0..#UA_MAXOP-1 operand number, OPND_ALL all operands
/// \return success

idaman bool ida_export clr_op_type(ea_t ea, int n);


/// Get default base of number for the current processor.
/// \return 2, 8, 10, 16

idaman int ida_export get_default_radix(void);


/// Get radix of the operand, in: flags.
/// If the operand is not a number, returns get_default_radix()
/// \param F  flags
/// \param n  number of operand (0, 1, -1)
/// \return 2, 8, 10, 16

idaman int ida_export get_radix(flags64_t F, int n);


//-------------------------------------------------------------------------
/// \defgroup FF_databits Bits: data bytes
//@{
#define DT_TYPE 0xF0000000             ///< Mask for DATA typing

#define FF_BYTE     0x00000000         ///< byte
#define FF_WORD     0x10000000         ///< word
#define FF_DWORD    0x20000000         ///< double word
#define FF_QWORD    0x30000000         ///< quadro word
#define FF_TBYTE    0x40000000         ///< tbyte
#define FF_STRLIT   0x50000000         ///< string literal
#define FF_STRUCT   0x60000000         ///< struct variable
#define FF_OWORD    0x70000000         ///< octaword/xmm word (16 bytes/128 bits)
#define FF_FLOAT    0x80000000         ///< float
#define FF_DOUBLE   0x90000000         ///< double
#define FF_PACKREAL 0xA0000000         ///< packed decimal real
#define FF_ALIGN    0xB0000000         ///< alignment directive
//                  0xC0000000         ///< reserved
#define FF_CUSTOM   0xD0000000         ///< custom data type
#define FF_YWORD    0xE0000000         ///< ymm word (32 bytes/256 bits)
#define FF_ZWORD    0xF0000000         ///< zmm word (64 bytes/512 bits)
//@}

/// \defgroup FF_datafuncs1 Functions: examine data bits
//@{
inline constexpr flags64_t idaapi code_flag(void)     { return FF_CODE; }              ///< #FF_CODE
inline constexpr flags64_t idaapi byte_flag(void)     { return FF_DATA|FF_BYTE; }      ///< Get a flags64_t representing a byte
inline constexpr flags64_t idaapi word_flag(void)     { return FF_DATA|FF_WORD; }      ///< Get a flags64_t representing a word
inline constexpr flags64_t idaapi dword_flag(void)    { return FF_DATA|FF_DWORD; }     ///< Get a flags64_t representing a double word
inline constexpr flags64_t idaapi qword_flag(void)    { return FF_DATA|FF_QWORD; }     ///< Get a flags64_t representing a quad word
inline constexpr flags64_t idaapi oword_flag(void)    { return FF_DATA|FF_OWORD; }     ///< Get a flags64_t representing a octaword
inline constexpr flags64_t idaapi yword_flag(void)    { return FF_DATA|FF_YWORD; }     ///< Get a flags64_t representing a ymm word
inline constexpr flags64_t idaapi zword_flag(void)    { return FF_DATA|FF_ZWORD; }     ///< Get a flags64_t representing a zmm word
inline constexpr flags64_t idaapi tbyte_flag(void)    { return FF_DATA|FF_TBYTE; }     ///< Get a flags64_t representing a tbyte
inline constexpr flags64_t idaapi strlit_flag(void)   { return FF_DATA|FF_STRLIT; }    ///< Get a flags64_t representing a string literal
inline constexpr flags64_t idaapi stru_flag(void)     { return FF_DATA|FF_STRUCT; }    ///< Get a flags64_t representing a struct
inline constexpr flags64_t idaapi cust_flag(void)     { return FF_DATA|FF_CUSTOM; }    ///< Get a flags64_t representing custom type data
inline constexpr flags64_t idaapi align_flag(void)    { return FF_DATA|FF_ALIGN; }     ///< Get a flags64_t representing an alignment directive
inline constexpr flags64_t idaapi float_flag(void)    { return FF_DATA|FF_FLOAT; }     ///< Get a flags64_t representing a float
inline constexpr flags64_t idaapi double_flag(void)   { return FF_DATA|FF_DOUBLE; }    ///< Get a flags64_t representing a double
inline constexpr flags64_t idaapi packreal_flag(void) { return FF_DATA|FF_PACKREAL; }  ///< Get a flags64_t representing a packed decimal real

inline THREAD_SAFE bool idaapi is_byte(flags64_t F)      { return is_data(F) && (F & DT_TYPE) == FF_BYTE; }      ///< #FF_BYTE
inline THREAD_SAFE bool idaapi is_word(flags64_t F)      { return is_data(F) && (F & DT_TYPE) == FF_WORD; }      ///< #FF_WORD
inline THREAD_SAFE bool idaapi is_dword(flags64_t F)     { return is_data(F) && (F & DT_TYPE) == FF_DWORD; }     ///< #FF_DWORD
inline THREAD_SAFE bool idaapi is_qword(flags64_t F)     { return is_data(F) && (F & DT_TYPE) == FF_QWORD; }     ///< #FF_QWORD
inline THREAD_SAFE bool idaapi is_oword(flags64_t F)     { return is_data(F) && (F & DT_TYPE) == FF_OWORD; }     ///< #FF_OWORD
inline THREAD_SAFE bool idaapi is_yword(flags64_t F)     { return is_data(F) && (F & DT_TYPE) == FF_YWORD; }     ///< #FF_YWORD
inline THREAD_SAFE bool idaapi is_zword(flags64_t F)     { return is_data(F) && (F & DT_TYPE) == FF_ZWORD; }     ///< #FF_ZWORD
inline THREAD_SAFE bool idaapi is_tbyte(flags64_t F)     { return is_data(F) && (F & DT_TYPE) == FF_TBYTE; }     ///< #FF_TBYTE
inline THREAD_SAFE bool idaapi is_float(flags64_t F)     { return is_data(F) && (F & DT_TYPE) == FF_FLOAT; }     ///< #FF_FLOAT
inline THREAD_SAFE bool idaapi is_double(flags64_t F)    { return is_data(F) && (F & DT_TYPE) == FF_DOUBLE; }    ///< #FF_DOUBLE
inline THREAD_SAFE bool idaapi is_pack_real(flags64_t F) { return is_data(F) && (F & DT_TYPE) == FF_PACKREAL; }  ///< #FF_PACKREAL
inline THREAD_SAFE bool idaapi is_strlit(flags64_t F)    { return is_data(F) && (F & DT_TYPE) == FF_STRLIT; }    ///< #FF_STRLIT
inline THREAD_SAFE bool idaapi is_struct(flags64_t F)    { return is_data(F) && (F & DT_TYPE) == FF_STRUCT; }    ///< #FF_STRUCT
inline THREAD_SAFE bool idaapi is_align(flags64_t F)     { return is_data(F) && (F & DT_TYPE) == FF_ALIGN; }     ///< #FF_ALIGN
inline THREAD_SAFE bool idaapi is_custom(flags64_t F)    { return is_data(F) && (F & DT_TYPE) == FF_CUSTOM; }    ///< #FF_CUSTOM

inline THREAD_SAFE bool idaapi f_is_byte(flags64_t F, void *)      { return is_byte(F); }                        ///< See is_byte()
inline THREAD_SAFE bool idaapi f_is_word(flags64_t F, void *)      { return is_word(F); }                        ///< See is_word()
inline THREAD_SAFE bool idaapi f_is_dword(flags64_t F, void *)     { return is_dword(F); }                       ///< See is_dword()
inline THREAD_SAFE bool idaapi f_is_qword(flags64_t F, void *)     { return is_qword(F); }                       ///< See is_qword()
inline THREAD_SAFE bool idaapi f_is_oword(flags64_t F, void *)     { return is_oword(F); }                       ///< See is_oword()
inline THREAD_SAFE bool idaapi f_is_yword(flags64_t F, void *)     { return is_yword(F); }                       ///< See is_yword()
inline THREAD_SAFE bool idaapi f_is_tbyte(flags64_t F, void *)     { return is_tbyte(F); }                       ///< See is_tbyte()
inline THREAD_SAFE bool idaapi f_is_float(flags64_t F, void *)     { return is_float(F); }                       ///< See is_float()
inline THREAD_SAFE bool idaapi f_is_double(flags64_t F, void *)    { return is_double(F); }                      ///< See is_double()
inline THREAD_SAFE bool idaapi f_is_pack_real(flags64_t F, void *) { return is_pack_real(F); }                   ///< See is_pack_real()
inline THREAD_SAFE bool idaapi f_is_strlit(flags64_t F, void *)    { return is_strlit(F); }                      ///< See is_strlit()
inline THREAD_SAFE bool idaapi f_is_struct(flags64_t F, void *)    { return is_struct(F); }                      ///< See is_struct()
inline THREAD_SAFE bool idaapi f_is_align(flags64_t F, void *)     { return is_align(F); }                       ///< See is_align()
inline THREAD_SAFE bool idaapi f_is_custom(flags64_t F, void *)    { return is_custom(F); }                      ///< See is_custom()


/// Do the given flags specify the same data type?

inline THREAD_SAFE bool idaapi is_same_data_type(flags64_t F1, flags64_t F2) { return ((F1 ^ F2) & DT_TYPE) == 0; }


/// Get flags from size (in bytes).
/// Supported sizes: 1, 2, 4, 8, 16, 32.
/// For other sizes returns 0

idaman flags64_t ida_export get_flags_by_size(size_t size);
//@} FF_datafuncs1


/// \defgroup FF_datafuncs2 Functions: manipulate data bits
/// \param ea      linear address
/// \param length  size of array in bytes. should be divisible by the size of
///                one item of the specified type.
/// \return success
//@{

/// Convert to data (byte, word, dword, etc).
/// This function may be used to create arrays.
/// \param ea        linear address
/// \param dataflag  type of data. Value of function byte_flag(), word_flag(), etc.
/// \param size      size of array in bytes. should be divisible by the size of
///                  one item of the specified type. for variable sized items
///                  it can be specified as 0, and the kernel will try to calculate the size.
/// \param tid       type id. If the specified type is a structure,
///                  then tid is structure id. Otherwise should be #BADNODE.
/// \return success

idaman bool ida_export create_data(
        ea_t ea,
        flags64_t dataflag,
        asize_t size,
        tid_t tid);


inline THREAD_SAFE flags64_t idaapi calc_dflags(flags64_t f, bool force) { return f | (force ? FF_COMM : 0); }
/// Convert to byte
inline bool idaapi create_byte(ea_t ea, asize_t length, bool force=false)
{
  return create_data(ea, calc_dflags(FF_BYTE, force), length, BADNODE);
}
/// Convert to word
inline bool idaapi create_word(ea_t ea, asize_t length, bool force=false)
{
  return create_data(ea, calc_dflags(FF_WORD, force), length, BADNODE);
}
/// Convert to dword
inline bool idaapi create_dword(ea_t ea, asize_t length, bool force=false)
{
  return create_data(ea, calc_dflags(FF_DWORD, force), length, BADNODE);
}
/// Convert to quadword
inline bool idaapi create_qword(ea_t ea, asize_t length, bool force=false)
{
  return create_data(ea, calc_dflags(FF_QWORD, force), length, BADNODE);
}
/// Convert to octaword/xmm word
inline bool idaapi create_oword(ea_t ea, asize_t length, bool force=false)
{
  return create_data(ea, calc_dflags(FF_OWORD, force), length, BADNODE);
}
/// Convert to ymm word
inline bool idaapi create_yword(ea_t ea, asize_t length, bool force=false)
{
  return create_data(ea, calc_dflags(FF_YWORD, force), length, BADNODE);
}
/// Convert to zmm word
inline bool idaapi create_zword(ea_t ea, asize_t length, bool force=false)
{
  return create_data(ea, calc_dflags(FF_ZWORD, force), length, BADNODE);
}
/// Convert to tbyte
inline bool idaapi create_tbyte(ea_t ea, asize_t length, bool force=false)
{
  return create_data(ea, calc_dflags(FF_TBYTE, force), length, BADNODE);
}
/// Convert to float
inline bool idaapi create_float(ea_t ea, asize_t length, bool force=false)
{
  return create_data(ea, calc_dflags(FF_FLOAT, force), length, BADNODE);
}
/// Convert to double
inline bool idaapi create_double(ea_t ea, asize_t length, bool force=false)
{
  return create_data(ea, calc_dflags(FF_DOUBLE, force), length, BADNODE);
}
/// Convert to packed decimal real
inline bool idaapi create_packed_real(ea_t ea, asize_t length, bool force=false)
{
  return create_data(ea, calc_dflags(FF_PACKREAL, force), length, BADNODE);
}
/// Convert to struct
inline bool idaapi create_struct(ea_t ea, asize_t length, tid_t tid, bool force=false)
{
  return create_data(ea, calc_dflags(FF_STRUCT, force), length, tid);
}
/// Convert to custom data type
inline bool idaapi create_custdata(ea_t ea, asize_t length, int dtid, int fid, bool force=false)
{
  return create_data(ea, calc_dflags(FF_CUSTOM, force), length, dtid|(fid<<16));
}


/// Create an alignment item.
/// \param ea        linear address
/// \param length    size of the item in bytes. 0 means to infer from ALIGNMENT
/// \param alignment alignment exponent. Example: 3 means align to 8 bytes.
///                  0 means to infer from LENGTH
/// It is forbidden to specify both LENGTH and ALIGNMENT as 0.
/// \return success

idaman bool ida_export create_align(ea_t ea, asize_t length, int alignment);

/// Calculate the minimal possible alignment exponent.
/// \param length    size of the item in bytes.
/// \return a value in the 1..32 range

idaman int  ida_export calc_min_align(asize_t length);


/// Calculate the maximal possible alignment exponent.
/// \param endea  end address of the alignment item.
/// \return a value in the 0..32 range

idaman int  ida_export calc_max_align(ea_t endea);

/// Calculate the default alignment exponent.
/// \param ea        linear address
/// \param mina      minimal possible alignment exponent.
/// \param maxa      minimal possible alignment exponent.

idaman int ida_export calc_def_align(ea_t ea, int mina, int maxa);


/// Convert to 16-bit quantity (take the byte size into account)

idaman bool ida_export create_16bit_data(ea_t ea, asize_t length);


/// Convert to 32-bit quantity (take the byte size into account)

idaman bool ida_export create_32bit_data(ea_t ea, asize_t length);


//@} FF_datafuncs2

//@} FF_op

/// \defgroup ALOPT_ string literal length options
/// passed as 'options' parameter to get_max_strlit_length()
//@{
#define ALOPT_IGNHEADS 0x01 ///< don't stop if another data item is encountered.
                            ///< only the byte values will be used to determine
                            ///< the string length.
                            ///< if not set, a defined data item or instruction
                            ///< will truncate the string
#define ALOPT_IGNPRINT 0x02 ///< if set, don't stop at non-printable codepoints,
                            ///< but only at the terminating character (or not
                            ///< unicode-mapped character (e.g., 0x8f in CP1252))
#define ALOPT_IGNCLT   0x04 ///< if set, don't stop at codepoints that are not
                            ///< part of the current 'culture'; accept all
                            ///< those that are graphical (this is typically
                            ///< used used by user-initiated actions creating
                            ///< string literals.)
#define ALOPT_MAX4K    0x08 ///< if string length is more than 4K, return the
                            ///< accumulated length
#define ALOPT_ONLYTERM 0x10 ///< only the termination characters can be at the
                            ///< string end. Without this option illegal
                            ///< characters also terminate the string.

//@}

/// Determine maximum length of string literal.
///
/// If the string literal has a length prefix (e.g., STRTYPE_LEN2 has
/// a two-byte length prefix), the length of that prefix (i.e., 2)
/// will be part of the returned value.
///
/// \param ea       starting address
/// \param strtype  string type. one of \ref STRTYPE_
/// \param options  combination of \ref ALOPT_
/// \return length of the string in octets (octet==8bit)

idaman size_t ida_export get_max_strlit_length(
        ea_t ea,
        int32 strtype,
        int options = 0);

/// \defgroup STRCONV_ string conversion flags
/// passed as 'flags' parameter to get_strlit_contents()
//@{
#define STRCONV_ESCAPE   0x00000001 ///< convert non-printable characters to C escapes (\n, \xNN, \uNNNN)
#define STRCONV_REPLCHAR 0x00000002 ///< convert non-printable characters to the Unicode replacement character (U+FFFD)
#define STRCONV_INCLLEN  0x00000004 ///< for Pascal-style strings, include the prefixing length byte(s) as C-escaped sequence
//@}

/// Get contents of string literal, as UTF-8-encoded codepoints.
/// This function returns the displayed part of the string
/// It works even if the string has not been created in the database yet.
///
/// If 'len' is size_t(-1), it will be computed like so:
///  - if a string literal is present at 'ea', get_item_size() * bytesize(ea) will be used
///  - otherwise, get_max_strlit_length(..., ALOPT_IGNHEADS) will be used
///
/// About 'maxcps': this specifies a limit to the number of codepoints,
/// not bytes in the UTF-8 output buffer. So for example although U+4e12
/// will use 3 bytes in the output buffer, it still counts as only 1
/// character -- unless STRCONV_ESCAPE is used.
/// If 'STRCONV_ESCAPE' is used, U+4e12 will be converted to the string
/// "\u4E12", and will use 6 bytes in the output buffer and also count
/// as 6 codepoints.
///
/// If 'STRCONV_REPLCHAR', any undecodable byte will re represented
/// as U+FFFD, occupy 3 bytes in the output buffer, and count for 1 codepoint.
///
/// \param[out]    utf8        output buffer
/// \param[in]     ea          linear address of the string
/// \param[in]     len         length of the string, in octets (octet=8bit)
/// \param[in]     type        type of the string. one of \ref STRTYPE_
/// \param[in, out] maxcps      maximum length of codepoints, after possible
///                            escaping, in output buffer (not counting terminating zero)
///                            on exit, will be set to 0 if string got truncated
///                            can be nullptr if not needed
/// \param[in]     flags       combination of \ref STRCONV_
/// \return length of generated text (in bytes) or -1

idaman ssize_t ida_export get_strlit_contents(
        qstring *utf8,
        ea_t ea,
        size_t len,
        int32 type,
        size_t *maxcps = nullptr,
        int flags = 0);


/// Convert to string literal and give a meaningful name.
/// 'start' may be higher than 'end', the kernel will swap them in this case
/// \param start    starting address
/// \param len      length of the string in bytes.
///                 if 0, then get_max_strlit_length() will be used
///                 to determine the length
/// \param strtype  string type. one of \ref STRTYPE_
/// \return success

idaman bool ida_export create_strlit(ea_t start, size_t len, int32 strtype);



//-------------------------------------------------------------------------
/// \defgroup PSTF_ flags for use with get_strlit_type_info
//@{
#define PSTF_TNORM    0   ///< use normal name
#define PSTF_TBRIEF   1   ///< use brief name (e.g., in the 'Strings' window)
#define PSTF_TINLIN   2   ///< use 'inline' name (e.g., in the structures comments)
#define PSTF_TMASK    3   ///< type mask
#define PSTF_HOTKEY   0x4 ///< have hotkey markers part of the name
#define PSTF_ENC      0x8 ///< if encoding is specified, append it
#define PSTF_ONLY_ENC 0xB ///< generate only the encoding name
//@}


/// Get string type information: the string type name (possibly
/// decorated with hotkey markers), and the tooltip.
///
/// \param out         the output buffer
/// \param strtype     the string type
/// \param out_tooltip an optional output buffer for the tooltip
/// \param flags       or'ed PSTF_* constants
/// \return length of generated text

idaman bool ida_export print_strlit_type(
        qstring *out,
        int32 strtype,
        qstring *out_tooltip = nullptr,
        int flags = 0);


/// Get additional information about an operand representation.
/// \param buf    buffer to receive the result. may not be nullptr
/// \param ea     linear address of item
/// \param n      number of operand, 0 or 1
/// \param flags  flags of the item
/// \return nullptr if no additional representation information

idaman opinfo_t *ida_export get_opinfo(
        opinfo_t *buf,
        ea_t ea,
        int n,
        flags64_t flags);


/// Set additional information about an operand representation.
/// This function is a low level one. Only the kernel should use it.
/// \param ea     linear address of the item
/// \param n      number of operand, 0 or 1 (see the note below)
/// \param flag   flags of the item
/// \param ti     additional representation information
/// \param suppress_events do not generate changing_op_type and op_type_changed events
/// \return success
/// \note for custom formats (if is_custfmt(flag, n) is true) or for offsets
/// (if is_off(flag, n) is true) N can be in range 0..UA_MAXOP-1 or equal to OPND_ALL.
/// In the case of OPND_ALL the additional information about all operands will be
/// set.

idaman bool ida_export set_opinfo(
        ea_t ea,
        int n,
        flags64_t flag,
        const opinfo_t *ti,
        bool suppress_events=false);


/// Get size of data type specified in flags 'F'.
/// \param ea  linear address of the item
/// \param F   flags
/// \param ti  additional information about the data type. For example,
///            if the current item is a structure instance,
///            then ti->tid is structure id. Otherwise is ignored (may be nullptr).
///            If specified as nullptr, will be automatically retrieved from the database
/// \return
///   - byte : 1
///   - word : 2
///   - etc...
///
/// If flags doesn't specify a data, then return 1

idaman asize_t ida_export get_data_elsize(ea_t ea, flags64_t F, const opinfo_t *ti=nullptr);


/// Get full size of data type specified in flags 'F'.
/// takes into account processors with wide bytes
/// e.g. returns 2 for a byte element with 16-bit bytes
inline asize_t get_full_data_elsize(ea_t ea, flags64_t F, const opinfo_t *ti=nullptr)
{
  asize_t nbytes = get_data_elsize(ea, F, ti);
  return nbytes * bytesize(ea);
}


/// Is the item at 'ea' variable size?.
/// \param ea        linear address of the item
/// \param F         flags
/// \param ti        additional information about the data type. For example,
///                  if the current item is a structure instance,
///                  then ti->tid is structure id. Otherwise is ignored (may be nullptr).
///                  If specified as nullptr, will be automatically retrieved from the database
/// \param itemsize  if not nullptr and the item is varsize, itemsize
///                  will contain the calculated item size (for struct types, the minimal size is returned)
/// \retval 1  varsize item
/// \retval 0  fixed item
/// \retval -1 error (bad data definition)

idaman int ida_export is_varsize_item(
        ea_t ea,
        flags64_t F,
        const opinfo_t *ti=nullptr,
        asize_t *itemsize=nullptr);


/// Can define item (instruction/data) of the specified 'length', starting at 'ea'?
/// \note if there is an item starting at 'ea', this function ignores it
/// \note this function converts to unexplored all encountered data items
///       with fixup information. Should be fixed in the future.
/// \param ea     start of the range for the new item
/// \param length length of the new item in bytes
/// \param flags  if not 0, then the kernel will ignore the data types
///               specified by the flags and destroy them. For example:
///                  <pre>
///                  1000 dw 5
///                  1002 db 5 ; undef
///                  1003 db 5 ; undef
///                  1004 dw 5
///                  1006 dd 5
///                  </pre>
///               can_define_item(1000, 6, 0) - false because of dw at 1004  \n
///               can_define_item(1000, 6, word_flag()) - true, word at 1004 is destroyed
/// \return 1-yes, 0-no
///
/// This function may return 0 if:
///      - a new item would cross segment boundaries
///      - a new item would overlap with existing items (except items specified by 'flags')

idaman bool ida_export can_define_item(ea_t ea, asize_t length, flags64_t flags);

/// \defgroup FF_CODE Code bytes
/// \ingroup FF_
/// Represent characteristics of instructions
//@{

//-------------------------------------------------------------------------
/// \defgroup FF_codebits Bits: code bytes
//@{
#define MS_CODE 0xF0000000LU             ///< Mask for code bits
#define FF_FUNC 0x10000000LU             ///< function start?
//              0x20000000LU             // not used
#define FF_IMMD 0x40000000LU             ///< Has Immediate value ?
#define FF_JUMP 0x80000000LU             ///< Has jump table or switch_info?
//@}

/// \defgroup FF_codefuncs Functions: work with code bits
//@{

/// Has immediate value?

inline THREAD_SAFE bool idaapi has_immd(flags64_t F)      { return is_code(F) && (F & FF_IMMD) != 0; }


/// Is function start?

inline THREAD_SAFE bool idaapi is_func(flags64_t F)      { return is_code(F) && (F & FF_FUNC) != 0; }


/// Set 'has immediate operand' flag.
/// Returns true if the #FF_IMMD bit was not set and now is set

idaman bool ida_export set_immd(ea_t ea);


//@} FF_codefuncs
//@} FF_CODE

//-----------------------------------------------------------------------
// Custom data type and format definitions
//-----------------------------------------------------------------------

/// Information about a data type
struct data_type_t
{
  int cbsize;                           ///< size of this structure
  void *ud;                             ///< user-defined data to be passed to callbacks
  int props;                            ///< properties
#define DTP_NODUP 0x0001                ///<   do not use dup construct
  const char *name;                     ///< name of the data type. must be unique
  const char *menu_name;                ///< Visible data type name to use in menus
                                        ///< if nullptr, no menu item will be created
  const char *hotkey;                   ///< Hotkey for the corresponding menu item
                                        ///< if nullptr, no hotkey will be associated with the menu item
  const char *asm_keyword;              ///< keyword to use for this type in the assembly
                                        ///< if nullptr, the data type cannot be used in the listing
                                        ///< it can still be used in cpuregs window
  asize_t value_size;                   ///< size of the value in bytes

  /// Should this type be shown in UI menus
  /// \return success
  bool is_present_in_menus() const { return menu_name != nullptr && asm_keyword != nullptr; }

  /// May create data? nullptr means always may
  /// \param ud      user-defined data
  /// \param ea      address of the future item
  /// \param nbytes  size of the future item
  bool (idaapi *may_create_at)(
        void *ud,
        ea_t ea,
        size_t nbytes);

  /// This function is used to determine size of the (possible) item at 'ea'.
  /// This callback is required only for varsize datatypes.
  /// \param ud       user-defined data
  /// \param ea       address of the item
  /// \param maxsize  maximal size of the item
  /// \return 0 if no such item can be created/displayed
  asize_t (idaapi *calc_item_size)(
        void *ud,
        ea_t ea,
        asize_t maxsize);

#ifndef SWIG
  DECLARE_COMPARISONS(data_type_t);
#endif
};

/// Information about a data format
struct data_format_t
{
  int32 cbsize;             ///< size of this structure
  void *ud;                 ///< user-defined data to be passed to callbacks
  int props;                ///< properties (currently 0)
  const char *name;         ///< Format name, must be unique
  const char *menu_name;    ///< Visible format name to use in menus
                            ///< if nullptr, no menu item will be created
  const char *hotkey;       ///< Hotkey for the corresponding menu item
                            ///< if nullptr, no hotkey will be associated with the menu item
  asize_t value_size;       ///< size of the value in bytes
                            ///< 0 means any size is ok
                            ///< data formats that are registered for standard types (dtid 0)
                            ///< may be called with any value_size (instruction operands only)
  int32 text_width;         ///< Usual width of the text representation
                            ///< This value is used to calculate the width
                            ///< of the control to display values of this type

  /// Should this format be shown in UI menus
  /// \return success
  bool is_present_in_menus() const { return menu_name != nullptr; }

  /// Convert to colored string.
  /// \param ud           user-defined data
  /// \param out          output buffer. may be nullptr
  /// \param value        value to print. may not be nullptr
  /// \param size         size of value in 8-bit bytes
  /// \param current_ea   current address (BADADDR if unknown)
  /// \param operand_num  current operand number
  /// \param dtid         custom data type id (0-standard built-in data type)
  /// \return success
  bool (idaapi *print)(
        void *ud,
        qstring *out,
        const void *value,
        asize_t size,
        ea_t current_ea,
        int operand_num,
        int dtid);

  /// Convert from uncolored string.
  /// \param ud           user-defined data
  /// \param value        output buffer. may be nullptr
  /// \param input        input string. may not be nullptr
  /// \param current_ea   current address (BADADDR if unknown)
  /// \param operand_num  current operand number (-1 if unknown)
  /// \param errstr       buffer for error message
  /// \return success
  bool (idaapi *scan)(
        void *ud,
        bytevec_t *value,
        const char *input,
        ea_t current_ea,
        int operand_num,
        qstring *errstr);

  /// Analyze custom data format occurrence
  /// This callback can be used to create xrefs from the current item.
  /// This callback may be missing.
  /// \param ud           user-defined data
  /// \param current_ea   current address (BADADDR if unknown)
  /// \param operand_num  current operand number
  void (idaapi *analyze)(
        void *ud,
        ea_t current_ea,
        int operand_num);

#ifndef SWIG
  DECLARE_COMPARISONS(data_format_t);
#endif
};


/// Register a new data type.
/// \param dtinfo  description of the new data type
/// \return > 0 : id of the new custom data type,
///         < 0 : error when the custom data type with the same name has
///               already been registered
///         \note dtid 0 is reserved for built-in data types.

idaman int ida_export register_custom_data_type(const data_type_t *dtinfo);


/// Unregister a data type.
/// When the idb is closed, all custom data types are automatically
/// unregistered, but since it happens too late (plugin modules could
/// already be unloaded) one has to unregister custom data types explicitly.
/// The ids of unregistered custom data types remain allocated and when the
/// same name is reused to register a custom data type, it will get assigned
/// the same id.
/// \param dtid   data type to unregister
/// \retval true  ok
/// \retval false no such dtid

idaman bool ida_export unregister_custom_data_type(int dtid);


/// Register a new data format.
/// \param dtform  description of the new data format
/// \return > 0 : id of the new custom data format,
///         < 0 : error when the custom data format with the same name has
///               already been registered to the data type
///         \note dfid 0 is unused.

idaman int ida_export register_custom_data_format(const data_format_t *dtform);


/// Unregister a data format.
/// \sa unregister_custom_data_type()
/// \param dfid   data format to unregister
/// \retval true  ok
/// \retval false no such dfid

idaman bool ida_export unregister_custom_data_format(int dfid);


/// Get definition of a registered custom data type.
/// \param dtid  data type id
/// \return data type definition or nullptr

idaman const data_type_t *ida_export get_custom_data_type(int dtid);


/// Get definition of a registered custom data format.
/// \param dfid  data format id
/// \return data format definition or nullptr

idaman const data_format_t *ida_export get_custom_data_format(int dfid);


/// Attach the data format to the data type.
/// \param dtid  data type id that can use the data format.
///              0 means all standard data types. Such data formats can be
///              applied to any data item or instruction operands. For
///              instruction operands, the data_format_t::value_size check
///              is not performed by the kernel.
/// \param dfid  data format id
/// \retval true  ok
/// \retval false no such `dtid', or no such `dfid', or the data format has
///               already been attached to the data type

idaman bool ida_export attach_custom_data_format(int dtid, int dfid);


/// Detach the data format from the data type.
/// Unregistering a custom data type detaches all attached data formats,
/// no need to detach them explicitly. You still need unregister them.
/// Unregistering a custom data format detaches it from all attached data
/// types.
/// \param dtid  data type id to detach data format from
/// \param dfid  data format id to detach
/// \retval true  ok
/// \retval false no such `dtid', or no such `dfid', or the data format was
///               not attached to the data type

idaman bool ida_export detach_custom_data_format(int dtid, int dfid);


/// Is the custom data format attached to the custom data type?
/// \param dtid  data type id
/// \param dfid  data format id
/// \return true or false

idaman bool ida_export is_attached_custom_data_format(int dtid, int dfid);

/// Get list of registered custom data type ids.
/// \param  out       buffer for the output. may be nullptr
/// \param  min_size  minimum value size
/// \param  max_size  maximum value size
/// \return number of custom data types with the specified size limits

idaman int ida_export get_custom_data_types(
        intvec_t *out,
        asize_t min_size=0,
        asize_t max_size=BADADDR);


/// Get list of attached custom data formats for the specified data type.
/// \param out    buffer for the output. may be nullptr
/// \param dtid   data type id
/// \return number of returned custom data formats. if error, returns -1

idaman int ida_export get_custom_data_formats(intvec_t *out, int dtid);


/// Get id of a custom data type.
/// \param name  name of the custom data type
/// \return id or -1

idaman int ida_export find_custom_data_type(const char *name);


/// Get id of a custom data format.
/// \param name  name of the custom data format
/// \return id or -1

idaman int ida_export find_custom_data_format(const char *name);


//--------------------------------------------------------------------------
//      I N D E N T E D   C O M M E N T S
//--------------------------------------------------------------------------

/// Set an indented comment.
/// \param ea      linear address
/// \param comm    comment string
///                - nullptr: do nothing (return 0)
///                - ""     : delete comment
/// \param rptble  is repeatable?
/// \return success

idaman bool ida_export set_cmt(ea_t ea, const char *comm, bool rptble);


/// Get an indented comment.
/// \param buf      output buffer, may be nullptr
/// \param ea       linear address. may point to tail byte, the function
///                 will find start of the item
/// \param rptble   get repeatable comment?
/// \return size of comment or -1

idaman ssize_t ida_export get_cmt(qstring *buf, ea_t ea, bool rptble);


/// Append to an indented comment.
/// Creates a new comment if none exists.
/// Appends a newline character and the specified string otherwise.
/// \param ea      linear address
/// \param str     comment string to append
/// \param rptble  append to repeatable comment?
/// \return success

idaman bool ida_export append_cmt(ea_t ea, const char *str, bool rptble);


//--------------------------------------------------------------------
//      P R E D E F I N E D   C O M M E N T S
//--------------------------------------------------------------------

/// Get predefined comment.
/// \param buf      buffer for the comment
/// \param ins      current instruction information
/// \return size of comment or -1

idaman ssize_t ida_export get_predef_insn_cmt(
        qstring *buf,
        const insn_t &ins);


//--------------------------------------------------------------------------
//      S E A R C H   F U N C T I O N S
//--------------------------------------------------------------------------
/// Find forward a byte with the specified value (only 8-bit value from the database).
/// example: ea=4 size=3 will inspect addresses 4, 5, and 6
/// \param sEA                linear address
/// \param size               number of bytes to inspect
/// \param value              value to find
/// \param bin_search_flags   combination of \ref BIN_SEARCH_
/// \return address of byte or #BADADDR

idaman ea_t ida_export find_byte(ea_t sEA, asize_t size, uchar value, int bin_search_flags);


/// Find reverse a byte with the specified value (only 8-bit value from the database).
/// example: ea=4 size=3 will inspect addresses 6, 5, and 4
/// \param sEA                the lower address of the search range
/// \param size               number of bytes to inspect
/// \param value              value to find
/// \param bin_search_flags   combination of \ref BIN_SEARCH_
/// \return address of byte or #BADADDR

idaman ea_t ida_export find_byter(ea_t sEA, asize_t size, uchar value, int bin_search_flags);


//-------------------------------------------------------------------------
struct compiled_binpat_t // compiled binary pattern compiled_binpat_t
{
  bytevec_t bytes;
  bytevec_t mask;
  rangevec_t strlits; // range of string literals, in _bytes_ ranges (not CPs)
  int encidx;

  compiled_binpat_t() : encidx(-1) {}
  bool all_bytes_defined() const { return mask.empty(); }
  void qclear() { bytes.qclear(); mask.qclear(); strlits.qclear(); encidx = -1; }

  bool operator==(const compiled_binpat_t &r) const
  {
    return bytes == r.bytes
        && mask == r.mask
        && strlits == r.strlits
        && encidx == r.encidx;
  }
  bool operator!=(const compiled_binpat_t &r) const { return !(*this == r); }
};
DECLARE_TYPE_AS_MOVABLE(compiled_binpat_t);
typedef qvector<compiled_binpat_t> compiled_binpat_vec_t;

#define PBSENC_DEF1BPU  0 /// Use the default 1 byte-per-unit IDB encoding
#define PBSENC_ALL     -1 /// Use all IDB encodings

/// Convert user-specified binary string to internal representation.
/// The 'in' parameter contains space-separated tokens:
/// \code
///  - numbers (numeric base is determined by 'radix')
///      - if value of number fits a byte, it is considered as a byte
///      - if value of number fits a word, it is considered as 2 bytes
///      - if value of number fits a dword,it is considered as 4 bytes
///  - "..." string constants
///  - 'x'  single-character constants
///  - ?    variable bytes
/// \endcode
///
/// Note that string constants are surrounded with double quotes.
///
/// Here are a few examples (assuming base 16):
/// \code
///  CD 21          - bytes 0xCD, 0x21
///  21CD           - bytes 0xCD, 0x21 (little endian ) or 0x21, 0xCD (big-endian)
///  "Hello", 0     - the null terminated string "Hello"
///  L"Hello"       - 'H', 0, 'e', 0, 'l', 0, 'l', 0, 'o', 0
///  B8 ? ? ? ? 90  - byte 0xB8, 4 bytes with any value, byte 0x90
/// \endcode
/// \param [out] out   a vector of compiled binary patterns, for use with bin_search2()
/// \param ea          linear address to convert for (the conversion depends on the
///                    address, because the number of bits in a byte depend on the
///                    segment type)
/// \param in          input text string
/// \param radix             numeric base of numbers (8,10,16)
/// \param strlits_encoding  the target encoding into which the string
///                          literals present in 'in', should be encoded.
///                          Can be any from [1, get_encoding_qty()), or
///                          the special values PBSENC_*
/// \param errbuf            error buffer (can be nullptr)
/// \return false either in case of parsing error, or if at least one
///               requested target encoding couldn't encode the string
///               literals present in "in".
//          true  otherwise
idaman bool ida_export parse_binpat_str(
        compiled_binpat_vec_t *out,
        ea_t ea,
        const char *in,
        int radix,
        int strlits_encoding=PBSENC_DEF1BPU,
        qstring *errbuf=nullptr);


/// Search for a string in the program.
/// \param start_ea linear address, start of range to search
/// \param end_ea   linear address, end of range to search (exclusive)
/// \param data     the prepared data to search for (see parse_binpat_str())
/// \param flags    combination of \ref BIN_SEARCH_
/// \return #BADADDR (if pressed Ctrl-Break or not found) or string address.

idaman ea_t ida_export bin_search2(
        ea_t start_ea,
        ea_t end_ea,
        const compiled_binpat_vec_t &data,
        int flags);

inline ea_t bin_search2(
        ea_t start_ea,
        ea_t end_ea,
        const uchar *image,
        const uchar *mask,
        size_t len,
        int flags)
{
  compiled_binpat_vec_t bbv;
  compiled_binpat_t &bv = bbv.push_back();
  bv.bytes.append(image, len);
  if ( mask != nullptr )
    bv.mask.append(mask, len);
  return bin_search2(start_ea, end_ea, bbv, flags);
}

/// Search for a patter in the program.
/// \param out_matched_idx index in data when pattern found
/// \param start_ea linear address, start of range to search
/// \param end_ea   linear address, end of range to search (exclusive)
/// \param data     the prepared data to search for (see parse_binpat_str())
/// \param flags    combination of \ref BIN_SEARCH_
/// \return #BADADDR (if pressed Ctrl-Break or not found) or pattern address.

idaman ea_t ida_export bin_search3(
        size_t *out_matched_idx,
        ea_t start_ea,
        ea_t end_ea,
        const compiled_binpat_vec_t &data,
        int flags);

///
/// \defgroup BIN_SEARCH_ Search flags
/// passed as 'flags' parameter to bin_search()
//@{
#define BIN_SEARCH_CASE         0x01 ///< case sensitive
#define BIN_SEARCH_NOCASE       0x00 ///< case insensitive
#define BIN_SEARCH_NOBREAK      0x02 ///< don't check for Ctrl-Break
#define BIN_SEARCH_INITED       0x04 ///< find_byte, find_byter: any initilized value
#define BIN_SEARCH_NOSHOW       0x08 ///< don't show search progress or update screen
#define BIN_SEARCH_FORWARD      0x00 ///< search forward for bytes
#define BIN_SEARCH_BACKWARD     0x10 ///< search backward for bytes
#define BIN_SEARCH_BITMASK      0x20 ///< searching using strict bit mask
//@}


/// Find the next initialized address

inline ea_t idaapi next_inited(ea_t ea, ea_t maxea)
{
  if ( ea >= maxea )
    return BADADDR;
  ++ea;
  return find_byte(ea, maxea-ea, 0, BIN_SEARCH_INITED);
}

/// Find the previous initialized address

inline ea_t idaapi prev_inited(ea_t ea, ea_t minea)
{
  if ( ea <= minea )
    return BADADDR;
  --ea;
  return find_byter(minea, ea-minea, 0, BIN_SEARCH_INITED);
}

/// Compare 'len' bytes of the program starting from 'ea' with 'image'.
/// \param ea          linear address
/// \param image       bytes to compare with
/// \param mask        array of mask bytes, it's length is 'len'.
///                    if the flag BIN_SEARCH_BITMASK is passsed, 'bitwise AND' is used
///                    to compare.
///                    if not;  1 means to perform the comparison of the corresponding byte.
///                    0 means not to perform.
///                    if mask == nullptr, then all bytes of 'image' will be compared.
///                    if mask == #SKIP_FF_MASK then 0xFF bytes will be skipped
/// \param len         length of block to compare in bytes.
/// \param bin_search_flags  combination of \ref BIN_SEARCH_
/// \retval 1 equal
/// \retval 0 not equal

idaman bool ida_export equal_bytes(
        ea_t ea,
        const uchar *image,
        const uchar *mask,
        size_t len,
        int bin_search_flags);

/// Used by equal_bytes() to skip 0xFF when searching the program
#define SKIP_FF_MASK  ((const uchar *)0xFF)

// Compare two bytes. This helper function is used for binary search.
inline bool bytes_match_for_bin_search(
        uchar c1,
        uchar c2,
        const uchar *mask,
        int i,
        int bin_search_flags)
{
  if ( (bin_search_flags & BIN_SEARCH_CASE) == 0 )
  {
    c1 = qtoupper(c1);
    c2 = qtoupper(c2);
  }
  if ( mask != nullptr )
  {
    if ( (bin_search_flags & BIN_SEARCH_BITMASK) != 0 )
      return ((c1 ^ c2) & mask[i]) == 0; // are bytes equal with mask applied?
    if ( mask == SKIP_FF_MASK )
    {
      if ( c2 == 0xFF )
        return true;
    }
    else if ( mask[i] == 0 )
    {
      return true;
    }
  }
  return c1 == c2;
}


//------------------------------------------------------------------------
//      H I D D E N   A R E A S
//------------------------------------------------------------------------

/// Hidden ranges - address ranges which can be replaced by their descriptions.
/// There is also a possibility to hide individual items completely (nalt.hpp, hide_item)
/// \note After modifying any of this struct's fields please call update_hidden_range()

struct hidden_range_t : public range_t
{
  char *description;    ///< description to display if the range is collapsed
  char *header;         ///< header lines to display if the range is expanded
  char *footer;         ///< footer lines to display if the range is expanded
  bool visible;         ///< the range state
  bgcolor_t color;      ///< range color
};

/// Update hidden range information in the database.
/// You cannot use this function to change the range boundaries
/// \param ha  range to update
/// \return success

idaman bool ida_export update_hidden_range(const hidden_range_t *ha);


/// Mark a range of addresses as hidden.
/// The range will be created in the invisible state with the default color
/// \param  ea1      linear address of start of the address range
/// \param  ea2      linear address of end of the address range
/// \param  description, header, footer  range parameters
/// \param  color    the range color
/// \return success

idaman bool ida_export add_hidden_range(
        ea_t ea1,
        ea_t ea2,
        const char *description,
        const char *header,
        const char *footer,
        bgcolor_t color=DEFCOLOR);


/// Get pointer to hidden range structure, in: linear address.
/// \param ea  any address in the hidden range

idaman hidden_range_t *ida_export get_hidden_range(ea_t ea);


/// Get pointer to hidden range structure, in: number of hidden range.
/// \param n  number of hidden range, is in range 0..get_hidden_range_qty()-1

idaman hidden_range_t *ida_export getn_hidden_range(int n);


/// Get number of hidden ranges

idaman int ida_export get_hidden_range_qty(void);


/// Get number of a hidden range.
/// \param ea  any address in the hidden range
/// \return number of hidden range (0..get_hidden_range_qty()-1)

idaman int ida_export get_hidden_range_num(ea_t ea);


/// Get pointer to previous hidden range.
/// \param ea  any address in the program
/// \return ptr to hidden range or nullptr if previous hidden range doesn't exist

idaman hidden_range_t *ida_export get_prev_hidden_range(ea_t ea);


/// Get pointer to next hidden range.
/// \param ea  any address in the program
/// \return ptr to hidden range or nullptr if next hidden range doesn't exist

idaman hidden_range_t *ida_export get_next_hidden_range(ea_t ea);


/// Get pointer to the first hidden range.
/// \return ptr to hidden range or nullptr

idaman hidden_range_t *ida_export get_first_hidden_range(void);


/// Get pointer to the last hidden range.
/// \return ptr to hidden range or nullptr

idaman hidden_range_t *ida_export get_last_hidden_range(void);


/// Delete hidden range.
/// \param ea  any address in the hidden range
/// \return success

idaman bool ida_export del_hidden_range(ea_t ea);


//--------------------------------------------------------------------------
#define GET_ITEM_HEAD_BODY      \
  if ( is_tail(get_flags(ea)) ) \
    ea = prev_not_tail(ea);     \
  return ea;
inline ea_t idaapi get_item_head(ea_t ea) { GET_ITEM_HEAD_BODY }

//------------------------------------------------------------------------
//      M E M O R Y   M A P P I N G
//------------------------------------------------------------------------

/// IDA supports memory mapping. References to the addresses from
/// the mapped range use data and meta-data from the mapping range.
/// \note You should set flag PR2_MAPPING in ph.flag2 to use memory mapping


/// Add memory mapping range.
/// \param  from start of the mapped range (nonexistent address)
/// \param  to   start of the mapping range (existent address)
/// \param  size size of the range
/// \return success

idaman bool ida_export add_mapping(ea_t from, ea_t to, asize_t size);


/// Delete memory mapping range.
/// \param ea any address in the mapped range

idaman void ida_export del_mapping(ea_t ea);


/// Translate address according to current mappings.
/// \param  ea address to translate
/// \return translated address

idaman ea_t ida_export use_mapping(ea_t ea);

/// Get number of mappings.

idaman size_t ida_export get_mappings_qty(void);

/// Get memory mapping range by its number.
/// \param  from start of the mapped range
/// \param  to   start of the mapping range
/// \param  size size of the range
/// \param  n    number of mapping range (0..get_mappings_qty()-1)
/// \return false if the specified range doesn't exist,
///         otherwise returns `from', `to', `size'
idaman bool ida_export get_mapping(
        ea_t *from,
        ea_t *to,
        asize_t *size,
        size_t n);


#ifndef BYTES_SOURCE    // undefined bit masks so no one can use them directly
#undef MS_VAL
#undef FF_IVL
#undef MS_CLS
#undef FF_CODE
#undef FF_DATA
#undef FF_TAIL
#undef FF_UNK
#undef MS_COMM
#undef FF_COMM
#undef FF_REF
#undef FF_LINE
#undef FF_NAME
#undef FF_LABL
#undef FF_ANYNAME
#undef FF_FLOW
#undef FF_SIGN
#undef FF_BNOT
#undef DT_TYPE
#undef FF_BYTE
#undef FF_WORD
#undef FF_DWORD
#undef FF_QWORD
#undef FF_OWORD
#undef FF_YWORD
#undef FF_ZWORD
#undef FF_FLOAT
#undef FF_DOUBLE
#undef FF_TBYTE
#undef FF_PACKREAL
#undef FF_STRLIT
#undef FF_STRUCT
#undef FF_ALIGN
#undef FF_CUSTOM
#undef MS_CODE
#undef FF_FUNC
#undef FF_IMMD
//#undef FF_JUMP
#undef MS_TAIL
#undef TL_TSFT
#undef TL_TOFF
#undef MAX_TOFF
#endif // BYTES_SOURCE

// byte array to hex string
inline THREAD_SAFE ssize_t get_hex_string(char *buf, size_t bufsize, const uchar *bytes, size_t len)
{
  const char *const start = buf;
  const char *const end   = buf + bufsize;
  for ( size_t i = 0; i < len; i++ )
    buf += ::qsnprintf(buf, end - buf, "%02X", *bytes++);
  return buf - start;
}


#ifndef NO_OBSOLETE_FUNCS
idaman DEPRECATED ea_t ida_export bin_search(ea_t, ea_t, const uchar *, const uchar *, size_t, int, int); // use bin_search2()
idaman DEPRECATED uchar ida_export get_8bit(ea_t *ea, uint32 *v, int *nbit);  // use get_octet2()
idaman DEPRECATED uchar ida_export get_octet(ea_t *ea, uint64 *v, int *nbit); // use get_octet2()
idaman DEPRECATED ea_t ida_export free_chunk(ea_t bottom, asize_t size, int32 step);
#endif

#endif // BYTES_HPP
