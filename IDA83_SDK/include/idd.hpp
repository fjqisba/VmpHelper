/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _IDD_HPP
#define _IDD_HPP

#include <ieee.h>
#include <range.hpp>
#include <ua.hpp>

/*! \file idd.hpp

  \brief Contains definition of the interface to IDD modules.

  The interface consists of structures describing the target
  debugged processor and a debugging API.
*/

/// The IDD interface version number
#define         IDD_INTERFACE_VERSION   28

class idc_value_t;
class tinfo_t;

//====================================================================
//
//                       Process and Threads
//

typedef int pid_t;                   ///< process id
typedef int thid_t;                  ///< thread id

#define NO_PROCESS pid_t(-1)         ///< No process
#define NO_THREAD  0                 ///< No thread.
                                     ///< in ::PROCESS_STARTED this value
                                     ///< can be used to specify that
                                     ///< the main thread has not been created.
                                     ///< It will be initialized later
                                     ///< by a ::THREAD_STARTED event.

/// Process information
struct process_info_t
{
  pid_t pid;    ///< process id
  qstring name; ///< process name
};
DECLARE_TYPE_AS_MOVABLE(process_info_t);
typedef qvector<process_info_t> procinfo_vec_t;

//--------------------------------------------------------------------
/// Runtime attributes of the debugger/process.
/// It is guaranteed that these attributes are really valid after start/attach process
struct debapp_attrs_t
{
  int32 cbsize;         ///< control field: size of this structure

  /// address size of the process.
  /// Since 64-bit debuggers usually can debug 32-bit applications, we cannot
  /// rely on sizeof(ea_t) to detect the current address size. The following
  /// variable should be used instead. It is initialized with 8 for 64-bit
  /// debuggers but they should adjust it as soon as they learn that a
  /// 32-bit application is being debugged.
  /// For 32-bit debuggers it is initialized with 4.
  int addrsize;

  qstring platform;     ///< platform name process is running/debugging under.
                        ///< (is used as a key value in exceptions.cfg)

/// \def{DEF_ADDRSIZE, Default address size - see debapp_attrs_t::addrsize}
#ifdef __EA64__
#define DEF_ADDRSIZE  8
#else
#define DEF_ADDRSIZE  4
#endif

  int is_be;

  /// Constructor - initialize with #DEF_ADDRSIZE
  debapp_attrs_t()
    : cbsize(sizeof(debapp_attrs_t)),
      addrsize(DEF_ADDRSIZE),
      is_be(-1)
  {}
};

//====================================================================
//
//                          Registers
//

typedef unsigned char register_class_t; ///< Each register is associated to
                                        ///< a register class.
                                        ///< example: "segment", "mmx", ...

/// Debuggee register information
struct register_info_t
{
  const char *name;                   ///< Register name.
  uint32 flags;                       ///< \ref REGISTER_
/// \defgroup REGISTER_ Register info attribute flags
/// Used by register_info_t::flags
//@{
#define REGISTER_READONLY 0x0001      ///< the user can't modify the current value of this register
#define REGISTER_IP       0x0002      ///< instruction pointer
#define REGISTER_SP       0x0004      ///< stack pointer
#define REGISTER_FP       0x0008      ///< frame pointer
#define REGISTER_ADDRESS  0x0010      ///< may contain an address
#define REGISTER_CS       0x0020      ///< code segment
#define REGISTER_SS       0x0040      ///< stack segment
#define REGISTER_NOLF     0x0080      ///< displays this register without returning to the next line,
                                      ///< allowing the next register to be displayed to its right (on the same line)
#define REGISTER_CUSTFMT  0x0100      ///< register should be displayed using a custom data format.
                                      ///< the format name is in bit_strings[0];
                                      ///< the corresponding ::regval_t will use ::bytevec_t
//@}
  register_class_t register_class;    ///< segment, mmx, etc.
  op_dtype_t dtype;                   ///< Register size (see \ref dt_)
  const char *const *bit_strings;     ///< strings corresponding to each bit of the register.
                                      ///< (nullptr = no bit, same name = multi-bits mask)
  uval_t default_bit_strings_mask;    ///< mask of default bits
};
DECLARE_TYPE_AS_MOVABLE(register_info_t);
typedef qvector<register_info_t> register_info_vec_t;

//--------------------------------------------------------------------------
struct dynamic_register_set_t
{
  typedef qvector<const char *> const_char_vec_t;

  register_info_vec_t       ri_vec;
  qstrvec_t                 strvec;
  const_char_vec_t          classname_ptrs;
  qvector<const_char_vec_t> bit_strings_ptrs_vec;

  void clear(void)
  {
    ri_vec.clear();
    strvec.clear();
    classname_ptrs.clear();
    bit_strings_ptrs_vec.clear();
  }

  void add_register(
        const char *name,
        int flags,
        op_dtype_t dtype,
        register_class_t register_class,
        const char *const *bit_strings,
        uval_t bits_mask)
  {
    // Allocate bit_strings.
    if ( bit_strings != nullptr )
    {
      size_t num_bits = (flags & REGISTER_CUSTFMT) != 0 ? 1
                      : dtype == dt_word                ? 16
                      : dtype == dt_dword               ? 32
                      : dtype == dt_qword               ? 64
                      :                                 0;
      QASSERT(1795, num_bits != 0);
      const_char_vec_t &ptrvec = bit_strings_ptrs_vec.push_back();
      ptrvec.resize(num_bits, nullptr);
      for ( size_t i = 0; i < num_bits; i++ )
      {
        if ( bit_strings[i] != nullptr )
        {
          qstring &field_name = strvec.push_back();
          field_name = bit_strings[i];
          ptrvec[i] = field_name.c_str();
        }
      }
      bit_strings = ptrvec.begin();
    }

    // Allocate name.
    qstring &regname = strvec.push_back();
    regname = name;

    // Add entry for register.
    register_info_t &ri = ri_vec.push_back();
    ri.name                     = regname.c_str();
    ri.flags                    = flags;
    ri.dtype                    = dtype;
    ri.register_class           = register_class;
    ri.bit_strings              = bit_strings;
    ri.default_bit_strings_mask = bits_mask;
  }

  void set_regclasses(const char **register_classes)
  {
    while ( *register_classes != nullptr )
    {
      qstring &register_class = strvec.push_back();
      register_class = *register_classes++;
      classname_ptrs.push_back(register_class.begin());
    }
    classname_ptrs.push_back(nullptr);
  }

  // Values for debugger_t.
  size_t nregs(void)               { return ri_vec.size(); }
  register_info_t *registers(void) { return ri_vec.begin(); }
  const char **regclasses(void)    { return classname_ptrs.begin(); }
};

// helper functions:
idaman THREAD_SAFE void ida_export serialize_dynamic_register_set(
        bytevec_t *buf,
        dynamic_register_set_t &idaregs);
idaman THREAD_SAFE void ida_export deserialize_dynamic_register_set(
        dynamic_register_set_t *idaregs,
        memory_deserializer_t &mmdsr);
idaman THREAD_SAFE void ida_export serialize_insn(
        bytevec_t *s,
        const insn_t &insn);
idaman THREAD_SAFE void ida_export deserialize_insn(
        insn_t *insn,
        memory_deserializer_t &mmdsr);

//====================================================================
//
//                           Memory
//

/// Used by debugger modules to report memory are information to IDA kernel.
/// It is ok to return empty fields if information is not available.
struct memory_info_t : public range_t
{
  qstring name;                ///< Memory range name
  qstring sclass;              ///< Memory range class name
  ea_t sbase;                  ///< Segment base (meaningful only for segmented architectures, e.g. 16-bit x86)
                               ///< The base is specified in paragraphs (i.e. shifted to the right by 4)
  uchar bitness;               ///< Number of bits in segment addresses (0-16bit, 1-32bit, 2-64bit)
  uchar perm;                  ///< Memory range permissions (0-no information): see segment.hpp
  memory_info_t(void)
    : sbase(0),bitness(0),perm(0) {}
  bool operator ==(const memory_info_t &r) const
  {
    return start_ea == r.start_ea
        && end_ea   == r.end_ea
        && name    == r.name
        && sclass  == r.sclass
        && sbase   == r.sbase
        && bitness == r.bitness
        && perm    == r.perm;
  }
  bool operator !=(const memory_info_t &r) const { return !(*this == r); }
};
DECLARE_TYPE_AS_MOVABLE(memory_info_t);
struct meminfo_vec_t : public qvector<memory_info_t> {}; ///< vector of memory info objects

/// Used by debugger modules to keep track of images that are not mapped uniformly into memory.
struct scattered_segm_t : public range_t
{
  qstring name; ///< name of the segment
};
DECLARE_TYPE_AS_MOVABLE(scattered_segm_t);
typedef qvector<scattered_segm_t> scattered_image_t; ///< vector of scattered segments

//====================================================================
//
//                         Debug events
//

/// Debug event codes
enum event_id_t
{
  NO_EVENT         = 0x00000000, ///< Not an interesting event. This event can be
                                 ///< used if the debugger module needs to return
                                 ///< an event but there are no valid events.
  PROCESS_STARTED  = 0x00000001, ///< New process has been started.
  PROCESS_EXITED   = 0x00000002, ///< Process has been stopped.
  THREAD_STARTED   = 0x00000004, ///< New thread has been started.
  THREAD_EXITED    = 0x00000008, ///< Thread has been stopped.
  BREAKPOINT       = 0x00000010, ///< Breakpoint has been reached. IDA will complain
                                 ///< about unknown breakpoints, they should be reported
                                 ///< as exceptions.
  STEP             = 0x00000020, ///< One instruction has been executed. Spurious
                                 ///< events of this kind are silently ignored by IDA.
  EXCEPTION        = 0x00000040, ///< Exception.
  LIB_LOADED       = 0x00000080, ///< New library has been loaded.
  LIB_UNLOADED     = 0x00000100, ///< Library has been unloaded.
  INFORMATION      = 0x00000200, ///< User-defined information.
                                 ///< This event can be used to return empty information
                                 ///< This will cause IDA to call get_debug_event()
                                 ///< immediately once more.
  PROCESS_ATTACHED = 0x00000400, ///< Successfully attached to running process.
  PROCESS_DETACHED = 0x00000800, ///< Successfully detached from process.
  PROCESS_SUSPENDED= 0x00001000, ///< Process has been suspended.
                                 ///< This event can be used by the debugger module
                                 ///< to signal if the process spontaneously gets
                                 ///< suspended (not because of an exception,
                                 ///< breakpoint, or single step). IDA will silently
                                 ///< switch to the 'suspended process' mode without
                                 ///< displaying any messages.
  TRACE_FULL       = 0x00002000, ///< The trace buffer of the tracer module is full
                                 ///< and IDA needs to read it before continuing
};

// helper functions:
struct debug_event_t;
idaman THREAD_SAFE void ida_export free_debug_event(debug_event_t *ev);
idaman THREAD_SAFE void ida_export copy_debug_event(debug_event_t *ev, const debug_event_t &r);
idaman THREAD_SAFE void ida_export set_debug_event_code(debug_event_t *ev, event_id_t id);

/// Describes a module load event.
/// (see ::PROCESS_STARTED, ::PROCESS_ATTACHED, ::LIB_LOADED)
struct modinfo_t
{
  qstring name;         ///< full name of the module
  ea_t base;            ///< module base address. if unknown pass #BADADDR
  asize_t size;         ///< module size. if unknown pass 0
  ea_t rebase_to;       ///< if not #BADADDR, then rebase the program to the specified address
};
DECLARE_TYPE_AS_MOVABLE(modinfo_t);
typedef qvector<modinfo_t> modinfovec_t;

/// Describes a breakpoint event.
/// (see ::BREAKPOINT)
struct bptaddr_t
{
  ea_t hea;             ///< Possible address referenced by hardware breakpoints
  ea_t kea;             ///< Address of the triggered bpt from the kernel's point
                        ///< of view. (for some systems with special memory mappings,
                        ///< the triggered ea might be different from event ea).
                        ///< Use to #BADADDR for flat memory model.
  bptaddr_t(): hea(BADADDR), kea(BADADDR) {}
};

/// Describes an exception.
/// (see ::EXCEPTION)
struct excinfo_t
{
  uint32 code;          ///< Exception code
  bool can_cont;        ///< Execution of the process can continue after this exception?
  ea_t ea;              ///< Possible address referenced by the exception
  qstring info;         ///< Exception message
};

/// This structure is used only when detailed information
///   about a debug event is needed.
struct debug_event_t
{
  pid_t pid;               ///< Process where the event occurred
  thid_t tid;              ///< Thread where the event occurred
  ea_t ea;                 ///< Address where the event occurred
  bool handled;            ///< Is event handled by the debugger?.
                           ///< (from the system's point of view)
                           ///< Meaningful for ::EXCEPTION events
private:
  event_id_t _eid;
#ifndef SWIG
  char bytes[qmax(sizeof(modinfo_t), sizeof(excinfo_t))];
  void check_usage(uint32 req) { QASSERT(1502, (_eid & req) != 0); }
#endif

public:
  debug_event_t(void) :
    pid(NO_PROCESS),
    tid(NO_THREAD),
    ea(BADADDR),
    handled(false),
    _eid(NO_EVENT)
  {
    memset(bytes, 0, sizeof(bytes));
  }
  debug_event_t(const debug_event_t &r) : _eid(NO_EVENT) { copy(r); }
  ~debug_event_t(void) { clear(); }
  debug_event_t &operator =(const debug_event_t &r) { return copy(r); }
  debug_event_t &copy(const debug_event_t &r) { copy_debug_event(this, r); return *this; }

  /// clear the dependent information (see below), set event code to NO_EVENT
  void clear(void) { free_debug_event(this); }

  void clear_all(void)
  {
    clear();
    pid = NO_PROCESS;
    tid = NO_THREAD;
    ea = BADADDR;
    handled = false;
  }

  /// Event code
  event_id_t eid() const { return _eid; }

  /// Set event code.
  /// If the new event code is compatible with the old one
  /// then the dependent information (see below) will be preserved.
  /// Otherwise the event will be cleared and the new event code will be set.
  void set_eid(event_id_t id) { set_debug_event_code(this, id); }

  /// Information that depends on the event code:

  ///< ::PROCESS_STARTED, ::PROCESS_ATTACHED, ::LIB_LOADED
  modinfo_t &modinfo()
  {
    check_usage(PROCESS_STARTED | PROCESS_ATTACHED | LIB_LOADED);
    return *(modinfo_t *)bytes;
  }
  ///< ::PROCESS_EXITED, ::THREAD_EXITED
  int &exit_code()
  {
    check_usage(PROCESS_EXITED | THREAD_EXITED);
    return *(int *)bytes;
  }
  ///< ::THREAD_STARTED (thread name)
  ///< ::LIB_UNLOADED (unloaded library name)
  ///< ::INFORMATION (will be displayed in the output window if not empty)
  qstring &info()
  {
    check_usage(THREAD_STARTED | LIB_UNLOADED | INFORMATION);
    return *(qstring *)bytes;
  }
  ///< ::BREAKPOINT
  bptaddr_t &bpt()
  {
    check_usage(BREAKPOINT);
    return *(bptaddr_t *)bytes;
  }
  ///< ::EXCEPTION
  excinfo_t &exc()
  {
    check_usage(EXCEPTION);
    return *(excinfo_t *)bytes;
  }

  const modinfo_t &modinfo() const { return CONST_CAST(debug_event_t*)(this)->modinfo(); }
  const int &exit_code() const     { return CONST_CAST(debug_event_t*)(this)->exit_code(); }
  const qstring &info() const      { return CONST_CAST(debug_event_t*)(this)->info(); }
  const bptaddr_t &bpt() const     { return CONST_CAST(debug_event_t*)(this)->bpt(); }
  const excinfo_t &exc() const     { return CONST_CAST(debug_event_t*)(this)->exc(); }

  modinfo_t &set_modinfo(event_id_t id)
  {
    set_eid(id);
    return modinfo();
  }

  void set_exit_code(event_id_t id, int code)
  {
    set_eid(id);
    exit_code() = code;
  }

  qstring &set_info(event_id_t id)
  {
    set_eid(id);
    return info();
  }

  bptaddr_t &set_bpt(void)
  {
    set_eid(BREAKPOINT);
    return bpt();
  }

  excinfo_t &set_exception(void)
  {
    set_eid(EXCEPTION);
    return exc();
  }

  /// On some systems with special memory mappings the triggered ea might be
  /// different from the actual ea. Calculate the address to use.
  ea_t bpt_ea(void) const
  {
    return _eid == BREAKPOINT && bpt().kea != BADADDR ? bpt().kea : ea;
  }

  friend THREAD_SAFE void ida_export free_debug_event(debug_event_t *ev);
  friend THREAD_SAFE void ida_export copy_debug_event(debug_event_t *ev, const debug_event_t &r);
  friend THREAD_SAFE void ida_export set_debug_event_code(debug_event_t *ev, event_id_t id);
};
DECLARE_TYPE_AS_MOVABLE(debug_event_t);

typedef int bpttype_t; ///< hardware breakpoint type (see \ref BPT_H)

/// \defgroup BPT_H Hardware breakpoint ids
/// Fire the breakpoint upon one of these events
//@{
const bpttype_t
  BPT_WRITE    = 1,                   ///< Write access
  BPT_READ     = 2,                   ///< Read access
  BPT_RDWR     = 3,                   ///< Read/write access
  BPT_SOFT     = 4,                   ///< Software breakpoint
  BPT_EXEC     = 8,                   ///< Execute instruction
  BPT_DEFAULT  = (BPT_SOFT|BPT_EXEC); ///< Choose bpt type automatically
//@}

/// Exception information
struct exception_info_t
{
  uint code;              ///< exception code
  uint32 flags;           ///< \ref EXC_
/// \defgroup EXC_ Exception info flags
/// Used by exception_info_t::flags
//@{
#define EXC_BREAK  0x0001 ///< break on the exception
#define EXC_HANDLE 0x0002 ///< should be handled by the debugger?
#define EXC_MSG    0x0004 ///< instead of a warning, log the exception to the output window
#define EXC_SILENT 0x0008 ///< do not warn or log to the output window
//@}

  /// Should we break on the exception?
  bool break_on(void) const { return (flags & EXC_BREAK) != 0; }

  /// Should we handle the exception?
  bool handle(void) const { return (flags & EXC_HANDLE) != 0; }

  qstring name;           ///< Exception standard name
  qstring desc;           ///< Long message used to display info about the exception

  exception_info_t(void) : code(0), flags(0) {}
  exception_info_t(uint _code, uint32 _flags, const char *_name, const char *_desc)
    : code(_code), flags(_flags), name(_name), desc(_desc) {}
};
DECLARE_TYPE_AS_MOVABLE(exception_info_t);
typedef qvector<exception_info_t> excvec_t; ///< vector of exception info objects

/// Structure to hold a register value.
/// Small values (up to 64-bit integers and floating point values) use
/// #RVT_INT and #RVT_FLOAT types. For bigger values the bytes() vector is used.
struct regval_t
{
/// \defgroup RVT_ Register value types
/// Used by regval_t::rvtype
//@{
#define RVT_INT         (-1)          ///< integer
#define RVT_FLOAT       (-2)          ///< floating point
#define RVT_UNAVAILABLE (-3)          ///< unavailable;
                                      ///< other values mean custom data type
//@}
  int32 rvtype = RVT_INT;             ///< one of \ref RVT_
#ifndef SWIG
  union
  {
#endif
    uint64 ival;                      ///< 8:  integer value
    fpvalue_t fval;                   ///< 12: floating point value in the internal representation (see ieee.h)
#ifndef SWIG
    uchar reserve[sizeof(bytevec_t)]; ///< bytevec_t: custom data type (use bytes() to access it)
  };
#endif
  regval_t() : ival(~uint64(0)) {}
  ~regval_t() { clear(); }
  regval_t(const regval_t &r) { *this = r; }

  /// Assign this regval to the given value
  regval_t &operator = (const regval_t &r)
  {
    if ( this == &r )
      return *this;
    if ( r.rvtype >= 0 )
    {
      if ( rvtype >= 0 )
        bytes() = r.bytes();
      else
        new (&bytes()) bytevec_t(r.bytes());
    }
    else // r.rvtype < 0
    {
      if ( rvtype >= 0 )
        bytes().~bytevec_t();
      memcpy(&fval, &r.fval, sizeof(fval));
    }
    rvtype = r.rvtype;
    return *this;
  }

  /// Clear register value
  void clear(void)
  {
    if ( rvtype >= 0 )
    {
      bytes().~bytevec_t();
      rvtype = RVT_INT;
    }
  }

  /// Compare two regvals with '=='
  bool operator == (const regval_t &r) const
  {
    if ( rvtype == r.rvtype )
    {
      if ( rvtype == RVT_UNAVAILABLE )
        return true;
      if ( rvtype == RVT_INT )
        return ival == r.ival;
      return memcmp(get_data(), r.get_data(), get_data_size()) == 0;
    }
    return false;
  }

  /// Compare two regvals with '!='
  bool operator != (const regval_t &r) const { return !(*this == r); }

  /// Set this = r and r = this
  void swap(regval_t &r) { qswap(*this, r); }

  /// Use set_int()
  void _set_int(uint64 x) { ival = x; }
  /// Use set_float()
  void _set_float(const fpvalue_t &x) { fval = x; rvtype = RVT_FLOAT; }
  /// Use set_bytes(const uchar *, size_t)
  void _set_bytes(const uchar *data, size_t size) { new (&bytes()) bytevec_t(data, size); rvtype = 0; }
  /// Use set_bytes(const bytevec_t &)
  void _set_bytes(const bytevec_t &v) { new (&bytes()) bytevec_t(v); rvtype = 0; }
  /// Use set_bytes(void)
  bytevec_t &_set_bytes(void) { new (&bytes()) bytevec_t; rvtype = 0; return bytes(); }
  /// Use set_unavailable(void)
  void _set_unavailable(void) { ival = 0; rvtype = RVT_UNAVAILABLE; }

  /// \name Setters
  /// These functions ensure that the previous value is cleared
  //@{
  /// Set int value (ival)
  void set_int(uint64 x) { clear(); _set_int(x); }
  /// Set float value (fval)
  void set_float(const fpvalue_t &x) { clear(); _set_float(x); }
  /// Set custom regval with raw data
  void set_bytes(const uchar *data, size_t size) { clear(); _set_bytes(data, size); }
  /// Set custom value with existing bytevec
  void set_bytes(const bytevec_t &v) { clear(); _set_bytes(v); }
  /// Initialize this regval to an empty custom value
  bytevec_t &set_bytes(void) { clear(); _set_bytes(); return bytes(); }
  /// Mark as unavailable
  void set_unavailable(void) { clear(); _set_unavailable(); }

  //@}

  /// \name Getters
  //@{
  /// Get custom value
        bytevec_t &bytes(void)       { return *(bytevec_t *)reserve; }
  /// Get const custom value
  const bytevec_t &bytes(void) const { return *(bytevec_t *)reserve; }
  /// Get pointer to value
        void *get_data(void)       { return rvtype >= 0 ? (void *)bytes().begin() : (void *)&fval; }
  /// Get const pointer to value
  const void *get_data(void) const { return rvtype >= 0 ? (void *)bytes().begin() : (void *)&fval; }
  /// Get size of value
  size_t get_data_size(void) const
  {
    if ( rvtype >= 0 )
      return bytes().size();
    if ( rvtype == RVT_INT )
      return sizeof(ival);
    if ( rvtype == RVT_FLOAT )
      return sizeof(fval);
    return 0;
  }
  //@}
};
DECLARE_TYPE_AS_MOVABLE(regval_t);
typedef qvector<regval_t> regvals_t; ///< vector register value objects

/// Instruction operand information
struct idd_opinfo_t
{
  bool modified;        ///< the operand is modified (written) by the instruction
  ea_t ea;              ///< operand address (#BADADDR - no address)
  regval_t value;       ///< operand value. custom data is represented by 'bytes'.
  int debregidx;        ///< for custom data: index of the corresponding register in dbg->registers
  int value_size;       ///< size of the value in bytes

  idd_opinfo_t(void) : modified(false), ea(BADADDR), debregidx(-1), value_size(0) {}
};

/// Call stack trace information
struct call_stack_info_t
{
  ea_t callea;          ///< the address of the call instruction.
                        ///< for the 0th frame this is usually just the current value of EIP.
  ea_t funcea;          ///< the address of the called function
  ea_t fp;              ///< the value of the frame pointer of the called function
  bool funcok;          ///< is the function present?
  bool operator==(const call_stack_info_t &r) const
  {
    return callea == r.callea
        && funcea == r.funcea
        && funcok == r.funcok
        && fp     == r.fp;
  }
  bool operator!=(const call_stack_info_t &r) const { return !(*this == r); }
};
DECLARE_TYPE_AS_MOVABLE(call_stack_info_t);
struct call_stack_t : public qvector<call_stack_info_t> {}; ///< defined as struct so it can be forward-declared

//-------------------------------------------------------------------------
THREAD_SAFE inline void append_regval(bytevec_t &s, const regval_t &value)
{
  s.pack_dd(value.rvtype+2);
  if ( value.rvtype == RVT_INT )
  {
    s.pack_dq(value.ival+1);
  }
  else if ( value.rvtype == RVT_FLOAT )
  {
    s.append(&value.fval, sizeof(value.fval));
  }
  else if ( value.rvtype != RVT_UNAVAILABLE )
  {
    const bytevec_t &b = value.bytes();
    s.pack_dd(b.size());
    s.append(b.begin(), b.size());
  }
}

//-------------------------------------------------------------------------
template <class T>
THREAD_SAFE inline void extract_regval(regval_t *out, T &v)
{
  out->clear();
  out->rvtype = extract_dd(v) - 2;
  if ( out->rvtype == RVT_INT )
  {
    out->ival = extract_dq(v) - 1;
  }
  else if ( out->rvtype == RVT_FLOAT )
  {
    extract_obj(v, &out->fval, sizeof(out->fval));
  }
  else if ( out->rvtype != RVT_UNAVAILABLE )
  {
    bytevec_t &b = out->_set_bytes();
    int size = extract_dd(v);
    b.resize(size);
    extract_obj(v, b.begin(), size);
  }
}

//-------------------------------------------------------------------------
template <class T>
THREAD_SAFE inline void extract_regvals(
        regval_t *values,
        int n,
        T &v,
        const uchar *regmap)
{
  for ( int i=0; i < n && !v.eof(); i++ )
    if ( regmap == nullptr || test_bit(regmap, i) )
      extract_regval(&values[i], v);
}

//--------------------------------------------------------------------------
THREAD_SAFE inline void unpack_regvals(
        regval_t *values,
        int n,
        const uchar *regmap,
        memory_deserializer_t &mmdsr)
{
  extract_regvals(values, n, mmdsr, regmap);
}


/// Call a function from the debugged application.
/// \param[out] retval function return value
///                   - for #APPCALL_MANUAL, r will hold the new stack point value
///                   - for #APPCALL_DEBEV, r will hold the exception information upon failure
///                                   and the return code will be eExecThrow
/// \param func_ea  address to call
/// \param tid      thread to use. #NO_THREAD means to use the current thread
/// \param ptif     pointer to type of the function to call
/// \param argv     array of arguments
/// \param argnum   number of actual arguments
/// \return #eOk if successful, otherwise an error code

idaman error_t ida_export dbg_appcall(
        idc_value_t *retval,
        ea_t func_ea,
        thid_t tid,
        const tinfo_t *ptif,
        idc_value_t *argv,
        size_t argnum);


/// Cleanup after manual appcall.
/// \param tid  thread to use. #NO_THREAD means to use the current thread
/// The application state is restored as it was before calling the last appcall().
/// Nested appcalls are supported.
/// \return #eOk if successful, otherwise an error code

idaman error_t ida_export cleanup_appcall(thid_t tid);


/// Return values for get_debug_event()
enum gdecode_t
{
  GDE_ERROR = -1,       ///< error
  GDE_NO_EVENT,         ///< no debug events are available
  GDE_ONE_EVENT,        ///< got one event, no more available yet
  GDE_MANY_EVENTS,      ///< got one event, more events available
};

/// Input argument for update_bpts()
struct update_bpt_info_t
{
  ea_t ea;              ///< in: bpt address
  bytevec_t orgbytes;   ///< in(del), out(add): original bytes (only for swbpts)
  bpttype_t type;       ///< in: bpt type
  int size;             ///< in: bpt size (only for hwbpts)
  uchar code;           ///< in: 0. #BPT_SKIP entries must be skipped by the debugger module
                        ///< out: \ref BPT_
  pid_t pid;            ///< in: process id
  thid_t tid;           ///< in: thread id

  update_bpt_info_t()
    : ea(BADADDR), type(BPT_SOFT), size(0), code(0), pid(NO_PROCESS), tid(NO_THREAD) {}

  /// facilitate update_bpt_vec_t::find()
  bool operator==(const update_bpt_info_t &b) const
  {
    return ea == b.ea && type == b.type;
  }
};
DECLARE_TYPE_AS_MOVABLE(update_bpt_info_t);
typedef qvector<update_bpt_info_t> update_bpt_vec_t; ///< vector of update breakpoint info objects

/// Input argument for update_lowcnds().
/// Server-side low-level breakpoint conditions
struct lowcnd_t
{
  ea_t ea;              ///< address of the condition
  qstring cndbody;      ///< new condition. empty means 'remove condition'
                        ///< the following fields are valid only if condition is not empty:
  bpttype_t type;       ///< existing breakpoint type
  bytevec_t orgbytes;   ///< original bytes (if type==#BPT_SOFT)
  insn_t cmd;           ///< decoded instruction at 'ea'
                        ///< (used for processors without single step feature, e.g. arm)
  bool compiled;        ///< has 'cndbody' already been compiled?
  int size;             ///< breakpoint size (if type!=#BPT_SOFT)
};
typedef qvector<lowcnd_t> lowcnd_vec_t; ///< vector of low-level breakpoint conditions

/// Output argument for ev_suspended
/// New thread names
struct thread_name_t
{
  thid_t tid;           ///< thread
  qstring name;         ///< new thread name
};
typedef qvector<thread_name_t> thread_name_vec_t; ///< vector of thread names

//====================================================================
/// How to resume the application. The corresponding bit for \ref DBG_FLAG_
/// must be set in order to use a resume mode.
enum resume_mode_t
{
  RESMOD_NONE,    ///< no stepping, run freely
  RESMOD_INTO,    ///< step into call (the most typical single stepping)
  RESMOD_OVER,    ///< step over call
  RESMOD_OUT,     ///< step out of the current function (run until return)
  RESMOD_SRCINTO, ///< until control reaches a different source line
  RESMOD_SRCOVER, ///< next source line in the current stack frame
  RESMOD_SRCOUT,  ///< next source line in the previous stack frame
  RESMOD_USER,    ///< step out to the user code
  RESMOD_HANDLE,  ///< step into the exception handler
  RESMOD_MAX,
};

//====================================================================
// Tracing bits
#define STEP_TRACE 0x01 // lowest level trace. trace buffers are not maintained
#define INSN_TRACE 0x02 // instruction tracing
#define FUNC_TRACE 0x04 // function tracing
#define BBLK_TRACE 0x08 // basic block tracing

//====================================================================
/// Debugger return codes.
/// Success if positive (> DRC_NONE).
enum drc_t
{
  DRC_EVENTS = 3,   ///< success, there are pending events
  DRC_CRC    = 2,   ///< success, but the input file crc does not match
  DRC_OK     = 1,   ///< success
  DRC_NONE   = 0,   ///< reaction to the event not implemented
  DRC_FAILED = -1,  ///< failed or false
  DRC_NETERR = -2,  ///< network error
  DRC_NOFILE = -3,  ///< file not found
  DRC_IDBSEG = -4,  ///< use idb segmentation
  DRC_NOPROC = -5,  ///< the process does not exist anymore
  DRC_NOCHG  = -6,  ///< no changes
  DRC_ERROR  = -7,  ///< unclassified error, may be complemented by errbuf
};

//====================================================================
/// This structure describes a debugger API module.
/// (functions needed to debug a process on a specific
///  operating system).
///
/// The address of this structure must be put into the ::dbg variable by
/// the plugin_t::init() function of the debugger plugin.
struct debugger_t
{
  int version;            ///< Expected kernel version,
                          ///<   should be #IDD_INTERFACE_VERSION
  const char *name;       ///< Short debugger name like win32 or linux
  int id;                 ///< one of \ref DEBUGGER_ID_

  /// \defgroup DEBUGGER_ID_ Debugger API module id
  /// Used by debugger_t::id
  //@{
  #define DEBUGGER_ID_X86_IA32_WIN32_USER              0 ///< Userland win32 processes (win32 debugging APIs)
  #define DEBUGGER_ID_X86_IA32_LINUX_USER              1 ///< Userland linux processes (ptrace())
  #define DEBUGGER_ID_X86_IA32_MACOSX_USER             3 ///< Userland MAC OS X processes
  #define DEBUGGER_ID_ARM_IPHONE_USER                  5 ///< iPhone 1.x
  #define DEBUGGER_ID_X86_IA32_BOCHS                   6 ///< BochsDbg.exe 32
  #define DEBUGGER_ID_6811_EMULATOR                    7 ///< MC6812 emulator (beta)
  #define DEBUGGER_ID_GDB_USER                         8 ///< GDB remote
  #define DEBUGGER_ID_WINDBG                           9 ///< WinDBG using Microsoft Debug engine
  #define DEBUGGER_ID_X86_DOSBOX_EMULATOR             10 ///< Dosbox MS-DOS emulator
  #define DEBUGGER_ID_ARM_LINUX_USER                  11 ///< Userland arm linux
  #define DEBUGGER_ID_TRACE_REPLAYER                  12 ///< Fake debugger to replay recorded traces
  #define DEBUGGER_ID_X86_PIN_TRACER                  14 ///< PIN Tracer module
  #define DEBUGGER_ID_DALVIK_USER                     15 ///< Dalvik
  #define DEBUGGER_ID_XNU_USER                        16 ///< XNU Kernel
  #define DEBUGGER_ID_ARM_MACOS_USER                  17 ///< Userland arm MAC OS
  //@}

  const char *processor;  ///< Required processor name.
                          ///< Used for instant debugging to load the correct
                          ///< processor module

  uint32 flags;           /// \ref DBG_FLAG_
  uint32 flags2;          /// \ref DBG_FLAG2_
                          /// may be set inside debugger_t::init_debugger() except of the severals

  /// \defgroup DBG_FLAG_ Debugger module features
  /// Used by debugger_t::flags
  //@{
  #define DBG_FLAG_REMOTE         0x00000001  ///< Remote debugger (requires remote host name unless #DBG_FLAG_NOHOST)
  #define DBG_FLAG_NOHOST         0x00000002  ///< Remote debugger with does not require network params (host/port/pass).
                                              ///< (a unique device connected to the machine)
  #define DBG_FLAG_FAKE_ATTACH    0x00000004  ///< ::PROCESS_ATTACHED is a fake event
                                              ///< and does not suspend the execution
  #define DBG_FLAG_HWDATBPT_ONE   0x00000008  ///< Hardware data breakpoints are
                                              ///< one byte size by default
  #define DBG_FLAG_CAN_CONT_BPT   0x00000010  ///< Debugger knows to continue from a bpt.
                                              ///< This flag also means that the debugger module
                                              ///< hides breakpoints from ida upon read_memory
  #define DBG_FLAG_NEEDPORT       0x00000020  ///< Remote debugger requires port number (to be used with DBG_FLAG_NOHOST)
  #define DBG_FLAG_DONT_DISTURB   0x00000040  ///< Debugger can handle only
                                              ///<   get_debug_event(),
                                              ///<   request_pause(),
                                              ///<   exit_process()
                                              ///< when the debugged process is running.
                                              ///< The kernel may also call service functions
                                              ///< (file I/O, map_address, etc)
  #define DBG_FLAG_SAFE           0x00000080  ///< The debugger is safe (probably because it just emulates the application
                                              ///< without really running it)
  #define DBG_FLAG_CLEAN_EXIT     0x00000100  ///< IDA must suspend the application and remove
                                              ///< all breakpoints before terminating the application.
                                              ///< Usually this is not required because the application memory
                                              ///< disappears upon termination.
  #define DBG_FLAG_USE_SREGS      0x00000200  ///< Take segment register values into account (non flat memory)
  #define DBG_FLAG_NOSTARTDIR     0x00000400  ///< Debugger module doesn't use startup directory
  #define DBG_FLAG_NOPARAMETERS   0x00000800  ///< Debugger module doesn't use commandline parameters
  #define DBG_FLAG_NOPASSWORD     0x00001000  ///< Remote debugger doesn't use password
  #define DBG_FLAG_CONNSTRING     0x00002000  ///< Display "Connection string" instead of "Hostname" and hide the "Port" field
  #define DBG_FLAG_SMALLBLKS      0x00004000  ///< If set, IDA uses 256-byte blocks for caching memory contents.
                                              ///< Otherwise, 1024-byte blocks are used
  #define DBG_FLAG_MANMEMINFO     0x00008000  ///< If set, manual memory region manipulation commands
                                              ///< will be available. Use this bit for debugger modules
                                              ///< that cannot return memory layout information
  #define DBG_FLAG_EXITSHOTOK     0x00010000  ///< IDA may take a memory snapshot at ::PROCESS_EXITED event
  #define DBG_FLAG_VIRTHREADS     0x00020000  ///< Thread IDs may be shuffled after each debug event.
                                              ///< (to be used for virtual threads that represent cpus for windbg kmode)
  #define DBG_FLAG_LOWCNDS        0x00040000  ///< Low level breakpoint conditions are supported.
  #define DBG_FLAG_DEBTHREAD      0x00080000  ///< Supports creation of a separate thread in ida
                                              ///< for the debugger (the debthread).
                                              ///< Most debugger functions will be called from debthread (exceptions are marked below)
                                              ///< The debugger module may directly call only #THREAD_SAFE functions.
                                              ///< To call other functions please use execute_sync().
                                              ///< The debthread significantly increases debugging
                                              ///< speed, especially if debug events occur frequently.
  #define DBG_FLAG_DEBUG_DLL      0x00100000  ///< Can debug standalone DLLs.
                                              ///< For example, Bochs debugger can debug any snippet of code
  #define DBG_FLAG_FAKE_MEMORY    0x00200000  ///< get_memory_info()/read_memory()/write_memory() work with the idb.
                                              ///< (there is no real process to read from, as for the replayer module)
                                              ///< the kernel will not call these functions if this flag is set.
                                              ///< however, third party plugins may call them, they must be implemented.
  #define DBG_FLAG_ANYSIZE_HWBPT  0x00400000  ///< The debugger supports arbitrary size hardware breakpoints.
  #define DBG_FLAG_TRACER_MODULE  0x00800000  ///< The module is a tracer, not a full featured debugger module
  #define DBG_FLAG_PREFER_SWBPTS  0x01000000  ///< Prefer to use software breakpoints
  #define DBG_FLAG_LAZY_WATCHPTS  0x02000000  ///< Watchpoints are triggered before the offending instruction is executed.
                                              ///< The debugger must temporarily disable the watchpoint and single-step
                                              ///< before resuming.
  #define DBG_FLAG_FAST_STEP      0x04000000  ///< Do not refresh memory layout info after single stepping
  //@}

  /// \defgroup DBG_FLAG2_ Debugger module features
  /// Used by debugger_t::flags2
  //@{
  #define DBG_HAS_GET_PROCESSES   0x00000001  ///< supports ev_get_processes
  #define DBG_HAS_ATTACH_PROCESS  0x00000002  ///< supports ev_attach_process
  #define DBG_HAS_DETACH_PROCESS  0x00000004  ///< supports ev_detach_process
  #define DBG_HAS_REQUEST_PAUSE   0x00000008  ///< supports ev_request_pause
  #define DBG_HAS_SET_EXCEPTION_INFO \
                                  0x00000010  ///< supports ev_set_exception_info
  #define DBG_HAS_THREAD_SUSPEND  0x00000020  ///< supports ev_thread_suspend
  #define DBG_HAS_THREAD_CONTINUE 0x00000040  ///< supports ev_thread_continue
  #define DBG_HAS_SET_RESUME_MODE 0x00000080  ///< supports ev_set_resume_mode.
                                              ///< Cannot be set inside the debugger_t::init_debugger()
  #define DBG_HAS_THREAD_GET_SREG_BASE \
                                  0x00000100  ///< supports ev_thread_get_sreg_base
  #define DBG_HAS_CHECK_BPT       0x00000200  ///< supports ev_check_bpt
  #define DBG_HAS_OPEN_FILE       0x00000400  ///< supports ev_open_file, ev_close_file, ev_read_file, ev_write_file
  #define DBG_HAS_UPDATE_CALL_STACK \
                                  0x00000800  ///< supports ev_update_call_stack
  #define DBG_HAS_APPCALL         0x00001000  ///< supports ev_appcall, ev_cleanup_appcall
  #define DBG_HAS_REXEC           0x00002000  ///< supports ev_rexec
  #define DBG_HAS_MAP_ADDRESS     0x00004000  ///< supports ev_map_address.
                                              ///< Avoid using this bit, especially together with DBG_FLAG_DEBTHREAD
                                              ///< because it may cause big slow downs
  //@}

  bool is_remote(void) const { return (flags & DBG_FLAG_REMOTE) != 0; }
  bool must_have_hostname(void) const
    { return (flags & (DBG_FLAG_REMOTE|DBG_FLAG_NOHOST)) == DBG_FLAG_REMOTE; }
  bool can_continue_from_bpt(void) const
    { return (flags & DBG_FLAG_CAN_CONT_BPT) != 0; }
  bool may_disturb(void) const
    { return (flags & DBG_FLAG_DONT_DISTURB) == 0; }
  bool is_safe(void) const
    { return (flags & DBG_FLAG_SAFE) != 0; }
  bool use_sregs(void) const
    { return (flags & DBG_FLAG_USE_SREGS) != 0; }
  size_t cache_block_size(void) const
    { return (flags & DBG_FLAG_SMALLBLKS) != 0 ? 256 : 1024; }
  bool use_memregs(void) const
    { return (flags & DBG_FLAG_MANMEMINFO) != 0; }
  bool may_take_exit_snapshot(void) const
    { return (flags & DBG_FLAG_EXITSHOTOK) != 0; }
  bool virtual_threads(void) const
    { return (flags & DBG_FLAG_VIRTHREADS) != 0; }
  bool supports_lowcnds(void) const
    { return (flags & DBG_FLAG_LOWCNDS) != 0; }
  bool supports_debthread(void) const
    { return (flags & DBG_FLAG_DEBTHREAD) != 0; }
  bool can_debug_standalone_dlls(void) const
    { return (flags & DBG_FLAG_DEBUG_DLL) != 0; }
  bool fake_memory(void) const
    { return (flags & DBG_FLAG_FAKE_MEMORY) != 0; }

  bool has_get_processes(void) const
    { return (flags2 & DBG_HAS_GET_PROCESSES) != 0; }
  bool has_attach_process(void) const
    { return (flags2 & DBG_HAS_ATTACH_PROCESS) != 0; }
  bool has_detach_process(void) const
    { return (flags2 & DBG_HAS_DETACH_PROCESS) != 0; }
  bool has_request_pause(void) const
    { return (flags2 & DBG_HAS_REQUEST_PAUSE) != 0; }
  bool has_set_exception_info(void) const
    { return (flags2 & DBG_HAS_SET_EXCEPTION_INFO) != 0; }
  bool has_thread_suspend(void) const
    { return (flags2 & DBG_HAS_THREAD_SUSPEND) != 0; }
  bool has_thread_continue(void) const
    { return (flags2 & DBG_HAS_THREAD_CONTINUE) != 0; }
  bool has_set_resume_mode(void) const
    { return (flags2 & DBG_HAS_SET_RESUME_MODE) != 0; }
  bool has_thread_get_sreg_base(void) const
    { return (flags2 & DBG_HAS_THREAD_GET_SREG_BASE) != 0; }
  bool has_check_bpt(void) const
    { return (flags2 & DBG_HAS_CHECK_BPT) != 0; }
  bool has_open_file(void) const
    { return (flags2 & DBG_HAS_OPEN_FILE) != 0; }
  bool has_update_call_stack(void) const
    { return (flags2 & DBG_HAS_UPDATE_CALL_STACK) != 0; }
  bool has_appcall(void) const
    { return (flags2 & DBG_HAS_APPCALL) != 0; }
  bool has_rexec(void) const
    { return (flags2 & DBG_HAS_REXEC) != 0; }
  bool has_map_address(void) const
    { return (flags2 & DBG_HAS_MAP_ADDRESS) != 0; }
  bool has_soft_bpt(void) const
    { return bpt_bytes != nullptr && bpt_size > 0; }

  const char **regclasses;                   ///< Array of register class names
  int default_regclasses;                    ///< Mask of default printed register classes
  register_info_t *registers;                ///< Array of registers. Use regs() to access it
  int nregs;                                 ///< Number of registers

  // A function for accessing the 'registers' array
  inline register_info_t &regs(int idx)
  {
    return registers[idx];
  }

  int memory_page_size;                      ///< Size of a memory page. Usually 4K

  const uchar *bpt_bytes;                    ///< A software breakpoint instruction
  uchar bpt_size;                            ///< Size of the software breakpoint instruction in bytes
  uchar filetype;                            ///< Input file type for the instant debugger.
                                             ///< This value will be used after attaching to a new process.
  ushort resume_modes;                       ///< \ref DBG_RESMOD_
  /// \defgroup DBG_RESMOD_ Resume modes
  /// Used by debugger_t::resume_modes
  //@{
  #define DBG_RESMOD_STEP_INTO      0x0001   ///< ::RESMOD_INTO is available
  #define DBG_RESMOD_STEP_OVER      0x0002   ///< ::RESMOD_OVER is available
  #define DBG_RESMOD_STEP_OUT       0x0004   ///< ::RESMOD_OUT is available
  #define DBG_RESMOD_STEP_SRCINTO   0x0008   ///< ::RESMOD_SRCINTO is available
  #define DBG_RESMOD_STEP_SRCOVER   0x0010   ///< ::RESMOD_SRCOVER is available
  #define DBG_RESMOD_STEP_SRCOUT    0x0020   ///< ::RESMOD_SRCOUT is available
  #define DBG_RESMOD_STEP_USER      0x0040   ///< ::RESMOD_USER is available
  #define DBG_RESMOD_STEP_HANDLE    0x0080   ///< ::RESMOD_HANDLE is available
  //@}
  bool is_resmod_avail(int resmod) const
    { return (resume_modes & (1 << (resmod - 1))) != 0; }

#if !defined(_MSC_VER)  // this compiler complains :(
  static const int default_port_number = 23946;
#define DEBUGGER_PORT_NUMBER debugger_t::default_port_number
#else
#define DEBUGGER_PORT_NUMBER 23946
#endif

  /// Set debugger options (parameters that are specific to the debugger module).
  /// \param keyword     keyword encountered in IDA.CFG/user config file.
  ///                    if nullptr, then an interactive dialog form should be displayed
  /// \param pri         option priority, one of \ref IDAOPT_PRIO values
  /// \param value_type  type of value of the keyword - one of \ref IDPOPT_T
  /// \param value       pointer to value
  /// \return one of \ref IDPOPT_RET, otherwise a pointer to an error message
  /// See the convenience function in dbg.hpp if you need to call it.
  /// The kernel will generate this event after reading the debugger specific
  /// config file (arguments are: keyword="", type=#IDPOPT_STR, value="")
  /// This event is optional.
  /// This event is generated in the main thread
  const char *(idaapi *set_dbg_options)(
        const char *keyword,
        int pri,
        int value_type,
        const void *value);

  /// Callback notification codes.
  ///
  /// They are passed to notify() when certain events occur in the kernel,
  /// allowing the debugger plugin to take appropriate actions.
  ///
  /// Debugger plugins must implement the desired reaction to these events
  /// in the notify() function.
  ///
  /// The notify() function should not be called directly. See inline functions
  /// below.
  enum event_t
  {
    /// Initialize debugger.
    /// This event is generated in the main thread.
    /// \param hostname (const char *)
    /// \param portnum  (int)
    /// \param password (const char *)
    /// \param errbuf (::qstring *) may be nullptr
    /// \return ::DRC_OK, ::DRC_FAILED
    ev_init_debugger,

    /// Terminate debugger.
    /// This event is generated in the main thread.
    /// \return ::DRC_OK, ::DRC_FAILED
    ev_term_debugger,

    /// Return information about the running processes.
    /// This event is generated in the main thread.
    /// Available if \ref DBG_HAS_GET_PROCESSES is set
    /// \param procs (::procinfo_vec_t *)
    /// \param errbuf (::qstring *) may be nullptr
    /// \return ::DRC_NONE, ::DRC_OK, ::DRC_FAILED, ::DRC_NETERR
    ev_get_processes,

    /// Start an executable to debug.
    /// This event is generated in debthread.
    /// Must be implemented.
    /// \param path              (const char *) path to executable
    /// \param args              (const char *) arguments to pass to executable
    /// \param startdir          (const char *) initial working directory of new process
    /// \param dbg_proc_flags    (uint32) \ref DBG_PROC_
    /// \param input_path        (const char *) path to the file that was used to create the idb file
    ///                          It is not always the same as 'path' - e.g. if we are analyzing
    ///                          a dll and want to launch an executable that loads it.
    /// \param input_file_crc32  (uint32) CRC value for 'input_path'
    /// \param errbuf (::qstring *) may be nullptr
    /// \return ::DRC_OK, ::DRC_CRC, ::DRC_FAILED, ::DRC_NETERR, ::DRC_NOFILE
    ev_start_process,

    /// Attach to an existing running process.
    /// event_id should be equal to -1 if not attaching to a crashed process.
    /// This event is generated in debthread.
    /// Available if \ref DBG_HAS_ATTACH_PROCESS is set
    /// \param pid               (::pid_t) process id to attach
    /// \param event_id          (int) event to trigger upon attaching
    /// \param dbg_proc_flags    (uint32) \ref DBG_PROC_
    /// \param errbuf (::qstring *) may be nullptr
    /// \return ::DRC_NONE, ::DRC_OK, ::DRC_FAILED, ::DRC_NETERR
    ev_attach_process,

    /// Detach from the debugged process.
    /// May be generated while the process is running or suspended.
    /// Must detach from the process in any case.
    /// The kernel will repeatedly call get_debug_event() until ::PROCESS_DETACHED is received.
    /// In this mode, all other events will be automatically handled and process will be resumed.
    /// This event is generated from debthread.
    /// Available if \ref DBG_HAS_DETACH_PROCESS is set
    /// \return ::DRC_NONE, ::DRC_OK, ::DRC_FAILED, ::DRC_NETERR
    ev_detach_process,

    /// Retrieve process- and debugger-specific runtime attributes.
    /// This event is generated in the main thread.
    /// \param out_pattrs  (::debapp_attrs_t *)
    /// \return ::DRC_NONE, ::DRC_OK
    ev_get_debapp_attrs,

    /// Rebase database if the debugged program has been rebased by the system.
    /// This event is generated in the main thread.
    /// \param new_base (::ea_t)
    /// \return ::DRC_NONE, ::DRC_OK
    ev_rebase_if_required_to,

    /// Prepare to pause the process.
    /// Normally the next get_debug_event() will pause the process
    /// If the process is sleeping,
    /// then the pause will not occur until the process wakes up.
    /// If the debugger module does not react to this event,
    /// then it will be impossible to pause the program.
    /// This event is generated in debthread.
    /// Available if \ref DBG_HAS_REQUEST_PAUSE is set
    /// \param errbuf (::qstring *) may be nullptr
    /// \return ::DRC_NONE, ::DRC_OK, ::DRC_FAILED, ::DRC_NETERR
    ev_request_pause,

    /// Stop the process.
    /// May be generated while the process is running or suspended.
    /// Must terminate the process in any case.
    /// The kernel will repeatedly call get_debug_event() until ::PROCESS_EXITED is received.
    /// In this mode, all other events will be automatically handled and process will be resumed.
    /// This event is generated in debthread.
    /// Must be implemented.
    /// \param errbuf (::qstring *) may be nullptr
    /// \return ::DRC_NONE, ::DRC_OK, ::DRC_FAILED, ::DRC_NETERR
    ev_exit_process,

    /// Get a pending debug event and suspend the process.
    /// This event will be generated regularly by IDA.
    /// This event is generated in debthread.
    /// IMPORTANT: the BREAKPOINT/EXCEPTION/STEP events must be reported
    /// only after reporting other pending events for a thread.
    /// Must be implemented.
    /// \param code       (::gdecode_t *)
    /// \param event      (::debug_event_t *)
    /// \param timeout_ms (int)
    /// \retval ignored
    ev_get_debug_event,

    /// Continue after handling the event.
    /// This event is generated in debthread.
    /// Must be implemented.
    /// \param event (::debug_event_t *)
    /// \return ::DRC_OK, ::DRC_FAILED, ::DRC_NETERR
    ev_resume,

    /// Set exception handling.
    /// This event is generated in debthread or the main thread.
    /// Available if \ref DBG_HAS_SET_EXCEPTION_INFO is set
    /// \param info (::exception_info_t *)
    /// \param qty  (int)
    /// \return ::DRC_NONE, ::DRC_OK
    ev_set_exception_info,

    /// This event will be generated by the kernel each time
    /// it has suspended the debuggee process and refreshed the database.
    /// The debugger module may add information to the database if necessary.
    ///
    /// The reason for introducing this event is that when an event like
    /// LOAD_DLL happens, the database does not reflect the memory state yet
    /// and therefore we can't add information about the dll into the database
    /// in the get_debug_event() function.
    /// Only when the kernel has adjusted the database we can do it.
    /// Example: for loaded PE DLLs we can add the exported function
    /// names to the list of debug names (see set_debug_names()).
    ///
    /// This event is generated in the main thread.
    /// \param dlls_added (bool)
    /// \param thr_names  (::thread_name_vec_t *) (for the kernel only, must be nullptr)
    /// \return ::DRC_NONE, ::DRC_OK
    ev_suspended,

    /// \name Threads
    /// The following events manipulate threads.
    /// These events are generated in debthread.
    /// \return ::DRC_OK, ::DRC_FAILED, ::DRC_NETERR
    //@{

    /// Suspend a running thread
    /// Available if \ref DBG_HAS_THREAD_SUSPEND is set
    /// \param tid (::thid_t)
    ev_thread_suspend,

    /// Resume a suspended thread
    /// Available if \ref DBG_HAS_THREAD_CONTINUE is set
    /// \param tid (::thid_t)
    ev_thread_continue,

    /// Specify resume action
    /// Available if \ref DBG_HAS_SET_RESUME_MODE is set
    /// \param tid    (::thid_t)
    /// \param resmod (::resume_mode_t)
    ev_set_resume_mode,

    //@}

    /// Read thread registers.
    /// This event is generated in debthread.
    /// Must be implemented.
    /// \param tid     (::thid_t) thread id
    /// \param clsmask (int) bitmask of register classes to read
    /// \param values  (::regval_t *) pointer to vector of regvals for all registers.
    ///                                regval must have debugger_t::nregs elements
    /// \param errbuf  (::qstring *) may be nullptr
    /// \return ::DRC_OK, ::DRC_FAILED, ::DRC_NETERR
    ev_read_registers,

    /// Write one thread register.
    /// This event is generated in debthread.
    /// Must be implemented.
    /// \param tid     (::thid_t) thread id
    /// \param regidx  (int) register index
    /// \param value   (const ::regval_t *) new value of the register
    /// \param errbuf  (::qstring *) may be nullptr
    /// \return ::DRC_OK, ::DRC_FAILED, ::DRC_NETERR
    ev_write_register,

    /// Get information about the base of a segment register.
    /// Currently used by the IBM PC module to resolve references like fs:0.
    /// This event is generated in debthread.
    /// Available if \ref DBG_HAS_THREAD_GET_SREG_BASE is set
    /// \param answer      (::ea_t *) pointer to the answer. can't be nullptr.
    /// \param tid         (::thid_t) thread id
    /// \param sreg_value  (int) value of the segment register (returned by get_reg_val())
    /// \param errbuf      (::qstring *) may be nullptr
    /// \return ::DRC_NONE, ::DRC_OK, ::DRC_FAILED, ::DRC_NETERR
    ev_thread_get_sreg_base,

    /// \name Memory manipulation
    /// The following events manipulate bytes in the memory.
    //@{

    /// Get information on the memory ranges.
    /// The debugger module fills 'ranges'. The returned vector must be sorted.
    /// This event is generated in debthread.
    /// Must be implemented.
    /// \param ranges  (::meminfo_vec_t *)
    /// \param errbuf  (::qstring *) may be nullptr
    /// \retval ::DRC_OK  new memory layout is returned
    /// \retval ::DRC_FAILED, ::DRC_NETERR, ::DRC_NOPROC, ::DRC_NOCHG, ::DRC_IDBSEG
    ev_get_memory_info,

    /// Read process memory.
    /// This event is generated in debthread.
    /// \param nbytes  (size_t *) number of read bytes
    /// \param ea      (::ea_t)
    /// \param buffer  (void *)
    /// \param size    (::size_t)
    /// \param errbuf  (::qstring *) may be nullptr
    /// \return ::DRC_OK, ::DRC_FAILED, ::DRC_NOPROC
    ev_read_memory,

    /// Write process memory.
    /// This event is generated in debthread.
    /// \param nbytes  (size_t *) number of written bytes
    /// \param ea      (::ea_t)
    /// \param buffer  (const void *)
    /// \param size    (::size_t)
    /// \param errbuf  (::qstring *) may be nullptr
    /// \retval ::DRC_OK, ::DRC_FAILED, ::DRC_NOPROC
    ev_write_memory,

    //@}

    /// Is it possible to set breakpoint?
    /// This event is generated in debthread or in the main thread if debthread
    /// is not running yet.
    /// It is generated to verify hardware breakpoints.
    /// Available if \ref DBG_HAS_CHECK_BPT is set
    /// \param bptvc  (int *) breakpoint verification codes \ref BPT_
    /// \param type   (::bpttype_t) \ref BPT_H
    /// \param ea     (::ea_t)
    /// \param len    (int)
    /// \return ::DRC_OK, ::DRC_NONE
    ev_check_bpt,

    /// Add/del breakpoints.
    /// bpts array contains nadd bpts to add, followed by ndel bpts to del.
    /// This event is generated in debthread.
    /// \param nbpts (int *) number of updated breakpoints
    /// \param bpts  (::update_bpt_info_t *)
    /// \param nadd  (int)
    /// \param ndel  (int)
    /// \param errbuf  (::qstring *) may be nullptr
    /// \return ::DRC_OK, ::DRC_FAILED, ::DRC_NETERR
    ev_update_bpts,

    /// Update low-level (server side) breakpoint conditions.
    /// This event is generated in debthread.
    /// \param nupdated  (int *) number of updated conditions
    /// \param lowcnds   (const ::lowcnd_t *)
    /// \param nlowcnds  (int)
    /// \param errbuf  (::qstring *) may be nullptr
    /// \return ::DRC_OK, ::DRC_NETERR
    ev_update_lowcnds,

    /// \name Remote file
    /// Open/close/read/write a remote file.
    /// These events are generated in the main thread
    /// Available if \ref DBG_HAS_OPEN_FILE is set
    //@{

    /// \param file      (const char *)
    /// \param fsize     (::uint64 *)
    /// \param readonly  (bool)
    /// \param errbuf    (::qstring *) may be nullptr
    /// \retval (int) handle
    /// \retval -1 error
    ev_open_file,

    /// \param fn  (int) handle
    /// \return ignored
    ev_close_file,

    /// \param fn      (int) handle
    /// \param off     (::qoff64_t)
    /// \param buf     (void *)
    /// \param size    (size_t)
    /// \param errbuf  (::qstring *) may be nullptr
    /// \retval number of read bytes
    ev_read_file,

    /// \param fn      (int) handle
    /// \param off     (::qoff64_t)
    /// \param buf     (const void *)
    /// \param size    (size_t)
    /// \param errbuf  (::qstring *) may be nullptr
    /// \retval number of written bytes
    ev_write_file,

    //@}

    /// Map process address.
    /// The debugger module may ignore this event.
    /// This event is generated in debthread.
    /// IDA will generate this event only if \ref DBG_HAS_MAP_ADDRESS is set.
    /// \param mapped   (::ea_t *) mapped address or #BADADDR
    /// \param off      (::ea_t) offset to map
    /// \param regs     (const ::regval_t *) current register values.
    ///                 if regs == nullptr, then perform global mapping,
    ///                 which is independent on used registers
    ///                 usually such a mapping is a trivial identity mapping
    /// \param regnum   (int) required mapping.
    ///                 May be specified as a segment register number or a regular
    ///                 register number if the required mapping can be deduced from it.
    ///                 For example, esp implies that ss should be used.
    /// \return ::DRC_NONE, ::DRC_OK see MAPPED
    ev_map_address,

    /// Get pointer to debugger specific events.
    /// This event returns a pointer to a structure that holds pointers to
    /// debugger module specific events. For information on the structure
    /// layout, please check the corresponding debugger module. Most debugger
    /// modules return nullptr because they do not have any extensions. Available
    /// extensions may be generated from plugins.
    /// This event is generated in the main thread.
    /// \param ext  (void **)
    /// \return ::DRC_NONE, ::DRC_OK see EXT
    ev_get_debmod_extensions,

    /// Calculate the call stack trace for the given thread.
    /// This event is generated when the process is suspended and should fill the 'trace' object
    /// with the information about the current call stack. If this event returns DRC_NONE, IDA
    /// will try to invoke a processor-specific mechanism (see processor_t::ev_update_call_stack).
    /// If the current processor module does not implement stack tracing, then IDA will fall back
    /// to a generic algorithm (based on the frame pointer chain) to calculate the trace.
    /// This event is ideal if the debugging targets manage stack frames in a peculiar way,
    /// requiring special analysis.
    /// This event is generated in the main thread.
    /// Available if \ref DBG_HAS_UPDATE_CALL_STACK is set
    /// \param tid    (::thid_t)
    /// \param trace  (::call_stack_t *)
    /// \retval ::DRC_NONE false or not implemented
    /// \return ::DRC_OK success
    ev_update_call_stack,

    /// Call application function.
    /// This event calls a function from the debugged application.
    /// This event is generated in debthread
    /// Available if \ref HAS_APPCALL is set
    /// \param[out] blob_ea (::ea_t *) ea of stkargs blob,
    ///                     #BADADDR if failed and errbuf is filled
    /// \param func_ea      (::ea_t) address to call
    /// \param tid          (::thid_t) thread to use
    /// \param fti          (const ::func_type_data_t *) type information for the generated event
    /// \param nargs        (int) number of actual arguments
    /// \param regargs      (const ::regobjs_t *) information about register arguments
    /// \param stkargs      (::relobj_t *) memory blob to pass as stack arguments
    ///                     (usually contains pointed data)
    ///                     it must be relocated by the callback but not changed otherwise
    /// \param retregs      (::regobjs_t *) event return registers.
    /// \param[out] errbuf  (::qstring *) the error message. if empty on failure, see EVENT.
    ///                     should not be filled if an appcall exception
    ///                     happened but #APPCALL_DEBEV is set
    /// \param[out] event   (::debug_event_t *) the last debug event that occurred during appcall execution
    ///                     filled only if the appcall execution fails and #APPCALL_DEBEV is set
    /// \param options      (int) appcall options, usually taken from \inf{appcall_options}.
    ///                     possible values: combination of \ref APPCALL_  or 0
    /// \retval ::DRC_NONE
    /// \retval ::DRC_OK, see BLOB_EA
    ev_appcall,

    /// Cleanup after appcall().
    /// The debugger module must keep the stack blob in the memory until this event
    /// is generated. It will be generated by the kernel for each successful appcall().
    /// There is an exception: if #APPCALL_MANUAL, IDA may not call cleanup_appcall.
    /// If the user selects to terminate a manual appcall, then cleanup_appcall will be generated.
    /// Otherwise, the debugger module should terminate the appcall when the generated
    /// event returns.
    /// This event is generated in debthread.
    /// Available if \ref HAS_APPCALL is set
    /// \param tid  (::thid_t)
    /// \retval ::DRC_EVENTS  success, there are pending events
    /// \retval ::DRC_OK      success
    /// \retval ::DRC_FAILED  failed
    /// \retval ::DRC_NETERR  network error
    ev_cleanup_appcall,

    /// Evaluate a low level breakpoint condition at 'ea'.
    /// Other evaluation errors are displayed in a dialog box.
    /// This call is used by IDA when the process has already been temporarily
    /// suspended for some reason and IDA has to decide whether the process
    /// should be resumed or definitely suspended because of a breakpoint
    /// with a low level condition.
    /// This event is generated in debthread.
    /// \param tid     (::thid_t)
    /// \param ea      (::ea_t)
    /// \param errbuf  (::qstring *) may be nullptr
    /// \retval ::DRC_OK      condition is satisfied
    /// \retval ::DRC_FAILED  not satisfied
    /// \retval ::DRC_NETERR  network error
    ev_eval_lowcnd,

    /// Perform a debugger-specific event.
    /// This event is generated in debthread
    /// \param fn        (int)
    /// \param buf       (const void *)
    /// \param size      (size_t)
    /// \param poutbuf   (void **)
    /// \param poutsize  (ssize_t *)
    /// \param errbuf    (::qstring *) may be nullptr
    /// \retval DRC_...
    ev_send_ioctl,

    /// Enable/Disable tracing.
    /// The kernel will generated this event if the debugger plugin set DBG_FLAG_TRACER_MODULE.
    /// TRACE_FLAGS can be a set of #STEP_TRACE, #INSN_TRACE, #BBLK_TRACE or #FUNC_TRACE.
    /// This event is generated in the main thread.
    /// \param tid          (::thid_t)
    /// \param enable       (bool)
    /// \param trace_flags  (int)
    /// \return ::DRC_OK, ::DRC_FAILED, ::DRC_NONE
    ev_dbg_enable_trace,

    /// Is tracing enabled?
    /// The kernel will generated this event if the debugger plugin set DBG_FLAG_TRACER_MODULE.
    /// TRACE_BIT can be one of the following: #STEP_TRACE, #INSN_TRACE, #BBLK_TRACE or #FUNC_TRACE
    /// \param tid       (::thid_t)
    /// \param tracebit  (int)
    /// \retval ::DRC_OK   bit is set
    /// \retval ::DRC_NONE bit is not set or not implemented
    ev_is_tracing_enabled,

    /// Execute a command on the remote computer.
    /// Available if \ref DBG_HAS_REXEC is set
    /// \param cmdline  (const char *)
    /// \return (int) exit code
    ev_rexec,

    /// Get the path to a file containing source debug info for the given module.
    /// This allows srcinfo providers to call into the debugger when looking for debug info.
    /// It is useful in certain cases like the iOS debugger, which is a remote debugger but
    /// the remote debugserver does not provide dwarf info. So, we allow the debugger client
    /// to decide where to look for debug info locally.
    /// \param path  (qstring *) output path (file might not exist)
    /// \param base  (::ea_t) base address of a module in the target process
    /// \return ::DRC_NONE, ::DRC_OK result stored in PATH
    ev_get_srcinfo_path,

    /// Search for a binary pattern in the program.
    /// \param out         (::ea_t *) binary pattern address
    /// \param start_ea    (::ea_t) linear address, start of range to search
    /// \param end_ea      (::ea_t) linear address, end of range to search (exclusive)
    /// \param data        (const ::compiled_binpat_vec_t *)
    ///                    the prepared data to search for (see parse_binpat_str())
    /// \param srch_flags  (int) combination of \ref BIN_SEARCH_
    /// \param errbuf      (::qstring *) may be nullptr
    /// \return ::DRC_OK      EA contains the binary pattern address
    /// \retval ::DRC_FAILED  not found
    /// \retval ::DRC_NONE    not implemented
    /// \retval ::DRC_NETERR, ::DRC_ERROR
    ev_bin_search,
  };

  /// Event notification callback.
  /// It will be hooked to the HT_IDD notification point
  /// when the debugger is loaded and unhooked during
  /// the debugger unloading.
  /// The debugger plugin will be the last one
  /// who will receive the notification.
  hook_cb_t *callback;

  /// Event notification handler
  ssize_t notify(event_t event_code, ...)
  {
    va_list va;
    va_start(va, event_code);
    ssize_t code = invoke_callbacks(HT_IDD, event_code, va);
    va_end(va);
    return code;
  }
  drc_t notify_drc(event_t event_code, ...)
  {
    va_list va;
    va_start(va, event_code);
    drc_t code = drc_t(invoke_callbacks(HT_IDD, event_code, va));
    va_end(va);
    return code;
  }

  /// \defgroup DBG_PROC_ Debug process flags
  /// Passed as 'dbg_proc_flags' parameter to debugger_t::start_process
  //@{
  #define DBG_PROC_IS_DLL 0x01            ///< database contains a dll (not exe)
  #define DBG_PROC_IS_GUI 0x02            ///< using gui version of ida
  #define DBG_PROC_32BIT  0x04            ///< application is 32-bit
  #define DBG_PROC_64BIT  0x08            ///< application is 64-bit
  #define DBG_NO_TRACE    0x10            ///< do not trace the application (mac/linux)
  #define DBG_HIDE_WINDOW 0x20            ///< application should be hidden on startup (windows)
  #define DBG_SUSPENDED   0x40            ///< application should be suspended on startup (mac)
  //@}

  /// \defgroup BPT_ Breakpoint verification codes
  /// Return values for debugger_t::check_bpt
  //@{
  #define BPT_OK           0      ///< breakpoint can be set
  #define BPT_INTERNAL_ERR 1      ///< interr occurred when verifying breakpoint
  #define BPT_BAD_TYPE     2      ///< bpt type is not supported
  #define BPT_BAD_ALIGN    3      ///< alignment is invalid
  #define BPT_BAD_ADDR     4      ///< ea is invalid
  #define BPT_BAD_LEN      5      ///< bpt len is invalid
  #define BPT_TOO_MANY     6      ///< reached max number of supported breakpoints
  #define BPT_READ_ERROR   7      ///< failed to read memory at bpt ea
  #define BPT_WRITE_ERROR  8      ///< failed to write memory at bpt ea
  #define BPT_SKIP         9      ///< update_bpts(): do not process bpt
  #define BPT_PAGE_OK     10      ///< update_bpts(): ok, added a page bpt
  //@}

  /// \defgroup APPCALL_ Appcall options
  /// Passed as 'options' parameter to debugger_t::appcall
  //@{
  #define APPCALL_MANUAL  0x0001  ///< Only set up the appcall, do not run.
                                  ///< debugger_t::cleanup_appcall will not be generated by ida!
  #define APPCALL_DEBEV   0x0002  ///< Return debug event information
  #define APPCALL_TIMEOUT 0x0004  ///< Appcall with timeout.
                                  ///< If timed out, errbuf will contain "timeout".
                                  ///< See #SET_APPCALL_TIMEOUT and #GET_APPCALL_TIMEOUT
  /// Set appcall timeout in milliseconds
  #define SET_APPCALL_TIMEOUT(msecs)   ((uint(msecs) << 16)|APPCALL_TIMEOUT)
  /// Timeout value is contained in high 2 bytes of 'options' parameter
  #define GET_APPCALL_TIMEOUT(options) (uint(options) >> 16)
  //@}

  // Notification helpers, should be used instead of direct dbg->notify(...) calls
  inline bool init_debugger(const char *hostname, int portnum, const char *password, qstring *errbuf=nullptr);
  inline bool term_debugger(void);
  inline drc_t get_processes(procinfo_vec_t *procs, qstring *errbuf=nullptr);
  inline drc_t start_process(const char *path,
                             const char *args,
                             const char *startdir,
                             uint32 dbg_proc_flags,
                             const char *input_path,
                             uint32 input_file_crc32,
                             qstring *errbuf=nullptr);
  inline drc_t attach_process(pid_t pid, int event_id, uint32 dbg_proc_flags, qstring *errbuf=nullptr);
  inline drc_t detach_process(qstring *errbuf=nullptr);
  inline bool get_debapp_attrs(debapp_attrs_t *out_pattrs);
  inline void rebase_if_required_to(ea_t new_base);
  inline drc_t request_pause(qstring *errbuf=nullptr);
  inline drc_t exit_process(qstring *errbuf=nullptr);
  inline gdecode_t get_debug_event(debug_event_t *event, int timeout_ms);
  inline drc_t resume(const debug_event_t *event, qstring *errbuf=nullptr);
  inline void set_exception_info(const exception_info_t *info, int qty);
  inline void suspended(bool dlls_added, thread_name_vec_t *thr_names=nullptr);
  inline drc_t thread_suspend(thid_t tid, qstring *errbuf=nullptr);
  inline drc_t thread_continue(thid_t tid, qstring *errbuf=nullptr);
  inline drc_t set_resume_mode(thid_t tid, resume_mode_t resmod, qstring *errbuf=nullptr);
  inline drc_t read_registers(thid_t tid, int clsmask, regval_t *values, qstring *errbuf=nullptr);
  inline drc_t write_register(thid_t tid, int regidx, const regval_t *value, qstring *errbuf=nullptr);
  inline drc_t thread_get_sreg_base(ea_t *answer, thid_t tid, int sreg_value, qstring *errbuf=nullptr);
  inline drc_t get_memory_info(meminfo_vec_t &ranges, qstring *errbuf=nullptr);
  inline drc_t read_memory(size_t *nbytes, ea_t ea, void *buffer, size_t size, qstring *errbuf=nullptr);
  inline drc_t write_memory(size_t *nbytes, ea_t ea, const void *buffer, size_t size, qstring *errbuf=nullptr);
  inline drc_t check_bpt(int *bptvc, bpttype_t type, ea_t ea, int len);
  inline drc_t update_bpts(int *nbpts, update_bpt_info_t *bpts, int nadd, int ndel, qstring *errbuf=nullptr);
  inline drc_t update_lowcnds(int *nupdated, const lowcnd_t *lowcnds, int nlowcnds, qstring *errbuf=nullptr);
  inline int open_file(const char *file, uint64 *fsize, bool readonly, qstring *errbuf=nullptr);
  inline void close_file(int fn);
  inline ssize_t read_file(int fn, qoff64_t off, void *buf, size_t size, qstring *errbuf=nullptr);
  inline ssize_t write_file(int fn, qoff64_t off, const void *buf, size_t size, qstring *errbuf=nullptr);
  inline ea_t map_address(ea_t off, const regval_t *regs, int regnum);
  inline const void *get_debmod_extensions(void);
  inline drc_t update_call_stack(thid_t tid, call_stack_t *trace);
  inline ea_t appcall(
          ea_t func_ea,
          thid_t tid,
          const struct func_type_data_t *fti,
          int nargs,
          const struct regobjs_t *regargs,
          struct relobj_t *stkargs,
          struct regobjs_t *retregs,
          qstring *errbuf,
          debug_event_t *event,
          int options);
  inline drc_t cleanup_appcall(thid_t tid);
  inline drc_t eval_lowcnd(thid_t tid, ea_t ea, qstring *errbuf=nullptr);
  inline drc_t send_ioctl(int fn, const void *buf, size_t size, void **poutbuf, ssize_t *poutsize, qstring *errbuf=nullptr);
  inline bool dbg_enable_trace(thid_t tid, bool enable, int trace_flags);
  inline bool is_tracing_enabled(thid_t tid, int tracebit);
  inline int rexec(const char *cmdline);
  inline bool get_srcinfo_path(qstring *path, ea_t base);
  inline drc_t bin_search(
          ea_t *out,
          ea_t start_ea,
          ea_t end_ea,
          const compiled_binpat_vec_t &data,
          int srch_flags,
          qstring *errbuf=nullptr);
};

#ifndef __X86__
  CASSERT(sizeof(debugger_t) == 104);
#else
  CASSERT(sizeof(debugger_t) == 60);
#endif


#define RQ_MASKING  0x0001  // masking step handler: unless errors, tmpbpt handlers won't be generated
                            // should be used only with request_internal_step()
#define RQ_SUSPEND  0x0002  // suspending step handler: suspends the app
                            // handle_debug_event: suspends the app
#define RQ_NOSUSP   0x0000  // running step handler: continues the app
#define RQ_IGNWERR  0x0004  // ignore breakpoint write failures
#define RQ_SILENT   0x0008  // all: no dialog boxes
#define RQ_VERBOSE  0x0000  // all: display dialog boxes
#define RQ_SWSCREEN 0x0010  // handle_debug_event: switch screens
#define RQ__NOTHRRF 0x0020  // handle_debug_event: do not refresh threads
#define RQ_PROCEXIT 0x0040  // snapshots: the process is exiting
#define RQ_IDAIDLE  0x0080  // handle_debug_event: ida is idle
#define RQ_SUSPRUN  0x0100  // handle_debug_event: suspend at PROCESS_STARTED
#define RQ_RESUME   0x0200  // handle_debug_event: resume application
#define RQ_RESMOD   0xF000  // resume_mode_t
#define RQ_RESMOD_SHIFT 12
#define RQ_INTO (RESMOD_INTO << RQ_RESMOD_SHIFT)

inline bool debugger_t::init_debugger(const char *hostname, int portnum, const char *password, qstring *errbuf)
{
  return notify_drc(ev_init_debugger, hostname, portnum, password, errbuf) == DRC_OK;
}
inline bool debugger_t::term_debugger(void)
{
  return notify_drc(ev_term_debugger) == DRC_OK;
}
inline drc_t debugger_t::get_processes(procinfo_vec_t *procs, qstring *errbuf)
{
  return notify_drc(ev_get_processes, procs, errbuf);
}
inline drc_t debugger_t::start_process(
        const char *path,
        const char *args,
        const char *startdir,
        uint32 dbg_proc_flags,
        const char *input_path,
        uint32 input_file_crc32,
        qstring *errbuf)
{
  return notify_drc(ev_start_process, path, args, startdir, dbg_proc_flags, input_path, input_file_crc32, errbuf);
}
inline drc_t debugger_t::attach_process(pid_t pid, int event_id, uint32 dbg_proc_flags, qstring *errbuf)
{
  return notify_drc(ev_attach_process, pid, event_id, dbg_proc_flags, errbuf);
}
inline drc_t debugger_t::detach_process(qstring *errbuf)
{
  return notify_drc(ev_detach_process, errbuf);
}
inline bool debugger_t::get_debapp_attrs(debapp_attrs_t *out_pattrs)
{
  return notify_drc(ev_get_debapp_attrs, out_pattrs) != DRC_NONE;
}
inline void debugger_t::rebase_if_required_to(ea_t new_base)
{
  notify_drc(ev_rebase_if_required_to, new_base);
}
inline drc_t debugger_t::request_pause(qstring *errbuf)
{
  return notify_drc(ev_request_pause, errbuf);
}
inline drc_t debugger_t::exit_process(qstring *errbuf)
{
  return notify_drc(ev_exit_process, errbuf);
}
inline gdecode_t debugger_t::get_debug_event(debug_event_t *event, int timeout_ms)
{
  gdecode_t code = GDE_ERROR;
  notify_drc(ev_get_debug_event, &code, event, timeout_ms);
  return code;
}
inline drc_t debugger_t::resume(const debug_event_t *event, qstring *errbuf)
{
  return notify_drc(ev_resume, event, errbuf);
}
inline void debugger_t::set_exception_info(const exception_info_t *info, int qty)
{
  notify_drc(ev_set_exception_info, info, qty);
}
inline void debugger_t::suspended(bool dlls_added, thread_name_vec_t *thr_names)
{
  notify_drc(ev_suspended, dlls_added, thr_names);
}
inline drc_t debugger_t::thread_suspend(thid_t tid, qstring *errbuf)
{
  return notify_drc(ev_thread_suspend, tid, errbuf);
}
inline drc_t debugger_t::thread_continue(thid_t tid, qstring *errbuf)
{
  return notify_drc(ev_thread_continue, tid, errbuf);
}
inline drc_t debugger_t::set_resume_mode(thid_t tid, resume_mode_t resmod, qstring *errbuf)
{
  return notify_drc(ev_set_resume_mode, tid, resmod, errbuf);
}
inline drc_t debugger_t::read_registers(thid_t tid, int clsmask, regval_t *values, qstring *errbuf)
{
  return notify_drc(ev_read_registers, tid, clsmask, values, errbuf);
}
inline drc_t debugger_t::write_register(thid_t tid, int regidx, const regval_t *value, qstring *errbuf)
{
  return notify_drc(ev_write_register, tid, regidx, value, errbuf);
}
inline drc_t debugger_t::thread_get_sreg_base(ea_t *answer, thid_t tid, int sreg_value, qstring *errbuf)
{
  return notify_drc(ev_thread_get_sreg_base, answer, tid, sreg_value, errbuf);
}
inline drc_t debugger_t::get_memory_info(meminfo_vec_t &ranges, qstring *errbuf)
{
  return notify_drc(ev_get_memory_info, &ranges, errbuf);
}
inline drc_t debugger_t::read_memory(size_t *nbytes, ea_t ea, void *buffer, size_t size, qstring *errbuf)
{
  return notify_drc(ev_read_memory, nbytes, ea, buffer, size, errbuf);
}
inline drc_t debugger_t::write_memory(size_t *nbytes, ea_t ea, const void *buffer, size_t size, qstring *errbuf)
{
  return notify_drc(ev_write_memory, nbytes, ea, buffer, size, errbuf);
}
inline drc_t debugger_t::check_bpt(int *bptvc, bpttype_t type, ea_t ea, int len)
{
  return notify_drc(ev_check_bpt, bptvc, type, ea, len);
}
inline drc_t debugger_t::update_bpts(int *nbpts, update_bpt_info_t *bpts, int nadd, int ndel, qstring *errbuf)
{
  return notify_drc(ev_update_bpts, nbpts, bpts, nadd, ndel, errbuf);
}
inline drc_t debugger_t::update_lowcnds(int *nupdated, const lowcnd_t *lowcnds, int nlowcnds, qstring *errbuf)
{
  return notify_drc(ev_update_lowcnds, nupdated, lowcnds, nlowcnds, errbuf);
}
inline int debugger_t::open_file(const char *file, uint64 *fsize, bool readonly, qstring *errbuf)
{
  return int(notify(ev_open_file, file, fsize, readonly, errbuf));
}
inline void debugger_t::close_file(int fn)
{
  notify(ev_close_file, fn);
}
inline ssize_t debugger_t::read_file(int fn, qoff64_t off, void *buf, size_t size, qstring *errbuf)
{
  return notify(ev_read_file, fn, off, buf, size, errbuf);
}
inline ssize_t debugger_t::write_file(int fn, qoff64_t off, const void *buf, size_t size, qstring *errbuf)
{
  return notify(ev_write_file, fn, off, buf, size, errbuf);
}
inline ea_t debugger_t::map_address(ea_t off, const regval_t *rvs, int regnum)
{
  ea_t mapped;
  return notify_drc(ev_map_address, &mapped, off, rvs, regnum) == DRC_OK
       ? mapped
       : off;
}
inline const void *debugger_t::get_debmod_extensions(void)
{
  void *ext;
  if ( notify_drc(ev_get_debmod_extensions, &ext) != DRC_OK )
    ext = nullptr;
  return ext;
}
inline drc_t debugger_t::update_call_stack(thid_t tid, call_stack_t *trace)
{
  return notify_drc(ev_update_call_stack, tid, trace);
}
inline ea_t debugger_t::appcall(
        ea_t func_ea,
        thid_t tid,
        const struct func_type_data_t *fti,
        int nargs,
        const struct regobjs_t *regargs,
        struct relobj_t *stkargs,
        struct regobjs_t *retregs,
        qstring *errbuf,
        debug_event_t *event,
        int options)
{
  ea_t blob_ea;
  if ( notify_drc(ev_appcall, &blob_ea, func_ea, tid, fti, nargs, regargs, stkargs, retregs, errbuf, event, options) != DRC_OK )
  {
    blob_ea = BADADDR;
    if ( errbuf != nullptr )
      *errbuf = "Debugger plugin does not support an application function call";
  }
  return blob_ea;
}
inline drc_t debugger_t::cleanup_appcall(thid_t tid)
{
  return notify_drc(ev_cleanup_appcall, tid);
}
inline drc_t debugger_t::eval_lowcnd(thid_t tid, ea_t ea, qstring *errbuf)
{
  return notify_drc(ev_eval_lowcnd, tid, ea, errbuf);
}
inline drc_t debugger_t::send_ioctl(int fn, const void *buf, size_t size, void **poutbuf, ssize_t *poutsize, qstring *errbuf)
{
  return notify_drc(ev_send_ioctl, fn, buf, size, poutbuf, poutsize, errbuf);
}
inline bool debugger_t::dbg_enable_trace(thid_t tid, bool enable, int trace_flags)
{
  return notify_drc(ev_dbg_enable_trace, tid, enable, trace_flags) == DRC_OK;
}
inline bool debugger_t::is_tracing_enabled(thid_t tid, int tracebit)
{
  return notify_drc(ev_is_tracing_enabled, tid, tracebit) == DRC_OK;
}
inline int debugger_t::rexec(const char *cmdline)
{
  return int(notify(ev_rexec, cmdline));
}
inline bool debugger_t::get_srcinfo_path(qstring *path, ea_t base)
{
  return notify_drc(ev_get_srcinfo_path, path, base) == DRC_OK;
}
inline drc_t debugger_t::bin_search(
        ea_t *out,
        ea_t start_ea,
        ea_t end_ea,
        const compiled_binpat_vec_t &data,
        int srch_flags,
        qstring *errbuf)
{
  return notify_drc(ev_bin_search, out, start_ea, end_ea, &data, srch_flags, errbuf);
}
#endif // _IDD_HPP
