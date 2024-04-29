/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _LOADER_HPP
#define _LOADER_HPP
#include <ida.hpp>

/*! \file loader.hpp

  \brief Definitions of IDP, LDR, PLUGIN module interfaces

  This file also contains:
    - functions to load files into the database
    - functions to generate output files
    - high level functions to work with the database (open, save, close)

  The LDR interface consists of one structure: loader_t      \n
  The IDP interface consists of one structure: processor_t   \n
  The PLUGIN interface consists of one structure: plugin_t

  Modules can't use standard FILE* functions.
  They must use functions from <fpro.h>

  Modules can't use standard memory allocation functions.
  They must use functions from <pro.h>

  The exported entry #1 in the module should point to the
  the appropriate structure. (loader_t for LDR module, for example)
*/

//----------------------------------------------------------------------
//              DEFINITION OF LDR MODULES
//----------------------------------------------------------------------

class linput_t;         // loader input source. see diskio.hpp for the functions
struct extlang_t;       // check expr.hpp
struct plugmod_t;       // idp.hpp

/// Loader description block - must be exported from the loader module
struct loader_t
{
  uint32 version;        ///< api version, should be #IDP_INTERFACE_VERSION
  uint32 flags;          ///< \ref LDRF_
/// \defgroup LDRF_ Loader flags
/// Used by loader_t::flags
//@{
#define LDRF_RELOAD   0x0001 ///< loader recognizes #NEF_RELOAD flag
#define LDRF_REQ_PROC 0x0002 ///< Requires a processor to be set.
                             ///< if this bit is not set, load_file() must
                             ///< call set_processor_type(..., SETPROC_LOADER)
//@}

  /// Check input file format.
  /// This function will be called one or more times depending on the result value.
  /// \param[out] fileformat name of file format
  /// \param[out] processor  desired processor (optional)
  /// \param li              input file
  /// \param filename        name of the input file,
  ///                        if it is an archive member name then the actual file doesn't exist
  /// \return
  /// 1 if file format is recognized, and fills 'fileformatname', otherwise returns 0.
  /// This function may return a unique file format number instead of 1.
  /// To get this unique number, please contact the author.
  /// If the return value is ORed with #ACCEPT_ARCHIVE, then
  /// it is an archive loader. Its process_archive() will be called
  /// instead of load_file().
  /// If the return value is ORed with #ACCEPT_CONTINUE, then
  /// this function will be called another time.
  /// If the return value is ORed with #ACCEPT_FIRST, then this format
  /// should be placed first in the "load file" dialog box.
  /// In the sorting order of file formats the archive formats have priority.
  int (idaapi *accept_file)(
        qstring *fileformatname,
        qstring *processor,
        linput_t *li,
        const char *filename);

/// Specify that a file format is served by archive loader
/// See loader_t::accept_file
#define ACCEPT_ARCHIVE 0x2000
/// Specify that the function must be called another time
/// See loader_t::accept_file
#define ACCEPT_CONTINUE 0x4000
/// Specify that a file format should be place first in "load file" dialog box.
/// See loader_t::accept_file
#define ACCEPT_FIRST    0x8000

  /// Load file into the database.
  /// \param li              input file
  /// \param neflags         \ref NEF_
  /// \param fileformatname  name of type of the file
  ///                        (it was returned by #accept_file)
  ///
  /// If this function fails, loader_failure() should be called
  void (idaapi *load_file)(
        linput_t *li,
        ushort neflags,
        const char *fileformatname);
/// \defgroup NEF_ Load file flags
/// Passed as 'neflags' parameter to loader_t::load_file
//@{
#define NEF_SEGS        0x0001            ///< Create segments
#define NEF_RSCS        0x0002            ///< Load resources
#define NEF_NAME        0x0004            ///< Rename entries
#define NEF_MAN         0x0008            ///< Manual load
#define NEF_FILL        0x0010            ///< Fill segment gaps
#define NEF_IMPS        0x0020            ///< Create import segment
#define NEF_FIRST       0x0080            ///< This is the first file loaded
                                          ///< into the database.
#define NEF_CODE        0x0100            ///< for load_binary_file():
                                          ///<   load as a code segment
#define NEF_RELOAD      0x0200            ///< reload the file at the same place:
                                          ///<   - don't create segments
                                          ///<   - don't create fixup info
                                          ///<   - don't import segments
                                          ///<   - etc.
                                          ///<
                                          ///< Load only the bytes into the base.
                                          ///< A loader should have the #LDRF_RELOAD
                                          ///< bit set.
#define NEF_FLAT        0x0400            ///< Autocreate FLAT group (PE)
#define NEF_MINI        0x0800            ///< Create mini database (do not copy
                                          ///< segment bytes from the input file;
                                          ///< use only the file header metadata)
#define NEF_LOPT        0x1000            ///< Display additional loader options dialog
#define NEF_LALL        0x2000            ///< Load all segments without questions
//@}

  /// Create output file from the database.
  /// This function may be absent.
  /// If fp == nullptr, then this function returns:
  ///                 - 0: can't create file of this type
  ///                 - 1: ok, can create file of this type
  ///
  /// If fp != nullptr, then this function should create the output file
  int (idaapi *save_file)(FILE *fp, const char *fileformatname);

  /// Take care of a moved segment (fix up relocations, for example).
  /// This function may be absent.
  /// A special calling method \code move_segm(BADADDR, delta, 0, formatname); \endcode
  /// means that the whole program has been moved in the memory (rebased) by delta bytes
  /// \param  from            previous linear address of the segment
  /// \param  to              current linear address of the segment
  /// \param  size            size of the moved segment
  /// \param  fileformatname  the file format
  /// \retval 1  ok
  /// \retval 0  failure
  int (idaapi *move_segm)(
          ea_t from,
          ea_t to,
          asize_t size,
          const char *fileformatname);

  /// Display list of archive members and let the user select one.
  /// Extract the selected archive member into a temporary file.
  /// \param[out]     temp_file      name of the file with the extracted archive member.
  /// \param          li             input file
  /// \param[in,out]  module_name    in: name of archive
  ///                                out: name of the extracted archive member
  /// \param[in,out]  neflags        \ref NEF_
  /// \param          fileformatname name of type of the file
  ///                                (it was returned by #accept_file)
  /// \param          defmember      extract the specified member,
  ///                                for example "subdir/member.exe",
  ///                                may be nullptr
  /// \param          errbuf         error message if 0 is returned,
  ///                                may be nullptr
  /// \return -1-cancelled by the user, 1-ok, 0-error, see errbuf for details
  int (idaapi *process_archive)(
          qstring *temp_file,
          linput_t *li,
          qstring *module_name,
          ushort *neflags,
          const char *fileformatname,
          const char *defmember,
          qstring *errbuf);
};


/// See loader_failure()

idaman AS_PRINTF(1, 0) NORETURN void ida_export vloader_failure(const char *format, va_list va);


/// Display a message about a loader failure and stop the loading process.
/// The kernel will destroy the database.
/// If format == nullptr, no message will be displayed
/// This function does not return (it longjumps)!
/// It may be called only from loader_t::load_file

AS_PRINTF(1, 2) NORETURN inline void loader_failure(const char *format=nullptr, ...)
{
  va_list va;
  va_start(va, format);
  vloader_failure(format, va);
}

//-------------------------------------------------------------------------
#if defined(__NT__)
#  define DLLEXT "dll"
#elif defined(__LINUX__)
#  define DLLEXT "so"
#elif defined(__MAC__)
#  define DLLEXT "dylib"
#else
#  error Unknown loader ext
#endif

//----------------------------------------------------------------------
/// \def{LOADER_DLL, Pattern to find loader files}
#ifdef __EA64__
#  define LOADER_DLL "*64." DLLEXT
#else
#  define LOADER_DLL "*." DLLEXT
#endif

//----------------------------------------------------------------------
//      Functions for the UI to load files
//----------------------------------------------------------------------
/// List of loaders
struct load_info_t
{
  load_info_t *next;
  qstring dllname;
  qstring ftypename;
  qstring processor;    ///< desired processor name
  filetype_t ftype;
  uint32 loader_flags;  ///< copy of loader_t::flags
  uint32 lflags;        ///< \ref LIF_
  int pri;              ///< 2-archldr, 1-place first, 0-normal priority

/// \defgroup LIF_ loader info flags
/// Used by load_info_t::lflags
//@{
#define LIF_ARCHLDR   0x0001    ///< archive loader
//@}

  bool is_archldr(void) { return (lflags & LIF_ARCHLDR) != 0; }
};
DECLARE_TYPE_AS_MOVABLE(load_info_t);

/// Build list of potential loaders

idaman load_info_t *ida_export build_loaders_list(linput_t *li, const char *filename);


/// Free the list of loaders

idaman void ida_export free_loaders_list(load_info_t *list);


/// Get name of loader from its DLL file
/// (for example, for PE files we will get "PE").
/// This function modifies the original string and returns a pointer into it.
/// NB: if the file extension is a registered extlang extension (e.g. py or idc)
/// the extension is retained

idaman char *ida_export get_loader_name_from_dll(char *dllname);


/// Get name of loader used to load the input file into the database.
/// If no external loader was used, returns -1.
/// Otherwise copies the loader file name without the extension in the buf
/// and returns its length
/// (for example, for PE files we will get "PE").
/// For scripted loaders, the file extension is retained.

idaman ssize_t ida_export get_loader_name(char *buf, size_t bufsize);


/// Load a binary file into the database.
/// This function usually is called from ui.
/// \param filename  the name of input file as is
///                    (if the input file is from library, then
///                     this is the name from the library)
/// \param li        loader input source
/// \param _neflags  \ref NEF_. For the first file,
///                  the flag #NEF_FIRST must be set.
/// \param fileoff   Offset in the input file
/// \param basepara  Load address in paragraphs
/// \param binoff    Load offset (load_address=(basepara<<4)+binoff)
/// \param nbytes    Number of bytes to load from the file.
///                    - 0: up to the end of the file
///
///                  If nbytes is bigger than the number of
///                  bytes rest, the kernel will load as much
///                  as possible
/// \retval true   ok
/// \retval false  failed (couldn't open the file)

idaman bool ida_export load_binary_file(
        const char *filename,
        linput_t *li,
        ushort _neflags,
        qoff64_t fileoff,
        ea_t basepara,
        ea_t binoff,
        uint64 nbytes);


/// Load a non-binary file into the database.
/// This function usually is called from ui.
/// \param filename   the name of input file as is
///                   (if the input file is from library, then
///                    this is the name from the library)
/// \param li         loader input source
/// \param sysdlldir  a directory with system dlls. Pass "." if unknown.
/// \param _neflags   \ref NEF_. For the first file
///                   the flag #NEF_FIRST must be set.
/// \param loader     pointer to ::load_info_t structure.
///                   If the current IDP module has \ph{loader} != nullptr
///                   then this argument is ignored.
/// \return success

idaman bool ida_export load_nonbinary_file(
        const char *filename,
        linput_t *li,
        const char *sysdlldir,
        ushort _neflags,
        load_info_t *loader);


/// Calls loader_t::process_archive()
/// For parameters and return value description
/// look at loader_t::process_archive().
/// Additional parameter 'loader' is a pointer to ::load_info_t structure.

idaman int ida_export process_archive(
        qstring *temp_file,
        linput_t *li,
        qstring *module_name,
        ushort *neflags,
        const char *defmember,
        const load_info_t *loader,
        qstring *errbuf=nullptr);

//--------------------------------------------------------------------------
/// Output file types
enum ofile_type_t
{
  OFILE_MAP  = 0,        ///< MAP file
  OFILE_EXE  = 1,        ///< Executable file
  OFILE_IDC  = 2,        ///< IDC file
  OFILE_LST  = 3,        ///< Disassembly listing
  OFILE_ASM  = 4,        ///< Assembly
  OFILE_DIF  = 5,        ///< Difference
};

//------------------------------------------------------------------
/// Generate an output file.
/// \param otype  type of output file.
/// \param fp     the output file handle
/// \param ea1    start address. For some file types this argument is ignored
/// \param ea2    end address. For some file types this argument is ignored
///               as usual in ida, the end address of the range is not included
/// \param flags  \ref GENFLG_
///
/// For ::OFILE_EXE:
/// \retval 0  can't generate exe file
/// \retval 1  ok
///
/// For other file types:
/// \return number of the generated lines. -1 if an error occurred

idaman int ida_export gen_file(ofile_type_t otype, FILE *fp, ea_t ea1, ea_t ea2, int flags);

/// \defgroup GENFLG_ Generate file flags
/// Passed as 'flags' parameter to gen_file()
//@{
#define GENFLG_MAPSEG  0x0001          ///< ::OFILE_MAP: generate map of segments
#define GENFLG_MAPNAME 0x0002          ///< ::OFILE_MAP: include dummy names
#define GENFLG_MAPDMNG 0x0004          ///< ::OFILE_MAP: demangle names
#define GENFLG_MAPLOC  0x0008          ///< ::OFILE_MAP: include local names
#define GENFLG_IDCTYPE 0x0008          ///< ::OFILE_IDC: gen only information about types
#define GENFLG_ASMTYPE 0x0010          ///< ::OFILE_ASM,::OFILE_LST: gen information about types too
#define GENFLG_GENHTML 0x0020          ///< ::OFILE_ASM,::OFILE_LST: generate html (::ui_genfile_callback will be used)
#define GENFLG_ASMINC  0x0040          ///< ::OFILE_ASM,::OFILE_LST: gen information only about types
//@}

//----------------------------------------------------------------------
//      Helper functions for the loaders & ui
//----------------------------------------------------------------------

/// Load portion of file into the database.
/// This function will include (ea1..ea2) into the addressing space of the
/// program (make it enabled).
/// \param li         pointer of input source
/// \param pos        position in the file
/// \param ea1,ea2    range of destination linear addresses
/// \param patchable  should the kernel remember correspondence of
///                   file offsets to linear addresses.
/// \retval 1  ok
/// \retval 0  read error, a warning is displayed
/// \note The storage type of the specified range will be changed to STT_VA.

idaman int ida_export file2base(
        linput_t *li,
        qoff64_t pos,
        ea_t ea1,
        ea_t ea2,
        int patchable);

#define FILEREG_PATCHABLE       1       ///< means that the input file may be
                                        ///< patched (i.e. no compression,
                                        ///< no iterated data, etc)
#define FILEREG_NOTPATCHABLE    0       ///< the data is kept in some encoded
                                        ///< form in the file.


/// Load database from the memory.
/// This function works for wide byte processors too.
/// \param memptr   pointer to buffer with bytes
/// \param ea1,ea2  range of destination linear addresses
/// \param fpos     position in the input file the data is taken from.
///                 if == -1, then no file position correspond to the data.
/// \return 1 always
/// \note The storage type of the specified range will be changed to STT_VA.

idaman int ida_export mem2base(const void *memptr, ea_t ea1, ea_t ea2, qoff64_t fpos);


/// Unload database to a binary file.
/// This function works for wide byte processors too.
/// \param fp       pointer to file
/// \param pos      position in the file
/// \param ea1,ea2  range of source linear addresses
/// \return 1-ok(always), write error leads to immediate exit

idaman int ida_export base2file(FILE *fp, qoff64_t pos, ea_t ea1, ea_t ea2);


/// Extract a module for an archive file.
/// Parse an archive file, show the list of modules to the user, allow him to
/// select a module, extract the selected module to a file (if the extract module
/// is an archive, repeat the process).
/// This function can handle ZIP, AR, AIXAR, OMFLIB files.
/// The temporary file will be automatically deleted by IDA at the end.
/// \param[in,out] filename    in: input file.
///                            out: name of the selected module.
/// \param bufsize             size of the buffer with 'filename'
/// \param[out] temp_file_ptr  will point to the name of the file that
///                            contains the extracted module
/// \param is_remote           is the input file remote?
/// \retval true   ok
/// \retval false  something bad happened (error message has been displayed to the user)

idaman bool ida_export extract_module_from_archive(
        char *filename,
        size_t bufsize,
        char **temp_file_ptr,
        bool is_remote);


/// Add long comment at \inf{min_ea}.
///   - Input file:     ....
///   - File format:    ....
///
/// This function should be called only from the loader to describe the input file.

idaman void ida_export create_filename_cmt(void);


/// Get the input file type.
/// This function can recognize libraries and zip files.

idaman filetype_t ida_export get_basic_file_type(linput_t *li);


/// Get name of the current file type.
/// The current file type is kept in \inf{filetype}.
/// \param buf      buffer for the file type name
/// \param bufsize  its size
/// \return size of answer, this function always succeeds

idaman size_t ida_export get_file_type_name(char *buf, size_t bufsize);


//----------------------------------------------------------------------
//      Work with IDS files: read and use information from them
//

/// See ::importer_t
struct impinfo_t
{
  const char *dllname;
  void (idaapi*func)(uval_t num, const char *name, uval_t node);
  uval_t node;
};


/// Callback for checking dll module - passed to import_module().
/// \param li  pointer to input file
/// \param ii  import info.
///            If the function finds that ii.dllname does not match
///            the module name passed to import_module(), it returns 0. \n
///            Otherwise it calls ii.func for each exported entry.      \n
///            If ii.dllname==nullptr then ii.func will be called
///            with num==0 and name==dllname.
/// \retval 0  dllname doesn't match, import_module() should continue
/// \retval 1  ok

typedef int idaapi importer_t(linput_t *li, impinfo_t *ii);


/// Find and import a DLL module.
/// This function adds information to the database (renames functions, etc).
/// \param module    name of DLL
/// \param windir    system directory with dlls
/// \param modnode   node with information about imported entries.
///                  either altval or supval arrays may be absent.
///                  the node should never be deleted.
///                    - imports by ordinals:
///                        altval(ord) contains linear address
///                    - imports by name:
///                        supval(ea) contains the imported name
///                  please use set_import_ordinal()/set_import_name()
///                  to work with MODNODE
/// \param importer  callback function (may be nullptr) to check dll module
/// \param ostype    type of operating system (subdir name).
///                  nullptr means the IDS directory itself (not recommended)

idaman void ida_export import_module(
        const char *module,
        const char *windir,
        uval_t modnode,
        importer_t *importer,
        const char *ostype);


/// Set information about the ordinal import entry.
/// This function performs 'modnode.altset(ord, ea2node(ea));'
/// \param modnode  node with information about imported entries
/// \param ea       linear address of the entry
/// \param ord      ordinal number of the entry

idaman void ida_export set_import_ordinal(
        uval_t modnode,
        ea_t ea,
        uval_t ord);


/// Set information about the named import entry.
/// This function performs 'modnode.supset_ea(ea, name);'
/// \param modnode  node with information about imported entries
/// \param ea       linear address of the entry
/// \param name     name of the entry

idaman void ida_export set_import_name(
        uval_t modnode,
        ea_t ea,
        const char *name);


/// Load and apply IDS file.
/// This function loads the specified IDS file and applies it to the database.
/// If the program imports functions from a module with the same name
/// as the name of the ids file being loaded, then only functions from this
/// module will be affected. Otherwise (i.e. when the program does not import
/// a module with this name) any function in the program may be affected.
/// \param fname  name of file to apply
/// \retval 1  ok
/// \retval 0  some error (a message is displayed).
///            if the ids file does not exist, no message is displayed

idaman int ida_export load_ids_module(char *fname);


//----------------------------------------------------------------------
//              DEFINITION OF PLUGIN MODULES
//----------------------------------------------------------------------
/// A plugin is a module in the plugins subdirectory that can perform
/// an action asked by the user. (usually via pressing a hotkey)
class plugin_t
{
public:
  int version;                  ///< Should be equal to #IDP_INTERFACE_VERSION
  int flags;                    ///< \ref PLUGIN_
/// \defgroup PLUGIN_ Plugin features
/// Used by plugin_t::flags
//@{
#define PLUGIN_MOD  0x0001      ///< Plugin changes the database.
                                ///< IDA won't call the plugin if
                                ///< the processor module prohibited any changes.
#define PLUGIN_DRAW 0x0002      ///< IDA should redraw everything after calling the plugin.
#define PLUGIN_SEG  0x0004      ///< Plugin may be applied only if the current address belongs to a segment
#define PLUGIN_UNL  0x0008      ///< Unload the plugin immediately after calling 'run'.
                                ///< This flag may be set anytime.
                                ///< The kernel checks it after each call to 'run'
                                ///< The main purpose of this flag is to ease
                                ///< the debugging of new plugins.
#define PLUGIN_HIDE 0x0010      ///< Plugin should not appear in the Edit, Plugins menu.
                                ///< This flag is checked at the start.
#define PLUGIN_DBG  0x0020      ///< A debugger plugin. init() should put
                                ///< the address of ::debugger_t to dbg.
#define PLUGIN_PROC 0x0040      ///< Load plugin when a processor module is loaded. (and keep it
                                ///< until the processor module is unloaded)
#define PLUGIN_FIX  0x0080      ///< Load plugin when IDA starts and keep it in the memory until IDA stops
#define PLUGIN_MULTI    0x0100  ///< The plugin can work with multiple idbs in parallel.
                                ///< init() returns a pointer to a plugmod_t object
                                ///< run/term functions are not used.
                                ///< Virtual functions of plugmod_t are used instead.
#define PLUGIN_SCRIPTED 0x8000  ///< Scripted plugin. Should not be used by plugins,
                                ///< the kernel sets it automatically.
//@}

  plugmod_t *(idaapi *init)(void);  ///< Initialize plugin - returns a pointer to plugmod_t
#if !defined(NO_OBSOLETE_FUNCS) || defined(__DEFINE_PLUGIN_RETURN_CODES__)
/// \defgroup PLUGIN_INIT Plugin initialization codes
/// Return values for plugin_t::init()
/// Deprecated, please update your plugins to use PLUGIN_MULTI.
//@{
#define PLUGIN_SKIP  nullptr          ///< Plugin doesn't want to be loaded
#define PLUGIN_OK    ((plugmod_t *)1) ///< Plugin agrees to work with the current database.
                                      ///< It will be loaded as soon as the user presses the hotkey
#define PLUGIN_KEEP  ((plugmod_t *)2) ///< Plugin agrees to work with the current database and wants to stay in the memory
//@}
#endif

  void (idaapi *term)(void);      ///< Terminate plugin. This function will be called
                                  ///< when the plugin is unloaded. May be nullptr.
                                  ///< Must be nullptr for PLUGIN_MULTI plugins
  bool (idaapi *run)(size_t arg); ///< Invoke plugin.
                                  ///< Must be nullptr for PLUGIN_MULTI plugins
  const char *comment;            ///< Long comment about the plugin.
                                  ///< it could appear in the status line
                                  ///< or as a hint
  const char *help;               ///< Multiline help about the plugin
  const char *wanted_name;        ///< The preferred short name of the plugin
  const char *wanted_hotkey;      ///< The preferred hotkey to run the plugin
};

#ifndef __X86__
  CASSERT(sizeof(plugin_t) == 64);
#else
  CASSERT(sizeof(plugin_t) == 36);
#endif

#if !defined(__KERNEL__) && !defined(PLUGIN_SUBMODULE)
idaman ida_module_data plugin_t PLUGIN; // (declaration for plugins)
#endif

/// Get plugin options from the command line.
/// If the user has specified the options in the -Oplugin_name:options
/// format, them this function will return the 'options' part of it
/// The 'plugin' parameter should denote the plugin name
/// Returns nullptr if there we no options specified

idaman const char *ida_export get_plugin_options(const char *plugin);


//--------------------------------------------------------------------------
/// Pattern to find plugin files
#ifdef __EA64__
#  define PLUGIN_DLL "*64." DLLEXT
#else
#  define PLUGIN_DLL "*." DLLEXT
#endif


// LOW LEVEL DLL LOADING FUNCTIONS
// Only the kernel should use these functions!
/// \cond
#define LNE_MAXSEG      10      // Max number of segments

#if 0
extern char dlldata[4096];      // Reserved place for DLL data
#define DLLDATASTART    0xA0    // Absolute offset of dlldata
extern char ldrdata[64];        // Reserved place for LOADER data
#define LDRDATASTART    (DLLDATASTART+sizeof(dlldata)) // Absolute offset of ldrdata
#endif

struct idadll_t
{
  void *dllinfo[LNE_MAXSEG];
  void *entry;                  // first entry point of DLL
  idadll_t(void) { dllinfo[0] = nullptr; entry = nullptr; }
  bool is_loaded(void) const { return dllinfo[0] != nullptr; }
};

#define MODULE_ENTRY_LOADER "LDSC"
#define MODULE_ENTRY_PLUGIN "PLUGIN"
#define MODULE_ENTRY_IDP "LPH"

int _load_core_module(
        idadll_t *dllmem,
        const char *file,
        const char *entry);
                                // dllmem - allocated segments
                                //          dos: segment 1 (data) isn't allocated
                                // Returns 0 - ok, else:
#define RE_NOFILE       1       /* No such file */
#define RE_NOTIDP       2       /* Not IDP file */
#define RE_NOPAGE       3       /* Can't load: bad segments */
#define RE_NOLINK       4       /* No linkage info */
#define RE_BADRTP       5       /* Bad relocation type */
#define RE_BADORD       6       /* Bad imported ordinal */
#define RE_BADATP       7       /* Bad relocation atype */
#define RE_BADMAP       8       /* DLLDATA offset is invalid */

void load_core_module_or_die(
        idadll_t *dllmem,
        const char *file,
        const char *entry);
idaman bool ida_export load_core_module(
        idadll_t *dllmem,
        const char *file,
        const char *entry);

idaman void ida_export free_dll(idadll_t *dllmem);
/// \endcond

/// Processor name
struct idp_name_t
{
  qstring lname;        ///< long processor name
  qstring sname;        ///< short processor name
  bool    hidden;       ///< is hidden
  idp_name_t() : hidden(false) {}
};
DECLARE_TYPE_AS_MOVABLE(idp_name_t);
typedef qvector<idp_name_t> idp_names_t; ///< vector of processor names

/// Processor module description
struct idp_desc_t
{
  qstring   path;       ///< module file name
  time_t    mtime;      ///< time of last modification
  qstring   family;     ///< processor's family
  idp_names_t names;    ///< processor names
  bool      is_script;  ///< the processor module is a script
  bool      checked;    ///< internal, for cache management
  idp_desc_t(): mtime(time_t(-1)), is_script(false), checked(false) {}
};
DECLARE_TYPE_AS_MOVABLE(idp_desc_t);
typedef qvector<idp_desc_t> idp_descs_t; ///< vector of processor module descriptions


/// Get IDA processor modules descriptions

idaman const idp_descs_t *ida_export get_idp_descs(void);


//--------------------------------------------------------------------------
/// \def{IDP_DLL, Pattern to find idp files}
#ifdef __EA64__
#  define IDP_DLL "*64." DLLEXT
#else
#  define IDP_DLL "*." DLLEXT
#endif


//--------------------------------------------------------------------------
/// Structure to store Plugin information
struct plugin_info_t
{
  plugin_info_t *next;  ///< next plugin information
  char *path;           ///< full path to the plugin
  char *org_name;       ///< original short name of the plugin
  char *name;           ///< short name of the plugin
                        ///< it will appear in the menu
  ushort org_hotkey;    ///< original hotkey to run the plugin
  ushort hotkey;        ///< current hotkey to run the plugin
  size_t arg;           ///< argument used to call the plugin
  plugin_t *entry;      ///< pointer to the plugin if it is already loaded
  idadll_t dllmem;
  int flags;            ///< a copy of plugin_t::flags
  char *comment;        ///< a copy of plugin_t::comment
};


/// Get pointer to the list of plugins. (some plugins might be listed several times
/// in the list - once for each configured argument)

idaman plugin_info_t *ida_export get_plugins(void);


/// Find a user-defined plugin and optionally load it.
/// \param name  short plugin name without path and extension,
///              or absolute path to the file name
/// \param load_if_needed if the plugin is not present in the memory, try to load it
/// \return pointer to plugin description block

idaman plugin_t *ida_export find_plugin(const char *name, bool load_if_needed=false);

inline plugin_t *load_plugin(const char *name)
{
  return find_plugin(name, true);
}


/// Run a loaded plugin with the specified argument.
/// \param ptr  pointer to plugin description block
/// \param arg  argument to run with

idaman bool ida_export run_plugin(const plugin_t *ptr, size_t arg);


/// Load & run a plugin

inline bool idaapi load_and_run_plugin(const char *name, size_t arg)
{
  return run_plugin(load_plugin(name), arg);
}


/// Run a plugin as configured.
/// \param ptr  pointer to plugin information block

idaman bool ida_export invoke_plugin(plugin_info_t *ptr);


/// Information for the user interface about available debuggers
struct dbg_info_t
{
  plugin_info_t *pi;
  struct debugger_t *dbg;
  dbg_info_t(plugin_info_t *_pi, struct debugger_t *_dbg) : pi(_pi), dbg(_dbg) {}
};
DECLARE_TYPE_AS_MOVABLE(dbg_info_t);


/// Get information about available debuggers

idaman size_t ida_export get_debugger_plugins(const dbg_info_t **array);


/// Initialize plugins with the specified flag

idaman void ida_export init_plugins(int flag);


/// Terminate plugins with the specified flag

idaman void ida_export term_plugins(int flag);


//------------------------------------------------------------------------

/// Get offset in the input file which corresponds to the given ea.
/// If the specified ea can't be mapped into the input file offset,
/// return -1.

idaman qoff64_t ida_export get_fileregion_offset(ea_t ea);


/// Get linear address which corresponds to the specified input file offset.
/// If can't be found, return #BADADDR

idaman ea_t ida_export get_fileregion_ea(qoff64_t offset);


//------------------------------------------------------------------------
/// Generate an exe file (unload the database in binary form).
/// \return fp  the output file handle. if fp == nullptr then return:
///               - 1: can generate an executable file
///               - 0: can't generate an executable file
/// \retval 1  ok
/// \retval 0  failed

idaman int ida_export gen_exe_file(FILE *fp);


//------------------------------------------------------------------------
/// Reload the input file.
/// This function reloads the byte values from the input file.
/// It doesn't modify the segmentation, names, comments, etc.
/// \param file       name of the input file. if file == nullptr then returns:
///                     - 1: can reload the input file
///                     - 0: can't reload the input file
/// \param is_remote  is the file located on a remote computer with
///                   the debugger server?
/// \return success

idaman bool ida_export reload_file(const char *file, bool is_remote);


//---------------------------------------------------------------------------
//       S N A P S H O T   F U N C T I O N S

/// Maximum database snapshot description length
#define MAX_DATABASE_DESCRIPTION 128

class snapshot_t;
typedef qvector<snapshot_t *> snapshots_t; ///< vector of database snapshots

/// Snapshot attributes
class snapshot_t
{
private:
  snapshot_t &operator=(const snapshot_t &);
  snapshot_t(const snapshot_t &);

  int compare(const snapshot_t &r) const
  {
    return ::compare(id, r.id);
  }

public:
  qtime64_t id;                          ///< snapshot ID. This value is computed using qgettimeofday()
  uint16 flags;                          ///< \ref SSF_
/// \defgroup SSF_ Snapshot flags
/// Used by snapshot_t::flags
//@{
#define SSF_AUTOMATIC         0x0001     ///< automatic snapshot
//@}
  char desc[MAX_DATABASE_DESCRIPTION];   ///< snapshot description
  char filename[QMAXPATH];               ///< snapshot file name
  snapshots_t children;                  ///< snapshot children
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  DECLARE_COMPARISON_OPERATORS(snapshot_t)
  void clear()
  {
    for ( snapshots_t::iterator p=children.begin();
          p != children.end();
          ++p )
    {
      delete *p;
    }
    children.clear();
  }

  snapshot_t(): id(0), flags(0)
  {
    filename[0] = desc[0] = '\0';
  }

  ~snapshot_t()
  {
    clear();
  }
};
DECLARE_TYPE_AS_MOVABLE(snapshot_t);

//------------------------------------------------------------------------
/// Build the snapshot tree.
/// \param root  snapshot root that will contain the snapshot tree elements.
/// \return success

idaman bool ida_export build_snapshot_tree(snapshot_t *root);


//------------------------------------------------------------------------
/// Update the snapshot attributes.
/// \note only the snapshot description can be updated.
/// \param filename  snapshot file name or nullptr for the current database
/// \param root      snapshot root (returned from build_snapshot_tree())
/// \param attr      snapshot instance containing the updated attributes
/// \param uf        \ref SSUF_
/// \return success
idaman bool ida_export update_snapshot_attributes(
        const char *filename,
        const snapshot_t *root,
        const snapshot_t *attr,
        int uf);

/// \defgroup SSUF_ Snapshot update flags
/// Passed as 'uf' parameter to update_snapshot_attributes()
//@{
#define SSUF_DESC        0x00000001             ///< Update the description
#define SSUF_PATH        0x00000002             ///< Update the path
#define SSUF_FLAGS       0x00000004             ///< Update the flags
//@}

//------------------------------------------------------------------------
/// Visit the snapshot tree.
/// \param root      snapshot root to start the enumeration from
/// \param callback  callback called for each child. return 0 to continue enumeration
///                  and non-zero to abort enumeration
/// \param ud        user data. will be passed back to the callback
/// \return true-ok, false-failed

idaman int ida_export visit_snapshot_tree(
        snapshot_t *root,
        int (idaapi *callback)(snapshot_t *ss, void *ud),
        void *ud=nullptr);


/// Flush buffers to the disk

idaman int ida_export flush_buffers(void);


/// Is the database considered as trusted?

idaman bool ida_export is_trusted_idb(void);

//------------------------------------------------------------------------
/// Save current database using a new file name.
/// \param outfile  output database file name
/// \param flags    \ref DBFL_
/// \param root     optional: snapshot tree root.
/// \param attr     optional: snapshot attributes
/// \note when both root and attr are not nullptr then the snapshot
///       attributes will be updated, otherwise the snapshot attributes
///       will be inherited from the current database.
/// \return success

idaman bool ida_export save_database(
        const char *outfile,
        uint32 flags,
        const snapshot_t *root = nullptr,
        const snapshot_t *attr = nullptr);

/// \defgroup DBFL_ Database flags
/// Used to manage saving/closing of a database
//@{
#define DBFL_KILL       0x01            ///< delete unpacked database
#define DBFL_COMP       0x02            ///< collect garbage
#define DBFL_BAK        0x04            ///< create backup file (if !DBFL_KILL)
#define DBFL_TEMP       0x08            ///< temporary database
//@}

/// Get the current database flag
/// \param dbfl     flag \ref DBFL_
/// \returns the state of the flag (set or cleared)

idaman bool ida_export is_database_flag(uint32 dbfl);

/// Set or clear database flag
/// \param dbfl     flag \ref DBFL_
/// \param cnd      set if true or clear flag otherwise

idaman void ida_export set_database_flag(uint32 dbfl, bool cnd=true);
inline void clr_database_flag(uint32 dbfl) { set_database_flag(dbfl, false); }

/// Is a temporary database?
inline bool is_temp_database(void) { return is_database_flag(DBFL_TEMP); }


//------------------------------------------------------------------------
/// \defgroup PATH_TYPE_ Types of the file pathes
//@{
enum path_type_t
{
  PATH_TYPE_CMD,  ///< full path to the file specified in the command line
  PATH_TYPE_IDB,  ///< full path of IDB file
  PATH_TYPE_ID0,  ///< full path of ID0 file
};
//@}

/// Get the file path
/// \param pt       file path type \ref PATH_TYPE_
/// \returns file path, never returns nullptr
idaman const char *ida_export get_path(path_type_t pt);

/// Set the file path
/// \param pt       file path type \ref PATH_TYPE_
/// \param path     new file path,
///                 use nullptr or empty string to clear the file path
idaman void ida_export set_path(path_type_t pt, const char *path);


/// Check the file extension
/// \returns true if it is the reserved extension
idaman bool ida_export is_database_ext(const char *ext);


/// Get the value of the ELF_DEBUG_FILE_DIRECTORY configuration
/// directive.
idaman const char *ida_export get_elf_debug_file_directory();

/// \cond

#endif
