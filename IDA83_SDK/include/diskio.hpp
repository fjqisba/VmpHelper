/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _DISKIO_HPP
#define _DISKIO_HPP

#include <stdio.h>

/*! \file diskio.hpp

  \brief File I/O functions for IDA

  You should not use standard C file I/O functions in modules.
  Use functions from this header, pro.h and fpro.h instead.

  This file also declares a call_system() function.
*/

//-------------------------------------------------------------------------
//      S E A R C H   F O R   F I L E S
//-------------------------------------------------------------------------


/// Get IDA directory (if subdir==nullptr)
/// or the specified subdirectory (see \ref SUBDIR)

idaman THREAD_SAFE const char *ida_export idadir(const char *subdir);


/// Search for IDA system file.
/// This function searches for a file in:
///   -# each directory specified by %IDAUSR%
///   -# ida directory [+ subdir]
/// and returns the first match.
/// \param[out] buf  buffer for file name
/// \param bufsize   size of output buffer
/// \param filename  name of file to search
/// \param subdir    if specified, the file is looked for in the specified subdirectory
///                  of the ida directory first (see \ref SUBDIR)
/// \return nullptr if not found, otherwise a pointer to full file name.

idaman THREAD_SAFE char *ida_export getsysfile(
        char *buf,
        size_t bufsize,
        const char *filename,
        const char *subdir);

/// \defgroup SUBDIR IDA subdirectories
/// Passed as 'subdir' parameter to idadir(), getsysfile(), and others.
//@{
#define CFG_SUBDIR "cfg"
#define IDC_SUBDIR "idc"
#define IDS_SUBDIR "ids"
#define IDP_SUBDIR "procs"
#define LDR_SUBDIR "loaders"
#define SIG_SUBDIR "sig"
#define TIL_SUBDIR "til"
#define PLG_SUBDIR "plugins"
#define THM_SUBDIR "themes"
//@}

/// Get user ida related directory.
/// \code
///   - if $IDAUSR is defined:
///       - the first element in $IDAUSR
///   - else
///       - default user directory ($HOME/.idapro or %APPDATA%Hex-Rays/IDA Pro)
/// \endcode

idaman THREAD_SAFE const char *ida_export get_user_idadir(void);


/// Get list of directories in which to find a specific IDA resource
/// (see \ref SUBDIR). The order of the resulting list is as follows:
/// \code
/// - [$IDAUSR/subdir (0..N entries)]
/// - $IDADIR/subdir
/// \endcode
/// \param[out] dirs  output vector for directory names
/// \param subdir     name of the resource to list
/// \param flags      \ref IDA_SUBDIR_ bits
/// \return number of directories appended to 'dirs'

idaman THREAD_SAFE int ida_export get_ida_subdirs(qstrvec_t *dirs, const char *subdir, int flags=0);

/// \defgroup IDA_SUBDIR_ Subdirectory modification flags
/// Passed as 'flags' parameter to get_ida_subdirs()
//@{
#define IDA_SUBDIR_IDP           0x0001  ///< append the processor name as a subdirectory
#define IDA_SUBDIR_IDADIR_FIRST  0x0002  ///< $IDADIR/subdir will be first, not last
#define IDA_SUBDIR_ONLY_EXISTING 0x0004  ///< only existing directories will be present
//@}


/// Get a folder location by CSIDL (see \ref CSIDL).
/// Path should be of at least MAX_PATH size

idaman THREAD_SAFE bool ida_export get_special_folder(char *buf, size_t bufsize, int csidl);

/// \defgroup CSIDL Common CSIDLs
/// Passed as 'csidl' parameter to get_special_folder()
//@{
#ifndef CSIDL_APPDATA
#define CSIDL_APPDATA                 0x001a
#endif
#ifndef CSIDL_LOCAL_APPDATA
#define CSIDL_LOCAL_APPDATA           0x001c
#endif
#ifndef CSIDL_PROGRAM_FILES
#define CSIDL_PROGRAM_FILES           0x0026
#endif
#ifndef CSIDL_PROGRAM_FILES_COMMON
#define CSIDL_PROGRAM_FILES_COMMON    0x002b
#endif
#ifndef CSIDL_PROGRAM_FILESX86
#define CSIDL_PROGRAM_FILESX86        0x002a
#endif
//@}

/// Enumerate files in the specified directory.
/// \param[out] answer  buffer to contain the file name for which
///                     file_enumerator_t::visit_file returns non-zero value
///                     (may be nullptr)
/// \param answer_size  size of 'answer'
/// \param path         directory to enumerate files in
/// \param fname        mask of file names to enumerate
/// \param fv           file_enumerator_t::visit_file function called for each file
///                       - file: full file name (with path)
///                       - if returns non-zero value, the enumeration
///                         is stopped and the return code is
///                         is returned to the caller.
///                     the callback function
/// \return zero or the code returned by 'func'

struct file_enumerator_t
{
  virtual int visit_file(const char *file) = 0;
  virtual ~file_enumerator_t() {}
};

idaman THREAD_SAFE int ida_export enumerate_files2(
        char *answer,
        size_t answer_size,
        const char *path,
        const char *fname,
        file_enumerator_t &fv);



//-------------------------------------------------------------------------
//      O P E N / R E A D / W R I T E / C L O S E   F I L E S
//-------------------------------------------------------------------------

/// \name Open/Read/Write/Close Files
/// There are two sets of "open file" functions.
/// The first set tries to open a file and returns success or failure.
/// The second set is "open or die": if the file cannot be opened
/// then the function will display an error message and exit.
//@{

/// Open a new file for write in text mode, deny write.
/// If a file exists, it will be removed.
/// \return nullptr if failure

idaman THREAD_SAFE FILE *ida_export fopenWT(const char *file);


/// Open a new file for write in binary mode, deny read/write.
/// If a file exists, it will be removed.
/// \return nullptr if failure

idaman THREAD_SAFE FILE *ida_export fopenWB(const char *file);


/// Open a file for read in text mode, deny none.
/// \return nullptr if failure

idaman THREAD_SAFE FILE *ida_export fopenRT(const char *file);


/// Open a file for read in binary mode, deny none.
/// \return nullptr if failure

idaman THREAD_SAFE FILE *ida_export fopenRB(const char *file);


/// Open a file for read/write in binary mode, deny write.
/// \return nullptr if failure

idaman THREAD_SAFE FILE *ida_export fopenM(const char *file);


/// Open a file for append in text mode, deny none.
/// \return nullptr if failure

idaman THREAD_SAFE FILE *ida_export fopenA(const char *file);


/// Open a file for read in binary mode or die, deny none.
/// If a file cannot be opened, this function displays a message and exits.

idaman THREAD_SAFE FILE *ida_export openR(const char *file);


/// Open a file for read in text mode or die, deny none.
/// If a file cannot be opened, this function displays a message and exits.

idaman THREAD_SAFE FILE *ida_export openRT(const char *file);


/// Open a file for read/write in binary mode or die, deny write.
/// If a file cannot be opened, this function displays a message and exits.

idaman THREAD_SAFE FILE *ida_export openM(const char *file);


//@}

//-------------------------------------------------------------------------
//      F I L E   S I Z E   /   D I S K   S P A C E
//-------------------------------------------------------------------------

/// Change size of file or die.
/// If an error occurs, this function displays a message and exits.
/// \param fp    pointer to file
/// \param size  new size of file

idaman THREAD_SAFE void ida_export echsize(FILE *fp, uint64 size);


/// Get free disk space in bytes.
/// \param path  name of any directory on the disk to get information about

idaman THREAD_SAFE uint64 ida_export get_free_disk_space(const char *path);


//-------------------------------------------------------------------------
//      I / O   P O R T   D E F I N I T I O N S   F I L E
//-------------------------------------------------------------------------
/// Describes an I/O port bit
struct ioport_bit_t
{
  qstring name;         ///< name of the bit
  qstring cmt;          ///< comment
};
DECLARE_TYPE_AS_MOVABLE(ioport_bit_t);
typedef qvector<ioport_bit_t> ioport_bits_t;

/// Describes an I/O port
struct ioport_t
{
  ea_t address;         ///< address of the port
  qstring name;         ///< name of the port
  qstring cmt;          ///< comment
  ioport_bits_t bits;   ///< bit names
  void *userdata;       ///< arbitrary data. initialized to nullptr.

  ioport_t()
    : address(0), userdata(nullptr)
  {
  }
};
DECLARE_TYPE_AS_MOVABLE(ioport_t);
typedef qvector<ioport_t> ioports_t;

/// Read i/o port definitions from a config file.
///
/// Each device definition in the input file begins with a line like this:
///
/// \v{.devicename}
///
/// After it go the port definitions in this format:
///
/// \v{portname          address}
///
/// The bit definitions (optional) are represented like this:
///
/// \v{portname.bitname  bitnumber}
///
/// Lines beginning with a space are ignored.
/// comment lines should be started with ';' character.
///
/// The default device is specified at the start of the file:
///
/// \v{.default device_name}
///
/// \note It is permissible to have a symbol mapped to several addresses
///       but all addresses must be unique.
/// \param[out] ports      output vector
/// \param device          contains device name to load. If default_device[0] == 0
///                        then the default device is determined by .default directive
///                        in the config file.
/// \param file            config file name
/// \param callback        callback to call when the input line can't be parsed normally.
///                          - line: input line to parse
///                          - returns error message. if nullptr, then the line is parsed ok.
/// \return -1 on error or size of vector

idaman THREAD_SAFE ssize_t ida_export read_ioports(
        ioports_t *ports,
        qstring *device,
        const char *file,
        const char *(idaapi *callback)(
          const ioports_t &ports,
          const char *line)=nullptr);


struct ioports_fallback_t
{
  // returns success or fills ERRBUF with an error message
  virtual bool handle(qstring *errbuf, const ioports_t &ports, const char *line) = 0;
};

idaman THREAD_SAFE ssize_t ida_export read_ioports2(
        ioports_t *ports,
        qstring *device,
        const char *file,
        ioports_fallback_t *callback=nullptr);


/// Allow the user to choose the ioport device.
/// \param[in,out] _device in: contains default device name. If default_device[0] == 0
///                        then the default device is determined by .default directive
///                        in the config file.
///                        out: the selected device name
/// \param file            config file name
/// \param parse_params    if present (non nullptr), then defines a callback which
///                        will be called for all lines not starting with a dot (.)
///                        This callback may parse these lines are prepare a simple
///                        processor parameter string. This string will be displayed
///                        along with the device name.
///                        If it returns #IOPORT_SKIP_DEVICE, then the current
///                        device will not be included in the list.
/// \retval true   the user selected a device, its name is in 'device'
/// \retval false  the selection was cancelled. if device=="NONE" upon return,
///                then no devices were found in the configuration file

idaman THREAD_SAFE bool ida_export choose_ioport_device(
        qstring *_device,
        const char *file,
        const char *(idaapi *parse_params)(
          qstring *buf,
          const char *line)=nullptr);

struct choose_ioport_parser_t
{
  /// \retval true and fill PARAM with a displayed string
  /// \retval false and empty PARAM to skip the current device
  /// \retval false and fill PARAM with an error message
  virtual bool parse(qstring *param, const char *line) = 0;
};

idaman THREAD_SAFE bool ida_export choose_ioport_device2(
        qstring *_device,
        const char *file,
        choose_ioport_parser_t *parse_params);

/// See 'parse_params' parameter to choose_ioport_device()
#define IOPORT_SKIP_DEVICE ((const char *)(-1))


/// Find ioport in the array of ioports

idaman THREAD_SAFE const ioport_t *ida_export find_ioport(const ioports_t &ports, ea_t address);


/// Find ioport bit in the array of ioports

idaman THREAD_SAFE const ioport_bit_t *ida_export find_ioport_bit(const ioports_t &ports, ea_t address, size_t bit);


//-------------------------------------------------------------------------
//      S Y S T E M   S P E C I F I C   C A L L S
//-------------------------------------------------------------------------

/// Execute a operating system command.
/// This function suspends the interface (Tvision), runs the command
/// and redraws the screen.
/// \param command  command to execute. If nullptr, an interactive shell is activated
/// \return the error code returned by system() call

idaman THREAD_SAFE int ida_export call_system(const char *command);


//-------------------------------------------------------------------------
//       L O A D E R   I N P U T   S O U R C E   F U N C T I O N S
//-------------------------------------------------------------------------

/// \name Loader Input Source
/// Starting with v4.8 IDA can load and run remote files.
/// In order to do that, we replace the FILE* in the loader modules
/// with an abstract input source (linput_t). The source might be linked to
/// a local or remote file.
//@{

class linput_t;         ///< loader input source


/// linput types
enum linput_type_t
{
  LINPUT_NONE,          ///< invalid linput
  LINPUT_LOCAL,         ///< local file
  LINPUT_RFILE,         ///< remote file (\dbg{open_file}, \dbg{read_file})
  LINPUT_PROCMEM,       ///< debugged process memory (read_dbg_memory())
  LINPUT_GENERIC        ///< generic linput
};


/// Read the input source.
/// If failed, inform the user and ask him if he wants to continue.
/// If he does not, this function will not return (loader_failure() will be called).
/// This function may be called only from loaders!

idaman void ida_export lread(linput_t *li, void *buf, size_t size);


/// Read the input source.
/// \return number of read bytes or -1

idaman ssize_t ida_export qlread(linput_t *li, void *buf, size_t size);


/// Read one line from the input source.
/// \return nullptr if failure, otherwise 's'

idaman char *ida_export qlgets(char *s, size_t len, linput_t *li);


/// Read one character from the input source.
/// \return EOF if failure, otherwise the read character

idaman int ida_export qlgetc(linput_t *li);


/// Read multiple bytes and swap if necessary.
/// \param li    input file
/// \param buf   pointer to output buffer
/// \param size  number of bytes to read
/// \param mf    big endian?
/// \retval 0    ok
/// \retval -1   failure

idaman int ida_export lreadbytes(linput_t *li, void *buf, size_t size, bool mf);

/// Helper to define lread2bytes(), lread4bytes(), etc
#define DEF_LREADBYTES(read, type, size)                       \
/*! \brief Read a value from linput - also see lreadbytes() */ \
inline int idaapi read(linput_t *li, type *res, bool mf)       \
               { return lreadbytes(li, res, size, mf); }
DEF_LREADBYTES(lread2bytes, int16, 2)
DEF_LREADBYTES(lread2bytes, uint16, 2)
DEF_LREADBYTES(lread4bytes, int32, 4)
DEF_LREADBYTES(lread4bytes, uint32, 4)
DEF_LREADBYTES(lread8bytes, int64, 8)
DEF_LREADBYTES(lread8bytes, uint64, 8)
#undef DEF_LREADBYTES


/// Read a zero-terminated string from the input.
/// If fpos == -1 then no seek will be performed.

idaman char *ida_export qlgetz(
        linput_t *li,
        int64 fpos,
        char *buf,
        size_t bufsize);


/// Get the input source size

idaman int64 ida_export qlsize(linput_t *li);


/// Set input source position.
/// \return the new position (not 0 as fseek!)

idaman qoff64_t ida_export qlseek(linput_t *li, qoff64_t pos, int whence=SEEK_SET);


/// Get input source position

inline qoff64_t idaapi qltell(linput_t *li) { return qlseek(li, 0, SEEK_CUR); }


/// Open loader input

idaman linput_t *ida_export open_linput(const char *file, bool remote);


/// Close loader input

idaman THREAD_SAFE void ida_export close_linput(linput_t *li);


/// Get FILE* from the input source.
/// If the input source is linked to a remote file, then return nullptr.
/// Otherwise return the underlying FILE*
/// Please do not use this function if possible.

idaman THREAD_SAFE FILE *ida_export qlfile(linput_t *li);


/// Convert FILE * to input source.
/// Used for temporary linput_t objects - call unmake_linput() to free
/// the slot after the use.

idaman THREAD_SAFE linput_t *ida_export make_linput(FILE *fp);

/// Free an linput_t object (also see make_linput())

idaman THREAD_SAFE void ida_export unmake_linput(linput_t *li);


/// Generic linput class - may be used to create a linput_t instance for
/// any data source
struct generic_linput_t
{
  /// \name Warning
  /// The following two fields must be filled before calling create_generic_linput()
  //@{
  uint64 filesize;      ///< input file size
  uint32 blocksize;     ///< preferred block size to work with
                        ///< read/write sizes will be in multiples of this number.
                        ///< for example, 4096 is a nice value
                        ///< blocksize 0 means that the filesize is unknown.
                        ///< the internal cache will be disabled in this case.
                        ///< also, seeks from the file end will fail.
                        ///< blocksize=-1 means error.
  //@}
  virtual ssize_t idaapi read(qoff64_t off, void *buffer, size_t nbytes) = 0;
  virtual ~generic_linput_t() {}
};

/// Create a generic linput
/// \param gl  linput description.
///            this object will be destroyed by close_linput()
///            using "delete gl;"

idaman THREAD_SAFE linput_t *ida_export create_generic_linput(generic_linput_t *gl);

/// Trivial memory linput

idaman THREAD_SAFE linput_t *ida_export create_bytearray_linput(const uchar *start, size_t size);


/// Create a linput for process memory.
/// This linput will use read_dbg_memory() to read data.
/// \param start  starting address of the input
/// \param size   size of the memory area to represent as linput
///               if unknown, may be passed as 0

idaman linput_t *ida_export create_memory_linput(ea_t start, asize_t size);

/// Get linput type

inline THREAD_SAFE linput_type_t idaapi get_linput_type(linput_t *li)
{
  return li != nullptr ? *(linput_type_t *)li : LINPUT_NONE;
}

/// Object that will free an linput_t at destruction-time
typedef janitor_t<linput_t*> linput_janitor_t;
/// Free the linput_t
template <> inline linput_janitor_t::~janitor_t()
{
  close_linput(resource);
}

//---------------------------------------------------------------------------
/// Helper class - adapts linput to be used in extract_... functions
/// as a data supplier (see kernwin.hpp)
class linput_buffer_t
{
public:
  linput_buffer_t(linput_t *linput, int64 size=0): li(linput), lsize(size) {}
  ssize_t read(void *buf, size_t n)
  {
    return qlread(li, buf, n);
  }
  bool eof()
  {
    if ( lsize == 0 )
      lsize = qlsize(li);
    return qltell(li) >= lsize;
  }
protected:
  linput_t *li;
private:
  int64 lsize;
};

//@}

// -------------------------------------------------------------------------

#ifndef NO_OBSOLETE_FUNCS
idaman DEPRECATED THREAD_SAFE FILE *ida_export ecreate(const char *file);
idaman DEPRECATED THREAD_SAFE void ida_export eclose(FILE *fp);
idaman DEPRECATED THREAD_SAFE void ida_export eread(FILE *fp, void *buf, size_t size);
idaman DEPRECATED THREAD_SAFE void ida_export ewrite(FILE *fp, const void *buf, size_t size);
idaman DEPRECATED THREAD_SAFE void ida_export eseek(FILE *fp, qoff64_t pos);
idaman DEPRECATED THREAD_SAFE int ida_export enumerate_files(
        char *answer,
        size_t answer_size,
        const char *path,
        const char *fname,
        int (idaapi*func)(const char *file,void *ud),
        void *ud=nullptr);
#endif
#endif // _DISKIO_HPP
