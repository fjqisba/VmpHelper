#ifndef NETWORK_HPP
#define NETWORK_HPP

#include <pro.h>
#include <md5.h>

#ifdef __NT__
#  if !defined(AF_MAX)
#    include <ws2tcpip.h>
#  endif
#  define SYSTEM "Windows"
#  define socklen_t int
#  define SHUT_RD SD_RECEIVE
#  define SHUT_WR SD_SEND
#  define SHUT_RDWR SD_BOTH
#else   // not NT, i.e. UNIX
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#  define closesocket(s)           close(s)
#  define SOCKET size_t
#  define INVALID_SOCKET size_t(-1)
#  define SOCKET_ERROR   (-1)
#  if defined(__LINUX__)
#    if defined(__ARM__)
#      if defined(__ANDROID__)
#        define SYSTEM "Android"
#      else
#        define SYSTEM "ARM Linux"
#      endif
#    else
#      if defined(__ANDROID__)
#        define SYSTEM "Android x86"
#        define SYSTEM "Android x86"
#      else
#        define SYSTEM "Linux"
#      endif
#    endif
     // linux debugger cannot be multithreaded because it uses thread_db.
     // i doubt that this library is meant to be used with multiple
     // applications simultaneously.
#    define __SINGLE_THREADED_SERVER__
#  elif defined(__MAC__)
#    define SYSTEM "Mac OS X"
#  else
#    error "Unknown platform"
#  endif
#  include <sys/socket.h>
#  include <netinet/in.h>
#endif

#ifndef __X86__
#  define _SYSBITS " 64-bit"
#else
#  define _SYSBITS " 32-bit"
#endif

#ifdef TESTABLE_BUILD
#  ifdef __EA64__
#    define SYSBITS _SYSBITS " (sizeof ea=64)"
#  else
#    define SYSBITS _SYSBITS " (sizeof ea=32)"
#  endif
#else
#    define SYSBITS _SYSBITS
#endif

#ifdef __SINGLE_THREADED_SERVER__
#  define __SERVER_TYPE__ "ST"
#else
#  define __SERVER_TYPE__ "MT"
#endif

#define TIMEOUT         (1000/25)       // timeout for polling (ms)
#define TIMEOUT_INFINITY -1
#define RECV_HELLO_TIMEOUT   1000       // timeout for the first packet (ms)
#define RECV_TIMEOUT_PERIOD  10000      // timeout for recv (ms)

// bidirectional codes (client <-> server)
enum base_packet_id_t
{
  RPC_OK = 0,  // response: function call succeeded
  RPC_UNK,     // response: unknown function code
  RPC_MEM,     // response: no memory
  base_packet_id_last
};

#define RPC_OPEN      3 // server->client: i'm ready, the very first packet

#define RPC_EVENT     4 // server->client: debug event ready, followed by debug_event
#define RPC_EVOK      5 // client->server: event processed (in response to RPC_EVENT)
#define RPC_CANCELLED 6 // client->server: operation was cancelled by the user
// we need EVOK to handle the situation when the debug
// event was detected by the server during polling and
// was sent to the client using RPC_EVENT but client has not received it yet
// and requested GET_DEBUG_EVENT. In this case we should not
// call remote_get_debug_event() but instead force the client
// to use the event sent by RPC_EVENT.
// In other words, if the server has sent RPC_EVENT but has not
// received RPC_EVOK, it should fail all GET_DEBUG_EVENTS.

// client->server codes
#define RPC_INIT                      10
#define RPC_TERM                      11
#define RPC_GET_PROCESSES             12
#define RPC_START_PROCESS             13
#define RPC_EXIT_PROCESS              14
#define RPC_ATTACH_PROCESS            15
#define RPC_DETACH_PROCESS            16
#define RPC_GET_DEBUG_EVENT           17
#define RPC_PREPARE_TO_PAUSE_PROCESS  18
#define RPC_STOPPED_AT_DEBUG_EVENT    19
#define RPC_CONTINUE_AFTER_EVENT      20
#define RPC_TH_SUSPEND                21
#define RPC_TH_CONTINUE               22
#define RPC_SET_RESUME_MODE           23
#define RPC_GET_MEMORY_INFO           24
#define RPC_READ_MEMORY               25
#define RPC_WRITE_MEMORY              26
#define RPC_UPDATE_BPTS               27
#define RPC_UPDATE_LOWCNDS            28
#define RPC_EVAL_LOWCND               29
#define RPC_ISOK_BPT                  30
#define RPC_READ_REGS                 31
#define RPC_WRITE_REG                 32
#define RPC_GET_SREG_BASE             33
#define RPC_SET_EXCEPTION_INFO        34

#define RPC_OPEN_FILE                 35
#define RPC_CLOSE_FILE                36
#define RPC_READ_FILE                 37
#define RPC_WRITE_FILE                38
#define RPC_IOCTL                     39 // both client and the server may send this packet
#define RPC_UPDATE_CALL_STACK         40
#define RPC_APPCALL                   41
#define RPC_CLEANUP_APPCALL           42
#define RPC_REXEC                     43
#define RPC_GET_SCATTERED_IMAGE       44
#define RPC_GET_IMAGE_UUID            45
#define RPC_GET_SEGM_START            46
#define RPC_BIN_SEARCH                47

// server->client codes
#define RPC_SET_DEBUG_NAMES           50
#define RPC_SYNC_STUB                 51
#define RPC_ERROR                     52
#define RPC_MSG                       53
#define RPC_WARNING                   54
#define RPC_HANDLE_DEBUG_EVENT        55
#define RPC_REPORT_IDC_ERROR          56
#define RPC_IMPORT_DLL                57

#pragma pack(push, 1)

struct PACKED rpc_packet_t
{                        // fields are always sent in the network order
  uint32 length;         // length of the packet (do not count length & code)
  uchar code;            // function code
};
CASSERT(sizeof(rpc_packet_t) == 5);
#pragma pack(pop)

enum rpc_notification_type_t
{
  rnt_unknown = 0,
  rnt_msg,
  rnt_warning,
  rnt_error,
};

#define DEFINE_ONE_NOTIFICATION_FUNCTION(FuncName, NotifCode, RpcEngineInst) \
  AS_PRINTF(2, 3) void FuncName(const char *format, ...)                \
  {                                                                     \
    va_list va;                                                         \
    va_start(va, format);                                               \
    dvnotif(NotifCode, RpcEngineInst, format, va);                      \
    va_end(va);                                                         \
  }

#define DEFINE_ALL_NOTIFICATION_FUNCTIONS(RpcEngineInst)        \
  DEFINE_ONE_NOTIFICATION_FUNCTION(dmsg,     0, RpcEngineInst)  \
  DEFINE_ONE_NOTIFICATION_FUNCTION(dwarning, 1, RpcEngineInst)  \
  DEFINE_ONE_NOTIFICATION_FUNCTION(derror,  -1, RpcEngineInst)

class rpc_engine_t;

//-------------------------------------------------------------------------
AS_PRINTF(2, 0) ssize_t dvnotif_client(
        int code,
        const char *format,
        va_list va);

#ifdef __NT__
#  define IRSERR_TIMEOUT WAIT_TIMEOUT
#else
#  define IRSERR_TIMEOUT ETIME
#endif
#define IRSERR_CANCELLED -0xE5CA7E // escape
#define IRSERR_SKIP_ITER -0x5217   // skip recv() in rpc_engine_t's recv_data loop

//-------------------------------------------------------------------------
//                           idarpc_stream_t
//-------------------------------------------------------------------------
// the idarpc_stream_t structure is not defined.
// it is used as an opaque type provided by the transport level.
// the transport level defines its own local type for it.
struct idarpc_stream_t;

idarpc_stream_t *irs_new(bool use_tls=false);

//-------------------------------------------------------------------------
struct host_port_t
{
  qstring host;
  ushort port = 0;

  host_port_t() {}
  host_port_t(const qstring &_host, ushort _port) : host(_host), port(_port) {}

  void clear() { host.clear(); port = 0; }
};
DECLARE_TYPE_AS_MOVABLE(host_port_t);

//-------------------------------------------------------------------------
struct endpoint_credentials_t : public host_port_t
{
  qstring username;
  // holds passwords provided through command-line parameters,
  // or environment variable. A password retrieved from the
  // keychain is not stored here.
  qstring password_override;

  endpoint_credentials_t() {}
  endpoint_credentials_t(const qstring &_host, ushort _port)
    : host_port_t(_host, _port) {}

  void clear() { this->host_port_t::clear(); username.clear(); password_override.clear(); }

  // Accepts the following schemes:
  //  `hostname:port`
  //  `user@hostname:port`
  //  `user:pass@hostname:port`
#define PCF_MERGE 1
  static bool parse_connstr(
        endpoint_credentials_t *out,
        const qstring &s,
        uint32 flags=0)
  {
    if ( (flags & PCF_MERGE) == 0 )
      out->clear();
    if ( s.empty() )
      return false;
    qstrvec_t parts;
    s.split(&parts, "@");
    if ( parts.size() > 2 )
      return false;
    if ( parts.size() == 2 )
    {
      const qstring &p0 = parts[0];
      if ( p0.empty() )
        return false;
      qstrvec_t identity_parts;
      p0.split(&identity_parts, ":");
      if ( identity_parts.size() > 2 )
        return false;
      out->username.swap(identity_parts[0]);
      if ( identity_parts.size() == 2 )
        out->password_override.swap(identity_parts[1]);
      parts.erase(parts.begin());
    }
    size_t idx = parts[0].find(':');
    if ( idx == qstring::npos )
    {
      out->host.swap(parts[0]);
    }
    else
    {
      out->host = parts[0].substr(0, idx);
      out->port = atol(parts[0].substr(idx+1).c_str());
    }
    return true;
  }
  bool parse_connstr(
        const qstring &s,
        uint32 flags=0)
  {
    return parse_connstr(this, s, flags);
  }

#define BCF_INCLUDE_USER 1
#define BCF_INCLUDE_PASS 2
  void build_connstr(
        qstring *out,
        uint32 flags=0) const
  {
    if ( host.empty() || port == 0 )
      return;

    qstring buf;
    if ( (flags & BCF_INCLUDE_USER) != 0 && !username.empty() )
      buf.append(username);
    if ( (flags & BCF_INCLUDE_PASS) != 0 && !password_override.empty() )
    {
      if ( !buf.empty() )
        buf.append(':');
      buf.append(password_override);
    }
    if ( !buf.empty() )
      buf.append('@');
    buf.cat_sprnt("%s:%d", host.c_str(), port);
    out->swap(buf);
  }
  qstring build_connstr(uint32 flags=0) const
  {
    qstring tmp;
    build_connstr(&tmp, flags);
    return tmp;
  }
};
DECLARE_TYPE_AS_MOVABLE(endpoint_credentials_t);

//-------------------------------------------------------------------------
struct irs_client_opts_t
{
  size_t cb = sizeof(*this);
  endpoint_credentials_t server;
  endpoint_credentials_t proxy;

  irs_client_opts_t() {}
  irs_client_opts_t(const qstring &_host, int _port)
    : server(_host, _port) {}
};
DECLARE_TYPE_AS_MOVABLE(irs_client_opts_t);

//-------------------------------------------------------------------------
struct irs_server_opts_t
{
  size_t cb = sizeof(*this);
  host_port_t bind;
  qstring certchain_path;
  qstring privkey_path;

  irs_server_opts_t() {}
  irs_server_opts_t(const qstring &_host, int _port)
    : bind(_host, _port) {}
};
DECLARE_TYPE_AS_MOVABLE(irs_server_opts_t);

bool irs_init_client(idarpc_stream_t *irs, const irs_client_opts_t &options);
bool irs_init_server(idarpc_stream_t *irs, const irs_server_opts_t &options);
bool irs_accept(idarpc_stream_t *irs, idarpc_stream_t *listener);
bool irs_handshake(idarpc_stream_t *irs, int timeout_ms = -1);
int irs_ready(idarpc_stream_t *irs, int timeout_ms = -1);
ssize_t irs_recv(idarpc_stream_t *irs, void *buf, size_t n);
ssize_t irs_send(idarpc_stream_t *irs, const void *buf, size_t n);
void irs_term(idarpc_stream_t **pirs, int shutdown_flags = -1);
int irs_get_error(idarpc_stream_t *irs);
const char *irs_strerror(idarpc_stream_t *irs);
bool irs_peername(idarpc_stream_t *irs, qstring *out, bool lookupname = true);
bool irs_sockname(idarpc_stream_t *irs, qstring *out, bool lookupname = true);
bool irs_sockport(idarpc_stream_t *irs, int *out);
// convenience functions
ssize_t irs_send_data(idarpc_stream_t *irs, const void *buf, size_t n);
ssize_t irs_recv_data(
        idarpc_stream_t *irs,
        void *buf,
        size_t n,
        int timeout_ms = -1);
bool irs_recv_str(idarpc_stream_t *irs, qstring *out, int timeout_ms = -1);
bool irs_send_str(idarpc_stream_t *irs, const qstring &str);

enum progress_loop_ctrl_t
{
  plc_proceed,
  plc_skip_iter,
  plc_cancel,
};
typedef progress_loop_ctrl_t irs_progress_cb_t(bool receiving, size_t processed, size_t total, void *);
void irs_set_progress_cb(idarpc_stream_t *irs, int ms, irs_progress_cb_t cb, void *ud=nullptr);
struct irs_cancellable_op_t
{
  idarpc_stream_t *irs;
  irs_cancellable_op_t(idarpc_stream_t *_irs, bool receiving, size_t goal=0);
  ~irs_cancellable_op_t();
  void inc_progress(size_t progress);
};

//-------------------------------------------------------------------------
typedef qtime64_t utc_timestamp_t;
constexpr uint32 TIMESTAMP_UTC     = 0x01;
constexpr uint32 TIMESTAMP_ISO8601 = 0x02;
constexpr uint32 TIMESTAMP_WITH_MS = 0x04;

//-------------------------------------------------------------------------
idaman THREAD_SAFE bool ida_export parse_timestamp(
        utc_timestamp_t *out,
        const char *in,
        uint32 flags = 0);

//-------------------------------------------------------------------------
constexpr size_t TIMESTAMP_BUFSZ = 25;
idaman THREAD_SAFE bool ida_export format_timestamp(
        char *out,
        size_t out_size,
        utc_timestamp_t ts,
        uint32 flags = 0);

//-------------------------------------------------------------------------
typedef uint64 lofi_timestamp_t; // low-fidelity timestamp. Only encodes up to 1/10th seconds
//-------------------------------------------------------------------------
THREAD_SAFE inline lofi_timestamp_t to_lofi_timestamp(qtime64_t ts)
{
  const uint64 s = get_secs(ts);
  const uint64 us = get_usecs(ts);
  return s * 10 + us / (100 * 1000);
}

//-------------------------------------------------------------------------
THREAD_SAFE inline qtime64_t from_lofi_timestamp(lofi_timestamp_t lts)
{
  return make_qtime64(lts / 10, (lts % 10) * (100 * 1000));
}

//-------------------------------------------------------------------------
//               base_dispatcher_t + network_client_handler_t
//-------------------------------------------------------------------------
struct network_client_handler_t
{
  FILE *channels[16];
  idarpc_stream_t *irs;
  qstring peer_name;
  uint32 session_id;
  utc_timestamp_t session_start;
  bool verbose;

  void close_all_channels();
  void clear_channels();
  int find_free_channel() const;

  network_client_handler_t(idarpc_stream_t *_irs, bool _verbose);
  virtual ~network_client_handler_t();

  virtual bool handle() = 0; // true - delete this
  virtual void shutdown_gracefully(int signum) = 0;

  void term_irs();

  AS_PRINTF(2, 3) int lprintf(const char *format, ...) const
  {
    va_list va;
    va_start(va, format);
    int code = vlprintf(format, va);
    va_end(va);
    return code;
  }
  AS_PRINTF(2, 0) int vlprintf(const char *format, va_list va) const;

private:
  DECLARE_UNCOPYABLE(network_client_handler_t);
};

//-------------------------------------------------------------------------
struct client_handlers_list_t
{
  typedef std::map<network_client_handler_t *, qthread_t> storage_t;
  storage_t storage;

  virtual ~client_handlers_list_t() {}
  virtual void lock() {}
  virtual void unlock() {}
  virtual bool is_multi_threaded() const { return false; }
};

//-------------------------------------------------------------------------
struct mt_client_handlers_list_t : public client_handlers_list_t
{
  qmutex_t mutex;

  mt_client_handlers_list_t() { mutex = qmutex_create(); QASSERT(1540, mutex != nullptr); }
  virtual ~mt_client_handlers_list_t() { qmutex_free(mutex); }
  virtual void lock() override { qmutex_lock(mutex); }
  virtual void unlock() override { qmutex_unlock(mutex);  }
  virtual bool is_multi_threaded() const override { return true; }
};

//-------------------------------------------------------------------------
struct base_dispatcher_t
{
  qstring ipv4_address;
  qstring certchain;
  qstring privkey;
  idarpc_stream_t *irs = nullptr;
  client_handlers_list_t *clients_list = nullptr;
  utc_timestamp_t start_time = qtime64();
  ushort port_number = -1;
  bool use_tls = true;
  bool verbose = false;

  base_dispatcher_t(bool multi_threaded);
  virtual ~base_dispatcher_t();
  void dispatch();

  virtual void collect_cliopts(cliopts_t *out);

  //
  void install_signal_handlers();

  //
  virtual network_client_handler_t *new_client_handler(idarpc_stream_t *_irs) = 0;
  void delete_client_handler(network_client_handler_t *inst);

  virtual void shutdown_gracefully(int signum);

protected:
  void add_notls_cliopts(cliopts_t *out);

private:
  void handle_session(network_client_handler_t *handler);
  void add_to_clients_list(network_client_handler_t *handler, qthread_t t);
  DECLARE_UNCOPYABLE(base_dispatcher_t);
};

// [-
//-------------------------------------------------------------------------
//                   server_dispatcher_t
//-------------------------------------------------------------------------
struct server_cmdline_cfg_t
{
  qstring connection_string;
  qstring log_file_path;
  qstring license_file_path;
  qstring config_file_path;
};

struct product_entry_t;
typedef qvector<product_entry_t> prodvec_t;
struct license_info_t;

//-------------------------------------------------------------------------
struct license_file_visitor_t
{
  virtual void check_license_type(
        const license_info_t &sign,
        const prodvec_t &prods) = 0;
  virtual bool on_product_entry(const product_entry_t &p) = 0;
  virtual void fill_server_info(const product_entry_t & /*p*/, const qstring & /*name*/, const qstring & /*email*/, const qstring & /*macaddr*/) {}
  virtual int on_parse_error(int code) { return code; }
};

//-------------------------------------------------------------------------
struct server_dispatcher_t : public base_dispatcher_t
{
  typedef base_dispatcher_t inherited;

  qstring license_file_name;
  qstring badreqdir;   // directory holding a dump of requests that caused an INTERR or unexpected exceptions
  FILE *log_file = nullptr;
  bool should_recreate_schema = false;
  bool may_upgrade_schema = false;
  bool record_conversations_by_default = false;

  server_dispatcher_t(
        bool _multi_threaded,
        int default_port,
        const char *default_license_file_name);
  virtual ~server_dispatcher_t() {}
  void check_license_file(license_file_visitor_t &lv) const;
  int read_license_file(license_file_visitor_t &lv) const;
  void get_license_file_contents(bytevec_t *data) const;

  virtual void collect_cliopts(cliopts_t *out) override;
  void apply_config();
  void setup_logging_output();
};

NORETURN AS_PRINTF(2, 3) void lerror(int code, const char *format, ...);
// ]-

//-------------------------------------------------------------------------
//                   packing/unpacking utils
//-------------------------------------------------------------------------
bytevec_t prepare_rpc_packet(uchar code);
void finalize_packet(bytevec_t &pkt);

//-------------------------------------------------------------------------
//                           rpc_engine_t
//-------------------------------------------------------------------------
#define VERBOSE_ENABLED
#ifdef VERBOSE_ENABLED
#define verb(x)  do { if ( verbose ) msg x; } while(0)
#define verb_eng(engine, x) do { if ( (engine)->verbose ) msg x; } while(0)
#else
#define verb(x)  //msg x
#define verb_eng(engine, x)
#endif
#define verbev(x)  //msg x

//-------------------------------------------------------------------------
struct rpc_packet_data_t
{
  uchar code;

  rpc_packet_data_t(uchar _code) : code(_code) {}
  virtual ~rpc_packet_data_t() {}
  virtual void serialize(bytevec_t *out, int version) const = 0;
  virtual bool deserialize(const uchar **ptr, size_t len, int version) = 0;
};

//-------------------------------------------------------------------------
typedef int ioctl_handler_t(
        class rpc_engine_t *rpc,
        int fn,
        const void *buf,
        size_t size,
        void **poutbuf,
        ssize_t *poutsize);

//-------------------------------------------------------------------------
typedef rpc_packet_data_t *rpc_packet_instantiator_t(const uchar *ptr, size_t len, int version);

//-------------------------------------------------------------------------
struct rpc_packet_type_desc_t
{
  uchar code;
  const char *name;
  rpc_packet_instantiator_t *instantiate;
};
DECLARE_TYPE_AS_MOVABLE(rpc_packet_type_desc_t);
typedef qvector<rpc_packet_type_desc_t> rpc_packet_type_desc_vec_t;

//-------------------------------------------------------------------------
struct rpc_pkt_timeout_t
{
  uchar pkt_code;
  int recv_timeout;             // miliseconds
};

//---------------------------------------------------------------------------
class rpc_engine_t
{
public:
  bool network_error = false;
  qstring last_errstr;

  // pointer to the ioctl request handler, in case you
  // need to handle ioctl requests from the server.
  ioctl_handler_t *ioctl_handler = nullptr;

  // This array specifies non-standard timeouts for some RPC calls
  const rpc_pkt_timeout_t *pkt_timeouts = nullptr;
  size_t n_pkt_timeouts = 0;

  int recv_timeout;
  bool is_client;
  bool logged_in = false;

protected:
  void register_packet_type_descs(const rpc_packet_type_desc_t *ptypes, size_t cnt);
  const rpc_packet_type_desc_t *find_packet_type_desc(int code) const;
  const rpc_packet_type_desc_t *find_packet_type_desc(const char *name) const;
  int get_timeout_for_request(uchar pkt_code) const;

public:
  rpc_engine_t(
        bool _is_client,
        const rpc_pkt_timeout_t *_pkt_timeouts = nullptr,
        size_t _n_pkt_timeouts = 0);
  virtual ~rpc_engine_t() {}

  int handle_ioctl_packet(bytevec_t &pkt, const uchar *ptr, const uchar *end);

  // low-level: deal with bytes, and don't handle "conversations".
  int send_data(bytevec_t &data);
  rpc_packet_t *recv_packet(uchar pkt_code);

  virtual rpc_packet_t *send_request_and_receive_reply(uchar pkt_code, bytevec_t &pkt) = 0;

  virtual idarpc_stream_t *get_irs() const = 0;
  AS_PRINTF(3, 0) virtual ssize_t send_notif(int code, const char *format, va_list va);

  virtual bool get_broken_connection(void) { return false; }
  virtual void set_broken_connection(void) {}

  int send_ioctl(int fn, const void *buf, size_t size, void **poutbuf, ssize_t *poutsize);
  void set_ioctl_handler(ioctl_handler_t *h) { ioctl_handler = h; }
  void set_pkt_timeouts(const rpc_pkt_timeout_t *_pkt_timeouts, size_t _n_pkt_timeouts)
  {
    pkt_timeouts = _pkt_timeouts;
    n_pkt_timeouts = _n_pkt_timeouts;
  }

  DEFINE_ALL_NOTIFICATION_FUNCTIONS(this);

private:
  rpc_packet_type_desc_vec_t ptypes;

  int recv_data(void *out, size_t len, int timeout_ms);

  AS_PRINTF(3,0) static ssize_t dvnotif(int code, rpc_engine_t *rpc, const char *format, va_list va);
};

//-------------------------------------------------------------------------
class recording_rpc_engine_t : public rpc_engine_t
{
#ifdef TESTABLE_BUILD
  FILE *conv = nullptr;
#endif
  idarpc_stream_t *rpc_irs;
  bool our_irs; // should we terminate rpc_irs in the destructor?
  int protocol_version;

protected:
  bool start_recording();
  void stop_recording();
  bool is_recording() const;
  void record(
        const rpc_packet_data_t &data,
        const uchar *bytes,
        size_t len,
        bool as_input) const;
  void record_input(const rpc_packet_data_t &data, const rpc_packet_t *rp) const;
  void record_output(const rpc_packet_data_t &data, const bytevec_t &bytes) const;
  // must be implemented if an instance is meant to be able to record.
  virtual bool get_conversation_path(qstring * /*out*/) const newapi { INTERR(1581); }
  // formatter is mandatory
  virtual void format_packet_data(
        qstring *out,
        const struct rpc_packet_data_t &data,
        const char *line_prefix=nullptr) const newapi;
  bool reinit_irs(qstring *errbuf, bool use_tls, const char *server_host, int port);

public:
  recording_rpc_engine_t(
        const rpc_packet_type_desc_t *descs,
        size_t cnt,
        idarpc_stream_t *_irs,
        bool _our_irs,
        bool _is_client,
        const rpc_pkt_timeout_t *_pkt_timeouts = nullptr,
        size_t _n_pkt_timeouts = 0,
        int _protocol_version = 0)
    : rpc_engine_t(_is_client, _pkt_timeouts, _n_pkt_timeouts),
      rpc_irs(_irs), our_irs(_our_irs), protocol_version(_protocol_version)
  {
    register_packet_type_descs(descs, cnt);
  }
  virtual ~recording_rpc_engine_t();
  virtual rpc_packet_t *send_request_and_receive_reply(uchar pkt_code, bytevec_t &pkt) override;
  rpc_packet_data_t *packet_data_from_raw(const rpc_packet_t *rp) const;
  virtual idarpc_stream_t *get_irs() const override { return rpc_irs; }
  bool is_our_irs() const { return our_irs; }
  void cancel_irs();
  int get_protocol_version() const { return protocol_version; }
  void set_protocol_version(int _protocol_version)
  {
#ifdef TESTABLE_BUILD
    QASSERT(2757, _protocol_version <= protocol_version);
#endif
    protocol_version = _protocol_version;
  }
};

//-------------------------------------------------------------------------
// This class can automatically reconnect if the connections drops.
class generic_client_t
{
  typedef recording_rpc_engine_t *rpc_engine_creator_t(idarpc_stream_t *_irs);

protected:
  rpc_engine_creator_t *create_rpc_engine;
  recording_rpc_engine_t *rpc_engine = nullptr;
private:
  qstring wait_dialog_contents;
  const char *const server_name;
  bool started_receiving_response = false;
  bool was_user_cancelled = false;

  virtual void init(idarpc_stream_t *_irs);

public:
  generic_client_t(
        const char *_server_name,
        rpc_engine_creator_t *engine_creator,
        idarpc_stream_t *_irs)
    : create_rpc_engine(engine_creator),
      server_name(_server_name)
  {
    generic_client_t::init(_irs);
  }
  virtual ~generic_client_t();
protected:
  virtual bool try_reconnect(qstring *errbuf) = 0;
  virtual rpc_packet_data_t *create_failure_packet(const char *errmsg) = 0;
  virtual bool is_handshake_packet(const rpc_packet_data_t &) { return false; }
};

//-------------------------------------------------------------------------
void extract_error(qstring *out, const rpc_packet_data_t *response);
template <typename T>
T *cast_or_extract_error(rpc_packet_data_t *data, uchar wanted_ptype, qstring *errbuf)
{
  T *response = nullptr;
  if ( data != nullptr )
  {
    if ( data->code == wanted_ptype )
    {
      response = (T *) data;
    }
    else
    {
      extract_error(errbuf, data);
      delete data;
    }
  }
  else
  {
    *errbuf = "No response";
  }
  return response;
}

//-------------------------------------------------------------------------
AS_PRINTF(3, 0) ssize_t dvnotif_rpc(
        int code,
        rpc_engine_t *rpc,
        const char *format,
        va_list va);

//---------------------------------------------------------------------------
AS_PRINTF(1, 0) int vlprintf(const char *format, va_list va);
AS_PRINTF(1, 2) int lprintf(const char *format, ...);
ssize_t lwrite(const void *data, size_t size);
void set_lprintf_output(FILE *out);

//---------------------------------------------------------------------------
void format_hex_dump(
        qstrvec_t *out,
        const uchar *buf,
        size_t size,
        bool for_comments,
        size_t nhex_per_line=16);

#define REPEAT_THRESHOLD 100    // that many or more equal bytes will
                                // be printed using the REPEAT_BYTES_MARKER
#define REPEAT_BYTES_MARKER '#'

//-------------------------------------------------------------------------
struct login_credentials_t : public endpoint_credentials_t
{
  endpoint_credentials_t proxy;
#define LCS_NO_TLS 0x1
#define LCS_SEEN_PROXY_OPTION 0x2
#define LCS_RESERVED_BITS 8
  uint32 state = 0;

  login_credentials_t(const qstring &_host, ushort _port)
    : endpoint_credentials_t(_host, _port) {}
  virtual ~login_credentials_t() {}
  virtual bool process_switch(const char *) newapi;
  virtual void clear() newapi { this->endpoint_credentials_t::clear(); proxy.clear(); state = 0; }

  bool load_password(qstring *out, qstring *errbuf) const
  {
    if ( !password_override.empty() )
    {
      *out = password_override;
      return true;
    }
    return do_load_password(out, errbuf);
  }

  bool load_proxy_password(qstring *out, qstring *errbuf) const
  {
    if ( !proxy.password_override.empty() )
    {
      *out = proxy.password_override;
      return true;
    }
    return do_load_proxy_password(out, errbuf);
  }

  bool use_tls() const { return (state & LCS_NO_TLS) == 0; }
  void set_use_tls(bool use_tls) { setflag(state, LCS_NO_TLS, !use_tls); }
  bool has_seen_proxy_option() const { return (state & LCS_SEEN_PROXY_OPTION) != 0; }

protected:
  bool load_pass_from_keychain(qstring * /*out*/, qstring * /*errbuf*/, const char * /*app_name*/) const;
  virtual bool do_load_password(qstring * /*out*/, qstring * /*errbuf*/) const newapi { return false; }
  virtual bool do_load_proxy_password(qstring * /*out*/, qstring * /*errbuf*/) const newapi { return false; }
  virtual bool write() const newapi { return false; }
};

//-------------------------------------------------------------------------
#define VAULT_APP_NAME "hexvault"
#define VAULT_PROXY_APP_NAME VAULT_APP_NAME "_proxy"
#define DEFAULT_VAULT_HOST "hexvault"
#define DEFAULT_VAULT_PORT 65433

//-------------------------------------------------------------------------
struct credential_validator_t
{
  // during the call to `validate()`,
  // `login_credentials_t::password_override` will hold
  // the candidate new password to be used for validation.
  virtual bool validate(login_credentials_t &cred) = 0;
};

//-------------------------------------------------------------------------
struct vault_credentials_t : public login_credentials_t
{
  typedef login_credentials_t inherited;
  qstring sitename;
#define VCS_SEEN_SITE_OPTION (0x1 << LCS_RESERVED_BITS)
#define VCS_UPDATE_REG_INFO  (0x2 << LCS_RESERVED_BITS)
#define VCS_USE_PROXY        (0x4 << LCS_RESERVED_BITS)

  vault_credentials_t() : login_credentials_t(DEFAULT_VAULT_HOST, DEFAULT_VAULT_PORT) {}
  virtual ~vault_credentials_t() {}
  void init();
  virtual bool process_switch(const char *arg) override;
  virtual void clear() override
  {
    this->login_credentials_t::clear();
    sitename.clear();
  }
  virtual bool do_load_password(qstring *out, qstring *errbuf) const override;
  virtual bool do_load_proxy_password(qstring *out, qstring *errbuf) const override;
  virtual bool write() const override;
  enum ask_user_result_t
  {
    AUR_CANCELLED = 0, // user rejected the prompt
    AUR_VALID,         // the validator (if any) succeeded
    AUR_INVALID,       // the validator (if any) failed
  };
  ask_user_result_t ask_user(
        credential_validator_t *validator,
        uint32 flags=0);

  void update() const;  // set/del reg info depending on 'VCS_UPDATE_REG_INFO'
  void del() const;
  void reg_set_site(const char *site) const;

  bool load_site();
  void load_proxy_info();

  bool has_seen_site_option() const { return (state & VCS_SEEN_SITE_OPTION) != 0; }

  static bool reg_should_store_info();
  static void reg_set_store_info(bool store_pass);
  static bool reg_del_store_info();

private:
  void get_reg_key(qstring *out) const;
};

//-------------------------------------------------------------------------
#ifdef DEMO_OR_FREE
#  define PUBLIC_LUMINA_HOST "public-lumina.hex-rays.com"
#  define PUBLIC_DEC_HOST "public-lumina.hex-rays.com"
#  define PUBLIC_TLM_HOST "public-lumina.hex-rays.com"
#else
#  define PUBLIC_LUMINA_HOST "lumina.hex-rays.com"
#  define PUBLIC_DEC_HOST "lumina.hex-rays.com"
#  define PUBLIC_TLM_HOST "tlm.hex-rays.com"
#endif
#define PUBLIC_LUMINA_PORT 443
#define PUBLIC_DEC_PORT 443
#define PUBLIC_TLM_PORT 443

#define LUMINA_APP_NAME "lumina"
#if defined(DEMO_OR_FREE) || defined(NOTEAMS)
#  define DEFAULT_LUMINA_HOST PUBLIC_LUMINA_HOST
#  define DEFAULT_LUMINA_PORT PUBLIC_LUMINA_PORT
#else
#  define DEFAULT_LUMINA_HOST "lumina"
#  define DEFAULT_LUMINA_PORT 65432
#endif

//-------------------------------------------------------------------------
struct lumina_credentials_t : public login_credentials_t
{
  bool is_primary;

  lumina_credentials_t()
  : login_credentials_t("", 0)
  {}
  virtual ~lumina_credentials_t() {}

  void init(bool set_as_primary=true);

  virtual bool do_load_password(qstring *out, qstring *errbuf) const override;
  virtual bool write() const override;
};

//-------------------------------------------------------------------------
struct dec_credentials_t : public login_credentials_t
{
  dec_credentials_t() : login_credentials_t(PUBLIC_DEC_HOST, PUBLIC_DEC_PORT) {}
  virtual ~dec_credentials_t() {}
};

//-------------------------------------------------------------------------
struct tlm_credentials_t : public login_credentials_t
{
  tlm_credentials_t() : login_credentials_t(PUBLIC_TLM_HOST, PUBLIC_TLM_PORT) {}
  virtual ~tlm_credentials_t() {}

  void init();
};

//-------------------------------------------------------------------------
#define NOSIG -1
void call_exit_handlers(int signum);
void call_exit_handlers();
void install_signal_and_exit_handlers();

struct exit_handler_t
{
  virtual void handle(int signum) = 0;

  exit_handler_t();
  virtual ~exit_handler_t();
  exit_handler_t(const exit_handler_t &) = delete;
  exit_handler_t &operator=(const exit_handler_t &r) = delete;
};


struct kc_ctx_t;
kc_ctx_t *get_keychain_context();

void ensure_one_server(const char *name);

void ensure_not_accessible_by_world(const char *path); // not functional on windows

#endif // NETWORK_HPP
