#ifndef SERVER_H_
#define SERVER_H_
#include <stdint.h>
#include <uv.h>

#include "config.h"

typedef enum SOCKS5_STATE {
    S5_WAITING = 0x00,
    S5_REQ_RCVD,
    S5_REQ_RPLYD,
    S5_AUTH_RCVD,
    S5_AUTH_RPLYD,
    S5_CMD_RCVD,
    S5_CMD_RPLYD,
    S5_FORWARDING
} s5_state_t;

typedef enum SOCKS5_CMD {
    S5_CMD_CONN = 0x01,
    S5_CMD_BIND,
    S5_CMD_UDP_ASSOCIATE
} s5_cmd_t;

#define S5_ERROR_MAP(V)                                          \
    V(-1, S5_BAD_PROTO, "Bad protocol version.")                 \
    V(-2, S5_BAD_CMD, "Bad protocol command.")                   \
    V(-3, S5_BAD_ATYP, "Bad address type.")                      \
    V(-4, S5_INTERNAL_ERR, "Internal error.")                    \
    V(-5, S5_MEMOP_FAIL, "Memory alloc failed")                  \
    V(0, s5_result_need_more, "Need more data.")                 \
    V(1, s5_result_auth_select, "Select authentication method.") \
    V(2, s5_result_auth_verify, "Verify authentication.")        \
    V(3, s5_result_exec_cmd, "Execute command.")

#define S5_REP_MAP(V)                                              \
    V(0x00, S5_SUCCEED, "succeeded")                               \
    V(0x01, S5_FAILURE, "general socks server failure")            \
    V(0x02, S5_RULE_NALLOWED, "connection not allowed by ruleset") \
    V(0x03, S5_NET_UNREACHABLE, "Network unreachable")             \
    V(0x04, S5_HOST_UNREACHABLE, "Host unreachable")               \
    V(0x05, S5_CONN_REFUSED, "Connection refused")                 \
    V(0x06, S5_TTL_EXPIRED, "TTL expired")                         \
    V(0x07, S5_CMD_NSUPPORTED, "Command not supported")            \
    V(0x08, S5_ATYP_NSUPPORTED, "Address type not supported")

typedef enum SOCKS5_ERROR {
#define S5_ERROR_GEN(code, name, _) name = code,
    S5_ERROR_MAP(S5_ERROR_GEN)
#undef S5_ERROR_GEN
} s5_err_t;

typedef enum SOCKS5_REP {
#define S5_REP_GEN(code, name, _) name = code,
    S5_REP_MAP(S5_REP_GEN)
#undef S5_REP_GEN
} s5_rep_t;

typedef struct {
    uint8_t ulen;
    char uname[255];
    uint8_t plen;
    char password[255];
} s5_auth_info_t;

typedef enum SOCKS5_ATYP {
    ATYP_IP4 = 0x01,
    ATYP_IP6 = 0x04,
    ATYP_DOMAIN = 0x03
} s5_atyp_t;

typedef enum {
    AUTH_NONE = 0x00,
    AUTH_GSSAPI = 0x01,
    AUTH_PASSWROD = 0x02,
    AUTH_IANA_BEGIN = 0x03,
    AUTH_IANA_END = 0x7f,
    AUTH_RESERVED_BEGIN = 0x80,
    AUTH_RESERVED_END = 0xfe,
    AUTH_NACCEPT = 0xff
} s5_auth_t;

typedef struct {
    uint8_t valid;

    uv_tcp_t client;
    uv_tcp_t remote;

    uv_buf_t buffer;
    s5_auth_t method;
    s5_auth_info_t* auth_info;

    size_t pending_counter;
    uint8_t remote_ip[16]; // Network order
    uint8_t remote_ip_type;
    uint16_t remote_port; // Network order
} server_ctx;

static void on_connection(uv_stream_t* server, int status);
static void on_close(uv_handle_t* peer);

static void handshake_alloc(uv_handle_t* handle, size_t suggested_size,
                            uv_buf_t* buf);
static void handshake_close(uv_handle_t* handle);
static void handshake_read(uv_stream_t* handle, ssize_t nread,
                           const uv_buf_t* buf);

// handshake functions
static void do_handshake(uv_stream_t* stream, const uv_buf_t* buf);
static int handshake_domain_resolve(uv_stream_t* stream, char* domain_feild);
static int handshake_req_rcvd(uv_stream_t* stream, const uv_buf_t* buf);
static int handshake_cmd_rcvd(uv_stream_t* stream, const uv_buf_t* buf);
static int handshake_auth_rcvd(uv_stream_t* stream, const uv_buf_t* buf);

// write operation callback of handshake procedure
static void handshake_after_write(uv_write_t* req, int status);

static void handshake_domain_resolved(uv_getaddrinfo_t* resolver, int status,
                                      struct addrinfo* res);

static void handshake_connect_to_remote(uv_connect_t* req, int status);
static int do_connect_to_remote(uv_stream_t* stream);
//
static void established_alloc(uv_handle_t* handle, size_t suggested_size,
                              uv_buf_t* buf);
static void established_client_read(uv_stream_t* handle, ssize_t nread,
                                    const uv_buf_t* buf);
static void established_remote_read(uv_stream_t* stream, ssize_t nread,
                                    const uv_buf_t* buf);
static void established_after_write(uv_write_t* req, int status);
static void handshake_cmd_write(uv_stream_t* stream, uint8_t rep);
static void handshake_last_write(uv_write_t* req, int status);
static void try_close(uv_handle_t* handle);
static void _try_close_single(uv_handle_t* handle);
#endif