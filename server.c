#include "server.h"

#include <assert.h>
#include <stdio.h>
#include <uv.h>

#include "config.h"
#include "utils.h"

uint8_t srv_auth_method[255] = {0};

int main() {
    int n;
    srv_auth_method[AUTH_NONE] = 1;
    // srv_auth_method[AUTH_PASSWROD] = 1;
    uv_loop_t* loop = uv_default_loop();
    uv_tcp_t listener;

    struct sockaddr addr;
    uv_ip4_addr("0.0.0.0", 1080, (struct sockaddr_in*)&addr);

    n = uv_tcp_init(loop, &listener);

    if (n < 0) SHOW_UV_ERROR_AND_EXIT(n);
    n = uv_tcp_bind(&listener, &addr, 0);
    if (n < 0) SHOW_UV_ERROR_AND_EXIT(n);
    n = uv_listen((uv_stream_t*)(void*)&listener, 5, on_connection);
    if (n < 0) SHOW_UV_ERROR_AND_EXIT(n);

    LOGI("Listening on %s:%d", SERVER_LISTEN, SERVER_PORT);
    return uv_run(loop, UV_RUN_DEFAULT);
}

static void on_connection(uv_stream_t* server, int status) {
    int n;
    if (status != 0) SHOW_UV_ERROR(n);
    ASSERT(status == 0);

    // using calloc to assure the memory is already cleared
    server_ctx* ctx = (server_ctx*)calloc(1, sizeof(server_ctx));
    if (!ctx) FATAL("malloc failed");
    ASSERT(ctx != NULL);

    ctx->client.data = ctx;
    ctx->remote.data = ctx;

    ctx->buffer.base = (char*)calloc(CTX_BUFFER_SIZE, sizeof(char));
    ctx->buffer.len = CTX_BUFFER_SIZE;
    if (!ctx->buffer.base) FATAL("malloc failed");
    ASSERT(ctx->buffer.base != NULL);

    n = uv_tcp_init(server->loop, &ctx->client);
    if (n < 0) SHOW_UV_ERROR_AND_EXIT(n);

    n = uv_accept(server, (uv_stream_t*)&ctx->client);
    if (n < 0) SHOW_UV_ERROR_AND_EXIT(n);

    n = uv_tcp_nodelay(&ctx->client, 1);
    if (n < 0) SHOW_UV_ERROR_AND_EXIT(n);

    n = uv_tcp_keepalive(&ctx->client, 1, 120);
    if (n < 0) SHOW_UV_ERROR_AND_EXIT(n);

    n = uv_read_start((uv_stream_t*)&ctx->client, handshake_alloc,
                      handshake_read);
    if (n < 0) SHOW_UV_ERROR_AND_EXIT(n);
    return;
}

static void on_close(uv_handle_t* peer) { free(peer); }

static void handshake_alloc(uv_handle_t* handle, size_t suggested_size,
                            uv_buf_t* buf) {
    buf->base = (char*)malloc(suggested_size);
    buf->len = suggested_size;
    if (!buf->base) {
        uv_close(handle, on_close);
        FATAL("malloc failed");
    }
    return;
}

static void handshake_read(uv_stream_t* handle, ssize_t nread,
                           const uv_buf_t* buf) {
    if (nread < 0) {
        LOGI("handshake EOF, closing");
        free(buf->base);
        uv_close((uv_handle_t*)handle, handshake_close);
        return;
    }
    if (nread == 0) {
        free(buf->base);
        return;
    }
    do_handshake(handle, buf);
}

static void do_handshake(uv_stream_t* stream, const uv_buf_t* buf) {
    server_ctx* ctx = (server_ctx*)stream->data;
    s5_err_t n;
    if (!ctx->valid) {
        n = handshake_req_rcvd(stream, buf);
    } else if (!ctx->auth_info && ctx->method != AUTH_NONE) {
        n = handshake_auth_rcvd(stream, buf);
    } else if (!ctx->remote_port) {
        uv_read_stop(stream);
        n = handshake_cmd_rcvd(stream, buf);
    }

    if (n < 0) {
        _try_close_single((uv_handle_t*)stream);
    }
    free(buf->base);
    return;
}

static int handshake_req_rcvd(uv_stream_t* stream, const uv_buf_t* buf) {
    server_ctx* ctx = (server_ctx*)stream->data;
    int n;
    char* ptr = buf->base;
    if (*ptr++ != 0x05) return S5_BAD_PROTO;
    uint8_t method = AUTH_NACCEPT;
    uint8_t nmethods = *ptr++;
    for (char* end = buf->base + 2 + nmethods; ptr != end; ptr++) {
        if (srv_auth_method[*ptr]) {
            method = *ptr;
            break;
        }
    }
    ctx->method = (s5_auth_t)method;
    uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t));
    if (!req) return S5_MEMOP_FAIL;
    ASSERT(req != NULL);
    char msg[2] = {0x05, method};
    memcpy(ctx->buffer.base, msg, 2);
    ctx->buffer.len = 2;
    ctx->valid = 0x01;
    n = uv_write(req, stream, &ctx->buffer, 1, handshake_after_write);
    if (n < 0) {
        SHOW_UV_ERROR(n);
        return S5_INTERNAL_ERR;
    }
    ASSERT(n == 0);
    return 0;
}

static int handshake_auth_rcvd(uv_stream_t* stream, const uv_buf_t* buf) {
    server_ctx* ctx = (server_ctx*)stream->data;
    int n;
    char* ptr = buf->base;
    if (ctx->method == AUTH_PASSWROD) {
        if (*ptr++ != 0x01) return S5_BAD_PROTO;
        uint8_t ulen = *ptr++;
        ctx->auth_info = (s5_auth_info_t*)malloc(sizeof(s5_auth_info_t));
        uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t));

        // TODO: may cause slight memory leakage here
        if (!ctx->auth_info || !req) return S5_MEMOP_FAIL;

        ctx->auth_info->ulen = ulen;
        memcpy(ctx->auth_info->uname, ptr, ulen);
        ctx->auth_info->uname[ulen] = '\0';
        ptr += ulen;
        uint8_t plen = *ptr++;
        memcpy(ctx->auth_info->password, ptr, plen);
        ctx->auth_info->password[plen] = '\0';
        char msg[2] = {0x01, 0x00};
        if (strcmp(ctx->auth_info->uname, USER_NAME) == 0 &&
            strcmp(ctx->auth_info->password, PASSWORD) == 0) {
            msg[1] = 0x00;
        } else {
            msg[1] = 0x01;
        }
        memcpy(ctx->buffer.base, msg, 2);
        ctx->buffer.len = 2;
        n = uv_write(req, stream, &ctx->buffer, 1, handshake_after_write);
        if (n < 0) {
            SHOW_UV_ERROR(n);
            return S5_INTERNAL_ERR;
        }
        ASSERT(n == 0);
    }
    return 0;
}

static void handshake_cmd_write(uv_stream_t* stream, uint8_t rep) {
    server_ctx* ctx = (server_ctx*)stream->data;
    char* msg = ctx->buffer.base;
    uv_write_t* wreq = (uv_write_t*)malloc(sizeof(uv_write_t));
    if(!wreq) {
        LOGE("malloc failed");
        try_close((uv_handle_t*)stream);
    }

    char head[4] = {0x05, rep, 0x00, ctx->remote_ip_type};
    memcpy(msg, head, 4);
    int addrlen = 0;
    if(ctx->remote_ip_type == ATYP_IP4) {
        memcpy(msg+4, ctx->remote_ip, 4);
        addrlen = 4;
    } else if(ctx->remote_ip_type == ATYP_IP6) {
        memcpy(msg+4, ctx->remote_ip, 16);
        addrlen = 16;
    }
    memcpy(msg+4+addrlen, &ctx->remote_port, 2);
    ctx->buffer.len = 6 + addrlen;
    int n = uv_write(wreq, stream, &ctx->buffer, 1, handshake_last_write);
    if(n < 0) {
        SHOW_UV_ERROR(n);
        _try_close_single((uv_handle_t*)stream);
    }
}

static int handshake_cmd_rcvd(uv_stream_t* stream, const uv_buf_t* buf) {
    server_ctx* ctx = (server_ctx*)stream->data;
    int n;
    // ver feild
    char* ptr = buf->base;
    if (*ptr++ != 0x05) {
        handshake_cmd_write(stream, 0x01);
        return S5_BAD_PROTO;
    }
    // cmd feild
    switch (*ptr++) {
        // only CONNECT command is supported in version 0.x,
        case S5_CMD_CONN:
            break;
        case S5_CMD_BIND:
            break;
        case S5_CMD_UDP_ASSOCIATE:
            break;
        default:
            LOGE("unkown cmd, closing");
            handshake_cmd_write(stream, 0x07);
            return S5_BAD_PROTO;
            break;
    }
    // rsv feild
    if (*ptr++ != 0) return S5_BAD_PROTO;
    // atyp feild
    uint8_t domain_len = 0;
    switch (*ptr++) {
        case ATYP_IP4:
            memcpy(ctx->remote_ip, ptr, 4);
            ctx->remote_ip_type = ATYP_IP4;
            ctx->valid = 0x02;
            ptr += 4;
            break;
        case ATYP_IP6:
            memcpy(ctx->remote_ip, ptr, 16);
            ctx->remote_ip_type = ATYP_IP6;
            ctx->valid = 0x02;
            ptr += 16;
            break;
        case ATYP_DOMAIN:
            domain_len = *ptr;
            // TODO: domain resolve is async, may cause problem
            n = handshake_domain_resolve(stream, ptr);
            if (n < 0) return n;
            ptr += (domain_len + 1);
            break;
        default:
            LOGE("addr type unknown, closing");
            handshake_cmd_write(stream, 0x07);
            return S5_BAD_PROTO;
            break;
    }
    ctx->remote_port = *((uint16_t*)ptr);
    return do_connect_to_remote(stream);
}

static int handshake_domain_resolve(uv_stream_t* stream, char* domain_feild) {
    int n;
    server_ctx* ctx = (server_ctx*)stream->data;
    uint8_t len = *domain_feild++;
    // char domain[256];

    uv_getaddrinfo_t* resolver =
        (uv_getaddrinfo_t*)malloc(sizeof(uv_getaddrinfo_t));
    if (!resolver) return S5_MEMOP_FAIL;
    resolver->data = ctx;
    // include '\0'
    memcpy(ctx->buffer.base + DOMAIN_BUFFER_BASE, domain_feild, len);
    (ctx->buffer.base+ DOMAIN_BUFFER_BASE)[len] = '\0';
    n = uv_getaddrinfo(stream->loop, resolver, handshake_domain_resolved,
                       ctx->buffer.base + DOMAIN_BUFFER_BASE, NULL, NULL);
    if (n < 0) {
        SHOW_UV_ERROR(n);
        free(resolver);
        handshake_cmd_write(stream, 0x04);
        return S5_INTERNAL_ERR;
    }
    ASSERT(n == 0);
    return 0;
}

static int do_connect_to_remote(uv_stream_t* stream) {
    server_ctx* ctx = (server_ctx*)stream->data;
    if (ctx->valid != 0x02) return 0;
    int n;
    n = uv_tcp_init(stream->loop, &ctx->remote);
    if (n < 0) {
        SHOW_UV_ERROR(n);
        handshake_cmd_write(stream, 0x01);
        return S5_INTERNAL_ERR;
    }
    uv_connect_t* conn = (uv_connect_t*)malloc(sizeof(uv_connect_t));
    if (!conn) {
        LOGE("malloc failed");
        handshake_cmd_write(stream, 0x01);
        return S5_MEMOP_FAIL;
    }
    conn->data = ctx;
    if (ctx->remote_ip_type == ATYP_IP4) {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = ctx->remote_port;
        memcpy(&addr.sin_addr.s_addr, ctx->remote_ip, 4);
        n = uv_tcp_connect(conn, &ctx->remote, &addr,
                           handshake_connect_to_remote);
    } else if (ctx->remote_ip_type == ATYP_IP6) {
        struct sockaddr_in6 addr6;
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = ctx->remote_port;
        memcpy(&addr6.sin6_addr.s6_addr, ctx->remote_ip, 16);
        n = uv_tcp_connect(conn, &ctx->remote, &addr6,
                           handshake_connect_to_remote);
    } else {
        FATAL("unkown addrtype");
    }
    if (n < 0) {
        SHOW_UV_ERROR(n);
        handshake_cmd_write(stream, 0x03);
        free(conn);
        return S5_INTERNAL_ERR;
    }
    return 0;
}

static void handshake_domain_resolved(uv_getaddrinfo_t* resolver, int status,
                                      struct addrinfo* res) {
    server_ctx* ctx = (server_ctx*)resolver->data;
    if (status < 0) {
        if (status == UV_ENOENT)
            LOGE("Resolve error, NXDOMAIN");
        else {
            LOGE("status code is %d", status);
            SHOW_UV_ERROR(status);
            DUMP_CTX(ctx);
        }
        handshake_cmd_write((uv_stream_t*)&ctx->client, 0x04);
        uv_freeaddrinfo(res);
        free(resolver);
        return;
    }

    if (res->ai_family == AF_INET) { // IPv4
        memcpy(ctx->remote_ip,
               &((struct sockaddr_in*)(res->ai_addr))->sin_addr.s_addr, 4);
        ctx->remote_ip_type = ATYP_IP4;
    } else if (res->ai_family == AF_INET6) {
        memcpy(ctx->remote_ip,
               &((struct sockaddr_in6*)(res->ai_addr))->sin6_addr.s6_addr, 16);
        ctx->remote_ip_type = ATYP_IP6;
    } else {
        FATAL("DNS resolve failed!");
    }
    ctx->valid = 0x02;
    uv_freeaddrinfo(res);
    free(resolver);
    int n = do_connect_to_remote((uv_stream_t*)&ctx->client);
    if (n < 0) {
        LOGE("connect to remote failed");
        try_close((uv_handle_t*)&ctx->client);
    }
    return;
}

static void handshake_connect_to_remote(uv_connect_t* req, int status) {
    server_ctx* ctx = (server_ctx*)req->data;
    int n;
    if (status < 0) {
        if (status != UV_ECANCELED) {
            SHOW_UV_ERROR(status);
            DUMP_CTX(ctx);
            try_close((uv_handle_t*)&ctx->remote);
            free(req);
        }
        if(status == UV_ECONNREFUSED) handshake_cmd_write((uv_stream_t*)&ctx->client, 0x05);
        else if(status == UV_ENETUNREACH) handshake_cmd_write((uv_stream_t*)&ctx->client, 0x03);
        return;
    }
    free(req);

    LOGCONN(&ctx->remote, "connected to %s:%u");

    int addrlen = ctx->remote_ip_type == ATYP_IP4 ? 4 : 16;

    char* ptr = ctx->buffer.base;
    uint8_t seg0[4] = {0x05, 0x00, 0x00, ctx->remote_ip_type};
    memcpy(ptr, seg0, 4);
    ptr += 4;
    memcpy(ptr, ctx->remote_ip, addrlen);
    ptr += addrlen;
    *((uint16_t*)ptr) = ctx->remote_port;

    uv_write_t* wreq = (uv_write_t*)malloc(sizeof(uv_write_t));
    if (!wreq) {
        LOGE("malloc failed");
        try_close((uv_handle_t*)&ctx->remote);
        ctx->buffer.base[1] = 0x01; // general socks failure
        handshake_cmd_write((uv_stream_t*)&ctx->client, 0x01);
        return;
    }

    ctx->buffer.len = addrlen + 6;
    n = uv_write(wreq, (uv_stream_t*)&ctx->client, &ctx->buffer, 1,
                 handshake_after_write);
    if (n < 0) {
        SHOW_UV_ERROR(n);
        free(wreq);
        uv_close((uv_handle_t*)&ctx->client, handshake_close);
        return;
    }

    n = uv_read_start((uv_stream_t*)&ctx->client, established_alloc,
                      established_client_read);
    if (n < 0) {
        SHOW_UV_ERROR(n);
        try_close((uv_handle_t*)&ctx->client);
        return;
    }
    ASSERT(n == 0);
    n = uv_read_start((uv_stream_t*)&ctx->remote, established_alloc,
                      established_remote_read);
    if (n < 0) {
        SHOW_UV_ERROR(n);
        try_close((uv_handle_t*)&ctx->remote);
        return;
    }
    ASSERT(n == 0);
    return;
}

static void handshake_last_write(uv_write_t* req, int status) {
    server_ctx* ctx = (server_ctx*)req->handle->data;
    if (status < 0) {
        SHOW_UV_ERROR(status);
        DUMP_CTX(ctx);
    }
    _try_close_single((uv_handle_t*)req->handle);
    free(req);
    return;    
}

static void handshake_after_write(uv_write_t* req, int status) {
    server_ctx* ctx = (server_ctx*)req->handle->data;
    if (status < 0) {
        SHOW_UV_ERROR(status);
        DUMP_CTX(ctx);
        _try_close_single((uv_handle_t*)req->handle);
    }
    ASSERT(status == 0);
    free(req);
    return;
}

static void handshake_close(uv_handle_t* handle) {
    server_ctx* ctx = (server_ctx*)handle->data;
    if (ctx->auth_info) free(ctx->auth_info);
    if (ctx->buffer.base) free(ctx->buffer.base);
    free(ctx);
    return;
}

static void established_alloc(uv_handle_t* handle, size_t suggested_size,
                              uv_buf_t* buf) {
    buf->base = (char*)malloc(suggested_size);
    buf->len = suggested_size;
    if (!buf->base) {
        uv_close(handle, on_close);
        FATAL("malloc failed");
    }
    return;
}

static void established_after_write(uv_write_t* req, int status) {
    server_ctx* ctx = (server_ctx*)req->handle->data;
    if (status < 0) {
        SHOW_UV_ERROR(status);
        DUMP_CTX(ctx);
        try_close((uv_handle_t*)req->handle);
    }

    if((uv_tcp_t*)req->handle == &ctx->client && !uv_is_closing((uv_handle_t*)&ctx->remote)) {
        if(ctx->pending_counter <= MAX_PENDING_PER_CONN && !uv_is_readable((uv_stream_t*)&ctx->remote)) {
            int n = uv_read_start((uv_stream_t*)&ctx->remote, established_alloc, established_remote_read);
            if(n < 0) {
                SHOW_UV_ERROR(n);
                try_close((uv_handle_t*)&ctx->remote);
                free(req->data);
                free(req);
                return;
            }
        }
        ctx->pending_counter--;
    }
    free(req->data);
    free(req);
    return;
}

static void established_client_read(uv_stream_t* stream, ssize_t nread,
                                    const uv_buf_t* buf) {
    int n;
    server_ctx* ctx = (server_ctx*)stream->data;
    if (nread < 0) {
        LOGCONN(stream, "client %s:%u EOF, closing");
        free(buf->base);
        try_close((uv_handle_t*)stream);
        return;
    }
    if (nread == 0) {
        free(buf->base);
        return;
    }
    uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t));
    if (!req) {
        LOGE("malloc failed");
        free(buf->base);
        try_close((uv_handle_t*)stream);
        return;
    }

    req->data = buf->base;
    uv_buf_t wr_buf = uv_buf_init(buf->base, nread);

    n = uv_write(req, (uv_stream_t*)&ctx->remote, &wr_buf, 1,
                 established_after_write);

    if (n < 0) {
        SHOW_UV_ERROR(n);
        LOGE("write to remote failed");
        free(buf->base);
        try_close((uv_handle_t*)&ctx->remote);
    }
    return;
}

static void established_remote_read(uv_stream_t* stream, ssize_t nread,
                                    const uv_buf_t* buf) {
    int n;
    server_ctx* ctx = (server_ctx*)stream->data;
    if (nread < 0) {
        LOGCONN(stream, "remote %s:%u EOF, closing");
        free(buf->base);
        try_close((uv_handle_t*)stream);
        return;
    }
    if (nread == 0) {
        free(buf->base);
        return;
    }
    uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t));
    if (!req) {
        LOGE("malloc failed");
        free(buf->base);
        try_close((uv_handle_t*)stream);
        return;
    }

    req->data = buf->base;
    uv_buf_t wr_buf = uv_buf_init(buf->base, nread);

    n = uv_write(req, (uv_stream_t*)&ctx->client, &wr_buf, 1,
                 established_after_write);

    if (n < 0) {
        SHOW_UV_ERROR(n);
        LOGE("write to client failed");
        free(buf->base);
        try_close((uv_handle_t*)&ctx->client);
    }
    if(ctx->pending_counter == MAX_PENDING_PER_CONN - 1) {
        uv_read_stop(stream);
    }
    ctx->pending_counter++;
    return;
}

static void try_close(uv_handle_t* handle) {
    server_ctx* ctx = handle->data;
    if(!uv_is_closing(handle)) {
        uv_close(handle, try_close);
        return;
    }
    uv_handle_t* handle2close = (uv_handle_t*)(handle == (uv_handle_t*)&ctx->client?&ctx->remote:&ctx->client);
    _try_close_single(handle2close);
    return;
}

static void _try_close_single(uv_handle_t* handle) {
    if(!uv_is_closing(handle)) {
        uv_close(handle, handshake_close);
    }
    return;
}