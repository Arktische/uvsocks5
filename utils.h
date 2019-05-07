#ifndef UTILS_H_
#define UTILS_H_
#include <assert.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <uv.h>
#define CONTAINER_OF(ptr, type, member)                    \
    ({                                                     \
        const typeof(((type *)0)->member) *__mptr = (ptr); \
        (type *)((char *)__mptr - offsetof(type, member)); \
    })
#define ASSERT(expr)                                                   \
    do {                                                               \
        if (!(expr)) {                                                 \
            fprintf(stderr, "Assertion failed in %s on line %d: %s\n", \
                    __FILE__, __LINE__, #expr);                        \
            abort();                                                   \
        }                                                              \
    } while (0)
#define STR(x) #x
#define TOSTR(x) STR(x)
#define LOGI(format, ...)                                              \
    do {                                                               \
        time_t now = time(NULL);                                       \
        char timestr[20];                                              \
        strftime(timestr, 20, TIME_FORMAT, localtime(&now));           \
        fprintf(stderr, "%s \e[01;32m INFO:  " format "\e[0m %s:%s\n", \
                timestr, ##__VA_ARGS__, __FILE__, TOSTR(__LINE__));    \
    } while (0)
#define LOGE(format, ...)                                              \
    do {                                                               \
        time_t now = time(NULL);                                       \
        char timestr[20];                                              \
        strftime(timestr, 20, TIME_FORMAT, localtime(&now));           \
        fprintf(stderr, "%s \e[01;35m ERROR: " format "\e[0m %s:%s\n", \
                timestr, ##__VA_ARGS__, __FILE__, TOSTR(__LINE__));    \
    } while (0)
#define FATAL(format, ...)                                             \
    do {                                                               \
        time_t now = time(NULL);                                       \
        char timestr[20];                                              \
        strftime(timestr, 20, TIME_FORMAT, localtime(&now));           \
        fprintf(stderr, "\e[01;31m %s FATAL: \e[0m" format " %s:%s\n", \
                timestr, ##__VA_ARGS__, __FILE__, TOSTR(__LINE__));    \
        exit(1);                                                       \
    } while (0)
#define SHOW_UV_ERROR(status)                         \
    do {                                              \
        LOGE("libuv error: %s", uv_strerror(status)); \
    } while (0)
#define SHOW_UV_ERROR_AND_EXIT(status)        \
    do {                                      \
        SHOW_UV_ERROR(status);                \
        LOGE("Fatal error, terminating... "); \
        exit(1);                              \
    } while (0)
#define LOGDBG(format, ...)                                             \
    do {                                                                \
        time_t now = time(NULL);                                        \
        char timestr[20];                                               \
        strftime(timestr, 20, TIME_FORMAT, localtime(&now));            \
        fprintf(stderr, "%s \e[01;33m DEBUG:  " format "\e[0m %s:%s\n", \
                timestr, ##__VA_ARGS__, __FILE__, TOSTR(__LINE__));     \
    } while (0)
#define LOGCONN(stream, message)                                             \
    do {                                                                     \
        struct sockaddr remote_addr;                                         \
        memset(&remote_addr, 0, sizeof(remote_addr));                        \
        int namelen = sizeof(remote_addr);                                   \
        if (uv_tcp_getpeername((uv_tcp_t *)stream,                           \
                               (struct sockaddr *)&remote_addr, &namelen))   \
            break;                                                           \
        char *ip_str = sockaddr_to_str(&remote_addr);                        \
        if (!ip_str) FATAL("unknown address type");                          \
        uint16_t port;                                                       \
                                                                             \
        if (remote_addr.sa_family == AF_INET) {                              \
            struct sockaddr_in *addr = (struct sockaddr_in *)&remote_addr;   \
            port = addr->sin_port;                                           \
        } else if (remote_addr.sa_family == AF_INET6) {                      \
            struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&remote_addr; \
            port = addr->sin6_port;                                          \
        }                                                                    \
        LOGI(message, ip_str, port);                                         \
        free(ip_str);                                                        \
    } while (0)
#define DUMP_CTX(ctx)                                                       \
    do {                                                                    \
        LOGDBG("------------CONTEXT INFORMATION START------------");        \
        LOGDBG("remote domain is %s", ctx->buffer.base + DOMAIN_BUFFER_BASE); \
        LOGCONN(&ctx->remote, "remote address is %s:%u");                   \
        LOGCONN(&ctx->client, "client address is %s:%u");                   \
        LOGDBG("------------CONTEXT INFORMATION END  ------------");        \
    } while (0)
char *sockaddr_to_str(struct sockaddr *addr);
#endif