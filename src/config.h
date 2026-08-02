/* config.h — compile-time tuning knobs.
 *
 * Every limit below is a #define on purpose: the whole server is sized
 * at compile time so there is ZERO heap allocation once main() finishes
 * startup. That's what makes RAM usage predictable on embedded / low-RAM
 * boards (routers, Pi Zero, OpenWRT devices, etc).
 *
 * To shrink RAM further: lower MAX_CONNS and the buffer sizes.
 * To shrink the BINARY further: build with `make tiny` (see Makefile),
 * which drops TLS and link-time-optimizes + strips the result.
 */
#ifndef CONFIG_H
#define CONFIG_H

/* Max simultaneous connections. Each costs sizeof(connection_t) bytes,
 * printed by `make sizes`. 64 conns @ default buffers ≈ 64 * ~9.2KB
 * = ~590KB worst case RAM for the connection pool — fine for a device
 * with 32-64MB RAM; drop to 16-32 for anything tighter. */
#ifndef MAX_CONNS
#define MAX_CONNS 64
#endif

/* Per-connection read/write buffer sizes. Kept small: most embedded
 * HTTP traffic (API calls, small static assets) fits comfortably.
 * Large file bodies never touch this buffer — they go via sendfile(). */
#ifndef READ_BUF_SIZE
#define READ_BUF_SIZE 4096
#endif
#ifndef WRITE_BUF_SIZE
#define WRITE_BUF_SIZE 4096
#endif

/* Hard caps to reject abusive clients before they cost us memory/CPU. */
#define MAX_HEADERS        32      /* headers per request              */
#define MAX_URI_LEN        1024
#define MAX_HEADER_LINE    512
#define MAX_REQUEST_LINE    2048   /* method + uri + version           */

/* Idle keep-alive timeout (seconds). Swept lazily, no per-conn timer. */
#define KEEPALIVE_TIMEOUT   15
#define REQUEST_TIMEOUT     10     /* time allowed to finish a request */

/* epoll_wait timeout used to drive the idle-connection sweep, in ms. */
#define EVENT_LOOP_TICK_MS  1000

#define MAX_EVENTS          64
#define LISTEN_BACKLOG       128

#define SERVER_NAME "microhttpd/1.0"

#endif /* CONFIG_H */
