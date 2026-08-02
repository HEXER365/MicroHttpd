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
#define MAX_URI_LEN        1024
#define MAX_HEADER_LINE    512
#define MAX_REQUEST_LINE    2048   /* method + uri + version           */

/* Idle keep-alive timeout (seconds). Swept lazily, no per-conn timer. */
#define KEEPALIVE_TIMEOUT   15
#define REQUEST_TIMEOUT     10     /* time allowed to finish a request */

/* Graceful shutdown: stop accepting new conns and wait this many
 * seconds for in-flight requests to drain before forcing them closed. */
#define SHUTDOWN_GRACE_SEC  5

/* epoll_wait timeout used to drive the idle-connection sweep, in ms. */
#define EVENT_LOOP_TICK_MS  1000

#define MAX_EVENTS          64
#define LISTEN_BACKLOG       128

/* Max docroot + URI path length we will ever try to open(). Anything
 * longer is rejected with 414 (was previously silently truncated by
 * snprintf, which was a footgun). Must fit comfortably below the
 * 2048-byte path buffer in serve_file(). */
#define MAX_FULL_PATH       2000

/* Default RLIMIT_AS ceiling in MiB. Override at runtime with -R.
 * Picked to give plenty of headroom over the fixed-size pool while
 * still preventing a runaway bug from eating a low-RAM device. */
#ifndef RLIMIT_AS_MB
#define RLIMIT_AS_MB 64
#endif

/* When non-zero, static file responses get a Cache-Control: max-age=N
 * header. Set to 0 at build time to disable. */
#ifndef STATIC_CACHE_MAX_AGE
#define STATIC_CACHE_MAX_AGE 3600
#endif

#define SERVER_NAME "microhttpd/1.0"
#define SERVER_SOURCE_ROOT "."

#endif /* CONFIG_H */
