# microhttpd

A tiny, single-threaded, event-driven HTTP/1.1 server in C, built specifically
for **low-RAM / low-CPU devices** (routers, SBCs, OpenWRT boxes, containers
with tight memory limits). Optional HTTPS via mbedTLS.

Tested in this environment: plain build **24 KB**, TLS build **28 KB**,
zero heap allocation after startup, ~8.1 KB RAM per open connection.

## Design, in one paragraph

One thread. One `epoll` loop, edge-triggered. A fixed-size array of
`MAX_CONNS` connection slots allocated once at startup — no `malloc` in the
request path at all, so memory use is a flat, predictable ceiling instead of
"however much traffic shows up." Static files go out via `sendfile()`
(zero-copy, kernel does the work). Headers/small bodies go through small
fixed buffers (4 KB by default). Keep-alive and pipelining are supported.
TLS, when enabled, is mbedTLS rather than OpenSSL — a full TLS 1.2/1.3
session runs in a few KB of RAM instead of OpenSSL's much heavier per-session
footprint, which matters a lot below ~64 MB of system RAM.

## Features

- Epoll-based async I/O, edge-triggered, single thread — scales to hundreds
  of idle keep-alive connections without a thread-per-connection cost
- Fixed-size connection pool, **zero heap allocation** after startup
- `sendfile()` zero-copy static file serving (with `pread`/`write` fallback
  for filesystems that don't support `sendfile`)
- HTTP/1.1 keep-alive + request pipelining
- Optional HTTPS via mbedTLS (TLS 1.2+; small code + RAM footprint)
- Path-traversal protection (`..` segments rejected), URL decoding, and
  **NUL-byte injection rejection** (`%00` is refused with 400)
- Idle/slow-client timeouts, header/body size limits — abuse-resistant by
  default without extra config
- `RLIMIT_AS` self-cap (configurable via `-R`) so a bug can't run away with
  a device's RAM
- **Conditional GET** with `ETag` / `Last-Modified` / `If-Modified-Since` /
  `If-None-Match` (returns `304 Not Modified`)
- `Cache-Control: public, max-age=N` on static responses
- `X-Content-Type-Options: nosniff` on every response
- **Correct `HEAD` handling** — headers (incl. `Content-Length`) are sent
  but no body bytes are streamed
- `Expect: 100-continue` acknowledged before the client sends the body
- Proper `505 HTTP Version Not Supported` for unknown HTTP versions
- Graceful shutdown on SIGTERM/SIGINT — in-flight requests drain for up
  to `SHUTDOWN_GRACE_SEC` seconds before being force-closed
- Config entirely via `#define`s in `config.h` — resize everything at
  compile time for your target device
- ~750 lines of C total, no dependencies beyond libc (+ mbedTLS if you want
  HTTPS)

## Build

```sh
make          # plain HTTP, default sizing (64 conns, 4KB buffers) -> ~24KB
make tls      # + HTTPS via mbedTLS                                -> ~28KB
make tiny     # plain HTTP, squeezed for very tight devices
              # (16 conns, 2KB buffers, -Os/-flto/--gc-sections/strip)
make debug    # ASan/UBSan build for development
make sizes    # print sizeof(connection_t)/sizeof(server_t) and binary size
make test     # smoke-test: build, start, curl, verify HEAD/NUL/304/etc
```

`make tls` needs mbedTLS headers/libs:
- Debian/Ubuntu: `apt install libmbedtls-dev`
- OpenWRT: `opkg install libmbedtls`
- Cross-compiling: `make tls-static CC=your-cross-gcc` once static
  `libmbedtls/libmbedx509/libmbedcrypto` are on your sysroot.

## Run

```sh
./microhttpd -p 8080 -d ./www                       # plain HTTP
./microhttpd -p 8443 -d ./www -c cert.pem -k key.pem  # HTTPS (tls build)
./microhttpd -p 8080 -d ./www -R 32                   # cap RAM at 32 MiB
```

Flags: `-p port` `-b bind-addr` `-d docroot` `-R rlimit-mb`
`-c cert.pem` `-k key.pem` (TLS build only)

Generate a quick self-signed cert for testing:
```sh
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
```
(Use a CA-signed cert for anything public.)

## Tuning for your device

Everything sizing-related lives in `src/config.h`:

| Define            | Default | Effect                                    |
|--------------------|--------:|--------------------------------------------|
| `MAX_CONNS`        | 64      | connection pool size (RAM ≈ N × ~8.1 KB)  |
| `READ_BUF_SIZE`     | 4096    | per-conn request buffer                   |
| `WRITE_BUF_SIZE`    | 4096    | per-conn response-header buffer           |
| `KEEPALIVE_TIMEOUT` | 15s     | idle keep-alive timeout                   |
| `REQUEST_TIMEOUT`   | 10s     | max time to finish sending a request      |
| `SHUTDOWN_GRACE_SEC`| 5s      | drain window on SIGTERM                   |
| `STATIC_CACHE_MAX_AGE` | 3600 | `Cache-Control: max-age=N` for static     |
| `RLIMIT_AS_MB`      | 64      | default RLIMIT_AS ceiling (override w/ -R)|

Override any of them at build time, e.g. for a 16 MB RAM device:

```sh
make CFLAGS_COMMON="-DMAX_CONNS=8 -DREAD_BUF_SIZE=1024 -DWRITE_BUF_SIZE=1024"
```

`make sizes` tells you exactly what a given config costs in RAM before you
deploy it.

## What it's not

This is a small embeddable static/API server, not a general-purpose web
server. It doesn't do CGI, virtual hosts, HTTP/2, or compression out of the
box. Adding an application handler is one function (`route()` in
`src/http.c`) — that's the intended extension point for dynamic responses.
For anything internet-facing at scale, put it behind a reverse proxy
(nginx/Caddy) for TLS termination, rate limiting, and HTTP/2 — this server
is built to be the fast, cheap thing sitting *behind* that, not to replace
it on the public edge of a high-traffic site.

## Files

```
src/config.h   size/timeout tuning knobs
src/server.h   shared structs (connection_t, server_t)
src/server.c   epoll loop, accept, connection pool, idle sweep, graceful shutdown
src/http.c     request parsing, routing, static file serving, conditional GET
src/tls.c      mbedTLS wrapper (compiled only with -DENABLE_TLS)
src/main.c     CLI args, startup, signal setup
www/           example docroot
```

## Security notes

- **NUL-byte injection**: `%00` in a URL is rejected with `400 Bad Request`.
  The previous behavior — silently truncating the path at the decoded NUL —
  allowed attacks like `/index.html%00.txt` to serve `index.html` to clients
  that expected a different file.
- **Path traversal**: both literal `..` segments and percent-encoded
  `%2e%2e` are rejected (the latter is decoded first, then caught by
  `uri_is_safe`).
- **Header parsing**: `Content-Length` is parsed with `strtol` + end-pointer
  validation; garbage like `Content-Length: -1abc` no longer silently
  becomes -1.
- **HTTP version**: requests with anything other than `HTTP/1.0` or
  `HTTP/1.1` are rejected with `505`.
- **Method allow-list**: `GET` / `HEAD` are served, `POST` / `PUT` /
  `PATCH` / `DELETE` return `405` (so the client knows it's not
  implemented rather than getting a 404 for the URI), and anything else
  returns `501`.

## Changelog (relative to upstream HEXER365/MicroHttpd)

### Bug fixes

- **NUL-byte injection** in `url_decode_inplace` — `%00` is now rejected
  with `400 Bad Request`. Previously, a decoded NUL silently truncated the
  URI for every subsequent `str*()` call, defeating the path-traversal
  check and allowing `/index.html%00.txt` to serve `index.html`.
- **HEAD sent the body** — `serve_file` always streamed the file via
  `sendfile()`, even for `HEAD`. Now `HEAD` returns headers (including
  `Content-Length`) and no body, per RFC 7231.
- **`send_simple` body overflow** — when the body didn't fit in `wbuf`,
  it was silently dropped while the `Content-Length` header still
  claimed the full size, causing clients to hang waiting for bytes that
  never came. Now the body is clamped and `Content-Length` reflects the
  actual bytes shipped.
- **TLS file-streaming data loss on `EAGAIN`** — when `tls_write`
  returned `EAGAIN` partway through a buffered read, the file position
  was advanced past the unsent bytes (because `read()` advances the FD
  offset internally), so the next `EPOLLOUT` re-read the NEXT chunk
  and the unsent bytes were lost. Switched to `pread()` + tracked
  `c->file_offset` so partial writes resume from the right place.
- **Path buffer truncation** in `serve_file` — `snprintf` into a 2048-byte
  stack buffer could silently truncate `docroot + uri` if either was
  very long, potentially opening the wrong file. Now overlong paths are
  rejected with `414 URI Too Long`.
- **Resource leak in `main.c`** — if `tls_server_init` failed, the
  listener and epoll FDs opened by `server_init` were never closed.
  Now `server_shutdown` is called before returning.
- **Async-signal-unsafe signal handler** — `on_signal` called
  `server_shutdown()` (which calls `close`, `epoll_ctl`, etc.) directly
  from the signal handler. Now it only flips a `volatile sig_atomic_t`
  flag, and the real shutdown happens in the main loop.
- **TLS handshake leftover data** — when the TLS handshake completed
  during an `EPOLLOUT`, the server switched to `EPOLLIN`-only and
  returned. With edge-triggered epoll, any application bytes the kernel
  had already buffered during the handshake were stranded until new
  bytes arrived. Now `handle_readable` is called explicitly after the
  handshake completes to drain any buffered data.
- **TLS `conn_init` partial-setup leak** — if `mbedtls_ssl_setup` failed
  after allocating internal buffers, those buffers were not freed.
  Now `mbedtls_ssl_free` is called on the failure path.
- **Header parsing missed the last header** — both the conditional-GET
  walker in `serve_file` and the request-header walker in
  `process_request` used `end = hdr_end`, where `hdr_end` points at the
  leading `\r` of the final `\r\n\r\n`. That `\r` is also the end of
  the last header line's CONTENT, so the last header's terminating `\n`
  was outside the search range and `memchr` returned NULL, breaking the
  loop early. This silently dropped `Connection: close`, `If-None-Match`,
  `If-Modified-Since`, and any other header that happened to be last.
  Fixed by extending the search range to `hdr_end + 4`.

### New features

- **Conditional GET** (`304 Not Modified`) via `ETag`, `Last-Modified`,
  `If-Modified-Since`, `If-None-Match`.
- **`Cache-Control: public, max-age=N`** on static responses
  (configurable via `STATIC_CACHE_MAX_AGE`).
- **`X-Content-Type-Options: nosniff`** on every response.
- **`Expect: 100-continue`** is acknowledged with `100 Continue` before
  the client sends the body.
- **Graceful shutdown** on SIGTERM/SIGINT — stops accepting new
  connections and drains in-flight requests for up to
  `SHUTDOWN_GRACE_SEC` seconds.
- **`-R rlimit-mb`** CLI flag to override `RLIMIT_AS` at runtime.
- **`make test`** target — smoke-tests GET/HEAD/404/NUL-injection/
  path-traversal/304/graceful-shutdown.
- **`-Werror`** in the default build.
- **Expanded MIME types** — added `.mjs`, `.xml`, `.md`, `.csv`, `.webp`,
  `.avif`, `.bmp`, `.woff`, `.ttf`, `.otf`, `.pdf`, `.zip`, `.gz`,
  `.tar`, `.wasm`, `.mp4`, `.webm`, `.mp3`, `.ogg`, `.wav`.
- **`sendfile` ENOSYS fallback** — on filesystems that don't support
  `sendfile` (some `tmpfs` configurations, FUSE filesystems, etc.),
  the server now falls back to a `pread`/`write` loop instead of
  closing the connection.
- **More HTTP status codes** recognized in `status_text()`:
  `100`, `302`, `401`, `414`, `416`, `501`, `505`.
- **HTTP version validation** — `HTTP/1.0` and `HTTP/1.1` are accepted;
  anything else gets `505 HTTP Version Not Supported`.
- **Method allow-list** — `GET`/`HEAD` are served, `POST`/`PUT`/`PATCH`/
  `DELETE` get `405`, anything else gets `501`.

### Cleanup

- Removed dead `MAX_HEADERS` define (was never referenced).
- Removed dead `rparsed` field from `connection_t` (was set but never
  read — saved 8 bytes per connection).
- Added `head_only` field to `connection_t` so `HEAD` can short-circuit
  the file-streaming state machine.
