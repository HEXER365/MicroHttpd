# microhttpd

A tiny, single-threaded, event-driven HTTP/1.1 server in C, built specifically
for **low-RAM / low-CPU devices** (routers, SBCs, OpenWRT boxes, containers
with tight memory limits). Optional HTTPS via mbedTLS.

Tested in this environment: plain build **23 KB**, TLS build **27 KB**,
zero heap allocation after startup, ~8.3 KB RAM per open connection.

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
- `sendfile()` zero-copy static file serving
- HTTP/1.1 keep-alive + request pipelining
- Optional HTTPS via mbedTLS (TLS 1.2+; small code + RAM footprint)
- Path-traversal protection (`..` segments rejected) and URL decoding
- Idle/slow-client timeouts, header/body size limits — abuse-resistant by
  default without extra config
- `RLIMIT_AS` self-cap so a bug can't run away with a device's RAM
- Config entirely via `#define`s in `config.h` — resize everything at
  compile time for your target device
- ~600 lines of C total, no dependencies beyond libc (+ mbedTLS if you want
  HTTPS)

## Build

```sh
make          # plain HTTP, default sizing (64 conns, 4KB buffers) -> ~23KB
make tls      # + HTTPS via mbedTLS                                -> ~27KB
make tiny     # plain HTTP, squeezed for very tight devices
              # (16 conns, 2KB buffers, -Os/-flto/--gc-sections/strip)
make debug    # ASan/UBSan build for development
make sizes    # print sizeof(connection_t)/sizeof(server_t) and binary size
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
```

Flags: `-p port` `-b bind-addr` `-d docroot` `-c cert.pem` `-k key.pem`

Generate a quick self-signed cert for testing:
```sh
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
```
(Use a CA-signed cert for anything public.)

## Tuning for your device

Everything sizing-related lives in `src/config.h`:

| Define            | Default | Effect                                    |
|--------------------|--------:|--------------------------------------------|
| `MAX_CONNS`        | 64      | connection pool size (RAM ≈ N × ~8.3 KB)  |
| `READ_BUF_SIZE`     | 4096    | per-conn request buffer                   |
| `WRITE_BUF_SIZE`    | 4096    | per-conn response-header buffer           |
| `KEEPALIVE_TIMEOUT` | 15s     | idle keep-alive timeout                   |
| `REQUEST_TIMEOUT`   | 10s     | max time to finish sending a request      |

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
src/server.c   epoll loop, accept, connection pool, idle sweep
src/http.c     request parsing, routing, static file serving
src/tls.c      mbedTLS wrapper (compiled only with -DENABLE_TLS)
src/main.c     CLI args, startup
www/           example docroot
```
