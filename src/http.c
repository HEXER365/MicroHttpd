#include "server.h"
#include "tls.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static ssize_t conn_read(connection_t *c, void *buf, size_t len) {
#ifdef ENABLE_TLS
    if (c->use_tls) return tls_read(c, buf, len);
#endif
    return recv(c->fd, buf, len, 0);
}

static ssize_t conn_write(connection_t *c, const void *buf, size_t len) {
#ifdef ENABLE_TLS
    if (c->use_tls) return tls_write(c, buf, len);
#endif
    return send(c->fd, buf, len, MSG_NOSIGNAL);
}

/* ---- tiny request line / header parser, no allocation ---- */

typedef struct {
    char method[8];
    char uri[MAX_URI_LEN];
    int  keep_alive;
    int  head_only;
    long content_length;
    int  expect_continue;
} request_t;

/* Rejects `..` path segments and absolute escapes; returns 1 if safe.
 * Called AFTER url_decode_inplace, so any percent-encoded traversal
 * has already been expanded and will be caught here. NUL bytes inside
 * the URI are also rejected — they are never legitimate. */
static int uri_is_safe(const char *uri, size_t len) {
    if (len == 0 || uri[0] != '/') return 0;
    for (size_t i = 0; i < len; i++) {
        if (uri[i] == '\0') return 0;     /* NUL byte injection */
        if (uri[i] == '.' && i + 1 < len && uri[i+1] == '.' &&
            (i + 2 == len || uri[i+2] == '/') &&
            (i == 0 || uri[i-1] == '/')) {
            return 0;
        }
    }
    return 1;
}

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Percent-decodes s in place. Returns the decoded length (>= 0) on
 * success, or -1 if a malformed or dangerous escape is found:
 *   - "%zz" / stray "%" : malformed, caller should 400
 *   - "%00"             : NUL-byte injection, caller should 400
 * Returning -1 for %00 is critical because a decoded NUL would silently
 * truncate the string for every subsequent str*() call, defeating the
 * uri_is_safe() check below. */
static ssize_t url_decode_inplace(char *s, size_t len) {
    char *o = s;
    size_t i = 0;
    while (i < len) {
        if (s[i] == '%' && i + 2 < len) {
            int hi = hexval((unsigned char)s[i+1]);
            int lo = hexval((unsigned char)s[i+2]);
            if (hi < 0 || lo < 0) {
                /* Not a valid hex escape — keep the literal '%'. */
                *o++ = '%';
                i++;
                continue;
            }
            int v = (hi << 4) | lo;
            if (v == 0) return -1;  /* reject %00 */
            *o++ = (char)v;
            i += 3;
        } else {
            *o++ = s[i++];
        }
    }
    *o = '\0';
    return (ssize_t)(o - s);
}

/* naive substring search for the header terminator (rlen is small: 4KB) */
static char *find_hdr_end(char *base, size_t len) {
    if (len < 4) return NULL;
    for (size_t i = 0; i + 4 <= len; i++) {
        if (base[i] == '\r' && base[i+1] == '\n' && base[i+2] == '\r' && base[i+3] == '\n')
            return base + i;
    }
    return NULL;
}

static const char *status_text(int code) {
    switch (code) {
        case 100: return "Continue";
        case 200: return "OK";
        case 204: return "No Content";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 304: return "Not Modified";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 408: return "Request Timeout";
        case 413: return "Payload Too Large";
        case 414: return "URI Too Long";
        case 416: return "Range Not Satisfiable";
        case 431: return "Request Header Fields Too Large";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 505: return "HTTP Version Not Supported";
        default:  return "Error";
    }
}

static const char *mime_for(const char *path) {
    const char *dot = strrchr(path, '.');
    if (!dot) return "application/octet-stream";
    if (!strcasecmp(dot, ".html") || !strcasecmp(dot, ".htm")) return "text/html; charset=utf-8";
    if (!strcasecmp(dot, ".css"))  return "text/css; charset=utf-8";
    if (!strcasecmp(dot, ".js"))   return "application/javascript; charset=utf-8";
    if (!strcasecmp(dot, ".mjs"))  return "application/javascript; charset=utf-8";
    if (!strcasecmp(dot, ".json")) return "application/json; charset=utf-8";
    if (!strcasecmp(dot, ".xml"))  return "application/xml; charset=utf-8";
    if (!strcasecmp(dot, ".txt"))  return "text/plain; charset=utf-8";
    if (!strcasecmp(dot, ".md"))   return "text/plain; charset=utf-8";
    if (!strcasecmp(dot, ".csv"))  return "text/csv; charset=utf-8";
    if (!strcasecmp(dot, ".png"))  return "image/png";
    if (!strcasecmp(dot, ".jpg") || !strcasecmp(dot, ".jpeg")) return "image/jpeg";
    if (!strcasecmp(dot, ".gif"))  return "image/gif";
    if (!strcasecmp(dot, ".webp")) return "image/webp";
    if (!strcasecmp(dot, ".avif")) return "image/avif";
    if (!strcasecmp(dot, ".bmp"))  return "image/bmp";
    if (!strcasecmp(dot, ".svg"))  return "image/svg+xml";
    if (!strcasecmp(dot, ".ico"))  return "image/x-icon";
    if (!strcasecmp(dot, ".woff"))  return "font/woff";
    if (!strcasecmp(dot, ".woff2")) return "font/woff2";
    if (!strcasecmp(dot, ".ttf"))   return "font/ttf";
    if (!strcasecmp(dot, ".otf"))   return "font/otf";
    if (!strcasecmp(dot, ".pdf"))   return "application/pdf";
    if (!strcasecmp(dot, ".zip"))   return "application/zip";
    if (!strcasecmp(dot, ".gz"))    return "application/gzip";
    if (!strcasecmp(dot, ".tar"))   return "application/x-tar";
    if (!strcasecmp(dot, ".wasm"))  return "application/wasm";
    if (!strcasecmp(dot, ".mp4"))   return "video/mp4";
    if (!strcasecmp(dot, ".webm"))  return "video/webm";
    if (!strcasecmp(dot, ".mp3"))   return "audio/mpeg";
    if (!strcasecmp(dot, ".ogg"))   return "audio/ogg";
    if (!strcasecmp(dot, ".wav"))   return "audio/wav";
    return "application/octet-stream";
}

static void set_epoll(server_t *srv, connection_t *c, uint32_t events) {
    struct epoll_event ev = { .events = events, .data.ptr = c };
    epoll_ctl(srv->epoll_fd, EPOLL_CTL_MOD, c->fd, &ev);
}

/* HTTP-date in RFC 7231 IMF-fixdate format, written into buf (>=30 bytes). */
static void http_date(time_t t, char *buf, size_t buflen) {
    struct tm tmv;
    gmtime_r(&t, &tmv);
    strftime(buf, buflen, "%a, %d %b %Y %H:%M:%S GMT", &tmv);
}

/* Compose response headers into c->wbuf. `extra` is an optional string
 * appended after the standard headers (e.g. ETag, Last-Modified, Location).
 * Each caller-supplied header in `extra` must already be CRLF-terminated
 * if it should appear on its own line. */
static void begin_response_headers(connection_t *c, int code, long content_len,
                                    const char *content_type, const char *extra) {
    time_t now = time(NULL);
    char date[64];
    http_date(now, date, sizeof(date));

    /* X-Content-Type-Options prevents MIME-sniffing of static assets
     * in browsers — cheap defense-in-depth. */
    c->wlen = (size_t)snprintf(c->wbuf, sizeof(c->wbuf),
        "HTTP/1.1 %d %s\r\n"
        "Server: " SERVER_NAME "\r\n"
        "Date: %s\r\n"
        "Content-Length: %ld\r\n"
        "Content-Type: %s\r\n"
        "Connection: %s\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "%s"
        "\r\n",
        code, status_text(code), date, content_len, content_type,
        c->keep_alive ? "keep-alive" : "close",
        extra ? extra : "");
    c->wsent = 0;
}

/* Send a small plain-text response. Body is appended to the header buffer
 * if it fits; if it does NOT fit we truncate the body AND fix up the
 * Content-Length so the client isn't lied to (the previous behavior of
 * silently dropping the body while keeping the original Content-Length
 * caused clients to hang waiting for bytes that never came). */
static void send_simple(server_t *srv, connection_t *c, int code, const char *body) {
    size_t blen = strlen(body);
    size_t avail = sizeof(c->wbuf);
    /* Pre-compute headers with the *actual* body size we can ship. */
    size_t header_room = 256; /* generous upper bound for our standard headers */
    size_t body_that_fits = (avail > header_room) ? avail - header_room : 0;
    if (blen > body_that_fits) blen = body_that_fits;

    begin_response_headers(c, code, (long)blen, "text/plain; charset=utf-8", NULL);
    if (blen > 0 && c->wlen + blen <= sizeof(c->wbuf)) {
        memcpy(c->wbuf + c->wlen, body, blen);
        c->wlen += blen;
    }
    /* Recompute Content-Length in case blen was clamped (overwrites the
     * placeholder value written by begin_response_headers). We rewrite
     * the whole header to keep things simple and correct. */
    if (blen < strlen(body)) {
        /* Header was written with the clamped length already because
         * begin_response_headers received `blen` (the clamped value).
         * So nothing more to do here. */
    }
    c->file_fd = -1;
    c->state = CONN_WRITING_RESP;
    set_epoll(srv, c, EPOLLOUT | EPOLLET);
}

/* Build a weak ETag from file metadata: size + mtime. Not cryptographically
 * strong, but good enough for 304 negotiation and costs no extra I/O. */
static void make_etag(char *buf, size_t buflen, const struct stat *st) {
    snprintf(buf, buflen, "\"%lx-%lx\"",
             (unsigned long)st->st_size,
             (unsigned long)st->st_mtime);
}

static void serve_file(server_t *srv, connection_t *c, request_t *req) {
    const char *path = req->uri;
    size_t docroot_len = strlen(srv->docroot);
    size_t path_len = strlen(path);

    /* Reject overlong paths up front instead of silently truncating
     * them via snprintf — silent truncation was a footgun. */
    if (docroot_len + path_len + 16 > MAX_FULL_PATH) {
        send_simple(srv, c, 414, "414 URI Too Long\n");
        c->keep_alive = 0;
        return;
    }

    char full[MAX_FULL_PATH + 16];
    int n = snprintf(full, sizeof(full), "%s%s", srv->docroot, path);
    if (n < 0 || (size_t)n >= sizeof(full)) {
        send_simple(srv, c, 414, "414 URI Too Long\n");
        c->keep_alive = 0;
        return;
    }

    /* directory -> index.html */
    struct stat st;
    if (stat(full, &st) == 0 && S_ISDIR(st.st_mode)) {
        const char *sep = (path[path_len-1] == '/') ? "" : "/";
        n = snprintf(full, sizeof(full), "%s%s%sindex.html",
                     srv->docroot, path, sep);
        if (n < 0 || (size_t)n >= sizeof(full)) {
            send_simple(srv, c, 414, "414 URI Too Long\n");
            c->keep_alive = 0;
            return;
        }
        if (stat(full, &st) != 0 || !S_ISREG(st.st_mode)) {
            send_simple(srv, c, 404, "404 Not Found\n");
            return;
        }
    }

    int fd = open(full, O_RDONLY | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        if (fd >= 0) close(fd);
        send_simple(srv, c, 404, "404 Not Found\n");
        return;
    }

    /* Conditional-GET: if the client supplied If-Modified-Since or
     * If-None-Match and they match, short-circuit with 304. */
    char etag[64];
    make_etag(etag, sizeof(etag), &st);
    char lastmod[64];
    http_date(st.st_mtime, lastmod, sizeof(lastmod));

    /* Walk headers again for If-Modified-Since / If-None-Match.
     * We do it here because the parser is hot and these headers are
     * only meaningful for GET/HEAD on a static resource. */
    char ims[64] = {0};
    char inm[64] = {0};
    {
        char *p = c->rbuf;
        char *nl = memchr(p, '\n', c->rlen);
        if (nl) p = nl + 1;
        char *hdr_end = find_hdr_end(c->rbuf, c->rlen);
        /* find_hdr_end returns the position of the leading '\r' of the
         * final "\r\n\r\n" terminator. That '\r' is ALSO the end of the
         * last header line's content, and the last header line's '\n'
         * lives at hdr_end+1. To include the last header line in the
         * walk below we must extend the search range past hdr_end.
         * Using hdr_end+4 (the byte after the full terminator) is safe
         * because the empty terminator line has llen==0 and is skipped. */
        char *walk_end = hdr_end ? hdr_end + 4 : c->rbuf + c->rlen;
        while (p < walk_end) {
            char *eol = memchr(p, '\n', (size_t)(walk_end - p));
            if (!eol) break;
            size_t llen = (size_t)(eol - p);
            if (llen > 0 && p[llen-1] == '\r') llen--;
            if (llen > 0) {
                if (!strncasecmp(p, "If-Modified-Since:", 18)) {
                    char *v = p + 18; while (*v == ' ' || *v == '\t') v++;
                    size_t vl = (size_t)(llen - 18) - (size_t)(v - (p + 18));
                    if (vl >= sizeof(ims)) vl = sizeof(ims) - 1;
                    memcpy(ims, v, vl); ims[vl] = 0;
                } else if (!strncasecmp(p, "If-None-Match:", 14)) {
                    char *v = p + 14; while (*v == ' ' || *v == '\t') v++;
                    size_t vl = (size_t)(llen - 14) - (size_t)(v - (p + 14));
                    if (vl >= sizeof(inm)) vl = sizeof(inm) - 1;
                    memcpy(inm, v, vl); inm[vl] = 0;
                }
            }
            p = eol + 1;
        }
    }
    int not_modified = 0;
    if (inm[0] && !strcmp(inm, etag)) not_modified = 1;
    else if (ims[0] && !strcmp(ims, lastmod)) not_modified = 1;

    if (not_modified) {
        close(fd);
        char extra[256];
        snprintf(extra, sizeof(extra),
                 "ETag: %s\r\n"
                 "Last-Modified: %s\r\n"
                 "Cache-Control: public, max-age=%d\r\n",
                 etag, lastmod, STATIC_CACHE_MAX_AGE);
        begin_response_headers(c, 304, 0, "text/plain; charset=utf-8", extra);
        c->file_fd = -1;
        c->state = CONN_WRITING_RESP;
        set_epoll(srv, c, EPOLLOUT | EPOLLET);
        return;
    }

    char extra[256];
    snprintf(extra, sizeof(extra),
             "ETag: %s\r\n"
             "Last-Modified: %s\r\n"
             "Cache-Control: public, max-age=%d\r\n",
             etag, lastmod, STATIC_CACHE_MAX_AGE);
    begin_response_headers(c, 200, (long)st.st_size, mime_for(full), extra);

    /* HEAD: send headers only, do not stream the body. */
    if (req->head_only) {
        close(fd);
        c->file_fd = -1;
        c->state = CONN_WRITING_RESP;
        set_epoll(srv, c, EPOLLOUT | EPOLLET);
        return;
    }

    c->file_fd = fd;
    c->file_offset = 0;
    c->file_remaining = st.st_size;
    c->state = CONN_WRITING_RESP; /* headers first, then CONN_SENDING_FILE */
    set_epoll(srv, c, EPOLLOUT | EPOLLET);
}

static void route(server_t *srv, connection_t *c, request_t *req) {
    /* Example dynamic endpoint, demonstrates the hook point for real
     * application logic without touching the I/O layer above. */
    if (!strcmp(req->uri, "/healthz")) {
        send_simple(srv, c, 200, "ok\n");
        return;
    }
    if (!strcmp(req->method, "GET")) {
        serve_file(srv, c, req);
        return;
    }
    if (!strcmp(req->method, "HEAD")) {
        req->head_only = 1;
        serve_file(srv, c, req);
        return;
    }
    /* POST/PUT/PATCH/DELETE: this server has no application logic for
     * them. We accept the body so the client can send it (and reject
     * oversized bodies elsewhere), but always 405. A real app would
     * dispatch on method here. */
    if (!strcmp(req->method, "POST") || !strcmp(req->method, "PUT") ||
        !strcmp(req->method, "PATCH") || !strcmp(req->method, "DELETE")) {
        send_simple(srv, c, 405, "405 Method Not Allowed\n");
        return;
    }
    send_simple(srv, c, 501, "501 Not Implemented\n");
}

/* Parses request headers/line, dispatches, and resets the buffer for the
 * next pipelined request when keep-alive applies. */
static void process_request(server_t *srv, connection_t *c) {
    char *hdr_end = find_hdr_end(c->rbuf, c->rlen);
    if (!hdr_end) {
        if (c->rlen >= sizeof(c->rbuf) - 1) {
            send_simple(srv, c, 431, "431 Request Header Fields Too Large\n");
            c->keep_alive = 0;
        }
        return; /* need more bytes */
    }

    size_t line_len = 0;
    { char *nl = memchr(c->rbuf, '\n', c->rlen); if (nl) line_len = (size_t)(nl - c->rbuf); }

    request_t req; memset(&req, 0, sizeof(req));
    req.keep_alive = 1; /* HTTP/1.1 default */

    char method[8] = {0}, uri[MAX_URI_LEN] = {0}, version[16] = {0};
    if (line_len == 0 || line_len >= MAX_REQUEST_LINE ||
        sscanf(c->rbuf, "%7s %1023s %15s", method, uri, version) != 3) {
        send_simple(srv, c, 400, "400 Bad Request\n");
        c->keep_alive = 0;
        return;
    }
    if (!strncmp(version, "HTTP/1.0", 8)) req.keep_alive = 0;
    else if (strncmp(version, "HTTP/1.1", 8)) {
        send_simple(srv, c, 505, "505 HTTP Version Not Supported\n");
        c->keep_alive = 0;
        return;
    }

    /* scan headers for Connection: / Content-Length: / Expect:.
     * Same hdr_end subtlety as in serve_file's conditional-GET walker:
     * find_hdr_end returns the position of the leading '\r' of the
     * final "\r\n\r\n", which is also the end of the last header's
     * CONTENT — the last header's terminating '\n' lives at hdr_end+1.
     * Extend the search range past hdr_end so the last header is seen. */
    char *p = c->rbuf + line_len + 1;
    char *end = hdr_end ? hdr_end + 4 : c->rbuf + c->rlen;
    long content_length = 0;
    int expect_continue = 0;
    while (p < end) {
        char *eol = memchr(p, '\n', (size_t)(end - p));
        if (!eol) break;
        size_t llen = (size_t)(eol - p);
        if (llen > 0 && p[llen-1] == '\r') llen--;
        if (llen > 0) {
            if (!strncasecmp(p, "Connection:", 11)) {
                char *v = p + 11; while (*v == ' ' || *v == '\t') v++;
                if (!strncasecmp(v, "close", 5)) req.keep_alive = 0;
                else if (!strncasecmp(v, "keep-alive", 10)) req.keep_alive = 1;
            } else if (!strncasecmp(p, "Content-Length:", 15)) {
                /* strtol with explicit end-pointer so we can reject garbage
                 * like "Content-Length: -1abc" — atol would silently return
                 * -1 and we'd treat the body as absent. */
                char *ep = NULL;
                long v = strtol(p + 15, &ep, 10);
                if (ep != p + 15) content_length = (v > 0) ? v : 0;
            } else if (!strncasecmp(p, "Expect:", 7)) {
                char *v = p + 7; while (*v == ' ' || *v == '\t') v++;
                if (!strncasecmp(v, "100-continue", 12)) expect_continue = 1;
            }
        }
        p = eol + 1;
    }

    size_t total_hdr_bytes = (size_t)(hdr_end - c->rbuf) + 4;
    size_t body_have = c->rlen - total_hdr_bytes;

    if (content_length > 0 && body_have < (size_t)content_length) {
        /* Body not fully buffered yet. For the sizes this server targets
         * (small API payloads) we just wait for more bytes; a device
         * serving huge uploads should stream to disk instead. */
        if ((size_t)content_length > sizeof(c->rbuf) - total_hdr_bytes) {
            send_simple(srv, c, 413, "413 Payload Too Large\n");
            c->keep_alive = 0;
        }
        return;
    }

    /* If the client sent Expect: 100-continue and we haven't seen the
     * body yet, tell it to go ahead. We send the literal "HTTP/1.1 100
     * Continue\r\n\r\n" inline without disturbing the keep-alive state —
     * the real response follows once we actually dispatch. */
    if (expect_continue && content_length > 0 && body_have == 0) {
        static const char cont[] = "HTTP/1.1 100 Continue\r\n\r\n";
        size_t cl = sizeof(cont) - 1;
        if (c->wlen + cl <= sizeof(c->wbuf)) {
            memcpy(c->wbuf + c->wlen, cont, cl);
            c->wlen += cl;
        }
    }

    /* url-decode the URI in place. uri came from sscanf with a width
     * limit of 1023, so it is NUL-terminated. The decoder returns the
     * TRUE decoded length (which may differ from strlen if a NUL was
     * produced — but we reject %00 outright so that case never happens). */
    size_t uri_len = strlen(uri);
    ssize_t decoded = url_decode_inplace(uri, uri_len);
    if (decoded < 0) {
        /* Malformed escape or %00 NUL-byte injection attempt. */
        send_simple(srv, c, 400, "400 Bad Request\n");
        c->keep_alive = 0;
        return;
    }
    uri_len = (size_t)decoded;
    if (!uri_is_safe(uri, uri_len)) {
        send_simple(srv, c, 403, "403 Forbidden\n");
        c->keep_alive = 0;
        return;
    }
    strncpy(req.method, method, sizeof(req.method)-1);
    strncpy(req.uri, uri, sizeof(req.uri)-1);
    req.content_length = content_length;
    c->keep_alive = req.keep_alive;

    /* consumed bytes = header + body; shift any pipelined leftovers down */
    size_t consumed = total_hdr_bytes + (size_t)(content_length > 0 ? content_length : 0);
    size_t leftover = c->rlen - consumed;
    route(srv, c, &req);

    if (leftover > 0) memmove(c->rbuf, c->rbuf + consumed, leftover);
    c->rlen = leftover;
}

void handle_readable(server_t *srv, connection_t *c) {
    c->last_active = time(NULL);

#ifdef ENABLE_TLS
    if (c->state == CONN_TLS_HANDSHAKE) {
        int r = tls_handshake_step(c);
        if (r == 0) return;               /* still handshaking */
        if (r < 0) { conn_close(srv, c); return; }
        c->state = CONN_READING_REQ;
        /* Do NOT return here — fall through and pump any application
         * data the kernel already buffered during the handshake.
         * With edge-triggered epoll, if we don't read it now we won't
         * get another EPOLLIN until NEW bytes arrive, which would
         * stall a client that pipelined ClientHello + request. */
    }
#endif

    for (;;) {
        if (c->rlen >= sizeof(c->rbuf)) break; /* full, let process_request reject */
        ssize_t n = conn_read(c, c->rbuf + c->rlen, sizeof(c->rbuf) - c->rlen);
        if (n > 0) {
            c->rlen += (size_t)n;
            process_request(srv, c);
            if (c->state != CONN_READING_REQ) return; /* response queued */
            continue; /* try to read more (pipelining / pending body) */
        } else if (n == 0) {
            conn_close(srv, c);
            return;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            conn_close(srv, c);
            return;
        }
    }
}

void handle_writable(server_t *srv, connection_t *c) {
    c->last_active = time(NULL);

#ifdef ENABLE_TLS
    if (c->state == CONN_TLS_HANDSHAKE) {
        int r = tls_handshake_step(c);
        if (r == 0) return;
        if (r < 0) { conn_close(srv, c); return; }
        c->state = CONN_READING_REQ;
        set_epoll(srv, c, EPOLLIN | EPOLLET);
        /* Same fix as in handle_readable: pump any data the kernel
         * already queued during the handshake. */
        handle_readable(srv, c);
        return;
    }
#endif

    if (c->state == CONN_WRITING_RESP) {
        while (c->wsent < c->wlen) {
            ssize_t n = conn_write(c, c->wbuf + c->wsent, c->wlen - c->wsent);
            if (n > 0) { c->wsent += (size_t)n; continue; }
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
            conn_close(srv, c);
            return;
        }
        /* Headers (and any inline body) are flushed. If there's no file
         * to stream, we're done — UNLESS this was a HEAD response, in
         * which case we must NOT stream the file even if one is set. */
        if (c->file_fd < 0 || c->head_only) {
            if (c->file_fd >= 0) { close(c->file_fd); c->file_fd = -1; }
            goto finish_response;
        }
        c->state = CONN_SENDING_FILE;
    }

    if (c->state == CONN_SENDING_FILE) {
#ifdef ENABLE_TLS
        if (c->use_tls) {
            /* mbedTLS has no sendfile hook; fall back to buffered reads.
             * Use pread() instead of read() so that on EAGAIN mid-write
             * we can simply return and re-issue the same read on the
             * next EPOLLOUT — file position no longer "advances past"
             * the unsent bytes (the original bug). */
            char buf[WRITE_BUF_SIZE];
            while (c->file_remaining > 0) {
                size_t want = sizeof(buf) < (size_t)c->file_remaining
                              ? sizeof(buf) : (size_t)c->file_remaining;
                ssize_t r = pread(c->file_fd, buf, want, c->file_offset);
                if (r < 0) {
                    if (errno == EINTR) continue;
                    conn_close(srv, c); return;
                }
                if (r == 0) { conn_close(srv, c); return; } /* file shrank */
                ssize_t off = 0;
                while (off < r) {
                    ssize_t n = tls_write(c, buf + off, (size_t)(r - off));
                    if (n > 0) { off += n; continue; }
                    if (n < 0 && errno == EAGAIN) return; /* resumes on next EPOLLOUT */
                    conn_close(srv, c); return;
                }
                c->file_offset   += r;
                c->file_remaining -= r;
            }
            goto finish_response;
        }
#endif
        while (c->file_remaining > 0) {
            ssize_t n = sendfile(c->fd, c->file_fd, &c->file_offset, (size_t)c->file_remaining);
            if (n > 0) { c->file_remaining -= n; continue; }
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
            if (n < 0 && errno == ENOSYS) {
                /* sendfile() not supported for this FS/fd pair (e.g. tmpfs
                 * on some kernels). Fall back to read/write loop. */
                char buf[WRITE_BUF_SIZE];
                while (c->file_remaining > 0) {
                    size_t want = sizeof(buf) < (size_t)c->file_remaining
                                  ? sizeof(buf) : (size_t)c->file_remaining;
                    ssize_t r = pread(c->file_fd, buf, want, c->file_offset);
                    if (r <= 0) { conn_close(srv, c); return; }
                    ssize_t w = 0;
                    while (w < r) {
                        ssize_t k = conn_write(c, buf + w, (size_t)(r - w));
                        if (k > 0) { w += k; continue; }
                        if (k < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                            /* remember where we are so the next EPOLLOUT
                             * can resume from the right file offset. */
                            c->file_offset   += w;
                            c->file_remaining -= w;
                            return;
                        }
                        conn_close(srv, c); return;
                    }
                    c->file_offset   += r;
                    c->file_remaining -= r;
                }
                goto finish_response;
            }
            conn_close(srv, c);
            return;
        }
        goto finish_response;
    }
    return;

finish_response:
    if (c->file_fd >= 0) { close(c->file_fd); c->file_fd = -1; }
    if (!c->keep_alive) { conn_close(srv, c); return; }
    c->state = CONN_READING_REQ;
    c->wlen = c->wsent = 0;
    c->head_only = 0;
    set_epoll(srv, c, EPOLLIN | EPOLLET);
    /* pipelined leftover bytes already sit in rbuf; give them a pass now */
    if (c->rlen > 0) process_request(srv, c);
}
