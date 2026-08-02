#include "server.h"
#include "tls.h"

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
    long content_length;
} request_t;

/* Rejects `..` path segments and absolute escapes; returns 1 if safe. */
static int uri_is_safe(const char *uri) {
    if (uri[0] != '/') return 0;
    const char *p = uri;
    while (*p) {
        if (p[0] == '.' && p[1] == '.' &&
            (p[2] == '/' || p[2] == '\0') &&
            (p == uri || p[-1] == '/')) {
            return 0;
        }
        p++;
    }
    return 1;
}

static void url_decode_inplace(char *s) {
    char *o = s;
    while (*s) {
        if (*s == '%' && s[1] && s[2]) {
            int hi = s[1], lo = s[2];
            int v = -1;
            char buf[3] = { (char)hi, (char)lo, 0 };
            v = (int)strtol(buf, NULL, 16);
            if (v >= 0) { *o++ = (char)v; s += 3; continue; }
        }
        *o++ = *s++;
    }
    *o = 0;
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
        case 200: return "OK";
        case 204: return "No Content";
        case 301: return "Moved Permanently";
        case 304: return "Not Modified";
        case 400: return "Bad Request";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 408: return "Request Timeout";
        case 413: return "Payload Too Large";
        case 431: return "Request Header Fields Too Large";
        case 500: return "Internal Server Error";
        default:  return "Error";
    }
}

static const char *mime_for(const char *path) {
    const char *dot = strrchr(path, '.');
    if (!dot) return "application/octet-stream";
    if (!strcasecmp(dot, ".html") || !strcasecmp(dot, ".htm")) return "text/html; charset=utf-8";
    if (!strcasecmp(dot, ".css"))  return "text/css; charset=utf-8";
    if (!strcasecmp(dot, ".js"))   return "application/javascript; charset=utf-8";
    if (!strcasecmp(dot, ".json")) return "application/json; charset=utf-8";
    if (!strcasecmp(dot, ".png"))  return "image/png";
    if (!strcasecmp(dot, ".jpg") || !strcasecmp(dot, ".jpeg")) return "image/jpeg";
    if (!strcasecmp(dot, ".gif"))  return "image/gif";
    if (!strcasecmp(dot, ".svg"))  return "image/svg+xml";
    if (!strcasecmp(dot, ".txt"))  return "text/plain; charset=utf-8";
    if (!strcasecmp(dot, ".ico"))  return "image/x-icon";
    if (!strcasecmp(dot, ".woff2")) return "font/woff2";
    return "application/octet-stream";
}

static void set_epoll(server_t *srv, connection_t *c, uint32_t events) {
    struct epoll_event ev = { .events = events, .data.ptr = c };
    epoll_ctl(srv->epoll_fd, EPOLL_CTL_MOD, c->fd, &ev);
}

static void begin_response_headers(connection_t *c, int code, long content_len,
                                    const char *content_type, const char *extra) {
    time_t now = time(NULL);
    char date[64];
    struct tm tmv;
    gmtime_r(&now, &tmv);
    strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S GMT", &tmv);

    c->wlen = (size_t)snprintf(c->wbuf, sizeof(c->wbuf),
        "HTTP/1.1 %d %s\r\n"
        "Server: " SERVER_NAME "\r\n"
        "Date: %s\r\n"
        "Content-Length: %ld\r\n"
        "Content-Type: %s\r\n"
        "Connection: %s\r\n"
        "%s"
        "\r\n",
        code, status_text(code), date, content_len, content_type,
        c->keep_alive ? "keep-alive" : "close",
        extra ? extra : "");
    c->wsent = 0;
}

static void send_simple(server_t *srv, connection_t *c, int code, const char *body) {
    size_t blen = strlen(body);
    begin_response_headers(c, code, (long)blen, "text/plain; charset=utf-8", NULL);
    /* body appended after headers if it fits the write buffer */
    if (c->wlen + blen < sizeof(c->wbuf)) {
        memcpy(c->wbuf + c->wlen, body, blen);
        c->wlen += blen;
    }
    c->file_fd = -1;
    c->state = CONN_WRITING_RESP;
    set_epoll(srv, c, EPOLLOUT | EPOLLET);
}

static void serve_file(server_t *srv, connection_t *c, const char *path) {
    char full[2048];
    snprintf(full, sizeof(full), "%s%s", srv->docroot, path);

    /* directory -> index.html */
    struct stat st;
    if (stat(full, &st) == 0 && S_ISDIR(st.st_mode)) {
        snprintf(full, sizeof(full), "%s%s%sindex.html", srv->docroot, path,
                 (path[strlen(path)-1] == '/') ? "" : "/");
    }

    int fd = open(full, O_RDONLY | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        if (fd >= 0) close(fd);
        send_simple(srv, c, 404, "404 Not Found\n");
        return;
    }

    begin_response_headers(c, 200, (long)st.st_size, mime_for(full), NULL);
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
    if (!strcmp(req->method, "GET") || !strcmp(req->method, "HEAD")) {
        serve_file(srv, c, req->uri);
        return;
    }
    send_simple(srv, c, 405, "405 Method Not Allowed\n");
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

    /* scan headers for Connection: / Content-Length: */
    char *p = c->rbuf + line_len + 1;
    char *end = hdr_end;
    long content_length = 0;
    while (p < end) {
        char *eol = memchr(p, '\n', (size_t)(end - p));
        if (!eol) break;
        size_t llen = (size_t)(eol - p);
        if (llen > 0 && p[llen-1] == '\r') llen--;
        if (llen > 0) {
            if (!strncasecmp(p, "Connection:", 11)) {
                char *v = p + 11; while (*v == ' ') v++;
                if (!strncasecmp(v, "close", 5)) req.keep_alive = 0;
                else if (!strncasecmp(v, "keep-alive", 10)) req.keep_alive = 1;
            } else if (!strncasecmp(p, "Content-Length:", 15)) {
                content_length = atol(p + 15);
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

    strncpy(req.method, method, sizeof(req.method)-1);
    url_decode_inplace(uri);
    if (!uri_is_safe(uri)) {
        send_simple(srv, c, 403, "403 Forbidden\n");
        c->keep_alive = 0;
        return;
    }
    strncpy(req.uri, uri, sizeof(req.uri)-1);
    req.content_length = content_length;
    c->keep_alive = req.keep_alive;

    /* consumed bytes = header + body; shift any pipelined leftovers down */
    size_t consumed = total_hdr_bytes + (size_t)(content_length > 0 ? content_length : 0);
    size_t leftover = c->rlen - consumed;
    route(srv, c, &req);

    if (leftover > 0) memmove(c->rbuf, c->rbuf + consumed, leftover);
    c->rlen = leftover;
    c->rparsed = 0;
}

void handle_readable(server_t *srv, connection_t *c) {
    c->last_active = time(NULL);

#ifdef ENABLE_TLS
    if (c->state == CONN_TLS_HANDSHAKE) {
        int r = tls_handshake_step(c);
        if (r == 0) return;               /* still handshaking */
        if (r < 0) { conn_close(srv, c); return; }
        c->state = CONN_READING_REQ;
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
        c->state = (c->file_fd >= 0) ? CONN_SENDING_FILE : CONN_WRITING_RESP;
        if (c->file_fd < 0) goto finish_response;
    }

    if (c->state == CONN_SENDING_FILE) {
#ifdef ENABLE_TLS
        if (c->use_tls) {
            /* mbedTLS has no sendfile hook; fall back to buffered reads. */
            char buf[WRITE_BUF_SIZE];
            while (c->file_remaining > 0) {
                ssize_t r = read(c->file_fd, buf, sizeof(buf) < (size_t)c->file_remaining
                                                   ? sizeof(buf) : (size_t)c->file_remaining);
                if (r <= 0) { conn_close(srv, c); return; }
                ssize_t off = 0;
                while (off < r) {
                    ssize_t n = tls_write(c, buf + off, (size_t)(r - off));
                    if (n > 0) { off += n; continue; }
                    if (n < 0 && errno == EAGAIN) return; /* resumes on next EPOLLOUT */
                    conn_close(srv, c); return;
                }
                c->file_remaining -= r;
            }
            goto finish_response;
        }
#endif
        while (c->file_remaining > 0) {
            ssize_t n = sendfile(c->fd, c->file_fd, &c->file_offset, (size_t)c->file_remaining);
            if (n > 0) { c->file_remaining -= n; continue; }
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
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
    set_epoll(srv, c, EPOLLIN | EPOLLET);
    /* pipelined leftover bytes already sit in rbuf; give them a pass now */
    if (c->rlen > 0) process_request(srv, c);
}
