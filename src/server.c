#include "server.h"
#include "tls.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <unistd.h>

static connection_t *alloc_conn(server_t *srv) {
    for (int i = 0; i < MAX_CONNS; i++) {
        if (srv->conns[i].state == CONN_FREE) return &srv->conns[i];
    }
    return NULL; /* pool exhausted: caller must reject the connection */
}

void conn_close(server_t *srv, connection_t *c) {
    if (c->state == CONN_FREE) return;
#ifdef ENABLE_TLS
    if (c->use_tls) tls_conn_free(c);
#endif
    if (c->file_fd >= 0) { close(c->file_fd); c->file_fd = -1; }
    epoll_ctl(srv->epoll_fd, EPOLL_CTL_DEL, c->fd, NULL);
    close(c->fd);
    c->fd = -1;
    c->state = CONN_FREE;
    c->rlen = c->rparsed = c->wlen = c->wsent = 0;
}

static void accept_all(server_t *srv) {
    for (;;) {
        struct sockaddr_in addr;
        socklen_t alen = sizeof(addr);
        int fd = accept4(srv->listen_fd, (struct sockaddr *)&addr, &alen, SOCK_NONBLOCK);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            if (errno == EINTR) continue;
            return;
        }

        connection_t *c = alloc_conn(srv);
        if (!c) {
            /* Pool exhausted — refuse cleanly instead of overcommitting RAM. */
            close(fd);
            continue;
        }

        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        memset(c, 0, sizeof(*c));
        c->fd = fd;
        c->addr = addr;
        c->file_fd = -1;
        c->keep_alive = 1;
        c->last_active = time(NULL);
        c->state = CONN_READING_REQ;

        uint32_t events = EPOLLIN | EPOLLET;
#ifdef ENABLE_TLS
        if (srv->tls_enabled) {
            if (tls_conn_init(srv, c) != 0) { close(fd); c->state = CONN_FREE; continue; }
            c->state = CONN_TLS_HANDSHAKE;
            events = EPOLLIN | EPOLLOUT | EPOLLET;
        }
#endif
        struct epoll_event ev = { .events = events, .data.ptr = c };
        if (epoll_ctl(srv->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
            close(fd);
            c->state = CONN_FREE;
        }
    }
}

static void sweep_idle(server_t *srv) {
    time_t now = time(NULL);
    for (int i = 0; i < MAX_CONNS; i++) {
        connection_t *c = &srv->conns[i];
        if (c->state == CONN_FREE) continue;
        int limit = (c->state == CONN_READING_REQ && c->rlen == 0)
                        ? KEEPALIVE_TIMEOUT : REQUEST_TIMEOUT;
        if (now - c->last_active > limit) conn_close(srv, c);
    }
}

int server_init(server_t *srv, const char *bind_addr, int port, const char *docroot) {
    memset(srv, 0, sizeof(*srv));
    srv->docroot = docroot;
    for (int i = 0; i < MAX_CONNS; i++) srv->conns[i].file_fd = -1;

    signal(SIGPIPE, SIG_IGN);

    srv->listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (srv->listen_fd < 0) { perror("socket"); return -1; }

    int one = 1;
    setsockopt(srv->listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (!bind_addr || !strcmp(bind_addr, "0.0.0.0"))
        addr.sin_addr.s_addr = INADDR_ANY;
    else
        inet_pton(AF_INET, bind_addr, &addr.sin_addr);

    if (bind(srv->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return -1;
    }
    if (listen(srv->listen_fd, LISTEN_BACKLOG) < 0) { perror("listen"); return -1; }

    srv->epoll_fd = epoll_create1(0);
    if (srv->epoll_fd < 0) { perror("epoll_create1"); return -1; }

    struct epoll_event ev = { .events = EPOLLIN, .data.ptr = NULL }; /* NULL = listener */
    epoll_ctl(srv->epoll_fd, EPOLL_CTL_ADD, srv->listen_fd, &ev);

    return 0;
}

void server_run(server_t *srv) {
    struct epoll_event events[MAX_EVENTS];
    time_t last_sweep = time(NULL);

    for (;;) {
        int n = epoll_wait(srv->epoll_fd, events, MAX_EVENTS, EVENT_LOOP_TICK_MS);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        for (int i = 0; i < n; i++) {
            if (events[i].data.ptr == NULL) { accept_all(srv); continue; }
            connection_t *c = (connection_t *)events[i].data.ptr;
            if (c->state == CONN_FREE) continue; /* stale event on a closed slot */

            if (events[i].events & (EPOLLHUP | EPOLLERR)) { conn_close(srv, c); continue; }
            if (events[i].events & EPOLLIN)  handle_readable(srv, c);
            if (c->state == CONN_FREE) continue;
            if (events[i].events & EPOLLOUT) handle_writable(srv, c);
        }
        time_t now = time(NULL);
        if (now != last_sweep) { sweep_idle(srv); last_sweep = now; }
    }
}

void server_shutdown(server_t *srv) {
    for (int i = 0; i < MAX_CONNS; i++)
        if (srv->conns[i].state != CONN_FREE) conn_close(srv, &srv->conns[i]);
    close(srv->listen_fd);
    close(srv->epoll_fd);
#ifdef ENABLE_TLS
    if (srv->tls_enabled) tls_server_free(srv);
#endif
}
