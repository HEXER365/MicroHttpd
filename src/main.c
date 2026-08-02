#include "server.h"
#include "tls.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>

static server_t g_srv;

/* Async-signal-safe: only sets a flag that the main epoll loop polls.
 * The actual shutdown (close, free, etc.) happens in the main thread
 * after epoll_wait returns, where it is safe to call non-async-signal-
 * safe libc functions. */
static void on_signal(int sig) {
    (void)sig;
    g_srv.shutdown_requested = 1;
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "usage: %s [-p port] [-b addr] [-d docroot]"
#ifdef ENABLE_TLS
        " [-c cert.pem -k key.pem]"
#endif
        " [-R rlimit-mb]\n"
        "  -p port      listen port (default 8080)\n"
        "  -b addr      bind address (default 0.0.0.0)\n"
        "  -d docroot   directory to serve (default ./www)\n"
        "  -R mb        RLIMIT_AS ceiling in MiB (default %d, 0 = unset)\n"
#ifdef ENABLE_TLS
        "  -c cert.pem  TLS certificate (enables HTTPS)\n"
        "  -k key.pem   TLS private key\n"
#endif
        , argv0, RLIMIT_AS_MB);
}

int main(int argc, char **argv) {
    int port = 8080;
    const char *bind_addr = "0.0.0.0";
    const char *docroot = "./www";
    long rlimit_mb = RLIMIT_AS_MB;
#ifdef ENABLE_TLS
    const char *cert = NULL, *key = NULL;
#endif

    int opt;
    while ((opt = getopt(argc, argv, "p:b:d:c:k:R:h")) != -1) {
        switch (opt) {
            case 'p': port = atoi(optarg); break;
            case 'b': bind_addr = optarg; break;
            case 'd': docroot = optarg; break;
            case 'R': rlimit_mb = atol(optarg); break;
#ifdef ENABLE_TLS
            case 'c': cert = optarg; break;
            case 'k': key = optarg; break;
#endif
            default: usage(argv[0]); return 1;
        }
    }

    if (port <= 0 || port > 65535) {
        fprintf(stderr, "invalid port %d\n", port);
        return 1;
    }

    if (server_init(&g_srv, bind_addr, port, docroot) != 0) {
        fprintf(stderr, "failed to start server\n");
        return 1;
    }

#ifdef ENABLE_TLS
    if (cert && key) {
        if (tls_server_init(&g_srv, cert, key) != 0) {
            fprintf(stderr, "failed to init TLS\n");
            /* IMPORTANT: server_init already opened listen_fd + epoll_fd.
             * Free them so we don't leak FDs (and so the next bind()
             * doesn't fail with EADDRINUSE on restart). */
            server_shutdown(&g_srv);
            return 1;
        }
        fprintf(stderr, "TLS enabled (cert=%s)\n", cert);
    } else if (cert || key) {
        fprintf(stderr, "TLS requires BOTH -c and -k\n");
        server_shutdown(&g_srv);
        return 1;
    }
#endif

    /* Optional: drop the RLIMIT_AS ceiling so a bug can't runaway-allocate
     * on a device that can't afford it. Safe because the whole design is
     * fixed-size; legitimate peak usage is well under this. */
    if (rlimit_mb > 0) {
        struct rlimit rl = {
            .rlim_cur = (rlim_t)rlimit_mb * 1024 * 1024,
            .rlim_max = (rlim_t)rlimit_mb * 1024 * 1024,
        };
        if (setrlimit(RLIMIT_AS, &rl) != 0) {
            perror("setrlimit(RLIMIT_AS)");
            /* Non-fatal: keep running, just without the ceiling. */
        }
    }

    /* signal() is fine here — the handler only flips a sig_atomic_t flag. */
    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    fprintf(stderr, SERVER_NAME " listening on %s:%d (docroot=%s, max_conns=%d)\n",
            bind_addr, port, docroot, MAX_CONNS);

    server_run(&g_srv);
    server_shutdown(&g_srv);
    return 0;
}
