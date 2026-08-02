#ifndef SERVER_H
#define SERVER_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "config.h"

#ifdef ENABLE_TLS
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#endif

typedef enum {
    CONN_FREE = 0,      /* slot unused                       */
    CONN_READING_REQ,   /* waiting for/reading request bytes */
    CONN_WRITING_RESP,  /* writing buffered response         */
    CONN_SENDING_FILE,  /* streaming a file via sendfile()   */
    CONN_TLS_HANDSHAKE  /* mid TLS handshake                 */
} conn_state_t;

typedef struct {
    int      fd;
    conn_state_t state;
    struct sockaddr_in addr;

    /* read side */
    char     rbuf[READ_BUF_SIZE];
    size_t   rlen;             /* bytes currently in rbuf     */
    size_t   rparsed;          /* bytes already parsed        */

    /* write side (small responses / headers) */
    char     wbuf[WRITE_BUF_SIZE];
    size_t   wlen;             /* total bytes to send         */
    size_t   wsent;            /* bytes already sent          */

    /* file streaming (sendfile) */
    int      file_fd;
    off_t    file_offset;
    off_t    file_remaining;

    int      keep_alive;       /* client wants keep-alive     */
    time_t   last_active;

#ifdef ENABLE_TLS
    int                 use_tls;
    mbedtls_ssl_context ssl;
#endif
} connection_t;

typedef struct {
    connection_t conns[MAX_CONNS];
    int          listen_fd;
    int          epoll_fd;
    const char  *docroot;

#ifdef ENABLE_TLS
    int tls_enabled;
    mbedtls_ssl_config      ssl_conf;
    mbedtls_x509_crt        cert;
    mbedtls_pk_context       pkey;
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
#endif
} server_t;

/* server.c */
int  server_init(server_t *srv, const char *bind_addr, int port, const char *docroot);
void server_run(server_t *srv);
void server_shutdown(server_t *srv);

/* http.c */
void handle_readable(server_t *srv, connection_t *c);
void handle_writable(server_t *srv, connection_t *c);
void conn_close(server_t *srv, connection_t *c);

#endif /* SERVER_H */
