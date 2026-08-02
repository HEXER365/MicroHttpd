#ifndef TLS_H
#define TLS_H

#include "server.h"

#ifdef ENABLE_TLS

/* Loads cert_path/key_path and configures srv->ssl_conf.
 * Returns 0 on success, -1 on failure (message printed to stderr). */
int  tls_server_init(server_t *srv, const char *cert_path, const char *key_path);
void tls_server_free(server_t *srv);

/* Per-connection setup/teardown. */
int  tls_conn_init(server_t *srv, connection_t *c);
void tls_conn_free(connection_t *c);

/* Returns: 1 handshake done, 0 need more I/O (EAGAIN), -1 fatal error. */
int  tls_handshake_step(connection_t *c);

/* mbedtls-backed read/write, POSIX-like semantics: >0 bytes, 0 = closed,
 * -1 with errno=EAGAIN = would block, -1 other = fatal. */
ssize_t tls_read(connection_t *c, void *buf, size_t len);
ssize_t tls_write(connection_t *c, const void *buf, size_t len);

#endif /* ENABLE_TLS */
#endif /* TLS_H */
