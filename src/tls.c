#ifdef ENABLE_TLS

#include "tls.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/version.h>

/* mbedTLS is chosen over OpenSSL specifically for this project:
 * a minimal mbedTLS build is ~150-250KB of code and a live TLS 1.2/1.3
 * session can run in a few KB of RAM (no BIGNUM/ASN.1 caching bloat),
 * which matters a lot on a router/SBC-class device. OpenSSL's per
 * connection memory footprint is typically several times larger. */

static int rng(void *ctx, unsigned char *out, size_t len) {
    return mbedtls_ctr_drbg_random(ctx, out, len);
}

int tls_server_init(server_t *srv, const char *cert_path, const char *key_path) {
    int ret;

    mbedtls_x509_crt_init(&srv->cert);
    mbedtls_pk_init(&srv->pkey);
    mbedtls_ssl_config_init(&srv->ssl_conf);
    mbedtls_entropy_init(&srv->entropy);
    mbedtls_ctr_drbg_init(&srv->ctr_drbg);

    const char *pers = "microhttpd";
    ret = mbedtls_ctr_drbg_seed(&srv->ctr_drbg, mbedtls_entropy_func, &srv->entropy,
                                 (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        fprintf(stderr, "tls: drbg seed failed (-0x%04x)\n", -ret);
        return -1;
    }

    ret = mbedtls_x509_crt_parse_file(&srv->cert, cert_path);
    if (ret != 0) {
        fprintf(stderr, "tls: failed to load cert '%s' (-0x%04x)\n", cert_path, -ret);
        return -1;
    }

#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    ret = mbedtls_pk_parse_keyfile(&srv->pkey, key_path, NULL, rng, &srv->ctr_drbg);
#else
    (void)rng;
    ret = mbedtls_pk_parse_keyfile(&srv->pkey, key_path, NULL);
#endif
    if (ret != 0) {
        fprintf(stderr, "tls: failed to load key '%s' (-0x%04x)\n", key_path, -ret);
        return -1;
    }

    ret = mbedtls_ssl_config_defaults(&srv->ssl_conf, MBEDTLS_SSL_IS_SERVER,
                                       MBEDTLS_SSL_TRANSPORT_STREAM,
                                       MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        fprintf(stderr, "tls: config defaults failed (-0x%04x)\n", -ret);
        return -1;
    }

    /* Prefer modern, cheap ciphers; low-RAM devices benefit from
     * avoiding heavy RSA handshakes where an ECDSA cert is available. */
    mbedtls_ssl_conf_min_version(&srv->ssl_conf, MBEDTLS_SSL_MAJOR_VERSION_3,
                                  MBEDTLS_SSL_MINOR_VERSION_3); /* TLS 1.2 floor */

    mbedtls_ssl_conf_rng(&srv->ssl_conf, mbedtls_ctr_drbg_random, &srv->ctr_drbg);
    mbedtls_ssl_conf_ca_chain(&srv->ssl_conf, srv->cert.next, NULL);

    ret = mbedtls_ssl_conf_own_cert(&srv->ssl_conf, &srv->cert, &srv->pkey);
    if (ret != 0) {
        fprintf(stderr, "tls: own_cert failed (-0x%04x)\n", -ret);
        return -1;
    }

    /* Shrink per-session RAM: cap the record buffer instead of the
     * default 16KB in/out buffers when the peer allows it. */
#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    mbedtls_ssl_conf_max_frag_len(&srv->ssl_conf, MBEDTLS_SSL_MAX_FRAG_LEN_4096);
#endif

    srv->tls_enabled = 1;
    return 0;
}

void tls_server_free(server_t *srv) {
    mbedtls_x509_crt_free(&srv->cert);
    mbedtls_pk_free(&srv->pkey);
    mbedtls_ssl_config_free(&srv->ssl_conf);
    mbedtls_ctr_drbg_free(&srv->ctr_drbg);
    mbedtls_entropy_free(&srv->entropy);
}

/* --- per connection --- */

static int bio_send(void *ctx, const unsigned char *buf, size_t len) {
    connection_t *c = (connection_t *)ctx;
    ssize_t n = send(c->fd, buf, len, MSG_NOSIGNAL);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return MBEDTLS_ERR_SSL_WANT_WRITE;
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return (int)n;
}

static int bio_recv(void *ctx, unsigned char *buf, size_t len) {
    connection_t *c = (connection_t *)ctx;
    ssize_t n = recv(c->fd, buf, len, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return MBEDTLS_ERR_SSL_WANT_READ;
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    if (n == 0) return MBEDTLS_ERR_SSL_CONN_EOF;
    return (int)n;
}

int tls_conn_init(server_t *srv, connection_t *c) {
    mbedtls_ssl_init(&c->ssl);
    if (mbedtls_ssl_setup(&c->ssl, &srv->ssl_conf) != 0) return -1;
    mbedtls_ssl_set_bio(&c->ssl, c, bio_send, bio_recv, NULL);
    c->use_tls = 1;
    return 0;
}

void tls_conn_free(connection_t *c) {
    if (c->use_tls) mbedtls_ssl_free(&c->ssl);
    c->use_tls = 0;
}

int tls_handshake_step(connection_t *c) {
    int ret = mbedtls_ssl_handshake(&c->ssl);
    if (ret == 0) return 1;
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) return 0;
    return -1;
}

ssize_t tls_read(connection_t *c, void *buf, size_t len) {
    int ret = mbedtls_ssl_read(&c->ssl, buf, len);
    if (ret >= 0) return ret;
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        errno = EAGAIN;
        return -1;
    }
    if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) return 0;
    return -1;
}

ssize_t tls_write(connection_t *c, const void *buf, size_t len) {
    int ret = mbedtls_ssl_write(&c->ssl, buf, len);
    if (ret >= 0) return ret;
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        errno = EAGAIN;
        return -1;
    }
    return -1;
}

#endif /* ENABLE_TLS */
