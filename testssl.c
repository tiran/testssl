/*
 * OpenSSL test program
 *
 * Written by Alex Gaynor and Paul Kehrer
 *
 * Modified by Christian Heimes
 *
 */
#include <assert.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#ifndef NO_TLS13
#  define NO_TLS13 0
#endif

char SERVER_KEY[] = "-----BEGIN RSA PRIVATE KEY-----\n"
"MIICWwIBAAKBgQC+pvhuud1dLaQQvzipdtlcTotgr5SuE2LvSx0gz/bg1U3u1eQ+\n"
"U5eqsxaEUceaX5p5Kk+QflvW8qdjVNxQuYS5uc0gK2+OZnlIYxCf4n5GYGzVIx3Q\n"
"SBj/TAEFB2WuVinZBiCbxgL7PFM1Kpa+EwVkCAduPpSflJJPwkYGrK2MHQIDAQAB\n"
"AoGAbwuZ0AR6JveahBaczjfnSpiFHf+mve2UxoQdpyr6ROJ4zg/PLW5K/KXrC48G\n"
"j6f3tXMrfKHcpEoZrQWUfYBRCUsGD5DCazEhD8zlxEHahIsqpwA0WWssJA2VOLEN\n"
"j6DuV2pCFbw67rfTBkTSo32ahfXxEKev5KswZk0JIzH3ooECQQDgzS9AI89h0gs8\n"
"Dt+1m11Rzqo3vZML7ZIyGApUzVan+a7hbc33nbGRkAXjHaUBJO31it/H6dTO+uwX\n"
"msWwNG5ZAkEA2RyFKs5xR5USTFaKLWCgpH/ydV96KPOpBND7TKQx62snDenFNNbn\n"
"FwwOhpahld+vqhYk+pfuWWUpQciE+Bu7ZQJASjfT4sQv4qbbKK/scePicnDdx9th\n"
"4e1EeB9xwb+tXXXUo/6Bor/AcUNwfiQ6Zt9PZOK9sR3lMZSsP7rMi7kzuQJABie6\n"
"1sXXjFH7nNJvRG4S39cIxq8YRYTy68II/dlB2QzGpKxV/POCxbJ/zu0CU79tuYK7\n"
"NaeNCFfH3aeTrX0LyQJAMBWjWmeKM2G2sCExheeQK0ROnaBC8itCECD4Jsve4nqf\n"
"r50+LF74iLXFwqysVCebPKMOpDWp/qQ1BbJQIPs7/A==\n"
"-----END RSA PRIVATE KEY-----";

char SERVER_CERT[] = "-----BEGIN CERTIFICATE-----\n"
"MIICKDCCAZGgAwIBAgIJAJn/HpR21r/8MA0GCSqGSIb3DQEBBQUAMFgxCzAJBgNV\n"
"BAYTAlVTMQswCQYDVQQIEwJJTDEQMA4GA1UEBxMHQ2hpY2FnbzEQMA4GA1UEChMH\n"
"VGVzdGluZzEYMBYGA1UEAxMPVGVzdGluZyBSb290IENBMCIYDzIwMDkwMzI1MTIz\n"
"NzUzWhgPMjAxNzA2MTExMjM3NTNaMBgxFjAUBgNVBAMTDWxvdmVseSBzZXJ2ZXIw\n"
"gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAL6m+G653V0tpBC/OKl22VxOi2Cv\n"
"lK4TYu9LHSDP9uDVTe7V5D5Tl6qzFoRRx5pfmnkqT5B+W9byp2NU3FC5hLm5zSAr\n"
"b45meUhjEJ/ifkZgbNUjHdBIGP9MAQUHZa5WKdkGIJvGAvs8UzUqlr4TBWQIB24+\n"
"lJ+Ukk/CRgasrYwdAgMBAAGjNjA0MB0GA1UdDgQWBBS4kC7Ij0W1TZXZqXQFAM2e\n"
"gKEG2DATBgNVHSUEDDAKBggrBgEFBQcDATANBgkqhkiG9w0BAQUFAAOBgQBh30Li\n"
"dJ+NlxIOx5343WqIBka3UbsOb2kxWrbkVCrvRapCMLCASO4FqiKWM+L0VDBprqIp\n"
"2mgpFQ6FHpoIENGvJhdEKpptQ5i7KaGhnDNTfdy3x1+h852G99f1iyj0RmbuFcM8\n"
"uzujnS8YXWvM7DM1Ilozk4MzPug8jzFp5uhKCQ==\n"
"-----END CERTIFICATE-----";

void assert_errno(bool condition, char *msg) {
    if (!condition) {
        perror(msg);
        exit(1);
    }
}

void assert_openssl(bool condition) {
    if (!condition) {
        printf("OpenSSL error\n");
        exit(1);
    }
}

int get_listening_port(int listener) {
    struct sockaddr_in server_bound_addr;
    socklen_t len = sizeof(server_bound_addr);
    int result = getsockname(listener, (struct sockaddr *)&server_bound_addr, &len);
    assert_errno(result != -1, "getsockname");
    return ntohs(server_bound_addr.sin_port);
}

EVP_PKEY *load_privatekey(char *key_bytes) {
    BIO *bio = BIO_new_mem_buf(key_bytes, strlen(key_bytes));
    EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    assert_openssl(key != NULL);
    return key;
}

X509 *load_certificate(char *cert_bytes) {
    BIO *bio = BIO_new_mem_buf(cert_bytes, strlen(cert_bytes));
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    assert_openssl(cert != NULL);
    return cert;
}

void create_loopback(SSL **server, SSL **client) {
    int result;

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    assert_errno(listener != -1, "socket");
    struct sockaddr_in server_addr;
    server_addr.sin_port = 0;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_family = AF_INET;
    result = bind(listener, (struct sockaddr *)&server_addr, sizeof(server_addr));
    assert_errno(result != -1, "bind");
    result = listen(listener, 1);
    assert_errno(result != -1, "listen");

    int client_sock = socket(AF_INET, SOCK_STREAM, 0);
    assert_errno(client_sock != -1, "socket");
    struct sockaddr_in dest_addr;
    dest_addr.sin_port = htons(get_listening_port(listener));
    inet_aton("127.0.0.1", &dest_addr.sin_addr);
    dest_addr.sin_family = AF_INET;
    result = connect(client_sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    assert_errno(result != -1, "connect");

    int server_sock = accept(listener, NULL, NULL);
    assert_errno(server_sock != -1, "accept");

    int options = SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;
    options |= SSL_OP_CIPHER_SERVER_PREFERENCE;
    options |= SSL_OP_SINGLE_DH_USE;
    options |= SSL_OP_SINGLE_ECDH_USE;
#if NO_TLS13
    options |= SSL_OP_NO_TLSv1_3;
#endif

    SSL_CTX *server_ctx = SSL_CTX_new(TLS_method());
    assert_openssl(server_ctx != NULL);
    SSL_CTX_set_options(server_ctx, options);
    SSL_CTX_use_PrivateKey(server_ctx, load_privatekey(SERVER_KEY));
    SSL_CTX_use_certificate(server_ctx, load_certificate(SERVER_CERT));
    *server = SSL_new(server_ctx);
    assert_openssl(*server != NULL);
    SSL_set_fd(*server, server_sock);
    SSL_set_accept_state(*server);

    SSL_CTX *client_ctx = SSL_CTX_new(TLS_method());
    assert_openssl(client_ctx != NULL);
    SSL_CTX_set_options(client_ctx, options);
    *client = SSL_new(client_ctx);
    SSL_set_mode(*client, SSL_MODE_AUTO_RETRY);
    assert_openssl(*client != NULL);
    SSL_set_fd(*client, client_sock);
    SSL_set_connect_state(*client);
}

void set_nonblocking(SSL *s, bool nonblocking) {
    int fd = SSL_get_fd(s);
    int flags = fcntl(fd, F_GETFL, 0);
    assert_errno(flags != -1, "fcntl");
    if (nonblocking) {
        flags |= O_NONBLOCK;
    } else {
        flags = flags & (~O_NONBLOCK);
    }
    flags = fcntl(fd, F_SETFL, flags);
    assert_errno(flags != -1, "fcntl");

    BIO_set_nbio(SSL_get_rbio(s), nonblocking);
    BIO_set_nbio(SSL_get_wbio(s), nonblocking);
}

void handshake(SSL *client, SSL *server) {
    set_nonblocking(client, true);
    set_nonblocking(server, true);

    SSL *conns[] = {client, server};
    int nconns = 2;
    while (nconns) {
        for (size_t i = 0; i < 2; i++) {
            if (conns[i] == NULL) {
                continue;
            }
            int result = SSL_do_handshake(conns[i]);
            int error = SSL_get_error(conns[i], result);
            if (error == SSL_ERROR_NONE) {
                conns[i] = NULL;
                nconns--;
            } else if (error != SSL_ERROR_WANT_READ) {
                assert_openssl(false);
            }
        }
    }

    printf("Server version: %s\n", SSL_get_version(server));
    printf("Client version: %s\n", SSL_get_version(client));

    set_nonblocking(client, false);
    set_nonblocking(server, false);
}

void write_read(SSL *writer, SSL *reader) {
    char out[4];

    printf("Writing %s...\n", SSL_is_server(writer) ? "server" : "client");
    int result = SSL_write(writer, "xyz", 3);
    assert_openssl(result == 3);

    printf("Reading %s...\n", SSL_is_server(reader) ? "server" : "client");
    result = SSL_read(reader, out, 3);
    if (result != 3) {
        result = SSL_get_error(reader, result);
        printf("OpenSSL error: %d\n", result);
        exit(1);
    }
}

void printerr(SSL *s, int result) {
    printf("result: %d\n", result);
    printf("SSL error: %d\n", SSL_get_error(s, result));
    printf("errno: %d\n", errno);
    printf("ERR: %lu\n", ERR_peek_error());
}

int main() {
    SSL *server, *client;
    int result;

    create_loopback(&server, &client);
    handshake(client, server);

    write_read(client, server);
#if 0
    write_read(server, client);
#endif

    printf("Calling client shutdown once!\n");
    assert_openssl(ERR_get_error() == 0);
    if (SSL_shutdown(client) == 0) {
        /* Disable read-ahead so that unwrap can work correctly. */
        SSL_set_read_ahead(client, 0);
        printf("Calling client shutdown twice!\n");
        result = SSL_shutdown(client);
        printerr(client, result);
        assert_openssl(result == 1);
        assert_openssl(ERR_get_error() == 0);

        printf("Calling server shutdown\n");
        result = SSL_shutdown(server);
        printerr(server, result);
        /* if (SSL_shutdown(server) == 0) { */
        /*     printf("Calling SSL shutdown client 2x"); */
        /*     assert_openssl(ERR_get_error() == 0); */
        /*     result = SSL_shutdown(client); */
        /*     assert_openssl(result == 1); */
        /*     result = SSL_shutdown(server); */
        /*     assert_openssl(result == 1); */
        /* } */
    }
}
