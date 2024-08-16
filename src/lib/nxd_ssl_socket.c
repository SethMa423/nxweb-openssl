/*
 * Copyright (c) 2011-2012 Yaroslav Stavnichiy <yarosla@gmail.com>
 *
 * This file is part of NXWEB.
 *
 * NXWEB is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation, either version 3
 * of the License, or (at your option) any later version.
 *
 * NXWEB is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with NXWEB. If not, see <http://www.gnu.org/licenses/>.
 */

#include "nxweb.h"

#ifdef WITH_SSL

#include <stdio.h>
#include <malloc.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int __attribute__((constructor)) nxd_ssl_socket_global_init(void)
{
  // this must be called once in the program
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();
}

void __attribute__((destructor)) nxd_ssl_socket_global_finalize(void) { EVP_cleanup(); }

int nxd_ssl_socket_init_server_parameters(SSL_CTX** ctx, const char* cert_file,
                                          const char* key_file, const char* dh_params_file,
                                          const char* cipher_priority_string)
{
  *ctx = NULL;
  const SSL_METHOD* method = SSLv23_server_method();
  *ctx = SSL_CTX_new(method);
  if (!*ctx) {
    nxweb_log_error("Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    return -1;
  }

  if (SSL_CTX_use_certificate_file(*ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    nxweb_log_error("load certificate failed");
    return -1;
  }
  if (SSL_CTX_use_PrivateKey_file(*ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    nxweb_log_error("load private key failed");
    return -1;
  }
  if (!SSL_CTX_check_private_key(*ctx)) {
    nxweb_log_error("Private key does not match the certificate public key");
    return -1;
  }

  // In fact, we dont need to generate ECDHE paramameter in advance, OpenSSL library
  // will do that for us.
  (void)dh_params_file;
  (void)cipher_priority_string;

  nxweb_log_debug("SSL_CTX created at %p", *ctx);
  return 0;
}

void nxd_ssl_socket_finalize_server_parameters(SSL_CTX* ctx)
{
  if (ctx) {
    SSL_CTX_free(ctx);
    nxweb_log_debug("SSL CTX free ctx %p", ctx);
  }
}

#if (__SIZEOF_POINTER__ == 8)
typedef uint64_t int_to_ptr;
#else
typedef uint32_t int_to_ptr;
#endif

static int do_handshake(nxd_ssl_socket* ss)
{
  nxe_loop* loop = ss->fs.data_is.super.loop;
  assert(!ss->handshake_complete && !ss->handshake_failed);
  if (!ss->handshake_started) {
    if (!ss->ssl)
      return -1;

    nxweb_log_debug("SSL in use at %p, socket=%d ", ss->ssl, ss->fs.fd);

    SSL_set_fd(ss->ssl, ss->fs.fd);
    ss->handshake_started = 1;

    ss->saved_is = ss->fs.data_os.pair;
    if (ss->saved_is)
      nxe_disconnect_streams(ss->fs.data_os.pair, &ss->fs.data_os);
    nxe_connect_streams(loop, &ss->handshake_stub_is, &ss->fs.data_os);
    nxe_istream_set_ready(loop, &ss->handshake_stub_is);

    ss->saved_os = ss->fs.data_is.pair;
    if (ss->saved_os)
      nxe_disconnect_streams(&ss->fs.data_is, ss->fs.data_is.pair);
    nxe_connect_streams(loop, &ss->fs.data_is, &ss->handshake_stub_os);
    nxe_ostream_set_ready(loop, &ss->handshake_stub_os);
  }

  int ret = SSL_accept(ss->ssl);
  if (ret > 0) {
    ss->handshake_complete = 1;

    nxe_istream_unset_ready(&ss->handshake_stub_is);
    nxe_disconnect_streams(&ss->handshake_stub_is, &ss->fs.data_os);
    if (ss->saved_is)
      nxe_connect_streams(loop, ss->saved_is, &ss->fs.data_os);

    nxe_ostream_unset_ready(&ss->handshake_stub_os);
    nxe_disconnect_streams(&ss->fs.data_is, &ss->handshake_stub_os);
    if (ss->saved_os)
      nxe_connect_streams(loop, &ss->fs.data_is, ss->saved_os);

    return 0;
  }
  else {
    int rc = SSL_get_error(ss->ssl, ret);

    // wait for a second try
    if (rc == SSL_ERROR_WANT_READ || rc == SSL_ERROR_WANT_WRITE)
      return 1;

    nxweb_log_error("SSL_accept() return with error %d nxd_ssl_socket=%p, msg: %s", rc, ss,
                    ERR_error_string(rc, NULL));
    if (rc == SSL_ERROR_ZERO_RETURN) {
      nxe_publish(&ss->fs.data_error, (nxe_data)NXE_RDCLOSED);
      nxweb_log_error("Connection closed by peer");
    }
    else if (rc == SSL_ERROR_SSL) {
      nxe_publish(&ss->fs.data_error, (nxe_data)NXE_PROTO_ERROR);
      nxweb_log_error("Http connection attempted on SSL port?");
    }
    else {
      nxe_publish(&ss->fs.data_error, (nxe_data)NXE_ERROR);
      nxweb_log_error("Unknown SSL error");
    }
    ss->handshake_failed = 1;
    return -1;
  }
}

static void handshake_stub_is_do_write(nxe_istream* is, nxe_ostream* os)
{
  nxd_ssl_socket* ss = (nxd_ssl_socket*)((char*)is - offsetof(nxd_ssl_socket, handshake_stub_is));
  // continue handshake
  if (ss->handshake_failed || do_handshake(ss)) {
    nxe_ostream_unset_ready(os);
  }
}

static void handshake_stub_os_do_read(nxe_ostream* os, nxe_istream* is)
{
  nxd_ssl_socket* ss = (nxd_ssl_socket*)((char*)os - offsetof(nxd_ssl_socket, handshake_stub_os));
  // continue handshake
  if (ss->handshake_failed || do_handshake(ss)) {
    nxe_istream_unset_ready(is);
  }
}

static nxe_size_t sock_data_recv_read(nxe_istream* is, nxe_ostream* os, void* ptr, nxe_size_t size,
                                      nxe_flags_t* flags)
{
  nxe_fd_source* fs = (nxe_fd_source*)((char*)is - offsetof(nxe_fd_source, data_is));
  nxd_ssl_socket* ss =
    (nxd_ssl_socket*)((char*)is - offsetof(nxe_fd_source, data_is) - offsetof(nxd_ssl_socket, fs));

  if (!ss->handshake_complete) {
    if (do_handshake(ss)) {
      nxe_istream_unset_ready(is);
      return 0;
    }
  }

  if (size > 0) {
    nxe_ssize_t bytes_received = SSL_read(ss->ssl, ptr, size);
    if (bytes_received <= 0) {
      nxe_istream_unset_ready(is);
      int rc = SSL_get_error(ss->ssl, bytes_received);
      if (rc == SSL_ERROR_WANT_READ || rc == SSL_ERROR_WANT_WRITE)
        return 0;
      if (rc == SSL_ERROR_ZERO_RETURN)
        nxe_publish(&fs->data_error, (nxe_data)NXE_RDCLOSED);
      else if (rc == SSL_ERROR_SYSCALL || rc == SSL_ERROR_SSL)
        nxe_publish(&fs->data_error, (nxe_data)NXE_ERROR);
    }
    return bytes_received;
  }
  return 0;
}

static nxe_ssize_t sock_data_send_write(nxe_ostream* os, nxe_istream* is, int fd,
                                        nx_file_reader* fr, nxe_data ptr, nxe_size_t size,
                                        nxe_flags_t* _flags)
{
  nxe_fd_source* fs = (nxe_fd_source*)((char*)os - offsetof(nxe_fd_source, data_os));
  nxd_ssl_socket* ss =
    (nxd_ssl_socket*)((char*)os - offsetof(nxe_fd_source, data_os) - offsetof(nxd_ssl_socket, fs));

  if (!ss->handshake_complete) {
    if (do_handshake(ss)) {
      nxe_ostream_unset_ready(os);
      return 0;
    }
  }

  nxe_flags_t flags = *_flags;
  nx_file_reader_to_mem_ptr(fd, fr, &ptr, &size, &flags);
  if (size) {
    nxe_loop* loop = os->super.loop;
    if (!loop->batch_write_fd) {
      int fd = fs->fd;
      _nxweb_batch_write_begin(fd);
      loop->batch_write_fd = fd;
    }
    nxe_ssize_t bytes_sent = SSL_write(ss->ssl, ptr.cptr, size);
    if (bytes_sent <= 0) {
      int rc = SSL_get_error(ss->ssl, bytes_sent);
      nxe_ostream_unset_ready(os);
      if (rc == SSL_ERROR_WANT_READ || rc == SSL_ERROR_WANT_WRITE) {
        nxweb_log_error(
          "SSL_write() returned SSL_ERROR_WANT_READ/WRITE; %ld bytes offered, some buffered", size);
        return 0;
      }
      nxe_publish(&fs->data_error, (nxe_data)NXE_ERROR);
      nxweb_log_warning("SSL_write() return with error %d", rc);
      return 0;
    }
    return bytes_sent;
  }
  return 0;
}

static void sock_data_send_shutdown(nxe_ostream* os)
{
  nxd_ssl_socket* ss =
    (nxd_ssl_socket*)((char*)os - offsetof(nxe_fd_source, data_os) - offsetof(nxd_ssl_socket, fs));
  SSL_shutdown(ss->ssl);
}

static const nxe_istream_class sock_data_recv_class = {.read = sock_data_recv_read};
static const nxe_ostream_class sock_data_send_class = {.write = sock_data_send_write,
                                                       .shutdown = sock_data_send_shutdown};

static const nxe_istream_class handshake_stub_is_class = {.do_write = handshake_stub_is_do_write};
static const nxe_ostream_class handshake_stub_os_class = {.do_read = handshake_stub_os_do_read};

static void socket_shutdown(nxd_socket* sock)
{
  nxd_ssl_socket* ss = (nxd_ssl_socket*)sock;
  SSL_shutdown(ss->ssl);
}

static void socket_finalize(nxd_socket* sock, int good)
{
  nxd_ssl_socket* ss = (nxd_ssl_socket*)sock;
  nxd_ssl_server_socket_finalize(sock, good);
}

static const nxd_socket_class ssl_server_socket_class = {.shutdown = socket_shutdown,
                                                         .finalize = socket_finalize};

void nxd_ssl_server_socket_init(nxd_ssl_socket* ss, SSL_CTX* ctx)
{
  memset(ss, 0, sizeof(nxd_socket));
  ss->cls = &ssl_server_socket_class;
  nxe_init_fd_source(&ss->fs, 0, &sock_data_recv_class, &sock_data_send_class, NXE_PUB_DEFAULT);
  nxe_init_istream(&ss->handshake_stub_is, &handshake_stub_is_class);
  nxe_init_ostream(&ss->handshake_stub_os, &handshake_stub_os_class);

  // We don't request any certificate from the client.
  ss->ssl = SSL_new(ctx);
  if (!ss->ssl)
    nxweb_log_warning("SSL session not initialized");
  else
    nxweb_log_debug("SSL init at ssl_server_socket_init to %p", ss->ssl);
}

void nxd_ssl_server_socket_finalize(nxd_ssl_socket* ss, int good)
{
  // this also disconnects streams and unsubscribes subscribers
  if (ss->fs.data_is.super.loop)
    nxe_unregister_fd_source(&ss->fs);
  SSL_free(ss->ssl);
  if (good)
    _nxweb_close_good_socket(ss->fs.fd);
  else
    _nxweb_close_bad_socket(ss->fs.fd);
}

#endif  // WITH_SSL