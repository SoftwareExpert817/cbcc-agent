#ifndef __CBCC_SOCK_H__
#define __CBCC_SOCK_H__

#include <openssl/ssl.h>

// create socket
int create_socket();

// set socket as non-blocking
int set_non_blocking_sock(int sock);

// set socket as listen mode
int set_listen_mode(int sock, bool listen_local, int port);

// send tlv buffer via socket
int send_tlv_buffer(int sock, cbcc_tlv_buffer_list_t *tlv_buffer_list);

// send tlv buffer via SSL socket
int ssl_send_tlv_buffer(SSL *ssl, cbcc_tlv_buffer_list_t *tlv_buffer_list);

// get max socket descriptor
int get_max_fd(int old_max_fd, fd_set *fds);

#endif		// __CBCC_SOCK_H__
