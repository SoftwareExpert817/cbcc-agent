#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <unistd.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "cbcc_common.h"

#include "cbcc_debug.h"
#include "cbcc_buffer.h"
#include "cbcc_sock.h"

// create socket
int create_socket()
{
	int sock;
	
	// create socket
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_VERBOSE, "UTIL: Could not create socket.(%s)", strerror(errno));
		return -1;
	}

	return sock;
}

// set socket as non blocking
int set_non_blocking_sock(int sock)
{
	int on = 1;

	// set socket option
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on)) != 0)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_VERBOSE, "UTIL: Could not set socket option(%s)", strerror(errno));
		close(sock);
		return -1;
	}
	
	// set socket into non-blocking mode
	on = 1;
	if (ioctl(sock, FIONBIO, &on) != 0)
	{
		close(sock);
		return -1;
	}
	
	return 0;
}

// set socket as listen mode
int set_listen_mode(int sock, bool listen_local, int port)
{
	struct sockaddr_in addr;

	// set address
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;

	if (!listen_local)
		addr.sin_addr.s_addr = htonl(INADDR_ANY);
	else
		addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	
	addr.sin_port = htons(port);
	
	// bind and listen on given address
	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) != 0)
		return -1;
	
	if (listen(sock, 5) != 0)
		return -1;
	
	return 0;
}

// send tlv buffer via socket
int send_tlv_buffer(int sock, cbcc_tlv_buffer_list_t *tlv_buffer_list)
{
	int i;
	
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_VERBOSE, "SOCKET: Sending TLV buffer with count '%d'", tlv_buffer_list->count);
	
	for (i = 0; i < tlv_buffer_list->count; i++)
	{
		cbcc_tlv_buffer_t *p = &tlv_buffer_list->tlv_buffer_list[i];

		unsigned char buf[CBCC_MAX_SOCK_BUF_LEN];
		
		CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_VERBOSE, "SOCKET: Sending TLV buffer with type '%d', len '%d', data '%s'", p->type, p->len, p->buffer);
		
		memcpy(buf, p, sizeof(cbcc_tlv_buffer_t));
		
		do
		{
			int ret = send(sock, buf, sizeof(buf), 0);
			if (ret < 0)
			{
				if (errno != EWOULDBLOCK)
				{
					CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "SOCK: send function faild due to '%s'", strerror(errno));
					return -1;
				}
				
				continue;
			}
			
			break;
		}
		while (1);

		CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_VERBOSE, "SOCKET: Sending TLV buffer(index:%d) has succeeded.", i);
	}

	return 0;
}

// send tlv buffer via SSL socket
int ssl_send_tlv_buffer(SSL *ssl, cbcc_tlv_buffer_list_t *tlv_buffer_list)
{
	int i;
	
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_VERBOSE, "SOCKET: Sending TLV buffer with count '%d'", tlv_buffer_list->count);
	
	for (i = 0; i < tlv_buffer_list->count; i++)
	{
		cbcc_tlv_buffer_t *p = &tlv_buffer_list->tlv_buffer_list[i];

		unsigned char buf[CBCC_MAX_SOCK_BUF_LEN];
		
		CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_VERBOSE, "SOCKET: Sending TLV buffer with type '%d', len '%d', data '%s'", p->type, p->len, p->buffer);
		
		memcpy(buf, p, sizeof(cbcc_tlv_buffer_t));
		do
		{
			int ret = SSL_write(ssl, buf, sizeof(buf));
			if (ret < 0)
			{
				if (errno != EWOULDBLOCK)
				{
					CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "SOCK: send function faild due to '%s'", ERR_error_string(ERR_get_error(), NULL));
					return -1;
				}
				
				continue;
			}

			break;
		}
		while (1);

		CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_VERBOSE, "SOCKET: Sending TLV buffer(index:%d) has succeeded.", i);
	}

	return 0;
}


// get max socket descriptor
int get_max_fd(int old_max_fd, fd_set *fds)
{
	int max_fd = -1;
	
	for (int i = 0; i <= old_max_fd; i++)
	{
		if (!FD_ISSET(i, fds))
			continue;
			
		if (i > max_fd)
			max_fd = i;
	}
	
	return max_fd;
}
