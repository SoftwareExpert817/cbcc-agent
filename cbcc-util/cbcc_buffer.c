#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "cbcc_common.h"
#include "cbcc_debug.h"
#include "cbcc_buffer.h"

// parse TLV buffer
int parse_buffer(unsigned char *buffer, int buf_len, cbcc_buffer_t *p)
{
	// first 4 bytes is type
	memcpy(&p->type, buffer, sizeof(int));
	if (p->type != CBCC_MSG_TYPE_SINGLE && p->type != CBCC_MSG_TYPE_START 
			&& p->type != CBCC_MSG_TYPE_CONTINUE && p->type != CBCC_MSG_TYPE_END)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_VERBOSE, "BUFFER: Buffer type '%d' is illegal", p->type);
		return -1;
	}
	
	if (p->type == CBCC_MSG_TYPE_START || p->type == CBCC_MSG_TYPE_SINGLE)
	{
		if (p->total_len != 0)
		{
			CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_VERBOSE, "BUFFER: Total length checking failed.");
			return -1;
		}
	}
	else if (p->type == CBCC_MSG_TYPE_CONTINUE || p->type == CBCC_MSG_TYPE_END)
	{
		if (p->total_len == 0)
		{
			CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_VERBOSE, "BUFFER: Total length checking failed.");
			return -1;
		}
	}

	// next 4 bytes is length
	memcpy(&p->len, buffer + sizeof(int), sizeof(int));
	if (p->len > (buf_len - 2 * sizeof(int)))
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_VERBOSE, "BUFFER: Buffer length checking failed(tlv len '%d', buffer len: %d)", buf_len, p->len);
		return -1;
	}
		
	// remain bytes is data
	if (!p->buffer)
		p->buffer = (unsigned char *) malloc(p->len + 1);
	else
		p->buffer = (unsigned char *) realloc(p->buffer, p->len + p->total_len + 1);
	
	memcpy(p->buffer + p->total_len, buffer + 2 * sizeof(int), p->len);
	
	// set total len
	p->total_len += p->len;
	
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_VERBOSE, "BUFFER: Parsing succeeded. TVL buffer type is '%d', len '%d', data '%s'", p->type, p->len, buffer + 2 * sizeof(int));
	
	return 0;
}

// add buffer to list
static void add_buffer_to_list(cbcc_buffer_list_t *buffer_list, cbcc_buffer_t *buf)
{
	if (buffer_list->count == 0)
	{
		buffer_list->buffer_list = buf;
	}
	else
	{
		cbcc_buffer_t *p = buffer_list->buffer_list;
		
		while (p->next)
			p = p->next;
		
		p->next = buf;
		buf->prev = p;
	}
	
	buffer_list->count++;
	
	return;
}

// get buffer by socket from list
cbcc_buffer_t *get_buffer_by_sock(cbcc_buffer_list_t *buffer_list, int sock)
{
	if (buffer_list->count == 0)
		return NULL;
	
	cbcc_buffer_t *p = buffer_list->buffer_list;
	while (p)
	{
		if (p->sock == sock)
			return p;
		
		p = p->next;
	}
	
	return NULL;
}

// add stream into buffer and check it has completed
int cbcc_buffer_add(cbcc_buffer_list_t *buffer_list, int sock, unsigned char *buf_stream, int buf_len, cbcc_buffer_t **p_buf, int *completed)
{
	cbcc_buffer_t *p;
	
	// init completed flag
	*completed = 0;
	
	// get buffer by socket
	if ((p = get_buffer_by_sock(buffer_list, sock)) == NULL)
	{
		p = (cbcc_buffer_t *) malloc(sizeof(cbcc_buffer_t));
		memset(p, 0, sizeof(cbcc_buffer_t));
		
		p->sock = sock;
		
		add_buffer_to_list(buffer_list, p);
	}
	
	// parse buffer
	if (parse_buffer(buf_stream, buf_len, p) != 0)
		return -1;
	
	if (p->type == CBCC_MSG_TYPE_END || p->type == CBCC_MSG_TYPE_SINGLE)
	{
		p->buffer[p->total_len] = '\0';
		
		*p_buf = p;
		*completed = 1;
	}

	return 0;

}

// free buffer from list
void cbcc_buffer_free(cbcc_buffer_list_t *buffer_list, int sock)
{
	cbcc_buffer_t *p;
	
	// get buffer by socket
	if ((p = get_buffer_by_sock(buffer_list, sock)) == NULL)
		return;
	
	if (p == buffer_list->buffer_list)
	{
		buffer_list->buffer_list = p->next;
		
		if (p->next)
			p->next->prev = NULL;
	}
	{
		if (p->prev)
			p->prev->next = p->next;
		if (p->next)
			p->next->prev = p->prev;
	}
	
	if (p->total_len > 0)
		free(p->buffer);
	
	free(p);
	
	buffer_list->count--;
	
	return;
}

static void free_buffer(cbcc_buffer_t *p)
{
	if (!p)
		return;
	
	// free next buffer
	if (p->next)
		free_buffer(p->next);
		
	// free buffer
	if (p->total_len > 0)
		free(p);
	
	// free self
	free(p);
	
	return;
}

// free buffer list
void cbcc_buffer_list_free(cbcc_buffer_list_t *buffer_list)
{
	if (buffer_list->count == 0)
		return;
		
	free_buffer(buffer_list->buffer_list);
	
	buffer_list->count = 0;
	buffer_list->buffer_list = NULL;
	
	return;
}

// build buffer from message
void cbcc_tlv_buffer_build(const char *msg, cbcc_tlv_buffer_list_t *buffer_list)
{
	const char *p = msg;
	
	// init buffer list
	memset(buffer_list, 0, sizeof(cbcc_buffer_list_t));
	
	// get count of tlv buffer list
	buffer_list->count = strlen(msg) / (CBCC_MAX_SOCK_BUF_LEN - 2 * sizeof(int));
	if (buffer_list->count * (CBCC_MAX_SOCK_BUF_LEN - 2 * sizeof(int)) < strlen(msg))
		buffer_list->count++;
	
	// allocate tlv buffer list
	buffer_list->tlv_buffer_list = (cbcc_tlv_buffer_t *) malloc(buffer_list->count * sizeof(cbcc_tlv_buffer_t));
	if (!buffer_list->tlv_buffer_list)
	{
		buffer_list->count = 0;
		return;
	}

	// set tlv buffer
	for (int i = 0; i < buffer_list->count; i++)
	{
		cbcc_tlv_buffer_t *buf = &buffer_list->tlv_buffer_list[i];
		
		// set type
		if (buffer_list->count == 1)
		{
			buf->type = CBCC_MSG_TYPE_SINGLE;
			buf->len = strlen(msg);
		}
		else
		{
			if (i == 0)
			{
				buf->type = CBCC_MSG_TYPE_START;
				buf->len = CBCC_MAX_SOCK_BUF_LEN - 2 * sizeof(int);
			}
			else if (i == (buffer_list->count - 1))
			{
				buf->type = CBCC_MSG_TYPE_END;
				buf->len = strlen(p);
			}
			else
			{
				buf->type = CBCC_MSG_TYPE_CONTINUE;
				buf->len = CBCC_MAX_SOCK_BUF_LEN - 2 * sizeof(int);
			}
		}
		
		memcpy(buf->buffer, p, buf->len);
		p += buf->len;
	}
	
	return;
}

// free tlv buffer list
void cbcc_tlv_buffer_free(cbcc_tlv_buffer_list_t *buffer_list)
{
	if (buffer_list->count == 0)
		return;
	
	free(buffer_list->tlv_buffer_list);
}
