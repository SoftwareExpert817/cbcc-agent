#ifndef __CBCC_BUFFER_H__
#define __CBCC_BUFFER_H__

enum CBCC_MSG_TYPE
{
	CBCC_MSG_TYPE_SINGLE = 0x0000,
	CBCC_MSG_TYPE_START = 0x0001,
	CBCC_MSG_TYPE_CONTINUE = 0x0002,
	CBCC_MSG_TYPE_END = 0x0003,
};

// buffer
typedef struct _cbcc_buffer
{
	int sock;
	
	int total_len;
	
	int type;
	int len;
	unsigned char *buffer;
	
	struct _cbcc_buffer *next;
	struct _cbcc_buffer *prev;
} cbcc_buffer_t;

// buffer list
typedef struct _cbcc_buffer_list
{
	int count;
	cbcc_buffer_t *buffer_list;
} cbcc_buffer_list_t;

// tlv buffer
typedef struct _cbcc_tlv_buffer
{
	int type;
	int len;
	unsigned char buffer[CBCC_MAX_SOCK_BUF_LEN - 2 * sizeof(int)];
} cbcc_tlv_buffer_t;

// tlv buffer list
typedef struct _cbcc_tlv_buffer_list
{
	int count;
	cbcc_tlv_buffer_t *tlv_buffer_list;
} cbcc_tlv_buffer_list_t;

// add stream into buffer and check it has completed
int cbcc_buffer_add(cbcc_buffer_list_t *buffer_list, int sock, unsigned char *buf_stream, int buf_len, cbcc_buffer_t **p_buf, int *completed);

// free buffer from buffer list
void cbcc_buffer_free(cbcc_buffer_list_t *buffer_list, int sock);

// free buffer list
void cbcc_buffer_list_free(cbcc_buffer_list_t *buffer_list);

// build tlv buffer from message
void cbcc_tlv_buffer_build(const char *msg, cbcc_tlv_buffer_list_t *buffer_list);

// free tlv buffer list
void cbcc_tlv_buffer_free(cbcc_tlv_buffer_list_t *buffer_list);

#endif		// __CBCC_BUFFER_H__
