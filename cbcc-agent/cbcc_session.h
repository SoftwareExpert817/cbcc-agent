#ifndef __CBCC_SESSION_H__
#define __CBCC_SESSION_H__

// cbccd command manager ssl parameters
typedef struct _cbcc_ssl_params
{
	const SSL_METHOD *meth;
	SSL_CTX *ctx;
	
	SSL *ssl;
} cbcc_ssl_params_t;

typedef struct _cbcc_admin_srcip_info
{
	bool is_connected;

	char admin_srcip[CBCC_MAX_GUID_LEN];
	time_t droped_tm;

	struct _cbcc_admin_srcip_info *next;
	struct _cbcc_admin_srcip_info *prev;
} cbcc_admin_srcip_info_t;

typedef struct _cbcc_admin_srcip_list
{
	int srcip_num;

	cbcc_admin_srcip_info_t *admin_infos;
} cbcc_admin_srcip_list_t;

// cbcc agent session manager
typedef struct _cbcc_agent_session_mgr
{
	bool init_flag;
	bool end_flag;
	
	cbcc_ssl_params_t ssl_params;			// SSL parameters
	
	bool session_established;			// flag for session established
	bool logined;					// flag for login
	
	int sock;					// session socket
	
	cbcc_buffer_list_t buffer_list;			// command buffer list
	cbcc_admin_srcip_list_t admin_list;
	
	pthread_t pt_session;				// session manager pthread ID
	pthread_t pt_keepalive;				// keepalive
	
	pthread_mutex_t rcv_mt;
	pthread_mutex_t send_mt;

	struct _cbcc_agent_ctx *c;
} cbcc_agent_session_mgr_t;


// intialize session manager
int cbcc_session_mgr_init(struct _cbcc_agent_ctx *c);
void cbcc_session_mgr_finalize(cbcc_agent_session_mgr_t *session_mgr);

// send/recv messages
int cbcc_session_send_msg(cbcc_agent_session_mgr_t *session_mgr, const char *msg);
int cbcc_session_recv_msg(cbcc_agent_session_mgr_t *session_mgr, char *msg, size_t msg_size);

#endif			// __CBCC_SESSION_H__
