
#include "cbcc_agent.h"

#include <openssl/err.h>

static void *session_mgr_proc(void *p);
static void *keepalive_proc(void *p);
static void *link_webadmin_proc(void *p);

// initialize ssl settings
static int init_ssl_settings(cbcc_agent_ctx_t *c)
{
	cbcc_ssl_params_t *ssl_params = &c->session_mgr.ssl_params;
	
	if (c->no_ssl)
		return 0;
	
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "SESSION: Initializing SSL settings");
	
	// init ssl library
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();
	OpenSSL_add_ssl_algorithms();
	
	// create ssl method
	ssl_params->meth = SSLv23_client_method();
	if (!ssl_params->meth)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "SESSION: Creating SSL method has failed.");
		return -1;
	}
	
	// create ssl context
	ssl_params->ctx = SSL_CTX_new(ssl_params->meth);
	if (!ssl_params->ctx)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "SESSION: Creating SSL context object has failed.");
		return -1;
	}

#if 0
	// set certificate and key file
	if (SSL_CTX_use_certificate_file(ssl_params->ctx, CBCC_CERT_FILE_PATH, SSL_FILETYPE_PEM) <= 0)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "SESSION: Using certificate file '%s' has failed due to '%s'.",
					CBCC_CERT_FILE_PATH, ERR_error_string(ERR_get_error(), NULL));

		SSL_CTX_free(ssl_params->ctx);
		
		return -1;
	}

	if (SSL_CTX_use_PrivateKey_file(ssl_params->ctx, CBCC_KEY_FILE_PATH, SSL_FILETYPE_PEM) <= 0)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "SESSION: Using private key file '%s' has failed.",
					CBCC_KEY_FILE_PATH, ERR_error_string(ERR_get_error(), NULL));

		SSL_CTX_free(ssl_params->ctx);
		
		return -1;
	}
	
	if (!SSL_CTX_check_private_key(ssl_params->ctx))
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "SESSION: Certificate and key file doesn't match");
		SSL_CTX_free(ssl_params->ctx);
		
		return -1;
	}
#endif
	
	return 0;
}

// finalize ssl settings
static void finalize_ssl_settings(cbcc_agent_ctx_t *c)
{
	cbcc_ssl_params_t *ssl_params = &c->session_mgr.ssl_params;
	
	if (c->no_ssl)
		return;
	
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "SESSION: Finalizing SSL settings");
	
	if (ssl_params->ssl)
	{
		SSL_shutdown(ssl_params->ssl);
		SSL_free(ssl_params->ssl);
	}
	
	// free loaded ssl strings
	ERR_free_strings();
	
	// free ssl context
	SSL_CTX_free(ssl_params->ctx);
	
	return;
}

// initialize CBCC session manager
int cbcc_session_mgr_init(cbcc_agent_ctx_t *c)
{
	cbcc_agent_session_mgr_t *session_mgr = &c->session_mgr;
	
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "SESSION: Initializing CBCC agent session manager.");
	
	// init ssl settings
	if (init_ssl_settings(c) != 0)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "SESSION: Initializing SSL settings has failed.");
		return -1;
	}
	
	// set context object
	session_mgr->c = c;
	
	// create thread for session manager
	if (pthread_create(&session_mgr->pt_session, NULL, session_mgr_proc, (void *) session_mgr) != 0)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "SESSION: Could not create thread for session management.");
		return -1;
	}
	
	// create thread to send keepalive command
	if (pthread_create(&session_mgr->pt_keepalive, NULL, keepalive_proc, (void *) session_mgr) != 0)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "SESSION: Could not create thread to send keepalive command.");
		
		session_mgr->end_flag = true;
		pthread_join(session_mgr->pt_session, NULL);
		
		return -1;
	}

	//Clean webadmin firewall at startup
	char script_cmd[CBCC_MAX_SCRIPT_CMD_LEN];
	snprintf(script_cmd, CBCC_MAX_SCRIPT_CMD_LEN, "/etc/./fw_manage clean");
	system(script_cmd);
	
	//Observe the webadmin login proc
	if (pthread_create(&session_mgr->pt_session, NULL, link_webadmin_proc, (void *) session_mgr) != 0)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "SESSION: Could not create thread for session management.");
		return -1;
	}

	// initialize mutex for session
	pthread_mutex_init(&session_mgr->rcv_mt, NULL);
	pthread_mutex_init(&session_mgr->send_mt, NULL);
	
	// set init flag
	session_mgr->init_flag = true;
	
	return 0;
}

// finalize CBCC session manager
void cbcc_session_mgr_finalize(cbcc_agent_session_mgr_t *session_mgr)
{
	//Clean webadmin firewall at closeup
	char script_cmd[CBCC_MAX_SCRIPT_CMD_LEN];
	snprintf(script_cmd, CBCC_MAX_SCRIPT_CMD_LEN, "/etc/./fw_manage clean");
	system(script_cmd);

	// check init flag
	if (!session_mgr->init_flag)
		return;
		
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "SESSION: Finalizing CBCC agent session manager.");
	
	// set end flag
	session_mgr->end_flag = true;
	
	// wait until keepalive thread has finished
	pthread_join(session_mgr->pt_keepalive, NULL);
	
	// wait until manager thread has finished
	pthread_join(session_mgr->pt_session, NULL);
	
	// close socket
	if (session_mgr->sock > 0)
		close(session_mgr->sock);
		
	// free buffer list
	cbcc_buffer_list_free(&session_mgr->buffer_list);
		
	// destroy mutex
	pthread_mutex_destroy(&session_mgr->rcv_mt);
	pthread_mutex_destroy(&session_mgr->send_mt);
	
	// free ssl settings
	finalize_ssl_settings(session_mgr->c);
	
	return;
}

// send message via session
int cbcc_session_send_msg(cbcc_agent_session_mgr_t *session_mgr, const char *msg)
{
	cbcc_tlv_buffer_list_t tlvs;
	
	pthread_mutex_lock(&session_mgr->send_mt);
	
	// build tlv message
	cbcc_tlv_buffer_build(msg, &tlvs);
	
	// send tlv message
	if (session_mgr->c->no_ssl)
		send_tlv_buffer(session_mgr->sock, &tlvs);
	else
		ssl_send_tlv_buffer(session_mgr->ssl_params.ssl, &tlvs);
	
	// free tlv list
	cbcc_tlv_buffer_free(&tlvs);
	
	pthread_mutex_unlock(&session_mgr->send_mt);
	
	return 0;
}

// receive message via session
int cbcc_session_recv_msg(cbcc_agent_session_mgr_t *session_mgr, char *msg, size_t msg_size)
{
	unsigned char cmd_buf[CBCC_MAX_SOCK_BUF_LEN];
	int ret;
	
	pthread_mutex_lock(&session_mgr->rcv_mt);
	
	while (1)
	{
		cbcc_buffer_t *buf = NULL;
		int completed = 0;
		
		// receive message
		if (session_mgr->c->no_ssl)
			ret = recv(session_mgr->sock, cmd_buf, sizeof(cmd_buf), 0);
		else
			ret = SSL_read(session_mgr->ssl_params.ssl, cmd_buf, sizeof(cmd_buf));
	
		// add tlv buffers into list
		if (cbcc_buffer_add(&session_mgr->buffer_list, session_mgr->sock, cmd_buf, ret, &buf, &completed) != 0)
		{
			CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "CMD: Parsing TLV buffer from socket '%d'", session_mgr->sock);
			ret = -1;
			
			cbcc_buffer_free(&session_mgr->buffer_list, session_mgr->sock);
			
			break;
		}

		if (completed)
		{
			snprintf(msg, msg_size, "%s", buf->buffer);
			ret = buf->len;
			
			// free buffer
			cbcc_buffer_free(&session_mgr->buffer_list, session_mgr->sock);
			
			break;
		}
	}
	
	pthread_mutex_unlock(&session_mgr->rcv_mt);

	return ret;
}

// free SSL info
static void free_ssl_info(cbcc_agent_session_mgr_t *session_mgr)
{
	if (session_mgr->c->no_ssl)
		return;
	
	if (!session_mgr->ssl_params.ssl)
		return;
	
	SSL_free(session_mgr->ssl_params.ssl);
	session_mgr->ssl_params.ssl = NULL;
	
	return;
}

// start SSL connection
static int start_ssl_connection(cbcc_agent_session_mgr_t *session_mgr)
{
	cbcc_ssl_params_t *ssl_params = &session_mgr->ssl_params;
	int err;
	
	if (session_mgr->c->no_ssl)
		return 0;
	
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "SESSION: Starting SSL connection with server");
	
	// create new ssl session and set client socket into ssl
	ssl_params->ssl = SSL_new(ssl_params->ctx);
	if (!ssl_params->ssl)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "SESSION: Could not create SSL structure due to '%s'", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}
	
	SSL_set_fd(ssl_params->ssl, session_mgr->sock);
	
	// accepting SSL request
	err = SSL_connect(ssl_params->ssl);
	if (err < 0)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "SESSION: SSL connection with server has failed due to '%s'",
				ERR_error_string(ERR_get_error(), NULL));
		
		free_ssl_info(session_mgr);
		
		return -1;
	}
	
	return 0;
}

// connect to cbccd
static int connect_to_cbccd(cbcc_agent_session_mgr_t *session_mgr)
{
	cbcc_agent_opt_t *agent_opt = &session_mgr->c->opt;
	
	struct sockaddr_in addr;
	
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "SESSION: Try to connect to cbccd '%s:%d'", agent_opt->accd_srv_name, agent_opt->accd_srv_port);
	
	// create socket
	session_mgr->sock = create_socket();
	if (session_mgr->sock < 0)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "SESSION: Could not create socket for connecting.(%s)", strerror(errno));
		return -1;
	}

	// set server address to connect
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(agent_opt->accd_srv_name);
	addr.sin_port = htons(agent_opt->accd_srv_port);

	if (connect(session_mgr->sock, (struct sockaddr *) &addr, sizeof(addr)) != 0)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "SESSION: Could not connect to cbccd server(%s)", strerror(errno));
		
		close(session_mgr->sock);
		session_mgr->sock = -1;
		
		return -1;
	}
	
	// start SSL connection
	if (start_ssl_connection(session_mgr) != 0)
	{
		close(session_mgr->sock);
		session_mgr->sock = -1;
		
		return -1;
	}

	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "SESSION: Connecting to cbccd has succeeded.");
	
	return 0;
}

static void make_login_json_for_OpenWRT(cbcc_agent_session_mgr_t *session_mgr)
{
	char *customer_ret = NULL;
	char *hostname_ret = NULL;
	char *password_ret = NULL;
	char *secret_ret = NULL;
	char *guid_ret = NULL;
	char *address_ret = NULL;

	char address[64];
	char customer[16];
	char hostname[16];
	char password[64];
	char secret[64];
	char guid[32];

	const char *roles[] = 
	{
		CBCC_CMD_MONITOR,
		CBCC_CMD_ADMIN,
		CBCC_CMD_REPORT,
		CBCC_CMD_CONFIG,
		NULL
	};
	
	//Login info
	get_host_info_from_system(&customer_ret, &hostname_ret, &password_ret, &secret_ret, &guid_ret);
	
	if(customer_ret != NULL) {
		strcpy(customer, customer_ret);
		free(customer_ret);
	}
	if(hostname_ret != NULL) {
		strcpy(hostname, hostname_ret);
		free(hostname_ret);
	}
	if(password_ret != NULL) {
		strcpy(password, password_ret);
		free(password_ret);
	}
	if(secret_ret != NULL) {
		strcpy(secret, secret_ret);
		free(secret_ret);
	}
	if(guid_ret != NULL) {
		strcpy(guid, guid_ret);
		free(guid_ret);
	}

	//Device Info
	address_ret = get_address_from_network_info();

	if(address_ret != NULL){
		strcpy(address, address_ret);
		free(address_ret);
	}

	//Device Inventory
	char Mainboard_Version[128];
	snprintf(Mainboard_Version, sizeof(Mainboard_Version), "");

	char Mainboard_Vendor[128];
	snprintf(Mainboard_Vendor, sizeof(Mainboard_Vendor), "Intel Corporation");
	char Mainboard_Product[128];
	snprintf(Mainboard_Product, sizeof(Mainboard_Product), "440BX Desktop Reference Platform");
	char System_Linux[128];
    snprintf(System_Linux, sizeof(System_Linux), "Linux version 3.8.6-cbsg40-smp (root@ry) (gcc version 4.3.4 [gcc-4_3-branch revision 152973] (SUSE Linux) ) #1 SMP Fri Nov 20 18:35:31 KST 2015");
    int Network_MaxSize = 10000000;
    char Network_DeviceName[128];
    snprintf(Network_DeviceName, sizeof(Network_DeviceName), "eth0");
    char Network_MACAddress[128];
    snprintf(Network_MACAddress, sizeof(Network_MACAddress), "00:0c:29:75:b9:e2");
    char Network_Vendor[128];
    snprintf(Network_Vendor, sizeof(Network_Vendor), "Advanced Micro Devices [AMD]");
    char Network_Product[128];
    snprintf(Network_Product, sizeof(Network_Product), "79c970 [PCnet32 LANCE]");
    char BIOS_Version[128];
    snprintf(BIOS_Version, sizeof(BIOS_Version), "6.00");
    char BIOS_Vendor[128];
    snprintf(BIOS_Vendor, sizeof(BIOS_Vendor), "Phoenix Technologies LTD");
    int Memory_MaxSize = 263737728;
    char Memory_Size[128];
    snprintf(Memory_Size, sizeof(Memory_Size), "536870912");
    char Memory_Banks_Size[128];
    snprintf(Memory_Banks_Size, sizeof(Memory_Banks_Size), "536870912");
    char Memory_Banks_Description[128];
    snprintf(Memory_Banks_Description, sizeof(Memory_Banks_Description), "DIMM DRAM EDO");
    char Storage_CDRom_Size[128];
    snprintf(Storage_CDRom_Size, sizeof(Storage_CDRom_Size), "");
    char Storage_CDRom_Product[128];
    snprintf(Storage_CDRom_Product, sizeof(Storage_CDRom_Product), "");
    char Storage_CDRom_Description[128];
    snprintf(Storage_CDRom_Description, sizeof(Storage_CDRom_Description), "DVD-RAM writer");
    char Storage_Harddisk_Size[128];
    snprintf(Storage_Harddisk_Size, sizeof(Storage_Harddisk_Size), "524836480");
    char Storage_Harddisk_Product[128];
    snprintf(Storage_Harddisk_Product, sizeof(Storage_Harddisk_Product), "");
    char Storage_Harddisk_Description[128];
    snprintf(Storage_Harddisk_Description, sizeof(Storage_Harddisk_Description), "SCSI Disk");
    int CPU_VirtualCores = 8;
    char CPU_Clock[128];
    snprintf(CPU_Clock, sizeof(CPU_Clock), "3591.704");
    char CPU_Vendor[128];
    snprintf(CPU_Vendor, sizeof(CPU_Vendor), "GenuineIntel");
    char CPU_Product[128];
    snprintf(CPU_Product, sizeof(CPU_Product), "Intel(R) Core(TM) i7-4790 CPU @ 3.60GHz");

	char *login_final_buff;
	char *tmp_login_buff;
	/************************* For login, common ********************************/
	cbcc_json_object_t cbcc_login_jobjs[] =	
	{		
		{
			.key = "config.common",
			.type = CBCC_JSON_DATA_TYPE_OBJECT,
		},
			{
				.key = "customer",
				.parent_key = "config.common",
				.type = CBCC_JSON_DATA_TYPE_STRING,
				.data.str_val_set = customer,
			},
			{
				.key = "hostname",
				.parent_key = "config.common",
				.type = CBCC_JSON_DATA_TYPE_STRING,
				.data.str_val_set = hostname,
			},
		{
			.key = "secret",
			.type = CBCC_JSON_DATA_TYPE_STRING,
			.data.str_val_set = secret,
		},
		{
			.key = "password",
			.type = CBCC_JSON_DATA_TYPE_STRING,
			.data.str_val_set = password,
		},
		{
			.key = "guid",
			.type = CBCC_JSON_DATA_TYPE_STRING,
			.data.str_val_set = guid,
		},
		{
			.key = "device.product",
			.type = CBCC_JSON_DATA_TYPE_OBJECT,
		},
			{
				.key = "product",
				.parent_key = "device.product",
				.type = CBCC_JSON_DATA_TYPE_OBJECT,
			},
				{
					.key = "acronym",
					.parent_key = "product",
					.type = CBCC_JSON_DATA_TYPE_STRING,
					.data.str_val_set = "MiniCBSG",
				},
				{
					.key = "version",
					.parent_key = "product",
					.type = CBCC_JSON_DATA_TYPE_STRING,
					.data.str_val_set = "101",
				},
				{
					.key = "serial",
					.parent_key = "product",
					.type = CBCC_JSON_DATA_TYPE_STRING,
					.data.str_val_set = "",
				},
				{
					.key = "model",
					.parent_key = "product",
					.type = CBCC_JSON_DATA_TYPE_STRING,
					.data.str_val_set = "",
				},
				{
					.key = "name",
					.parent_key = "product",
					.type = CBCC_JSON_DATA_TYPE_STRING,
					.data.str_val_set = "MiniCBSG",
				},
				{
					.key = "submodel",
					.parent_key = "product",
					.type = CBCC_JSON_DATA_TYPE_STRING,
					.data.str_val_set = "",
				},
				{
					.key = "description",
					.parent_key = "product",
					.type = CBCC_JSON_DATA_TYPE_STRING,
					.data.str_val_set = "MiniCBSG",
				},
				{
					.key = "lineage",
					.parent_key = "product",
					.type = CBCC_JSON_DATA_TYPE_STRING,
					.data.str_val_set = "MIniCBSGv101",
				},
				{
					.key = "type",
					.parent_key = "product",
					.type = CBCC_JSON_DATA_TYPE_STRING,
					.data.str_val_set = "mini_device",
				},
			{
				.key = "vendor",
				.parent_key = "device.product",
				.type = CBCC_JSON_DATA_TYPE_OBJECT,
			},
				{
					.key = "url",
					.parent_key = "vendor",
					.type = CBCC_JSON_DATA_TYPE_STRING,
					.data.str_val_set = "http://cholbyok.com",
				},
				{
					.key = "name",
					.parent_key = "vendor",
					.type = CBCC_JSON_DATA_TYPE_STRING,
					.data.str_val_set = "IST",
				},
	};

	//for json_login save
	cbcc_json_build(cbcc_login_jobjs, CBCC_JOBJS_COUNT(cbcc_login_jobjs), &tmp_login_buff);
	login_final_buff = tmp_login_buff;

	/************************** For Device.info *********************************/
	cbcc_json_object_t cbcc_device_info_jobjs[] =
	{
		{
			.key = "device.info",
			.type = CBCC_JSON_DATA_TYPE_OBJECT,
		},
			{
				.key = "roles",
				.parent_key = "device.info",
				.type = CBCC_JSON_DATA_TYPE_OBJ_ARRAY,
				.obj_exist_data = true,
				.data.str_val_set = roles,
			},
			{
				.key = "status",
				.parent_key = "device.info",
				.type = CBCC_JSON_DATA_TYPE_OBJECT,
			},
				{
					.key = "connection",
					.parent_key = "status",
					.type = CBCC_JSON_DATA_TYPE_STRING,
					.must_specify = true,
					.data.str_val_set = "ONLINE",
				},
				{
					.key = "registration",
					.parent_key = "status",
					.type = CBCC_JSON_DATA_TYPE_STRING,
					.data.str_val_set = "CONFIRMED",
				},
				{
					.key = "timestamp",
					.parent_key = "status",
					.type = CBCC_JSON_DATA_TYPE_INT,
					.data.int_val_set = 0,
				},
				{
					.key = "device",
					.parent_key = "status",
					.type = CBCC_JSON_DATA_TYPE_STRING,
					.data.str_val_set = "PINGABLE",
				},
			{
				.key = "name",
				.parent_key = "device.info",
				.type = CBCC_JSON_DATA_TYPE_STRING,
				.data.str_val_set = customer,
			},
			{
				.key = "address",
				.parent_key = "device.info",
				.type = CBCC_JSON_DATA_TYPE_OBJECT,
			},
				{
					.key = "ipv4_public",
					.parent_key = "address",
					.type = CBCC_JSON_DATA_TYPE_STRING,
					.data.str_val_set = address,
				},
				{
					.key = "ipv4_agent",
					.parent_key = "address",
					.type = CBCC_JSON_DATA_TYPE_STRING,
					.data.str_val_set = address,
				},
	};

	//for json_service
	cbcc_json_add(login_final_buff, cbcc_device_info_jobjs, CBCC_JOBJS_COUNT(cbcc_device_info_jobjs), &tmp_login_buff);
	login_final_buff = tmp_login_buff;

	/************************** For Device.inventory ****************************/
	cbcc_json_object_t cbcc_device_inventory_jobjs[] =
	{
		{
			.key = "device.inventory",
			.type = CBCC_JSON_DATA_TYPE_OBJECT,
		},
			{
				.key = "Mainboard",
				.parent_key = "device.inventory",
				.type = CBCC_JSON_DATA_TYPE_OBJECT,
			},
				{
					.key = "Version",
					.parent_key = "Mainboard",
					.type = CBCC_JSON_DATA_TYPE_STRING,
					.data.str_val_set = Mainboard_Version,
				},
				{
					.key = "Vendor",
					.parent_key = "Mainboard",
					.type = CBCC_JSON_DATA_TYPE_STRING,
					.data.str_val_set = Mainboard_Vendor,
				},
				{
					.key = "Product",
					.parent_key = "Mainboard",
					.type = CBCC_JSON_DATA_TYPE_STRING,
					.data.str_val_set = Mainboard_Product,
				},
			{
				.key = "System",
				.parent_key = "device.inventory",
				.type = CBCC_JSON_DATA_TYPE_OBJECT,
			},
				{
					.key = "Linux",
					.parent_key = "System",
					.type = CBCC_JSON_DATA_TYPE_STRING,
					.data.str_val_set = System_Linux,
				},
			{
				.key = "Network",
				.parent_key = "device.inventory",
				.type = CBCC_JSON_DATA_TYPE_OBJECT,
			},
				{
					.key = "MaxSize",
					.parent_key = "Network",
					.type = CBCC_JSON_DATA_TYPE_INT,
					.data.int_val_set = Network_MaxSize,
				},
				{
					.key = "DeviceName",
					.parent_key = "Network",
					.type = CBCC_JSON_DATA_TYPE_STRING,
					.data.str_val_set = Network_DeviceName,
				},
				{
					.key = "MACAddress",
					.parent_key = "Network",
					.type = CBCC_JSON_DATA_TYPE_STRING,
					.data.str_val_set = Network_MACAddress,
				},
				{
					.key = "Vendor",
					.parent_key = "Network",
					.type = CBCC_JSON_DATA_TYPE_STRING,
					.data.str_val_set = Network_Vendor,
				},
				{
					.key = "Product",
					.parent_key = "Network",
					.type = CBCC_JSON_DATA_TYPE_STRING,
					.data.str_val_set = Network_Product,
				},
			{
				.key = "BIOS",
				.parent_key = "device.inventory",
				.type = CBCC_JSON_DATA_TYPE_OBJECT,
			},
				{
					.key = "Version",
					.parent_key = "BIOS",
					.type = CBCC_JSON_DATA_TYPE_STRING,
					.data.str_val_set = BIOS_Version,
				},
				{
					.key = "Vendor",
					.parent_key = "BIOS",
					.type = CBCC_JSON_DATA_TYPE_STRING,
					.data.str_val_set = BIOS_Vendor,
				},
			{
				.key = "Memory",
				.parent_key = "device.inventory",
				.type = CBCC_JSON_DATA_TYPE_OBJECT,
			},
				{
					.key = "MaxSize",
					.parent_key = "Memory",
					.type = CBCC_JSON_DATA_TYPE_INT,
					.data.int_val_set = Memory_MaxSize,
				},
				{
					.key = "Size",
					.parent_key = "Memory",
					.type = CBCC_JSON_DATA_TYPE_STRING,
					.data.str_val_set = Memory_Size,
				},
				{
					.key = "Banks",
					.parent_key = "Memory",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "Size",
						.parent_key = "Banks",
						.type = CBCC_JSON_DATA_TYPE_STRING, 
						.data.str_val_set = Memory_Banks_Size,
					},
					{
						.key = "Description",
						.parent_key = "Banks",
						.type = CBCC_JSON_DATA_TYPE_STRING, 
						.data.str_val_set = Memory_Banks_Description,
					},
			{
				.key = "Storage",
				.parent_key = "device.inventory",
				.type = CBCC_JSON_DATA_TYPE_OBJECT,
			},
				{
					.key = "CDRom",
					.parent_key = "Storage",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "Size",
						.parent_key = "CDRom",
						.type = CBCC_JSON_DATA_TYPE_STRING, 
						.data.str_val_set = Storage_CDRom_Size,
					},
					{
						.key = "Product",
						.parent_key = "CDRom",
						.type = CBCC_JSON_DATA_TYPE_STRING, 
						.data.str_val_set = Storage_CDRom_Product,
					},
					{
						.key = "Description",
						.parent_key = "CDRom",
						.type = CBCC_JSON_DATA_TYPE_STRING, 
						.data.str_val_set = Storage_CDRom_Description,
					},
				{
					.key = "Harddisk",
					.parent_key = "Storage",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "Size",
						.parent_key = "Harddisk",
						.type = CBCC_JSON_DATA_TYPE_STRING, 
						.data.str_val_set = Storage_Harddisk_Size,
					},
					{
						.key = "Product",
						.parent_key = "Harddisk",
						.type = CBCC_JSON_DATA_TYPE_STRING, 
						.data.str_val_set = Storage_Harddisk_Product,
					},
					{
						.key = "Description",
						.parent_key = "Harddisk",
						.type = CBCC_JSON_DATA_TYPE_STRING, 
						.data.str_val_set = Storage_Harddisk_Description,
					},
			{
				.key = "CPU",
				.parent_key = "device.inventory",
				.type = CBCC_JSON_DATA_TYPE_OBJECT,
			},
				{
					.key = "VIrtualCores",
					.parent_key = "CPU",
					.type = CBCC_JSON_DATA_TYPE_INT,
					.data.int_val_set = CPU_VirtualCores,
				},
				{
					.key = "Clock",
					.parent_key = "CPU",
					.type = CBCC_JSON_DATA_TYPE_STRING,
					.data.str_val_set = CPU_Clock,
				},
				{
					.key = "Vendor",
					.parent_key = "CPU",
					.type = CBCC_JSON_DATA_TYPE_STRING,
					.data.str_val_set = CPU_Vendor,
				},
				{
					.key = "Product",
					.parent_key = "CPU",
					.type = CBCC_JSON_DATA_TYPE_STRING,
					.data.str_val_set = CPU_Product,
				},
	};

	cbcc_json_add(login_final_buff, cbcc_device_inventory_jobjs, CBCC_JOBJS_COUNT(cbcc_device_inventory_jobjs), &tmp_login_buff);
	login_final_buff = tmp_login_buff;

	char *final_fpath = "/etc/cbcc-agent/login_data.json";
	FILE *login_final_file = fopen(final_fpath, "w");
	if(login_final_file == NULL) {
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "SESSION: Can not open '%s'", final_fpath);
		return;
	}

	fwrite(login_final_buff, 1, strlen(login_final_buff), login_final_file);
	fclose(login_final_file);

	free(login_final_buff);

	return;
}

// get login data from confd
static int get_login_data_from_confd(cbcc_agent_session_mgr_t *session_mgr, char **login_data)
{
	make_login_json_for_OpenWRT(session_mgr);

	char *login_data_fpath = "/etc/cbcc-agent/login_data.json";
	
	// reencode file contents
	if (cbcc_json_read_from_file(login_data_fpath, login_data) != 0)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "LOGIN: Login data from %s isn't JSON format", login_data_fpath);
		return -1;
	}
	
	return 0;
}

// login into cbccd
static int login_into_cbccd(cbcc_agent_session_mgr_t *session_mgr)
{
	char *login_cmd;
	char login_resp[CBCC_MAX_CMD_RESP_LEN];
	
	char *login_data;
	
	int resp_code;
	
	// check login flag
	if (session_mgr->logined)
		return 0;
	
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "LOGIN: Try login to cbccd...");
	
	// get login data from confd
	if (get_login_data_from_confd(session_mgr, &login_data) < 0)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "LOGIN: Could not get login data from confd.");
		return -1;
	}

	// build login command
	cbcc_json_object_t cbcc_login_cmd_objs[] =
	{
		{
			.key = "cmd",
			.type = CBCC_JSON_DATA_TYPE_STRING,
			.data.str_val_set = CBCC_CMD_LOGIN,
		},
		{
			.key = "data",
			.type = CBCC_JSON_DATA_TYPE_OBJECT,
			.obj_exist_data = true,
			.data.str_val_set = login_data
		},
	};
	
	// build json string for login command
	cbcc_json_build(cbcc_login_cmd_objs, sizeof(cbcc_login_cmd_objs) / sizeof(cbcc_json_object_t), &login_cmd);
	
	// send login command
	if (cbcc_session_send_msg(session_mgr, login_cmd) < 0)
	{
		free(login_cmd);
		free(login_data);

		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "SESSION: Sending login command to server has been failed.");
		return -1;
	}
	
	free(login_cmd);
	free(login_data);

	// get response for login
	if (cbcc_session_recv_msg(session_mgr, login_resp, sizeof(login_resp)) < 0)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "SESSION: Receiving msg from server has been failed.");
		return -1;
	}

	// parse login response
	cbcc_json_object_t cbcc_login_resp_objs[] =
	{
		{
			.key = "code",
			.type = CBCC_JSON_DATA_TYPE_INT,
			.data.int_val = &resp_code,
		}
	};
	
	if (cbcc_json_parse_from_buffer(login_resp, cbcc_login_resp_objs, sizeof(cbcc_login_resp_objs) / sizeof(cbcc_json_object_t)) != 0)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "LOGIN: Could not parse response data from cbccd.");
		return 0;
	}
	
	if (resp_code == CBCC_RESP_OK)
	{
		CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "LOGIN: Login to cbccd has succeeded.");
		session_mgr->logined = true;
	}
	else
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "LOGIN: Login to cbccd has failed(errcode: %d)", resp_code);
	}
	
	return 0;
}

// process commands
static const char *cbcc_cmd_names[] =
{
	CBCC_CMD_LOGIN,
	CBCC_CMD_MONITOR,
	CBCC_CMD_DEPLOY,
	CBCC_CMD_CREATE_BACKUP,
	CBCC_CMD_RESTORE_BACKUP,
	CBCC_CMD_ACTION,
	CBCC_CMD_REPORT,
	CBCC_CMD_AGENT_DISABLE,
	CBCC_CMD_CHECK_CONFIG,
	CBCC_CMD_KEEPALIVE,
	CBCC_CMD_OPENPORT,
	NULL
};

void cbcc_cmd_openport(struct _cbcc_agent_ctx *c, const char *cmd_data)
{
	char admin_srcip[CBCC_MAX_GUID_LEN];

	memset(admin_srcip, 0, CBCC_MAX_GUID_LEN);

	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_VERBOSE, "SESSION: Processing openport command data '%s'", cmd_data);

	//parse admin_srcip to open 4444 port
	cbcc_json_object_t openport_jobjs[] = 
	{
		{
			.key = "admin_srcip",
			.type = CBCC_JSON_DATA_TYPE_STRING,
			.data.str_val = admin_srcip,
			.data_size = CBCC_MAX_GUID_LEN
		}
	};

	if (cbcc_json_parse_from_buffer(cmd_data, openport_jobjs, CBCC_JOBJS_COUNT(openport_jobjs)) != 0)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "SESSION: Could not parse openport command.");
		return;
	}

	//Write Confd /etc/config/
	char script_cmd[CBCC_MAX_SCRIPT_CMD_LEN];
	snprintf(script_cmd, CBCC_MAX_SCRIPT_CMD_LEN, "/etc/./fw_manage add %s", admin_srcip);
	system(script_cmd);

	// create thread for session manager
	cbcc_agent_session_mgr_t *session_mgr = &c->session_mgr;

	cbcc_admin_srcip_info_t *admin_info;
	admin_info = (cbcc_admin_srcip_info_t *) malloc(sizeof(cbcc_admin_srcip_info_t));
	memset(admin_info, 0, sizeof(cbcc_admin_srcip_info_t));

	strcpy(admin_info->admin_srcip, admin_srcip);
	admin_info->is_connected = true;
	add_admin_info(session_mgr, admin_info);

	return;
}

static void process_cmds(cbcc_agent_ctx_t *c, const char *cmd)
{
	char cmd_name[CBCC_MAX_CMD_NAME_LEN];
	char *cmd_data = NULL;
	
	enum CBCC_CMD_CODES cmd_code = CBCC_CMD_CODE_UNKNOWN;
	
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_VERBOSE, "CMD: Process command '%s'", cmd);
	
	cbcc_json_object_t cmd_objs[] =
	{
		{
			.key = "cmd",
			.type = CBCC_JSON_DATA_TYPE_STRING,
			.data.str_val = cmd_name,
			.data_size = sizeof(cmd_name)
		},
		{
			.key = "data",
			.type = CBCC_JSON_DATA_TYPE_OBJECT_BIG,
			.data.str_val_big = &cmd_data,
		}
	};
	
	// parse command
	if (cbcc_json_parse_from_buffer(cmd, cmd_objs, CBCC_JOBJS_COUNT(cmd_objs)) != 0)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "CMD: Could not parse command '%s'", cmd);
		return;
	}
	
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "CMD: Process command '%s'", cmd_name);
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_VERBOSE, "CMD: Command is '%s', command data is '%s'", cmd_name, cmd_data);
	
	// get command code
	for (unsigned int i = 0; i < CBCC_CMD_CODE_UNKNOWN; i++)
	{
		if (!cbcc_cmd_names[i])
			break;
		
		if (strcmp(cmd_name, cbcc_cmd_names[i]) == 0)
		{
			cmd_code = i;
			break;
		}
	}
	
	if (cmd_code == CBCC_CMD_CODE_UNKNOWN)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "CMD: Unknown command '%s'", cmd_name);
		
		if (cmd_data)
			free(cmd_data);
		
		return;
	}
	
	// process command
	switch (cmd_code)
	{
		case CBCC_CMD_CODE_DEPLOY_OBJ:
			cbcc_config_deploy_set_data(c, cmd_data);
			break;

		case CBCC_CMD_CODE_CREATE_BACKUP:
			cbcc_admin_create_backup(c, cmd_data);
			break;
			
		case CBCC_CMD_CODE_RESTORE_BACKUP:
			cbcc_admin_restore_backup(c, cmd_data);
			break;
		
		case CBCC_CMD_CODE_ACTION:
			cbcc_admin_action(c, cmd_data);
			break;
		
		case CBCC_CMD_CODE_AGENT_DISABLE:
			cbcc_agent_stop(c);
			break;
		
		case CBCC_CMD_CODE_CHECK_CONFIG:
			cbcc_config_check(c);
			break;

		case CBCC_CMD_CODE_OPENPORT:
			cbcc_cmd_openport(c, cmd_data);
			break;
		
		default:
			break;
	}
	
	if (cmd_data)
		free(cmd_data);
	
	return;
}

// process commands from cbccd
static void process_cmds_from_cbccd(cbcc_agent_session_mgr_t *session_mgr)
{
	cbcc_agent_opt_t *agent_opt = &session_mgr->c->opt;
	fd_set fds;
	
	// set socket as non-blocking mode
	set_non_blocking_sock(session_mgr->sock);
	
	// init socket set
	FD_ZERO(&fds);
	FD_SET(session_mgr->sock, &fds);
	
	// get commmands from cbccd server by async mode
	while (1)
	{
		struct timeval tv;
		fd_set tmp_fds;
		
		int ret;
		
		unsigned char cmd_buf[CBCC_MAX_SOCK_BUF_LEN];
		
		tv.tv_sec = 0;
		tv.tv_usec = 50 * 1000;
		
		// check end flag
		if (session_mgr->end_flag)
			return;
		
		// copy socket set
		memcpy(&tmp_fds, &fds, sizeof(fd_set));
		
		// async select call
		ret = select(session_mgr->sock + 1, &tmp_fds, NULL, NULL, &tv);
		if (ret == -1)
		{
			CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "SESSION: Async I/O for session socket has failed due to %s", strerror(errno));
			return;
		}
		
		// check if socket has I/O event
		if (!FD_ISSET(session_mgr->sock, &tmp_fds))
			continue;
		
		do
		{	
			// receive command
			if (session_mgr->c->no_ssl)
				ret = recv(session_mgr->sock, cmd_buf, sizeof(cmd_buf), 0);
			else
				ret = SSL_read(session_mgr->ssl_params.ssl, cmd_buf, sizeof(cmd_buf));

			if (ret > 0)
			{
				cbcc_buffer_t *buf = NULL;
				int completed = 0;
			
				// lock mutex
				pthread_mutex_lock(&session_mgr->rcv_mt);
			
				// add tlv buffers into list
				if (cbcc_buffer_add(&session_mgr->buffer_list, session_mgr->sock, cmd_buf, ret, &buf, &completed) != 0)
				{
					CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "CMD: Parsing TLV buffer from socket '%d'", session_mgr->sock);
					pthread_mutex_unlock(&session_mgr->rcv_mt);
				
					continue;
				}
			
				if (completed)
				{
					// process command
					process_cmds(session_mgr->c, (const char *) buf->buffer);
				
					// free buffer
					cbcc_buffer_free(&session_mgr->buffer_list, session_mgr->sock);
				}
			
				// unlock mutex
				pthread_mutex_unlock(&session_mgr->rcv_mt);
				
				break;
			}
			else if (ret == 0)
			{
				CBCC_DEBUG_WARN(CBCC_DEBUG_LEVEL_NOR, "SESSION: The connection with CBCCD server has terminated");
				return;
			}
			else
			{
				// if reading is in pending state, then continue
				if (errno == EWOULDBLOCK)
					continue;
				
				if (session_mgr->c->no_ssl)
				{
					CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "SESSION: The connection with CBCCD server has terminated abnormally due to '%s'",
								strerror(errno));
				}
				else
				{
					CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "SESSION: The connection with CBCCD server has terminated abnormally due to '%s'",
								ERR_error_string(ERR_get_error(), NULL));
				}
			
				return;
			}
		}
		while (1);
	}
	
	return;
}

// session manager thread proc
static void *session_mgr_proc(void *p)
{
	cbcc_agent_session_mgr_t *session_mgr = (cbcc_agent_session_mgr_t *) p;
	
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "SESSION: Starting CBCC sessoin management thread.");
	
	while (!session_mgr->end_flag)
	{
		// check session is established
		if (!session_mgr->session_established)
		{
			// if session is not established, then try connect
			if (connect_to_cbccd(session_mgr) != 0)
			{
				sleep(CBCC_AGENT_CONNECT_INTERVAL);
				continue;
			}
			
			session_mgr->session_established = true;
			
			sleep(1);
		}

		// login into cbccd
		if (login_into_cbccd(session_mgr) != 0)
		{
			// close client socket
			close(session_mgr->sock);
			
			// free ssl info
			free_ssl_info(session_mgr);

			// set session establishing flag
			session_mgr->session_established = false;
			
			continue;
		}
		else
		{
			// check login status
			if (!session_mgr->logined)
			{
				sleep(CBCC_AGENT_LOGIN_INTERVAL);
				continue;
			}
		}
		
		// process commands from cbccd
		process_cmds_from_cbccd(session_mgr);
		
		// if command process is existed, then set flags for session
		session_mgr->session_established = false;
		session_mgr->logined = false;
	}
	
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "SESSION: Stopped CBCC session management thread.");
	
	return 0;
}

static void check_admin_link_status(cbcc_agent_session_mgr_t *session_mgr, time_t curr_tm)
{
	cbcc_admin_srcip_info_t *admin_info = session_mgr->admin_list.admin_infos;
	while (admin_info)
	{
		char fpath[CBCC_MAX_PATH];
		snprintf(fpath, CBCC_MAX_PATH, "/etc/conntrackd/%s", admin_info->admin_srcip);

		char script_cmd[CBCC_MAX_SCRIPT_CMD_LEN];
		snprintf(script_cmd, CBCC_MAX_SCRIPT_CMD_LEN, "netstat -apn | grep 4444 | grep %s | grep ESTABLISHED > %s", admin_info->admin_srcip, fpath);
		CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_VERBOSE, "SESSION: Running script '%s'", script_cmd);
		system(script_cmd);

		FILE *fp = fopen(fpath, "r");
		if (!fp)
		{
			CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "SESSION: Could not read /etc/connected/%s", admin_info->admin_srcip);
			return;
		}
		char buf[CBCC_MAX_GUID_LEN];
		memset(buf, 0, CBCC_MAX_GUID_LEN);

		fgets(buf, CBCC_MAX_GUID_LEN, fp);
		fclose(fp);
	
		//check connected status
		if (admin_info->is_connected)
		{
			if (!strncmp(buf, "tcp", 3))
			{
				// CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "SESSION: link status: ESTABLISHED");
				admin_info = admin_info->next;
				continue;
			}
			else
			{
				CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "SESSION: link status: Just Dropped '%s'", admin_info->admin_srcip);
				admin_info->is_connected = false;
				admin_info->droped_tm = curr_tm;
			}
		}
		else
		{
			if (!strncmp(buf, "tcp", 3))
			{
				CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "SESSION: link status: Just Connected '%s'", admin_info->admin_srcip);
				admin_info->is_connected = true;
				admin_info = admin_info->next;
				continue;
			}
			else
			{
				// CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "SESSION: link status: Not ESTABLISHED");
				if (curr_tm - admin_info->droped_tm > CBCC_MAX_WEB_LINK_INTERVAL + 5)
				{
					//delete from allow webadmin confd
					//Delete Confd///////////////////////////////////////////
					snprintf(script_cmd, CBCC_MAX_SCRIPT_CMD_LEN, "/etc/./fw_manage delete %s", admin_info->admin_srcip);
					system(script_cmd);

					if (session_mgr->admin_list.admin_infos == admin_info)
					{
						session_mgr->admin_list.admin_infos = admin_info->next;
						if (admin_info->next)
							admin_info->next->prev = NULL;
					}
					else
					{
						if (admin_info->prev)
							admin_info->prev->next = admin_info->next;
						if (admin_info->next)
							admin_info->next->prev = admin_info->prev;
					}

					session_mgr->admin_list.srcip_num--;
				}
			}
		}
		admin_info = admin_info->next;
	}

	return;
}

//add admin srcip into admin_info_t
void add_admin_info(cbcc_agent_session_mgr_t *session_mgr, cbcc_admin_srcip_info_t *admin_info)
{
	// add device info to list
	if (session_mgr->admin_list.srcip_num == 0)
	{
		session_mgr->admin_list.admin_infos = admin_info;
	}
	else
	{
		cbcc_admin_srcip_info_t *p = session_mgr->admin_list.admin_infos;
		while (p->next)
			p = p->next;
		
		p->next = admin_info;
		admin_info->prev = p;
	}
	
	// increate count of devices
	session_mgr->admin_list.srcip_num++;
	
	return;
}

static void *link_webadmin_proc(void *p)
{
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_HIGH, "SESSION: Started webadmin management thread.");

	cbcc_agent_session_mgr_t *session_mgr = (cbcc_agent_session_mgr_t *) p;

	while (!session_mgr->end_flag)
	{	
		time_t curr_tm = time(NULL);
		check_admin_link_status(session_mgr, curr_tm);

		sleep(5);
	}
		
	return;
}

static void *keepalive_proc(void *p)
{
	cbcc_agent_session_mgr_t *session_mgr = (cbcc_agent_session_mgr_t *) p;

	bool first_time = true;
	time_t sent_tm = time(NULL);
	
	char *cmd = NULL;
	
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "SESSION: Started keepalive proc");
	
	// build command for keepalive
	cbcc_json_object_t keepalive_cmd_jobjs[] =
	{
		{
			.key = "cmd",
			.type = CBCC_JSON_DATA_TYPE_STRING,
			.data.str_val_set = CBCC_CMD_KEEPALIVE,
		}
	};
	
	cbcc_json_build(keepalive_cmd_jobjs, CBCC_JOBJS_COUNT(keepalive_cmd_jobjs), &cmd);
	
	while (!session_mgr->end_flag)
	{
		bool send_flag = false;
		time_t curr_tm = time(NULL);

		// check login flag
		if (!session_mgr->logined)
		{
			sleep(1);
			continue;
		}
		
		// check send flag
		if (first_time)
		{
			first_time = false;
			send_flag = true;
		}
		else
		{
			if ((curr_tm - sent_tm) > CBCC_KEEPALIVE_INTERVAL)
				send_flag = true;
		}
		
		if (!send_flag)
		{
			sleep(1);
			continue;
		}
		
		// send keepalive command
		cbcc_session_send_msg(session_mgr, cmd);
		
		// set sent time
		sent_tm = curr_tm;
	}
	
	CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "SESSION: Stopped keepalive proc");
	
	// free command buffer
	free(cmd);
	
	return 0;
}
