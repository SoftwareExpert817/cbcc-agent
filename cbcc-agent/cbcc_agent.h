#ifndef __CBCC_AGENT_H__
#define __CBCC_AGENT_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "cbcc_common.h"

#include "cbcc_util.h"
#include "cbcc_debug.h"
#include "cbcc_json.h"
#include "cbcc_buffer.h"
#include "cbcc_sock.h"

struct _cbcc_agent_ctx;

#include "cbcc_session.h"
#include "cbcc_monitor.h"
#include "cbcc_config.h"
#include "cbcc_admin.h"

// CBCC agent option
typedef struct _cbcc_agent_opt
{
	char accd_srv_name[CBCC_MAX_HNAME_LEN];
	int accd_srv_port;
	
	char login_data_fpath[CBCC_MAX_PATH];
	char monitor_data_fpath[CBCC_MAX_PATH];
	
	char set_script_path[CBCC_MAX_PATH];
	char get_script_path[CBCC_MAX_PATH];
	char man_script_path[CBCC_MAX_PATH];
	char report_script_path[CBCC_MAX_PATH];
} cbcc_agent_opt_t;

// CBCC agent context struct
typedef struct _cbcc_agent_ctx
{
	bool no_ssl;
	cbcc_agent_opt_t opt;						// cbcc agent options

	cbcc_agent_session_mgr_t session_mgr;		// cbcc agent session manager
	cbcc_agent_config_t conf_mgr;				// cbcc agent configuration manager
	cbcc_agent_monitor_t mon_mgr;				// cbcc agent monitor
} cbcc_agent_ctx_t;

// stop cbcc agent
void cbcc_agent_stop(struct _cbcc_agent_ctx *c);

#endif		// __CBCC_AGENT_H__
