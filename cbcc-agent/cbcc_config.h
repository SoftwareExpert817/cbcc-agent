#ifndef __CBCC_CONFIG_H__
#define __CBCC_CONFIG_H__

// cbcc agent configuration manager
typedef struct _cbcc_agent_config
{
	bool init_flag;
	bool end_flag;
	
	pthread_t pt_conf;

	struct _cbcc_agent_ctx *c;
} cbcc_agent_config_t;

// set configuration data deployed by cbccd
void cbcc_config_deploy_set_data(struct _cbcc_agent_ctx *c, const char *cmd_data);
void cbcc_config_check(struct _cbcc_agent_ctx *c);

// initialize and finalize configuration
int cbcc_agent_config_init(struct _cbcc_agent_ctx *c);
void cbcc_agent_config_finalize(cbcc_agent_config_t *conf_mgr);

#endif			// __CBCC_CONFIG_H__
