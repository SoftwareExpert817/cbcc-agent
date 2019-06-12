
#include "cbcc_agent.h"

#include <sys/stat.h>

#define CBCC_GLOBAL_NETWORK_NETWORK_NAME		"global.network.network"

#define FIREWALL_FPATH							"/etc/config/firewall"
#define DEFINITION_FPATH						"/etc/config/definition"

//set configuration data into OpenWRT deployed by cbccd
static void OpenWRT_set_object()
{
	char *fp;
	char *fpath;

	struct stat st;

	// get json data from file
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_VERBOSE, "CONFIG: Getting json data from file /etc/cbcc-agent/cbcc-agent.conf.");

	char config_fpath[CBCC_MAX_PATH];
	snprintf(config_fpath, sizeof(config_fpath), CBCC_CONF_CACHE_FILE_PATH);
	char *config_data;

	if (read_file_contents(config_fpath, &config_data) < 0)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "MON: Could not read JSON data from %s", config_fpath);
		return;
	}

	cbcc_json_array_t *deploy_objs;
	deploy_objs = (cbcc_json_array_t *) malloc(sizeof(cbcc_json_array_t));
	memset(deploy_objs, 0, sizeof(cbcc_json_array_t));

	cbcc_json_object_t deploy_jobjs[] =
	{
		{
			.key = "deploy.objects",
			.type = CBCC_JSON_DATA_TYPE_OBJ_ARRAY,
			.must_specify = true,
			.data.arr_val = deploy_objs,
		},
	};

	if (cbcc_json_parse_from_buffer(config_data, deploy_jobjs, CBCC_JOBJS_COUNT(deploy_jobjs)) != 0)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "DEPLOY: Could not parse 'deploy.objects' from command '%s'.", config_data);
		return;
	}

	// make definition_tmp buffer to store only internal definitions, not CBCC definitions.
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_VERBOSE, "CONFIG: Make definition temporary buffer to store only internal definitions. Not CBCC deployed definitions.");

	fpath = DEFINITION_FPATH;
	if ((fp = fopen(fpath, "r")) == NULL)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "CONFIG: Could not read definition file /etc/config/definition. Configuring failed");
		return;
	}

	if (stat(fpath, &st) != 0)
		return;
	char *definition_tmp;
	definition_tmp = (char *) malloc(st.st_size + 1);
	memset(definition_tmp, 0, st.st_size + 1);

	char buf[128];
	int fp_pos = 0;

	while (fgets(buf, sizeof(buf), fp))
	{
		if (strncmp(buf, "config", 6) == 0)
		{
			fp_pos = ftell(fp) - strlen(buf);
			fgets(buf, sizeof(buf), fp);
			if (strncmp((buf + (strlen(buf) - 8)), "(CBCC)'", 7) != 0)
			{
				fseek(fp, fp_pos, SEEK_SET);
				fread(definition_tmp, 1, st.st_size + 1, fp);
				break;
			}
		}
	}

	fclose(fp);

	//make firewall_tmp buffer to store only internal firewalls, not CBCC firewalls.
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_VERBOSE, "CONFIG: Make firewall temporary buffer to store only internal firewalls. Not CBCC deployed firewalls.");

	fp_pos = 0;
	fp = NULL;

	fpath = FIREWALL_FPATH;
	if ((fp = fopen(fpath, "r")) == NULL)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "CONFIG: Could not read firewall file /etc/config/firewall.");
		return;
	}
	if (stat(fpath, &st) != 0)
		return;
	char *firewall_tmp;
	firewall_tmp = (char *) malloc(st.st_size + 1);
	memset(firewall_tmp, 0, st.st_size + 1);
	
	while (fgets(buf, sizeof(buf), fp))
	{
		if (strncmp(buf, "config", 6) == 0)
		{
			fp_pos = ftell(fp) - strlen(buf);
			fgets(buf, sizeof(buf), fp);
			if (strncmp((buf + (strlen(buf) - 8)), "(CBCC)'", 7) != 0)
			{
				fseek(fp, fp_pos, SEEK_SET);
				fread(firewall_tmp, 1, st.st_size + 1, fp);
				break;
			}
		}
	}

	fclose(fp);

	//make buffers for each deploy objects by type
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_VERBOSE, "CONFIG: Make buffers for each CBCC deployed objects by type.");

	char *definition_deploy;
	char *firewall_deploy;

	definition_deploy = (char *) malloc(strlen(config_data));
	memset(definition_deploy, 0, strlen(config_data));
	firewall_deploy = (char *) malloc(strlen(config_data));
	memset(firewall_deploy, 0, strlen(config_data));

	char deploy_data[512] = {0, };

	//get deploy_type
	char deploy_type[CBCC_MAX_CMD_NAME_LEN] = {0, };
	char deploy_guid[CBCC_MAX_CMD_NAME_LEN] = {0, };
	char deploy_data_name[CBCC_MAX_CMD_NAME_LEN] = {0, };
	char deploy_data_type[CBCC_MAX_CMD_NAME_LEN] = {0, };
	char deploy_data_address[CBCC_MAX_CMD_NAME_LEN] = {0, };
	char deploy_data_netmask[CBCC_MAX_CMD_NAME_LEN] = {0, };
	char deploy_data_class[CBCC_MAX_CMD_NAME_LEN] = {0, };
	char deploy_data_src[CBCC_MAX_CMD_NAME_LEN] = {0, };
	char deploy_data_dst[CBCC_MAX_CMD_NAME_LEN] = {0, };
	char deploy_data_source[CBCC_MAX_CMD_NAME_LEN] = {0, };
	char deploy_data_destination[CBCC_MAX_CMD_NAME_LEN] = {0, };
	char deploy_data_service[CBCC_MAX_CMD_NAME_LEN] = {0, };
	char deploy_data_action[CBCC_MAX_CMD_NAME_LEN] = {0, };
	char real_data_source[CBCC_MAX_CMD_NAME_LEN] = {0, };
	char real_data_destination[CBCC_MAX_CMD_NAME_LEN] = {0, };
	char real_data_service[CBCC_MAX_CMD_NAME_LEN] = {0, };
	char real_data_src[CBCC_MAX_CMD_NAME_LEN] = {0, };
	char real_data_dst[CBCC_MAX_CMD_NAME_LEN] = {0, };
	char real_src_mask[CBCC_MAX_CMD_NAME_LEN] = {0, };
	char real_dst_mask[CBCC_MAX_CMD_NAME_LEN] = {0, };
	char deploy_data_icmp_tc[CBCC_MAX_CMD_NAME_LEN] = {0, };

	for (int i = 0; i < deploy_objs->arr_len; i++)
	{
		char *deploy_each_val = deploy_objs->data.str_vals[i];

		cbcc_json_object_t deploy_each_type_jobj[] =
		{
			//what type is deploy object?
			{
				.key = "class",
				.parent_key = "data",
				.type = CBCC_JSON_DATA_TYPE_STRING,
				.data.str_val = deploy_data_class,
				.data_size = sizeof(deploy_data_class),
			},
			//network definition and service definition
			{
				.key = "name",
				.parent_key = "data",
				.type = CBCC_JSON_DATA_TYPE_STRING,
				.data.str_val = deploy_data_name,
				.data_size = sizeof(deploy_data_name),
			},
			{
				.key = "type",
				.parent_key = "data",
				.type = CBCC_JSON_DATA_TYPE_STRING,
				.data.str_val = deploy_data_type,
				.data_size = sizeof(deploy_data_type),
			},
			{
				.key = "address",
				.parent_key = "data",
				.type = CBCC_JSON_DATA_TYPE_STRING,
				.data.str_val = deploy_data_address,
				.data_size = sizeof(deploy_data_address),
			},
			{
				.key = "netmask",
				.parent_key = "data",
				.type = CBCC_JSON_DATA_TYPE_STRING,
				.data.str_val = deploy_data_netmask,
				.data_size = sizeof(deploy_data_netmask),
			},
			//case global.packetfilter.packetfilter
			{
				.key = "source",
				.parent_key = "data",
				.type = CBCC_JSON_DATA_TYPE_STRING,
				.data.str_val = deploy_data_source,
				.data_size = sizeof(deploy_data_source),
			},
			{
				.key = "destination",
				.parent_key = "data",
				.type = CBCC_JSON_DATA_TYPE_STRING,
				.data.str_val = deploy_data_destination,
				.data_size = sizeof(deploy_data_destination),
			},
			{
				.key = "service",
				.parent_key = "data",
				.type = CBCC_JSON_DATA_TYPE_STRING,
				.data.str_val = deploy_data_service,
				.data_size = sizeof(deploy_data_service),
			},
			{
				.key = "action",
				.parent_key = "data",
				.type = CBCC_JSON_DATA_TYPE_STRING,
				.data.str_val = deploy_data_action,
				.data_size = sizeof(deploy_data_action),
			},
			//service type: tcp, udp, tcpudp;
			{
				.key = "src",
				.parent_key = "data",
				.type = CBCC_JSON_DATA_TYPE_STRING,
				.data.str_val = deploy_data_src,
				.data_size = sizeof(deploy_data_src),
			},
			{
				.key = "dst",
				.parent_key = "data",
				.type = CBCC_JSON_DATA_TYPE_STRING,
				.data.str_val = deploy_data_dst,
				.data_size = sizeof(deploy_data_dst),
			},
			// service type: icmp
			{
				.key = "icmp_tc",
				.parent_key = "data",
				.type = CBCC_JSON_DATA_TYPE_STRING,
				.data.str_val = deploy_data_icmp_tc,
				.data_size = sizeof(deploy_data_icmp_tc),
			},
		};
		if (cbcc_json_parse_from_buffer(deploy_each_val, deploy_each_type_jobj, CBCC_JOBJS_COUNT(deploy_each_type_jobj)) !=0)
		{
			CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "DEPLOY: Could not parse 'deploy.type' from command '%s'.", deploy_each_val);
			return;
		}

		//do operation for each deploy_type
		if (strcmp(deploy_data_class, "network") == 0)
		{
			memset(deploy_data, 0, sizeof(deploy_data));

			if (strcmp(deploy_data_type, "host") == 0)
			{
				snprintf(deploy_data, sizeof(deploy_data), "config network \n\toption name '%s(CBCC)'\n\toption comment 'CBCC'\n\toption net_type '%s'\n\toption ipaddr '%s'\n\toption netmask_host '32'\n\n", deploy_data_name, deploy_data_type, deploy_data_address);
			}
			else
			{
				snprintf(deploy_data, sizeof(deploy_data), "config network \n\toption name '%s(CBCC)'\n\toption comment 'CBCC'\n\toption net_type '%s'\n\toption ipaddr '%s'\n\toption netmask '%s'\n\n", deploy_data_name, deploy_data_type, deploy_data_address, deploy_data_netmask);
			}
			
			strcat(definition_deploy, deploy_data);
		}
		else if (strcmp(deploy_data_class, "service") == 0)
		{
			memset(deploy_data, 0, sizeof(deploy_data));

			if (strcmp(deploy_data_type, "tcp") == 0 || strcmp(deploy_data_type, "udp") == 0 || strcmp(deploy_data_type, "tcpudp") == 0)
			{
				snprintf(deploy_data, sizeof(deploy_data), "config service \n\toption name '%s(CBCC)'\n\toption comment 'CBCC'\n\toption protocol '%s'\n\toption src_port '%s'\n\toption dest_port '%s'\n\n", deploy_data_name, deploy_data_type, deploy_data_src, deploy_data_dst);
			}
			else if (strcmp(deploy_data_type, "ah") == 0)
			{
				snprintf(deploy_data, sizeof(deploy_data), "config service \n\toption name '%s(CBCC)'\n\toption comment 'CBCC'\n\toption protocol '%s'\n\toption ah_protocol '256:4294967295'\n\n", deploy_data_name, deploy_data_type);
			}
			else if (strcmp(deploy_data_type, "esp") == 0)
			{
				snprintf(deploy_data, sizeof(deploy_data), "config service \n\toption name '%s(CBCC)'\n\toption comment 'CBCC'\n\toption protocol '%s'\n\toption esp_protocol '256:4294967295'\n\n", deploy_data_name, deploy_data_type);
			}
			else if (strcmp(deploy_data_type, "icmp") == 0)
			{
				char icmp_type_str[32];
				memset(icmp_type_str, 0, sizeof(icmp_type_str));

				if (!strcmp(deploy_data_icmp_tc, "00_00"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "echo-reply");
				else if (!strcmp(deploy_data_icmp_tc, "03_00"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "network-unreachable");
				else if (!strcmp(deploy_data_icmp_tc, "03_01"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "host-unreachable");
				else if (!strcmp(deploy_data_icmp_tc, "03_02"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "protocol-unreachable");
				else if (!strcmp(deploy_data_icmp_tc, "03_03"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "port-unreachable");
				else if (!strcmp(deploy_data_icmp_tc, "03_04"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "fragmentation-needed");
				else if (!strcmp(deploy_data_icmp_tc, "03_05"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "source-route-failed");
				else if (!strcmp(deploy_data_icmp_tc, "03_06"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "network-unknown");
				else if (!strcmp(deploy_data_icmp_tc, "03_07"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "host-unknown");
				else if (!strcmp(deploy_data_icmp_tc, "03_09"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "network-prohibited");
				else if (!strcmp(deploy_data_icmp_tc, "03_10"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "host-prohibited");
				else if (!strcmp(deploy_data_icmp_tc, "03_11"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "TOS-network-unreachable");
				else if (!strcmp(deploy_data_icmp_tc, "03_12"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "TOS-host-unreachable");
				else if (!strcmp(deploy_data_icmp_tc, "03_13"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "communication-prohibited");
				else if (!strcmp(deploy_data_icmp_tc, "03_14"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "host-precedence-violation");
				else if (!strcmp(deploy_data_icmp_tc, "03_15"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "precedence-cutoff");
				else if (!strcmp(deploy_data_icmp_tc, "04_00"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "source-quench");
				else if (!strcmp(deploy_data_icmp_tc, "05_00"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "network-redirect");
				else if (!strcmp(deploy_data_icmp_tc, "05_01"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "host-redirect");
				else if (!strcmp(deploy_data_icmp_tc, "05_02"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "TOS-network-redirect");
				else if (!strcmp(deploy_data_icmp_tc, "05_03"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "TOS-host-redirect");
				else if (!strcmp(deploy_data_icmp_tc, "08_00"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "echo-request");
				else if (!strcmp(deploy_data_icmp_tc, "09_00"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "router-advertisement");
				else if (!strcmp(deploy_data_icmp_tc, "09_16"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "router-solicitation");
				else if (!strcmp(deploy_data_icmp_tc, "11_00"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "ttl-zero-during-transit");
				else if (!strcmp(deploy_data_icmp_tc, "11_01"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "ttl-zero-during-reassembly");
				else if (!strcmp(deploy_data_icmp_tc, "12_00"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "parameter-problem");
				else if (!strcmp(deploy_data_icmp_tc, "12_01"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "required-option-missing");
				else if (!strcmp(deploy_data_icmp_tc, "12_02"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "ip-header-bad");
				else if (!strcmp(deploy_data_icmp_tc, "14_00"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "timestamp-reply");
				else if (!strcmp(deploy_data_icmp_tc, "15_00"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "timestamp-request");
				else if (!strcmp(deploy_data_icmp_tc, "17_00"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "address-mask-request");
				else if (!strcmp(deploy_data_icmp_tc, "18_00"))
					snprintf(icmp_type_str, sizeof(icmp_type_str), "address-mask-reply");

				snprintf(deploy_data, sizeof(deploy_data), "\nconfig service \n\t option name '%s(CBCC)'\n\t option comment 'CBCC'\n\t option protocol '%s'\n\t option icmp_type '%s'\n", deploy_data_name, deploy_data_type, icmp_type_str);
			}

			strcat(definition_deploy, deploy_data);
		}
		else if (strcmp(deploy_data_class, "packetfilter") == 0)
		{
			memset(real_data_src, 0, CBCC_MAX_CMD_NAME_LEN);
			memset(real_data_dst, 0, CBCC_MAX_CMD_NAME_LEN);
			for (int j = 0; j < deploy_objs->arr_len; j++)
			{
				char *tmp_val = deploy_objs->data.str_vals[j];
				cbcc_json_object_t tmp_jobjs[] =
				{
					{
						.key = "guid",
						.type = CBCC_JSON_DATA_TYPE_STRING,
						.data.str_val = deploy_guid,
						.data_size = sizeof(deploy_guid),
					},
					{
						.key = "type",
						.type = CBCC_JSON_DATA_TYPE_STRING,
						.data.str_val = deploy_type,
						.data_size = sizeof(deploy_type),
					},
					{
						.key = "address",
						.parent_key = "data",
						.type = CBCC_JSON_DATA_TYPE_STRING,
						.data.str_val = deploy_data_address,
						.data_size = sizeof(deploy_data_address),
					},
					{
						.key = "netmask",
						.parent_key = "data",
						.type = CBCC_JSON_DATA_TYPE_STRING,
						.data.str_val = deploy_data_netmask,
						.data_size = sizeof(deploy_data_netmask),
					},
					{
						.key = "type",
						.parent_key = "data",
						.type = CBCC_JSON_DATA_TYPE_STRING,
						.data.str_val = deploy_data_type,
						.data_size = sizeof(deploy_data_type),
					},
					{
						.key = "dst",
						.parent_key = "data",
						.type = CBCC_JSON_DATA_TYPE_STRING,
						.data.str_val = deploy_data_dst,
						.data_size = sizeof(deploy_data_dst),
					},
					{
						.key = "src",
						.parent_key = "data",
						.type = CBCC_JSON_DATA_TYPE_STRING,
						.data.str_val = deploy_data_src,
						.data_size = sizeof(deploy_data_src),
					},
				};
				cbcc_json_parse_from_buffer(tmp_val, tmp_jobjs, CBCC_JOBJS_COUNT(tmp_jobjs));

				//do not compare with himself
				if (strcmp(deploy_type, "global.packetfilter.packetfilter") == 0)
					continue;

				if (strcmp(deploy_guid, deploy_data_source) == 0)
				{
					memcpy(real_data_source, deploy_data_address, CBCC_MAX_CMD_NAME_LEN);
					if (strcmp(deploy_data_type, "host") == 0)
					{
						snprintf(real_src_mask, sizeof(real_src_mask), "32");
					}
					else
					{
						strcpy(real_src_mask, deploy_data_netmask);
					}
					
					//no continue because case of same source and destination.
				}
				if (strcmp(deploy_guid, deploy_data_destination) == 0)
				{
					memcpy(real_data_destination, deploy_data_address, CBCC_MAX_CMD_NAME_LEN);
					if (strcmp(deploy_data_type, "host") == 0)
					{
						snprintf(real_dst_mask, sizeof(real_dst_mask), "32");
					}
					else
					{
						strcpy(real_dst_mask, deploy_data_netmask);
					}
					continue;
				}
				else if (strcmp(deploy_guid, deploy_data_service) == 0)
				{
					strcpy(real_data_service, deploy_data_type);
					strcpy(real_data_dst, deploy_data_dst);
					strcpy(real_data_src, deploy_data_src);

					continue;
				}
				else
					continue;
			}

			memset(deploy_data, 0, sizeof(deploy_data));

			if (strcmp(real_data_service, "tcp") == 0 || strcmp(real_data_service, "tcpudp") == 0 || strcmp(real_data_service, "udp") == 0)
			{
				if (strcmp(deploy_data_action, "accept") == 0)
				{
					snprintf(deploy_data, sizeof(deploy_data), "config rule\n\toption name '%s(CBCC)'\n\toption src 'global'\n\toption dest '*'\n\toption comment 'CBCC'\n\toption src_ip '%s/%s'\n\toption dest_ip '%s/%s'\n\toption proto '%s'\n\toption src_port '%s'\n\toption dest_port '%s'\n\toption extra '-j zone_local_forward'\n\toption enabled '1'\n\n", deploy_data_name, real_data_source, real_src_mask, real_data_destination, real_dst_mask, real_data_service, real_data_src, real_data_dst);	
				}
				else if (strcmp(deploy_data_action, "drop") == 0)
				{
					snprintf(deploy_data, sizeof(deploy_data), "config rule\n\toption name '%s(CBCC)'\n\toption src 'global'\n\toption dest '*'\n\toption comment 'CBCC'\n\toption src_ip '%s/%s'\n\toption dest_ip '%s/%s'\n\toption proto '%s'\n\toption src_port '%s'\n\toption dest_port '%s'\n\toption target 'DROP'\n\toption enabled '1'\n\n", deploy_data_name, real_data_source, real_src_mask, real_data_destination, real_dst_mask, real_data_service, real_data_src, real_data_dst);
				}
				else if (strcmp(deploy_data_action, "reject") == 0)
				{
					snprintf(deploy_data, sizeof(deploy_data), "config rule\n\toption name '%s(CBCC)'\n\toption src 'global'\n\toption dest '*'\n\toption comment 'CBCC'\n\toption src_ip '%s/%s'\n\toption dest_ip '%s/%s'\n\toption proto '%s'\n\toption src_port '%s'\n\toption dest_port '%s'\n\toption target 'REJECT'\n\toption enabled '1'\n\n", deploy_data_name, real_data_source, real_src_mask, real_data_destination, real_dst_mask, real_data_service, real_data_src, real_data_dst);
				}

				strcat(firewall_deploy, deploy_data);
			}
		}
	}

	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_VERBOSE, "CONFIG: Classify all deploy objects has been succeded.");

	fpath = DEFINITION_FPATH;
	if ((fp = fopen(fpath, "w")) == NULL)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "CONFIG: Could not finalize definition file /etc/config/definition.");
		return;
	}

	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_VERBOSE, "CONFIG: Writing definitions deployed from CBCCD: '%s'", definition_deploy);
	fwrite(definition_deploy, 1, strlen(definition_deploy), fp);

	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_VERBOSE, "CONFIG: Writing definitions defined by internal user: '%s'", definition_tmp);
	fwrite(definition_tmp, 1, strlen(definition_tmp), fp);
	fclose(fp);

	fpath = FIREWALL_FPATH;
	if ((fp = fopen(fpath, "w")) == NULL)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "CONFIG: Could not finalize firewall file /etc/config/firewall.");
		return;
	}

	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_VERBOSE, "CONFIG: Writing firewalls deployed from CBCCD: '%s'", firewall_deploy);
	fwrite(firewall_deploy, 1, strlen(firewall_deploy), fp);

	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_VERBOSE, "CONFIG: Writing firewalls defined by internal user: '%s'", firewall_tmp);
	fwrite(firewall_tmp, 1, strlen(firewall_tmp), fp);
	fclose(fp);

	//restart firewall
	char script_cmd[CBCC_MAX_SCRIPT_CMD_LEN];
	snprintf(script_cmd, CBCC_MAX_SCRIPT_CMD_LEN, "/etc/init.d/firewall restart > /dev/null 2>&1");
	system(script_cmd);

	free(definition_deploy);
	free(firewall_deploy);
	free(definition_tmp);
	free(firewall_tmp);

	return;
}

// set configuration data deployed by cbccd
void cbcc_config_deploy_set_data(struct _cbcc_agent_ctx *c, const char *cmd_data)
{
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "DEPLOY: Deploying objects from '%s'", cmd_data);
	
	// write cache into file
	FILE *cache_fp = fopen(CBCC_CONF_CACHE_FILE_PATH, "w");
	if (!cache_fp)
	{
		CBCC_DEBUG_WARN(CBCC_DEBUG_LEVEL_NOR, "DEPLOY: Could not open cache file '%s' for writting", CBCC_CONF_CACHE_FILE_PATH);
	}
	else
	{
		fwrite(cmd_data, 1, strlen(cmd_data), cache_fp);
		fclose(cache_fp);
	}

	OpenWRT_set_object();
	
	return;
}

// build command to get configuration
static void build_config_cmd(char **cmd)
{
	char md5sum[CBCC_MD5SUM_LEN * 2 + 1];
	
	// get md5sum of config cache
	memset(md5sum, 0, sizeof(md5sum));
	get_md5sum_of_file(CBCC_CONF_CACHE_FILE_PATH, false, md5sum, sizeof(md5sum));
	
	// build command
	cbcc_json_object_t config_cmd_jobjs[] =
	{
		{
			.key = "cmd",
			.type = CBCC_JSON_DATA_TYPE_STRING,
			.data.str_val_set = CBCC_CMD_DEPLOY,
		},
		{
			.key = "data",
			.type = CBCC_JSON_DATA_TYPE_OBJECT,
		},
		{
			.key = "md5sum",
			.type = CBCC_JSON_DATA_TYPE_STRING,
			.parent_key = "data",
			.data.str_val_set = md5sum,
		}
	};
	
	cbcc_json_build(config_cmd_jobjs, CBCC_JOBJS_COUNT(config_cmd_jobjs), cmd);
	
	return;
}

// send deploy.objects command
static void send_deploy_objects_cmd(cbcc_agent_config_t *conf_mgr)
{
	char *cmd = NULL;
	
	// build command
	build_config_cmd(&cmd);
	
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_HIGH, "CONFIG: Sending deploy.objects command");
	
	// send command
	cbcc_session_send_msg(&conf_mgr->c->session_mgr, cmd);
	
	// free command
	free(cmd);

	return;
}

// thread proc to get configurations
static void *get_config_proc(void *p)
{
	cbcc_agent_config_t *conf_mgr = (cbcc_agent_config_t *) p;
	
	bool first_time = true;
	time_t sent_tm = time(NULL);
	
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "CONFIG: Started configuration downloading thread.");
	
	while (!conf_mgr->end_flag)
	{
		bool send_flag = false;
		time_t curr_tm = time(NULL);
		
		// check login flag
		if (!conf_mgr->c->session_mgr.logined)
		{
			sleep(1);
			continue;
		}
		
		if (first_time)
		{
			first_time = false;
			send_flag = true;
		}
		else
		{
			if ((curr_tm - sent_tm) > CBCC_CONFIG_DB_FETCH_INTERVAL)
				send_flag = true;
		}
		
		if (!send_flag)
		{
			sleep(1);
			continue;
		}
		
		// send deploying objects command
		send_deploy_objects_cmd(conf_mgr);
		
		// set sent time
		sent_tm = curr_tm;
	}
	
	CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "CONFIG: Stopped configuration downloading thread.");
	
	return 0;
}

// send deploy.objects command to check modified configs
void cbcc_config_check(struct _cbcc_agent_ctx *c)
{
	send_deploy_objects_cmd(&c->conf_mgr);
	return;
}

// initialize configuration
int cbcc_agent_config_init(struct _cbcc_agent_ctx *c)
{
	cbcc_agent_config_t *conf_mgr = &c->conf_mgr;
	
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "CONFIG: Initializing configuration manager.");
	
	// set context object
	conf_mgr->c = c;
	
	// create thread to get configuration thread
	if (pthread_create(&conf_mgr->pt_conf, NULL, get_config_proc, (void *) conf_mgr) != 0)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "CONFIG: Could not create thread to get configurations");
		return -1;
	}
	
	conf_mgr->init_flag = true;
	
	return 0;
}

// finalize configuration
void cbcc_agent_config_finalize(cbcc_agent_config_t *conf_mgr)
{
	if (!conf_mgr->init_flag)
		return;
	
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "CONFIG: Finalizing configuration manager.");
	
	// set end flag
	conf_mgr->end_flag = true;
	
	// wait until thread has finished
	pthread_join(conf_mgr->pt_conf, NULL);
	
	return;
}
