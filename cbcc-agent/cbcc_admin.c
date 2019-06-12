
#include "cbcc_agent.h"

// send result of created backup
static void send_create_backup_res(struct _cbcc_agent_ctx *c, cbcc_backup_info_t *backup_info)
{
	char *create_backup_cmd;
	
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "ADMIN: Sending create.backup result");
	
	// build command data
	cbcc_json_object_t backup_res_jobjs[] =
	{
		{
			.key = "cmd",
			.type = CBCC_JSON_DATA_TYPE_STRING,
			.data.str_val_set = CBCC_CMD_CREATE_BACKUP
		},
		{
			.key = "data",
			.type = CBCC_JSON_DATA_TYPE_OBJECT,
		},
		{
			.key = "auto_backup",
			.type = CBCC_JSON_DATA_TYPE_INT,
			.parent_key = "data",
			.data.int_val_set = backup_info->auto_backup ? 1 : 0
		},
		{
			.key = "guid",
			.type = CBCC_JSON_DATA_TYPE_STRING,
			.parent_key = "data",
			.data.str_val_set = backup_info->guid,
		},
		{
			.key = "comment",
			.type = CBCC_JSON_DATA_TYPE_STRING,
			.parent_key = "data",
			.data.str_val_set = backup_info->comment,
		},
		{
			.key = "filesize",
			.type = CBCC_JSON_DATA_TYPE_INT,
			.parent_key = "data",
			.data.int_val_set = backup_info->file_size,
		},
		{
			.key = "md5sum",
			.type = CBCC_JSON_DATA_TYPE_STRING,
			.parent_key = "data",
			.data.str_val_set = backup_info->md5sum,
		},
		{
			.key = "base64_encoded",
			.type = CBCC_JSON_DATA_TYPE_STRING,
			.parent_key = "data",
			.data.str_val_set = backup_info->base64_encoded,
		},
		{
			.key = "version",
			.type = CBCC_JSON_DATA_TYPE_STRING,
			.parent_key = "data",
			.data.str_val_set = backup_info->version,
		},
		{
			.key = "user",
			.type = CBCC_JSON_DATA_TYPE_STRING,
			.parent_key = "data",
			.data.str_val_set = backup_info->user,
		}
	};
	
	cbcc_json_build(backup_res_jobjs, CBCC_JOBJS_COUNT(backup_res_jobjs), &create_backup_cmd);
	
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_VERBOSE, "ADMIN: Sending create.backup result '%s'", create_backup_cmd);

	// send message to CBCC
	cbcc_session_send_msg(&c->session_mgr, create_backup_cmd);
	
	// free command buffer
	free(create_backup_cmd);
	
	return;
}

// create backup
void cbcc_admin_create_backup(struct _cbcc_agent_ctx *c, const char *cmd_data)
{
	cbcc_backup_info_t backup_info;
	char *script_param = NULL;
	
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "ADMIN: Parsing create.backup command data '%s'", cmd_data);
	
	// initialize backup info
	memset(&backup_info, 0, sizeof(backup_info));
	
	// parse backup params
	cbcc_json_object_t backup_params_jobjs[] =
	{
		{
			.key = "guid",
			.type = CBCC_JSON_DATA_TYPE_STRING,
			.parent_key = "backup.objects",
			.data.str_val = backup_info.guid,
			.data_size = sizeof(backup_info.guid)
		},
		{
			.key = "comment",
			.type = CBCC_JSON_DATA_TYPE_STRING,
			.parent_key = "backup.objects",
			.data.str_val = backup_info.comment,
			.data_size = sizeof(backup_info.comment)
		},
		{
			.key = "auto_backup",
			.type = CBCC_JSON_DATA_TYPE_BOOLEAN,
			.parent_key = "backup.objects",
			.data.bool_val = &backup_info.auto_backup,
		},
		{
			.key = "user",
			.type = CBCC_JSON_DATA_TYPE_STRING,
			.parent_key = "backup.objects",
			.data.str_val = backup_info.user,
			.data_size = sizeof(backup_info.user)
		}
	};
	
	if (cbcc_json_parse_from_buffer(cmd_data, backup_params_jobjs, CBCC_JOBJS_COUNT(backup_params_jobjs)) != 0)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "ADMIN: Could not parse command data '%s'", cmd_data);
		return;
	}

	//make backup file
	char cmd[CBCC_MAX_PATH];
	char backup_fname[CBCC_MAX_PATH];

	if (!strcmp(backup_info.comment, ""))
	{
		time_t tt = time(NULL);
		struct tm *tm = localtime(&tt);

		char curr_date[128];
		strftime(curr_date, sizeof(curr_date), "%Y-%m-%d-%H:%M", tm);

		snprintf(backup_fname, sizeof(backup_fname), "/tmp/%s.tar.gz", curr_date);		
		// snprintf(backup_fpath, sizeof(backup_fpath), "tar cvzf %s.tar.gz /etc/config", curr_date);
	}
	else
		snprintf(backup_fname, sizeof(backup_fname), "/tmp/%s.tar.gz", backup_info.comment);

	snprintf(cmd, sizeof(cmd), "tar cvzf %s /etc/config", backup_fname);

	system(cmd);

	memcpy(backup_info.file_path, backup_fname, sizeof(backup_info.file_path));
	snprintf(backup_info.version, sizeof(backup_info.version), "MiniCBSG101");
	
	// set other backup result info
	if ((backup_info.file_size = get_file_size(backup_info.file_path)) <= 0)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "ADMIN: Invalid backup file '%s'", backup_info.file_path);
		return;
	}
	
	// get md5sum
	if (get_md5sum_of_file(backup_info.file_path, 1, backup_info.md5sum, sizeof(backup_info.md5sum)) != 0)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "ADMIN: Could not get md5sum for file '%s'", backup_info.file_path);
		return;
	}
	
	// get base64 encoded data
	if (get_base64_encoded_from_file(backup_info.file_path, &backup_info.base64_encoded) != 0)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "ADMIN: Could not get base64 encoded data from backup file '%s'", backup_info.file_path);
		return;
	}

	// send backup result
	send_create_backup_res(c, &backup_info);
	
	// free base64 encoded string
	free(backup_info.base64_encoded);
	
	return;
}

// parse backup info for restoring
static int parse_backup_info(const char *cmd_data, cbcc_backup_info_t *backup_info)
{
	cbcc_json_object_t backup_info_jobjs[] =
	{
		{
			.key = "auto_backup",
			.type = CBCC_JSON_DATA_TYPE_INT,
			.data.int_val = &backup_info->auto_backup
		},
		{
			.key = "guid",
			.type = CBCC_JSON_DATA_TYPE_STRING,
			.data.str_val = backup_info->guid,
			.data_size = sizeof(backup_info->guid)
		},
		{
			.key = "comment",
			.type = CBCC_JSON_DATA_TYPE_STRING,
			.data.str_val = backup_info->comment,
			.data_size = sizeof(backup_info->comment)
		},
		{
			.key = "filesize",
			.type = CBCC_JSON_DATA_TYPE_INT,
			.data.int_val = &backup_info->file_size,
		},
		{
			.key = "md5sum",
			.type = CBCC_JSON_DATA_TYPE_STRING,
			.data.str_val = backup_info->md5sum,
			.data_size = sizeof(backup_info->md5sum)
		},
		{
			.key = "base64_encoded",
			.type = CBCC_JSON_DATA_TYPE_STRING_BIG,
			.data.str_val_big = &backup_info->base64_encoded,
		},
		{
			.key = "version",
			.type = CBCC_JSON_DATA_TYPE_STRING,
			.data.str_val = backup_info->version,
			.data_size = sizeof(backup_info->version)
		},
		{
			.key = "user",
			.type = CBCC_JSON_DATA_TYPE_STRING,
			.data.str_val = backup_info->user,
			.data_size = sizeof(backup_info->user)
		}
	};
	
	if (cbcc_json_parse_from_buffer(cmd_data, backup_info_jobjs, CBCC_JOBJS_COUNT(backup_info_jobjs)) != 0)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "ADMIN: Could not parse JSON buffer for setting backup info");
		return -1;
	}
	
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_HIGH, "ADMIN: Parsing restore.backup info has succeeded.");

	return 0;
}

// do restore backup
static void do_restore_backup(cbcc_agent_ctx_t *c, cbcc_backup_info_t *backup_info)
{
	char backup_fpath[CBCC_MAX_PATH];
	char cmd_script[CBCC_MAX_PATH];

	memcpy(backup_fpath, backup_info->file_path, sizeof(backup_fpath));

	snprintf(cmd_script, sizeof(cmd_script), "tar xvzf %s", backup_fpath);

	system(cmd_script);	
	
	return;
}

// restore backup
void cbcc_admin_restore_backup(struct _cbcc_agent_ctx *c, const char *cmd_data)
{
	cbcc_backup_info_t backup_info;
	
	// initialize backup info
	memset(&backup_info, 0, sizeof(backup_info));
	
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "ADMIN: Processing restore.backup command.");
	
	// parse backup info
	if (parse_backup_info(cmd_data, &backup_info) != 0)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "ADMIN: Could not parse backup info for restoring");
		return;
	}
	
	// call script to restore backup
	do_restore_backup(c, &backup_info);

	return;
}

// do action
static void do_action(cbcc_agent_ctx_t *c, const char *act_guid, const char *act_str)
{
	if (!strcmp(act_str, "install_pattern"))
	{
		char script_cmd[CBCC_MAX_PATH];
		snprintf(script_cmd, sizeof(script_cmd), "/usr/bin/./update.sh");
		system(script_cmd);
	}
	// if (!strcmp(act_str, "install_firmware"))
	// {
	// 	char script_cmd[CBCC_MAX_PATH];
	// 	snprintf(script_cmd, sizeof(script_cmd), "/bin/./install.sh");
	// 	system(script_cmd);
	// }
	// if (!strcmp(act_str, "prefetch_update"))
	// {
	// 	char script_cmd[CBCC_MAX_PATH];
	// 	snprintf(script_cmd, sizeof(script_cmd), "/bin/./download.sh");
	// 	system(script_cmd);
	// }

	// if (!strcmp(act_str, "prefetch_update") || !strcmp(act_str, "install_firmware") || !strcmp(act_str, "install_pattern"))
	// {
		// char *fpath = "/etc/config/download";
		// char script_cmd[CBCC_MAX_PATH];

		// snprintf(script_cmd, sizeof(script_cmd), "touch /etc/config/download");
		// system(script_cmd);

		// FILE *fp = fopen(fpath, "r");
		// if (!fp)
		// {
		// 	CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "ADMIN: Could not read %s", fpath);
		// 	return;
		// }
		// char buf[CBCC_MAX_PATH];

		// char address_tmp[32];
		// char portnum_tmp[16];

		// char address_ret[32];
		// char portnum_ret[16];

		// int len;

		// while(fgets(buf, sizeof(buf), fp))
		// {
		// 	if (!strncmp(buf, "        option webserver", 24))
		// 	{
		// 		memset(address_tmp, 0, sizeof(address_tmp));
		// 		len = strlen(buf) - 27;
		// 		strncpy(address_tmp, strstr(buf, "'"), len);
		// 		snprintf(address_ret, sizeof(address_ret), "%s", address_tmp + 1);
		// 		CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_HIGH, "1");
		// 	}
		// 	if (!strncmp(buf, "        option port", 19))
		// 	{
		// 		memset(portnum_tmp, 0, sizeof(portnum_tmp));
		// 		len = strlen(buf) - 22;
		// 		strncpy(portnum_tmp, strstr(buf, "'"), len);
		// 		snprintf(portnum_ret, sizeof(portnum_ret), "%s", portnum_tmp + 1);
		// 	}
		// }
		// fclose(fp);

		// snprintf(script_cmd, sizeof(script_cmd), "rm -rf /etc/cbcc-agent/info");
		// system(script_cmd);

		// snprintf(script_cmd, sizeof(script_cmd), "iptables -A AUTO_OUTPUT -d %s -j ACCEPT", address_ret);
		// system(script_cmd);

		// snprintf(script_cmd, sizeof(script_cmd), "wget -P /etc/cbcc-agent/ http://%s:%s/download/info", address_ret, portnum_ret);
		// system(script_cmd);

		// snprintf(script_cmd, sizeof(script_cmd), "touch /etc/cbcc-agent/info");
		// system(script_cmd);

		// char *downinfo_fpath = "/etc/cbcc-agent/info";
		// FILE *downinfo_fp = fopen(downinfo_fpath, "r");
		// if (!downinfo_fp)
		// {
		// 	CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "ADMIN: Could not read %s", downinfo_fpath);
		// 	return;
		// }

		// char filename_tmp[32];
		// char version_tmp[16];

		// char filename_ret[32];
		// char version_ret[16];

		// while(fgets(buf, sizeof(buf), downinfo_fp))
		// {
		// 	if (!strncmp(buf, "        \"filename\"", 18))
		// 	{
		// 		memset(filename_tmp, 0, sizeof(filename_tmp));
		// 		len = strlen(buf) - 21;
		// 		strncpy(filename_tmp, strstr(buf, "="), len);
		// 		snprintf(filename_ret, sizeof(filename_ret), "%s", filename_tmp + 3);
		// 	}
		// 	if (!strncmp(buf, "        \"version\"", 16))
		// 	{
		// 		memset(version_tmp, 0, sizeof(version_tmp));
		// 		len = strlen(buf) - 19;
		// 		strncpy(version_tmp, strstr(buf, "="), len);
		// 		snprintf(version_ret, sizeof(version_ret), "%s", version_tmp + 3);
		// 	}
		// }
		// fclose(downinfo_fp);

		// snprintf(script_cmd, sizeof(script_cmd), "wget -P /etc/cbcc-agent/ http://%s:%s/download/%s", address_ret, portnum_ret, filename_ret);
		// system(script_cmd);

		// snprintf(script_cmd, sizeof(script_cmd), "sysupgrade -T /etc/cbcc-agent/%s", filename_ret);
		// system(script_cmd);

		// snprintf(script_cmd, sizeof(script_cmd), "rm -rf /etc/cbcc-agent/%s", filename_ret);
		// system(script_cmd);

		// remove("/etc/cbcc-agent/%s", filename_ret);

		// char *filename_fpath = "/etc/cbcc-agent/filename";
		// FILE *filename_fp = fopen(filename_fpath, "w");
		// fwrite(filename_ret, 1, sizeof(filename_ret), filename_fp);
		// fclose(filename_fp);

		// char *version_fpath = "/etc/cbcc-agent/version";
		// FILE *version_fp = fopen(version_fpath, "w");
		// fwrite(version_ret, 1, sizeof(version_ret), version_fp);
		// fclose(version_fp);

	// 	return;
	// }
	// else if (!strcmp(act_str, "install_firmware"))
	// {
	// 	char script_cmdbbb[CBCC_MAX_PATH];
	// 	snprintf(script_cmdbbb, sizeof(script_cmdbbb), "touch /etc/cbcc-agent/filename");
	// 	system(script_cmdbbb);

	// 	char *last_version_fpath = "/etc/cbcc-agent/filename";
	// 	FILE *last_version_fp = fopen(last_version_fpath, "r");

	// 	char last_version_fname[CBCC_MAX_PATH];
	// 	fgets(last_version_fname, sizeof(last_version_fname), last_version_fp);
	// 	fclose(last_version_fp);

	// 	char script_cmd[CBCC_MAX_PATH];
	// 	snprintf(script_cmd, sizeof(script_cmd), "sysupgrade -T /etc/cbcc-agent/%s", last_version_fname);

	// 	system(script_cmd);
	// }
	// else if (!strcmp(act_str, "install_pattern"))
	// {
	// 	char script_cmdaaa[CBCC_MAX_PATH];
	// 	snprintf(script_cmdaaa, sizeof(script_cmdaaa), "touch /etc/cbcc-agent/filename");
	// 	system(script_cmdaaa);

	// 	char *last_version_fpath = "/etc/cbcc-agent/filename";
	// 	FILE *last_version_fp = fopen(last_version_fpath, "r");

	// 	char last_version_fname[CBCC_MAX_PATH];
	// 	fgets(last_version_fname, sizeof(last_version_fname), last_version_fp);

	// 	char script_cmd[CBCC_MAX_PATH];
	// 	snprintf(script_cmd, sizeof(script_cmd), "sysupgrade -T /etc/cbcc-agent/%s", last_version_fname);

	// 	system(script_cmd);
	// }
	
	return;
}

// reboot or shutdown system
static void admin_power_system(bool shutdown)
{
	const char *power_cmd = shutdown ? "poweroff" : "reboot";
	
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "ADMIN: Running command '%s'", power_cmd);
	system(power_cmd);
	
	return;
}

// process action command
static const char *action_type_strs[] =
{
	CBCC_ACTION_TYPE_REBOOT_STR,
	CBCC_ACTION_TYPE_SHUTDOWN_STR,
	CBCC_ACTION_TYPE_PREFETCH_STR,
	CBCC_ACTION_TYPE_FIRMWARE_STR,
	CBCC_ACTION_TYPE_PATTERN_STR,
	NULL
};

enum CBCC_ACTION_TYPE get_action_type(const char *act_type_str)
{
	int i = 0;
	while (action_type_strs[i] != NULL)
	{
		if (strcmp(action_type_strs[i], act_type_str) == 0)
			return i;
		
		i++;
	}
	
	return CBCC_ACTION_TYPE_UNKNOWN;
}

void cbcc_admin_action(struct _cbcc_agent_ctx *c, const char *cmd_data)
{
	char action_str[CBCC_MAX_ACT_TYPE_LEN];
	char act_guid[CBCC_MAX_GUID_LEN];
	
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "ADMIN: Processing action command data '%s'", cmd_data);
	
	// parse action command
	cbcc_json_object_t action_jobjs[] =
	{
		{
			.key = "guid",
			.type = CBCC_JSON_DATA_TYPE_STRING,
			.data.str_val = act_guid,
			.data_size = sizeof(act_guid)
		},
		{
			.key = "action.types",
			.type = CBCC_JSON_DATA_TYPE_STRING,
			.data.str_val = action_str,
			.data_size = sizeof(action_str)
		}
	};
	
	if (cbcc_json_parse_from_buffer(cmd_data, action_jobjs, CBCC_JOBJS_COUNT(action_jobjs)) != 0)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "ADMIN: Could not parse action command.");
		return;
	}
	
	// get action type
	enum CBCC_ACTION_TYPE act_type = get_action_type(action_str);
	if (act_type == CBCC_ACTION_TYPE_UNKNOWN)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "ADMIN: Unknown action type string '%s'", action_str);
		return;
	}
	
	switch (act_type)
	{
		case CBCC_ACTION_TYPE_REBOOT:
			admin_power_system(false);
			break;
		
		case CBCC_ACTION_TYPE_SHUTDOWN:
			admin_power_system(true);
			break;
			
		case CBCC_ACTION_TYPE_PREFETCH:
		case CBCC_ACTION_TYPE_FIRMWARE:
		case CBCC_ACTION_TYPE_PATTERN:
			do_action(c, act_guid, action_str);
			break;
		
		default:
			break;
	}
	
	return;
}
