#ifndef __CBCC_ADMIN_H__
#define __CBCC_ADMIN_H__

// backup info structure
typedef struct _cbcc_backup_info
{
	bool auto_backup;
	time_t timestamp;

	char guid[CBCC_MAX_GUID_LEN];
	char comment[CBCC_MAX_COMMENT_LEN];

	char file_name[CBCC_MAX_PATH];
	char file_path[CBCC_MAX_PATH];
	int file_size;
	char md5sum[CBCC_MD5SUM_LEN * 2 + 1];
	
	char *base64_encoded;

	char version[CBCC_MAX_VER_LEN];
	char user[CBCC_MAX_UNAME_LEN];
} cbcc_backup_info_t;

// create backup
void cbcc_admin_create_backup(struct _cbcc_agent_ctx *c, const char *cmd_data);

// restore backup
void cbcc_admin_restore_backup(struct _cbcc_agent_ctx *c, const char *cmd_data);

// process action command
void cbcc_admin_action(struct _cbcc_agent_ctx *c, const char *cmd_data);

#endif			// __CBCC_ADMIN_H__
