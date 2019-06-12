#ifndef __COMMON_H__
#define __COMMON_H__

#define CBCC_VERSION_STR			"0.9.1.4"

// constants
#define CBCC_MAX_PATH					128
#define CBCC_MAX_HNAME_LEN				128
#define CBCC_MAX_IPADDR_LEN				32
#define CBCC_MAX_LOG_MSG_LEN			40960

#define CBCC_MAX_GUID_LEN				128
#define CBCC_MAX_SECRET_LEN				64
#define CBCC_MAX_COMMENT_LEN			128
#define CBCC_MAX_UNAME_LEN				64
#define CBCC_MAX_VER_LEN				32
#define CBCC_MAX_ACT_TYPE_LEN			64
#define CBCC_MAX_EXEC_TYPE_LEN			32
#define CBCC_MAX_STATUS_LEN				64
#define CBCC_MAX_DATE_LEN				64
#define CBCC_MAX_HASH_LEN				64
#define CBCC_MAX_REG_STATUS_LEN			32
#define CBCC_MAX_OUNAME_LEN				128
#define CBCC_MAX_INTERVALS_LEN			32
#define CBCC_MAX_OU_NAME_LEN			128

#define CBCC_MAX_JSON_KEY_LEN			128
#define CBCC_MAX_JSON_DATA_LEN			4096

#define CBCC_MAX_JSON_ARR_SIZE			256
#define CBCC_MAX_JSON_ARR_FIELD_LEN		4096

#define CBCC_MAX_SOCK_BUF_LEN			1024

#define CBCC_MAX_CMD_NAME_LEN			64
#define CBCC_MAX_CMD_DATA_LEN			40960
#define CBCC_MAX_CMD_LEN				CBCC_MAX_CMD_NAME_LEN + CBCC_MAX_CMD_DATA_LEN

#define CBCC_MAX_SCRIPT_CMD_LEN   		128

#define CBCC_MAX_CMD_RESP_LEN			1024

#define CBCC_MAX_WAPI_ACT_LEN			64

// constants related with SQL
#define CBCC_MAX_PGSQL_CONNSTR_LEN		128

#define CBCC_MAX_TBL_NAME_LEN			CBCC_MAX_JSON_KEY_LEN

#define CBCC_MAX_SQL_LEN				4096

#define CBCC_MAX_COL_NAME_LEN			128
#define CBCC_MAX_COL_DATA_LEN			4096

// process name
#define CBCCD_PROC_NAME					"cbccd"
#define CBCC_AGENT_PROC_NAME			"cbcc_agent"

// cbccd listen port number
#define CBCCD_CMD_LISTEN_PORT			4433
#define CBCCD_NOTIFY_LISTEN_PORT		6001
#define CBCCD_WAPI_LISTEN_PORT			6002

// several intervals
#define CBCC_AGENT_CONNECT_INTERVAL			5
#define CBCC_AGENT_LOGIN_INTERVAL			10
#define CBCC_AGENT_MON_INTERVAL				60
#define CBCC_AGENT_REPORT_INTERVAL			15 * 60			// 15 min
#define CBCC_MAX_WEB_LINK_INTERVAL			5 * 60 			// 5 min

#define CBCC_ADMIN_DB_FETCH_INTERVAL		60
#define CBCC_CONFIG_DB_FETCH_INTERVAL		5 * 60			// 5 min
#define CBCC_KEEPALIVE_INTERVAL				15				// 15 seconds

// md5sum length
#define CBCC_MD5SUM_LEN						16

// directory path holding backup files
#define			CBCCD_BACKUP_DIR_PATH				"/var/storage/sessions/backup"
#define			CBCC_AGENT_BACKUP_DIR_PATH			"/var/storage/cbcc-agent/backups"

// directory path holoding reporting images
#define			CBCCD_REPORT_DIR_PATH				"/var/storage/sessions/rrd-images"

// file path for certificates
#define			CBCCD_CA_CERT_FILE_PATH				"/etc/cbccd/cbccca.crt"
#define			CBCCD_CERT_FILE_PATH				"/etc/cbccd/cbccserver.crt"
#define			CBCCD_KEY_FILE_PATH					"/etc/cbccd/cbccserver.key"

#define			CBCC_CA_CERT_FILE_PATH				"/etc/cbcc-agent/cbccca.crt"
#define			CBCC_CERT_FILE_PATH					"/etc/cbcc-agent/cbccagent.crt"
#define			CBCC_KEY_FILE_PATH					"/etc/cbcc-agent/cbccagent.key"

// file path for configuration caching
#define			CBCC_CONF_CACHE_FILE_PATH			"/etc/cbcc-agent/config.cache"

// action type
enum CBCC_ACTION_TYPE
{
	CBCC_ACTION_TYPE_REBOOT = 0,
	CBCC_ACTION_TYPE_SHUTDOWN,
	CBCC_ACTION_TYPE_PREFETCH,
	CBCC_ACTION_TYPE_FIRMWARE,
	CBCC_ACTION_TYPE_PATTERN,
	CBCC_ACTION_TYPE_UNKNOWN,
};

#define CBCC_ACTION_TYPE_REBOOT_STR		"reboot_device"
#define CBCC_ACTION_TYPE_SHUTDOWN_STR		"shutdown_device"
#define CBCC_ACTION_TYPE_PREFETCH_STR		"prefetch_update"
#define CBCC_ACTION_TYPE_FIRMWARE_STR		"install_firmware"
#define CBCC_ACTION_TYPE_PATTERN_STR		"install_pattern"

// CBCCD command codes
enum CBCC_CMD_CODES
{
	CBCC_CMD_CODE_LOGIN = 0,
	CBCC_CMD_CODE_MONITOR,
	CBCC_CMD_CODE_DEPLOY_OBJ,
	CBCC_CMD_CODE_CREATE_BACKUP,
	CBCC_CMD_CODE_RESTORE_BACKUP,
	CBCC_CMD_CODE_ACTION,
	CBCC_CMD_CODE_REPORT,
	CBCC_CMD_CODE_AGENT_DISABLE,
	CBCC_CMD_CODE_CHECK_CONFIG,
	CBCC_CMD_CODE_KEEPALIVE,
	CBCC_CMD_CODE_OPENPORT,
	
	CBCC_CMD_CODE_UNKNOWN,
};

// CBCCD command names
#define CBCC_CMD_LOGIN			"device.login"
#define CBCC_CMD_ADMIN			"device.admin"
#define CBCC_CMD_CONFIG			"device.config"
#define CBCC_CMD_MONITOR		"device.monitor"
#define CBCC_CMD_DEPLOY			"device.deploy.object"
#define CBCC_CMD_CREATE_BACKUP		"device.create.backup"
#define CBCC_CMD_RESTORE_BACKUP		"device.restore.backup"
#define CBCC_CMD_ACTION			"device.action"
#define CBCC_CMD_REPORT			"device.report"
#define CBCC_CMD_AGENT_DISABLE		"device.agent.disable"
#define CBCC_CMD_CHECK_CONFIG		"device.config.check"
#define CBCC_CMD_KEEPALIVE		"device.keepalive"
#define CBCC_CMD_OPENPORT		"device.openport"

// command response code
enum CBCC_RESP_CODE
{
	CBCC_RESP_OK = 0,

	CBCC_RESP_UNKNOWN_ACT = 1,
	CBCC_RESP_UNKNOWN_TBL,
	CBCC_RESP_NOT_FOUND_GUID,
	CBCC_RESP_NOT_FOUND_OU,
	CBCC_RESP_UNKNOWN_OBJ_TYPE,
	CBCC_RESP_OBJ_IS_USING,
	CBCC_RESP_OU_NAME_DUPLICATE,
	
	CBCC_RESP_NOT_CONNECTED = 10,
	CBCC_RESP_NOT_LOGINED,
	CBCC_RESP_SECRET_MISMATCHED,
	CBCC_RESP_DEVICE_IN_BLACKLIST,
	
	CBCC_RESP_CONFD_FAILED = 20,

	CBCC_RESP_JSON_INVALID = 25,
	CBCC_RESP_CREATE_BACKUP_FAILED,
	CBCC_RESP_NO_EXIST_BACKUP,
	CBCC_RESP_NO_VALID_BACKUP,
	
	CBCC_RESP_DB_OPER_FAILED = 35,
	
	CBCC_RESP_SEND_FAILED = 40,
	CBCC_RESP_OUT_OF_MEM,
	
	CBCC_RESP_FILE_OPER_FAILED = 50,
};

#endif		// __COMMON_H__
