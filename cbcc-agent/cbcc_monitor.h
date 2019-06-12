#ifndef __CBCC_MONITOR_H__
#define __CBCC_MONITOR_H__

typedef struct _service_struct
{
	char *service_name;

	int mem_level;
	char mem_hint[2];
	int cpu_level;
	char cpu_hint[2];
	int cpu_usage;
	int mem_usage;
	int resident_size;
	int status;
	char running[8];
	char enabled[8];
	int active;
	char exist[8];
} service_struct_t;

typedef struct _license_struct
{
	int level;
	char owner[8];
	int AVU2D;
	int IPSU2D;
	int NAT;
 	char ExpirationDate[128];
	char RegistrationDate[128];
	int WAFU2D;
	int CSCD;
	int HighAvailability;
} license_struct_t;

typedef struct _resource_struct
{
	char *partition_name;

	int blocksize;
	char filesystem[8];
	int percent;
	int used;
	int size;
	char blocks_fulltime[32];
	int availiable;
	int active;
	int total;
	char block_persec[16];
} resource_struct_t;

typedef struct _network_struct
{
	char *net_name;

	int nic_state;
	char RX_errors[16];
	char TX_errors[16];
	char RX_BPS[16];
	char TX_BPS[16];
	char RX_bytes[16];
	char TX_bytes[16];
	int link_state;
	int Total_bytes;
} network_struct_t;

// CBCC agemt monitor
typedef struct _cbcc_agent_monitor
{
	bool init_flag;
	bool end_flag;
	
	pthread_t pt_mon;				// monitoring thread ID
	
	struct _cbcc_agent_ctx *c;	

} cbcc_agent_monitor_t;

// initialize and finalize monitor
int cbcc_agent_monitor_init(struct _cbcc_agent_ctx *c);
void cbcc_agent_monitor_finalize(cbcc_agent_monitor_t *mon_mgr);

#endif		// __CBCC_MONITOR_H__
