
#include "cbcc_agent.h"
#include "cbcc_monitor.h"

#include <sys/stat.h>
#include <time.h>

static void get_service_info_by_service_name(service_struct_t service_name, service_struct_t **service_get_info)
{
	char script_cmd[CBCC_MAX_CMD_NAME_LEN];
	char fpath[CBCC_MAX_PATH];
	snprintf(fpath, sizeof(fpath), "/etc/cbcc-agent/%s.info", service_name.service_name);
	snprintf(script_cmd, sizeof(script_cmd), "top -n 1 | grep %s > %s", service_name.service_name, fpath);

	system(script_cmd);

	FILE *fp = fopen(fpath, "a");
	if (fp == NULL)
	{
		service_name.status = 0;
		service_name.active = 0;

		snprintf(service_name.enabled, sizeof(service_name.enabled) , "false");
		snprintf(service_name.running, sizeof(service_name.running) , "false");
		snprintf(service_name.exist, sizeof(service_name.exist) , "false");

		service_name.mem_usage = 0;
		snprintf(service_name.mem_hint, sizeof(service_name.mem_hint) , "0");
		service_name.mem_level = 0;
		service_name.cpu_usage = 0;

		snprintf(service_name.cpu_hint, sizeof(service_name.cpu_hint) , "0");
		service_name.cpu_level = 0;
		service_name.resident_size = 0;

		*service_get_info = &service_name;
		return;
	}
	struct stat st;
	if (stat(fpath, &st) != 0)
		return;
	char *pdata;
	pdata = (char *) malloc(st.st_size + 1);
	int data_len = fread(pdata, 1, st.st_size, fp);
	data_len = fread(pdata, 1, st.st_size, fp);

	pdata[data_len] = '\0';

	if (pdata[42] == '/')//43
	{
		service_name.status = 1;
		service_name.active = 1;

		snprintf(service_name.enabled, sizeof(service_name.enabled) , "true");
		snprintf(service_name.running, sizeof(service_name.running) , "true");
		snprintf(service_name.exist, sizeof(service_name.exist) , "true");

		char mem_hint[2];
		mem_hint[0] = pdata[85]; mem_hint[5] = pdata[86]; mem_hint[2] = '\0';
		char cpu_hint[2];
		cpu_hint[0] = pdata[90]; cpu_hint[1] = pdata[91]; cpu_hint[2] = '\0';
		char res_size_tmp[8];
		res_size_tmp[0] = pdata[79]; res_size_tmp[1] = pdata[80]; res_size_tmp[2] = pdata[81]; res_size_tmp[3] = pdata[82]; res_size_tmp[4] = '\0'; 
		
		int mem_usage = atoi(mem_hint);
		int cpu_usage = atoi(cpu_hint);
		int res_size = atoi(res_size_tmp);
		int mem_level;
		int cpu_level;

		if (mem_usage < 25)
			mem_level = 1;
		else if (mem_usage >= 25 && mem_usage < 50)
			mem_level = 2;
		else if (mem_usage >= 50 && mem_usage <75)
			mem_level = 3;
		else
			mem_level = 4;

		if (cpu_usage < 25)
			cpu_level = 1;
		else if (cpu_usage >= 25 && cpu_usage < 50)
			mem_level = 2;
		else if (cpu_usage >= 50 && cpu_usage <75)
			cpu_level = 3;
		else
			cpu_level = 4;

		service_name.mem_usage = mem_usage;
		snprintf(service_name.mem_hint, sizeof(service_name.mem_hint) , "%s", mem_hint);
		service_name.mem_level = mem_level;
		service_name.cpu_usage = cpu_usage;

		snprintf(service_name.cpu_hint, sizeof(service_name.cpu_hint) , "%s", cpu_hint);
		service_name.cpu_level = cpu_level;
		service_name.resident_size = res_size;
	}
	else
	{
		service_name.status = 0;
		service_name.active = 0;

		snprintf(service_name.enabled, sizeof(service_name.enabled) , "false");
		snprintf(service_name.running, sizeof(service_name.running) , "false");
		snprintf(service_name.exist, sizeof(service_name.exist) , "false");

		service_name.mem_usage = 0;
		snprintf(service_name.mem_hint, sizeof(service_name.mem_hint) , "0");
		service_name.mem_level = 0;
		service_name.cpu_usage = 0;

		snprintf(service_name.cpu_hint, sizeof(service_name.cpu_hint) , "0");
		service_name.cpu_level = 0;
		service_name.resident_size = 0;
	}

	*service_get_info = &service_name;

	fclose(fp);
	// remove(fpath);

	 return;
}

static void get_license_info_from_lic_file(license_struct_t license, license_struct_t **license_get_info)
{
	char *fpath = "/etc/license.lic";
	char script_cmd[CBCC_MAX_CMD_NAME_LEN];

	snprintf(script_cmd, sizeof(script_cmd), "touch /etc/license.lic");
	system(script_cmd);

	FILE *fp = fopen(fpath, "r");

	if (fp == NULL)
	{
		license.level = 0;
		license.AVU2D = 0;
		license.IPSU2D = 0;
		license.NAT = 0;
		license.WAFU2D = 0;
		license.CSCD = 0;
		license.HighAvailability = 0;

		*license_get_info = &license;
		return;
	}

	char buf[256];
	char owner_tmp[128];
	char registration_tmp[128];
	char expiration_tmp[128];
	int len;

	snprintf(license.RegistrationDate, sizeof(license.RegistrationDate), "0");
	snprintf(license.ExpirationDate, sizeof(license.ExpirationDate), "0");

	while (fgets(buf, sizeof(buf), fp))
	{
		if (!strncmp(buf, "Owner =", 7))
		{
			memset(owner_tmp, 0, sizeof(owner_tmp));
			len = strlen(buf) - 7;
			strncpy(owner_tmp, strstr(buf, "="), len);
			snprintf(license.owner, sizeof(license.owner), "%s", owner_tmp + 2);
		}
		if (!strncmp(buf, "Registration Date =", 19))
		{
			memset(registration_tmp, 0, sizeof(registration_tmp));
			len = strlen(buf) - 19;
			strncpy(registration_tmp, strstr(buf, "="), len);
			snprintf(license.RegistrationDate, sizeof(license.RegistrationDate), "%s", registration_tmp + 2);
		}
		if (!strncmp(buf, "Expiration Date =", 17))
		{
			memset(expiration_tmp, 0, sizeof(expiration_tmp));
			len = strlen(buf) - 17;
			strncpy(expiration_tmp, strstr(buf, "="), len);
			snprintf(license.ExpirationDate, sizeof(license.ExpirationDate), "%s", expiration_tmp + 2);
		}
	}
	time_t tt = time(NULL);
	struct tm *tm = localtime(&tt);

	char curr_date[128];
	strftime(curr_date, sizeof(curr_date), "%Y-%m-%d", tm);
	
	if (strcmp(curr_date, license.ExpirationDate) < 0)	
	{
		license.level = 1;
		license.AVU2D = 1;
		license.IPSU2D = 1;
		license.NAT = 1;
		license.WAFU2D = 1;
		license.CSCD = 1;
		license.HighAvailability = 1;
	}
	else
	{
		license.level = 0;
		license.AVU2D = 0;
		license.IPSU2D = 0;
		license.NAT = 0;
		license.WAFU2D = 0;
		license.CSCD = 0;
		license.HighAvailability = 0;	
	}
	*license_get_info = &license;

	fclose(fp);

	return;
}

static void get_resource_info_from_df(resource_struct_t hard_part, resource_struct_t **hard_part_get_info)
{
	//init resource info
	hard_part.percent = 0;
	hard_part.size = 0;
	hard_part.active = 0;
	hard_part.blocksize = 0;
	hard_part.total = 0;
	hard_part.used = 0;
	hard_part.availiable = 0;
	snprintf(hard_part.blocks_fulltime, sizeof(hard_part.blocks_fulltime), "0");
	snprintf(hard_part.block_persec, sizeof(hard_part.block_persec), "0");

	char script_cmd[CBCC_MAX_CMD_NAME_LEN];
	char fpath[CBCC_MAX_PATH];

	if (!strcmp(hard_part.partition_name, "/dev/root"))
	{
		snprintf(fpath, sizeof(fpath), "/etc/cbcc-agent/dev_root.df");
	}
	if (!strcmp(hard_part.partition_name, "/dev"))
	{
		snprintf(fpath, sizeof(fpath), "/etc/cbcc-agent/dev.df");
	}
	if (!strcmp(hard_part.partition_name, "/tmp"))
	{
		snprintf(fpath, sizeof(fpath), "/etc/cbcc-agent/tmp.df");
	}

	snprintf(script_cmd, sizeof(script_cmd), "df | grep %s > %s", hard_part.partition_name, fpath);
	system(script_cmd);

	FILE *fp = fopen(fpath, "r");
	if (fp == NULL)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "MON: Could not read %s file", fpath);
		remove(fpath);
		return;
	}
	char pdata[128];
	//if the partition is /dev then the info added with /dev/root so...
	if (!strcmp(hard_part.partition_name, "/dev"))
	{
		fgets(pdata, sizeof(pdata), fp);
		fgets(pdata, sizeof(pdata), fp);
	}
	fgets(pdata, sizeof(pdata), fp);

	snprintf(hard_part.filesystem, sizeof(hard_part.filesystem) , "ext4");
	hard_part.size = 0;
	hard_part.blocksize = 4096;
	snprintf(hard_part.block_persec, sizeof(hard_part.block_persec), "10");

	char blocks_fulltime[32] = {0, };
	for (int i = 0; i < 6; i++)
	{
		blocks_fulltime[i] = pdata[i + 25];
	}
	blocks_fulltime[7] = '\0';
	// char *blocks_fulltime = split_ldm_defined_char(pdata, 2);
	snprintf(hard_part.blocks_fulltime, sizeof(hard_part.blocks_fulltime), "%s", blocks_fulltime);

	char used[32] = {0, };
	for (int i = 0; i < 6; i++)
	{
		used[i] = pdata[i + 34];
	}
	used[7] = '\0';
	// char *used = split_ldm_defined_char(pdata, 3);
	hard_part.used = atoi(used);

	char availiable[32] = {0, };
	for (int i = 0; i < 6; i++)
	{
		availiable[i] = pdata[i + 45];
	}
	availiable[7] = '\0';
	// char *availiable = split_ldm_defined_char(pdata, 4);
	hard_part.availiable = atoi(availiable);

	hard_part.total =  atoi(used) + atoi(availiable);

	// char *percent_tmp = split_ldm_defined_char(pdata, 5);
	hard_part.percent = hard_part.used / hard_part.total * 100;

	*hard_part_get_info = &hard_part;

	fclose(fp);
	remove(fpath);

	return;
}

static void get_net_info_from_ifconfig(network_struct_t net, network_struct_t **get_net_info)
{
	char script_cmd[CBCC_MAX_PATH];
	char fpath[CBCC_MAX_PATH];

	if (!strcmp(net.net_name, "eth0.1"))
	{
		snprintf(fpath, sizeof(fpath), "/etc/cbcc-agent/eth0");
	}
	if (!strcmp(net.net_name, "eth0.2"))
	{
		snprintf(fpath, sizeof(fpath), "/etc/cbcc-agent/eth1");
	}

	char fpath_tmp[CBCC_MAX_PATH];

	snprintf(fpath_tmp, sizeof(fpath_tmp), "%sstatus", fpath);
	snprintf(script_cmd, sizeof(script_cmd), "ifconfig %s > %s", net.net_name, fpath_tmp);
	system(script_cmd);

	FILE *fp_tmp = fopen(fpath_tmp, "r");
	if (fp_tmp == NULL)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "MON: Could not read %s file", fpath_tmp);
		net.nic_state = 0;
		net.link_state = 0;
		snprintf(net.TX_errors, sizeof(net.TX_errors), "0");
		snprintf(net.RX_errors, sizeof(net.RX_errors), "0");
		snprintf(net.TX_BPS, sizeof(net.TX_BPS), "0");
		snprintf(net.RX_BPS, sizeof(net.RX_BPS), "0");
		snprintf(net.TX_bytes, sizeof(net.TX_bytes), "0");
		snprintf(net.RX_bytes, sizeof(net.RX_bytes), "0");

		*get_net_info = &net;
		return;
	}
	char buf[128];
	char pdata[16];
	memset(buf, 0, sizeof(buf));
	fgets(buf, sizeof(buf), fp_tmp);

	if (!strncmp(buf, "eth", 3))
	{
		net.nic_state = 1;
		net.link_state = 1;

		snprintf(fpath_tmp, sizeof(fpath_tmp), "%sTX_bytes", fpath);
		snprintf(script_cmd, sizeof(script_cmd), "ifconfig %s | grep TX | grep bytes | cut -d ' ' -f17> %s", net.net_name, fpath_tmp);
		system(script_cmd);
		fp_tmp = fopen(fpath_tmp, "r");
		if (fp_tmp == NULL)
		{
			CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "MON: Could not read %s file", fpath_tmp);
			remove(fpath_tmp);
			return;
		}
		memset(buf, 0, sizeof(buf));
		fgets(buf, sizeof(buf), fp_tmp);
		memset(pdata, 0, sizeof(pdata));
		strncpy(pdata, strstr(buf, ":"), strlen(buf) - 6);
		snprintf(net.TX_bytes, sizeof(net.TX_bytes), "%s", pdata + 1);
		snprintf(net.TX_BPS, sizeof(net.TX_BPS), "%s", pdata + 4);
		if (strcmp(net.TX_BPS, "") == 0)
		{
			snprintf(net.TX_BPS, sizeof(net.TX_BPS), "0");
		}

		snprintf(fpath_tmp, sizeof(fpath_tmp), "%sTX_errors", fpath);
		snprintf(script_cmd, sizeof(script_cmd), "ifconfig %s | grep TX | grep packets | cut -d ' ' -f13> %s", net.net_name, fpath_tmp);
		system(script_cmd);
		fp_tmp = fopen(fpath_tmp, "r");
		if (fp_tmp == NULL)
		{
			CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "MON: Could not read %s file", fpath_tmp);
			remove(fpath_tmp);
			return;
		}
		memset(buf, 0, sizeof(buf));
		fgets(buf, sizeof(buf), fp_tmp);
		memset(pdata, 0, sizeof(pdata));
		strncpy(pdata, strstr(buf, ":"), strlen(buf) - 7);
		snprintf(net.TX_errors, sizeof(net.TX_errors), "%s", pdata + 1);

		snprintf(fpath_tmp, sizeof(fpath_tmp), "%sRX_bytes", fpath);
		snprintf(script_cmd, sizeof(script_cmd), "ifconfig %s | grep RX | grep bytes | cut -d ' ' -f12> %s", net.net_name, fpath_tmp);
		system(script_cmd);
		fp_tmp = fopen(fpath_tmp, "r");
		if (fp_tmp == NULL)
		{
			CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "MON: Could not read %s file", fpath_tmp);
			remove(fpath_tmp);
			return;
		}
		memset(buf, 0, sizeof(buf));
		fgets(buf, sizeof(buf), fp_tmp);
		memset(pdata, 0, sizeof(pdata));
		strncpy(pdata, strstr(buf, ":"), strlen(buf) - 6);
		snprintf(net.RX_bytes, sizeof(net.RX_bytes), "%s", pdata + 1);
		snprintf(net.RX_BPS, sizeof(net.RX_BPS), "%s", pdata + 4);
		if (strcmp(net.RX_BPS, "") == 0)
		{
			snprintf(net.RX_BPS, sizeof(net.RX_BPS), "0");
		}

		snprintf(fpath_tmp, sizeof(fpath_tmp), "%sRX_errors", fpath);
		snprintf(script_cmd, sizeof(script_cmd), "ifconfig %s | grep RX | grep packets | cut -d ' ' -f13> %s", net.net_name, fpath_tmp);
		system(script_cmd);
		fp_tmp = fopen(fpath_tmp, "r");
		if (fp_tmp == NULL)
		{
			CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "MON: Could not read %s file", fpath_tmp);
			remove(fpath_tmp);
			return;
		}
		memset(buf, 0, sizeof(buf));
		fgets(buf, sizeof(buf), fp_tmp);
		memset(pdata, 0, sizeof(pdata));
		strncpy(pdata, strstr(buf, ":"), strlen(buf) - 7);
		snprintf(net.RX_errors, sizeof(net.RX_errors), "%s", pdata + 1);

		net.Total_bytes = atoi(net.TX_bytes) + atoi(net.RX_bytes);
	}
	else
	{
		net.nic_state = 0;
		net.link_state = 0;
		snprintf(net.TX_errors, sizeof(net.TX_errors), "0");
		snprintf(net.RX_errors, sizeof(net.RX_errors), "0");
		snprintf(net.TX_BPS, sizeof(net.TX_BPS), "0");
		snprintf(net.RX_BPS, sizeof(net.RX_BPS), "0");
		snprintf(net.TX_bytes, sizeof(net.TX_bytes), "0");
		snprintf(net.RX_bytes, sizeof(net.RX_bytes), "0");
	}

	*get_net_info = &net;

	fclose(fp_tmp);
	remove(fpath);
	remove(fpath_tmp);

	return;
}

static void get_mem_info(int *mem_swap_percent, int *mem_swap_used, int *mem_swap_total, int *mem_main_percent, int *mem_main_used, int *mem_main_total)
{
	char *fpath = "/etc/cbcc-agent/mem_info";
	char script_cmd[128];

	memset(script_cmd, 0, sizeof(script_cmd));
	snprintf(script_cmd, sizeof(script_cmd), "cat /proc/meminfo | grep MemTotal | cut -d ':' -f2 | cut -d 'k' -f1 > %s", fpath);
	system(script_cmd);
	FILE *fp = fopen(fpath, "r");
	if (fp == NULL)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "MON: Could not read %s", fpath);
		remove(fpath);
		return;
	}
	char buf[128];
	memset(buf, 0, sizeof(buf));
	fgets(buf, sizeof(buf), fp);
	int mem_main_total_ret = atoi(buf);
	*mem_main_total = mem_main_total_ret;

	memset(script_cmd, 0, sizeof(script_cmd));
	snprintf(script_cmd, sizeof(script_cmd), "cat /proc/meminfo | grep MemFree | cut -d ':' -f2 | cut -d 'k' -f1 > %s", fpath);
	system(script_cmd);
	fp = fopen(fpath, "r");
	if (fp == NULL)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "MON: Could not read %s", fpath);
		remove(fpath);
		return;
	}
	memset(buf, 0, sizeof(buf));
	fgets(buf, sizeof(buf), fp);
	int mem_main_used_ret = mem_main_total_ret - atoi(buf);
	*mem_main_used = mem_main_used_ret;

	int mem_main_percent_ret;
	if (mem_main_total_ret == 0)
		mem_main_percent_ret = 0;
	else
		mem_main_percent_ret = mem_main_used_ret * 100 / mem_main_total_ret;

	*mem_main_percent = mem_main_percent_ret;

	memset(script_cmd, 0, sizeof(script_cmd));
	snprintf(script_cmd, sizeof(script_cmd), "cat /proc/meminfo | grep SwapTotal | cut -d ':' -f2 | cut -d 'k' -f1 > %s", fpath);
	system(script_cmd);
	fp = fopen(fpath, "r");
	if (fp == NULL)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "MON: Could not read %s", fpath);
		remove(fpath);
		return;
	}
	memset(buf, 0, sizeof(buf));
	fgets(buf, sizeof(buf), fp);
	int mem_swap_total_ret = atoi(buf);
	*mem_swap_total = mem_swap_total_ret;

	memset(script_cmd, 0, sizeof(script_cmd));
	snprintf(script_cmd, sizeof(script_cmd), "cat /proc/meminfo | grep SwapFree | cut -d ':' -f2 | cut -d 'k' -f1 > %s", fpath);
	system(script_cmd);
	fp = fopen(fpath, "r");
	if (fp == NULL)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "MON: Could not read %s", fpath);
		remove(fpath);
		return;
	}
	memset(buf, 0, sizeof(buf));
	fgets(buf, sizeof(buf), fp);
	int mem_swap_used_ret = mem_swap_total_ret - atoi(buf);
	*mem_swap_used = mem_swap_used_ret;

	int mem_swap_percent_ret;
	if (mem_swap_total_ret == 0)
		mem_swap_percent_ret = 0;
	else
		mem_swap_percent_ret = mem_swap_used_ret * 100 / mem_swap_total_ret;
	
	*mem_swap_percent = mem_swap_percent_ret;

	fclose(fp);
	remove(fpath);

	return;
}

static void get_cpu_info(int *cpu_usage_average, int *cpu_usage_values, char **cpu_load_values_1, char **cpu_load_values_5, char **cpu_load_values_15, int *cpu_load_trend)
{
	char *fpath = "/etc/cbcc-agent/cpu_info";
	char script_cmd[128];

	memset(script_cmd, 0, sizeof(script_cmd));
	snprintf(script_cmd, sizeof(script_cmd), "cat /proc/stat | grep cpu0 | cut -d ' ' -f2 > %s", fpath);
	system(script_cmd);
	FILE *fp = fopen(fpath, "r");
	if (fp == NULL)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "MON: Could not read %s", fpath);
		remove(fpath);
		return;
	}
	char buf[128];
	memset(buf, 0, sizeof(buf));
	fgets(buf, sizeof(buf), fp);
	int cpu_total = atoi(buf);

	memset(script_cmd, 0, sizeof(script_cmd));
	snprintf(script_cmd, sizeof(script_cmd), "cat /proc/stat | grep cpu0 | cut -d ' ' -f4 > %s", fpath);
	system(script_cmd);
	fp = fopen(fpath, "r");
	if (fp == NULL)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "MON: Could not read %s", fpath);
		remove(fpath);
		return;
	}
	memset(buf, 0, sizeof(buf));
	fgets(buf, sizeof(buf), fp);
	int cpu_usage = atoi(buf);
	int usage_ret = (int)(10*cpu_usage/cpu_total);
	*cpu_usage_values = usage_ret;
	*cpu_usage_average = usage_ret;

	memset(script_cmd, 0, sizeof(script_cmd));
	snprintf(script_cmd, sizeof(script_cmd), "cat /proc/loadavg | cut -d ' ' -f1 > %s", fpath);
	system(script_cmd);
	fp = fopen(fpath, "r");
	if (fp == NULL)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "MON: Could not read %s", fpath);
		remove(fpath);
		return;
	}
	memset(buf, 0, sizeof(buf));
	fgets(buf, sizeof(buf), fp);
	double cpu_load_values_1_ret = atof(buf);
	buf[4] = '\0';
	*cpu_load_values_1 = &buf;

	memset(script_cmd, 0, sizeof(script_cmd));
	snprintf(script_cmd, sizeof(script_cmd), "cat /proc/loadavg | cut -d ' ' -f2 > %s", fpath);
	system(script_cmd);
	fp = fopen(fpath, "r");
	if (fp == NULL)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "MON: Could not read %s", fpath);
		remove(fpath);
		return;
	}

	char buf5[128];
	memset(buf5, 0, sizeof(buf5));
	fgets(buf5, sizeof(buf5), fp);
	double cpu_load_values_5_ret = atof(buf5);
	buf5[4] = '\0';
	*cpu_load_values_5 = &buf5;

	memset(script_cmd, 0, sizeof(script_cmd));
	snprintf(script_cmd, sizeof(script_cmd), "cat /proc/loadavg | cut -d ' ' -f3 > %s", fpath);
	system(script_cmd);
	fp = fopen(fpath, "r");
	if (fp == NULL)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "MON: Could not read %s", fpath);
		remove(fpath);
		return;
	}

	char buf15[128];
	memset(buf15, 0, sizeof(buf15));
	fgets(buf15, sizeof(buf15), fp);
	double cpu_load_values_15_ret = atof(buf15);
	buf15[4] = '\0';
	*cpu_load_values_15 = &buf15;

	*cpu_load_trend = (int)((cpu_load_values_1_ret + cpu_load_values_5_ret + cpu_load_values_15_ret)/3 *100);

	fclose(fp);
	remove(fpath);

	return;
}

static int calc_threat_trend(int today, int yesterday, int last_7, int last_30)
{
	int trend;
	int tmp1 = 0;
	int tmp2 = 0;
	int tmp3 = 0;

	if (today != 0 && yesterday != 0)
	{
		tmp1 = (int)(50/today-50/yesterday);
	}
	else if (today == 0 && yesterday != 0)
	{
		tmp1 = (int)(-1*yesterday*50);
	}
	else if (today != 0 && yesterday == 0)
	{
		tmp1 = (int)(today*50);
	}
	else
	{
		tmp1 = 0;
	}

	if (today != 0 && last_7 != 0)
	{
		tmp2 = (int)(50/today-50/last_7);
	}
	else if (today == 0 && last_7 != 0)
	{
		tmp2 = (int)(-1*last_7*50);
	}
	else if (today != 0 && last_7 == 0)
	{
		tmp2 = (int)(last_7*50);
	}
	else
	{
		tmp2 = 0;
	}

	if (today != 0 && last_30 != 0)
	{
		tmp3 = (int)(50/today-50/last_30);
	}
	else if (today == 0 && last_30 != 0)
	{
		tmp3 = (int)(-1*last_30*50);
	}
	else if (today != 0 && last_30 == 0)
	{
		tmp3 = (int)(last_30*50);
	}
	else
	{
		tmp3 = 0;
	}

	trend = (tmp1 + tmp2 + tmp3) / 3;

	if (trend > 100)
	{
		trend = 100;
	}
	if (trend < -100)
	{
		trend = -100;
	}

	return trend;
}

static int calc_threat_level(int trend)
{
	int level;
	if (trend < -50 && trend >= -100)
	{
		level = 0;
	}
	else if (trend < 0 && trend >= -50)
	{
		level = 1;
	}
	else if (trend == 0)
	{
		level = 2;
	}
	else if (trend < 50 && trend > 0)
	{
		level = 3;
	}
	else
	{
		level = 4;
	}

	return level;
}

static void get_threat_summary(char *sort, char **today, char **yesterday, char **last_7, char **last_30)
{
	FILE *fp = NULL;
	char *fpath;
	if (strcmp(sort, "pfilter") == 0)
	{
		fpath = "/etc/cbcc-agent/threat/pfilter";	
	}
	if (strcmp(sort, "ips") == 0)
	{
		fpath = "/etc/cbcc-agent/threat/ips";	
	}
	if (strcmp(sort, "portscan") == 0)
	{
		fpath = "/etc/cbcc-agent/threat/portscan";	
	}
	if (strcmp(sort, "restart") == 0)
	{
		fpath = "/etc/cbcc-agent/threat/restart";	
	}
	if (strcmp(sort, "login") == 0)
	{
		fpath = "/etc/cbcc-agent/threat/login";	
	}
	if (strcmp(sort, "viruses") == 0)
	{
		fpath = "/etc/cbcc-agent/threat/viruses";	
	}
	
	if ((fp = fopen(fpath, "r")) == NULL)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_VERBOSE, "MON: Could not read fw_threat info file %s", fpath);
		return;
	}
	char buf[32] = {0, };
	int i = 0;
	int num = 0;
	int sum = 0;
	while (fgets(buf, sizeof(buf), fp))
	{
		if (i == 0)
		{
			i++;
			memset(buf, 0, sizeof(buf));
			continue;
		}
		else
		{
			if (strncmp(buf, "last", 4) == 0)
			{
				i = 1;
				memset(buf, 0, sizeof(buf));
				continue;
			}
			num = atoi(buf);
			sum = sum + num;
			if (i == 1)
			{
				*today = num;
			}
			else if (i == 2)
			{
				*yesterday = num;
			}
			else if (i == 7)
			{
				*last_7 = sum;
			}
			else if (i == 30)
			{
				*last_30 = sum;
			}
			i++;
			memset(buf, 0, sizeof(buf));
		}
	}
	fclose(fp);
	return;
}

static void make_monitor_json_for_OpenWRT(cbcc_agent_monitor_t *mon_mgr)
{
	/*************************** Monitoring.service Info ***************************/
	service_struct_t service_squid;
	service_struct_t service_ntp;
	service_struct_t service_dhcp;
	service_struct_t service_snort;
	service_struct_t service_dns;

	service_squid.service_name = "httpd";
	service_ntp.service_name = "ntp";
	service_dhcp.service_name = "dhcpd";
	service_snort.service_name = "snortd";
	service_dns.service_name = "dns";

	service_struct_t *service_get_info;

	//get serivce info by each service name
	get_service_info_by_service_name(service_squid, &service_get_info);
	service_squid = *service_get_info;
	get_service_info_by_service_name(service_ntp, &service_get_info);
	service_ntp = *service_get_info;
	get_service_info_by_service_name(service_dhcp, &service_get_info);
	service_dhcp = *service_get_info;
	get_service_info_by_service_name(service_snort, &service_get_info);
	service_snort = *service_get_info;
	get_service_info_by_service_name(service_dns, &service_get_info);
	service_dns = *service_get_info;
	// free(service_get_info);

	//monitoring.service whole values
	int service_level = 0;

	char *websec_exist = service_squid.exist;
	int websec_active = service_squid.active;

	char *netsec_exist = service_snort.exist;
	int netsec_active = service_snort.active;

	char misc_exist[8];
	int misc_active;

	if (service_dns.active == 0 && service_dhcp.active == 0 && service_ntp.active ==0)
	{
		snprintf(misc_exist, sizeof(misc_exist), "false");
		misc_active = 0;
	}
	else
	{
		snprintf(misc_exist, sizeof(misc_exist), "true");
		misc_active = 1;
	}
	/******************************************************************************/

	/**************************** Monitoring.license Info *************************/
	license_struct_t license;
	license_struct_t *license_get_info;
	get_license_info_from_lic_file(license, &license_get_info);
	license = *license_get_info;
	// free(license_get_info);
	/******************************************************************************/

	/*********************************** Login info *******************************/
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
	/******************************************************************************/

	/************************ Monitoring.Version Info *****************************/
	int ips_date_level = 0;
	char ips_date_hint[8];
	snprintf(ips_date_hint, sizeof(ips_date_hint), "0");
	/******************************************************************************/

	/******************************* Device Info **********************************/
	const char roles[4][32] = 
	{
		CBCC_CMD_MONITOR,
		CBCC_CMD_ADMIN,
		CBCC_CMD_REPORT,
		CBCC_CMD_CONFIG,
	};

	//Device Info
	address_ret = get_address_from_network_info();

	if(address_ret != NULL){
		strcpy(address, address_ret);
		free(address_ret);
	}
	/******************************************************************************/

	/***************************** Device Inventory *******************************/
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
	/******************************************************************************/

	/**************************** Monitoring.Resource Info ************************/
	resource_struct_t hard_part1;
	resource_struct_t hard_part2;
	resource_struct_t hard_part3;

	hard_part1.partition_name = "/dev/root";
	hard_part2.partition_name = "/tmp";
	hard_part3.partition_name = "/dev";

	resource_struct_t *hard_part_get_info;
	get_resource_info_from_df(hard_part1, &hard_part_get_info);
	hard_part1 = *hard_part_get_info;
	get_resource_info_from_df(hard_part2, &hard_part_get_info);
	hard_part2 = *hard_part_get_info;
	get_resource_info_from_df(hard_part3, &hard_part_get_info);
	hard_part3 = *hard_part_get_info;
	// free(hard_part_get_info);

	int hard_total;
	hard_total = hard_part1.total + hard_part2.total + hard_part3.total;

	int hard_used;
	hard_used = hard_part1.used + hard_part2.used + hard_part3.used;

	int hard_percent;
	hard_percent = hard_used * 100 / hard_total;


	network_struct_t net0;
	network_struct_t net1;

	net0.net_name = "eth0.1";
	net1.net_name = "eth0.2";

	network_struct_t *get_net_info;
	get_net_info_from_ifconfig(net0, &get_net_info);
	net0 = *get_net_info;
	get_net_info_from_ifconfig(net1, &get_net_info);
	net1 = *get_net_info;

	int cpu_usage_values, cpu_usage_average, cpu_load_trend;
	char *cpu_load_values_1, *cpu_load_values_5, *cpu_load_values_15;
	get_cpu_info(&cpu_usage_average, &cpu_usage_values, &cpu_load_values_1, &cpu_load_values_5, &cpu_load_values_15, &cpu_load_trend);
	

	cbcc_json_array_t *cpu_array;
	cpu_array = (cbcc_json_array_t *) malloc(sizeof(cbcc_json_array_t));
	memset(cpu_array, 0, sizeof(cbcc_json_array_t));

	cpu_array->arr_len = 1;
	cpu_array->data.int_vals[0] = cpu_usage_values;

	cbcc_json_array_t *load_array;
	load_array = (cbcc_json_array_t *) malloc(sizeof(cbcc_json_array_t));
	memset(load_array, 0, sizeof(cbcc_json_array_t));

	load_array->arr_len = 3;
	strcpy(load_array->data.str_vals[0], cpu_load_values_1);
	strcpy(load_array->data.str_vals[1], cpu_load_values_5);
	strcpy(load_array->data.str_vals[2], cpu_load_values_15);

	int mem_swap_percent, mem_swap_used, mem_swap_total, mem_main_percent, mem_main_used, mem_main_total;
	get_mem_info(&mem_swap_percent, &mem_swap_used, &mem_swap_total, &mem_main_percent, &mem_main_used, &mem_main_total);

	/******************************************************************************/

	/************************* monitoring.threat info *****************************/
	int today_restart = 0;
	int today_ips = 0;
	int today_portscan = 0;
	int today_pfilter = 0;
	int today_login = 0;
	int today_viruses = 0;

	int yesterday_restart = 0;
	int yesterday_ips = 0;
	int yesterday_portscan = 0;
	int yesterday_pfilter = 0;
	int yesterday_login = 0;
	int yesterday_viruses = 0;

	int last_7_restart = 0;
	int last_7_ips = 0;
	int last_7_portscan = 0;
	int last_7_pfilter = 0;
	int last_7_login = 0;
	int last_7_viruses = 0;

	int last_30_restart = 0;
	int last_30_ips = 0;
	int last_30_portscan = 0;
	int last_30_pfilter = 0;
	int last_30_login = 0;
	int last_30_viruses = 0;

	int level_threat = 0;

	int level_restart = 0;
	int level_ips = 0;
	int level_portscan = 0;
	int level_pfilter = 0;
	int level_login = 0;
	int level_viruses = 0;

	int hint_restart = 0;
	int hint_ips = 0;
	int hint_portscan = 0;
	int hint_pfilter = 0;
	int hint_login = 0;
	int hint_viruses = 0;

	int trend_restart = 0;
	int trend_ips = 0;
	int trend_portscan = 0;
	int trend_pfilter = 0;
	int trend_login = 0;
	int trend_viruses = 0;
	
	cbcc_json_array_t *array_restart;
	cbcc_json_array_t *array_ips;
	cbcc_json_array_t *array_portscan;
	cbcc_json_array_t *array_pfilter;
	cbcc_json_array_t *array_login;
	cbcc_json_array_t *array_viruses;

	get_threat_summary("pfilter", &today_pfilter, &yesterday_pfilter, &last_7_pfilter, &last_30_pfilter);
	get_threat_summary("ips", &today_ips, &yesterday_ips, &last_7_ips, &last_30_ips);
	get_threat_summary("restart", &today_restart, &yesterday_restart, &last_7_restart, &last_30_restart);
	get_threat_summary("login", &today_login, &yesterday_login, &last_7_login, &last_30_login);
	get_threat_summary("portscan", &today_portscan, &yesterday_portscan, &last_7_portscan, &last_30_portscan);
	get_threat_summary("viruses", &today_viruses, &yesterday_viruses, &last_7_viruses, &last_30_viruses);

	trend_pfilter = calc_threat_trend(today_pfilter, yesterday_pfilter, last_7_pfilter, last_30_pfilter);
	trend_ips = calc_threat_trend(today_ips, yesterday_ips, last_7_ips, last_30_ips);
	trend_restart = calc_threat_trend(today_restart, yesterday_restart, last_7_restart, last_30_restart);
	trend_login = calc_threat_trend(today_login, yesterday_login, last_7_login, last_30_login);
	trend_portscan = calc_threat_trend(today_portscan, yesterday_portscan, last_7_portscan, last_30_portscan);
	trend_viruses = calc_threat_trend(today_viruses, yesterday_viruses, last_7_viruses, last_30_viruses);

	hint_pfilter = trend_pfilter;
	hint_viruses = trend_viruses;
	hint_login = trend_login;
	hint_portscan = trend_portscan;
	hint_ips = trend_ips;
	hint_restart = trend_restart;

	level_pfilter = calc_threat_level(trend_pfilter);
	level_ips = calc_threat_level(trend_ips);
	level_login = calc_threat_level(trend_login);
	level_restart = calc_threat_level(trend_restart);
	level_portscan = calc_threat_level(trend_portscan);
	level_viruses = calc_threat_level(trend_viruses);

	array_restart = (cbcc_json_array_t *) malloc(sizeof(cbcc_json_array_t));
	if (!array_restart)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_HIGH, "MON: Could not create array_restart.");
		return;
	}
	memset(array_restart, 0, sizeof(cbcc_json_array_t));
	array_ips = (cbcc_json_array_t *) malloc(sizeof(cbcc_json_array_t));
	if (!array_ips)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_HIGH, "MON: Could not create array_ips.");
		return;
	}
	memset(array_ips, 0, sizeof(cbcc_json_array_t));
	array_portscan = (cbcc_json_array_t *) malloc(sizeof(cbcc_json_array_t));
	if (!array_portscan)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_HIGH, "MON: Could not create array_portscan.");
		return;
	}
	memset(array_portscan, 0, sizeof(cbcc_json_array_t));
	array_pfilter = (cbcc_json_array_t *) malloc(sizeof(cbcc_json_array_t));
	if (!array_pfilter)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_HIGH, "MON: Could not create array_restart.");
		return;
	}
	memset(array_pfilter, 0, sizeof(cbcc_json_array_t));
	array_login = (cbcc_json_array_t *) malloc(sizeof(cbcc_json_array_t));
	if (!array_login)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_HIGH, "MON: Could not create array_login.");
		return;
	}
	memset(array_login, 0, sizeof(cbcc_json_array_t));
	array_viruses = (cbcc_json_array_t *) malloc(sizeof(cbcc_json_array_t));
	if (!array_viruses)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_HIGH, "MON: Could not create array_viruses.");
		return;
	}
	memset(array_viruses, 0, sizeof(cbcc_json_array_t));

	array_restart->arr_len = 4;
	array_ips->arr_len = 4;
	array_portscan->arr_len = 4;
	array_login->arr_len = 4;
	array_pfilter->arr_len = 4;
	array_viruses->arr_len = 4;

	array_restart->data.int_vals[0] = today_restart;
	array_restart->data.int_vals[1] = yesterday_restart;
	array_restart->data.int_vals[2] = last_7_restart;
	array_restart->data.int_vals[3] = last_30_restart;
	array_ips->data.int_vals[0] = today_ips;
	array_ips->data.int_vals[1] = yesterday_ips;
	array_ips->data.int_vals[2] = last_7_ips;
	array_ips->data.int_vals[3] = last_30_ips;
	array_portscan->data.int_vals[0] = today_portscan;
	array_portscan->data.int_vals[1] = yesterday_portscan;
	array_portscan->data.int_vals[2] = last_7_portscan;
	array_portscan->data.int_vals[3] = last_30_portscan;
	array_pfilter->data.int_vals[0] = today_pfilter;
	array_pfilter->data.int_vals[1] = yesterday_pfilter;
	array_pfilter->data.int_vals[2] = last_7_pfilter;
	array_pfilter->data.int_vals[3] = last_30_pfilter;
	array_login->data.int_vals[0] = today_login;
	array_login->data.int_vals[1] = yesterday_login;
	array_login->data.int_vals[2] = last_7_login;
	array_login->data.int_vals[3] = last_30_login;
	array_viruses->data.int_vals[0] = today_viruses;
	array_viruses->data.int_vals[1] = yesterday_viruses;
	array_viruses->data.int_vals[2] = last_7_viruses;
	array_viruses->data.int_vals[3] = last_30_viruses;

	/******************************************************************************/
//########################### Building Json File ##################################
	char *mon_final_buff;
	char *tmp_mon_buff;
	/************************* For login, common ********************************/
	cbcc_json_object_t cbcc_mon_login_jobjs[] =	
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
			.data.str_val_set = "",
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
					.data.str_val_set = guid,
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
	cbcc_json_build(cbcc_mon_login_jobjs, CBCC_JOBJS_COUNT(cbcc_mon_login_jobjs), &tmp_mon_buff);
	mon_final_buff = tmp_mon_buff;

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

	cbcc_json_add(mon_final_buff, cbcc_device_inventory_jobjs, CBCC_JOBJS_COUNT(cbcc_device_inventory_jobjs), &tmp_mon_buff);
	mon_final_buff = tmp_mon_buff;

	/************************** For monitoring.service **************************/
	cbcc_json_object_t cbcc_mon_service_jobjs[] =	
	{
		{
			.key = "monitoring.service",
			.type = CBCC_JSON_DATA_TYPE_OBJECT,
		},
			{
				.key = "status",
				.parent_key = "monitoring.service",
				.type = CBCC_JSON_DATA_TYPE_OBJECT,
			},
				{
					.key = "level",
					.parent_key = "status",
					.type = CBCC_JSON_DATA_TYPE_INT,
					.data.int_val_set = service_level,
				},
				{
					.key = "misc",
					.parent_key = "status",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "cpu",
						.parent_key = "misc",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "details",
							.parent_key = "cpu",
							.type = CBCC_JSON_DATA_TYPE_OBJECT,
						},
							{
								.key = "dns",
								.parent_key = "details",
								.type = CBCC_JSON_DATA_TYPE_OBJECT,
							},
								{
									.key = "level",
									.parent_key = "dns",
									.type = CBCC_JSON_DATA_TYPE_INT,
									.data.int_val_set = service_dns.cpu_level,
								},
								{
									.key = "hint",
									.parent_key = "dns",
									.type = CBCC_JSON_DATA_TYPE_STRING,
									.data.str_val_set = service_dns.cpu_hint,
								},
							{
								.key = "ntp",
								.parent_key = "details",
								.type = CBCC_JSON_DATA_TYPE_OBJECT,
							},
								{
									.key = "level",
									.parent_key = "ntp",
									.type = CBCC_JSON_DATA_TYPE_INT,
									.data.int_val_set = service_ntp.cpu_level,
								},
								{
									.key = "hint",
									.parent_key = "ntp",
									.type = CBCC_JSON_DATA_TYPE_STRING,
									.data.str_val_set = service_ntp.cpu_hint,
								},
							{
								.key = "dhcp",
								.parent_key = "details",
								.type = CBCC_JSON_DATA_TYPE_OBJECT,
							},
								{
									.key = "level",
									.parent_key = "dhcp",
									.type = CBCC_JSON_DATA_TYPE_INT,
									.data.int_val_set = service_dhcp.cpu_level,
								},
								{
									.key = "hint",
									.parent_key = "dhcp",
									.type = CBCC_JSON_DATA_TYPE_STRING,
									.data.str_val_set = service_dhcp.cpu_hint,
								},
					{
						.key = "mem",
						.parent_key = "misc",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "details",
							.parent_key = "mem",
							.type = CBCC_JSON_DATA_TYPE_OBJECT,
						},
							{
								.key = "dns",
								.parent_key = "details",
								.type = CBCC_JSON_DATA_TYPE_OBJECT,
							},
								{
									.key = "level",
									.parent_key = "dns",
									.type = CBCC_JSON_DATA_TYPE_INT,
									.data.int_val_set = service_dns.mem_level,
								},
								{
									.key = "hint",
									.parent_key = "dns",
									.type = CBCC_JSON_DATA_TYPE_STRING,
									.data.str_val_set = service_dns.mem_hint,
								},
							{
								.key = "ntp",
								.parent_key = "details",
								.type = CBCC_JSON_DATA_TYPE_OBJECT,
							},
								{
									.key = "level",
									.parent_key = "ntp",
									.type = CBCC_JSON_DATA_TYPE_INT,
									.data.int_val_set = service_ntp.mem_level,
								},
								{
									.key = "hint",
									.parent_key = "ntp",
									.type = CBCC_JSON_DATA_TYPE_STRING,
									.data.str_val_set = service_ntp.mem_hint,
								},
							{
								.key = "dhcp",
								.parent_key = "details",
								.type = CBCC_JSON_DATA_TYPE_OBJECT,
							},
								{
									.key = "level",
									.parent_key = "dhcp",
									.type = CBCC_JSON_DATA_TYPE_INT,
									.data.int_val_set = service_dns.mem_level,
								},
								{
									.key = "hint",
									.parent_key = "dhcp",
									.type = CBCC_JSON_DATA_TYPE_STRING,
									.data.str_val_set = service_dns.mem_hint,
								},
			{
				.key = "data",
				.parent_key = "monitoring.service",
				.type = CBCC_JSON_DATA_TYPE_OBJECT,
			},
				{
					.key = "websec",
					.parent_key = "data",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "name",
						.parent_key = "websec",
						.type = CBCC_JSON_DATA_TYPE_STRING,
						.data.str_val_set = "Web Security",
					},
					{
						.key = "active",
						.parent_key = "websec",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.int_val_set = websec_active,
					},
					{
						.key = "exists",
						.parent_key = "websec",
						.type = CBCC_JSON_DATA_TYPE_STRING,
						.data.str_val_set = websec_exist,
					},
					{
						.key = "details",
						.parent_key = "websec",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "http",
							.parent_key = "details",
							.type = CBCC_JSON_DATA_TYPE_OBJECT,
						},
						{
							.key = "cpu",
							.parent_key = "http",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = service_squid.cpu_usage,
						},
						{
							.key = "mem",
							.parent_key = "http",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = service_squid.mem_usage,
						},
						{
							.key = "rss",
							.parent_key = "http",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = service_squid.resident_size,
						},
						{
							.key = "status",
							.parent_key = "http",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = service_squid.status,
						},
						{
							.key = "running",
							.parent_key = "http",
							.type = CBCC_JSON_DATA_TYPE_STRING,
							.data.str_val_set = service_squid.running,
						},
						{
							.key = "name",
							.parent_key = "http",
							.type = CBCC_JSON_DATA_TYPE_STRING,
							.data.str_val_set = "HTTP Proxy",
						},
						{
							.key = "enabled",
							.parent_key = "http",
							.type = CBCC_JSON_DATA_TYPE_STRING,
							.data.str_val_set = service_squid.enabled,
						},
				{
					.key = "misc",
					.parent_key = "data",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "name",
						.parent_key = "misc",
						.type = CBCC_JSON_DATA_TYPE_STRING,
						.data.str_val_set = "Network Service",
					},
					{
						.key = "active",
						.parent_key = "misc",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.int_val_set = misc_active,
					},
					{
						.key = "exists",
						.parent_key = "misc",
						.type = CBCC_JSON_DATA_TYPE_STRING,
						.data.str_val_set = misc_exist,
					},
					{
						.key = "details",
						.parent_key = "misc",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "dhcp",
							.parent_key = "details",
							.type = CBCC_JSON_DATA_TYPE_OBJECT,
						},
							{
								.key = "cpu",
								.parent_key = "dhcp",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = service_dhcp.cpu_usage,
							},
							{
								.key = "mem",
								.parent_key = "dhcp",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = service_dhcp.mem_usage,
							},
							{
								.key = "rss",
								.parent_key = "dhcp",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = service_dhcp.resident_size,
							},
							{
								.key = "enabled",
								.parent_key = "dhcp",
								.type = CBCC_JSON_DATA_TYPE_STRING,
								.data.str_val_set = service_dhcp.enabled,
							},
							{
								.key = "name",
								.parent_key = "dhcp",
								.type = CBCC_JSON_DATA_TYPE_STRING,
								.data.str_val_set = "DHCP Server",
							},
							{
								.key = "running",
								.parent_key = "dhcp",
								.type = CBCC_JSON_DATA_TYPE_STRING,
								.data.str_val_set = service_dhcp.running,
							},
							{
								.key = "status",
								.parent_key = "dhcp",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = service_dhcp.status,
							},
						{
							.key = "ntp",
							.parent_key = "details",
							.type = CBCC_JSON_DATA_TYPE_OBJECT,
						},
							{
								.key = "cpu",
								.parent_key = "ntp",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = service_ntp.cpu_usage,
							},
							{
								.key = "mem",
								.parent_key = "ntp",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = service_ntp.mem_usage,
							},
							{
								.key = "rss",
								.parent_key = "ntp",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = service_ntp.resident_size,
							},
							{
								.key = "enabled",
								.parent_key = "ntp",
								.type = CBCC_JSON_DATA_TYPE_STRING,
								.data.str_val_set = service_ntp.enabled,
							},
							{
								.key = "name",
								.parent_key = "ntp",
								.type = CBCC_JSON_DATA_TYPE_STRING,
								.data.str_val_set = "NTP Server",
							},
							{
								.key = "running",
								.parent_key = "ntp",
								.type = CBCC_JSON_DATA_TYPE_STRING,
								.data.str_val_set = service_ntp.running,
							},
							{
								.key = "status",
								.parent_key = "ntp",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = service_ntp.status,
							},
						{
							.key = "dns",
							.parent_key = "details",
							.type = CBCC_JSON_DATA_TYPE_OBJECT,
						},
							{
								.key = "cpu",
								.parent_key = "dns",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = service_dns.cpu_usage,
							},
							{
								.key = "mem",
								.parent_key = "dns",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = service_dns.mem_usage,
							},
							{
								.key = "rss",
								.parent_key = "dns",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = service_dns.resident_size,
							},
							{
								.key = "enabled",
								.parent_key = "dns",
								.type = CBCC_JSON_DATA_TYPE_STRING,
								.data.str_val_set = service_dns.enabled,
							},
							{
								.key = "name",
								.parent_key = "dns",
								.type = CBCC_JSON_DATA_TYPE_STRING,
								.data.str_val_set = "DNS Server",
							},
							{
								.key = "running",
								.parent_key = "dns",
								.type = CBCC_JSON_DATA_TYPE_STRING,
								.data.str_val_set = service_dns.running,
							},
							{
								.key = "status",
								.parent_key = "dns",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = service_dns.status,
							},
				{
					.key = "netsec",
					.parent_key = "data",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "name",
						.parent_key = "netsec",
						.type = CBCC_JSON_DATA_TYPE_STRING,
						.data.str_val_set = "Network Security",
					},
					{
						.key = "active",
						.parent_key = "netsec",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.int_val_set = netsec_active,
					},
					{
						.key = "exists",
						.parent_key = "netsec",
						.type = CBCC_JSON_DATA_TYPE_STRING,
						.data.str_val_set = netsec_exist,
					},
					{
						.key = "details",
						.parent_key = "netsec",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "ips",
							.parent_key = "details",
							.type = CBCC_JSON_DATA_TYPE_OBJECT,
						},
						{
							.key = "cpu",
							.parent_key = "ips",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = service_snort.cpu_usage,
						},
						{
							.key = "mem",
							.parent_key = "ips",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = service_snort.mem_usage,
						},
						{
							.key = "rss",
							.parent_key = "ips",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = service_snort.resident_size,
						},
						{
							.key = "status",
							.parent_key = "ips",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = service_snort.status,
						},
						{
							.key = "running",
							.parent_key = "ips",
							.type = CBCC_JSON_DATA_TYPE_STRING,
							.data.str_val_set = service_snort.running,
						},
						{
							.key = "name",
							.parent_key = "ips",
							.type = CBCC_JSON_DATA_TYPE_STRING,
							.data.str_val_set = "Intrusion Prevention",
						},
						{
							.key = "enabled",
							.parent_key = "ips",
							.type = CBCC_JSON_DATA_TYPE_STRING,
							.data.str_val_set = service_snort.enabled,
						},
	};

	//for json_service
	cbcc_json_add(mon_final_buff, cbcc_mon_service_jobjs, CBCC_JOBJS_COUNT(cbcc_mon_service_jobjs), &tmp_mon_buff);
	mon_final_buff = tmp_mon_buff;

	/********************** For Monitoring.License *****************************/
	cbcc_json_object_t cbcc_mon_license_jobjs[] =
	{
		{
			.key = "monitoring.license",
			.type = CBCC_JSON_DATA_TYPE_OBJECT,
		},
			{
				.key = "status",
				.parent_key = "monitoring.license",
				.type = CBCC_JSON_DATA_TYPE_OBJECT,
			},
				{
					.key = "level",
					.parent_key = "status",
					.type = CBCC_JSON_DATA_TYPE_INT,
					.data.int_val_set = license.level,
				},
			{
				.key = "data",
				.parent_key = "monitoring.license",
				.type = CBCC_JSON_DATA_TYPE_OBJECT,
			},
				{
					.key = "info",
					.parent_key = "data",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "Owner",
						.parent_key = "info",
						.type = CBCC_JSON_DATA_TYPE_STRING,
						.data.str_val_set = license.owner,
					},
					{
						.key = "Id",
						.parent_key = "info",
						.type = CBCC_JSON_DATA_TYPE_STRING,
						.data.str_val_set = guid,
					},
				{
					.key = "options",
					.parent_key = "data",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "IPSU2D",
						.parent_key = "options",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.int_val_set = license.IPSU2D,
					},
					{
						.key = "NAT",
						.parent_key = "options",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.int_val_set = license.NAT,
					},
					{
						.key = "WAFU2D",
						.parent_key = "options",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.int_val_set = license.WAFU2D,
					},
					{
						.key = "AVU2D",
						.parent_key = "options",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.int_val_set = license.AVU2D,
					},
					{
						.key = "HighAvailability",
						.parent_key = "options",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.int_val_set = license.HighAvailability,
					},
					{
						.key = "CSCD",
						.parent_key = "options",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.int_val_set = license.CSCD,
					},
					{
						.key = "ExpirationDate",
						.parent_key = "options",
						.type = CBCC_JSON_DATA_TYPE_STRING,
						.data.str_val_set = license.ExpirationDate,
					},
					{
						.key = "RegistrationDate",
						.parent_key = "options",
						.type = CBCC_JSON_DATA_TYPE_STRING,
						.data.str_val_set = license.RegistrationDate,
					},
	};

	//for json_license
	cbcc_json_add(mon_final_buff, cbcc_mon_license_jobjs, CBCC_JOBJS_COUNT(cbcc_mon_license_jobjs), &tmp_mon_buff);
	mon_final_buff = tmp_mon_buff;

	/*************************** For Monitoring.Version *************************/
	cbcc_json_object_t cbcc_mon_version_jobjs[] =
	{
		{
			.key = "monitoring.version",
			.type = CBCC_JSON_DATA_TYPE_OBJECT,
		},
			{
				.key = "status",
				.parent_key = "monitoring.version",
				.type = CBCC_JSON_DATA_TYPE_OBJECT,
			},
				{
					.key = "waf_pattern",
					.parent_key = "status",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "failures",
						.parent_key = "waf_pattern",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "level",
							.parent_key = "failures",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = 0,
						},
						{
							.key = "hint",
							.parent_key = "failures",
							.type = CBCC_JSON_DATA_TYPE_STRING,
							.data.str_val_set = "0",
						},
					{
						.key = "count",
						.parent_key = "waf_pattern",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "level",
							.parent_key = "count",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = ips_date_level,
						},
						{
							.key = "hint",
							.parent_key = "count",
							.type = CBCC_JSON_DATA_TYPE_STRING,
							.data.str_val_set = ips_date_hint,
						},
					{
						.key = "auto",
						.parent_key = "waf_pattern",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "level",
							.parent_key = "auto",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = 0,
						},
						{
							.key = "hint",
							.parent_key = "auto",
							.type = CBCC_JSON_DATA_TYPE_STRING,
							.data.str_val_set = "0",
						},
				{
					.key = "av_pattern",
					.parent_key = "status",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "failures",
						.parent_key = "av_pattern",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "level",
							.parent_key = "failures",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = 0,
						},
						{
							.key = "hint",
							.parent_key = "failures",
							.type = CBCC_JSON_DATA_TYPE_STRING,
							.data.str_val_set = "0",
						},
					{
						.key = "count",
						.parent_key = "av_pattern",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "level",
							.parent_key = "count",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = ips_date_level,
						},
						{
							.key = "hint",
							.parent_key = "count",
							.type = CBCC_JSON_DATA_TYPE_STRING,
							.data.str_val_set = ips_date_hint,
						},
					{
						.key = "auto",
						.parent_key = "av_pattern",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "level",
							.parent_key = "auto",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = 0,
						},
						{
							.key = "hint",
							.parent_key = "auto",
							.type = CBCC_JSON_DATA_TYPE_STRING,
							.data.str_val_set = "0",
						},
				{
					.key = "level",
					.parent_key = "status",
					.type = CBCC_JSON_DATA_TYPE_INT,
					.data.int_val_set = 0,
				},
				{
					.key = "pattern",
					.parent_key = "status",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "failures",
						.parent_key = "pattern",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "level",
							.parent_key = "failures",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = 0,
						},
						{
							.key = "hint",
							.parent_key = "failures",
							.type = CBCC_JSON_DATA_TYPE_STRING,
							.data.str_val_set = "0",
						},
					{
						.key = "count",
						.parent_key = "pattern",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "level",
							.parent_key = "count",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = ips_date_level,
						},
						{
							.key = "hint",
							.parent_key = "count",
							.type = CBCC_JSON_DATA_TYPE_STRING,
							.data.str_val_set = ips_date_hint,
						},
					{
						.key = "auto",
						.parent_key = "pattern",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "level",
							.parent_key = "auto",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = 0,
						},
						{
							.key = "hint",
							.parent_key = "auto",
							.type = CBCC_JSON_DATA_TYPE_STRING,
							.data.str_val_set = "0",
						},
				{
					.key = "firmware",
					.parent_key = "status",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "failures",
						.parent_key = "firmware",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "level",
							.parent_key = "failures",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = 0,
						},
						{
							.key = "hint",
							.parent_key = "failures",
							.type = CBCC_JSON_DATA_TYPE_STRING,
							.data.str_val_set = "0",
						},
					{
						.key = "count",
						.parent_key = "firmware",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "level",
							.parent_key = "count",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = 0,
						},
						{
							.key = "hint",
							.parent_key = "count",
							.type = CBCC_JSON_DATA_TYPE_STRING,
							.data.str_val_set = "0",
						},
					{
						.key = "auto",
						.parent_key = "firmware",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "level",
							.parent_key = "auto",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = 0,
						},
						{
							.key = "hint",
							.parent_key = "auto",
							.type = CBCC_JSON_DATA_TYPE_STRING,
							.data.str_val_set = "0",
						},
				{
					.key = "download",
					.parent_key = "status",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "failures",
						.parent_key = "download",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "level",
							.parent_key = "failures",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = 0,
						},
						{
							.key = "hint",
							.parent_key = "failures",
							.type = CBCC_JSON_DATA_TYPE_STRING,
							.data.str_val_set = "0",
						},
					{
						.key = "u2dcache",
						.parent_key = "download",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "level",
							.parent_key = "u2dcache",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = 0,
						},
						{
							.key = "hint",
							.parent_key = "u2dcache",
							.type = CBCC_JSON_DATA_TYPE_STRING,
							.data.str_val_set = "0",
						},
			{
				.key = "data",
				.parent_key = "monitoring.version",
				.type = CBCC_JSON_DATA_TYPE_OBJECT,
			},
				{
					.key = "waf_pattern",
					.parent_key = "data",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "failures",
						.parent_key = "waf_pattern",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.int_val_set = 0,
					},
					{
						.key = "count",
						.parent_key = "waf_pattern",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.int_val_set = 0,
					},
					{
						.key = "auto",
						.parent_key = "waf_pattern",
						.type = CBCC_JSON_DATA_TYPE_STRING,
						.data.str_val_set = "true",
					},
					{
						.key = "active",
						.parent_key = "waf_pattern",
						.type = CBCC_JSON_DATA_TYPE_STRING,
						.data.str_val_set = "WAF_20170710",
					},
					{
						.key = "local",
						.parent_key = "waf_pattern",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.int_val_set = 0,
					},
					{
						.key = "remote",
						.parent_key = "waf_pattern",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.int_val_set = 0,
					},
				{
					.key = "av_pattern",
					.parent_key = "data",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "failures",
						.parent_key = "av_pattern",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.int_val_set = 0,
					},
					{
						.key = "count",
						.parent_key = "av_pattern",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.int_val_set = 0,
					},
					{
						.key = "auto",
						.parent_key = "av_pattern",
						.type = CBCC_JSON_DATA_TYPE_STRING,
						.data.str_val_set = "false",
					},
					{
						.key = "active",
						.parent_key = "av_pattern",
						.type = CBCC_JSON_DATA_TYPE_STRING,
						.data.str_val_set = "n/a",
					},
					{
						.key = "local",
						.parent_key = "av_pattern",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.int_val_set = 0,
					},
					{
						.key = "remote",
						.parent_key = "av_pattern",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.int_val_set = 0,
					},
				{
					.key = "pattern",
					.parent_key = "data",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "failures",
						.parent_key = "pattern",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.int_val_set = 0,
					},
					{
						.key = "count",
						.parent_key = "pattern",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.int_val_set = 0,
					},
					{
						.key = "auto",
						.parent_key = "pattern",
						.type = CBCC_JSON_DATA_TYPE_STRING,
						.data.str_val_set = "true",
					},
					{
						.key = "active",
						.parent_key = "pattern",
						.type = CBCC_JSON_DATA_TYPE_STRING,
						.data.str_val_set = "IPS_20170710",
					},
					{
						.key = "local",
						.parent_key = "pattern",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.int_val_set = 0,
					},
					{
						.key = "remote",
						.parent_key = "pattern",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.int_val_set = 0,
					},
				{
					.key = "firmware",
					.parent_key = "data",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "failures",
						.parent_key = "firmware",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.int_val_set = 0,
					},
					{
						.key = "lineage",
						.parent_key = "firmware",
						.type = CBCC_JSON_DATA_TYPE_STRING,
						.data.str_val_set = "MIniCBSGv101",
					},
					{
						.key = "count",
						.parent_key = "firmware",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.int_val_set = 0,
					},
					{
						.key = "auto",
						.parent_key = "firmware",
						.type = CBCC_JSON_DATA_TYPE_STRING,
						.data.str_val_set = "false",
					},
					{
						.key = "version",
						.parent_key = "firmware",
						.type = CBCC_JSON_DATA_TYPE_STRING,
						.data.str_val_set = "101",
					},
					{
						.key = "active",
						.parent_key = "firmware",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.int_val_set = 0,
					},
					{
						.key = "local",
						.parent_key = "firmware",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.int_val_set = 0,
					},
					{
						.key = "remote",
						.parent_key = "firmware",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.int_val_set = 0,
					},
				{
					.key = "download",
					.parent_key = "data",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "failures",
						.parent_key = "download",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.int_val_set = 0,
					},
					{
						.key = "u2dcache",
						.parent_key = "download",
						.type = CBCC_JSON_DATA_TYPE_STRING,
						.data.str_val_set = "false",
					},					
	};

	//for json_version save
	cbcc_json_add(mon_final_buff, cbcc_mon_version_jobjs, CBCC_JOBJS_COUNT(cbcc_mon_version_jobjs), &tmp_mon_buff);
	mon_final_buff = tmp_mon_buff;

	/************************ For Monitoring.dashboard **************************/
	cbcc_json_object_t cbcc_mon_dashboard_jobjs[] =
	{
		{
			.key = "monitoring.dashboard",
			.type = CBCC_JSON_DATA_TYPE_OBJECT,
		},
			{
				.key = "status",
				.parent_key = "monitoring.dashboard",
				.type = CBCC_JSON_DATA_TYPE_OBJECT,
			},
				{
					.key = "availability",
					.parent_key = "status",
					.type = CBCC_JSON_DATA_TYPE_INT,
					.data.int_val_set = 0,
				},
				{
					.key = "resource",
					.parent_key = "status",
					.type = CBCC_JSON_DATA_TYPE_INT,
					.data.int_val_set = 1,
				},
				{
					.key = "threat",
					.parent_key = "status",
					.type = CBCC_JSON_DATA_TYPE_INT,
					.data.int_val_set = 1,
				},
				{
					.key = "version",
					.parent_key = "status",
					.type = CBCC_JSON_DATA_TYPE_INT,
					.data.int_val_set = 1,
				},
				{
					.key = "license",
					.parent_key = "status",
					.type = CBCC_JSON_DATA_TYPE_INT,
					.data.int_val_set = 1,
				},
				{
					.key = "service",
					.parent_key = "status",
					.type = CBCC_JSON_DATA_TYPE_INT,
					.data.int_val_set = 1,
				},
				{
					.key = "level",
					.parent_key = "status",
					.type = CBCC_JSON_DATA_TYPE_INT,
					.data.int_val_set = 1,
				},
	};

	//for json_dashboard
	cbcc_json_add(mon_final_buff, cbcc_mon_dashboard_jobjs, CBCC_JOBJS_COUNT(cbcc_mon_dashboard_jobjs), &tmp_mon_buff);
	mon_final_buff = tmp_mon_buff;

	/*********************** For monitoring.resource ****************************/
	cbcc_json_object_t cbcc_mon_resource_jobjs[] =
	{
		{
			.key = "monitoring.resource",
			.type = CBCC_JSON_DATA_TYPE_OBJECT,
		},
			{
				.key = "status",
				.parent_key = "monitoring.resource",
				.type = CBCC_JSON_DATA_TYPE_OBJECT,
			},
				{
					.key = "level",
					.parent_key = "status",
					.type = CBCC_JSON_DATA_TYPE_INT,
					.data.int_val_set = 1,
				},
				{
					.key = "hdd",
					.parent_key = "status",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "level",
						.parent_key = "hdd",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.int_val_set = 1,
					},
					{
						.key = "hint",
						.parent_key = "hdd",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.int_val_set = 10.33333333333,
					},
					{
						.key = "details",
						.parent_key = "hdd",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "/",
							.parent_key = "details",
							.type = CBCC_JSON_DATA_TYPE_OBJECT,
						},
							{
								.key = "level",
								.parent_key = "/",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = 1,
							},
							{
								.key = "hint",
								.parent_key = "/",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = 22,
							},
						{
							.key = "/tmp",
							.parent_key = "details",
							.type = CBCC_JSON_DATA_TYPE_OBJECT,
						},
							{
								.key = "level",
								.parent_key = "/tmp",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = 1,
							},
							{
								.key = "hint",
								.parent_key = "/tmp",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = 9,
							},
						{
							.key = "/dev",
							.parent_key = "details",
							.type = CBCC_JSON_DATA_TYPE_OBJECT,
						},
							{
								.key = "level",
								.parent_key = "/dev",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = 1,
							},
							{
								.key = "hint",
								.parent_key = "/dev",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = 0,
							},
				{
					.key = "mem",
					.parent_key = "status",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "swap",
						.parent_key = "mem",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "percent",
							.parent_key = "swap",
							.type = CBCC_JSON_DATA_TYPE_OBJECT,
						},
							{
								.key = "level",
								.parent_key = "percent",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = 1,
							},
							{
								.key = "hint",
								.parent_key = "percent",
								.type = CBCC_JSON_DATA_TYPE_STRING,
								.data.str_val_set = "1",
							},
					{
						.key = "main",
						.parent_key = "mem",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "percent",
							.parent_key = "main",
							.type = CBCC_JSON_DATA_TYPE_OBJECT,
						},
							{
								.key = "level",
								.parent_key = "percent",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = 2,
							},
							{
								.key = "hint",
								.parent_key = "percent",
								.type = CBCC_JSON_DATA_TYPE_STRING,
								.data.str_val_set = "44",
							},
				{
					.key = "net",
					.parent_key = "status",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "nic_state",
						.parent_key = "net",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "level",
							.parent_key = "nic_state",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = net0.nic_state + net1.nic_state,
						},
						{
							.key = "details",
							.parent_key = "nic_state",
							.type = CBCC_JSON_DATA_TYPE_OBJECT,
						},
							{
								.key = "eth0",
								.parent_key = "details",
								.type = CBCC_JSON_DATA_TYPE_OBJECT,
							},
								{
									.key = "level",
									.parent_key = "eth0",
									.type = CBCC_JSON_DATA_TYPE_INT,
									.data.int_val_set = net0.nic_state,
								},
					{
						.key = "link_state",
						.parent_key = "net",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "level",
							.parent_key = "link_state",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = net0.link_state + net1.link_state,
						},
						{
							.key = "details",
							.parent_key = "link_state",
							.type = CBCC_JSON_DATA_TYPE_OBJECT,
						},
							{
								.key = "eth0",
								.parent_key = "details",
								.type = CBCC_JSON_DATA_TYPE_OBJECT,
							},
								{
									.key = "level",
									.parent_key = "eth0",
									.type = CBCC_JSON_DATA_TYPE_INT,
									.data.int_val_set = net0.link_state,
								},
			{
				.key = "data",
				.parent_key = "monitoring.resource",
				.type = CBCC_JSON_DATA_TYPE_OBJECT,
			},
				{
					.key = "hdd",
					.parent_key = "data",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "percent",
						.parent_key = "hdd",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.int_val_set = hard_percent,
					},
					{
						.key = "used",
						.parent_key = "hdd",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.int_val_set = hard_used * 1024,
					},
					{
						.key = "total",
						.parent_key = "hdd",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.int_val_set = hard_total * 1024,
					},
					{
						.key = "details",
						.parent_key = "hdd",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "/",
							.parent_key = "details",
							.type = CBCC_JSON_DATA_TYPE_OBJECT,
						},
							{
								.key = "blocks_fulltime",
								.parent_key = "/",
								.type = CBCC_JSON_DATA_TYPE_STRING,
								.data.str_val_set = hard_part1.blocks_fulltime,
							},
							{
								.key = "blocksize",
								.parent_key = "/",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = hard_part1.blocksize * 1024,
							},
							{
								.key = "percent",
								.parent_key = "/",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = hard_part1.percent,
							},
							{
								.key = "filesystem",
								.parent_key = "/",
								.type = CBCC_JSON_DATA_TYPE_STRING,
								.data.str_val_set = hard_part1.filesystem,
							},
							{
								.key = "used",
								.parent_key = "/",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.str_val_set = hard_part1.used * 1024,
							},
							{
								.key = "availiable",
								.parent_key = "/",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.str_val_set = hard_part1.availiable * 1024,
							},
							{
								.key = "total",
								.parent_key = "/",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set =	hard_part1.total * 1024,
							},
							{
								.key = "block_persec",
								.parent_key = "/",
								.type = CBCC_JSON_DATA_TYPE_STRING,
								.data.str_val_set = hard_part1.block_persec,
							},
							{
								.key = "size",
								.parent_key = "/",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = hard_part1.size * 1024,
							},
						{
							.key = "/tmp",
							.parent_key = "details",
							.type = CBCC_JSON_DATA_TYPE_OBJECT,
						},
							{
								.key = "blocks_fulltime",
								.parent_key = "/tmp",
								.type = CBCC_JSON_DATA_TYPE_STRING,
								.data.str_val_set = hard_part2.blocks_fulltime,
							},
							{
								.key = "blocksize",
								.parent_key = "/tmp",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = hard_part2.blocksize * 1024,
							},
							{
								.key = "percent",
								.parent_key = "/tmp",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = hard_part2.percent,
							},
							{
								.key = "filesystem",
								.parent_key = "/tmp",
								.type = CBCC_JSON_DATA_TYPE_STRING,
								.data.str_val_set = hard_part2.filesystem,
							},
							{
								.key = "used",
								.parent_key = "/tmp",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.str_val_set = hard_part2.used * 1024,
							},
							{
								.key = "availiable",
								.parent_key = "/tmp",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.str_val_set = hard_part2.availiable * 1024,
							},
							{
								.key = "total",
								.parent_key = "/tmp",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set =	hard_part2.total * 1024,
							},
							{
								.key = "block_persec",
								.parent_key = "/tmp",
								.type = CBCC_JSON_DATA_TYPE_STRING,
								.data.str_val_set = hard_part2.block_persec,
							},
							{
								.key = "size",
								.parent_key = "/tmp",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = hard_part2.size * 1024,
							},
						{
							.key = "/dev",
							.parent_key = "details",
							.type = CBCC_JSON_DATA_TYPE_OBJECT,
						},
							{
								.key = "blocks_fulltime",
								.parent_key = "/dev",
								.type = CBCC_JSON_DATA_TYPE_STRING,
								.data.str_val_set = hard_part3.blocks_fulltime,
							},
							{
								.key = "blocksize",
								.parent_key = "/dev",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = hard_part3.blocksize * 1024,
							},
							{
								.key = "percent",
								.parent_key = "/dev",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = hard_part3.percent,
							},
							{
								.key = "filesystem",
								.parent_key = "/dev",
								.type = CBCC_JSON_DATA_TYPE_STRING,
								.data.str_val_set = hard_part3.filesystem,
							},
							{
								.key = "used",
								.parent_key = "/dev",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.str_val_set = hard_part3.used * 1024,
							},
							{
								.key = "availiable",
								.parent_key = "/dev",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.str_val_set = hard_part3.availiable * 1024,
							},
							{
								.key = "total",
								.parent_key = "/dev",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set =	hard_part3.total * 1024,
							},
							{
								.key = "block_persec",
								.parent_key = "/dev",
								.type = CBCC_JSON_DATA_TYPE_STRING,
								.data.str_val_set = hard_part3.block_persec,
							},
							{
								.key = "size",
								.parent_key = "/dev",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = hard_part3.size * 1024,
							},
				{
					.key = "cpu",
					.parent_key = "data",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "usage",
						.parent_key = "cpu",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "average",
							.parent_key = "usage",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = cpu_usage_average,
						},
						{
							.key = "values",
							.parent_key = "usage",
							.type = CBCC_JSON_DATA_TYPE_INT_ARRAY,
							.data.arr_val = cpu_array,
						},
					{
						.key = "load",
						.parent_key = "cpu",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},

						{
							.key = "values",
							.parent_key = "load",
							.type = CBCC_JSON_DATA_TYPE_STR_ARRAY,
							.data.arr_val = load_array,
						},
						{
							.key = "trend",
							.parent_key = "load",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = cpu_load_trend,
						},
				{
					.key = "mem",
					.parent_key = "data",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "swap",
						.parent_key = "mem",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "percent",
							.parent_key = "swap",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = mem_swap_percent,
						},
						{
							.key = "used",
							.parent_key = "swap",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = mem_swap_used,
						},
						{
							.key = "total",
							.parent_key = "swap",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = mem_swap_total,
						},
					{
						.key = "main",
						.parent_key = "mem",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "percent",
							.parent_key = "main",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = mem_main_percent,
						},
						{
							.key = "used",
							.parent_key = "main",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = mem_main_used,
						},
						{
							.key = "total",
							.parent_key = "main",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = mem_main_total,
						},
				{
					.key = "net",
					.parent_key = "data",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "details",
						.parent_key = "net",
						.type = CBCC_JSON_DATA_TYPE_OBJECT
					},
						{
							.key = "eth0",
							.parent_key = "details",
							.type = CBCC_JSON_DATA_TYPE_OBJECT,
						},
							{
								.key = "nic_state",
								.parent_key = "eth0",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = net0.nic_state,
							},
							{
								.key = "RX_errors",
								.parent_key = "eth0",
								.type = CBCC_JSON_DATA_TYPE_STRING,
								.data.str_val_set = net0.RX_errors,
							},
							{
								.key = "RX_BPS",
								.parent_key = "eth0",
								.type = CBCC_JSON_DATA_TYPE_STRING,
								.data.str_val_set = net0.RX_BPS,
							},
							{
								.key = "TX_BPS",
								.parent_key = "eth0",
								.type = CBCC_JSON_DATA_TYPE_STRING,
								.data.str_val_set = net0.TX_BPS,
							},
							{
								.key = "TX_bytes",
								.parent_key = "eth0",
								.type = CBCC_JSON_DATA_TYPE_STRING,
								.data.str_val_set = net0.TX_bytes,
							},
							{
								.key = "link_state",
								.parent_key = "eth0",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = net0.link_state,
							},
							{
								.key = "RX_bytes",
								.parent_key = "eth0",
								.type = CBCC_JSON_DATA_TYPE_STRING,
								.data.str_val_set = net0.RX_bytes,
							},
							{
								.key = "TX_errors",
								.parent_key = "eth0",
								.type = CBCC_JSON_DATA_TYPE_STRING,
								.data.str_val_set = net0.TX_errors,
							},
							{
								.key = "Total_bytes",
								.parent_key = "eth0",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = net0.Total_bytes,
							},
						{
							.key = "eth1",
							.parent_key = "details",
							.type = CBCC_JSON_DATA_TYPE_OBJECT,
						},
							{
								.key = "nic_state",
								.parent_key = "eth1",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = net1.nic_state,
							},
							{
								.key = "RX_errors",
								.parent_key = "eth1",
								.type = CBCC_JSON_DATA_TYPE_STRING,
								.data.str_val_set = net1.RX_errors,
							},
							{
								.key = "RX_BPS",
								.parent_key = "eth1",
								.type = CBCC_JSON_DATA_TYPE_STRING,
								.data.str_val_set = net1.RX_BPS,
							},
							{
								.key = "TX_BPS",
								.parent_key = "eth1",
								.type = CBCC_JSON_DATA_TYPE_STRING,
								.data.str_val_set = net1.TX_BPS,
							},
							{
								.key = "TX_bytes",
								.parent_key = "eth1",
								.type = CBCC_JSON_DATA_TYPE_STRING,
								.data.str_val_set = net1.TX_bytes,
							},
							{
								.key = "link_state",
								.parent_key = "eth1",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = net1.link_state,
							},
							{
								.key = "RX_bytes",
								.parent_key = "eth1",
								.type = CBCC_JSON_DATA_TYPE_STRING,
								.data.str_val_set = net1.RX_bytes,
							},
							{
								.key = "TX_errors",
								.parent_key = "eth1",
								.type = CBCC_JSON_DATA_TYPE_STRING,
								.data.str_val_set = net1.TX_errors,
							},
							{
								.key = "Total_bytes",
								.parent_key = "eth1",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = net1.Total_bytes,
							},
	};
	//for json_resource save
	cbcc_json_add(mon_final_buff, cbcc_mon_resource_jobjs, CBCC_JOBJS_COUNT(cbcc_mon_resource_jobjs), &tmp_mon_buff);
	mon_final_buff = tmp_mon_buff;

	/************************ For Monitoring.threat **************************/
	cbcc_json_object_t cbcc_mon_threat_jobjs[] =
	{
		{
			.key = "monitoring.threat",
			.type = CBCC_JSON_DATA_TYPE_OBJECT,
		},
			{
				.key = "status",
				.parent_key = "monitoring.threat",
				.type = CBCC_JSON_DATA_TYPE_OBJECT,
			},
				{
					.key = "level",
					.parent_key = "status",
					.type = CBCC_JSON_DATA_TYPE_INT,
					.data.int_val_set = level_threat,
				},
				{
					.key = "system_restarts",
					.parent_key = "status",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "deviation",
						.parent_key = "system_restarts",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "level",
							.parent_key = "deviation",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = level_restart,
						},
						{
							.key = "hint",
							.parent_key = "deviation",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = hint_restart,
						},
				{
					.key = "Intrusion_events",
					.parent_key = "status",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "deviation",
						.parent_key = "Intrusion_events",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "level",
							.parent_key = "deviation",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = level_ips,
						},
						{
							.key = "hint",
							.parent_key = "deviation",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = hint_ips,
						},
				{
					.key = "portscan_events",
					.parent_key = "status",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "deviation",
						.parent_key = "portscan_events",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "level",
							.parent_key = "deviation",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = level_portscan,
						},
						{
							.key = "hint",
							.parent_key = "deviation",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = hint_portscan,
						},
				{
					.key = "pfilter_events",
					.parent_key = "status",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "deviation",
						.parent_key = "pfilter_events",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "level",
							.parent_key = "deviation",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = level_pfilter,
						},
						{
							.key = "hint",
							.parent_key = "deviation",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = hint_pfilter,
						},
				{
					.key = "failed_logins",
					.parent_key = "status",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "deviation",
						.parent_key = "failed_logins",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "level",
							.parent_key = "deviation",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = level_login,
						},
						{
							.key = "hint",
							.parent_key = "deviation",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = hint_login,
						},
				{
					.key = "caught_viruses",
					.parent_key = "status",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "deviation",
						.parent_key = "caught_viruses",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "level",
							.parent_key = "deviation",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = level_viruses,
						},
						{
							.key = "hint",
							.parent_key = "deviation",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = hint_viruses,
						},
			{
				.key = "data",
				.parent_key = "monitoring.threat",
				.type = CBCC_JSON_DATA_TYPE_OBJECT,
			},
				{
					.key = "system_restarts",
					.parent_key = "data",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "deviation",
						.parent_key = "system_restarts",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.str_val_set = trend_restart,
					},
					{
						.key = "values",
						.parent_key = "system_restarts",
						.type = CBCC_JSON_DATA_TYPE_INT_ARRAY,
						.data.arr_val = array_restart,
					},
				{
					.key = "intrusion_events",
					.parent_key = "data",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "deviation",
						.parent_key = "intrusion_events",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.str_val_set = trend_ips,
					},
					{
						.key = "values",
						.parent_key = "intrusion_events",
						.type = CBCC_JSON_DATA_TYPE_INT_ARRAY,
						.data.arr_val = array_ips,
					},
				// {
				// 	.key = "portscan_events",
				// 	.parent_key = "data",
				// 	.type = CBCC_JSON_DATA_TYPE_OBJECT,
				// },
				// 	{
				// 		.key = "deviation",
				// 		.parent_key = "portscan_events",
				// 		.type = CBCC_JSON_DATA_TYPE_INT,
				// 		.data.str_val_set = trend_portscan,
				// 	},
				// 	{
				// 		.key = "values",
				// 		.parent_key = "portscan_events",
				// 		.type = CBCC_JSON_DATA_TYPE_INT_ARRAY,
				// 		.data.arr_val = array_portscan,
				// 	},
				{
					.key = "pfilter_events",
					.parent_key = "data",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "deviation",
						.parent_key = "pfilter_events",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.str_val_set = trend_pfilter,
					},
					{
						.key = "values",
						.parent_key = "pfilter_events",
						.type = CBCC_JSON_DATA_TYPE_INT_ARRAY,
						.data.arr_val = array_pfilter,
					},
				{
					.key = "failed_logins",
					.parent_key = "data",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "deviation",
						.parent_key = "failed_logins",
						.type = CBCC_JSON_DATA_TYPE_INT,
						.data.str_val_set = trend_login,
					},
					{
						.key = "values",
						.parent_key = "failed_logins",
						.type = CBCC_JSON_DATA_TYPE_INT_ARRAY,
						.data.arr_val = array_login,
					},
				// {
				// 	.key = "caught_viruses",
				// 	.parent_key = "data",
				// 	.type = CBCC_JSON_DATA_TYPE_OBJECT,
				// },
				// 	{
				// 		.key = "deviation",
				// 		.parent_key = "caught_viruses",
				// 		.type = CBCC_JSON_DATA_TYPE_INT,
				// 		.data.str_val_set = trend_viruses,
				// 	},
				// 	{
				// 		.key = "values",
				// 		.parent_key = "caught_viruses",
				// 		.type = CBCC_JSON_DATA_TYPE_INT_ARRAY,
				// 		.data.arr_val = array_viruses,
				// 	},
	};
	cbcc_json_add(mon_final_buff, cbcc_mon_threat_jobjs, CBCC_JOBJS_COUNT(cbcc_mon_threat_jobjs), &tmp_mon_buff);
	mon_final_buff = tmp_mon_buff;
	/************************ For Monitoring.availibilty **************************/
	cbcc_json_object_t cbcc_mon_availability_jobjs[] =
	{
		{
			.key = "monitoring.availability",
			.type = CBCC_JSON_DATA_TYPE_OBJECT,
		},
			{
				.key = "status",
				.parent_key = "monitoring.availability",
				.type = CBCC_JSON_DATA_TYPE_OBJECT,
			},
				{
					.key = "level",
					.parent_key = "status",
					.type = CBCC_JSON_DATA_TYPE_INT,
					.data.int_val_set = 0,
				},
			{
				.key = "data",
				.parent_key = "monitoring.availability",
				.type = CBCC_JSON_DATA_TYPE_OBJECT,
			},
				{
					.key = "ha",
					.parent_key = "data",
					.type = CBCC_JSON_DATA_TYPE_OBJECT,
				},
					{
						.key = "info",
						.parent_key = "ha",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "nodes",
							.parent_key = "info",
							.type = CBCC_JSON_DATA_TYPE_OBJECT,
						},
							{
								.key = "active",
								.parent_key = "nodes",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = 0,
							},
							{
								.key = "total",
								.parent_key = "nodes",
								.type = CBCC_JSON_DATA_TYPE_INT,
								.data.int_val_set = 0,
							},	
					{
						.key = "config",
						.parent_key = "ha",
						.type = CBCC_JSON_DATA_TYPE_OBJECT,
					},
						{
							.key = "network",
							.parent_key = "config",
							.type = CBCC_JSON_DATA_TYPE_STRING,
							.data.str_val_set = "",
						},
						{
							.key = "device_name",
							.parent_key = "config",
							.type = CBCC_JSON_DATA_TYPE_STRING,
							.data.str_val_set = "",
						},
						{
							.key = "status",
							.parent_key = "config",
							.type = CBCC_JSON_DATA_TYPE_STRING,
							.data.str_val_set = "false",
						},
						{
							.key = "autojoin",
							.parent_key = "config",
							.type = CBCC_JSON_DATA_TYPE_INT,
							.data.int_val_set = 0,
						},
						{
							.key = "type",
							.parent_key = "config",
							.type = CBCC_JSON_DATA_TYPE_STRING,
							.data.str_val_set = "off",
						},
						{
							.key = "itfhw_ref",
							.parent_key = "config",
							.type = CBCC_JSON_DATA_TYPE_STRING,
							.data.str_val_set = "",
						},
	};
	cbcc_json_add(mon_final_buff, cbcc_mon_availability_jobjs, CBCC_JOBJS_COUNT(cbcc_mon_availability_jobjs), &tmp_mon_buff);
	mon_final_buff = tmp_mon_buff;
	char *final_fpath = "/etc/cbcc-agent/monitor_data.json";
	FILE *mon_final_file = fopen(final_fpath, "w");
	if (mon_final_file == NULL)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "MON: Could not read %s", final_fpath);
		remove(final_fpath);
		return;
	}
	fwrite(mon_final_buff, 1, strlen(mon_final_buff), mon_final_file);
	fclose(mon_final_file);

	free(mon_final_buff);

	free(array_restart);
	free(array_ips);
	free(array_portscan);
	free(array_pfilter);
	free(array_login);
	free(array_viruses);
	free(cpu_array);

	return;
}

// get monitoring data
static int get_mon_data_from_confd(cbcc_agent_monitor_t *mon_mgr, char **mon_data)
{
	make_monitor_json_for_OpenWRT(mon_mgr);

	char *monitor_data_fpath = "/etc/cbcc-agent/monitor_data.json";
	
	// get json data from file
	if (read_file_contents(monitor_data_fpath, mon_data) < 0)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "MON: Could not read JSON data from %s", monitor_data_fpath);
		return -1;
	}

	return 0;
}

// send monitoring data
static int cbcc_mon_send_data(cbcc_agent_monitor_t *mon_mgr)
{
	char *mon_cmd = NULL;
	char *mon_data = NULL;
	
	int ret = 0;
	
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_HIGH, "MON: Sending monitoring data.");
	
	// get monitoring data from confd
	if (get_mon_data_from_confd(mon_mgr, &mon_data) != 0)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "MON: Could not monitoring data from confd.");
		return -1;
	}
	
	cbcc_json_object_t cbcc_mon_objs[] =
	{
		{
			.key = "cmd",
			.type = CBCC_JSON_DATA_TYPE_STRING,
			.data.str_val_set = CBCC_CMD_MONITOR,
		},
		{
			.key = "data",
			.type = CBCC_JSON_DATA_TYPE_OBJECT,
			.obj_exist_data = true,
			.data.str_val_set = mon_data,
		}
	};
	
	// build json data
	cbcc_json_build(cbcc_mon_objs, CBCC_JOBJS_COUNT(cbcc_mon_objs), &mon_cmd);
	
	// send monitor data
	if (cbcc_session_send_msg(&mon_mgr->c->session_mgr, mon_cmd) < 0)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "MON: Could not send monitoring data due to '%s'", strerror(errno));
		ret = -1;
	}
	
	free(mon_cmd);
	free(mon_data);
	
	return ret;
}

// cbcc agent monitoring thread proc
static void *cbcc_agent_monitor_proc(void *p)
{
	cbcc_agent_monitor_t *mon_mgr = (cbcc_agent_monitor_t *) p;
	
	bool first_time = true;
	time_t monitor_sent_tm = time(NULL);
	
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "MON: Started CBCC agent monitoring thread.");
	
	while (!mon_mgr->end_flag)
	{
		bool send_monitor_data = false;
		time_t curr_tm = time(NULL);
		
		// check device is logined
		if (!mon_mgr->c->session_mgr.logined)
		{
			sleep(1);
			continue;
		}

		// determine flag to send monitor data
		if (first_time)
		{
			send_monitor_data = true;
			first_time = false;
		}
		else
		{
			if ((curr_tm - monitor_sent_tm) > CBCC_AGENT_MON_INTERVAL)
				send_monitor_data = true;
		}

		if (!send_monitor_data)
		{
			sleep(1);
			continue;
		}

		// send monitoring data
		cbcc_mon_send_data(mon_mgr);

		// update sent time
		monitor_sent_tm = curr_tm;
		
		sleep(1);
	}
	
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "MON: Stopped CBCC agent monitoring thread.");
	
	return 0;
}


// initialize cbcc agent monitor
int cbcc_agent_monitor_init(cbcc_agent_ctx_t *c)
{
	cbcc_agent_monitor_t *mon_mgr = &c->mon_mgr;
	
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "MON: Initializing CBCCD monitoring manager.");
	
	// set context object
	mon_mgr->c = c;
	
	// create thread to send monitoring command
	if (pthread_create(&mon_mgr->pt_mon, NULL, cbcc_agent_monitor_proc, (void *) mon_mgr) != 0)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "MON: Could not create thread for monitoring due to %s", strerror(errno));
		return -1;
	}
	
	mon_mgr->init_flag = true;
	
	return 0;
}

// finalize cbcc agent monitor
void cbcc_agent_monitor_finalize(cbcc_agent_monitor_t *mon_mgr)
{
	// check init flag
	if (!mon_mgr->init_flag)
		return;
	
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "MON: Finalizing CBCCD monitoring manager.");
	
	// set end flag
	mon_mgr->end_flag = true;
	
	// wait until monitoring thread has finished
	pthread_join(mon_mgr->pt_mon, NULL);
	
	return;
}