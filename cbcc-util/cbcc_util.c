#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#include <openssl/md5.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#include "cbcc_common.h"

#include "cbcc_debug.h"
#include "cbcc_util.h"

// get process ID by process name
pid_t get_procid_by_procname(const char *proc_name)
{
	FILE *pid_fp;                                 // file pointer to pid file
	FILE *proc_fp;                              // file pointer to /proc/<pid>/cmdline file

	pid_t pid = 0;
	
	char pid_fpath[CBCC_MAX_PATH];
	
	char proc_fpath[CBCC_MAX_PATH];
	char buf[512];
	
	// make process ID file path from process name
	snprintf(pid_fpath, sizeof(pid_fpath), "/var/run/%s.pid", proc_name);

	// open PID file
	pid_fp = fopen(pid_fpath, "r");
	if (!pid_fp)
		return 0;

	// get pid
	while (fgets(buf, sizeof(buf), pid_fp) != NULL)
	{
		// remove endline charactors
		buf[strlen(buf) - 1] = '\0';

		if (strlen(buf) == 0)
			continue;

		pid = atoi(buf);
		if (pid > 0)
			break;
	}

	// close pid file
	fclose(pid_fp);

	// check pid is valid
	if (pid < 1)
		return 0;

	// check /proc file system
	snprintf(proc_fpath, sizeof(proc_fpath), "/proc/%d/cmdline", pid);

	proc_fp = fopen(proc_fpath, "r");
	if (!proc_fp)
		return 0;

	fgets(buf, sizeof(buf), proc_fp);

	fclose(proc_fp);

	// check command line
	if (strstr(buf, proc_name))
		return pid;

	return 0;

}

// write PID file
void write_pid_file(const char *proc_name)
{
	FILE *pid_fp;
	pid_t pid;
	
	char pid_fpath[CBCC_MAX_PATH];
	
	// make process ID file path from process name
	snprintf(pid_fpath, sizeof(pid_fpath), "/var/run/%s.pid", proc_name);

	// get current process ID
	pid = getpid();

	// open pid file and write pid into it
	pid_fp = fopen(pid_fpath, "w");
	if (!pid_fp)
	{
		fprintf(stderr, "Create PID file %s failed\n", pid_fpath);
		exit(1);
	}

	fprintf(pid_fp, "%d\n", pid);

	// close pid file
	fclose(pid_fp);

	return;
}

// daemonize program
void daemonize()
{
	int pid, sid;

	// fork new process
	pid = fork();
	if (pid < 0)
		exit(1);

	if (pid > 0)
	{
		// child created, parent exit
		exit(0);
	}

	// set file permission 750
	umask(027);

	// get new process group
	sid = setsid();
	if (sid < 0)
		exit(1);

	// close standard I/O, stdin, stdout, stderr
	close(0);
	close(1);
	close(2);

	// redirect stdin/stdout/stderr to /dev/null
	open("/dev/null", O_RDWR);

	dup(0);		// stdout
	dup(0);		// stderr

	return;
}

// get file size
int get_file_size(const char *fpath)
{
	struct stat st;
	
	// get file stat
	if (stat(fpath, &st) != 0)
		return -1;
		
	// check if given file is regular
	if (!S_ISREG(st.st_mode))
		return -1;
		
	return st.st_size;
}

// convert object name to table name
void get_tblname_by_objname(const char *obj_name, char *tbl_name, size_t s)
{
	const char *p = obj_name;
	unsigned int i = 0;
	
	while (*p != '\0')
	{
		// check buffer overflow
		if (i == (s - 1))
			break;
		
		// replace '.' to '_'
		if (*p == '.')
			tbl_name[i++] = '_';
		else
			tbl_name[i++] = *p;

		p++;
	}
	
	tbl_name[i] = '\0';
	
	return;
}

// get object type by table name
void get_objtype_by_tblname(const char *tbl_name, char *obj_type, size_t s)
{
	const char *p = tbl_name;
	unsigned int i = 0;
	
	while (*p != '\0')
	{
		// check buffer overflow
		if (i == (s - 1))
			break;
		
		// replace '_' to '.'
		if (*p == '_')
			obj_type[i++] = '.';
		else
			obj_type[i++] = *p;

		p++;
	}
	
	obj_type[i] = '\0';
	
	return;
}

// read file contents
int read_file_contents(const char *fpath, char **buf)
{
	FILE *fp;
	
	char *pdata = NULL;
	unsigned int data_len;
	
	struct stat st;
	
	// get file size
	if (stat(fpath, &st) != 0)
		return -1;
	
	// check file mode
	if (!S_ISREG(st.st_mode))
		return -1;
	
	// check file size
	if (st.st_size <= 0)
		return -1;
	
	// open file
	fp = fopen(fpath, "r");
	if (!fp)
		return -1;
	
	// allocate memory
	pdata = (char *) malloc(st.st_size + 1);
	if (!pdata)
	{
		fclose(fp);
		return -1;
	}
	
	// read monitoring data
	data_len = fread(pdata, 1, st.st_size, fp);
	pdata[data_len] = '\0';

	// close file
	fclose(fp);
	
	*buf = pdata;
	
	return data_len;
}

// create guid by key
// Note: guid will have '-' in index 8, 12, 16, 20

void create_random_guid(char *guid, size_t s)
{
	char key[32];
	
	unsigned char md5sum[CBCC_MD5SUM_LEN];
	MD5_CTX md5_ctx;
	
	// get key by timestamp
	snprintf(key, sizeof(key), "%lu", time(NULL) + rand());
	
	// initialize MD5 context
	if (!MD5_Init(&md5_ctx))
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_HIGH, "UTIL: Could not initialize MD5 context");
		return;
	}
	
	MD5_Update(&md5_ctx, key, strlen(key));
	MD5_Final(md5sum, &md5_ctx);
	
	// init guid buffer
	memset(guid, 0, s);
	
	// set guid
	for (int i = 0; i < CBCC_MD5SUM_LEN; i++)
	{
		char tmp[3];
		
		if (i == 4 || i == 6 || i == 8 || i == 10)
			strcat(guid, "-");
		
		snprintf(tmp, sizeof(tmp), "%02x", md5sum[i]);
		strcat(guid, tmp);
	}
	
	return;
}

// get md5sum of file
int get_md5sum_of_file(const char *fpath, int binary_mode, char *md5sum_of_file, size_t s)
{
	FILE *fp;
	
	unsigned char *buf;
	int fsize;
	
	// get file size
	fsize = get_file_size(fpath);
	if (fsize <= 0)
		return -1;
	
	// get file contents
	fp = fopen(fpath, binary_mode ? "rb" : "r");
	if (!fp)
		return -1;
	
	buf = (unsigned char *) malloc(fsize);
	fread(buf, 1, fsize, fp);
	
	fclose(fp);

	unsigned char md5sum[CBCC_MD5SUM_LEN];
	MD5_CTX md5_ctx;
	
	// initialize MD5 context
	if (!MD5_Init(&md5_ctx))
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_HIGH, "UTIL: Could not initialize MD5 context");
		free(buf);
		
		return -1;
	}
	
	MD5_Update(&md5_ctx, buf, fsize);
	MD5_Final(md5sum, &md5_ctx);
	
	// free file buffer
	free(buf);
	
	// set md5sum of file
	memset(md5sum_of_file, 0, s);
	for (int i = 0; i < CBCC_MD5SUM_LEN; i++)
	{
		char tmp[3];
		
		snprintf(tmp, sizeof(tmp), "%02x", md5sum[i]);
		strcat(md5sum_of_file, tmp);
	}
	
	return 0;
}

// get md5sum of buffer
int get_md5sum_of_buffer(const char *buffer, char *md5sum, size_t s)
{
	unsigned char md5[CBCC_MD5SUM_LEN];
	MD5_CTX md5_ctx;
	
	// initialize MD5 context
	if (!MD5_Init(&md5_ctx))
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_HIGH, "UTIL: Could not initialize MD5 context");
		return -1;
	}
	
	MD5_Update(&md5_ctx, buffer, strlen(buffer));
	MD5_Final(md5, &md5_ctx);
	
	// set md5sum of file
	memset(md5sum, 0, s);
	for (int i = 0; i < CBCC_MD5SUM_LEN; i++)
	{
		char tmp[3];
		
		snprintf(tmp, sizeof(tmp), "%02x", md5[i]);
		strcat(md5sum, tmp);
	}
	
	return 0;
}

// base 64 encoding function
static int base64_encode(unsigned char *src, int src_len, char **dst)
{
	BIO *bmem, *b64;
	BUF_MEM *bptr;

	char *ret;

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new(BIO_s_mem());
	
	BIO_push(b64, bmem);

	BIO_write(b64, src, src_len);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	ret = (char *) malloc(bptr->length);
	memcpy(ret, bptr->data, bptr->length - 1);
	ret[bptr->length - 1] = 0;

	BIO_free_all(b64);

	*dst = ret;
	
	return 0;
}

// get base64 encoded data
int get_base64_encoded_from_file(const char *fpath, char **base64_encoded)
{
	FILE *fp;
	
	unsigned char *buf;
	int fsize;
	
	// get file size
	fsize = get_file_size(fpath);
	if (fsize <= 0)
		return -1;
	
	// get file contents
	fp = fopen(fpath, "rb");
	if (!fp)
		return -1;
	
	buf = (unsigned char *) malloc(fsize);
	fread(buf, 1, fsize, fp);
	
	fclose(fp);

	base64_encode(buf, fsize, base64_encoded);
	
	return 0;
}

// decode base64 encoded data and write into file
int decode_base64_to_file(const char *base64_encoded, const char *fpath)
{
	BIO *b64, *bio_in, *bio_out;
	FILE *fp_in, *fp_out;
	
	unsigned char buf[512];
	int buf_len;

	fp_in = fmemopen((void *) base64_encoded, strlen(base64_encoded), "r");
	if (!fp_in)
		return -1;
	
	fp_out = fopen(fpath, "wb");
	if (!fp_out)
	{
		fclose(fp_in);
		return -1;
	}

	b64 = BIO_new(BIO_f_base64());
	bio_in = BIO_new_fp(fp_in, BIO_NOCLOSE);
	bio_out = BIO_new_fp(fp_out, BIO_NOCLOSE);
	BIO_push(b64, bio_in);
	
	while((buf_len = BIO_read(b64, buf, sizeof(buf))) > 0)
		BIO_write(bio_out, buf, buf_len);

	BIO_flush(bio_in);
	BIO_flush(bio_out);
	BIO_free_all(b64);
	
	fclose(fp_in);
	fclose(fp_out);

	return 0;
}

void get_host_info_from_system(
					char **customer, 
					char **hostname, 
					char **password, 
					char **secret, 
					char **guid)
{
	char buf[128] = {0, };
	char customer_tmp[64] = {0, };
	char hostname_tmp[64] = {0, };
	char guid_tmp[64] = {0, };
	char secret_tmp[256] = {0, };

	int len;

	char *customer_ret = NULL;
	char *hostname_ret = NULL;
	char *secret_ret = NULL;
	char *password_ret = NULL;
	char *guid_ret = NULL;

	char *cmd = NULL;

	char *fpath = "/etc/config/system";
	FILE *fp = NULL;
	
	fp = fopen(fpath, "r");
	if(fp != NULL) {
		while(fgets(buf, sizeof(buf), fp))
		{
			if (!strncmp(buf, "	option org", 11))
			{
				memset(customer_tmp, 0, sizeof(customer_tmp));
				len = strlen(buf) - 14;
				strncpy(customer_tmp, strstr(buf, "'"), len);
				customer_ret = (char *)malloc(64);
				memset(customer_ret, '\0', sizeof(customer_ret));
				strcpy(customer_ret, customer_tmp + 1);
			}
			if (!strncmp(buf, "	option hostname", 16))
			{
				memset(hostname_tmp, 0, sizeof(hostname_tmp));
				len = strlen(buf) - 19;
				strncpy(hostname_tmp, strstr(buf, "'"), len);
				hostname_ret = (char *)malloc(64);
				memset(hostname_ret, 0, sizeof(hostname_ret));
				strcpy(hostname_ret, hostname_tmp + 1);			
			}
		}

		fclose(fp);
	}

	//getting GUID
	char *guid_fpath = "/etc/machineID";
	cmd = "touch /etc/machineID";
	system(cmd);

	fp = fopen(guid_fpath, "r");
	if (fp != NULL)
	{
		guid_ret = (char *)malloc(32);
		memset(guid_ret, 0, sizeof(guid_ret));
		fgets(guid_tmp, sizeof(guid_tmp), fp);
		snprintf(guid_ret, strlen(guid_tmp) + 1, "%s", guid_tmp);

		fclose(fp);
	}

	//getting password
	char *password_fpath = "/etc/password";
	cmd = "touch /etc/password";
	system(cmd);

	fp = fopen(password_fpath, "r");
	if(fp != NULL){
		password_ret = (char *)malloc(256);
		memset(password_ret, 0, sizeof(password_ret));
		fgets(password_ret, sizeof(password_ret), fp);
		fclose(fp);
	}

	// getting secret
	char *secret_fpath = "/etc/config/cbccd";
	cmd = "touch /etc/config/cbccd";
	system(cmd);

	fp = fopen(secret_fpath, "r");
	if(fp != NULL){
		char buf_lan[64] = {0, };
		while(fgets(buf_lan, sizeof(buf_lan), fp))
		{
			secret_ret = (char *)malloc(256);
			memset(secret_ret, 0, sizeof(secret_ret));
			if (!strncmp(buf_lan, "	option secret", 14))
			{
				memset(secret_tmp, 0, sizeof(secret_tmp));
				int len = strlen(buf_lan) - 17;
				strncpy(secret_tmp, strstr(buf_lan, "'"), len);
				strcpy(secret_ret, secret_tmp + 1);
				break;
			}
		}

		fclose(fp);
	}

	*hostname = hostname_ret;
	*customer = customer_ret;
	*password = password_ret;
	*secret = secret_ret;
	*guid = guid_ret;

	return;
}

char *get_address_from_network_info()
{
	char *fpath = "/etc/config/network";
	FILE *fp = fopen(fpath, "r");
	if(fp == NULL) {
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "SESSION: Cannot open '%s'", fpath);
		return;
	}
	char buf[128];
	char tmp[64];
	char *ret = NULL;

	while (fgets(buf, sizeof(buf), fp))
	{
		if (!strncmp(buf, "config interface 'lan'", 22))
		{
			char buf_lan[128];
			while(fgets(buf_lan, sizeof(buf_lan), fp))
			{
				if (!strncmp(buf_lan, "	option ipaddr", 14))
				{
					memset(tmp, 0, sizeof(tmp));
					int len = strlen(buf_lan) - 17;
					strncpy(tmp, strstr(buf_lan, "'"), len);
					ret = (char *)malloc(64);
					memset(ret, 0, sizeof(ret));
					strcpy(ret, tmp + 1);
					fclose(fp);
					return ret;
				}
			}
		}
	}


	fclose(fp);
	
	return ret;
}

