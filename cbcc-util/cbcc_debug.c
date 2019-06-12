#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <pthread.h>
#include <syslog.h>

#include "cbcc_common.h"
#include "cbcc_debug.h"

static FILE *cbcc_log_fp = NULL;
static enum CBCC_DEBUG_LEVEL s_log_level;
static char msg[CBCC_MAX_LOG_MSG_LEN];

static pthread_mutex_t pt_mt = PTHREAD_MUTEX_INITIALIZER;

// initialize debugging
int cbcc_dbg_init(const char *proc_name, enum CBCC_DEBUG_LEVEL log_level)
{
	char log_fpath[CBCC_MAX_PATH];
	
	// make logging file path
	snprintf(log_fpath, sizeof(log_fpath), "/var/log/%s.log", proc_name);

	// open log file
	cbcc_log_fp = fopen(log_fpath, "w");
	if (!cbcc_log_fp)
	{
		fprintf(stderr, "Could not open log file '%s' for writing\n", log_fpath);
		snprintf(log_fpath, sizeof(log_fpath), "/var/%s.log", proc_name);
		
		cbcc_log_fp = fopen(log_fpath, "w");
		if (!cbcc_log_fp)
		{
			fprintf(stderr, "Could not open log file '%s' for writing\n", log_fpath);
			return -1;
		}
		// return -1;
	}

	// open syslog
	openlog("cbcc-agent", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_USER);
	
	// set logging level
	s_log_level = log_level;

	// init mutex
	pthread_mutex_init(&pt_mt, NULL);

	return 0;
}

// finalize debugging
void cbcc_dbg_finalize()
{
	// close log file handler
	if (cbcc_log_fp)
	{
		fclose(cbcc_log_fp);
		cbcc_log_fp = NULL;
	}

	// close syslog
	closelog();

	// destroy mutex
	pthread_mutex_destroy(&pt_mt);

	return;
}

// write debugging info into file
static const char *cbcc_log_type_str[] = 
{
	"Info",
	"Warn",
	"Err",
};

void cbcc_debug_log(enum CBCC_DEBUG_TYPE log_type, enum CBCC_DEBUG_LEVEL log_level, const char *file_name, int file_line, const char *format, ...)
{
	va_list va_args;

	time_t tt;
	struct tm *tm;
	char time_str[64];

	// check logging file pointer
	if (!cbcc_log_fp)
		return;

	// check log level
	if (log_level > s_log_level)
		return;

	// mutex lock
	pthread_mutex_lock(&pt_mt);

	va_start(va_args, format);
	vsnprintf(msg, sizeof(msg), format, va_args);
	va_end(va_args);

	// get current time and make time string
	time(&tt);
	tm = localtime(&tt);

	strftime(time_str, sizeof(time_str), "%a %d %b %Y %T", tm);

	// print message
	fprintf(stderr, "%s [%d]\t%s : %s(at %s:%d)\n", time_str, log_level, cbcc_log_type_str[log_type], msg, file_name, file_line);
	syslog(LOG_INFO, "%s : %s(at %s:%d)\n", cbcc_log_type_str[log_type], msg, file_name, file_line);

	// mutex unlock
	pthread_mutex_unlock(&pt_mt);

	return;
}
