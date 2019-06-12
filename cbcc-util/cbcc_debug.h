#ifndef __CBCC_DEBUG_H__
#define __CBCC_DEBUG_H__

/// Wrapper macros to spare the application passing a type argument
#define CBCC_DEBUG_MSG(level, ...)		cbcc_debug_log(CBCC_DEBUG_TYPE_MSG, level, __FILE__, __LINE__, __VA_ARGS__);
#define CBCC_DEBUG_WARN(level, ...)		cbcc_debug_log(CBCC_DEBUG_TYPE_WARN, level, __FILE__, __LINE__, __VA_ARGS__);
#define CBCC_DEBUG_ERR(level, ...)		cbcc_debug_log(CBCC_DEBUG_TYPE_ERR, level, __FILE__, __LINE__, __VA_ARGS__);

// levels of debugging
enum CBCC_DEBUG_LEVEL
{
	CBCC_DEBUG_LEVEL_LOW = 1,
	CBCC_DEBUG_LEVEL_NOR,
	CBCC_DEBUG_LEVEL_HIGH,
	CBCC_DEBUG_LEVEL_VERBOSE,
};

// types of debugging
enum CBCC_DEBUG_TYPE
{
	CBCC_DEBUG_TYPE_MSG = 0,
	CBCC_DEBUG_TYPE_WARN,
	CBCC_DEBUG_TYPE_ERR
};

// CBCC debugging functions
int cbcc_dbg_init(const char *proc_name, enum CBCC_DEBUG_LEVEL log_level);
void cbcc_dbg_finalize();

void cbcc_debug_log(enum CBCC_DEBUG_TYPE log_type, enum CBCC_DEBUG_LEVEL log_level, const char *file_name, int file_line, const char *format, ...);

#endif		// __CBCC_DEBUG_H__
