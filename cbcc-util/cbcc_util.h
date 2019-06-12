#ifndef __CBCCUTIL_H__
#define __CBCCUTIL_H__
#include <unistd.h>

// get process ID by process name
pid_t get_procid_by_procname(const char *proc_name);

// write PID file
void write_pid_file(const char *proc_name);

// daemonize program
void daemonize();

// get file size
int get_file_size(const char *file_path);

// convert object name to table name
void get_tblname_by_objname(const char *obj_name, char *tbl_name, size_t s);

// get object type from table name
void get_objtype_by_tblname(const char *tbl_name, char *obj_type, size_t s);

// read file contents
int read_file_contents(const char *fpath, char **buf);

// get md5sum of file
int get_md5sum_of_file(const char *fpath, int binary_mode, char *md5sum, size_t s);

// get md5sum of buffer
int get_md5sum_of_buffer(const char *buffer, char *md5sum, size_t s);

// get base64 encoded data
int get_base64_encoded_from_file(const char *fpath, char **base64_encoded);

// decode base64 encoded data and write into file
int decode_base64_to_file(const char *base64_encoded, const char *fpath);

// create guid
void create_random_guid(char *guid, size_t s);

// get host info from system
void get_host_info_from_system(char **customer, char **hostname, char **password, char **secret, char **guid);

// get address from /etc/config/network
char *get_address_from_network_info();

#endif		// __CBCCUTIL_H__
