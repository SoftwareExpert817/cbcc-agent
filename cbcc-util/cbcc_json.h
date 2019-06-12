#ifndef __CBCC_JSON_H__
#define __CBCC_JSON_H__

#include <stdbool.h>
#include <json-c/json.h>

#define CBCC_JOBJS_COUNT(x)			sizeof(x) / sizeof(cbcc_json_object_t)

// CBCC json data type
enum CBCC_JSON_DATA_TYPE
{
	CBCC_JSON_DATA_TYPE_OBJECT,
	CBCC_JSON_DATA_TYPE_STRING,
	CBCC_JSON_DATA_TYPE_INT,
	CBCC_JSON_DATA_TYPE_STR_ARRAY,
	CBCC_JSON_DATA_TYPE_INT_ARRAY,
	CBCC_JSON_DATA_TYPE_OBJ_ARRAY,
	CBCC_JSON_DATA_TYPE_STRING_BIG,
	CBCC_JSON_DATA_TYPE_OBJECT_BIG,
	CBCC_JSON_DATA_TYPE_BOOLEAN,
	CBCC_JSON_DATA_TYPE_OBJ_PAIRS,
};

// json array data type
union arr_data
{
	char str_vals[CBCC_MAX_JSON_ARR_SIZE][CBCC_MAX_JSON_ARR_FIELD_LEN];
	int int_vals[CBCC_MAX_JSON_ARR_SIZE];
};

typedef struct _cbcc_json_array
{
	int arr_len;
	union arr_data data;
} cbcc_json_array_t;

// json key/value pair data type
typedef struct _cbcc_json_pair
{
	char key[CBCC_MAX_JSON_KEY_LEN];
	char data[CBCC_MAX_JSON_DATA_LEN];
	
	struct _cbcc_json_pair *next;
} cbcc_json_pair_t;

typedef struct _cbcc_json_pairs
{
	int count;
	cbcc_json_pair_t *pairs;
} cbcc_json_pairs_t;

// json object data value
union cbcc_json_data
{
	char *str_val;
	char **str_val_big;
	cbcc_json_array_t *arr_val;
	int *int_val;
	cbcc_json_pairs_t *pairs;
	bool *bool_val;
	
	const char *str_val_set;
	int int_val_set;
};

// CBCC json object structure
typedef struct _cbcc_json_object
{
	const char *key;
	const char *parent_key;
	
	bool obj_exist_data;			// if type is object and data is exist, then true

	union cbcc_json_data data;
	size_t data_size;			// this value will be effect when data type is string
	
	bool must_specify;
	bool is_root;				// specify json object is root
	
	enum CBCC_JSON_DATA_TYPE type;
} cbcc_json_object_t;

// API for CBCC json manupulation
int cbcc_json_parse_from_file(const char *file_path, cbcc_json_object_t *cbcc_jobjs, int objs_num);
int cbcc_json_parse_from_buffer(const char *json_buffer, cbcc_json_object_t *cbcc_jobjs, int objs_num);

void cbcc_json_mem_free(cbcc_json_object_t *cbcc_jobjs, int objs_num);
void cbcc_json_free_pairs(cbcc_json_pairs_t *pairs);

int cbcc_json_update(const char *json_buffer, cbcc_json_object_t *update_objs, int objs_num, char *updated_buffer, size_t s);
int cbcc_json_build(cbcc_json_object_t *cbcc_jobjs, int objs_num, char **pp_json_str);
int cbcc_json_add(const char *json_buffer, cbcc_json_object_t *cbcc_jobjs, int objs_num, char **pp_added_buffer);
int cbcc_json_remove(const char *json_buffer, cbcc_json_object_t *remove_jobjs, int objs_num, char **pp_removed_buffer);

int cbcc_json_read_from_file(const char *file_path, char **dst_jstr);

#endif		// __CBCC_JSON_H__
