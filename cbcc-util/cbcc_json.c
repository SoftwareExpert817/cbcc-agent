#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "cbcc_common.h"
#include "cbcc_util.h"
#include "cbcc_debug.h"

#include "cbcc_json.h"

// create new json object from file
static json_object *cbcc_jobj_new_from_file(const char *fpath)
{
	FILE *fp;
	int file_size;
	
	char *buf;
	
	// get file size
	file_size = get_file_size(fpath);
	if (file_size <= 0)
		return NULL;

	// open file for reading
	fp = fopen(fpath, "r");
	if (!fp)
		return NULL;
	
	// allocate buffer for reading json data
	buf = (char *) malloc(file_size + 1);
	if (!buf)
	{
		fclose(fp);
		return NULL;
	}
	
	memset(buf, 0, file_size + 1);
	
	// read buffer
	fread(buf, 1, file_size, fp);
	
	// close file
	fclose(fp);
	
	// create json object by parsing buffer
	json_object *j_obj = json_tokener_parse(buf);
	
	// free buffer
	free(buf);
	
	// check json object is valid
	if (!j_obj || is_error(j_obj))
		return NULL;
	
	return j_obj;
}

// create new json object from json buffer
static json_object *cbcc_jobj_new_from_buffer(const char *buffer)
{
	// create json object by parsing buffer
	json_object *j_obj = json_tokener_parse(buffer);
	
	// check json object is valid
	if (!j_obj || is_error(j_obj))
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_VERBOSE, "JSON: Invalid JSON buffer '%s'", buffer);
		return NULL;
	}
	
	return j_obj;
}

// free json object
static void cbcc_jobj_free(json_object *j_obj)
{
	json_object_put(j_obj);
}

// check object type
static int check_obj_validation(cbcc_json_object_t *cbcc_jobj, json_object *j_obj)
{
	enum CBCC_JSON_DATA_TYPE data_type = cbcc_jobj->type;
	enum json_type jobj_type = json_object_get_type(j_obj);
	
	if (data_type == CBCC_JSON_DATA_TYPE_STRING && jobj_type == json_type_string)
		return 0;

	if (data_type == CBCC_JSON_DATA_TYPE_STRING_BIG && jobj_type == json_type_string)
		return 0;
		
	if (data_type == CBCC_JSON_DATA_TYPE_INT && jobj_type == json_type_int)
		return 0;
	
	if (data_type == CBCC_JSON_DATA_TYPE_BOOLEAN && jobj_type == json_type_boolean)
		return 0;
		
	if ((data_type == CBCC_JSON_DATA_TYPE_STR_ARRAY || data_type == CBCC_JSON_DATA_TYPE_INT_ARRAY) && jobj_type == json_type_array)
		return 0;
		
	if (data_type == CBCC_JSON_DATA_TYPE_OBJECT && jobj_type == json_type_object)
		return 0;

	if (data_type == CBCC_JSON_DATA_TYPE_OBJECT_BIG && jobj_type == json_type_object)
		return 0;
		
	if (data_type == CBCC_JSON_DATA_TYPE_OBJ_PAIRS && jobj_type == json_type_object)
		return 0;
	
	if (data_type == CBCC_JSON_DATA_TYPE_OBJ_ARRAY && jobj_type == json_type_array)
		return 0;
	
	CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_VERBOSE, "JSON: Object validation has failed. object type is '%d', json type is '%d'", data_type, jobj_type);

	return -1;
}

// set array data from json
static void cbcc_json_set_arr_data(json_object *j_obj, bool is_str, cbcc_json_array_t *arr_val)
{
	json_object *j_arr_obj;
	
	// init array
	memset(arr_val, 0, sizeof(cbcc_json_array_t));
	
	// set array length
	arr_val->arr_len = json_object_array_length(j_obj);
	if (arr_val->arr_len > CBCC_MAX_JSON_ARR_SIZE)
		arr_val->arr_len = CBCC_MAX_JSON_ARR_SIZE;
	
	for (int i = 0; i < arr_val->arr_len; i++)
	{
		j_arr_obj = json_object_array_get_idx(j_obj, i);
		
		// set array data
		if (is_str)
			snprintf(arr_val->data.str_vals[i], sizeof(arr_val->data.str_vals[i]), "%s", json_object_get_string(j_arr_obj));
		else
			arr_val->data.int_vals[i] = json_object_get_int(j_arr_obj);
	}
	
	return;
}

// free json pairs
static void free_json_pair(cbcc_json_pair_t *pair)
{
	if (pair->next)
		free_json_pair(pair->next);
	
	free(pair);
	
	return;
}

void cbcc_json_free_pairs(cbcc_json_pairs_t *pairs)
{
	if (pairs->count == 0)
		return;
	
	free_json_pair(pairs->pairs);
	
	return;
}

// set pairs data
static void set_json_pairs(cbcc_json_pairs_t *pairs, const char *key, const char *val)
{
	cbcc_json_pair_t *pair;
	
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_VERBOSE, "JSON: Setting JSON pair with key '%s', val '%s'", key, val);
	
	// allocate memory for a pair
	pair = (cbcc_json_pair_t *) malloc(sizeof(cbcc_json_pair_t));
	if (!pair)
		return;
	
	memset(pair, 0, sizeof(cbcc_json_pair_t));
	
	// check pairs count
	if (pairs->count == 0)
	{
		pairs->pairs = pair;
	}
	else
	{
		cbcc_json_pair_t *p = pairs->pairs;
		while (p->next)
			p = p->next;
		
		p->next = pair;
	}
	
	strcpy(pair->key, key);
	strcpy(pair->data, val);
	
	pairs->count++;
	
	return;
}

static void cbcc_json_set_pairs(json_object *j_obj, cbcc_json_pairs_t *pairs)
{
	json_object_object_foreach(j_obj, key, j_sub_obj)
	{
		const char *val = json_object_get_string(j_sub_obj);
		set_json_pairs(pairs, key, val);
	}
	
	return;
}

// get json sub object by key
static json_object *cbcc_get_jobj_by_key(json_object *j_obj, const char *obj_key)
{
	json_object *j_last_ret_obj = NULL;
	json_object *j_ret_obj;
	
	// try to get object from root at first
	j_ret_obj = json_object_object_get(j_obj, obj_key);
	if (j_ret_obj)
		j_last_ret_obj = j_ret_obj;
	
	json_object_object_foreach(j_obj, key, j_sub_obj)
	{
		if (!j_sub_obj)
			continue;
		
		// check object key is same
		if (strcmp(obj_key, key) == 0)
			j_last_ret_obj = j_sub_obj;
		
		// if object type is object, then do recursive call
		if (json_object_get_type(j_sub_obj) == json_type_object)
		{
			j_ret_obj = cbcc_get_jobj_by_key(j_sub_obj, obj_key);
			if (j_ret_obj)
				j_last_ret_obj = j_ret_obj;
		}
	}
	
	return j_last_ret_obj;
}

// parse json object
static int cbcc_jobj_parse(json_object *j_obj, cbcc_json_object_t *cbcc_jobj, int obj_num)
{
	json_object *j_sub_obj;
	
	for (int i = 0; i < obj_num; i++)
	{
		json_object *j_par_obj = NULL;
		
		cbcc_json_object_t *obj = &cbcc_jobj[i];
		
		// get parent object by key
		if (obj->parent_key)
		{
			j_par_obj = cbcc_get_jobj_by_key(j_obj, obj->parent_key);
			if (!j_par_obj)
			{
				if (obj->must_specify)
				{
					CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "JSON: Could not get json object by key '%s'", obj->parent_key);
					return -1;
				}
				else
				{
					CBCC_DEBUG_WARN(CBCC_DEBUG_LEVEL_VERBOSE, "JSON: Could not get json object by key '%s'", obj->parent_key);
				}
				
				continue;
			}
		}
		
		// get sub object by key
		if (!obj->is_root)
		{
			j_sub_obj = cbcc_get_jobj_by_key(j_par_obj ? j_par_obj : j_obj, obj->key);
			if (!j_sub_obj)
			{
				// if this field should be specified in json structure, then return failure
				if (obj->must_specify)
				{
					CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "JSON: Could not get json object by key '%s'", obj->key);
					return -1;
				}
				else
				{
					CBCC_DEBUG_WARN(CBCC_DEBUG_LEVEL_VERBOSE, "JSON: Could not get json object by key '%s'", obj->key);
				}
			
				continue;
			}
		}
		else
			j_sub_obj = j_obj;
		
		// check object type
		if (check_obj_validation(obj, j_sub_obj) != 0)
		{
			CBCC_DEBUG_WARN(CBCC_DEBUG_LEVEL_NOR, "JSON: Could not get value for key '%s'. Object validataion has failed.", obj->key);
			continue;
		}
		
		// set value from sub object
		switch (obj->type)
		{
			case CBCC_JSON_DATA_TYPE_OBJECT:
			case CBCC_JSON_DATA_TYPE_STRING:
				snprintf(obj->data.str_val, obj->data_size, "%s", json_object_get_string(j_sub_obj));
				break;
			
			case CBCC_JSON_DATA_TYPE_STRING_BIG:
			case CBCC_JSON_DATA_TYPE_OBJECT_BIG:
				{
					const char *str = json_object_get_string(j_sub_obj);
					int str_len = strlen(str);
					if (str_len == 0)
						break;
					
					char *buf = (char *) malloc(str_len + 1);
					strcpy(buf, str);
					buf[str_len] = '\0';
					
					*(obj->data.str_val_big) = buf;
				}
				
				break;
				
			case CBCC_JSON_DATA_TYPE_INT:
				*(obj->data.int_val) = json_object_get_int(j_sub_obj);
				break;
			
			case CBCC_JSON_DATA_TYPE_BOOLEAN:
				*(obj->data.int_val) = json_object_get_boolean(j_sub_obj) ? 1 : 0;
				break;
			
			case CBCC_JSON_DATA_TYPE_STR_ARRAY:
			case CBCC_JSON_DATA_TYPE_OBJ_ARRAY:
				cbcc_json_set_arr_data(j_sub_obj, true, obj->data.arr_val);
				break;
			
			case CBCC_JSON_DATA_TYPE_INT_ARRAY:
				cbcc_json_set_arr_data(j_sub_obj, false, obj->data.arr_val);
				break;
			
			case CBCC_JSON_DATA_TYPE_OBJ_PAIRS:
				cbcc_json_set_pairs(j_sub_obj, obj->data.pairs);
				break;
				
			default:
				break;
		}
	}
	
	return 0;
}

// parser json buffer
int cbcc_json_parse_from_buffer(const char *json_buffer, cbcc_json_object_t *cbcc_jobjs, int objs_num)
{
	int ret = 0;
	
	json_object *j_obj = cbcc_jobj_new_from_buffer(json_buffer);
	if (!j_obj)
		return -1;
	
	if (cbcc_jobj_parse(j_obj, cbcc_jobjs, objs_num) != 0)
		ret = -1;
	
	// free json object
	cbcc_jobj_free(j_obj);
	
	return ret;
}

// parser json file
int cbcc_json_parse_from_file(const char *file_path, cbcc_json_object_t *cbcc_jobjs, int objs_num)
{
	int ret = 0;
	
	json_object *j_obj = cbcc_jobj_new_from_file(file_path);
	if (!j_obj)
		return -1;
	
	if (cbcc_jobj_parse(j_obj, cbcc_jobjs, objs_num) != 0)
		ret = -1;
	
	// free json object
	cbcc_jobj_free(j_obj);
	
	return ret;
}

// build json string from json objects
int cbcc_json_build(cbcc_json_object_t *cbcc_jobjs, int objs_num, char **pp_json_str)
{
	json_object *j_obj;
	const char *j_str;
	
	char *ret = NULL;
	
	// create json object
	j_obj = json_object_new_object();
	
	for (int i = 0; i < objs_num; i++)
	{
		json_object *j_par_obj = NULL;
		
		cbcc_json_object_t *obj = &cbcc_jobjs[i];

		// if parent key is specified, then get parent object
		if (obj->parent_key)
		{
			j_par_obj = cbcc_get_jobj_by_key(j_obj, obj->parent_key);
			
			if (!j_par_obj)
			{
				CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_HIGH, "JSON: Could not find parent object by key '%s'", obj->parent_key);
				continue;
			}
			else
			{
				char *ret_jstr = json_object_get_string(j_par_obj);
			}
		}
		
		// add json object
		if (obj->type == CBCC_JSON_DATA_TYPE_OBJECT)
		{
			json_object *j_sub_obj;
			if (!obj->obj_exist_data)
			{
				j_sub_obj = json_object_new_object();
			}
			else
			{
				j_sub_obj = json_tokener_parse(obj->data.str_val_set);
				if (!j_sub_obj || is_error(j_sub_obj))
				{
					CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_HIGH, "JSON: Could not parse JSON object from string '%s'", obj->data.str_val_set);
					continue;
				}
			}

			json_object_object_add(j_par_obj ? j_par_obj : j_obj, obj->key, j_sub_obj);
		}
		else if (obj->type == CBCC_JSON_DATA_TYPE_STRING)
		{
			if (obj->data.str_val_set)
				json_object_object_add(j_par_obj ? j_par_obj : j_obj, obj->key, json_object_new_string(obj->data.str_val_set));
			else
				json_object_object_add(j_par_obj ? j_par_obj : j_obj, obj->key, json_object_new_string(""));
		}
		else if (obj->type == CBCC_JSON_DATA_TYPE_INT)
		{
			json_object_object_add(j_par_obj ? j_par_obj : j_obj, obj->key, json_object_new_int(obj->data.int_val_set));
		}
		else if (obj->type == CBCC_JSON_DATA_TYPE_BOOLEAN)
		{
			json_object_object_add(j_par_obj ? j_par_obj : j_obj, obj->key, json_object_new_boolean(obj->data.int_val_set ? true : false));
		}
		else if (obj->type == CBCC_JSON_DATA_TYPE_STR_ARRAY || obj->type == CBCC_JSON_DATA_TYPE_INT_ARRAY)
		{
			cbcc_json_array_t *arr_data = obj->data.arr_val;
			json_object *j_arr_obj = json_object_new_array();
			
			for (int i = 0; i < arr_data->arr_len; i++)
			{
				if (obj->type == CBCC_JSON_DATA_TYPE_STR_ARRAY)
					json_object_array_add(j_arr_obj, json_object_new_string(arr_data->data.str_vals[i]));
				else
					json_object_array_add(j_arr_obj, json_object_new_int(arr_data->data.int_vals[i]));
			}
			
			json_object_object_add(j_par_obj ? j_par_obj : j_obj, obj->key, j_arr_obj);
		}
		else if (obj->type == CBCC_JSON_DATA_TYPE_OBJ_ARRAY)
		{
			json_object *j_arr_obj = json_object_new_array();
			cbcc_json_array_t *arr_data = obj->data.arr_val;
			if (arr_data)
			{
				for (int i = 0; i < arr_data->arr_len; i++)
				{
					CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_VERBOSE, "JSON: Adding JSON array object with data '%s'", arr_data->data.str_vals[i]);
					
					json_object *j_arr_sub_obj = json_tokener_parse(arr_data->data.str_vals[i]);
					if (!j_arr_sub_obj || is_error(j_arr_sub_obj))
					{
						CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_HIGH, "JSON: Invalid JSON object data '%s'", arr_data->data.str_vals[i]);
						continue;
					}
				
					json_object_array_add(j_arr_obj, j_arr_sub_obj);
				}
			}

			json_object_object_add(j_par_obj ? j_par_obj : j_obj, obj->key, j_arr_obj);
		}
	}
	
	// make json string
	j_str = json_object_get_string(j_obj);
	
	ret = (char *) malloc(strlen(j_str) + 1);
	strcpy(ret, j_str);
	ret[strlen(j_str)] = '\0';
	
	// free json object
	json_object_put(j_obj);
	
	*pp_json_str = ret;
	
	return 0;
}

// reencode json string while removing spaces in original
int cbcc_json_read_from_file(const char *fpath, char **dst_jstr)
{
	json_object *j_obj;
	char *buf;
	
	char *p;
	
	// set destination json string as NULL
	*dst_jstr = NULL;
	
	// read file contents from file
	if (read_file_contents(fpath, &buf) < 0)
		return -1;
	
	// get json object from original string
	j_obj = json_tokener_parse(buf);
	
	// free buffer
	free(buf);
	
	// check json object is valid
	if (!j_obj || is_error(j_obj))
		return -1;
	
	// convert json object to string
	const char *j_buf = json_object_get_string(j_obj);

	p = (char *) malloc(strlen(j_buf) + 1);
	strcpy(p, j_buf);
	p[strlen(j_buf)] = '\0';
	
	// put json object
	json_object_put(j_obj);
	
	*dst_jstr = p;
	
	return 0;
}

// update json object by given objects
static int cbcc_jobj_update(json_object *j_obj, cbcc_json_object_t *update_objs, int objs_num, char *updated_buffer, size_t s)
{
	json_object *j_sub_obj;
	
	for (int i = 0; i < objs_num; i++)
	{
		cbcc_json_object_t *obj = &update_objs[i];
		json_object *j_par_obj = NULL;
		
		// get parent object
		if (obj->parent_key)
		{
			j_par_obj = cbcc_get_jobj_by_key(j_obj, obj->parent_key);
			if (!j_par_obj)
			{
				CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_HIGH, "JSON: Could not find parent object by key '%s'", obj->parent_key);
				continue;
			}
		}

		j_sub_obj = cbcc_get_jobj_by_key(j_obj, obj->key);
		if (!j_sub_obj)
		{
			CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_HIGH, "JSON: Could not find json object by key '%s'", obj->key);
			continue;
		}
		
		// check object type
		if (check_obj_validation(obj, j_sub_obj) != 0)
		{
			CBCC_DEBUG_WARN(CBCC_DEBUG_LEVEL_VERBOSE, "JSON: Could not get value for key '%s'. Object validataion has failed.", obj->key);
			continue;
		}
		
		// remove object
		json_object_object_del(j_par_obj ? j_par_obj : j_obj, obj->key);
		
		// add object
		switch (obj->type)
		{
			case CBCC_JSON_DATA_TYPE_STRING:
				json_object_object_add(j_par_obj ? j_par_obj : j_obj, obj->key, json_object_new_string(obj->data.str_val_set));
				break;
				
			case CBCC_JSON_DATA_TYPE_INT:
				json_object_object_add(j_par_obj ? j_par_obj : j_obj, obj->key, json_object_new_int(obj->data.int_val_set));
				break;
				
			default:
				break;
		}
	}
	
	// make json string from object
	snprintf(updated_buffer, s, "%s", json_object_get_string(j_obj));
	
	return 0;
}

// update json buffer by given objects
int cbcc_json_update(const char *json_buffer, cbcc_json_object_t *update_objs, int objs_num, char *updated_buffer, size_t s)
{
	int ret = 0;
	
	json_object *j_obj = cbcc_jobj_new_from_buffer(json_buffer);
	if (!j_obj)
		return -1;
	
	if (cbcc_jobj_update(j_obj, update_objs, objs_num, updated_buffer, s) != 0)
		ret = -1;
	
	// free json object
	cbcc_jobj_free(j_obj);
	
	return ret;
}

// add json object into exist object
static int cbcc_jobj_add(json_object *j_obj, cbcc_json_object_t *cbcc_jobjs, int objs_num, char **pp_added_buffer)
{
	const char *j_str;
	char *ret;
	
	for (int i = 0; i < objs_num; i++)
	{
		cbcc_json_object_t *obj = &cbcc_jobjs[i];
		json_object *j_par_obj = NULL;
		
		// get parent object
		if (obj->parent_key)
		{
			j_par_obj = cbcc_get_jobj_by_key(j_obj, obj->parent_key);
			if (!j_par_obj)
			{
				CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_HIGH, "JSON: Could not find json object by key '%s'", obj->parent_key);
				continue;
			}
		}
		
		// if given key has already added, then remove it
		if (json_object_object_get(j_par_obj ? j_par_obj : j_obj, obj->key))
			json_object_object_del(j_par_obj ? j_par_obj : j_obj, obj->key);
		
		switch (obj->type)
		{
			case CBCC_JSON_DATA_TYPE_OBJECT:
				{
					json_object *j_sub_obj = json_object_new_object();
					json_object_object_add(j_par_obj ? j_par_obj : j_obj, obj->key, j_sub_obj);
				}
				
				break;
				
			case CBCC_JSON_DATA_TYPE_STRING:
				json_object_object_add(j_par_obj ? j_par_obj : j_obj, obj->key, json_object_new_string(obj->data.str_val_set));
				break;
			
			case CBCC_JSON_DATA_TYPE_INT:
				json_object_object_add(j_par_obj ? j_par_obj : j_obj, obj->key, json_object_new_int(obj->data.int_val_set));
				break;
			
			case CBCC_JSON_DATA_TYPE_BOOLEAN:
				json_object_object_add(j_par_obj ? j_par_obj : j_obj, obj->key, json_object_new_boolean(obj->data.int_val_set));
				break;

			case CBCC_JSON_DATA_TYPE_STR_ARRAY:
			case CBCC_JSON_DATA_TYPE_INT_ARRAY:
				{
					cbcc_json_array_t *arr_data = obj->data.arr_val;
					json_object *j_arr_obj = json_object_new_array();
					
					for (int i = 0; i < arr_data->arr_len; i++)
					{
						if (obj->type == CBCC_JSON_DATA_TYPE_STR_ARRAY)
							json_object_array_add(j_arr_obj, json_object_new_string(arr_data->data.str_vals[i]));
						else
							json_object_array_add(j_arr_obj, json_object_new_int(arr_data->data.int_vals[i]));
					}
				
					json_object_object_add(j_par_obj ? j_par_obj : j_obj, obj->key, j_arr_obj);
				}
				break;
			
			default:
				break;
		}
	}
	
	j_str = json_object_get_string(j_obj);
	
	ret = (char *) malloc(strlen(j_str) + 1);
	strcpy(ret, j_str);
	ret[strlen(j_str)] = '\0';
	
	*pp_added_buffer = ret;
	
	return 0;
}

int cbcc_json_add(const char *json_buffer, cbcc_json_object_t *cbcc_jobjs, int objs_num, char **added_buffer)
{
	int ret = 0;
	json_object *j_obj = cbcc_jobj_new_from_buffer(json_buffer);
	if (!j_obj)
		return -1;
		
	if (cbcc_jobj_add(j_obj, cbcc_jobjs, objs_num, added_buffer) != 0)
		ret = -1;
		
	// free json object
	cbcc_jobj_free(j_obj);
	
	return ret;
}

// remove json object from exist object
static int cbcc_jobj_remove(json_object *j_obj, cbcc_json_object_t *remove_jobjs, int objs_num, char **pp_removed_buffer)
{
	const char *j_str;
	char *ret;
	
	for (int i = 0; i < objs_num; i++)
	{
		cbcc_json_object_t *obj = &remove_jobjs[i];
		json_object *j_par_obj = NULL;
		
		// get parent object
		if (obj->parent_key)
		{
			j_par_obj = cbcc_get_jobj_by_key(j_obj, obj->parent_key);
			if (!j_par_obj)
			{
				CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_HIGH, "JSON: Could not find json object by key '%s'", obj->parent_key);
				continue;
			}
		}
		
		// if given key has already added, then remove it
		if (json_object_object_get(j_par_obj ? j_par_obj : j_obj, obj->key))
			json_object_object_del(j_par_obj ? j_par_obj : j_obj, obj->key);
		else
		{
			CBCC_DEBUG_WARN(CBCC_DEBUG_LEVEL_HIGH, "JSON: Could not found json object by key '%s' with parent key '%s'",
						obj->key, obj->parent_key);
		}
	}
	
	j_str = json_object_get_string(j_obj);
	
	ret = (char *) malloc(strlen(j_str) + 1);
	strcpy(ret, j_str);
	ret[strlen(j_str)] = '\0';
	
	*pp_removed_buffer = ret;
	
	return 0;
}

int cbcc_json_remove(const char *json_buffer, cbcc_json_object_t *remove_jobjs, int objs_num, char **pp_removed_buffer)
{
	int ret = 0;
	json_object *j_obj = cbcc_jobj_new_from_buffer(json_buffer);
	if (!j_obj)
		return -1;
		
	if (cbcc_jobj_remove(j_obj, remove_jobjs, objs_num, pp_removed_buffer) != 0)
		ret = -1;
		
	// free json object
	cbcc_jobj_free(j_obj);
	
	return ret;
}

// free allocated memory for parsing json
void cbcc_json_mem_free(cbcc_json_object_t *cbcc_jobjs, int objs_num)
{
	for (int i = 0; i < objs_num; i++)
	{
		switch (cbcc_jobjs[i].type)
		{
			case CBCC_JSON_DATA_TYPE_STRING_BIG:
			case CBCC_JSON_DATA_TYPE_OBJECT_BIG:
				if (*(cbcc_jobjs[i].data.str_val_big))
					free(*(cbcc_jobjs[i].data.str_val_big));
				
				break;
			
			case CBCC_JSON_DATA_TYPE_OBJ_PAIRS:
				cbcc_json_free_pairs(cbcc_jobjs[i].data.pairs);
				break;
			
			default:
				break;
		}
	}
	
	return;
}
