#include "util_common.h"
/*
 * id = 1
 * name = gy
 * age = 32
 */
int com_cfg_get_value(char *filename, char *key, char *value)
{
	FILE    *fp;
	char    buf[512], bufkey[512], bufvalue[512], *p;
	int     len, flag = -1;

	if(filename == NULL || key == NULL || value == NULL)
		return EINVAL;
	fp = fopen(filename, "r");
	if(fp == NULL)
		return errno;
	while(fgets(buf, sizeof(buf), fp) != NULL){
		com_str_trim(buf);
		if(buf[0] == '#' || buf[0] == 0)
			continue;
		//get = position
		if((p = strchr(buf, '=')) == NULL)
			return EINVAL;
		//get cfg key
		len = p - buf;
		memset(bufkey, 0, sizeof(bufkey));
		strncpy(bufkey, buf, len);
		com_str_rtrim(bufkey);
		//get cfg value
		if(!strcmp(bufkey, key)){
			memset(bufvalue, 0, sizeof(bufvalue));
			strcpy(bufvalue, p+1);
			com_str_ltrim(bufvalue);
			strcpy(value, bufvalue);
			flag = 0;
			break;
		}
	}
	fclose(fp);
	return flag;
}
/*
 * 1,gy,32
 * 2,ly,32
 */
int com_cfg_get_row(char *filename, int row, char *value)
{
	FILE    *fp;
	char    buf[512];
	int     x = 0, flag = -1;

	if(filename == NULL || row <= 0 || value == NULL)
		return EINVAL;
	fp = fopen(filename, "r");
	if(fp == NULL)
		return errno;
	while(fgets(buf, sizeof(buf), fp) != NULL){
		com_str_trim(buf);
		if(buf[0] == '#' || buf[0] == 0)
			continue;
		if(++x < row)
			continue;
		//get value
		strcpy(value, buf);
		flag = 0;
		break;
	}
	fclose(fp);
	return flag;
}
