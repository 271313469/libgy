#include "util_common.h"

int com_str_isdigit(char *str)
{
	int     i;
	assert(str != NULL);
	if(strlen(str) == 0)
		return 0;
	for(i=0; str[i]!=0; i++)
		if(!isdigit(str[i]))
			return 0;
	return 1;
}
int com_str_ishex(char *str)
{
	int     i;
	assert(str != NULL);
	if(strlen(str) == 0)
		return 0;
	for(i=0; str[i]!=0; i++)
		if(!isxdigit(str[i]))
			return 0;
	return 1;
}
int com_str_isasc(char *str)
{
	int     i;
	assert(str != NULL);
	if(strlen(str) == 0)
		return 0;
	for(i=0; str[i]!=0; i++)
		if(!isascii(str[i]))
			return 0;
	return 1;
}
char *com_str_ltrim(char *str)
{
	char *p;
	for(p=str; *p!=0; p++)
		if(!isspace(*p))
			break;
	if(p != str)
		memmove(str, p, strlen(p)+1);
	return str;
}       
char *com_str_rtrim(char *str)
{
	char *p;
	if(strlen(str) == 0)
		return str;
	p = str + strlen(str)-1;
	while((p!=str) && isspace(*p))
		*p-- = 0; 
	return str;
}
char *com_str_trim(char *str)
{
	com_str_ltrim(str);
	com_str_rtrim(str);
	return str;
}
