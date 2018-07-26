#include "nid_common.h"

/*
 * sliding window
 */ 
int nid_window_init(nid_window *win, uint32_t size, uint32_t timeout)
{
	if(win == NULL || size == 0 || timeout == 0)
		return EINVAL;
	win->size = size;
	win->timeout = timeout;
	win->cursize = 0;
	win->elem = calloc(1, sizeof(nid_winelem) * size);
	return 0;
}
int nid_window_add(nid_window *win, uint32_t key, void *value)
{
	uint32_t    i;
	if(win == NULL || value == NULL)
		return EINVAL;
	if(win->cursize >= win->size)
		return -1;
	i = key % win->size;
	if(win->elem[i].status == 0){
		win->elem[i].status = 1;
		win->elem[i].key = key;
		win->elem[i].timestamp = time(NULL);
		win->elem[i].value = value;
		win->cursize++;
		return 0;
	}
	for(i = 0; i < win->size; i++){
		if(win->elem[i].status == 0){
			win->elem[i].status = 1;
			win->elem[i].key = key;
			win->elem[i].timestamp = time(NULL);
			win->elem[i].value = value;
			win->cursize++;
			return 0;
		}
	}
	return -1;
}
int nid_window_del(nid_window *win, uint32_t key, void *value)
{
	uint32_t    i;
	if(win == NULL || value == NULL)
		return EINVAL;
	if(win->cursize == 0)
		return -1;
	i = key % win->size;
	if(win->elem[i].status == 1 && win->elem[i].key == key){
		win->elem[i].status = 0;
		value = &win->elem[i].value;
		win->cursize--;
		return 0;
	}
	for(i = 0; i < win->size; i++){
		if(win->elem[i].status == 1 && win->elem[i].key == key){
			win->elem[i].status = 0;
			value = &win->elem[i].value;
			win->cursize--;
			return 0;
		}
	}
	return -1;
}
int nid_window_timeout(nid_window *win, void *value)
{
	int		i;
	time_t	now;
	if(win == NULL || value == NULL)
		return EINVAL;
	if(win->cursize == 0)
		return -1;
	now = time(NULL);
	for(i = 0; i < win->size; i++)
		if(win->elem[i].status == 1 && (win->elem[i].timestamp + win->timeout < now))
			return nid_window_del(win, win->elem[i].key, value);
	return -1;
}
int nid_window_clear(nid_window *win, void *value)
{
	int		i;
	if(win == NULL || value == NULL)
		return EINVAL;
	if(win->cursize == 0)
		return -1;
	for(i = 0; i < win->size; i++){
		if(win->elem[i].status == 1){
			win->elem[i].status = 0;
			value = &win->elem[i].value;
			win->cursize--;
			return 0;
		}
	}
	return -1;
}
void nid_window_count(nid_window *win, uint32_t *cursize)
{
	*cursize = win->cursize;
}
void nid_window_destroy(nid_window *win)
{
	if(win->elem != NULL)
		free(win->elem);
}

