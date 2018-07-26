#include "util_common.h"

int com_queue_init(com_queue *q)
{
	if(q == NULL)
		return EINVAL;
	LIST_INIT(&q->head);
	q->count = 0;
	return 0;
}
void com_queue_destroy(com_queue *q)
{
	if(q == NULL)
		return;
	memset(q, 0, sizeof(com_queue));
}
int com_queue_put(com_queue *q, void *ptr)
{
	com_list *link = (com_list *)ptr;
	if(q == NULL || ptr == NULL)
		return EINVAL;
	LIST_ADD(&q->head, link);
	q->count++;
	return 0;
}
int com_queue_get(com_queue *q, void **ptr)
{
	com_list *link;
	if(q == NULL || ptr == NULL)
		return EINVAL;
	if(q->count == 0)
		return -1;
	LIST_DEL(&q->head, link);
	*ptr = link;
	q->count--;
	return 0;
}
int com_queue_count(com_queue *q, uint32_t *count)
{
	if(q == NULL || count == NULL)
		return EINVAL;
	*count = q->count;
	return 0;
}
