#include "util_common.h"

int com_rq_init(com_rq_t *q, uint32_t count, uint32_t size)
{
	if(q == NULL || count < 1 || size % sizeof(long))
		return EINVAL;
	q->count = count;
	q->size = size;
	q->head = q->tail = 0;
	q->data = calloc(count, size);
	if(q->data == NULL)
		return errno;
	return 0;
}
void com_rq_destroy(com_rq_t *q)
{
	if(q == NULL)
		return ;
	if(q->data)
		free(q->data);
	memset(q, 0, sizeof(com_rq_t));
	return ;
}
int com_rq_put(com_rq_t *q, void *e)
{
	if(q->head - q->tail == q->count)
		return -1;
	memcpy(q->data + q->size * (q->head % q->count), e, q->size);
	q->head++;
	return 0;
}
int com_rq_get(com_rq_t *q, void *e)
{
	if(q->tail == q->head)
		return -1;
	memcpy(e, q->data + q->size * (q->tail % q->count), q->size);
	q->tail++;
	return 0;
}
