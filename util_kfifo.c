#include "util_common.h"

#define MIN(a,b) ((a) < (b) ? (a):(b))

int com_kfifo_init(com_kfifo *fifo, uint32_t size)
{
	fifo->buffer = malloc(size);
	if(fifo->buffer == NULL)
		return errno;
	fifo->size = size;
	fifo->in = fifo->out = 0;
	return 0;
}
void com_kfifo_destroy(com_kfifo *fifo)
{
	if(fifo->buffer)
		free(fifo->buffer);
	memset(fifo, 0, sizeof(com_kfifo));
	return;
}
uint32_t com_kfifo_put(com_kfifo *fifo, char *buffer, uint32_t len)
{
	uint32_t	n;
	len = MIN(len, fifo->size - fifo->in + fifo->out);
	/* first put the data starting from fifo->in to buffer end */
	n = MIN(len, fifo->size - (fifo->in & (fifo->size -1)));
	memcpy(fifo->buffer + (fifo->in & (fifo->size -1)), buffer, n);
	/* then put the rest (if any) at the beginning of the buffer */
	memcpy(fifo->buffer, buffer + n, len - n);
	fifo->in += len;
	return len;
}
uint32_t com_kfifo_get(com_kfifo *fifo, char *buffer, uint32_t len)
{
	uint32_t	n;
	len = MIN(len, fifo->in - fifo->out);
	/* first get the data from fifo->out until the end of the buffer */
	n = MIN(len, fifo->size - (fifo->out & (fifo->size -1)));
	memcpy(buffer, fifo->buffer + (fifo->out & (fifo->size -1)), n);
	/* then get the rest (if any) from the beginning of the buffer */
	memcpy(buffer + n, fifo->buffer, len - n);
	fifo->out += len;
	return len;
}
