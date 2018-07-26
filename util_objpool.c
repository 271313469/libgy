#include "util_common.h"
/*
 * obj pool function
 */
#define COM_OBJ_NODE_HEAD	(sizeof(com_obj_node) - sizeof(void*))
#define COM_OBJ_NODE_SIZE	(COM_OBJ_NODE_HEAD + pool->size)

int com_objpool_create(com_obj_pool **pool, int count, int size)
{
	int		ret = 0, i;
	com_obj_node *obj;

	if(count < 1 || size < sizeof(long) || size % sizeof(long))
		return EINVAL; 
	ret = com_mmap_create((void**)pool, sizeof(com_obj_pool));
	if(ret != 0)
		return ret;
	ret = com_lock_init(&(*pool)->lock, COM_LOCK_SHARE);
	if(ret != 0)
		return ret;
	(*pool)->count = count;
	(*pool)->free = count;
	(*pool)->size = size;
	(*pool)->head = 0;
	(*pool)->tail = count-1;
	(*pool)->memsize = count * (size + COM_OBJ_NODE_HEAD);
	ret = com_mmap_create(&(*pool)->ptr, (*pool)->memsize);
	if(ret != 0)
		return ret;
	obj = (*pool)->ptr;
	for(i=0; i<count; i++){
		obj->status = 0;
		if(i == count-1)
			obj->next = -1;
		else
			obj->next = i+1;
		obj = (void*)obj + size + COM_OBJ_NODE_HEAD;
	}
	return 0;
}

int com_objpool_destroy(com_obj_pool *pool)
{
	if(pool == NULL)
		return EINVAL;
	pthread_mutex_destroy(&pool->lock);
	free(pool->ptr);
	memset(pool, 0, sizeof(com_obj_pool));
	return 0;
}

int com_objpool_malloc(com_obj_pool *pool, void **obj)
{
	int		ret = 0;
	com_obj_node *node;

	if(pool == NULL)
		return EINVAL;
	COM_LOCK(&pool->lock);
	if(pool->free <= 0){
		ret = ENOMEM;
		goto over;
	}
	if(pool->head < 0){
		ret = EFAULT;
		goto over;
	}
	node = pool->ptr + (pool->head)*COM_OBJ_NODE_SIZE;
	if(node ->status != 0){
		ret = EFAULT;
		goto over;
	}
	pool->free--;
	pool->head = node->next;
	node->status = 1;
	node->next = -2;
	*obj = &node->data;
over:
	COM_UNLOCK(&pool->lock);
	return ret;
}

int com_objpool_free(com_obj_pool *pool, void *obj)
{
	int		ret = 0, index;
	com_obj_node *node, *tail;

	if(pool == NULL || obj == NULL || obj < pool->ptr || obj > (pool->ptr + pool->memsize))
		return EINVAL; 
	COM_LOCK(&pool->lock);
	node = obj - COM_OBJ_NODE_HEAD;
	if(node->status != 1){
		ret = EFAULT;
		goto over;
	}
	node->status = 0;
	node->next = -1;
	index = ((void*)node - pool->ptr)/COM_OBJ_NODE_SIZE;
	if(pool->head < 0)
		pool->head = index;
	else{
		tail = pool->ptr + (pool->tail)*COM_OBJ_NODE_SIZE;
		tail->next = index;
	}
	pool->tail = index;
	pool->free++;
over:
	COM_UNLOCK(&pool->lock);
	return ret;
}

int com_objpool_count(com_obj_pool *pool, int *count)
{
	if(pool == NULL || count == NULL)
		return EINVAL; 
	COM_LOCK(&pool->lock);
	*count = pool->free;
	COM_UNLOCK(&pool->lock);
	return 0;
}
