#include "util_common.h"

#define UNUSE   0
#define INUSE   1

static int check_str_isdigit(char *str)
{
	int     i;
	assert(str != NULL);
	if(strlen(str) == 0 || strlen(str) > 20)
		return 0;
	for(i=0; str[i]!='\0'; i++){
		if(!isdigit(str[i]))
			return 0;
	}
	return 1;
}
static int check_node_unuse_isleaf(digittree_node *node)
{
	int     i;
	assert(node != NULL);
	if(node->valid == INUSE)
		return 0;
	for(i=0; i<10; i++){
		if(node->child[i] != NULL)
			return 0;
	}
	return 1;
}
int digittree_create(digittree_tree **tree)
{
	int    ret;
	digittree_node  *p;

	if(tree == NULL)
		return EINVAL;
	ret = com_mmap_create((void**)tree, sizeof(digittree_tree));
	if(0 != ret)
		return ret;
	//init tree
	(*tree)->nodes = 0;
	ret = com_lock_init(&(*tree)->lock, COM_LOCK_SHARE);
	if(0 != ret)
		return ret;
	//init root
	ret = com_mmap_create((void**)&p, sizeof(digittree_node));
	if(0 != ret)
		return ret;
	memset(p, 0, sizeof(digittree_node));
	(*tree)->root = p;
	return 0;
}
int digittree_find(digittree_tree *tree, char *str, void **data)
{
	int	i, j, find = -1;
	digittree_node  *p = NULL;

	if(tree == NULL || str == NULL || data == NULL)
		return EINVAL;
	if(!check_str_isdigit(str)) 
		return EINVAL;
	p = tree->root;
	COM_LOCK(&tree->lock);
	for(i=0; str[i]!='\0'; i++, p=p->child[j]){
		j = str[i] - '0';
		if(p->child[j] ==NULL)
			break;
		if(p->child[j]->valid == INUSE){
			find = 0;
			(*data) = p->child[j]->data;
			break;
		}
	}
	COM_UNLOCK(&tree->lock);
	return find;
}
int digittree_add(digittree_tree *tree, char *str, void *data)
{
	int	ret;
	int	i, j;
	digittree_node  *p, *pn;

	if(tree == NULL || str == NULL)
		return EINVAL;
	if(!check_str_isdigit(str))
		return EINVAL;
	p = tree->root;
	COM_LOCK(&tree->lock);
	ret = -1;
	for(i=0; str[i]!='\0'; i++, p=p->child[j]){
		j = str[i] - '0';
		if(p->child[j] == NULL){
			ret = com_mmap_create((void**)&pn, sizeof(digittree_node));
			if(0 != ret){
				log_error(com_mmap_create,ret);
				break;
			}
			memset(pn, 0, sizeof(digittree_node));
			pn->parent = p;
			pn->label = j;
			pn->level = i+1;
			pn->data = data;
			p->child[j] = pn;
			tree->nodes++;
			//log_printf("*** add:%d,%d ***\n", pn->level, pn->label);
		}
		if(str[i+1] == '\0'){
			if(p->child[j]->valid == INUSE){
				ret = -1;
			}else{
				p->child[j]->valid = INUSE;
				ret = 0;
			}
			break;
		}
	}
	COM_UNLOCK(&tree->lock);
	return ret;
}
int digittree_del(digittree_tree *tree, char *str, void **data)
{
	int	ret;
	int	i, j;
	digittree_node  *p, *pc;

	if(tree == NULL || str == NULL)
		return EINVAL;
	if(!check_str_isdigit(str))
		return EINVAL;
	p = tree->root;
	COM_LOCK(&tree->lock);
	ret = -1;
	for(i=0; str[i]!='\0'; i++, p=p->child[j]){
		j = str[i] - '0';
		if(p->child[j] == NULL)
			break;
		if(str[i+1] == '\0'){
			if(p->child[j]->valid == INUSE){
				p->child[j]->valid = UNUSE;
				(*data) = p->child[j]->data;
				ret = 0;
				pc = p->child[j];
				while((pc!=tree->root) && check_node_unuse_isleaf(pc)){
					p = pc->parent;
					p->child[(int)pc->label] = NULL;
					//log_printf("*** del child:%d,%d ***\n", pc->level, pc->label);
					com_mmap_destroy(pc, sizeof(digittree_node));
					tree->nodes--;
					pc = p;
				}
			}
			break;
		}
	}
	COM_UNLOCK(&tree->lock);
	return ret;
}
static void travel_node(digittree_tree *tree, digittree_node *node)
{
	int     i, j, k;
	char    buf[22];
	char    buf2[22];
	digittree_node  *p = NULL;

	if(node->valid == INUSE){
		j = 0; p = node;
		while(p != tree->root){
			buf[j++] = '0'+p->label;
			p = p->parent;
		}
		k = 0; buf2[j] = '\0';
		while(--j >= 0)
			buf2[k++] = buf[j];
		log_printf("*** travel:%s ***\n", buf2);
	}
	for(i=0; i<10; i++){
		if(node->child[i] != NULL){
			travel_node(tree, node->child[i]);
		}
	}
}
int digittree_travel(digittree_tree *tree)
{
	if(tree == NULL || tree->root == NULL)
		return EINVAL;
	COM_LOCK(&tree->lock);
	travel_node(tree, tree->root);
	COM_UNLOCK(&tree->lock);
	log_printf("*** travel nodes:%d\n", tree->nodes);
	return 0;
}
