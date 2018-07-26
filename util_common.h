#ifndef UTIL_COMMON_H 
#define UTIL_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <dirent.h>
#include <time.h>
#include <stdarg.h>
#include <ctype.h>
#include <setjmp.h>

#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <endian.h>
#include <pthread.h>

#define ETH_MAC_HEAD_MIN    14
#define ETH_IP_HEAD_MIN     20
#define ETH_TCP_HEAD_MIN    20
#define ETH_UDP_HEAD_MIN    8
#define ETH_ICMP_HEAD_MIN   8
#define ETH_IGMP_HEAD_MIN   8

#define ETH_MAC_DATA_MIN    54      //6+6+2 + 20 + 20
#define ETH_MAC_DATA_MAX    1518    //6+6+4+2 + 1500
#define ETH_IP_DATA_MIN     46
#define ETH_IP_DATA_MAX     1500
#define ETH_TCP_DATA_MAX    1472    //1500 - 20 - 8

#define log_error(name, ret) log_printf("%s error(%d),(%s)(%d)(%s)\n", #name,ret,__FILE__,__LINE__,__FUNCTION__)

enum{
	COM_LOCK_NORMAL,
	COM_LOCK_SHARE,
	COM_LOCK_REUSE,
};
enum{
	LOG_FILETYPE_NONE,
	LOG_FILETYPE_STDOUT,
	LOG_FILETYPE_FIFO,
	LOG_FILETYPE_REGULAR,
	LOG_FILETYPE_ADVANCED,
};

/* lock */
#define COM_LOCK(lock)		do{if(pthread_mutex_lock(lock)) return EDEADLK;}while(0)
#define COM_UNLOCK(lock)	do{pthread_mutex_unlock(lock);}while(0)

typedef unsigned char		uchar;
typedef unsigned short		ushort;
typedef unsigned int		uint;
typedef unsigned long		ulong;
typedef unsigned long long	ullong;


/***************/
/* 1.struct    */
/***************/
typedef struct com_list com_list;
struct com_list{
	struct com_list *next, *prev;
};
#define LIST_INIT(p)		(p)->next=(p), (p)->prev=(p);
#define LIST_ADD(h, p)		(p)->next=(h), (p)->prev=(h)->prev, (h)->prev->next=(p), (h)->prev=(p);
#define LIST_DEL(h, p)		(p)=(h)->next, (h)->next=(p)->next, (p)->next->prev=(h);
#define LIST_EMPTY(h)		(h)->next==(h)
#define LIST_FOR_EACH(h, p)	for((p)=(h)->next; (p)!=(h); (p)=(p)->next)

typedef struct com_queue com_queue;
struct com_queue{
	uint32_t		count;
	com_list	head;
};

typedef struct com_rq_t com_rq_t;
struct com_rq_t{
	uint32_t    count;
	uint32_t    size;
	uint32_t    head;
	uint32_t    tail;
	void		*data;
};

/* obj pool */
typedef struct com_obj_pool  com_obj_pool;
typedef struct com_obj_node  com_obj_node;
struct com_obj_pool{
	pthread_mutex_t	lock;
	int		count;
	int		size;
	int		free;
	int		head;
	int		tail;
	long	memsize;
	void    *ptr;
};
struct com_obj_node{
	int		status; //0:unuse, 1:inuse
	int		next;   //>=0:next, -1:tail, -2:inuse
	void    *data;
};

/* proc */
typedef struct com_child com_child;
struct com_child{
	int		(*child_main)(int pipefd);
	char	name[64];
	pid_t	pid;
	int		status;
};
/* alth */

/* signal */
typedef void com_sigfunc(int signo);
com_sigfunc *com_signal(int signo, com_sigfunc *func);

/* file */
typedef struct com_log_t    com_log_t;
typedef struct com_log_file com_log_file;
struct com_log_t{
	char    name[PATH_MAX];
	char    type;
	int     fd;
	com_log_file    *file;
};
struct com_log_file{
	int     timeout;
	time_t  opentime;
	size_t  sizeout;
	size_t  cursize;
	void	*buffer;
	pthread_mutex_t lock;
};
typedef struct fifo2file_t  fifo2file_t;
struct fifo2file_t{
	char    fifo[PATH_MAX];
	char    file[PATH_MAX];
	size_t  size;
	int		expire;
};

/* mem */
typedef struct com_kfifo com_kfifo;
struct com_kfifo {
	char    *buffer;
	uint32_t	size;
	uint32_t	in;
	uint32_t	out;
};

/* dttree */
#define DIGITTREE_NODE_COUNT    111111
typedef struct digittree_node digittree_node;
typedef struct digittree_tree digittree_tree;
struct digittree_tree{
	int		nodes;
	pthread_mutex_t	lock;
	digittree_node  *root;
};
struct digittree_node{
	digittree_node  *parent;
	digittree_node  *child[10];
	char	label;
	char	level;
	char	valid;
	void	*data;
};


/***************/
/* 2.function  */
/***************/

/* proc */
void com_proc_detach();
int com_proc_waitall(void);

/* alth */
uint32_t com_crc32(char *buffer, size_t length);
uint32_t BKDRHash(char *str);

/* lock */
int com_lock_init(pthread_mutex_t *mutex, int type);

/* file */
int log_init(char *filename, char type, int timeout, size_t size);
int log_printf(const char *fmt,...);
void log_destroy();
int com_readn(int fd, void *buf, size_t size, size_t *len);
int com_writen(int fd, void *buf, size_t size, size_t *len);
int com_del_expiredfile(char *path, int expire);
int log_fifo2file(char *fifoname, char *filename, size_t size, int expire, char *runflag);

/* mem */
int com_mmap_file(void **pmmap, char *filename, size_t size);
int com_mmap_create(void **pmmap, size_t size);
int com_mmap_destroy(void *pmmap, size_t len);
int com_kfifo_init(com_kfifo *fifo, uint32_t size);
void com_kfifo_destroy(com_kfifo *fifo);
uint32_t com_kfifo_put(com_kfifo *fifo, char *buffer, uint32_t len);
uint32_t com_kfifo_get(com_kfifo *fifo, char *buffer, uint32_t len);

/* str */
int com_str_isdigit(char *str);
int com_str_ishex(char *str);
int com_str_isasc(char *str);
char *com_str_ltrim(char *str);
char *com_str_rtrim(char *str);
char *com_str_trim(char *str);

/* cfg */
int com_cfg_get_value_by_key(char *filename, char *key, char *value);
int com_cfg_get_value_by_row(char *filename, int row, char *value);
int com_cfg_get_value_by_field(char *buf, int filed, char *value);

/* socket */
int com_socket_setnonblock(int sockfd);
int com_socket_get_localip(char *ip);
int com_socket_create_tcp_listen(int *sockfd, char *ip, int port,int backlog);
int com_socket_create_tcp_connect(int *sockfd, char *ip, int port);
int com_socket_read(int sockfd, void *buf, size_t n, size_t *len);
int com_socket_write(int sockfd, void *buf, size_t n, size_t *len);
int com_socket_readn(int sockfd, void *buf, size_t n, size_t *len);
int com_socket_writen(int sockfd, void *buf, size_t n, size_t *len);
int com_socket_read_timeout(int sockfd, void *buf, size_t n, size_t *len, int timeout);
int com_socket_read_timeout(int sockfd, void *buf, size_t n, size_t *len, int timeout);
int com_socket_write_timeout(int sockfd, void *buf, size_t n, size_t *len, int timeout);
/* mac layer*/
int common_mac_set_promisc(char if_name[], int fd);
int common_mac_get_hwaddr(char if_name[], int fd, u_char mac[]);
int common_mac_get_index(char if_name[], int fd, int *if_index);
int common_mac_bind_if(char if_name[], int fd, short protocol);
int common_mac_get_ifall(struct ifreq *allif, int num, int *count);
char *common_mac_get_ip(char if_name[], int fd);
int common_mac_convert_addr2mac(char addr[], u_char *mac);
/* ip layer */
void print_ip(struct ip *ip);
void print_tcp(struct tcphdr *tcp);
/* net layer */
int common_sock_bind_if(int fd, char if_name[]);
int common_socket_set_sndtimeo(int fd, struct timeval *tv);
int common_socket_set_rcvtimeo(int fd, struct timeval *tv);

/* dttree */
int digittree_create(digittree_tree **tree);
int digittree_find(digittree_tree *tree, char *str, void **data);
int digittree_add(digittree_tree *tree, char *str, void *data);
int digittree_del(digittree_tree *tree, char *str, void **data);
int digittree_travel(digittree_tree *tree);

/* queue */
int com_queue_init(com_queue *q);
int com_queue_put(com_queue *q, void *ptr);
int com_queue_get(com_queue *q, void **ptr);
int com_queue_count(com_queue *q, uint32_t *count);

int com_rq_init(com_rq_t *q, uint32_t count, uint32_t size);
void com_rq_destroy(com_rq_t *q);
int com_rq_put(com_rq_t *q, void *e);
int com_rq_get(com_rq_t *q, void *e);

/* obj pool */
int com_objpool_create(com_obj_pool **pool, int count, int size);
int com_objpool_destroy(com_obj_pool *pool);
int com_objpool_malloc(com_obj_pool *pool, void **ptr);
int com_objpool_free(com_obj_pool *pool, void *ptr);
int com_objpool_get_count(com_obj_pool *pool, int *count);

#endif
