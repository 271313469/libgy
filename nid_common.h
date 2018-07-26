#ifndef NID_COMMON_H
#define NID_COMMON_H

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

#define	CPU_NUM		4
#define TCP_WMEM	16384
#define TCP_RMEM	87380
#define MAXEVENTS	100
#define NID_PK_MAX	2560
#define CMPPSP_MAX	10000
#define CMPPSMG_MAX	100

enum{
	SOCKET_UNUSE = 0,
	SOCKET_INUSE = 1,
	SOCKET_LOGIN = 2,
	SOCKET_ERROR = 3,
	SOCKET_CLOSE = 4,
};

typedef struct nid_flow			nid_flow;
typedef struct nid_store		nid_store;
typedef struct nid_msgq			nid_msgq;
typedef struct nid_sock			nid_sock;
typedef struct nid_window		nid_window;
typedef struct nid_winelem		nid_winelem;
typedef struct worker_attr_t	worker_attr_t;
typedef struct worker_fd_t		worker_fd_t;

typedef struct cmppsp_desc		cmppsp_desc;
typedef struct cmppsp_node		cmppsp_node;
typedef struct cmppsmg_desc		cmppsmg_desc;
typedef struct cmppsmg_node		cmppsmg_node;

/*
 * nid
 */
struct nid_flow
{
	uint32_t	mof;
	uint32_t	mtf;
	uint32_t	mosrf;
	uint32_t	mtsrf;
};
struct nid_store
{
	uint32_t	mos;
	uint32_t	mts;
	uint32_t	mosrs;
	uint32_t	mtsrs;
};
struct nid_msgq
{
	void		*moq;
	void		*mtq;
	void		*mosrq;
	void		*mtsrq;
	void		*failq;
};
/*
 * socket
 */
struct nid_winelem
{
	char		status;		//0:unuse, 1:inuse
	uint32_t	key;		//key=seq
	time_t		timestamp;
	void		*value;
};
struct nid_window
{
	uint32_t	size;
	uint32_t	cursize;
	uint32_t	timeout;
	nid_winelem	*elem;	//winelem array 
};
struct nid_sock
{
	char		wid;		//worker id
	char		status;		//0:unuse 1:inuse 2:login 3:error 4:close
	char		curtimes;	//cur timeout times
	char		timeoflag;	//timeout flag
	char		sendflag;	//send msg flag
	uint16_t	nid;		//node id
	uint32_t	seq;
	uint32_t	utime;
	uint32_t    nread;
	uint32_t    nwrite;
	char		readbuf[NID_PK_MAX];
	char		writebuf[NID_PK_MAX];
	nid_window	window;
	void		*errpk;
};
/*
 * worker
 */
struct worker_fd_t
{
	char	runflag;
	int		maxsock;
	int		minfd;
	int		maxfd;
	int		curlink;
	nid_sock	*socks;
};
struct worker_attr_t
{
	int     id;
	int     epfd;
	int     link;
};


/*
 * SP
 */
struct cmppsp_desc
{
	uint16_t	idx;		//[1,65535]
	char		sp_id[7];	//corp_id
	char		sp_code[22];//svc_id
	char		service[11];//busy_id
	char    	pwd[16];	//MD5(Source_Addr + 000000000 + secret + timestamp)
	char		ip[16];
	uint8_t		proto;		//1:cmpp20, 2:cmpp30
	uint8_t		link;		//[0,255]
	uint16_t	speed;		//[0,65535]
	uint16_t	window;		//[1,16,1000]
	uint16_t	timeout;	//[1,60,900]
	uint8_t		times;		//[1,3,255]
	uint16_t	interval;	//[1,300,900]
};
struct cmppsp_node
{
	cmppsp_desc	desc;
	uint8_t		status;		//0:unuse 1:inuse
	uint8_t		curlink;
	char		sendflag;
	nid_flow	flow;
	nid_store	store;
	nid_msgq	msgq;
	pthread_mutex_t	*lock;
};
/*
 * RSMG
 */
struct cmppsmg_desc
{
	uint16_t	idx;		//[1,65535]
	char		smg_id[7];
	char		ip[16];
	uint16_t	port30;
	uint16_t	port20;
	char		spwd[16];
	char		rpwd[16];
	uint8_t		slink;		//[0,255]
	uint8_t		rlink;		//[0,255]
	uint16_t	windows;	//[1,100,1000]
	uint16_t	timeout;	//[1,60,900]
	uint8_t		times;		//[1,3,255]
	uint16_t	interval;	//[1,300,900]
};
struct cmppsmg_node
{
	cmppsmg_desc	desc;
	uint8_t		status;
	uint8_t		curslink;
	uint8_t		currlink;
	char		sendflag;
	nid_flow	flow;
	nid_store	store;
	nid_msgq	msgq;
	pthread_mutex_t	*lock;
};

int nid_window_init(nid_window *win, uint32_t size, uint32_t timeout);
int nid_window_add(nid_window *win, uint32_t key, void *value);
int nid_window_del(nid_window *win, uint32_t key, void *value);
int nid_window_timeout(nid_window *win, void *value);
int nid_window_clear(nid_window *win, void *value);
void nid_window_count(nid_window *win, uint32_t *cursize);
void nid_window_destroy(nid_window *win);

#endif
