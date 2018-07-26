#include "util_common.h"

int com_socket_create_tcp_listen(int *sockfd, char *ip, int port,int backlog)
{
	int		fd;
	struct  sockaddr_in serv_addr;

	if(sockfd == NULL || ip == NULL)
		return EINVAL;
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if(fd < 0)
		return errno;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);
	serv_addr.sin_addr.s_addr = inet_addr(ip);
	bzero(&serv_addr.sin_zero, 8);
	if(bind(fd, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr_in)) < 0)
		return errno;
	if(listen(fd, backlog) < 0)
		return errno;
	*sockfd = fd;
	return 0;
}
int com_socket_create_tcp_connect(int *sockfd, char *ip, int port)
{
	int		fd;
	struct  sockaddr_in serv_addr;

	if(sockfd == NULL || ip == NULL)
		return EINVAL;
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if(fd < 0)
		return errno;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);
	serv_addr.sin_addr.s_addr = inet_addr(ip);
	bzero(&serv_addr.sin_zero, 8);
	if(connect(fd, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr_in)) < 0)
		return errno;
	*sockfd = fd;
	return 0;
}

int com_socket_read(int sockfd, void *buf, size_t size, size_t *len)
{
	ssize_t	n;
	*len = 0;
	do{
		n = read(sockfd, buf, size);
	}while(n == -1 && errno == EINTR);
	if(n > 0){
		*len = n;
		return 0;
	}else if(n == 0){
		return EPIPE;
	}
	if(errno == EAGAIN)
		return 0;
	return errno;
}
int com_socket_write(int sockfd, void *buf, size_t size, size_t *len)
{
	ssize_t	n;
	*len = 0;
	do{
		n = write(sockfd, buf, size);
	}while(n == -1 && errno == EINTR);
	if(n > 0){
		*len = n;
		return 0;
	}
	if(errno == EAGAIN)
		return 0;
	return errno;
}
int com_socket_readn(int sockfd, void *buf, size_t size, size_t *len)
{
	ssize_t	n;
	*len = 0;
	while(size > 0){
		n = read(sockfd, buf, size);
		if(n > 0){
			size -= n;
			buf += n;
			*len += n;
		}else if(n < 0){
			if(errno == EINTR)
				continue;
			else if(errno == EAGAIN)
				return 0;
			return errno;
		}else{
			return EPIPE;
		}
	}
	return 0;
}
int com_socket_writen(int sockfd, void *buf, size_t size, size_t *len)
{
	ssize_t	n;
	*len = 0;
	while(size > 0){
		n = write(sockfd, buf, size);
		if(n > 0){
			size -= n;
			buf += n;
			*len += n;
		}else{
			if(errno == EINTR)
				continue;
			else if(errno == EAGAIN)
				return 0;
			return errno;
		}
	}
	return 0;
}
int com_socket_readn_timeout(int sockfd, void *buf, size_t size, size_t *len, int timeout)
{
	int		nfds;
	struct	pollfd	pfds[1];
	ssize_t	n;
	*len = 0;
	while(size > 0){
		if(timeout > 0){
			pfds[0].fd = sockfd;
			pfds[0].events = POLLIN;
			do{
				nfds = poll(pfds, 1, timeout);
			}while(nfds < 0 && errno == EINTR);
			if(nfds < 0)
				return errno;
			else if(nfds == 0)
				return ETIMEDOUT;
		}
		n = read(sockfd, buf, size);
		if(n > 0){
			size -= n;
			buf += n;
			*len += n;
		}else if(n < 0){
			if(errno == EINTR)
				continue;
			else if(errno == EAGAIN)
				return 0;
			return errno;
		}else{
			return EPIPE;
		}
	}
	return 0;
}
int com_socket_writen_timeout(int sockfd, void *buf, size_t size, size_t *len, int timeout)
{
	int		nfds;
	struct	pollfd	pfds[1];
	ssize_t	n;
	*len = 0;
	while(size > 0){
		if(timeout > 0){
			pfds[0].fd = sockfd;
			pfds[0].events = POLLOUT;
			do{
				nfds = poll(pfds, 1, timeout);
			}while(nfds < 0 && errno == EINTR);
			if(nfds < 0)
				return errno;
			else if(nfds == 0)
				return ETIMEDOUT;
		}
		n = write(sockfd, buf, size);
		if(n > 0){
			size -= n;
			buf += n;
			*len += n;
		}else{
			if(errno == EINTR)
				continue;
			else if(errno == EAGAIN)
				return 0;
			return errno;
		}
	}
	return 0;
}

/*
 * mac layer function
 */
int com_mac_set_promisc(char if_name[], int fd)
{
	int		ret = 0;
	struct	ifreq	ifr;

	if(if_name == NULL || strlen(if_name) >= IFNAMSIZ || fd < 0)
		return EINVAL;
	strcpy(ifr.ifr_name, if_name);
	ret = ioctl(fd, SIOCGIFFLAGS, &ifr);
	if(ret != 0){
		log_error(ioctl, errno);
		return errno;
	}
	ifr.ifr_flags |= IFF_PROMISC;
	ret = ioctl(fd, SIOCSIFFLAGS, &ifr);
	if(ret != 0){
		log_error(ioctl, errno);
		return errno;
	}
	return 0;
}
int com_mac_get_hwaddr(char if_name[], int fd, u_char mac[])
{
	int		ret = 0;
	struct	ifreq	ifr;

	if(if_name == NULL || strlen(if_name) >= IFNAMSIZ || fd < 0 || mac == NULL)
		return EINVAL;
	strcpy(ifr.ifr_name, if_name);
	ret = ioctl(fd, SIOCGIFHWADDR, &ifr);
	if(ret != 0){
		log_error(ioctl, errno);
		return errno;
	}
	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	return 0;
}
int com_mac_get_index(char if_name[], int fd, int *if_index)
{
	int		ret = 0;
	struct	ifreq	ifr;

	if(if_name == NULL || strlen(if_name) >= IFNAMSIZ || fd < 0 || if_index == NULL)
		return EINVAL;
	strcpy(ifr.ifr_name, if_name);
	ret = ioctl(fd, SIOCGIFINDEX, &ifr);
	if(ret != 0){
		log_error(ioctl, errno);
		return errno;
	}
	*if_index = ifr.ifr_ifindex;
	return 0;
}
int com_mac_bind_if(char if_name[], int fd, short protocol)
{
	int		ret = 0;
	struct	ifreq	ifr;
	struct	sockaddr_ll	sa;

	if(if_name == NULL || strlen(if_name) >= IFNAMSIZ || fd < 0)
		return EINVAL;
	strcpy(ifr.ifr_name, if_name);
	ret = ioctl(fd, SIOCGIFINDEX, &ifr);
	if(ret != 0){
		log_error(ioctl, errno);
		return errno;
	}
	//set addr
	memset(&sa, 0, sizeof(struct sockaddr_ll));
	sa.sll_family = PF_PACKET;
	sa.sll_protocol = htons(protocol);
	sa.sll_ifindex = ifr.ifr_ifindex;
	//bind if
	ret = bind(fd, (struct sockaddr*)&sa, sizeof(struct sockaddr_ll));
	if(ret != 0){
		log_error(bind, errno);
		return errno;
	}
	return 0;
}
int com_mac_get_ifall(struct ifreq *allif, int num, int *count)
{
	int     ret, sock;
	struct  ifconf  ifc;
	char    buf[25 * sizeof(struct ifreq)];

	if(allif == NULL || num < 1 || count == NULL)
		return EINVAL;
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if(sock == -1){
		log_error(socket, errno);
		return errno;
	}
	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;
	ret = ioctl(sock, SIOCGIFCONF, &ifc);
	if(ret == -1){
		log_error(ioctl, errno);
		return errno;
	}
	*count = ifc.ifc_len / sizeof(struct ifreq);
	if(*count > num)
		*count = num;
	memcpy(allif, ifc.ifc_req, *count * sizeof(struct ifreq));
	return 0;
}
char *com_mac_get_ip(char if_name[], int fd)
{
	int		ret = 0;
	struct	ifreq	ifr;

	if(if_name == NULL || strlen(if_name) >= IFNAMSIZ || fd < 0)
		return NULL;
	strcpy(ifr.ifr_name, if_name);
	ret = ioctl(fd, SIOCGIFADDR, &ifr);
	if(ret != 0){
		log_error(ioctl, errno);
		return NULL;
	}
	return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}
int com_mac_convert_addr2mac(char addr[], u_char *mac)
{
	int		i;
	char	c, *p = addr;
	//addr eg. 00:0c:29:5d:9d:e8 
	if(addr == NULL || strlen(addr) != 17 || mac == NULL)
		return EINVAL;
	for(i=0; i<6; i++, p+=3){
		c = strtol(p, NULL, 16);
		mac[i] = c;
	}
	return 0;
}

/*
 * ip layer
 */
void print_ip(struct ip *ip)
{
	if(ip == NULL)
		return;
	printf("ip_v[%d]hl[%d]tos[%d]len[%d]id[%x]off[%x]ttl[%d]p[%d]sum[%x]src[%x]dst[%x]\n",
			ip->ip_v, ip->ip_hl, ip->ip_tos, ntohs(ip->ip_len), ntohs(ip->ip_id), ntohs(ip->ip_off),
			ip->ip_ttl, ip->ip_p, ntohs(ip->ip_sum),
			ntohl(ip->ip_src.s_addr), ntohl(ip->ip_dst.s_addr));
}
void print_tcp(struct tcphdr *tcp)
{
	if(tcp == NULL)
		return;
	printf("tcp_src[%d]dst[%d]seq[%x]ack[%x]doff[%d]urg[%d]ack[%d]psh[%d]rst[%d]syn[%d]fin[%d]win[%d]check[%x]ptr[%x]\n",
			ntohs(tcp->source), ntohs(tcp->dest), ntohl(tcp->seq), ntohl(tcp->ack_seq),
			tcp->doff, tcp->urg, tcp->ack, tcp->psh, tcp->rst, tcp->syn, tcp->fin,
			ntohs(tcp->window), ntohs(tcp->check), ntohs(tcp->urg_ptr));
}

/*
 * socket function
 */
int com_sock_bind_if(int fd, char if_name[])
{
	int     ret = 0;
	struct  ifreq   ifr;

	if(if_name == NULL || fd < 0)
		return EINVAL;
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name)-1);
	ret = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(struct ifreq));
	if(ret != 0){
		log_error(setsockopt, errno);
		return errno;
	}
	return 0;
}
int com_sock_set_sndtimeo(int fd, struct timeval *tv)
{
	int	ret = 0;

	if(fd < 0 || tv == NULL)
		return EINVAL;
	ret = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, tv, sizeof(struct timeval));
	if(ret != 0){ 
		log_error(setsockopt, errno);
		return errno;
	}
	return 0;
}
int com_sock_set_rcvtimeo(int fd, struct timeval *tv)
{
	int	ret = 0;

	if(fd < 0 || tv == NULL)
		return EINVAL;
	ret = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, tv, sizeof(struct timeval));
	if(ret != 0){ 
		log_error(setsockopt, errno);
		return errno;
	}
	return 0;
}
