#include "util_common.h"

com_log_t glog;

int log_init(char *filename, char type, int timeout, size_t sizeout)
{
	int	ret;
	pthread_mutexattr_t	mattr;
	if(filename == NULL)
		return EINVAL;
	snprintf(glog.name, sizeof(glog.name), "%s", filename);
	glog.type = type;
	glog.fd = -1;
	glog.file = NULL;
	if(type == LOG_FILETYPE_NONE || type == LOG_FILETYPE_STDOUT){
		return 0;
	}else if(type == LOG_FILETYPE_FIFO){
		mkfifo(filename, 0644);
		glog.fd = open(filename, O_RDWR | O_NONBLOCK, 0);
		if(glog.fd < 0)
			return errno;
	}else if(type == LOG_FILETYPE_REGULAR){
		glog.fd = open(filename, O_WRONLY | O_CREAT | O_APPEND | O_NONBLOCK, 0644);
		if(glog.fd < 0)
			return errno;
	}else if(type == LOG_FILETYPE_ADVANCED){
		if(timeout < 1 || sizeout < 1)
			return EINVAL;
		ret = com_mmap_create((void**)&glog.file, sizeof(com_log_file));
		if(ret != 0)
			return ret;
		glog.file->timeout = timeout;
		glog.file->sizeout = sizeout;
		glog.file->opentime = time(NULL);
		glog.file->cursize = 0;
		ret = com_mmap_file(&glog.file->buffer, glog.name, glog.file->sizeout);
		if(ret != 0)
			return ret;
		pthread_mutexattr_init(&mattr);
		pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
		if(pthread_mutex_init(&glog.file->lock, &mattr) != 0)
			return errno;
	}else{
		return EINVAL;
	}
	return 0;
}
int log_printf(const char *fmt, ...)
{
	size_t	len, nwrite;
	char    buf[PIPE_BUF], log[PIPE_BUF], tmp[16];
	struct  timeval tv;
	struct  tm tm;
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	gettimeofday(&tv, NULL);
	localtime_r(&tv.tv_sec, &tm);
	sprintf(tmp, "%04d%02d%02d%02d%02d%02d", tm.tm_year+1900, tm.tm_mon+1,tm.tm_mday, tm.tm_hour, tm.tm_min, tm .tm_sec);
	if(glog.type == LOG_FILETYPE_FIFO || glog.type == LOG_FILETYPE_REGULAR){
		len = snprintf(log, sizeof(log), "%s.%lu-%u-%lu>%s\n", tmp, tv.tv_usec, getpid(), pthread_self(), buf);
		return com_writen(glog.fd, log, len, &nwrite);
	}else if(glog.type == LOG_FILETYPE_ADVANCED){
		len = snprintf(log, sizeof(log), "%s.%lu-%u-%lu>%s\n", tmp, tv.tv_usec, getpid(), pthread_self(), buf);
		COM_LOCK(&glog.file->lock);
		if((glog.file->cursize + len > glog.file->sizeout) || (glog.file->opentime + glog.file->timeout < tv.tv_sec)){
			munmap(glog.file->buffer, glog.file->sizeout);
			snprintf(buf, sizeof(buf), "%s.%s.log", glog.name, tmp);
			rename(glog.name, buf);
			com_mmap_file(&glog.file->buffer, glog.name, glog.file->sizeout);
			glog.file->opentime = tv.tv_sec;
			glog.file->cursize = 0;
		}
		if(glog.file->buffer != NULL){
			memcpy(glog.file->buffer + glog.file->cursize, log, len);
			glog.file->cursize += len;
		}
		COM_UNLOCK(&glog.file->lock);
	}else if(glog.type == LOG_FILETYPE_STDOUT){
		fprintf(stdout, "%s.%lu-%u-%lu>%s\n", tmp, tv.tv_usec, getpid(), pthread_self(), buf);
	}
	return 0;
}
void log_destroy()
{
	if(glog.fd != -1)
		close(glog.fd);
	if(glog.file != NULL){
		pthread_mutex_destroy(&glog.file->lock);
		if(glog.file->buffer != NULL)
			munmap(glog.file->buffer, glog.file->sizeout);
		munmap(glog.file, sizeof(com_log_file));
	}
	memset(&glog, 0, sizeof(com_log_t));
	glog.fd = -1;
	return;
}
int com_readn(int fd, void *buf, size_t size, size_t *len)
{
	ssize_t n;
	*len = 0;
	while(size > 0){
		n = read(fd, buf, size);
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
int com_writen(int fd, void *buf, size_t size, size_t *len)
{
	ssize_t n;
	*len = 0;
	while(size > 0){
		n = write(fd, buf, size);
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
int com_del_expiredfile(char *path, int expire)
{
	DIR     *dp; 
	struct	dirent	*dirp;
	struct	stat	tmp; 
	char    fpath[1024];
	time_t	now;

	if(path == NULL || expire < 1)
		return EINVAL;
	dp = opendir(path);
	if(dp == NULL)
		return errno;
	now = time(NULL);
	while((dirp = readdir(dp)) != NULL){
		if(!strcmp(dirp->d_name, ".") || !strcmp(dirp->d_name, ".."))
			continue;
		snprintf(fpath, sizeof(fpath), "%s/%s", path, dirp->d_name);
		if(stat(fpath, &tmp) != 0)
			continue;
		if(tmp.st_mtime + expire < now)
			unlink(fpath);
	}
	closedir(dp);
	return 0;
}

int log_fifo2file(char *fifoname, char *filename, size_t size, int expire, char *runflag)
{
	int		fd1, fd2;
	size_t	nread, nwrite, sum;
	char	file[PATH_MAX], filenew[PATH_MAX], tmp[16];
	char	buffer[65536];
	struct  pollfd  pfds[1];
	int     nfds;
	time_t	create, now;
	struct	stat st;
	struct	tm	tm;

	if(fifoname == NULL || filename == NULL)
		return EINVAL;
	/* open fifo */
	mkfifo(fifoname, 0644);
	if(stat(fifoname, &st) != 0)
		return errno;
	if(!S_ISFIFO(st.st_mode))
		return -1;
	if((fd1 = open(fifoname, O_RDWR|O_NONBLOCK, 0)) < 0)
		return errno;
	pfds[0].fd = fd1;
	pfds[0].events = POLLIN;
	/* open file */
	snprintf(file, sizeof(file), "%s.tmp", filename);
write:
	if((fd2 = open(file, O_WRONLY|O_NONBLOCK|O_CREAT, 0644)) < 0)
		return errno;
	create = time(NULL);
	sum = 0;
	/* read fifo, write file */
	while(*runflag){
		nfds = poll(pfds, 1, 30000);
		if(nfds > 0){
			while((nread = read(fd1, buffer, sizeof(buffer))) > 0){
				nwrite = write(fd2, buffer, nread);
				if(nwrite < 0)
					break;
				sum += nwrite;
			}
		}
		now = time(NULL);
		if((size > 0 && sum > size) || (expire > 0 && now > create + expire)){
			close(fd2);
			localtime_r(&now, &tm);
			sprintf(tmp, "%04d%02d%02d%02d%02d%02d", tm.tm_year+1900, tm.tm_mon+1,tm.tm_mday, tm.tm_hour, tm.tm_min, tm .tm_sec);
			snprintf(filenew, sizeof(filenew), "%s-%s.log", filename, tmp);
			rename(file, filenew);
			goto write;
		}
	}
	close(fd1);
	close(fd2);
	now = time(NULL);
	localtime_r(&now, &tm);
	sprintf(tmp, "%04d%02d%02d%02d%02d%02d", tm.tm_year+1900, tm.tm_mon+1,tm.tm_mday, tm.tm_hour, tm.tm_min, tm .tm_sec);
	snprintf(filenew, sizeof(filenew), "%s-%s.log", filename, tmp);
	rename(file, filenew);
	return 0;
}
