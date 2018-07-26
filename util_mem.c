#include "util_common.h"

int com_mmap_file(void **pmmap, char *filename, size_t size)
{
	int     fd;
	if(size < 1)
		return EINVAL;
	if(filename == NULL)
		return com_mmap_create(pmmap, size);
	fd = open(filename, O_RDWR|O_CREAT, 0644);
	if(fd < 0)
		return errno;
	if(lseek(fd, size - 1, SEEK_SET) < 0){
		close(fd);
		return errno;
	}
	if(write(fd, "", 1) < 0){
		close(fd);
		return errno;
	}
	(*pmmap) = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	if((*pmmap) == MAP_FAILED)
		return errno;
	memset(*pmmap, 0, size);
	return 0;
}
int com_mmap_create(void **pmmap, size_t size)
{
	int     fd;
	if(size < 1)
		return EINVAL;
	fd = open("/dev/zero", O_RDWR);
	if(fd < 0)
		return errno;
	(*pmmap) = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	if((*pmmap) == MAP_FAILED)
		return errno;
	memset(*pmmap, 0, size);
	return 0;
}
int com_mmap_destroy(void *pmmap, size_t len)
{
	if(munmap(pmmap, len) < 0)
		return errno; 
	return 0;
}
