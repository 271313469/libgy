#include "util_common.h"

void com_proc_detach()
{
	int     i;
	pid_t   pid;
	int     fd0, fd1, fd2;

	umask(0);
	if((pid = fork()) < 0)
		fprintf(stderr, "fork failed\n");
	if(pid > 0)
		exit(0);
	signal(SIGHUP, SIG_IGN);
	setsid();
	if((pid = fork()) < 0)
		fprintf(stderr, "fork failed\n");
	else if(pid > 0)
		exit(0);
	for(i=0; i<getdtablesize(); i++)
		(void)close(i);
	fd0 = open("/dev/null", O_RDWR);
	fd1 = dup(0);
	fd2 = dup(0);
	if(fd0 != 0 || fd1 != 1 || fd2 != 2)
		exit(1);
	sleep(1);
	return ;
}

int com_proc_waitall(void)
{                       
	int     status;           
	pid_t   pid;    
	while(1){
		if((pid = wait(&status)) >= 0){
			if(WIFEXITED(status)){
			}else if(WIFSIGNALED(status)){
			}else if(WIFSTOPPED(status)){
				//log_printf("process[%d] has stopped!\n",pid);
			}else{
				//log_printf("process[%d] has died with unkonown statusus!\n",pid);
			}
			continue;
		}
		if(errno == EINTR)
			continue;
		if(errno == ECHILD)
			break;
	}
	return 0;
}
