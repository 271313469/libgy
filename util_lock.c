#include "util_common.h"

int com_lock_init(pthread_mutex_t *mutex, int type)
{
	int		ret;
	pthread_mutexattr_t	mattr;

	ret = pthread_mutexattr_init(&mattr);
	if(ret != 0)
		return errno;
	ret = pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_ERRORCHECK);
	if(ret != 0)
		goto over;
	if(type == COM_LOCK_NORMAL){
		goto init;
	}else if(type == COM_LOCK_SHARE){
	}else if(type == COM_LOCK_REUSE){
		ret = pthread_mutexattr_setprotocol(&mattr, PTHREAD_PRIO_INHERIT);
		if(ret)
			goto over;
		ret = pthread_mutexattr_setrobust_np(&mattr, PTHREAD_MUTEX_ROBUST_NP);
		if(ret)
			goto over;
	}
	ret = pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
	if(ret != 0)
		goto over;
init:
	return pthread_mutex_init(mutex, &mattr);
over:
	pthread_mutexattr_destroy(&mattr);
	return errno;
}
