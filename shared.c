#include <sys/syscall.h>      /* Definition of SYS_* constants */

#include "shared.h"

volatile int __thread thr_local;

static int gettid(void) {
	return syscall(SYS_gettid);
}

int shared_fn(void) {
	/**((int*)0) = 1;*/
#if 0
	if (!thr_local) {
		thr_local = -gettid();
	}
#endif
	return thr_local;
}
