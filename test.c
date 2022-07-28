
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>      /* Definition of SYS_* constants */

#include "minicriu-client.h"
#include "shared.h"

static pid_t gettid(void) {
	return syscall(SYS_gettid);
}

void *thread(void *arg) {

	minicriu_register_new_thread();

	thr_local = -gettid();

	pid_t old = gettid();
	printf("tid %d\n", old);

	while (1) {
		printf("old tid %d new tid %d local %d\n", old, gettid(), shared_fn());
		usleep(300000);
	}
}

int main(int argc, char *argv[]) {

	int fd = open("./file", O_CREAT, 0600);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	void *addr = mmap(NULL, 4096 * 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (addr == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	*(int*)addr = 1;

	pid_t oldpid = getpid();
	printf("pid %ld\n", oldpid);

	thr_local = -gettid();

	pthread_t other;
#if 0
	pthread_create(&other, NULL, thread, NULL);
#endif
	sleep(1);

	if (argc == 1) {
		minicriu_dump();
	}

	printf("done\n");

	/*sleep(3);*/
	/**((int*)0) = 1;*/
	shared_fn();

	printf("done2\n");
#if 1
	while (1) {
		printf("pid old %ld new %ld local %d\n", oldpid, getpid(), shared_fn());
		/**((int*)0) = 1;*/
		sleep(1);
	}

	// WILL NOT WORK: other has a stale TID inside
	pthread_join(other, NULL);
#endif

	return 0;
}
