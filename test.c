
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>      /* Definition of SYS_* constants */

#include "minicriu-client.h"

static pid_t gettid(void) {
	return syscall(SYS_gettid);
}

void *thread(void *arg) {

	minicriu_register_new_thread();

	pid_t old = gettid();
	printf("tid %d\n", old);

	while (1) {
		printf("old tid %d new tid %d\n", old, gettid());
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

#if 0
	pthread_t other;
	pthread_create(&other, NULL, thread, NULL);
	sleep(1);
#endif

	if (argc == 1) {
		minicriu_dump();
	}

	printf("done\n");

	volatile int loop = 1;
	while(loop);
	sleep(3);
	*((int*)0) = 1;

	printf("done2\n");
#if 0
	while (1) {
		printf("pid old %ld new %ld\n", oldpid, getpid());
		/**((int*)0) = 1;*/
		sleep(1);
	}

	// WILL NOT WORK: other has a stale TID inside
	pthread_join(other, NULL);
#endif

	return 0;
}
