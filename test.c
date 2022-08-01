
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>      /* Definition of SYS_* constants */

#include "minicriu-client.h"
#include "shared.h"


static pthread_t main_thread;

static pid_t gettid(void) {
	return syscall(SYS_gettid);
}

static void do_kill(pthread_t thr, const char *msg) {
	int err;
	do {
		err = pthread_kill(thr, SIGUSR2);
	} while (err == EINTR);
	if (err) {
		perror(msg);
	}
}

void sighnd(int sig) {
	char buf[64];
	int len = snprintf(buf, sizeof(buf), "SIG %d\n", gettid());
	write(STDOUT_FILENO, buf, len);
}

void *thread(void *arg) {

	minicriu_register_new_thread();

	thr_local = -gettid();

	pid_t old = gettid();
	printf("tid %d\n", old);

	while (1) {
		printf("THREAD old tid %d new tid %d local %d\n", old, gettid(), shared_fn());
		do_kill(main_thread, "kill main");
		usleep(300000);
	}
}

int main(int argc, char *argv[]) {

	signal(SIGUSR2, sighnd);

	main_thread = pthread_self();

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
	pthread_create(&other, NULL, thread, NULL);

	sleep(100);

	if (argc == 1) {
		minicriu_dump();
	}

	printf("done\n");

	/*sleep(3);*/
	/**((int*)0) = 1;*/
	shared_fn();

	printf("done2\n");

	while (1) {
		printf("MAIN pid old %ld new %ld local %d\n", oldpid, getpid(), shared_fn());
		do_kill(other, "kill other");
		sleep(1);
	}

	pthread_join(other, NULL);

	return 0;
}
