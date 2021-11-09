
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/fcntl.h>
#include <sys/mman.h>

static int dump() {
	struct sigaction old, new;

	new.sa_handler = SIG_DFL;
	if (sigaction(SIGABRT, &new, &old)) {
		perror("sigaction");
		return 1;
	}

	raise(SIGABRT);

	if (sigaction(SIGABRT, &old, NULL)) {
		perror("sigaction 2");
	}

	return 0;
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

	volatile register long canary asm("rbx") = 0xaabbccdd;
	dump();

	printf("pid old %ld new %ld\n", oldpid, getpid());

	return 0;
}
