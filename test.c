/*
 * Copyright 2017-2022 Azul Systems, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
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
	thr_local = -gettid();

	pid_t old = gettid();
	printf("tid %d\n", old);

	while (1) {
		fprintf(stderr, "THREAD old tid %d new tid %d local %d\n", old, gettid(), shared_fn());
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
	struct stat st;
	if (fstat(fd, &st)) {
        perror("fstat");
    } else if (st.st_size != 4096) {
        fprintf(stderr, "Unexpected size; 'file' should be truncated to 4096 bytes\n");
        return 1;
    }

	void *addr = mmap(NULL, 4096 * 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (addr == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	*(int*)addr = 1;

	pid_t oldpid = getpid();
	printf("pid %d\n", oldpid);

	thr_local = -gettid();

	pthread_t other;
	pthread_create(&other, NULL, thread, NULL);

	sleep(100);

	if (argc == 1) {
		if (minicriu_dump()) {
		    fprintf(stderr, "TEST FAILED\n");
		    exit(1);
		}
	}

	printf("done\n");

	/*sleep(3);*/
	/**((int*)0) = 1;*/
	shared_fn();

	printf("done2\n");

	while (1) {
		printf("MAIN pid old %d new %d tid %d local %d\n", oldpid, getpid(), gettid(), shared_fn());
		do_kill(other, "kill other");
		sleep(1);
	}

	pthread_join(other, NULL);

	return 0;
}
