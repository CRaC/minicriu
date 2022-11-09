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

#define _GNU_SOURCE

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <pthread.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/syscall.h>      /* Definition of SYS_* constants */
#include <sys/prctl.h>
#include <sys/mman.h>
#include <linux/futex.h>

#include "minicriu-client.h"

#define MC_THREAD_SIG SIGSYS

static volatile uint32_t mc_futex_checkpoint;
static volatile uint32_t mc_futex_restore;

static void mc_sighnd(int sig);

struct savedctx {
	unsigned long fsbase, gsbase;
};

#define SAVE_CTX(ctx) do { \
	asm volatile("rdfsbase %0" : "=r" (ctx.fsbase) : : "memory"); \
	asm volatile("rdgsbase %0" : "=r" (ctx.gsbase) : : "memory"); \
} while(0)

#define RESTORE_CTX(ctx) do { \
	asm volatile("wrfsbase %0" : : "r" (ctx.fsbase) : "memory"); \
	asm volatile("wrgsbase %0" : : "r" (ctx.gsbase) : "memory"); \
} while(0)

static pid_t* gettid_ptr(pthread_t thr) {
	const size_t header_size =
#if defined(__x86_64__)
		0x2c0;
#else
#error "Unimplemented arch"
#endif
	return (pid_t*) ((char*)thr + header_size + 2 * sizeof(void*));
}

static int readfile(const char *file, char *buf, size_t len) {
	int fd = open(file, O_RDONLY);
	if (fd < 0) {
		return -errno;
	}
	int bytes = read(fd, buf, len);
	if (bytes < 0) {
		bytes = -errno;
	}
	close(fd);
	return bytes;
}

static int writefile(const char *file, const char *buf, size_t len) {
	int fd = open(file, O_RDWR);
	if (fd < 0) {
		return -errno;
	}
	int bytes = write(fd, buf, len);
	if (bytes < 0) {
		bytes = -errno;
	}
	close(fd);
	return bytes;
}

int minicriu_dump(void) {

	pid_t mytid = syscall(SYS_gettid);
	pid_t mypid = getpid();

	printf("minicriu thread %d\n", mytid);

	char auxv[1024];
	int auxvlen = readfile("/proc/self/auxv", auxv, sizeof(auxv));
	if (auxvlen < 0) {
		fprintf(stderr, "read auxv: %s\n", strerror(auxvlen));
	}

	char comm[1024];
	int commlen = readfile("/proc/self/comm", auxv, sizeof(auxv));
	if (commlen < 0) {
		fprintf(stderr, "read comm: %s\n", strerror(commlen));
	}

	struct savedctx ctx;
	SAVE_CTX(ctx);

	struct sigaction newhnd = { .sa_handler = mc_sighnd };
	struct sigaction oldhnd;

	if (sigaction(MC_THREAD_SIG, &newhnd, &oldhnd)) {
		perror("sigaction");
		return 1;
	}

	DIR* tasksdir = opendir("/proc/self/task/");
	struct dirent *taskdent;
	while ((taskdent = readdir(tasksdir))) {
		if (taskdent->d_name[0] == '.') {
			continue;
		}
		int tid = atoi(taskdent->d_name);
		printf("minicriu %d me %d\n", tid, mytid == tid);
		if (tid == mytid) {
			continue;
		}
		if (tid == mypid) {
			/* don't touch premodorial thread */
			continue;
		}
		int r = syscall(SYS_tkill, tid, MC_THREAD_SIG);
		__atomic_fetch_sub(&mc_futex_checkpoint, 1, __ATOMIC_SEQ_CST);
	}
	closedir(tasksdir);

	uint32_t current_count;
	while ((current_count = mc_futex_checkpoint) != 0) {
		syscall(SYS_futex, &mc_futex_checkpoint, FUTEX_WAIT, current_count);
	}

	struct sigaction acts[SIGRTMAX];
	struct sigaction new = { .sa_handler = SIG_DFL };
	for (int i = 1; i < SIGRTMAX; ++i) {
		if (sigaction(i, &new, &acts[i])) {
			char msg[256];
			snprintf(msg, sizeof(msg), "sigaction checkpoint %d: %m", i);
			fprintf(stderr, "%s\n", msg);
		}
	}

	acts[MC_THREAD_SIG] = oldhnd;

	pid_t pid = syscall(SYS_getpid);
	syscall(SYS_kill, mytid, SIGABRT, 1313, mytid);

	RESTORE_CTX(ctx);

	int newtid = syscall(SYS_gettid);
	*gettid_ptr(pthread_self()) = newtid;

	for (int i = 1; i < SIGRTMAX; ++i) {
		if (sigaction(i, &acts[i], NULL)) {
			char msg[256];
			snprintf(msg, sizeof(msg), "sigaction restore %d: %m", i);
			fprintf(stderr, "%s\n", msg);
		}
	}

	if ((0 < auxvlen) && (prctl(PR_SET_MM, PR_SET_MM_AUXV, auxv, auxvlen, 0) < 0)) {
		perror("prctl auxv");
	}

	writefile("/proc/self/comm", comm, commlen);

#if 0
	FILE *f = fopen("/proc/self/maps", "r");
	char line[4096];
	while (fgets(line, sizeof(line), f)) {
		if (!strstr(line, "proj/minicriu/minicriu")) {
			continue;
		}
		char *low, *high;
		if (sscanf(line, "%p-%p", &low, &high) != 2) {
			continue;
		}
		if (munmap(low, high - low)) {
			perror("munmap");
		}
	}

	int fd = open("./test", O_RDONLY);
	if (fd < 0) {
		perror("open ./test");
		return 0;
	}

	if (syscall(SYS_prctl, PR_SET_MM, PR_SET_MM_EXE_FILE, fd, 0, 0)) {
		perror("prctl EXE_FILE");
	}
#endif

#if 0
	char *stack = mmap(NULL, 1 * 4096,
			PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_GROWSDOWN | MAP_ANONYMOUS,
			-1, 0);
	if (stack == MAP_FAILED) {
		perror("mmap stack");
	}
	char *cmd = strcpy(stack, "./test");
	printf("cmd = %p\n", cmd);

	if (prctl(PR_SET_MM, PR_SET_MM_ARG_START, cmd, 0, 0)) {
		perror("PR_SET_MM_ARG_START");
	}
	printf("end = %p\n", cmd + strlen(cmd) + 1);
	if (prctl(PR_SET_MM, PR_SET_MM_ARG_END, cmd + strlen(cmd) + 1), 0, 0) {
		perror("PR_SET_MM_ARG_END");
	}
#endif

	mc_futex_restore = 1;
	syscall(SYS_futex, &mc_futex_restore, FUTEX_WAKE, INT_MAX);

	volatile int thread_loop = 0;
	while (thread_loop);

	return 0;
}


static void mc_sighnd(int sig) {

	__atomic_fetch_add(&mc_futex_checkpoint, 1, __ATOMIC_SEQ_CST);
	syscall(SYS_futex, &mc_futex_checkpoint, FUTEX_WAKE, 1);

	struct savedctx ctx;
	SAVE_CTX(ctx);

	int tid = syscall(SYS_gettid);

	pthread_t self = pthread_self();
	pid_t *tidptr = gettid_ptr(self);
	pthread_kill(self, 0);

	char buf[256];
	int len = snprintf(buf, sizeof(buf), "%s: self %p tidptr %p *tidptr %d\n",
			__func__, self, tidptr, *tidptr);
	write(2, buf, len);

	assert(*gettid_ptr(pthread_self()) == tid);

	while (!mc_futex_restore) {
		// syscall sets thread-local errno while thread-local
		// storage is not yet initialized.
		// syscall(SYS_futex, &mc_futex_restore, FUTEX_WAIT, 0);
		unsigned long ret;
		asm volatile (
			"syscall\n\t"
			: "=a"(ret)
			: "a"(SYS_futex),
			  "D"(&mc_futex_restore),
			  "S"(FUTEX_WAIT),
			  "d"(0),
			  "b"(tid)
			: "memory");
	}

	RESTORE_CTX(ctx);

	int newtid = syscall(SYS_gettid);
	*gettid_ptr(pthread_self()) = newtid;

	volatile int thread_loop = 0;
	while (thread_loop);
}

int minicriu_register_new_thread(void) {

	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, MC_THREAD_SIG);
	if (pthread_sigmask(SIG_UNBLOCK, &set, NULL)) {
		perror("sigprocmask UNBLOCK");
		return 1;
	}

	return 0;
}


