#define _GNU_SOURCE

#include <stdio.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <sys/syscall.h>      /* Definition of SYS_* constants */
#include <linux/futex.h>

#include "minicriu-client.h"

#define MC_THREAD_SIG SIGUSR1

static volatile uint32_t mc_futex_checkpoint;
static volatile uint32_t mc_futex_restore;

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

int minicriu_dump(void) {
	struct sigaction old, new;

	new.sa_handler = SIG_DFL;
	if (sigaction(SIGABRT, &new, &old)) {
		perror("sigaction");
		return 1;
	}

	struct savedctx ctx;
	SAVE_CTX(ctx);

	DIR* tasksdir = opendir("/proc/self/task/");
	struct dirent *taskdent;
	while ((taskdent = readdir(tasksdir))) {
		if (taskdent->d_name[0] == '.') {
			continue;
		}
		int tid = atoi(taskdent->d_name);
		if (tid == syscall(SYS_gettid)) {
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

	raise(SIGABRT);

	mc_futex_restore = 1;
	syscall(SYS_futex, &mc_futex_restore, FUTEX_WAKE, INT_MAX);

	RESTORE_CTX(ctx);

	if (sigaction(SIGABRT, &old, NULL)) {
		perror("sigaction 2");
	}

	return 0;
}

static void mc_sighnd(int sig) {

	__atomic_fetch_add(&mc_futex_checkpoint, 1, __ATOMIC_SEQ_CST);
	syscall(SYS_futex, &mc_futex_checkpoint, FUTEX_WAKE, 1);

	struct savedctx ctx;
	SAVE_CTX(ctx);

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
			  "d"(0)
			: "memory");
	}

	RESTORE_CTX(ctx);

	syscall(SYS_write, 1, "restored\n", 9);
}

int minicriu_register_new_thread(void) {
	struct sigaction new;
	new.sa_handler = mc_sighnd;
	if (sigaction(MC_THREAD_SIG, &new, NULL)) {
		perror("sigaction");
		return 1;
	}
}


