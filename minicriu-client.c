#define _GNU_SOURCE

#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/syscall.h>      /* Definition of SYS_* constants */
#include <sys/prctl.h>
#include <sys/mman.h>
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

static void writefile(const char *file, const char *content, size_t len) {
	int fd = open(file, O_RDWR);
	if (fd < 0) {
		perror(file);
		return;
	}
	write(fd, content, len);
	close(fd);
}

int minicriu_dump(void) {
	struct sigaction old, new;
	int fd;

	pid_t mytid = syscall(SYS_gettid);

	new.sa_handler = SIG_DFL;
	if (sigaction(SIGABRT, &new, &old)) {
		perror("sigaction");
		return 1;
	}

	char auxv[1024];
	int auxvlen = 0;
	fd = open("/proc/self/auxv", O_RDONLY);
	if (fd < 0) {
		perror("open auxv");
	} else {
		if ((auxvlen = read(fd, auxv, sizeof(auxv))) < 0) {
			perror("read auxv");
		}
		close(fd);
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
		if (tid == mytid) {
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

#if 1
	pid_t pid = syscall(SYS_getpid);
	syscall(SYS_kill, pid, SIGABRT);

	mc_futex_restore = 1;
	syscall(SYS_futex, &mc_futex_restore, FUTEX_WAKE, INT_MAX);
#endif

	RESTORE_CTX(ctx);

	if (sigaction(SIGABRT, &old, NULL)) {
		perror("sigaction 2");
	}

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

	if ((0 < auxvlen) && (prctl(PR_SET_MM, PR_SET_MM_AUXV, auxv, auxvlen, 0) < 0)) {
		perror("prctl auxv");
	}

	writefile("/proc/self/auxv", auxv, auxvlen);

	/*while(1);*/
#if 1
	fd = open("./test", O_RDONLY);
	if (fd < 0) {
		perror("open ./test");
		return 0;
	}

	if (syscall(SYS_prctl, PR_SET_MM, PR_SET_MM_EXE_FILE, fd, 0, 0)) {
		perror("prctl EXE_FILE");
	}

	writefile("/proc/self/comm", "./test", 6);

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


