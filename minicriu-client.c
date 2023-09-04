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

#include <asm/prctl.h>
#include <assert.h>
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/futex.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/procfs.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h> /* Definition of SYS_* constants */
#include <unistd.h>

#include "minicriu-client.h"

// Signal sent to all threads but the checkpointing one
#define MC_CHECKPOINT_THREAD SIGSYS
// Registers are checkpointed on all threads
#define MC_PERSIST_REGISTERS SIGUSR1
#define MC_MAX_MAPS 512
#define MC_MAX_PHDRS 512
#define MC_MAX_THREADS 64
#define MC_OWNER_SIZE 5
#define MC_NOTE_PADDING 4

// Enable or disable debug logging
#define DEBUG 0

#if DEBUG
	#define debug_log(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
	#define debug_log
#endif

Elf64_Ehdr ehdr;
Elf64_Phdr phdr[MC_MAX_PHDRS];
struct elf_prstatus prstatus[MC_MAX_THREADS];

static pthread_mutex_t mc_getregs_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_barrier_t mc_thread_barrier;
static volatile int mc_gregs_counter;
static volatile int mc_thread_counter;

static volatile uint32_t mc_futex_checkpoint;
static volatile uint32_t mc_futex_restore;
static volatile uint32_t mc_restored_threads;
int mc_mapscnt;
static volatile uint32_t mc_barrier_initialization;

static void mc_checkpoint_thread(int sig);
static int mc_getmap();
static int mc_cleanup();

struct savedctx {
	unsigned long fsbase, gsbase;
};

struct mc_map {
	void *start;
	void *end;
} maps[MC_MAX_MAPS];

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

static unsigned long align_up(unsigned long v, unsigned p) {
	return (v + p - 1) & ~(p - 1);
}

typedef struct {
	FILE *file;
	size_t bytes_written;
} core_writer;

static int core_write_padding(core_writer *w, size_t bytes) {
	char paddingData[0x1000];
	memset(paddingData, 0, sizeof(paddingData));
	while (bytes > 0) {
		size_t max = bytes > sizeof(paddingData) ? sizeof(paddingData) : bytes;
		int written = fwrite(paddingData, 1, max, w->file);
		if (written == 0) {
			fprintf(stderr, "Cannot write padding: %m\n");
			return 1;
		}
		w->bytes_written += written;
		bytes -= written;
	}
	return 0;
}

static int core_write(core_writer *w, const void *data, size_t bytes) {
	size_t written = fwrite(data, 1, bytes, w->file);
	if (written != bytes) {
		fprintf(stderr, "Written too few bytes (%ld/%ld): %m", written, bytes);
		// FIXME
		exit(1);
	}
	w->bytes_written += bytes;
	return 0;
}

static int core_write_note_prologue(core_writer *w, Elf64_Word type, size_t bytes) {
	char owner[] = "CORE"; // "CORE" gives more information while reading using readelf and eu-readelf tools

	Elf64_Nhdr nhdr;
	nhdr.n_type = type;
	nhdr.n_namesz = sizeof(owner);
	nhdr.n_descsz = bytes;
	core_write(w, &nhdr, sizeof(Elf64_Nhdr));
	core_write(w, owner, sizeof(owner));

	if (nhdr.n_namesz % MC_NOTE_PADDING != 0) {
		int padding = align_up(w->bytes_written, MC_NOTE_PADDING) - w->bytes_written;
		core_write_padding(w, padding);
	}
}

static int core_write_note_epilogue(core_writer *w, size_t bytes) {
	if (bytes % MC_NOTE_PADDING != 0) {
		int padding = align_up(w->bytes_written, MC_NOTE_PADDING) - w->bytes_written;
		core_write_padding(w, padding);
	}
}

static int core_write_note(core_writer *w, Elf64_Word type, const void *data, size_t bytes) {
	core_write_note_prologue(w, type, bytes);
	core_write(w, data, bytes);
	core_write_note_epilogue(w, bytes);
	return 0;
}

static int mc_save_core_file() {

	pid_t pid = syscall(SYS_getpid);
	int phnum = 0;

	// Create Elf header
	memset(&ehdr, 0, sizeof(ehdr));
	memcpy(ehdr.e_ident, ELFMAG, SELFMAG);
	ehdr.e_ident[EI_CLASS] = ELFCLASS64;
	#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
	#else
	ehdr.e_ident[EI_DATA] = ELFDATA2MSB;
	#endif
	ehdr.e_ident[EI_VERSION] = EV_CURRENT;
	ehdr.e_ident[EI_OSABI] = ELFOSABI_SYSV;
	ehdr.e_type = ET_CORE;
	ehdr.e_machine = EM_X86_64;
	ehdr.e_version = EV_CURRENT;
	ehdr.e_phoff = sizeof(Elf64_Ehdr);
	ehdr.e_ehsize = sizeof(Elf64_Ehdr);
	ehdr.e_phentsize = sizeof(Elf64_Phdr);

	// Create PT_NOTE phdr
	phdr[phnum].p_type = PT_NOTE;
	phdr[phnum].p_flags = 0;
	phdr[phnum].p_offset = 0;
	phdr[phnum].p_vaddr = 0;
	phdr[phnum].p_paddr = 0;
	phdr[phnum].p_memsz = 0;
	phdr[phnum].p_filesz = 0;
	phdr[phnum++].p_align = 0;

	FILE *proc_maps = fopen("/proc/self/maps", "r");
	if (proc_maps == NULL) {
		perror("Could not open maps file. Failed to create checkpoint.");
		return 1;
	}

	struct nt_note {
		long count;
		long page_size;
		long descsz;
		struct filemap
		{
			long start;
			long end;
			long fileofs;
		} filemaps[MC_MAX_PHDRS];
		char filepath[MC_MAX_PHDRS][512];
	} nt_file;

	// Initialize NT_FILE
	nt_file.descsz = 0;
	nt_file.descsz += sizeof(nt_file.count) + sizeof(nt_file.page_size);
	nt_file.page_size = 0x1000;

	// Create PT_LOAD and NT_FILE phdrs
	char buffer[256];
	while (fgets(buffer, sizeof(buffer), proc_maps)) {
		void *addr_start, *addr_end;
		char perms[8];
		long ofs;
		int name_start = 0;
		int name_end = 0;

		int res = sscanf(buffer, "%p-%p %7s %lx %*x:%*x %*x %n%*[^\n]%n", &addr_start,
			&addr_end, perms, &ofs, &name_start, &name_end);

		if (res < 4) {
			perror("sscanf. Failed to create checkpoint.");
			fclose(proc_maps);
			return 1;
		}

		// [vsyscall] is mapped to the same address in each process
		if (!strncmp(buffer + name_start, "[vsyscall]", sizeof("[vsyscall]") - 1)) {
			continue;
		}

		// Save mapped files
		if (name_end > name_start && *(buffer + name_start) != '[') {
			int count = nt_file.count;
			nt_file.filemaps[count].start = (long int)addr_start;
			nt_file.filemaps[count].end = (long int)addr_end;
			nt_file.filemaps[count].fileofs = ofs / nt_file.page_size;
			memcpy(nt_file.filepath[count], buffer + name_start, name_end - name_start);
			nt_file.filepath[count][name_end - name_start] = '\0';
			nt_file.descsz += sizeof(struct filemap) + name_end - name_start + 1;
			nt_file.count++;
		}

		phdr[phnum].p_type = PT_LOAD;
		phdr[phnum].p_flags = 0;
		phdr[phnum].p_flags |= perms[0] == 'r' ? PF_R : 0;
		phdr[phnum].p_flags |= perms[1] == 'w' ? PF_W : 0;
		phdr[phnum].p_flags |= perms[2] == 'x' ? PF_X : 0;
		phdr[phnum].p_offset = 0;
		phdr[phnum].p_vaddr = (long unsigned int)addr_start;
		phdr[phnum].p_paddr = 0;
		phdr[phnum].p_memsz = addr_end - addr_start;
		// TODO: We should check if the mapped memory equals the file contents
		// and in that case make filesz 0.
		// Even if the mapping is non-readable we should check if it's all-zeroes
		// and exclude contents only if that's so: application might have temporarily
		// non-accessible parts of memory whose protection will eventually change.
		phdr[phnum].p_filesz = phdr[phnum].p_flags != 0 ? addr_end - addr_start : 0;
		phdr[phnum++].p_align = 0x1000;
	}

	fclose(proc_maps);

	char auxv[1024];
	int auxvlen = readfile("/proc/self/auxv", auxv, sizeof(auxv));
	if (auxvlen < 0) {
		fprintf(stderr, "read auxv: %s\n", strerror(auxvlen));
	}

	// Updating headers
	ehdr.e_phnum = phnum;
	int auxv_sz = sizeof(Elf64_Nhdr) + align_up(MC_OWNER_SIZE, MC_NOTE_PADDING) + align_up(auxvlen, MC_NOTE_PADDING);
	int prstatus_sz = mc_thread_counter * (sizeof(Elf64_Nhdr) + sizeof(struct elf_prstatus) + align_up(MC_OWNER_SIZE, MC_NOTE_PADDING));
	int ntfile_sz = sizeof(Elf64_Nhdr) + align_up(nt_file.descsz, MC_NOTE_PADDING) + align_up(MC_OWNER_SIZE, MC_NOTE_PADDING);
	phdr[0].p_filesz = auxv_sz + prstatus_sz + ntfile_sz;
	phdr[0].p_offset = sizeof(Elf64_Ehdr) + ehdr.e_phnum * ehdr.e_phentsize;
	for (int i = 1; i < phnum; i++) {
		phdr[i].p_offset = align_up(phdr[i - 1].p_offset + phdr[i - 1].p_filesz, phdr[i].p_align);
	}

	char filename[32];
	sprintf(filename, "minicriu-core.%d", pid);
	core_writer w = {
		.file = fopen(filename, "w+"),
		.bytes_written = 0,
	};
	if (w.file == NULL) {
		perror("Could not create file for minicriu dump. Failed to create checkpoint.");
		return 1;
	}

	// Write elf header
	core_write(&w, &ehdr, sizeof(Elf64_Ehdr));
	// Write phdrs
	core_write(&w, phdr, sizeof(Elf64_Phdr) * phnum);

	core_write_note(&w, NT_AUXV, &auxv, auxvlen);

	int thread_counter = mc_thread_counter;
	// Write PRSTATUS data for every process thread
	for (int i = 0; i < thread_counter; i++) {
		core_write_note(&w, NT_PRSTATUS, &prstatus[i], sizeof(struct elf_prstatus));
	}

	// Write NT_FILE
	core_write_note_prologue(&w, NT_FILE, nt_file.descsz);
	core_write(&w, &nt_file, sizeof(nt_file.count) + sizeof(nt_file.page_size));
	core_write(&w, &nt_file.filemaps, sizeof(struct filemap) * nt_file.count);
	for (int i = 0; i < nt_file.count; i++) {
		if (fputs(nt_file.filepath[i], w.file) == EOF) {
			perror("fputs");
		}
		if (fputc('\0', w.file) == EOF) {
			perror("putc");
		}
		w.bytes_written += strlen(nt_file.filepath[i]) + 1;
	}
	core_write_note_epilogue(&w, nt_file.descsz);

	// Write PT_LOAD
	for (int i = 1; i < phnum; i++) {
		if (phdr[i].p_filesz != 0) {
			int padding = phdr[i].p_offset - (phdr[i - 1].p_offset + phdr[i - 1].p_filesz);
			core_write_padding(&w, padding);

			int written = fwrite((void *)phdr[i].p_vaddr, 1, phdr[i].p_filesz, w.file);
			w.bytes_written += written;

			if (written != phdr[i].p_filesz) {
				// This happens when the mapping is larger than the mapped file (rounded up to page size)
				// - errno is EFAULT. Accessing that memory directly would result in SIGBUS.
				if (errno != EFAULT) {
					perror("Failed write map content");
					return 1;
				}

				// We fill the unwritten data with zeros
				core_write_padding(&w, phdr[i].p_filesz - written);
			}
		}
	}

	fclose(w.file);
	return 0;
}

static void mc_persist_registers(int sig, siginfo_t *info, void *ctx) {
	ucontext_t *uc = (ucontext_t *)ctx;
	greg_t *gregs = uc->uc_mcontext.gregs;
	int thread_id = gregs[REG_RDX]; // get extra argument

	struct user_regs_struct *uregs = (void *)prstatus[thread_id].pr_reg;
	uregs->r15 = gregs[REG_R15];
	uregs->r14 = gregs[REG_R14];
	uregs->r13 = gregs[REG_R13];
	uregs->r12 = gregs[REG_R12];
	uregs->rbp = gregs[REG_RBP];
	uregs->rbx = gregs[REG_RBX];
	uregs->r11 = gregs[REG_R11];
	uregs->r10 = gregs[REG_R10];
	uregs->r9 = gregs[REG_R9];
	uregs->r8 = gregs[REG_R8];
	uregs->rax = gregs[REG_RAX];
	uregs->rcx = gregs[REG_RCX];
	uregs->rdx = gregs[REG_RDX];
	uregs->rsi = gregs[REG_RSI];
	uregs->rdi = gregs[REG_RDI];
	uregs->rip = gregs[REG_RIP];
	uregs->eflags = gregs[REG_EFL];
	uregs->rsp = gregs[REG_RSP];
	syscall(SYS_arch_prctl, ARCH_GET_FS, &(uregs->fs_base));
	syscall(SYS_arch_prctl, ARCH_GET_GS, &(uregs->gs_base));

	prstatus[thread_id].pr_pid = syscall(SYS_gettid);

	// Wait until all threads save their registers
	pthread_barrier_wait(&mc_thread_barrier);
	if (thread_id == mc_thread_counter - 1) {
		mc_save_core_file();
	}

	// Wait for all data to be saved. Otherwise the stack data will probably be corrupted.
	pthread_barrier_wait(&mc_thread_barrier);
}

static inline bool mc_is_internal_signal(int signum) {
	// GLIBC uses signals 32 and 33 internally and manipulation causes EINVAL
	return signum == SIGKILL || signum == SIGSTOP || (signum > SIGSYS && signum < SIGRTMIN);
}

// It is not possible to change signal mask for another thread, so in the unlikely
// case that the thread blocks MC_CHECKPOINT_THREAD we must give up on checkpoint.
// In the past this was unblocked by minicriu_register_new_thread but there's no
// guarantee that the thread wouldn't block the signal at any later point: therefore
// we'll just make it a requirement from the application side.
static bool mc_check_signal_blocked(const char *taskid) {
	char buf[256];
	snprintf(buf, sizeof(buf), "/proc/self/task/%s", taskid);
	FILE *status = fopen(buf, "r");
	char line[256];
	while (fgets(line, sizeof(line), status)) {
		if (!strncmp(line, "SigBlk:", 7)) {
			unsigned long long bits = strtoull(line + 7, NULL, 16);
			if (bits & (1 << (MC_CHECKPOINT_THREAD - 1))) {
				fprintf(stderr, "Thread LWP %s is blocking signal %d, cannot perform checkpoint.\n", taskid, MC_CHECKPOINT_THREAD);
				fclose(status);
				return true;
			}
			break; // ignore rest
		}
	}
	fclose(status);
	return false;
}

int minicriu_dump(void) {

	pid_t mytid = syscall(SYS_gettid);
	pid_t mypid = getpid();

	debug_log("minicriu thread %d\n", mytid);

	char comm[1024];
	int commlen = readfile("/proc/self/comm", comm, sizeof(comm));
	if (commlen < 0) {
		fprintf(stderr, "read comm: %s\n", strerror(commlen));
	}

	struct savedctx ctx;
	SAVE_CTX(ctx);

	struct sigaction checkpoint_thread = {
		.sa_handler = mc_checkpoint_thread
	};
	struct sigaction persist_registers = {
		.sa_sigaction = mc_persist_registers,
		.sa_flags = SA_SIGINFO
	};

	struct sigaction sigactions[SIGRTMAX];
	for (int i = 1; i < SIGRTMAX; ++i) {
		if (mc_is_internal_signal(i)) continue;
		if (sigaction(i, NULL, &sigactions[i])) {
			perror("Cannot save signal handler");
			return 1;
		}
	}

	if (sigaction(MC_CHECKPOINT_THREAD, &checkpoint_thread, NULL)) {
		perror("sigaction");
		return 1;
	}

	if (sigaction(MC_PERSIST_REGISTERS, &persist_registers, NULL)) {
		perror("sigaction");
		return 1;
	}

	sigset_t sigset, oldset;
	if (sigemptyset(&sigset) || sigaddset(&sigset, MC_PERSIST_REGISTERS)) {
		perror("Cannot set signal mask");
		return 1;
	}
	if (pthread_sigmask(SIG_UNBLOCK, &sigset, &oldset)) {
		perror("Cannot unblock signals");
		return 1;
	}

	int thread_counter = 0;
	DIR *tasksdir = opendir("/proc/self/task/");
	struct dirent *taskdent;
	while ((taskdent = readdir(tasksdir))) {
		if (taskdent->d_name[0] == '.') {
			continue;
		}
		int tid = atoi(taskdent->d_name);
		debug_log("minicriu %d me %d\n", tid, mytid == tid);
		if (tid == mytid) {
			continue;
		}
		if (mc_check_signal_blocked(taskdent->d_name)) {
			closedir(tasksdir);
			return 1;
		}
		int r = syscall(SYS_tkill, tid, MC_CHECKPOINT_THREAD);
		__atomic_fetch_sub(&mc_futex_checkpoint, 1, __ATOMIC_SEQ_CST);
		thread_counter++;
	}
	closedir(tasksdir);

	mc_thread_counter = thread_counter + 1;
	debug_log("thread_counter = %d\n", thread_counter);

	uint32_t current_count;
	while ((current_count = mc_futex_checkpoint) != 0) {
		syscall(SYS_futex, &mc_futex_checkpoint, FUTEX_WAIT, current_count);
	}

	// Initialize barrier
	pthread_barrier_init(&mc_thread_barrier, NULL, mc_thread_counter);

	// Say to other threads that barrier is initialized
	__atomic_fetch_add(&mc_barrier_initialization, 1, __ATOMIC_SEQ_CST);
	syscall(SYS_futex, &mc_barrier_initialization, FUTEX_WAKE, thread_counter);
	if (mc_getmap())
		printf("failed to get maps from /proc/self/maps\n");

	pid_t pid = syscall(SYS_getpid);

	// Save registers
	pthread_mutex_lock(&mc_getregs_mutex);
	int extra_arg = mc_gregs_counter++;
	pthread_mutex_unlock(&mc_getregs_mutex);
	int r = syscall(SYS_tkill, syscall(SYS_gettid), MC_PERSIST_REGISTERS, extra_arg);

	RESTORE_CTX(ctx);

	int newtid = syscall(SYS_gettid);
	*gettid_ptr(pthread_self()) = newtid;

	for (int i = 1; i < SIGRTMAX; ++i) {
		if (mc_is_internal_signal(i)) continue;
		if (sigaction(i, &sigactions[i], NULL)) {
			perror("Cannot restore signal handler");
			return 1;
		}
	}

	if (pthread_sigmask(SIG_SETMASK, &oldset, NULL)) {
		perror("sigprocmask UNBLOCK");
		return 1;
	}

	writefile("/proc/self/comm", comm, commlen);

	mc_futex_restore = 1;
	syscall(SYS_futex, &mc_futex_restore, FUTEX_WAKE, INT_MAX);

	/*
	*	Here we synchronize the threads so that we do not
	*	munmap segments before the threads are restored
	*/

	while ((current_count = mc_restored_threads) != thread_counter) {
		syscall(SYS_futex, &mc_restored_threads, FUTEX_WAIT, current_count);
	}

	if (mc_cleanup())
		printf("failed to clean up maps\n");

	volatile int thread_loop = 0;
	while (thread_loop);

	return 0;
}


static void mc_checkpoint_thread(int sig) {

	__atomic_fetch_add(&mc_futex_checkpoint, 1, __ATOMIC_SEQ_CST);
	syscall(SYS_futex, &mc_futex_checkpoint, FUTEX_WAKE, 1);

	struct savedctx ctx;
	SAVE_CTX(ctx);
	int tid = syscall(SYS_gettid);
	debug_log("(%d) fsbase %lx gsbase %lx\n", tid, ctx.fsbase, ctx.gsbase);

	pthread_t self = pthread_self();
	pid_t *tidptr = gettid_ptr(self);
	pthread_kill(self, 0); // noop, just error checking

	debug_log("%s: self %ld tidptr %p *tidptr %d\n",
		__func__, self, tidptr, *tidptr);

	assert(*gettid_ptr(pthread_self()) == tid);

	// Make sure that barrier was initialized
	uint32_t current_count;
	while ((current_count = mc_barrier_initialization) == 0) {
		syscall(SYS_futex, &mc_barrier_initialization, FUTEX_WAIT, current_count);
	}

	// Note: if signal MC_CHECKPOINT_THREAD is blocked, we won't get here, and we don't
	// have chance to perform the checkpoint.
	sigset_t sigmask, old_sigmask;
	if (sigemptyset(&sigmask) || sigaddset(&sigmask, MC_PERSIST_REGISTERS)) {
		perror("Cannot construct thread sigmask");
	}
	if (pthread_sigmask(SIG_UNBLOCK, &sigmask, &old_sigmask)) {
		perror("Cannot get thread sigmask");
	}

	// Save registers
	pthread_mutex_lock(&mc_getregs_mutex);
	int extra_arg = mc_gregs_counter++;
	pthread_mutex_unlock(&mc_getregs_mutex);
	int r = syscall(SYS_tkill, syscall(SYS_gettid), MC_PERSIST_REGISTERS, extra_arg);


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

	__atomic_fetch_add(&mc_restored_threads, 1, __ATOMIC_SEQ_CST);
	syscall(SYS_futex, &mc_restored_threads, FUTEX_WAKE, 1);

	RESTORE_CTX(ctx);

	int newtid = syscall(SYS_gettid);
	*gettid_ptr(pthread_self()) = newtid;

	if (pthread_sigmask(SIG_SETMASK, &old_sigmask, NULL)) {
		perror("Cannot restore thread sigmask");
	}

	volatile int thread_loop = 0;
	while (thread_loop);
}

static int mc_getmap() {
	char line[512];
	mc_mapscnt = 0;
	FILE *proc_maps;
	proc_maps = fopen("/proc/self/maps", "r");

	if (!proc_maps) {
		perror("open maps");
		return 1;
	}

	while (fgets(line, sizeof(line), proc_maps)) {
		void *addr_start, *addr_end;
		char mapname[256];
		if (sscanf(line, "%p-%p %*s %*x %*d:%*d %*d %s",
					&addr_start, &addr_end, mapname) < 2) {
			fclose(proc_maps);
			perror("maps sscanf");
			return 1;
		}

		/*
		* there is no need to save [vsyscall] as it always
		* maps to the same address in the kernel space
		*/
		if (!strncmp(mapname, "[vsyscall]", 10)) continue;

		if (mc_mapscnt == MC_MAX_MAPS) {
			fclose(proc_maps);
			perror("maps limit");
			return 1;
		}

		maps[mc_mapscnt].start = addr_start;
		maps[mc_mapscnt++].end = addr_end;
	}
	fclose(proc_maps);

	return 0;
}

static int mc_cleanup() {
	char line[512];
	FILE *proc_maps = fopen("/proc/self/maps", "r");
	void *last_map_start;
	void *last_map_end;

	// find last segment mapped in user space
	while (fgets(line, sizeof(line), proc_maps)) {
		void *addr_start, *addr_end;
		char mapname[256];
		if (sscanf(line, "%p-%p %*s %*x %*d:%*d %*d %s",
					&addr_start, &addr_end, mapname) < 2) {
			fclose(proc_maps);
			perror("maps sscanf");
			return 1;
		}

		// location of [vsyscall] page is fixed in the kernel ABI
		if (!strncmp(mapname, "[vsyscall]", 10)) continue;
		last_map_start = addr_start;
		last_map_end = addr_end;
	}
	fclose(proc_maps);

	munmap(0, (size_t)maps[0].start);
	for (int i = 0; i < mc_mapscnt - 1; i++) {
		munmap(maps[i].end, maps[i + 1].start - maps[i].end);
	}

	if(maps[mc_mapscnt - 1].start < last_map_start) {
		munmap(maps[mc_mapscnt - 1].end, last_map_end - maps[mc_mapscnt - 1].end);
	}
	return 0;
}
