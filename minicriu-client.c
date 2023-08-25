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
#include <sys/procfs.h>
#include <pthread.h>
#include <elf.h>
#include <asm/prctl.h>

#include "minicriu-client.h"

#define MC_THREAD_SIG SIGSYS
#define MC_GET_REGISTERS SIGUSR1
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
Elf64_Nhdr nhdr[MC_MAX_THREADS];
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


static void mc_sighnd(int sig);
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

	struct  nt_note {
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

		int res = sscanf(buffer, "%p-%p %7s %lx %*d:%*d %*x %n%*[^\n]%n", &addr_start,
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
		phdr[phnum].p_filesz = phdr[phnum].p_flags != 0 ? addr_end - addr_start : 0;
		phdr[phnum++].p_align = 0x1000;
	}

	fclose(proc_maps);

	// Updating headers
	ehdr.e_phnum = phnum;
	int prstatus_sz = mc_thread_counter * (sizeof(Elf64_Nhdr) + sizeof(struct elf_prstatus) + align_up(MC_OWNER_SIZE, 4));
	int ntfile_sz = sizeof(Elf64_Nhdr) + align_up(nt_file.descsz, 4) + align_up(MC_OWNER_SIZE, 4);
	phdr[0].p_filesz = prstatus_sz + ntfile_sz;
	phdr[0].p_offset = sizeof(Elf64_Ehdr) + ehdr.e_phnum * ehdr.e_phentsize;
	for (int i = 1; i < phnum; i++) {
		phdr[i].p_offset = align_up(phdr[i - 1].p_offset + phdr[i - 1].p_filesz, phdr[i].p_align);
	}

	char filename[32];
	sprintf(filename, "minicriu-core.%d", pid);
	FILE *coreFile = fopen(filename, "w+");
	if (coreFile == NULL) {
		perror("Could not create file for minicriu dump. Failed to create checkpoint.");
		return 1;
	}
	int bytesWritten = 0;

	// Write elf header
	fwrite(&ehdr, sizeof(Elf64_Ehdr), 1, coreFile);
	bytesWritten += sizeof(Elf64_Ehdr);

	// Write phdrs
	fwrite(phdr, sizeof(Elf64_Phdr), phnum, coreFile);
	bytesWritten += sizeof(Elf64_Phdr) * phnum;

	char owner[] = "CORE"; // "CORE" gives more information while reading using readelf and eu-readelf tools
	char paddingData[0x1000];
	memset(paddingData, 0x0, 0x1000);
	int thread_counter = mc_thread_counter;

	// Write PRSTATUS data for every process thread
	int notes_size = 0;
	for (int i = 0; i < thread_counter; i++) {
		Elf64_Nhdr *cur_nhdr = &nhdr[i];

		cur_nhdr->n_namesz = sizeof(owner);
		cur_nhdr->n_descsz = sizeof(struct elf_prstatus);
		cur_nhdr->n_type = NT_PRSTATUS;

		fwrite(cur_nhdr, sizeof(Elf64_Nhdr), 1, coreFile);
		bytesWritten += sizeof(Elf64_Nhdr);
		notes_size += sizeof(Elf64_Nhdr);

		fwrite(owner, sizeof(owner), 1, coreFile);
		bytesWritten += sizeof(owner);
		notes_size += sizeof(owner);

		if (cur_nhdr->n_namesz % MC_NOTE_PADDING != 0) {
			int padding = align_up(bytesWritten, MC_NOTE_PADDING) - bytesWritten;
			fwrite(paddingData, padding, 1, coreFile);
			bytesWritten += padding;
			notes_size += padding;
		}

		fwrite(&prstatus[i], sizeof(struct elf_prstatus), 1, coreFile);
		bytesWritten += sizeof(struct elf_prstatus);
		notes_size += sizeof(struct elf_prstatus);

		if (cur_nhdr->n_descsz % MC_NOTE_PADDING != 0) {
			int padding = align_up(bytesWritten, MC_NOTE_PADDING) - bytesWritten;
			fwrite(paddingData, padding, 1, coreFile);
			bytesWritten += padding;
			notes_size += padding;
		}
	}

	// Write NT_FILE
	Elf64_Nhdr *cur_nhdr = &nhdr[thread_counter];
	cur_nhdr->n_namesz = sizeof(owner);
	cur_nhdr->n_descsz = nt_file.descsz;
	cur_nhdr->n_type = NT_FILE;

	fwrite(cur_nhdr, sizeof(Elf64_Nhdr), 1, coreFile);
	bytesWritten += sizeof(Elf64_Nhdr);
	notes_size += sizeof(Elf64_Nhdr);

	fwrite(owner, sizeof(owner), 1, coreFile);
	bytesWritten += sizeof(owner);
	notes_size += sizeof(owner);

	if (cur_nhdr->n_namesz % MC_NOTE_PADDING != 0) {
		int padding = align_up(bytesWritten, MC_NOTE_PADDING) - bytesWritten;
		fwrite(paddingData, padding, 1, coreFile);
		bytesWritten += padding;
		notes_size += padding;
	}

	fwrite(&nt_file, sizeof(nt_file.count) + sizeof(nt_file.page_size), 1, coreFile);
	fwrite(&nt_file.filemaps, sizeof(struct filemap), nt_file.count, coreFile);
	for (int i = 0; i < nt_file.count; i++) {
		fputs(nt_file.filepath[i], coreFile);
		fputc('\0', coreFile);
	}

	if (cur_nhdr->n_descsz % MC_NOTE_PADDING != 0) {
		int padding = align_up(bytesWritten, MC_NOTE_PADDING) - bytesWritten;
		fwrite(paddingData, padding, 1, coreFile);
		bytesWritten += padding;
		notes_size += padding;
	}

	// Write PT_LOAD
	for (int i = 1; i < phnum; i++) {
		if (phdr[i].p_filesz != 0) {
			int padding = phdr[i].p_offset - (phdr[i - 1].p_offset + phdr[i - 1].p_filesz);
			if (padding > 0) {
				fwrite(paddingData, sizeof(paddingData), padding / sizeof(paddingData), coreFile);
				fwrite(paddingData, padding % sizeof(paddingData), 1, coreFile);
			}

			int written = fwrite((void *)phdr[i].p_vaddr, 1, phdr[i].p_filesz, coreFile);

			if (written != phdr[i].p_filesz) {
			    // This happens when the mapping is larger than the mapped file (rounded up to page size)
			    // - errno is EFAULT. Accessing that memory directly would result in SIGBUS.
				if (errno != EFAULT) {
				    perror("Failed write map content");
				    return 1;
				}

				// We fill the unwritten data with zeros
				int leftData = phdr[i].p_filesz - written;
				do {
				    int n = leftData < sizeof(paddingData) ? leftData : sizeof(paddingData);

                    int writtenZeroes = fwrite(paddingData, 1, n, coreFile);
                    if (writtenZeroes == 0) {
                        perror("Failed replace map content with zeroes. Failed to create checkpoint.");
                        fclose(coreFile);
                        return 1;
                    }
                    leftData -= writtenZeroes;
				} while (leftData > 0);

				leftData = leftData % sizeof(paddingData);
				if (leftData) {
					if (fwrite(paddingData, leftData, 1, coreFile)) {
						perror("Failed replace map content with zeroes. Failed to create checkpoint.");
						fclose(coreFile);
						return 1;
					}
				}
			}
		}
	}

	fclose(coreFile);
	return 0;
}

static void mc_make_core(int sig, siginfo_t *info, void *ctx) {
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

int minicriu_dump(void) {

	pid_t mytid = syscall(SYS_gettid);
	pid_t mypid = getpid();

	debug_log("minicriu thread %d\n", mytid);

	char auxv[1024];
	int auxvlen = readfile("/proc/self/auxv", auxv, sizeof(auxv));
	if (auxvlen < 0) {
		fprintf(stderr, "read auxv: %s\n", strerror(auxvlen));
	}

	char comm[1024];
	int commlen = readfile("/proc/self/comm", comm, sizeof(comm));
	if (commlen < 0) {
		fprintf(stderr, "read comm: %s\n", strerror(commlen));
	}

	struct savedctx ctx;
	SAVE_CTX(ctx);

	struct sigaction newhnd1 = { .sa_handler = mc_sighnd };
	struct sigaction newhnd2 = {
		.sa_sigaction = mc_make_core,
		.sa_flags = SA_SIGINFO
	};

	struct sigaction oldhnd1;
	struct sigaction oldhnd2;

	if (sigaction(MC_THREAD_SIG, &newhnd1, &oldhnd1)) {
		perror("sigaction");
		return 1;
	}

	if (sigaction(MC_GET_REGISTERS, &newhnd2, &oldhnd2)) {
		perror("sigaction");
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
		if (tid == mypid) {
			/* don't touch premodorial thread */
			continue;
		}
		int r = syscall(SYS_tkill, tid, MC_THREAD_SIG);
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

    // TODO: save signal handlers

	pid_t pid = syscall(SYS_getpid);

	// Save registers
	pthread_mutex_lock(&mc_getregs_mutex);
	int extra_arg = mc_gregs_counter++;
	pthread_mutex_unlock(&mc_getregs_mutex);
	int r = syscall(SYS_tkill, syscall(SYS_gettid), MC_GET_REGISTERS, extra_arg);

	RESTORE_CTX(ctx);

	int newtid = syscall(SYS_gettid);
	*gettid_ptr(pthread_self()) = newtid;

	if (sigaction(MC_THREAD_SIG, &oldhnd1, NULL)) {
		perror("sigaction");
		return 1;
	}

	if (sigaction(MC_GET_REGISTERS, &oldhnd2, NULL)) {
		perror("sigaction");
		return 1;
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


static void mc_sighnd(int sig) {

	__atomic_fetch_add(&mc_futex_checkpoint, 1, __ATOMIC_SEQ_CST);
	syscall(SYS_futex, &mc_futex_checkpoint, FUTEX_WAKE, 1);

	struct savedctx ctx;
	SAVE_CTX(ctx);
	int tid = syscall(SYS_gettid);
	debug_log("(%d) fsbase %lx gsbase %lx\n", tid, ctx.fsbase, ctx.gsbase);

	pthread_t self = pthread_self();
	pid_t *tidptr = gettid_ptr(self);
	pthread_kill(self, 0);

	debug_log("%s: self %ld tidptr %p *tidptr %d\n",
		__func__, self, tidptr, *tidptr);

	assert(*gettid_ptr(pthread_self()) == tid);

	// Make sure that barrier was initialized
	uint32_t current_count;
	while ((current_count = mc_barrier_initialization) == 0) {
		syscall(SYS_futex, &mc_barrier_initialization, FUTEX_WAIT, current_count);
	}

	// Save registers
	pthread_mutex_lock(&mc_getregs_mutex);
	int extra_arg = mc_gregs_counter++;
	pthread_mutex_unlock(&mc_getregs_mutex);
	int r = syscall(SYS_tkill, syscall(SYS_gettid), MC_GET_REGISTERS, extra_arg);


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
