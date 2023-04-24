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
#define MC_MAX_PHDRS 512
#define MC_MAX_THREADS 64
#define MC_NOTE_PADDING 4

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

Elf64_Ehdr ehdr;
Elf64_Phdr phdr[MC_MAX_PHDRS];
Elf64_Nhdr nhdr[MC_MAX_THREADS];
struct elf_prstatus prstatus[MC_MAX_THREADS];

static pthread_mutex_t mc_getregs_mutex;
static volatile uint32_t mc_thread_counter;
static volatile uint32_t mc_futex_thread_gregs;

static void mc_get_registers(int sig, siginfo_t *info, void *ctx) {
	ucontext_t *uc = (ucontext_t *)ctx;
	greg_t *gregs = uc->uc_mcontext.gregs;

	pthread_mutex_lock(&mc_getregs_mutex); // it's enough to use mutex only for getting mc_thread_counter
	printf("(%d) RIP = %llx\n", mc_thread_counter, gregs[REG_RIP]);
	struct user_regs_struct *uregs = (void *)prstatus[mc_thread_counter].pr_reg;
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

	prstatus[mc_thread_counter++].pr_pid = syscall(SYS_gettid);
	pthread_mutex_unlock(&mc_getregs_mutex);
}

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
		return (pid_t *)((char *)thr + header_size + 2 * sizeof(void *));
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

static int isLittleEndian() {
	unsigned int x = 1;
	char *c = (char *)&x;
	return (int)*c;
}

static unsigned long align_up(unsigned long v, unsigned p) {
	return (v + p - 1) & ~(p - 1);
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
	struct sigaction get_regs_hnd = { 
		.sa_sigaction = mc_get_registers,
		.sa_flags = SA_SIGINFO
	};

	struct sigaction oldhnd;
	struct sigaction old_get_regs_hnd;

	if (sigaction(MC_THREAD_SIG, &newhnd, &oldhnd)) {
		perror("sigaction");
		return 1;
	}

	if (sigaction(MC_GET_REGISTERS, &get_regs_hnd, &old_get_regs_hnd)) {
		perror("sigaction get registers handler");
		return 1;
	}

	int thread_count = 0;
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
		thread_count++;
	}
	closedir(tasksdir);

	uint32_t current_count;
	while ((current_count = mc_futex_checkpoint) != 0) {
		syscall(SYS_futex, &mc_futex_checkpoint, FUTEX_WAIT, current_count);
	}

	pid_t pid = syscall(SYS_getpid);
	int phnum = 0;

	// Creating Elf header
	memcpy(ehdr.e_ident, ELFMAG, SELFMAG); // Set magic number
	ehdr.e_ident[EI_CLASS] = ELFCLASS64;
	ehdr.e_ident[EI_DATA] = isLittleEndian() ? ELFDATA2LSB : ELFDATA2MSB;
	ehdr.e_ident[EI_VERSION] = EV_CURRENT;
	ehdr.e_ident[EI_OSABI] = ELFOSABI_SYSV; // Maybe i should determine real ABI ?
	ehdr.e_type = ET_CORE;
	ehdr.e_machine = EM_X86_64; // ????
	ehdr.e_version = EV_CURRENT; // always EV_CURRENT
	ehdr.e_entry = 0; // That's not an executable ELF
	ehdr.e_phoff = sizeof(Elf64_Ehdr); // Program header offset
	ehdr.e_shoff = 0; // That core file will not have sections headers
	ehdr.e_flags = 0; // ???
	ehdr.e_ehsize = sizeof(Elf64_Ehdr);
	ehdr.e_phentsize = sizeof(Elf64_Phdr);
	ehdr.e_phnum = 0; // number of program headers (UPDATE)
	ehdr.e_shentsize = 0; // does not use sections
	ehdr.e_shnum = 0; // does not use sections
	ehdr.e_shstrndx = 0; // does not use sections

	// Creating PT_NOTE program header
	phdr[phnum].p_type = PT_NOTE;
	phdr[phnum].p_flags = 0;
	phdr[phnum].p_offset = 0; // size of header + size of all phrds (UPDATE)
	phdr[phnum].p_vaddr = 0;
	phdr[phnum].p_paddr = 0;
	phdr[phnum].p_memsz = 0;
	phdr[phnum].p_filesz = 0; // to update
	phdr[phnum++].p_align = 0;

	// Open /proc/self/maps to read process memory
	FILE *proc_maps = fopen("/proc/self/maps", "r");
	if (proc_maps == NULL) {
		printf("Coudnot open maps file\n");
		return 0;
	} else {
		printf("File was open!!!\n");
	}

	// NT_FILE initializaiton
	nt_file.descsz = 0;
	nt_file.descsz += sizeof(nt_file.count) + sizeof(nt_file.page_size);
	nt_file.page_size =  0x1000;

	// Creating PT_LOAD and NT_FILE
	char buffer[256];
	while (fgets(buffer, sizeof(buffer), proc_maps)) {
		void *addr_start, *addr_end;
		char perms[8];
		long ofs;
		int name_start = 0;
		int name_end = 0;

		int res = sscanf(buffer, "%p-%p %7s %lx %*d:%*d %*lx %n%*[^\n]%n", &addr_start, 
			&addr_end, perms, &ofs, &name_start, &name_end);
		
		if (res < 4) {
			perror("sscanf");
			fclose(proc_maps);
			return 1;
		}

		// [vsyscall] is mapped to the same address in each process
		if (!strncmp(buffer + name_start, "[vsyscall]", sizeof("[vsyscall]") - 1)) {
			continue;
		}

		if (name_end > name_start && *(buffer + name_start) != '[') {
			// information for PT_NOTE
			int count = nt_file.count;
			nt_file.filemaps[count].start = (long int)addr_start;
			nt_file.filemaps[count].end = (long int)addr_end;
			nt_file.filemaps[count].fileofs = ofs / nt_file.page_size;
			memcpy(nt_file.filepath[count], buffer + name_start, name_end - name_start);
			nt_file.filepath[count][name_end - name_start] = '\0';
			nt_file.descsz += sizeof(struct filemap) + name_end - name_start + 1;
			nt_file.count++;
		}

		// fill phdr
		phdr[phnum].p_type = PT_LOAD;
		phdr[phnum].p_flags = 0;
		phdr[phnum].p_flags |= perms[0] == 'r' ? PF_R : 0;
		phdr[phnum].p_flags |= perms[1] == 'w' ? PF_W : 0;
		phdr[phnum].p_flags |= perms[2] == 'x' ? PF_X : 0;
		phdr[phnum].p_offset = 0; // need to update
		phdr[phnum].p_vaddr = (long unsigned int)addr_start;
		phdr[phnum].p_paddr = 0;
		phdr[phnum].p_memsz = addr_end - addr_start;
		phdr[phnum].p_filesz = phdr[phnum].p_flags != 0 ? addr_end - addr_start : 0;
		phdr[phnum++].p_align = 0x1000; // ????
	}

	fclose(proc_maps);

	// Updating headers
	ehdr.e_phnum = phnum;
	// mannual count of pt_note size
	phdr[0].p_filesz = sizeof(Elf64_Nhdr) + align_up(5, 4) + align_up(nt_file.descsz, 4) + (mc_thread_counter + 1) * (sizeof(Elf64_Nhdr) + sizeof(struct elf_prstatus) + align_up(5, 4));
	// update headers phdrs informaiton
	phdr[0].p_offset = sizeof(Elf64_Ehdr) + ehdr.e_phnum * ehdr.e_phentsize; // PT_NOTE
	for (int i = 1; i < phnum; i++) { // PT_LOAD
		// it's aligned at original core file
		phdr[i].p_offset = align_up(phdr[i - 1].p_offset + phdr[i - 1].p_filesz, phdr[i].p_align);
	}

	// Create core file
	char filename[32];
	sprintf(filename, "minicriu-core.%d", pid);
	FILE *coreFile = fopen(filename, "w+");
	int bytesWritten = 0;

	// write elf header
	fwrite(&ehdr, sizeof(Elf64_Ehdr), 1, coreFile);
	bytesWritten += sizeof(Elf64_Ehdr);

	// Write phdrs
	fwrite(phdr, sizeof(Elf64_Phdr), phnum, coreFile);
	bytesWritten += sizeof(Elf64_Phdr) * phnum;

	
	// save main thread registers
	pthread_t self = pthread_self();
	pthread_kill(self, MC_GET_REGISTERS);

	char owner[] = "CORE"; // "core" gives more information while reading using readelf and eu-readelf tools
	char paddingData[MC_NOTE_PADDING];
	memset(paddingData, 0x00, MC_NOTE_PADDING);
	int thread_counter = mc_thread_counter;

	// write pt_note PRSTATUS data for every program thread 
	int notes_size = 0;
	for (int i = 0; i < thread_counter; i++) {
		Elf64_Nhdr *cur_nhdr = &nhdr[i];

		cur_nhdr->n_namesz = sizeof(owner);
		cur_nhdr->n_descsz = sizeof(struct elf_prstatus);
		cur_nhdr->n_type = NT_PRSTATUS;

		// write nhdr
		fwrite(cur_nhdr, sizeof(Elf64_Nhdr), 1, coreFile);
		bytesWritten += sizeof(Elf64_Nhdr);
		notes_size += sizeof(Elf64_Nhdr);

		// write name
		fwrite(owner, sizeof(owner), 1, coreFile);
		bytesWritten += sizeof(owner);
		notes_size += sizeof(owner);


		// add name padding
		if (cur_nhdr->n_namesz % MC_NOTE_PADDING != 0) {
			int padding = align_up(bytesWritten, MC_NOTE_PADDING) - bytesWritten;
			fwrite(paddingData, padding, 1, coreFile);
			bytesWritten += padding;
			notes_size += padding;
		}

		// write desc
		fwrite(&prstatus[i], sizeof(struct elf_prstatus), 1, coreFile);
		bytesWritten += sizeof(struct elf_prstatus);
		notes_size += sizeof(struct elf_prstatus);


		// add desc padding
		if (cur_nhdr->n_descsz % MC_NOTE_PADDING != 0) {
			int padding = align_up(bytesWritten, MC_NOTE_PADDING) - bytesWritten;
			fwrite(paddingData, padding, 1, coreFile);
			bytesWritten += padding;
			notes_size += padding;
		}
	}

	// Creating NT_FILE
	Elf64_Nhdr *cur_nhdr = &nhdr[thread_counter];
	cur_nhdr->n_namesz = sizeof(owner);
	cur_nhdr->n_descsz = nt_file.descsz;
	cur_nhdr->n_type = NT_FILE;

	// writing nhdr
	fwrite(cur_nhdr, sizeof(Elf64_Nhdr), 1, coreFile);
	bytesWritten += sizeof(Elf64_Nhdr);
	notes_size += sizeof(Elf64_Nhdr);

	// name
	fwrite(owner, sizeof(owner), 1, coreFile);
	bytesWritten += sizeof(owner);
	notes_size += sizeof(owner);
	// + padding
	if (cur_nhdr->n_namesz % MC_NOTE_PADDING != 0) {
		int padding = align_up(bytesWritten, MC_NOTE_PADDING) - bytesWritten;
		fwrite(paddingData, padding, 1, coreFile);
		bytesWritten += padding;
		notes_size += padding;
	}

	// desc
	fwrite(&nt_file, sizeof(nt_file.count) + sizeof(nt_file.page_size), 1, coreFile);
	fwrite(&nt_file.filemaps, sizeof(struct filemap), nt_file.count, coreFile);
	for (int i = 0; i < nt_file.count; i++) {
		fputs(nt_file.filepath[i], coreFile);
		fputc('\0', coreFile);
	}
	// + padding
	if (cur_nhdr->n_descsz % MC_NOTE_PADDING != 0) {
		int padding = align_up(bytesWritten, MC_NOTE_PADDING) - bytesWritten;
		fwrite(paddingData, padding, 1, coreFile);
		bytesWritten += padding;
		notes_size += padding;
	}

	// write PT_LOAD
	for (int i = 1; i < phnum; i++) {
		if (phdr[i].p_filesz != 0) {
			int padding = phdr[i].p_offset - (phdr[i - 1].p_offset + phdr[i - 1].p_filesz);
			if (padding > 0) {
				// add padding for alignment
				fwrite(paddingData, sizeof(paddingData), padding / sizeof(paddingData), coreFile);
				fwrite(paddingData, padding % sizeof(paddingData), 1, coreFile);
			}
			fwrite((void *)phdr[i].p_vaddr, phdr[i].p_filesz, 1, coreFile);
		}
	}

	fclose(coreFile);
	printf("Writing has ended!\n");
	
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
	acts[MC_GET_REGISTERS] = old_get_regs_hnd;
	printf("Making an abort\n");;
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

	struct savedctx ctx;
	SAVE_CTX(ctx);
	int tid = syscall(SYS_gettid);
	printf("(%d) fsbase %lx gsbase %lx\n", tid, ctx.fsbase, ctx.gsbase);

	pthread_t self = pthread_self();
	pid_t *tidptr = gettid_ptr(self);
	pthread_kill(self, 0);

	char buf[256];
	int len = snprintf(buf, sizeof(buf), "%s: self %p tidptr %p *tidptr %d\n",
		__func__, self, tidptr, *tidptr);
	write(2, buf, len);

	assert(*gettid_ptr(pthread_self()) == tid);

	// save registers
	pthread_kill(self, MC_GET_REGISTERS);
	__atomic_fetch_add(&mc_futex_checkpoint, 1, __ATOMIC_SEQ_CST);
	syscall(SYS_futex, &mc_futex_checkpoint, FUTEX_WAKE, 1);

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


