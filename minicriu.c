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
#include <alloca.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sched.h>
#include <sys/capability.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <sys/user.h>
#include <sys/prctl.h>
#include <sys/procfs.h>
#include <sys/stat.h>
#include <sys/ucontext.h>
#include <asm/prctl.h>		/* Definition of ARCH_* constants */
#include <sys/syscall.h>	  /* Definition of SYS_* constants */
#include <linux/sched.h>
#include <linux/elf.h>
#include <limits.h>


static struct elf_prpsinfo *prpsinfo;

#define MAX_THREADS 128
#define MAX_FILEMAPS 1024

static int thread_n;
static struct elf_prstatus *prstatus[MAX_THREADS];
static struct user_fpregs_struct *prfpreg[MAX_THREADS];
static char stack[MAX_THREADS][4 * 4096];

static pthread_barrier_t thread_barrier;

static size_t elfsz;
static void *rawelf;
static void *nt_file_start = NULL;

static void arch_prctl(int code, unsigned long addr) {
	if (syscall(SYS_arch_prctl, code, addr)) {
		perror("arch_prctl");
		abort();
	}
}

static void restore(int sig, siginfo_t *info, void *ctx) {
	ucontext_t *uc = (ucontext_t *) ctx;

	greg_t *gregs = uc->uc_mcontext.gregs;
	int thread_id = gregs[REG_RDX];
	struct user_regs_struct *uregs = (void*)prstatus[thread_id]->pr_reg;

	/*printf("restore %d fsbase %llx\n", thread_id, uregs->fs_base);*/

	gregs[REG_R15] = uregs->r15;
	gregs[REG_R14] = uregs->r14;
	gregs[REG_R13] = uregs->r13;
	gregs[REG_R12] = uregs->r12;
	gregs[REG_RBP] = uregs->rbp;
	gregs[REG_RBX] = uregs->rbx;
	gregs[REG_R11] = uregs->r11;
	gregs[REG_R10] = uregs->r10;
	gregs[REG_R9] = uregs->r9;
	gregs[REG_R8] = uregs->r8;
	gregs[REG_RAX] = uregs->rax;
	gregs[REG_RCX] = uregs->rcx;
	gregs[REG_RDX] = uregs->rdx;
	gregs[REG_RSI] = uregs->rsi;
	gregs[REG_RDI] = uregs->rdi;
	/*gregs[REG_] = uregs->orig_rax;*/
	gregs[REG_RIP] = uregs->rip;
	/*gregs[REG_] = uregs->cs;*/
	gregs[REG_EFL] = uregs->eflags;
	gregs[REG_RSP] = uregs->rsp;
	/*gregs[REG_] = uregs->ss;*/
	arch_prctl(ARCH_SET_FS, uregs->fs_base);
	arch_prctl(ARCH_SET_GS, uregs->gs_base);
	/*gregs[REG_] = uregs->fs_base;*/
	/*gregs[REG_] = uregs->gs_base;*/
	/*gregs[REG_] = uregs->ds;*/
	/*gregs[REG_] = uregs->es;*/
	/*gregs[REG_] = uregs->fs;*/
	/*gregs[REG_] = uregs->gs;*/

	/*
	* 	Here we synchronize the restoration of threads so their
	*	SIGSIS signal handler was not replaced by old one
	*	after the current thread recovery.
	*/

	pthread_barrier_wait(&thread_barrier);

#if 0
	if (thread_id == 0) {
		munmap(rawelf, elfsz);
	}
#endif

#if 0
	volatile int block = 1;
	while (block) {
	}
#endif
}

static unsigned long align_up(unsigned long v, unsigned p) {
	return (v + p - 1) & ~(p - 1);
}

static int clonefn(void *arg) {
	int r = syscall(SYS_tkill, syscall(SYS_gettid), SIGSYS,
			/* extra arg to _signal handler_ */ arg);
	fprintf(stderr, "should not reach here (thread %d)\n", (int)(long)arg);
	return 1;
}

static int is_conflict(void *p1, size_t s1, void *p2, size_t s2) {
	return (p1 >= p2 && p1 < p2 + s2) || (p2 >= p1 && p2 < p1 + s1);
}

static const Elf64_Phdr *find_notes(const Elf64_Ehdr *ehdr, const Elf64_Phdr *phdrs) {
	for (int i = 0; i < ehdr->e_phnum; ++i) {
		const Elf64_Phdr *ph = phdrs + i;
		if (ph->p_type == PT_NOTE) {
			return ph;
		}
	}
	return NULL;
}

typedef void note_visitor(off_t nameoff, off_t doff, const Elf64_Nhdr *nh);

static void visit_notes(const Elf64_Phdr *ph_notes, note_visitor *visitor) {
	off_t noff = ph_notes->p_offset;
	while (noff < ph_notes->p_offset + ph_notes->p_filesz) {
		Elf64_Nhdr *nh = rawelf + noff;
		off_t nameoff = noff + sizeof(*nh);
		off_t doff = nameoff + align_up(nh->n_namesz, 4);
		noff = doff + align_up(nh->n_descsz, 4);

		visitor(nameoff, doff, nh);
	}
}

static bool has_resource_cap() {
	cap_t capabilities = cap_get_proc();
	cap_flag_value_t has_resource_cap = CAP_CLEAR;
	if (CAP_IS_SUPPORTED(CAP_SYS_RESOURCE) && cap_get_flag(capabilities, CAP_SYS_RESOURCE, CAP_EFFECTIVE, &has_resource_cap)) {
		perror("Failed to check for CAP_SYS_RESOURCE capability");
	}
	cap_free(capabilities);
	return has_resource_cap == CAP_SET;
}

// what does this really do?
static void visit_note(off_t nameoff, off_t doff, const Elf64_Nhdr *nh) {
	void *target = NULL;
	if (!strcmp("CORE", rawelf + nameoff)) {
		switch (nh->n_type) {
		case NT_PRPSINFO: target = &prpsinfo; break;
		case NT_PRSTATUS: target = &prstatus[thread_n++]; break;
		case NT_PRFPREG:  target = &prfpreg[thread_n];  break;
		case NT_AUXV:
			if (has_resource_cap() && prctl(PR_SET_MM, PR_SET_MM_AUXV, rawelf + doff, nh->n_descsz, 0)) {
				perror("Cannot set auxiliary vector");
			}
		default: break;
		}
	}
	if (!strcmp("LINUX", rawelf + nameoff)) {
		switch (nh->n_type) {
		case NT_X86_XSTATE: break;
		default: break;
		}
	}
	if (target) {
		*(void**)target = rawelf + doff;
	}
}

static void find_filemap(off_t nameoff, off_t doff, const Elf64_Nhdr *nh) {
	if (!strcmp("CORE", rawelf + nameoff) && nh->n_type == NT_FILE) {
		nt_file_start = rawelf + doff;
	}
}

static const char *find_file(void *addr, size_t size, size_t *file_offset) {
	if (nt_file_start == NULL) {
		return NULL;
	}
	struct {
		long count;
		long page_size;
		struct filemap {
			long start;
			long end;
			long file_ofs;
		} map[0];
	} *fh = nt_file_start;

	char *name = (char*)(&fh->map[fh->count]);
	for (int i = 0; i < fh->count; ++i) {
		struct filemap *fm = &fh->map[i];

		if ((void *) fm->start == addr) {
			if (fm->end - fm->start != size) {
				fprintf(stderr, "Mismatched size for %p: mapping says 0x%lx, requesting 0x%lx\n",
					addr, fm->end - fm->start, size);
				exit(1);
			}
			*file_offset = fm->file_ofs * 0x1000; // page size
			return name;
		}

		name = name + strlen(name) + 1;
	}
	return NULL;
}

int main(int argc, char *argv[]) {
	const char* elfpath = argv[1];

	int core_fd = open(elfpath, O_RDONLY);
	if (core_fd < 0) {
		perror("open");
		return 1;
	}

	struct stat st;
	if (fstat(core_fd, &st)) {
		perror("stat");
		return 1;
	}

	elfsz = align_up(st.st_size, 4096);
	rawelf = mmap(NULL, elfsz, PROT_READ, MAP_PRIVATE, core_fd, 0);
	if (rawelf == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *) rawelf;
	if (strncmp(ehdr->e_ident, ELFMAG, SELFMAG)) {
		fprintf(stderr, "ELF header mismatch\n");
		return 1;
	}

	if (!ehdr->e_phoff ||
			!ehdr->e_phnum ||
			ehdr->e_phentsize != sizeof(Elf64_Phdr)) {
		printf("bad ehdr\n");
		return 1;
	}
	const Elf64_Phdr *phdrs = (const Elf64_Phdr *) (rawelf + ehdr->e_phoff);
	const Elf64_Phdr *ph_notes = find_notes(ehdr, phdrs);
	if (!ph_notes) {
		fprintf(stderr, "cannot find PT_NOTE\n");
		return 1;
	}

	visit_notes(ph_notes, find_filemap);

	for (int i = 0; i < ehdr->e_phnum; ++i) {
		const Elf64_Phdr *ph = phdrs + i;
		if (ph->p_type != PT_LOAD) {
			continue;
		}
		// Resolve potential conflict
		void *vaddr = (void *)ph->p_vaddr;
		size_t memsz = ph->p_memsz;
		size_t filesz = ph->p_filesz;
		size_t offset = ph->p_offset;
		if (is_conflict(rawelf, elfsz, vaddr, memsz)) {
			// We should unmap our rawelf, to not leave any chunks scattered around.
			if (munmap(rawelf, elfsz)) {
				perror("Cannot unmap coredump");
			}
		}
		if (munmap(vaddr, memsz)) {
			// munmap on are that is not mapped is noop
			perror("Failure unmapping minicriu mapping");
		}
		int fd = -1;
		size_t file_offset = 0;
		const char *name = find_file(vaddr, memsz, &file_offset);
		if (name != NULL) {
			fd = open(name, O_RDONLY);
			if (fd < 0) {
				fprintf(stderr, "Cannot open file %s: %m\n", name);
				file_offset = 0;
			}
		}
		void *addr = mmap(vaddr, memsz,
						  PROT_WRITE | PROT_READ,
						  MAP_PRIVATE | MAP_FIXED | (fd < 0 ? MAP_ANONYMOUS : 0),
						  fd, file_offset);
		if (addr != vaddr) {
			if (addr == MAP_FAILED) {
				fprintf(stderr, "WARN: mmap %s = %d 0x%lx phdr vaddr %p filesz 0x%lx off 0x%lx: %m\n",
						name, fd, file_offset, vaddr, filesz, offset);
			} else {
				fprintf(stderr, "WARN: mmap phdr target mismatch %p -> %p\n", vaddr, addr);
			}
		}
		close(fd);
		if (is_conflict(rawelf, elfsz, vaddr, memsz)) {
			void *old = rawelf;
			// Remap coredump somewhere else
			rawelf = mmap(NULL, elfsz, PROT_READ, MAP_PRIVATE, fd, 0);
			if (rawelf == MAP_FAILED) {
				perror("mmap coredump");
				return 1;
			}
			fprintf(stderr, "Relocated core dump %p -> %p", old, rawelf);
			ehdr = (const Elf64_Ehdr *) rawelf;
			phdrs = (const Elf64_Phdr *) (rawelf + ehdr->e_phoff);
			ph_notes = find_notes(ehdr, phdrs);
		}
	}

	visit_notes(ph_notes, visit_note);

	for (int i = 0; i < ehdr->e_phnum; ++i) {
		const Elf64_Phdr *ph = phdrs + i;
		if (ph->p_type != PT_LOAD) {
			continue;
		}
		size_t total = 0;
		while (total < ph->p_filesz) {
			size_t read = pread(core_fd, (void*)ph->p_vaddr, ph->p_filesz - total, ph->p_offset + total);
			if (read < 0) {
				perror("Failed to read in memory");
				return 1;
			} else if (read == 0) {
				fprintf(stderr, "Cannot read data for %llx (section %d/%d, offset %llx) (EOF): read %lu/%llu bytes\n",
					ph->p_vaddr, i, ehdr->e_phnum, ph->p_offset + total, total, ph->p_filesz);
				return 1;
			}
			total += read;
		}

		int mprot = 0;
		mprot |= ph->p_flags & PF_R ? PROT_READ : 0;
		mprot |= ph->p_flags & PF_W ? PROT_WRITE : 0;
		mprot |= ph->p_flags & PF_X ? PROT_EXEC : 0;
		mprotect((void*)ph->p_vaddr, ph->p_memsz, mprot);
	}

	struct sigaction sa = {
		.sa_sigaction = restore,
		.sa_flags = SA_SIGINFO
	};
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGSYS, &sa, NULL)) {
		perror("sigaction");
		return 1;
	}

	pthread_barrier_init(&thread_barrier, NULL, thread_n);

	for (int i = 1; i < thread_n; ++i) {
		const int flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SYSVSEM
			| CLONE_SIGHAND | CLONE_THREAD;
			/*| CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID*/
#if 0
		static_assert(sizeof(stack[i]) == 4 * 4096);
		struct clone_args args = {
			.flags = flags,
			.stack = (unsigned long)stack[i],
			.stack_size = sizeof(stack[i]),
		};
		memset(stack[i], 0xaa, sizeof(stack[i]));
		int ret = syscall(SYS_clone3, &args, sizeof(args), 0xaaaaaaaaaaaaa, 0xbbbbbbbbbbb);
		if (ret == -1) {
			perror("clone3");
		} else if (!ret) {
			volatile register long thread_id asm("rax") = i;
			raise(SIGUSR1);
			fprintf(stderr, "should not reach here\n");
		}
#else
		if (-1 == clone(clonefn, stack[i] + sizeof(stack[i]), flags, (void*)(uintptr_t)i)) {
			perror("clone");
		}
#endif
	}

	// TODO: auxv info is now in the core dump, restore it if we have the CAP_SYS_RESOURCE permission

	clonefn((void*)(uintptr_t)0);
	fprintf(stderr, "should not reach here\n");
	return 0;
}
