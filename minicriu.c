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
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <sys/user.h>
#include <sys/procfs.h>
#include <sys/stat.h>
#include <sys/ucontext.h>
#include <asm/prctl.h>        /* Definition of ARCH_* constants */
#include <sys/syscall.h>      /* Definition of SYS_* constants */
#include <linux/sched.h>
#include <linux/elf.h>


static struct elf_prpsinfo *prpsinfo;

#define MAX_THREADS 128

static int thread_n;
static struct elf_prstatus *prstatus[MAX_THREADS];
static struct user_fpregs_struct *prfpreg[MAX_THREADS];
static char stack[MAX_THREADS][4 * 4096];

static size_t elfsz;
static void *rawelf;

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

int main(int argc, char *argv[]) {
	const char* elfpath = argv[1];

	int fd = open(elfpath, O_RDONLY);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	struct stat st;
	if (fstat(fd, &st)) {
		perror("stat");
		return 1;
	}

	elfsz = align_up(st.st_size, 4096);
	rawelf = mmap(NULL, elfsz, PROT_READ, MAP_PRIVATE, fd, 0);
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

	const Elf64_Phdr *ph_notes = NULL;
	for (int i = 0; i < ehdr->e_phnum; ++i) {
		const Elf64_Phdr *ph = phdrs + i;
		if (ph->p_type == PT_NOTE) {
			ph_notes = ph;
			break;
		}
	}

	if (!ph_notes) {
		fprintf(stderr, "cannot find PT_NOTE\n");
		return 1;
	}

	for (int i = 0; i < ehdr->e_phnum; ++i) {
		const Elf64_Phdr *ph = phdrs + i;
		if (ph->p_type != PT_LOAD) {
			continue;
		}
		if (munmap((void*)ph->p_vaddr, ph->p_memsz)) {
			/*perror("munmap");*/
		}
		void *addr = mmap((void*)ph->p_vaddr,
				ph->p_memsz,
				PROT_WRITE,
				MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
				-1, 0);
		if (addr != (void*)ph->p_vaddr) {
			if (addr == MAP_FAILED) {
				fprintf(stderr, "WARN: mmap phdr vaddr %16llx filesz %16llx off %16llx: %m\n",
						ph->p_vaddr, ph->p_filesz, ph->p_offset);
			} else {
				fprintf(stderr, "WARN: mmap phdr target mismatch %llx -> %p\n", ph->p_vaddr, addr);
			}
		}
	}

	off_t noff = ph_notes->p_offset;
	while (noff < ph_notes->p_offset + ph_notes->p_filesz) {
		Elf64_Nhdr *nh = rawelf + noff;
		off_t nameoff = noff + sizeof(*nh);
		off_t doff = nameoff + align_up(nh->n_namesz, 4);
		noff = doff + align_up(nh->n_descsz, 4);

		/*printf("%16s 0x%08lx 0x%08lx\n", rawelf + nameoff, nh->n_type, nh->n_descsz);*/
		void *target = NULL;
		if (!strcmp("CORE", rawelf + nameoff)) {
			switch (nh->n_type) {
			case NT_PRPSINFO: target = &prpsinfo; break;
			case NT_PRSTATUS: target = &prstatus[thread_n++]; break;
			case NT_PRFPREG:  target = &prfpreg[thread_n];  break;
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

		if (!strcmp("CORE", rawelf + nameoff) && nh->n_type == NT_FILE) {
			struct {
				long count;
				long page_size;
				struct filemap {
					long start;
					long end;
					long file_ofs;
				} map[0];
			} *fh = rawelf + doff;

			char *name = (char*)(&fh->map[fh->count]);
			for (int i = 0; i < fh->count; ++i) {
				struct filemap *fm = &fh->map[i];

				int fd = open(name, O_RDONLY);
				munmap((void*)fm->start, fm->end - fm->start);
				void *addr = mmap((void*)fm->start,
						fm->end - fm->start,
						PROT_READ | PROT_WRITE | PROT_EXEC,
						MAP_FIXED | MAP_PRIVATE,
						fd, fm->file_ofs * fh->page_size);
				if (addr != (void*)fm->start) {
					if (addr == MAP_FAILED) {
						perror("mmap file");
					} else {
						fprintf(stderr, "mmap mismatch 2\n");
					}
					return 1;
				}
				close(fd);

				name = name + strlen(name) + 1;
			}
		}
	}


	for (int i = 0; i < ehdr->e_phnum; ++i) {
		const Elf64_Phdr *ph = phdrs + i;
		if (ph->p_type != PT_LOAD) {
			continue;
		}
		pread(fd, (void*)ph->p_vaddr, ph->p_filesz, ph->p_offset);

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
	clonefn((void*)(uintptr_t)0);
	fprintf(stderr, "should not reach here\n");
	return 0;
}
