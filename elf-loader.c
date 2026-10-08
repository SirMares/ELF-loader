// SPDX-License-Identifier: BSD-3-Clause

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <elf.h>
#include <string.h>

void *map_elf(const char *filename)
{
	// This part helps you store the content of the ELF file inside the buffer.
	struct stat st;
	void *file;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	fstat(fd, &st);

	file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file == MAP_FAILED) {
		perror("mmap");
		close(fd);
		exit(1);
	}

	return file;
}

void load_and_run(const char *filename, int argc, char **argv, char **envp)
{
	void *elf_contents = map_elf(filename);
	unsigned char *e_ident = (unsigned char *)elf_contents;

	// ELF validation (existing code)
	if (e_ident[0] != 0x7F || e_ident[1] != 'E' || e_ident[2] != 'L' || e_ident[3] != 'F') {
		perror("Not a valid ELF file");
		exit(3);
	}
	if (e_ident[4] != 2) {
		perror("Not a 64-bit ELF");
		exit(4);
	}

	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_contents;
	Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)elf_contents + ehdr->e_phoff);

	/**
	 * TODO: Support Static PIE Executables
	 * Map PT_LOAD segments at a random load base.
	 * Adjust virtual addresses of segments and entry point by load_base.
	 */
	uintptr_t load_base = 0;
	int is_pie = (ehdr->e_type == ET_DYN);

	if (is_pie) {
		load_base = (uintptr_t)mmap((void *)0x555500000000,
		0x10000000,
		PROT_NONE,
		MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
		-1, 0);
		if (load_base == (uintptr_t)MAP_FAILED) {
			perror("mmap for load base");
			exit(1);
		}

		munmap((void *)load_base, 0x10000000);

		load_base = load_base & ~0x1FFFFF;
	}

	// Load PT_LOAD segments
	for (int i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_LOAD) {
			uintptr_t segment_vaddr = phdr[i].p_vaddr;

			if (is_pie)
				segment_vaddr += load_base;

			size_t page_offset = segment_vaddr & 0xFFF;
			size_t aligned_vaddr = segment_vaddr - page_offset;
			size_t aligned_memsz = phdr[i].p_memsz + page_offset;

			if (aligned_memsz % 0x1000 != 0)
				aligned_memsz += 0x1000 - (aligned_memsz % 0x1000);

			// Map memory with initial RW permissions
			void *segment_addr = mmap((void *)aligned_vaddr,
									aligned_memsz,
									PROT_READ | PROT_WRITE,
									MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
									-1, 0);
			if (segment_addr == MAP_FAILED) {
				perror("mmap segment");
				exit(1);
			}

			// Copy segment data from file to memory
			memcpy((char *)segment_addr + page_offset,
				   (char *)elf_contents + phdr[i].p_offset,
				   phdr[i].p_filesz);

			// Zero out the remaining memory (BSS section)
			if (phdr[i].p_memsz > phdr[i].p_filesz) {
				memset((char *)segment_addr + page_offset + phdr[i].p_filesz,
					   0,
					   phdr[i].p_memsz - phdr[i].p_filesz);
			}

			// Set proper memory permissions
			int prot = 0;

			if (phdr[i].p_flags & PF_R)
				prot |= PROT_READ;
			if (phdr[i].p_flags & PF_W)
				prot |= PROT_WRITE;
			if (phdr[i].p_flags & PF_X)
				prot |= PROT_EXEC;

			if (mprotect(segment_addr, aligned_memsz, prot) == -1) {
				perror("mprotect");
				exit(1);
			}
		}
	}

	/**
	 * TODO: Support Static Non-PIE Binaries with libc
	 * Must set up a valid process stack, including:
	 *  - argc, argv, envp
	 *  - auxv vector (with entries like AT_PHDR, AT_PHENT, AT_PHNUM, etc.)
	 */
	// Create a stack region
	size_t stack_size = 64 * 1024; // 64KB stack
	void *stack_addr = mmap(NULL, stack_size,
	PROT_READ | PROT_WRITE,
	MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (stack_addr == MAP_FAILED) {
		perror("mmap stack");
		exit(1);
	}

	char *sp = (char *)stack_addr + stack_size;

	sp = (char *)((uintptr_t)sp & ~0xF);


	// Count environment variables
	int envc = 0;

	while (envp[envc])
		envc++;

	// Prepare auxiliary vector
	Elf64_auxv_t auxv[20];
	int auxv_count = 0;

	uintptr_t adjusted_phdr = (uintptr_t)phdr;
	uintptr_t adjusted_entry = ehdr->e_entry;

	if (is_pie) {
		adjusted_phdr = load_base + ehdr->e_phoff;
		adjusted_entry = load_base + ehdr->e_entry;
	}

	// Essential auxv entries
	auxv[auxv_count].a_type = AT_PHDR;
	auxv[auxv_count].a_un.a_val = adjusted_phdr;
	auxv_count++;

	auxv[auxv_count].a_type = AT_PHENT;
	auxv[auxv_count].a_un.a_val = ehdr->e_phentsize;
	auxv_count++;

	auxv[auxv_count].a_type = AT_PHNUM;
	auxv[auxv_count].a_un.a_val = ehdr->e_phnum;
	auxv_count++;

	auxv[auxv_count].a_type = AT_ENTRY;
	auxv[auxv_count].a_un.a_val = adjusted_entry;
	auxv_count++;

	auxv[auxv_count].a_type = AT_PAGESZ;
	auxv[auxv_count].a_un.a_val = 4096;
	auxv_count++;

	auxv[auxv_count].a_type = AT_BASE;
	auxv[auxv_count].a_un.a_val = is_pie ? load_base : 0;
	auxv_count++;

	auxv[auxv_count].a_type = AT_FLAGS;
	auxv[auxv_count].a_un.a_val = 0;
	auxv_count++;

	auxv[auxv_count].a_type = AT_UID;
	auxv[auxv_count].a_un.a_val = getuid();
	auxv_count++;

	auxv[auxv_count].a_type = AT_EUID;
	auxv[auxv_count].a_un.a_val = geteuid();
	auxv_count++;

	auxv[auxv_count].a_type = AT_GID;
	auxv[auxv_count].a_un.a_val = getgid();
	auxv_count++;

	auxv[auxv_count].a_type = AT_EGID;
	auxv[auxv_count].a_un.a_val = getegid();
	auxv_count++;

	// AT_RANDOM
	uint8_t random_bytes[16] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
	};

	// First copy random bytes for AT_RANDOM
	sp -= 16;
	uintptr_t random_addr = (uintptr_t)sp;

	memcpy(sp, random_bytes, 16);

	auxv[auxv_count].a_type = AT_RANDOM;
	auxv[auxv_count].a_un.a_val = random_addr;
	auxv_count++;

	auxv[auxv_count].a_type = AT_NULL;
	auxv[auxv_count].a_un.a_val = 0;
	auxv_count++;

	for (int i = auxv_count - 1; i >= 0; i--) {
		sp -= sizeof(Elf64_auxv_t);
		*(Elf64_auxv_t *)sp = auxv[i];
	}

	// Push environment pointers
	sp -= sizeof(char *);
	*(char **)sp = NULL;

	for (int i = envc - 1; i >= 0; i--) {
		sp -= sizeof(char *);
		*(char **)sp = envp[i];
	}

	// Push argument pointers
	sp -= sizeof(char *);
	*(char **)sp = NULL;

	for (int i = argc - 1; i >= 0; i--) {
		sp -= sizeof(char *);
		*(char **)sp = argv[i];
	}

	// Push argc
	sp -= sizeof(long);
	*(long *)sp = argc;

	// Calculate the entry point
	void (*entry)() = (void (*)())(is_pie ? adjusted_entry : ehdr->e_entry);

	// Transfer control
	__asm__ __volatile__(
		"mov %0, %%rsp\n"
		"xor %%rbp, %%rbp\n"
		"jmp *%1\n"
		:
		: "r"(sp), "r"(entry)
		: "memory"
	);
}

int main(int argc, char **argv, char **envp)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <static-elf-binary>\n", argv[0]);
		exit(1);
	}

	load_and_run(argv[1], argc - 1, &argv[1], envp);
	return 0;
}
