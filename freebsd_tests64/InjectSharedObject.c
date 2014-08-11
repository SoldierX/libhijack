/*
 * Copyright (c) 2011-2014, Shawn Webb
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *    1) Redistributions of source code must retain the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer.
 *    2) Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials
 *       provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <fcntl.h>

#include <hijack.h>
#include <hijack_func.h>
#include "os_resolv.h"

void usage(const char *name)
{
	fprintf(stderr, "USAGE: %s <pid> <shellcode stub> <shared object> <function>\n", name);
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	HIJACK *hijack;
	FUNC *funcs, *func;
	unsigned long shellcode_addr, filename_addr, dlopen_addr, dlsym_addr, funcname_addr, pltgot_addr, i;
	struct stat sb;
	void *shellcode, *p1;
	int fd;
	REGS *regs, *backup;
    int noaddr=0;
    RTLD_SYM *sym;
	
	if (argc != 5)
		usage(argv[0]);
	
	hijack = InitHijack();
#if 0
    ToggleFlag(hijack, F_DEBUG);
    ToggleFlag(hijack, F_DEBUG_VERBOSE);
#endif
	AssignPid(hijack, atoi(argv[1]));
	
	if (Attach(hijack) != ERROR_NONE)
	{
		fprintf(stderr, "[-] Couldn't attach!\n");
		exit(EXIT_FAILURE);
	}
	backup = GetRegs(hijack);
	regs = malloc(sizeof(REGS));
	
	if (stat(argv[2], &sb) == -1) {
        perror("stat");
        Detach(hijack);
        exit(EXIT_FAILURE);
    }
    if (!(shellcode = malloc(sb.st_size))) {
        perror("malloc");
        Detach(hijack);
        close(fd);
        exit(EXIT_FAILURE);
    }
	
	fd = open(argv[2], O_RDONLY);
    if (read(fd, shellcode, sb.st_size) != sb.st_size) {
        perror("read");
        Detach(hijack);
        close(fd);
        exit(EXIT_FAILURE);
    }
    close(fd);
	
	LocateAllFunctions(hijack);
    sym = resolv_rtld_sym(hijack, "dlopen");
    if (!(sym)) {
        fprintf(stderr, "[-] Could not locate dlopen inside the RTLD\n");
        Detach(hijack);
        exit(EXIT_FAILURE);
    }
    dlopen_addr = sym->p.ulp;
	printf("dlopen_addr: 0x%016lx\n", sym->p.ulp);
	
    sym = resolv_rtld_sym(hijack, "dlsym");
    if (!(sym)) {
        fprintf(stderr, "[-] Could not locate dlsym inside the RTLD\n");
        Detach(hijack);
        exit(EXIT_FAILURE);
    }
    dlsym_addr = sym->p.ulp;
	printf("dlsym_addr: 0x%016lx\n", dlsym_addr);
	
	memcpy(regs, backup, sizeof(REGS));

    /* Ensure we can find the function reference before trying to map memory and perform the hooks */
	funcs = FindAllFunctionsByName(hijack, argv[4], false);
	for (func = funcs; func != NULL; func = func->next)
	{
		if (!(func->name))
			continue;
		
		pltgot_addr = FindFunctionInGot(hijack, hijack->pltgot, func->vaddr);
		if (pltgot_addr > 0)
			break;
	}
    if (!pltgot_addr) {
        fprintf(stderr, "[-] Could not find function reference in the PLT/GOT.\n");
        Detach(hijack);
        exit(1);
    }
	
	printf("pltgot_addr: 0x%08lx\n", pltgot_addr);
	
	LocateSystemCall(hijack);
	filename_addr = MapMemory(hijack, (unsigned long)NULL, 4096,PROT_READ | PROT_EXEC | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE);
	
	memcpy(regs, backup, sizeof(REGS));
	
	p1 = memmem(shellcode, sb.st_size, "\x22\x22\x22\x22\x22\x22\x22\x22", 8);
    if (!(p1)) {
        perror("memmem");
        Detach(hijack);
        exit(1);
    }
    if (!noaddr)
        memcpy(p1, &filename_addr, 8);
	
	funcname_addr = filename_addr + strlen(argv[3]) + 1;
	shellcode_addr = funcname_addr + strlen(argv[4]) + 1;
	printf("filename_addr: 0x%016lx\n", filename_addr);
	printf("shellcode_addr: 0x%016lx\n", shellcode_addr);
	printf("rsp: 0x%016lx\n", regs->r_rsp);
	printf("rip: 0x%016lx\n", regs->r_rip);
	
	p1 = memmem(shellcode, sb.st_size, "\x33\x33\x33\x33\x33\x33\x33\x33", 8);
    if (!(p1)) {
        perror("memmem");
        Detach(hijack);
        exit(1);
    }
    if (!noaddr)
        memcpy(p1, &dlopen_addr, 8);
	
	p1 = memmem(shellcode, sb.st_size, "\x44\x44\x44\x44\x44\x44\x44\x44", 8);
    if (!(p1)) {
        perror("memmem");
        Detach(hijack);
        exit(1);
    }
    if (!noaddr)
        memcpy(p1, &funcname_addr, 8);
	
	p1 = memmem(shellcode, sb.st_size, "\x55\x55\x55\x55\x55\x55\x55\x55", 8);
    if (!(p1)) {
        perror("memmem");
        Detach(hijack);
        exit(1);
    }
    if (!noaddr)
        memcpy(p1, &dlsym_addr, 8);
	
	p1 = memmem(shellcode, sb.st_size, "\x66\x66\x66\x66\x66\x66\x66\x66", 8);
    if (!(p1)) {
        perror("memmem");
        Detach(hijack);
        exit(1);
    }
    if (!noaddr)
        memcpy(p1, &pltgot_addr, 8);
	
	if (WriteData(hijack, filename_addr, (unsigned char *)argv[3], strlen(argv[3])) != ERROR_NONE) {
        perror("ptrace");
        Detach(hijack);
        munmap(shellcode, sb.st_size);
        close(fd);
        exit(EXIT_FAILURE);
    }
	if (WriteData(hijack, funcname_addr, (unsigned char *)argv[4], strlen(argv[4])) != ERROR_NONE) {
        perror("ptrace");
        Detach(hijack);
        munmap(shellcode, sb.st_size);
        close(fd);
        exit(EXIT_FAILURE);
    }
	if (WriteData(hijack, shellcode_addr, (unsigned char *)shellcode, sb.st_size) != ERROR_NONE) {
        perror("ptrace");
        Detach(hijack);
        munmap(shellcode, sb.st_size);
        close(fd);
        exit(EXIT_FAILURE);
    }

    if (1) {
        regs->r_rsp -= 8;
        SetRegs(hijack, regs);
        if (WriteData(hijack, regs->r_rsp, (unsigned char *)(&(regs->r_rip)), 8) != ERROR_NONE) {
            perror("ptrace");
            Detach(hijack);
            exit(EXIT_FAILURE);
        }
        
        regs->r_rip = shellcode_addr;
        SetRegs(hijack, regs);
    }
	
	Detach(hijack);
	
	return 0;
}
