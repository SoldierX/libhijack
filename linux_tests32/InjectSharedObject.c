/*
 * Copyright (c) 2011-2013, Shawn Webb
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 
 *    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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

void usage(const char *name)
{
	fprintf(stderr, "USAGE: %s <pid> <shellcode stub> <shared object> <function>\n", name);
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	HIJACK *hijack;
	FUNC *funcs, *func;
	unsigned long shellcode_addr, filename_addr, dlopen_addr, dlsym_addr, funcname_addr, pltgot_addr;
	struct stat sb;
	char *shellcode, *p1;
	int fd;
	struct user_regs_struct *regs, *backup;
	
	if (argc != 5)
		usage(argv[0]);
	
	hijack = InitHijack();
    ToggleFlag(hijack, F_DEBUG);
    ToggleFlag(hijack, F_DEBUG_VERBOSE);
	AssignPid(hijack, atoi(argv[1]));
	
	if (Attach(hijack) != ERROR_NONE)
	{
		fprintf(stderr, "[-] Couldn't attach!\n");
		exit(EXIT_FAILURE);
	}
	backup = GetRegs(hijack);
	regs = malloc(sizeof(struct user_regs_struct));
	
	stat(argv[2], &sb);
	shellcode = malloc(sb.st_size);
	
	fd = open(argv[2], O_RDONLY);
	read(fd, shellcode, sb.st_size);
	close(fd);
	
	LocateAllFunctions(hijack);
	funcs = FindFunctionInLibraryByName(hijack, "/lib/tls/i686/cmov/libdl.so.2", "dlopen");
	if (!(funcs))
	{
		fprintf(stderr, "[-] Couldn't locate dlopen!\n");
		exit(EXIT_FAILURE);
	}
	dlopen_addr = funcs->vaddr;
	printf("dlopen_addr: 0x%08lx\n", dlopen_addr);
	
	funcs = FindFunctionInLibraryByName(hijack, "/lib/tls/i686/cmov/libdl.so.2", "dlsym");
	if (!(funcs))
	{
		fprintf(stderr, "[-] Couldn't locate dlsym!\n");
		exit(EXIT_FAILURE);
	}
	dlsym_addr = funcs->vaddr;
	printf("dlsym_addr: 0x%08lx\n", dlsym_addr);
	
	memcpy(regs, backup, sizeof(struct user_regs_struct));
	
	LocateSystemCall(hijack);
	filename_addr = MapMemory(hijack, (unsigned long)NULL, 4096,PROT_READ | PROT_EXEC | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE);
	
	memcpy(regs, backup, sizeof(struct user_regs_struct));
	
	p1 = memmem(shellcode, sb.st_size, "\x22\x22\x22\x22", 4);
	memcpy(p1, &filename_addr, 4);
	
	funcname_addr = filename_addr + strlen(argv[3]) + 1;
	shellcode_addr = funcname_addr + strlen(argv[4]) + 1;
	printf("filename_addr: 0x%08lx\n", filename_addr);
	printf("shellcode_addr: 0x%08lx\n", shellcode_addr);
	printf("esp: 0x%08lx\n", regs->esp);
	printf("eip: 0x%08lx\n", regs->eip);
	
	p1 = memmem(shellcode, sb.st_size, "\x33\x33\x33\x33", 4);
	memcpy(p1, &dlopen_addr, 4);
	
	p1 = memmem(shellcode, sb.st_size, "\x44\x44\x44\x44", 4);
	memcpy(p1, &funcname_addr, 4);
	
	p1 = memmem(shellcode, sb.st_size, "\x55\x55\x55\x55", 4);
	memcpy(p1, &dlsym_addr, 4);
	
	funcs = FindAllFunctionsByName(hijack, argv[4], false);
	for (func = funcs; func != NULL; func = func->next)
	{
		if (!(func->name))
			continue;
		
		pltgot_addr = FindFunctionInGot(hijack, hijack->pltgot, func->vaddr);
		if (pltgot_addr > 0)
			break;
	}
	
	printf("pltgot_addr: 0x%08lx\n", pltgot_addr);
	
	p1 = memmem(shellcode, sb.st_size, "\x66\x66\x66\x66", 4);
	memcpy(p1, &pltgot_addr, 4);
	
	WriteData(hijack, filename_addr, (unsigned char *)argv[3], strlen(argv[3]));
	WriteData(hijack, funcname_addr, (unsigned char *)argv[4], strlen(argv[4]));
	WriteData(hijack, shellcode_addr, (unsigned char *)shellcode, sb.st_size);
	
	regs->esp -= 4;
	SetRegs(hijack, regs);
	WriteData(hijack, regs->esp, &(regs->eip), 4);
	
	regs->eip = shellcode_addr;
	
	if (regs->orig_eax >= 0)
	{
		switch (regs->eax)
		{
			case -514: /* -ERESTARTNOHAND */
			case -512: /* -ERESTARTSYS */
			case -513: /* -ERESTARTNOINTR */
			case -516: /* -ERESTART_RESTARTBLOCK */
				regs->eip += 2;
				break;
		}
	}
	SetRegs(hijack, regs);
	
	Detach(hijack);
	
	return 0;
}
