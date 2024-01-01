/*
 * Copyright (c) 2018-2023, Shawn Webb <shawn.webb@hardenedbsd.org>
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials
 *      provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include <sys/types.h>
#include <sys/mman.h>

#include "hijack.h"
#include "hijack_prog.h"

void do_iterate_entries(pid_t);

int M_flag = 0;
int R_flag = 0;
int v_flag = 0;

static HIJACK *
local_hijack_init(pid_t pid)
{
	HIJACK *ctx;
	unsigned int verbose;

	verbose = 0;
	if (v_flag > 0)
		verbose |= F_DEBUG;
	if (v_flag > 1)
		verbose |= F_DEBUG_VERBOSE;

	ctx = InitHijack(F_DEFAULT | verbose);
	if (ctx == NULL) {
		fprintf(stderr, "Could not create hijack ctx\n");
		exit(1);
	}

	if (AssignPid(ctx, pid)) {
		fprintf(stderr, "Could not assign the PID\n");
		exit(1);
	}

	if (Attach(ctx)) {
		fprintf(stderr, "Could not attach to the PID: %s\n",
		    GetErrorString(ctx));

		/* For good measure */
		Detach(ctx);
		exit(1);
	}

	return (ctx);
}

static void
print_all_functions(pid_t pid)
{
	unsigned long addr;
	PLT *plts, *plt;
	HIJACK *ctx;
	FUNC *func;

	ctx = local_hijack_init(pid);

	if (LocateAllFunctions(ctx)) {
		fprintf(stderr, "Could not cache functions: %s\n",
		    GetErrorString(ctx));
	}

	plts = GetAllPLTs(ctx);
	for (plt = plts; plt != NULL; plt = plt->next) {
		printf("[+] Looking in %s\n", plt->libname);

		for (func = ctx->funcs; func != NULL; func = func->next) {
			if (func->name == NULL)
				continue;

			addr = FindFunctionInGot(ctx, plt->p.ptr, func->vaddr);

			if (M_flag) {
				printf("%s\t%s\t0x%016lx:%lu",
				    func->libname, func->name,
				    func->vaddr, func->sz);
				if (addr > 0)
					printf(" 0x%016lx", addr);
			} else {
				printf("[+]    %s\t%s @ 0x%016lx (%lu)",
				    func->libname, func->name,
				    func->vaddr, func->sz);
				if (addr > 0)
					printf("        -> 0x%016lx", addr);

			}

			printf("\n");
		}
	}

	Detach(ctx);
}

static void
locate_system_call(pid_t pid)
{
	HIJACK *ctx;

	ctx = local_hijack_init(pid);

	if (LocateSystemCall(ctx)) {
		fprintf(stderr, "Could not locate the system call: %s\n",
		    GetErrorString(ctx));
		Detach(ctx);
		return;
	}

	if (M_flag)
		printf("0x%016lx\n", ctx->syscalladdr);
	else
		printf("[+] System call located at 0x%016lx\n", ctx->syscalladdr);

	Detach(ctx);
}

static void
map_memory(pid_t pid)
{
	HIJACK *ctx;
	unsigned long addr;

	ctx = local_hijack_init(pid);

	if (LocateSystemCall(ctx)) {
		fprintf(stderr, "Could not locate the system call: %s\n",
		    GetErrorString(ctx));
		Detach(ctx);
		return;
	}

	addr = MapMemory(ctx, (unsigned long)NULL, 4096,
	    PROT_READ | /* PROT_WRITE | */ PROT_EXEC,
	    MAP_SHARED | MAP_ANON);

	if (M_flag)
		printf("0x%016lx\n", addr);
	else
		printf("[+] New mapping is at 0x%016lx\n", addr);

	Detach(ctx);
}

static void
local_rtld_resolve(pid_t pid, char *name)
{
	HIJACK *ctx;
	RTLD_SYM *sym;

	ctx = local_hijack_init(pid);
	sym = resolv_rtld_sym(ctx, name);

	if (sym == NULL) {
		printf("[-] %s not found\n", name);
		return;
	}

	printf("[+] %s is at 0x%016lx\n", name, sym->p.ulp);

	Detach(ctx);
}

static void
inject_shellcode(pid_t pid, unsigned long addr, char *path)
{
	HIJACK *ctx;
	REGS *regs;

	ctx = local_hijack_init(pid);
	if (R_flag) {
		regs = GetRegs(ctx);
		if (InjectShellcodeAndRun(ctx, addr, (const char *)path, true)) {
			fprintf(stderr, "[-] Could not inject and run shellcode: %s\n",
			    GetErrorString(ctx));
		}
	}

	Detach(ctx);
}

static void
internal_load_library(pid_t pid, char *path)
{
	HIJACK *ctx;

	ctx = local_hijack_init(pid);
	LocateSystemCall(ctx);
	load_library(ctx, path);
#if 0
	Detach(ctx);
#endif
}

void
do_iterate_entries(pid_t pid)
{
	HIJACK *ctx;

	ctx = local_hijack_init(pid);
	if (ctx == NULL)
		return;
	IterateObjectEntries(ctx, iterate_object_entries);
	Detach(ctx);
}

int
main(int argc, char *argv[])
{
	unsigned long addr;
	pid_t pid;
	int ch;

	pid = 0;
	while ((ch = getopt(argc, argv, "l:mMPRsSva:i:p:r:")) != -1) {
		switch (ch) {
		case 'a':
			if (sscanf(optarg, "0x%016lx", &addr) != 1) {
				printf("bad address\n");
				exit(1);
			}
			break;
		case 'i':
			inject_shellcode(pid, addr, optarg);
			break;
		case 'p':
			if (sscanf(optarg, "%d", &pid) != 1) {
				printf("lolwut\n");
				exit(1);
			}
			break;
		case 'l':
			internal_load_library(pid, optarg);
			break;
		case 'm':
			map_memory(pid);
			break;
		case 'M':
			M_flag = 1;
			break;
		case 'P':
			print_all_functions(pid);
			break;
		case 'R':
			R_flag = 1;
			break;
		case 'r':
			local_rtld_resolve(pid, optarg);
			break;
		case 's':
			locate_system_call(pid);
			break;
		case 'S':
			do_iterate_entries(pid);
			break;
		case 'v':
			v_flag++;
			break;
		}
	}

	return (0);
}
