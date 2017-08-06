/*
 * Copyright (c) 2017, Shawn Webb
 * All rights reserved.
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

static HIJACK *
local_hijack_init(pid_t pid)
{
	HIJACK *ctx;

	ctx = InitHijack(F_DEFAULT);
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

			printf("[+]    %s\t%s @ 0x%016lx (%lu)",
			    func->libname, func->name, func->vaddr,
			    func->sz);
			if (addr > 0)
				printf("        -> 0x%016lx", addr);

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

	addr = MapMemory(ctx, (unsigned long)NULL, 4096, PROT_NONE, MAP_SHARED | MAP_ANON);

	printf("[+] New mapping is at 0x%016lx\n", addr);

	Detach(ctx);
}

int
main(int argc, char *argv[])
{
	pid_t pid;
	int ch;

	pid = 0;
	while ((ch = getopt(argc, argv, "mPsp:")) != -1) {
		switch (ch) {
		case 'p':
			if (sscanf(optarg, "%d", &pid) != 1) {
				printf("lolwut\n");
				exit(1);
			}
			break;
		case 'm':
			map_memory(pid);
			break;
		case 'P':
			print_all_functions(pid);
			break;
		case 's':
			locate_system_call(pid);
			break;
		}
	}

	return (0);
}
