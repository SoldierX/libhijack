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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <hijack.h>
#include <hijack_func.h>

void usage(const char *name)
{
	fprintf(stderr, "USAGE: %s <pid>\n", name);
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	HIJACK *hijack;
	FUNC *func;
	unsigned long addr;
	PLT *plts, *plt;
	
	if (argc != 2)
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

	if (LocateAllFunctions(hijack) != ERROR_NONE)
	{
		fprintf(stderr, "[-] Couldn't locate all functions!\n");
		exit(EXIT_FAILURE);
	}

	
	printf("[*] PLT/GOT @ 0x%016lx\n", hijack->pltgot);
	printf("[*] Baseaddr @ 0x%016lx\n", hijack->baseaddr);

#if 0
    for (func = hijack->funcs; func != NULL; func = func->next)
        printf("[+] %s %s: 0x%016lx\n", func->libname, func->name, func->vaddr);
#endif

	plts = GetAllPLTs(hijack);
	for (plt = plts; plt != NULL; plt = plt->next)
	{
		printf("[+] Looking in %s\n", plt->libname);

		for (func = hijack->funcs; func != NULL; func = func->next)
		{
			if (!(func->name))
				continue;
			
			addr = FindFunctionInGot(hijack, plt->p.ptr, func->vaddr);
			
			printf("[+]    %s\t%s @ 0x%016lx (%u)", func->libname, func->name, func->vaddr, func->sz);
			if (addr > 0)
				printf("        -> 0x%016lx", addr);
			
			printf("\n");
		}
	}

	Detach(hijack);
	
	return 0;
}
