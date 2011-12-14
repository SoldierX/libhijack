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

    for (func = hijack->funcs; func != NULL; func = func->next)
        printf("[+] %s %s: 0x%016lx\n", func->libname, func->name, func->vaddr);

#if 0
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
#endif

	Detach(hijack);
	
	return 0;
}
