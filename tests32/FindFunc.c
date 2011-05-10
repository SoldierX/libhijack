#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <hijack.h>
#include <hijack_func.h>

void usage(const char *name)
{
	fprintf(stderr, "USAGE: %s <pid> <func>\n", name);
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	HIJACK *hijack;
	FUNC *funcs, *func;
	
	if (argc != 3)
		usage(argv[0]);
	
	hijack = InitHijack();
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
	
	funcs = FindAllFunctionsByName(hijack, argv[2], true);
	for (func = funcs; func != NULL; func = func->next)
	{
		if (!(func->name))
			continue;
		
		printf("[+] %s\t%s @ 0x%08lx (%u)\n", func->libname, func->name, func->vaddr, func->sz);
	}
	
	Detach(hijack);
	
	return 0;
}
