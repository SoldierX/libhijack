#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <hijack.h>
#include <hijack_func.h>

#include <sys/types.h>
#include <sys/mman.h>

void usage(const char *name)
{
	fprintf(stderr, "USAGE: %s <pid> <shared object>\n", name);
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	HIJACK *hijack;
	FUNC *func;
	unsigned long addr;
	PLT *plts, *plt;
	
	if (argc != 3)
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

    if (LocateSystemCall(hijack) != ERROR_NONE) {
        fprintf(stderr, "[-] Couldn't locate system call!\n");
        exit(EXIT_FAILURE);
    }

    LoadLibrary(hijack, argv[2]);
	
	Detach(hijack);
	
	return 0;
}
