#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <link.h>

#include <dlfcn.h>

int main(int argc, char *argv[])
{
    void *sym;

    do {
        printf("pid: %d\n", getpid());
    } while (getc(stdin) != '\n');

    sym = dlfunc(RTLD_DEFAULT, "func");
    printf("sym: 0x%016lx\n", (unsigned long)sym);

	return EXIT_FAILURE;
}
