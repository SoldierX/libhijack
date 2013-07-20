#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <link.h>
#include <dlfcn.h>

int main(int argc, char *argv[])
{
    unsigned int (*handle)(unsigned int);
    char *name;

    name = (argv[1] ? argv[1] : "sleep");

    printf("%d\n", getpid());
    getc(stdin);
    
    handle = dlsym(RTLD_NEXT, name);
    printf("%s: %p\n", name, handle);
    if (handle)
        handle(1);

	return EXIT_FAILURE;
}
