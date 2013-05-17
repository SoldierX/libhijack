#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>

int main(int argc, char *argv[])
{
    dlopen("/dev/null", RTLD_GLOBAL | RTLD_LAZY);

	while (printf("%d\n", getpid()))
		sleep(5);
	return EXIT_FAILURE;
}
