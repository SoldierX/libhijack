#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <link.h>

int main(int argc, char *argv[])
{
	while (printf("%d\n", getpid()))
		sleep(5);
	return EXIT_FAILURE;
}
