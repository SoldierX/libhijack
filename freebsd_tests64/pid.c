#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <link.h>

#include "rtld.h"

int main(int argc, char *argv[])
{
    struct link_map *map;
    struct Struct_Obj_Entry *entry;

	while (printf("%d\n", getpid()))
		sleep(5);
	return EXIT_FAILURE;
}
