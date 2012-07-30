#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <elf.h>
#include <link.h>

#include <dlfcn.h>

#include "rtld.h"

int testvar1;
char *testvar2;
unsigned long testvar3[16];
char *testvar4="asdf";
char testvar5[] = "qwer";

int main(int argc, char *argv[])
{
    void *sym;
    struct Struct_Obj_Entry *soe;

    do {
        printf("pid: %d\n", getpid());
    } while (getc(stdin) != '\n');

    sym = dlfunc(RTLD_DEFAULT, argv[1] ? argv[1] : "pcap_create");
    printf("sym: 0x%016lx\n", (unsigned long)sym);

	return EXIT_FAILURE;
}
