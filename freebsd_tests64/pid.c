#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <elf.h>
#include <link.h>

#include <dlfcn.h>

#include "rtld.h"

#define DEFAULT_SYM "pcap_create"

int testvar1;
char *testvar2;
unsigned long testvar3[16];
char *testvar4="asdf";
char testvar5[] = "qwer";

int main(int argc, char *argv[])
{
    void *sym;
    struct Struct_Obj_Entry *soe = (struct Struct_Obj_Entry *)0x000000080061b000;

    do {
        printf("pid: %d\n", getpid());
    } while (getc(stdin) != '\n');

    sym = dlfunc(RTLD_DEFAULT, argv[1] ? argv[1] : DEFAULT_SYM);
    printf("%s: 0x%016lx\n", argv[1] ? argv[1] : DEFAULT_SYM, (unsigned long)sym);

    do {
        sleep(1);
    } while (getc(stdin) != '\n');

	return EXIT_FAILURE;
}
