#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <elf.h>
#include <link.h>

#include "hijack.h"
#include "error.h"
#include "misc.h"
#include "hijack_ptrace.h"
#include "map.h"
#include "hijack_elf.h"

struct rtld_aux {
    char *path;
    int fd;
    void *lmap; /* short for "local map" */
    struct stat sb;
    
    union {
        void *ptr;
        unsigned char *buf;
        ElfW(Ehdr) *ehdr;
    } ehdr;

    union {
        void *ptr;
        unsigned char *buf;
        ElfW(Phdr) *phdr;
    } phdr;
};

EXPORTED_SYM int load_library(HIJACK *hijack, char *path)
{
    struct rtld_aux aux;

    aux.path = strdup(path);
    stat(aux.path, &(aux.sb));

    aux.fd = open(aux.path, O_RDONLY);
    if (aux.fd < 0)
        return -1;

    aux.lmap = mmap(NULL, aux.sb.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, aux.fd, 0);
    if (!(aux.lmap))
        return -1;

    aux.ehdr.ehdr = aux.lmap;

    return 0;
}
