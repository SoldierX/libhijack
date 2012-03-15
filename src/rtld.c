#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/param.h>

#include <elf.h>
#include <link.h>

#include "hijack.h"
#include "error.h"
#include "misc.h"
#include "hijack_ptrace.h"
#include "map.h"
#include "hijack_elf.h"

struct rtld_loadable {
    union {
        void *ptr;
        unsigned char *buf;
        ElfW(Phdr) *phdr;
    } phdr;

    unsigned long vaddr;
    unsigned long addr;
    unsigned long limit;
    unsigned long offset;

    struct rtld_loadable *next;
};

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

    unsigned long base_addr;
    unsigned long base_vaddr;
    unsigned long base_offset;
    unsigned long base_vlimit;
    unsigned long mapsize;
    unsigned long mapping;

    struct rtld_loadable *loadables;
};

void rtld_add_loadable(HIJACK *hijack, struct rtld_aux *aux, ElfW(Phdr) *phdr) {
    struct rtld_loadable *loadable;

    if ((aux->loadables)) {
        for (loadable = aux->loadables; loadable->next != NULL; loadable = loadable->next)
            ;

        loadable->next = _hijack_malloc(hijack, sizeof(struct rtld_loadable));
        if (!(loadable->next))
            return;

        loadable = loadable->next;
    } else {
        aux->loadables = loadable = _hijack_malloc(hijack, sizeof(struct rtld_loadable));
        if (!(loadable))
            return;
    }

    loadable->phdr.phdr = phdr;
}

int rtld_load_headers(HIJACK *hijack, struct rtld_aux *aux) {
    unsigned long i;

    aux->lmap = mmap(NULL, aux->sb.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, aux->fd, 0);
    if (aux->lmap == MAP_FAILED) {
        perror("[-] rtld_load_headers: mmap");
        return -1;
    }

    aux->ehdr.ehdr = aux->lmap;
    aux->phdr.phdr = aux->lmap + aux->ehdr.ehdr->e_phoff;

    for (i=0; i < aux->ehdr.ehdr->e_phnum; i++)
        if (aux->phdr.phdr[i].p_type == PT_LOAD)
            rtld_add_loadable(hijack, aux, aux->phdr.phdr + i);

    return 0;
}

/*
 * Actually load the shared object
 * Logic taken from freebsd/9-stable/libexec/rtld-elf/map_object.c
 */
void rtld_create_maps(HIJACK *hijack, struct rtld_aux *aux) {
    struct rtld_loadable *first_loadable, *last_loadable;

    /* Grab first and last loadable PHDRs */
    first_loadable = aux->loadables;
    for (last_loadable = aux->loadables; last_loadable->next != NULL; last_loadable = last_loadable->next)
        ;

    aux->base_offset = trunc_page(first_loadable->phdr.phdr->p_offset);
    aux->base_vaddr = trunc_page(first_loadable->phdr.phdr->p_vaddr);
    aux->base_vlimit = round_page(last_loadable->phdr.phdr->p_vaddr + last_loadable->phdr.phdr->p_memsz);
    aux->mapsize = aux->base_vlimit - aux->base_vaddr;
    aux->base_addr = (unsigned long)NULL;

    aux->mapping = MapMemory(hijack, aux->base_addr, aux->mapsize, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_SHARED);

    if (IsFlagSet(hijack, F_DEBUG)) {
        fprintf(stderr, "map[0x%016lx]:\n", aux->mapping);
        fprintf(stderr, "    mapsize\t= %lu\n", aux->mapsize);
        fprintf(stderr, "    limit\t= %lu\n", aux->base_vlimit);
    }
}

EXPORTED_SYM int load_library(HIJACK *hijack, char *path)
{
    struct rtld_aux aux;
    memset(&aux, 0x00, sizeof(struct rtld_aux));

    aux.path = strdup(path);
    stat(aux.path, &(aux.sb));

    aux.fd = open(aux.path, O_RDONLY);
    if (aux.fd < 0)
        return -1;

    if (rtld_load_headers(hijack, &aux) == -1)
        return -1;

    rtld_create_maps(hijack, &aux);

    return 0;
}
