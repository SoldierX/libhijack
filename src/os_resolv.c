#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
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
#include "os_resolv.h"

/*
 * Find the RTLD's linkmap.
 *
 * We need it on both Linux and FreeBSD so that we can resolve RTLD functions
 * and piggyback off the native RTLD and eventually patch into it.
 *
 * XXX This function probably ought to be in elf.c, not in os_resolv.c
 */
unsigned long find_rtld_linkmap(HIJACK *hijack)
{
    struct link_map *l, *p=NULL;
    unsigned long addr=NULL;

    l = &(hijack->soe->linkmap);

    while ((l->l_next)) {
        if ((p) && (p) != &(hijack->soe->linkmap))
            free(p);

        p = l;
        l = read_data(hijack, l->l_next, sizeof(struct link_map));
    }

    addr = (unsigned long)(p->l_next);
    free(p);
    free(l);

    return addr;
}

/*
 * Resolve exported dynamically-loaded symbols from the RTLD.
 * Even though the RTLD relocates itself after it's loaded,
 * we have its linkmap, which points to its relocated base
 * mapping. The symbols in the relocated RTLD are in the same
 * relative location.
 *
 * This function needs to be made more performant. It opens
 * the RTLD in memory, mmaps it, and grabs the dynamic symbol
 * table entries. The returned object carries the fully
 * resolved address based on the base address from the linkmap
 * added with the offset from the symbol table.
 */
RTLD_SYM *resolv_rtld_sym(HIJACK *hijack, char *name)
{
    RTLD_SYM *sym=NULL;
    struct link_map *l;
    char *path;
    void *buf;
    int fd;
    struct stat sb;
    char *symname;
    char *strtab;
    ElfW(Sym) *symtab=NULL;
    ElfW(Ehdr) *ehdr=NULL;
    ElfW(Shdr) *shdr=NULL;
    ElfW(Phdr) *phdr=NULL;
    ElfW(Dyn) *dyn=NULL;
    unsigned long i;
    unsigned long symsz;

    if (!(hijack))
        return NULL;

    l = read_data(hijack, find_rtld_linkmap(hijack), sizeof(struct link_map));
    if (!(l)) {
        fprintf(stderr, "[-] Cannot find rtld's linkmap\n");
        return NULL;
    }

    path = read_str(hijack, l->l_name);
    if (!(path)) {
        fprintf(stderr, "[-] Cannot read rtld's path\n");
        return NULL;
    }

    stat(path, &sb);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "[-] Cannot open rtld file\n");
        return NULL;
    }

    buf = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (buf == MAP_FAILED) {
        fprintf(stderr, "[-] Cannot mmap rtld into tmp mapping\n");
        close(fd);
        return NULL;
    }

    ehdr = buf;
    shdr = buf + ehdr->e_shoff;
    for (i=0; i < ehdr->e_shnum; i++) {
        switch (shdr[i].sh_type) {
            case SHT_DYNSYM:
                symtab = buf+shdr[i].sh_offset;
                symsz = shdr[i].sh_size/sizeof(ElfW(Sym));
                break;
        }
    }

    phdr = buf+ehdr->e_phoff;
    for (i=0; i < ehdr->e_phnum; i++) {
        switch (phdr[i].p_type) {
            case PT_DYNAMIC:
                dyn = buf+phdr[i].p_offset;
                break;
        }
    }

    for (i=0; dyn[i].d_tag != DT_NULL; i++) {
        switch (dyn[i].d_tag) {
            case DT_STRTAB:
                strtab = buf+dyn[i].d_un.d_val;
                break;
        }
    }

    for (i=0; i < symsz; i++) {
        if (!strcmp(name, strtab+symtab[i].st_name)) {
            sym = _hijack_malloc(hijack, sizeof(RTLD_SYM));

            sym->name = strdup(strtab+symtab[i].st_name);
            sym->p.ulp = (unsigned long)(l->l_addr + symtab[i].st_value);
            sym->sz = symtab[i].st_size;

            switch (ELF_ST_TYPE(symtab[i].st_info)) {
                case STT_FUNC:
                    sym->type = FUNC;
                    break;
                case STT_OBJECT:
                    sym->type = VAR;
                    break;
            }

            /* We shouldn't see multiple symbols that share the same name */
            break;
        }
    }

    /* If no match, sym will be NULL  */
    munmap(buf, sb.st_size);
    close(fd);
    return sym;
}
