/*
 * Copyright (c) 2011-2014, Shawn Webb
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *    1) Redistributions of source code must retain the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer.
 *    2) Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials
 *       provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

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

#if defined(FreeBSD)
/*
 * Find the RTLD's linkmap. On FreeBSD, the RTLD's linkmap is the last entry.
 *
 * We need it on both Linux and FreeBSD so that we can resolve RTLD functions
 * and piggyback off the native RTLD and eventually patch into it.
 *
 * XXX This function probably ought to be in elf.c, not in os_resolv.c
 */
unsigned long find_rtld_linkmap(HIJACK *hijack)
{
    struct link_map *l, *p=NULL;
    unsigned long addr=(unsigned long)NULL;

    if (!(hijack) || !(hijack->soe))
        return (unsigned long)NULL;

    l = &(hijack->soe->linkmap);

    while ((l->l_next)) {
        if ((p) && (p) != &(hijack->soe->linkmap))
            free(p);

        p = l;
        l = read_data(hijack, (unsigned long)(l->l_next), sizeof(struct link_map));
        if (!(l))
            return (unsigned long)NULL;
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
EXPORTED_SYM RTLD_SYM *resolv_rtld_sym(HIJACK *hijack, char *name)
{
    RTLD_SYM *sym=NULL;
    struct link_map *l;
    char *path;
    void *buf;
    int fd;
    struct stat sb;
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
    if (!(l))
        return NULL;

    path = read_str(hijack, (unsigned long)(l->l_name));
    if (!(path))
        return NULL;

    if (stat(path, &sb) < 0) {
        free(l);
        free(path);
        return NULL;
    }

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        free(l);
        free(path);
        return NULL;
    }

    free(path);

    buf = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (buf == MAP_FAILED) {
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

    /* XXX This should _never_ happen with the RTLD */
    if (!(dyn) || !(strtab)) {
        munmap(buf, sb.st_size);
        close(fd);
        free(l);
        return NULL;
    }

    for (i=0; i < symsz; i++) {
        if (!strcmp(name, strtab+symtab[i].st_name)) {
            sym = _hijack_malloc(hijack, sizeof(RTLD_SYM));
            if (!(sym)) {
                munmap(buf, sb.st_size);
                close(fd);
                free(l);
                return NULL;
            }

            sym->name = strdup(strtab+symtab[i].st_name);
            if (!(sym->name)) {
                munmap(buf, sb.st_size);
                close(fd);
                free(l);
                free(sym);
                return NULL;
            }
            sym->p.ulp = (unsigned long)(l->l_addr + symtab[i].st_value);
            sym->sz = symtab[i].st_size;

            switch (ELF_ST_TYPE(symtab[i].st_info)) {
                case STT_FUNC:
                    sym->type = RTLD_SYM_FUNC;
                    break;
                case STT_OBJECT:
                    sym->type = RTLD_SYM_VAR;
                    break;
            }

            /* We shouldn't see multiple symbols that share the same name */
            break;
        }
    }

    /* If no match, sym will be NULL  */
    munmap(buf, sb.st_size);
    close(fd);
    free(l);
    return sym;
}
#endif
