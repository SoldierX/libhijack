/*
 * Copyright (c) 2011-2012, Shawn Webb
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 
 *    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

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
#include "os_resolv.h"

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

    unsigned long obj_tail_addr;
    unsigned long last_soe_addr;
    
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

    ElfW(Phdr) *phdyn;
    ElfW(Phdr) *phtls;
    ElfW(Phdr) *phinterp;

    unsigned long phdr_vaddr;
    unsigned long phsize;
    unsigned long stack_flags;
    unsigned long relro_page;
    unsigned long relro_size;

    unsigned long base_addr;
    unsigned long base_vaddr;
    unsigned long base_offset;
    unsigned long base_vlimit;
    unsigned long mapsize;
    unsigned long mapping;

    /* Used for storing auxiliary info (struct Struct_Obj_entry) */
    unsigned long auxmap;

    struct rtld_loadable *loadables;
};

int append_soe(HIJACK *, unsigned long, struct Struct_Obj_Entry *);

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

    for (i=0; i < aux->ehdr.ehdr->e_phnum; i++) {
        switch (aux->phdr.phdr[i].p_type) {
            case PT_INTERP:
                aux->phinterp = aux->phdr.phdr + i;
                break;
            case PT_PHDR:
                aux->phdr_vaddr = aux->phdr.phdr[i].p_vaddr;
                aux->phsize = aux->phdr.phdr[i].p_memsz;
                break;
            case PT_DYNAMIC:
                aux->phdyn = aux->phdr.phdr + i;
                break;
            case PT_LOAD:
                rtld_add_loadable(hijack, aux, aux->phdr.phdr + i);
                break;
            case PT_TLS:
                aux->phtls = aux->phdr.phdr + i;
                break;
            case PT_GNU_RELRO:
                aux->relro_page = aux->phdr.phdr[i].p_vaddr;
                aux->relro_size = aux->phdr.phdr[i].p_memsz;
                break;
        }
    }

    return 0;
}

/*
 * Actually load the shared object
 * Logic taken from freebsd/9-stable/libexec/rtld-elf/map_object.c
 */
int rtld_create_maps(HIJACK *hijack, struct rtld_aux *aux) {
    struct rtld_loadable *first_loadable, *last_loadable, *loadable;
    int err;
    char *bss;
    unsigned long bss_vaddr, bss_addr, bss_page, nclear;

    /* Grab first and last loadable PHDRs */
    first_loadable = aux->loadables;
    for (last_loadable = aux->loadables; last_loadable->next != NULL; last_loadable = last_loadable->next)
        ;

    /* Create one large mapping to hold the whole shared object */
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

    /* Do the math for all the PHDRs */
    for (loadable = first_loadable; loadable != NULL; loadable = loadable->next) {
        loadable->offset = trunc_page(loadable->phdr.phdr->p_offset);
        loadable->vaddr = trunc_page(loadable->phdr.phdr->p_vaddr);
        loadable->limit = round_page(loadable->phdr.phdr->p_vaddr + loadable->phdr.phdr->p_filesz);
        loadable->addr = aux->mapping + (loadable->vaddr - aux->base_vaddr);

        if (loadable->phdr.phdr->p_filesz != loadable->phdr.phdr->p_memsz) {
            /* BSS */
            bss_vaddr = loadable->phdr.phdr->p_vaddr + loadable->phdr.phdr->p_filesz;
            bss_addr = aux->mapping + (bss_vaddr - aux->base_vaddr);
            bss_page = aux->mapping + (trunc_page(bss_vaddr) - aux->base_vaddr);
            nclear = loadable->limit - bss_vaddr;

            if (nclear > 0) {
                bss = _hijack_malloc(hijack, nclear);
                if (!(bss))
                    return -1;
                err = WriteData(hijack, bss_addr, bss, nclear);
                free(bss);

                if (IsFlagSet(hijack, F_DEBUG) && IsFlagSet(hijack, F_DEBUG_VERBOSE)) {
                    fprintf(stderr, "Wrote BSS to 0x%016lx. Length %lu.\n", bss_addr, nclear);
                }
            }
        } else {
            err = WriteData(hijack, loadable->addr, aux->lmap + loadable->offset, loadable->phdr.phdr->p_memsz);
            if (IsFlagSet(hijack, F_DEBUG) && IsFlagSet(hijack, F_DEBUG_VERBOSE)) {
                fprintf(stderr, "Wrote to 0x%016lx. Length %lu. From offset %lu.\n", loadable->addr, loadable->phdr.phdr->p_memsz, loadable->offset);
            }
        }
    }

    return 0;
}

int rtld_hook_into_rtld(HIJACK *hijack, struct rtld_aux *aux)
{
    struct Struct_Obj_Entry soe;
    
    memset(&soe, 0x00, sizeof(struct Struct_Obj_Entry));

    /* Fill in a new Struct_Obj_Entry struct */
    soe.dl_refcount++;


    soe.phsize = aux->ehdr.ehdr->e_phnum * sizeof(ElfW(Phdr));
    soe.mapbase = aux->mapping;
    soe.mapsize = aux->mapsize;
    soe.textsize = round_page(aux->loadables->phdr.phdr->p_vaddr + aux->loadables->phdr.phdr->p_memsz) - aux->base_vaddr;
    soe.vaddrbase = aux->base_vaddr;
    soe.relocbase = aux->mapping - aux->base_vaddr;
    soe.dynamic = (ElfW(Dyn) *)(soe.relocbase + aux->phdyn->p_vaddr);
    if (aux->ehdr.ehdr->e_entry)
        soe.entry = soe.relocbase + aux->ehdr.ehdr->e_entry;
    if (aux->phdr_vaddr) {
        soe.phdr = (ElfW(Phdr) *)(soe.relocbase + aux->phdr_vaddr);
    } else {
        soe.phdr = _hijack_malloc(hijack, soe.phsize);
        if (!(soe.phdr))
            return -1;

        memcpy(soe.phdr, aux->ehdr.ptr + aux->ehdr.ehdr->e_phoff, soe.phsize);
        soe.phdr_alloc = true;
    }
    if ((aux->phinterp))
        soe.interp = soe.relocbase + aux->phinterp->p_vaddr;
    if ((aux->phtls)) {
        /* TODO: Figure this part out */
    }
    soe.stack_flags = PROT_READ | PROT_WRITE | PROT_EXEC;
    soe.relro_page = soe.relocbase + trunc_page(soe.relro_page);
    soe.relro_size = round_page(soe.relro_size);

    /* Create auxiliary mapping and write the Struct_Obj_Entry */
    aux->auxmap = MapMemory(hijack, (unsigned long)NULL, getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_SHARED);
    if (soe.phdr_alloc) {
        if (WriteData(hijack, aux->auxmap + sizeof(struct Struct_Obj_Entry), soe.phdr, soe.phsize) != ERROR_NONE)
            return -1;

        free(soe.phdr);
        soe.phdr = aux->auxmap + sizeof(struct Struct_Obj_Entry);
        soe.phdr_alloc = false;
    }
    WriteData(hijack, aux->auxmap, &soe, sizeof(struct Struct_Obj_Entry));

    return append_soe(hijack, aux->auxmap, &soe);
}

/*
 * Find an approprite SOE entry to hook our injected SOE into:
 *      (oursoe->next = soe->next; soe->next = oursoe)
 */
unsigned long find_appropriate_soe(HIJACK *hijack, struct Struct_Obj_Entry **retsoe) {
    static struct Struct_Obj_Entry *soe=NULL;
    ElfW(Dyn) *dyn=NULL;
    struct link_map *l=NULL;
    unsigned long addr;

    *retsoe = NULL;

    if (!(hijack) || !(hijack->soe)) {
        fprintf(stderr, "[-] You didn't initialize libhijack correctly.\n");
        return (unsigned long)NULL;
    }

    l = read_data(hijack, hijack->soe->linkmap.l_next, sizeof(struct link_map));
    if (!(l)) {
        fprintf(stderr, "[-] Cannot load the previous linkmap struct at 0x%016lx.\n", (unsigned long)(hijack->soe->linkmap.l_next));
        return (unsigned long)NULL;
    }

    addr = l->l_ld;
    do {
        if ((dyn))
            _hijack_free(hijack, dyn, sizeof(ElfW(Dyn)));

        dyn = read_data(hijack, addr, sizeof(ElfW(Dyn)));
        if (!(dyn)) {
            fprintf(stderr, "[-] dyn at 0x%016lx couldn't load\n", addr);
            return (unsigned long)NULL;
        }

        if (dyn->d_tag == DT_PLTGOT)
            break;

        addr += sizeof(ElfW(Dyn));
    } while (dyn->d_tag != DT_NULL);

    if (!(dyn)) {
        fprintf(stderr, "[-] dyn is NULL\n");
        return (unsigned long)NULL;
    }

    addr = (unsigned long)(l->l_addr) + (unsigned long)(dyn->d_un.d_ptr) + sizeof(unsigned long);
    soe = read_data(hijack, addr, sizeof(struct Struct_Obj_Entry));
    if (!(soe)) {
        fprintf(stderr, "[-] Could not get soe from got at 0x%016lx\n", addr);
        return (unsigned long)NULL;
    }

    *retsoe = soe;

    return addr;
}

/*
 * Append our SOE in the middle.
 */
int append_soe(HIJACK *hijack, unsigned long addr, struct Struct_Obj_Entry *soe) {
    struct Struct_Obj_Entry *prevsoe=NULL, *realsoe;
    unsigned long last_soe_addr;

    /* Hook the Struct_Object_Entry into the real linked list */
    realsoe = hijack->soe;
    while ((realsoe->next)) {
        if ((prevsoe))
            free(prevsoe);

        prevsoe = realsoe;
        realsoe = read_data(hijack, realsoe->next, sizeof(struct Struct_Obj_Entry));
    }

    if (!(realsoe))
        return -1;
#if 0
    realsoe->next = addr;
    WriteData(hijack, (unsigned long)(prevsoe->next), realsoe, sizeof(struct Struct_Obj_Entry));

    last_soe_addr = find_last_soe_addr(hijack, 0x800600000, 0x80083a000);
    while (last_soe_addr) {
        WriteData(hijack, last_soe_addr, &addr, sizeof(unsigned long));

        last_soe_addr = find_last_soe_addr(hijack, last_soe_addr+sizeof(unsigned long), 0x80083a000);
    }
#endif

    return 0;
}

EXPORTED_SYM int load_library(HIJACK *hijack, char *path)
{
    struct rtld_aux aux;
    unsigned long addr;
    struct Struct_Obj_Entry *soe=NULL;
    char *name=NULL;

    memset(&aux, 0x00, sizeof(struct rtld_aux));

    addr = find_appropriate_soe(hijack, &soe);
    if (addr)
        name = read_str(hijack, soe->path);

    fprintf(stderr, "[*] path = %s, addr = 0x%016lx, soe = 0x%016lx\n", (name) ? name : "(null)", addr, (unsigned long)soe);
    return 0;

    aux.path = strdup(path);
    stat(aux.path, &(aux.sb));

    aux.fd = open(aux.path, O_RDONLY);
    if (aux.fd < 0)
        return -1;

    if (rtld_load_headers(hijack, &aux) == -1)
        return -1;

    if (rtld_create_maps(hijack, &aux) == -1)
        return -1;

    if (rtld_hook_into_rtld(hijack, &aux) == -1)
        return -1;

    return 0;
}
