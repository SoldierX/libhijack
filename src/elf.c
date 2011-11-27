/*
 * Copyright (c) 2011, Shawn Webb
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 
 *    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#include <elf.h>
#include <link.h>

#include "hijack.h"
#include "error.h"
#include "misc.h"
#include "hijack_ptrace.h"
#include "map.h"
#include "hijack_elf.h"

int init_elf_headers(HIJACK *hijack)
{
	hijack->ehdr.raw = read_data(hijack, (unsigned long)(hijack->baseaddr), sizeof(ElfW(Ehdr)));
	if (!(hijack->ehdr.raw))
		return -1;
	
	hijack->phdr.raw = read_data(hijack, ((unsigned long)(hijack->baseaddr) + hijack->ehdr.ehdr->e_phoff), hijack->ehdr.ehdr->e_phentsize * hijack->ehdr.ehdr->e_phnum);
	if (!(hijack->phdr.raw))
		return -1;

	return 0;
}

unsigned long find_pltgot(HIJACK *hijack)
{
	unsigned int i;
	unsigned long ret;
	ElfW(Dyn) *dyn=NULL;
	
	SetError(hijack, ERROR_NONE);
	
	if (IsFlagSet(hijack, F_DEBUG))
		fprintf(stderr, "[*] Attempting to find PLT/GOT\n");
	
	for (i=0; i<hijack->ehdr.ehdr->e_phnum; i++)
	{
		if (hijack->phdr.phdr[i].p_type == PT_DYNAMIC)
		{
			dyn = (ElfW(Dyn) *)read_data(hijack, (unsigned long)(hijack->phdr.phdr[i].p_vaddr), hijack->phdr.phdr[i].p_memsz);
			break;
		}
	}
	
	if (!(dyn))
	{
		if (IsFlagSet(hijack, F_DEBUG))
			fprintf(stderr, "[*] Could not locate DYNAMIC PHDR!\n");
		
		SetError(hijack, ERROR_NEEDED);
		return (unsigned long)NULL;
	}
	
	for (i=0; dyn[i].d_tag != DT_NULL; i++) {
		if (dyn[i].d_tag == DT_PLTGOT) {
			ret = (unsigned long)(dyn[i].d_un.d_ptr);
			free(dyn);
			return ret;
		}
	}

	free(dyn);

	if (IsFlagSet(hijack, F_DEBUG))
		fprintf(stderr, "[*] Could not locate PLT/GOT\n");
	
	SetError(hijack, ERROR_NEEDED);
	return (unsigned long)NULL;
}

unsigned long find_link_map_addr(HIJACK *hijack)
{
	unsigned long *addr;
	unsigned long ret;
	
#if defined(FreeBSD)
    addr = read_data(hijack, hijack->pltgot + (sizeof(unsigned long)), sizeof(unsigned long));
    if (IsFlagSet(hijack, F_DEBUG) && IsFlagSet(hijack, F_DEBUG_VERBOSE))
        fprintf(stderr, "[*] find_link_map_addr: First Struct_Obj_Entry: 0x%16lx\n", *addr);
    hijack->soe = read_data(hijack, *addr, sizeof(struct Struct_Obj_Entry));
    free(addr);
    return (unsigned long)NULL;
#endif
	addr = read_data(hijack, hijack->pltgot + sizeof(unsigned long), sizeof(unsigned long));
	if (!(addr))
		return (unsigned long)NULL;
	
	ret = *addr;
	free(addr);
	return ret;
}

struct link_map *get_next_linkmap(HIJACK *hijack, unsigned long addr)
{
	if ((void *)addr == NULL)
		return NULL;
	
	return (struct link_map *)read_data(hijack, addr, sizeof(struct link_map));
}

void parse_linkmap(HIJACK *hijack, struct link_map *linkmap, linkmap_callback callback)
{
	int err;
	ElfW(Dyn) *libdyn=NULL;
	char *libstrtab=NULL;
	ElfW(Sym) *libsym=NULL;
	
	unsigned long dynaddr=0, symaddr=0, hashtable=0, i=0;
	ElfW(Word) numsyms;
	
	char *name, *libname;

#if defined(FreeBSD)
    struct Struct_Obj_Entry *soe;
    char *soename;
#endif
	
	if (!(linkmap))
		return;
	
	libname = read_str(hijack, (unsigned long)(linkmap->l_name));
    if (IsFlagSet(hijack, F_DEBUG) && IsFlagSet(hijack, F_DEBUG_VERBOSE)) {
        fprintf(stderr, "[*] parse_linkmap: linkmap->l_name: 0x%16lx\n", (unsigned long)(linkmap->l_name));
        fprintf(stderr, "[*] parse_linkmap: linkmap->l_ld: 0x%16lx\n", (unsigned long)(linkmap->l_ld));
    }


	if (!(libname) || !strlen(libname)) {
		if ((libname))
			free(libname);

		err = ERROR_NEEDED;
		goto notfound;
	}
	
	dynaddr = (unsigned long)(linkmap->l_ld);
	do {
		if (libdyn)
			free(libdyn);

		libdyn = (ElfW(Dyn) *)read_data(hijack, (unsigned long)dynaddr, sizeof(ElfW(Dyn)));
		if (!(libdyn))
		{
			err = GetErrorCode(hijack);
			goto notfound;
		}
		
		if (libdyn->d_tag == DT_STRTAB)
			libstrtab = (char *)(libdyn->d_un.d_ptr);
		else if (libdyn->d_tag == DT_SYMTAB)
			symaddr = (unsigned long)(libdyn->d_un.d_ptr);
		else if (libdyn->d_tag == DT_HASH)
			hashtable = (unsigned long)(libdyn->d_un.d_ptr);
		
		dynaddr += sizeof(ElfW(Dyn));
	} while (libdyn->d_tag != DT_NULL);
	
	if ((libdyn))
		free(libdyn);

	if (symaddr == 0 || libstrtab == NULL || hashtable == 0) {
		err = SetError(hijack, ERROR_NEEDED);
		goto notfound;
	}

#if defined(FreeBSD)
    soe = hijack->soe;
    do {
        soename = read_str(hijack, soe->path);
        if (!strcmp(soename, libname))
            break;

        soe = read_data(hijack, (unsigned long)(soe->next), sizeof(struct Struct_Obj_Entry));
    } while(soe != NULL);

    if (soe == NULL) {
        if (IsFlagSet(hijack, F_DEBUG))
            fprintf(stderr, "[-] ERROR: soe is NULL when searching for %s!\n", libname);
        err = SetError(hijack, ERROR_NONE);
        goto notfound;
    }

    numsyms = soe->nchains;
#else
    if (IsFlagSet(hijack, F_DEBUG) && IsFlagSet(hijack, F_DEBUG_VERBOSE))
        fprintf(stderr, "[*] parse_linkmap: hashtable: 0x%16lx\n", hashtable);
	
	hashtable += sizeof(ElfW(Word));
	memcpy(&numsyms, read_data(hijack, hashtable, sizeof(ElfW(Word))), sizeof(ElfW(Word)));
#endif
	
	if (IsFlagSet(hijack, F_DEBUG_VERBOSE))
		fprintf(stderr, "numsyms: %u\n", (unsigned int)numsyms);
	
	symaddr += sizeof(ElfW(Sym));
	
	#if defined(i686)
		do {
			if ((libsym))
				free(libsym);

			libsym = (ElfW(Sym) *)read_data(hijack, (unsigned long)symaddr, sizeof(ElfW(Sym)));
			if (!(libsym)) {
				err = GetErrorCode(hijack);
				goto notfound;
			}
			
			if (ELF32_ST_TYPE(libsym->st_info) != STT_FUNC) {
				symaddr += sizeof(ElfW(Sym));
				continue;
			}
			
			name = read_str(hijack, (unsigned long)(libstrtab + libsym->st_name));
			if ((name)) {
				/* XXX name should be cleaned up. Callback should duplicate (strdup) the name if needed... */
				if (callback(hijack, linkmap, name, ((unsigned long)(linkmap->l_addr) + libsym->st_value), (size_t)(libsym->st_size)) != CONTPROC) {
					free(name);
					break;
				}
				
				free(name);
			}
			
			symaddr += sizeof(ElfW(Sym));
		} while (i++ < numsyms);
	#elif defined(x86_64) || defined(amd64)
		do {
			if ((libsym))
				free(libsym);

			libsym = (ElfW(Sym) *)read_data(hijack, (unsigned long)symaddr, sizeof(ElfW(Sym)));
			if (!(libsym))
			{
				err = GetErrorCode(hijack);
				goto notfound;
			}
			
			if (ELF64_ST_TYPE(libsym->st_info) != STT_FUNC)
			{
				symaddr += sizeof(ElfW(Sym));
				continue;
			}
			
			name = read_str(hijack, (unsigned long)(libstrtab + libsym->st_name));
			if ((name)) {
				if (callback(hijack, linkmap, name, ((unsigned long)(linkmap->l_addr) + libsym->st_value), (size_t)(libsym->st_size)) != CONTPROC) {
					free(name);
					break;
				}

				free(name);
			}
			
			symaddr += sizeof(ElfW(Sym));
		} while (i++ < numsyms);
	#endif
	
notfound:
	SetError(hijack, err);
}

CBRESULT syscall_callback(HIJACK *hijack, struct link_map *linkmap, char *name, unsigned long vaddr, size_t sz)
{
	unsigned long syscalladdr;
	
	syscalladdr = search_mem(hijack, vaddr, sz, SYSCALLSEARCH, strlen(SYSCALLSEARCH));
	if (syscalladdr)
	{
		hijack->syscalladdr = syscalladdr;
		return TERMPROC;
	}
	
	return CONTPROC;
}

unsigned long search_mem(HIJACK *hijack, unsigned long funcaddr, size_t funcsz, void *data, size_t datasz)
{
	void *funcdata;
	unsigned long ret;
	
	funcdata = read_data(hijack, funcaddr, funcsz);
	if (!(funcdata))
		return (unsigned long)NULL;
	
	ret = (unsigned long)memmem(funcdata, funcsz, data, datasz);
	
	if ((funcdata))
		free(funcdata);
	
	if (ret)
		return (unsigned long)(funcaddr + (ret - (unsigned long)funcdata));
	
	return (unsigned long)NULL;
}

int init_hijack_system(HIJACK *hijack)
{
	if (!IsAttached(hijack))
		return SetError(hijack, ERROR_NOTATTACHED);
	
	if (init_elf_headers(hijack) != 0)
		return SetError(hijack, ERROR_SYSCALL);
	
	if ((hijack->pltgot = find_pltgot(hijack)) == (unsigned long)NULL)
		return GetErrorCode(hijack);
	
#if defined(FreeBSD)
    find_link_map_addr(hijack);
    hijack->linkhead = &(hijack->soe->linkmap);
#else
	if ((hijack->linkhead = get_next_linkmap(hijack, find_link_map_addr(hijack))) == NULL)
		return GetErrorCode(hijack);
#endif
	
	return SetError(hijack, ERROR_NONE);
}

unsigned long find_func_addr_in_got(HIJACK *hijack, unsigned long pltaddr, unsigned long addr)
{
	void *p;
	unsigned long got_data;
	unsigned int i;
	
	if (!IsAttached(hijack))
	{
		SetError(hijack, ERROR_NOTATTACHED);
		return 0;
	}
	
	/* XXX Assume that read_data won't error out, possible NULL pointer dereference */
	p = read_data(hijack, pltaddr, sizeof(unsigned long));
	got_data = *((unsigned long *)p);
	i = 1;
	while (got_data > 0)
	{
		free(p);

		if (got_data == addr)
			break;
		if (IsFlagSet(hijack, F_DEBUG_VERBOSE))
			fprintf(stderr, "[*] got[%u]: 0x%08lx\n", i, got_data);
		p = read_data(hijack, pltaddr + ((++i) * sizeof(unsigned long)), sizeof(unsigned long));
		got_data = *((unsigned long *)p);
	}
	
	if (!got_data)
	{
		SetError(hijack, ERROR_NEEDED);
		return 0;
	}
	
	return pltaddr + (i * sizeof(unsigned long));
}
