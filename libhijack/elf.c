/*
 * Copyright (c) 2011-2023, Shawn Webb <shawn.webb@hardenedbsd.org>
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials
 *      provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
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
#include "hijack_machdep.h"

int
init_elf_headers(HIJACK *hijack)
{

	if (IsFlagSet(hijack, F_DEBUG) && IsFlagSet(hijack, F_DEBUG_VERBOSE))
		fprintf(stderr, "[*] Attempting to read ELF headers from 0x%016lx\n",
		    hijack->baseaddr);

	hijack->ehdr.raw = read_data(hijack, (unsigned long)(hijack->baseaddr), sizeof(ElfW(Ehdr)));
	if (!(hijack->ehdr.raw)) {
		return (-1);
	}

	if (!IS_ELF(*(hijack->ehdr.ehdr))) {
		if (IsFlagSet(hijack, F_DEBUG))
			fprintf(stderr, "[-] Process is not an ELF file\n");
		return (-1);
	}

	if (IsFlagSet(hijack, F_DEBUG) && IsFlagSet(hijack, F_DEBUG_VERBOSE))
		fprintf(stderr, "[*] Attempting to read process headers from 0x%016lx\n",
		    (unsigned long)(hijack->baseaddr) + hijack->ehdr.ehdr->e_phoff);

	if (IsFlagSet(hijack, F_DEBUG) && IsFlagSet(hijack, F_DEBUG_VERBOSE))
		fprintf(stderr, "[*] process headers are at offset 0x%016lx\n",
		    (unsigned long)(hijack->ehdr.ehdr->e_phoff));

	if (!IS_ELF(*(hijack->ehdr.ehdr))) {
		if (IsFlagSet(hijack, F_DEBUG)) {
			fprintf(stderr, "[-] Process is not an ELF image\n");
		}
		return (-1);
	}

	hijack->phdr.raw = read_data(hijack, ((unsigned long)(hijack->baseaddr) + hijack->ehdr.ehdr->e_phoff), hijack->ehdr.ehdr->e_phentsize * hijack->ehdr.ehdr->e_phnum);
	if (!(hijack->phdr.raw))
		return (-1);

	if (hijack->ehdr.ehdr->e_type == ET_DYN) {
		hijack->flags |= F_PIE;
		hijack->basefixup = hijack->baseaddr;
	}

	return (0);
}

unsigned long
find_pltgot(HIJACK *hijack)
{
	unsigned int i;
	unsigned long ret;
	ElfW(Dyn) *dyn;

	dyn = NULL;
	SetError(hijack, ERROR_NONE);

	if (IsFlagSet(hijack, F_DEBUG))
		fprintf(stderr, "[*] Attempting to find PLT/GOT\n");
    
	for (i=0; i<hijack->ehdr.ehdr->e_phnum; i++) {
		if (hijack->phdr.phdr[i].p_type == PT_DYNAMIC)
		{
			dyn = (ElfW(Dyn) *)read_data(hijack,
			    hijack->basefixup +
			    (unsigned long)(hijack->phdr.phdr[i].p_vaddr),
			    hijack->phdr.phdr[i].p_memsz);
			break;
		}
	}
    
	if (!(dyn)) {
		if (IsFlagSet(hijack, F_DEBUG))
			fprintf(stderr, "[*] Could not locate DYNAMIC PHDR!\n");

		SetError(hijack, ERROR_NEEDED);
		return ((unsigned long)NULL);
	}

	if (hijack->flags & F_DEBUG_VERBOSE)
		fprintf(stderr, "[*] Found dynamic phdr at 0x%016lx\n",
		    hijack->basefixup + hijack->phdr.phdr[i].p_vaddr);
    
	for (i=0; dyn[i].d_tag != DT_NULL; i++) {
		if (dyn[i].d_tag == DT_PLTGOT) {
			if (hijack->flags & F_DEBUG_VERBOSE)
				fprintf(stderr, "[*] Found PLT/GOT at 0x%016lx\n",
				    hijack->basefixup + (unsigned long)(dyn[i].d_un.d_ptr));
			ret = hijack->basefixup + (unsigned long)(dyn[i].d_un.d_ptr);
			free(dyn);
			return (ret);
		}
	}

	free(dyn);

	if (IsFlagSet(hijack, F_DEBUG))
		fprintf(stderr, "[*] Could not locate PLT/GOT\n");
    
	SetError(hijack, ERROR_NEEDED);
	return ((unsigned long)NULL);
}

/*
 * On FreeBSD, the linkmap isn't a big deal. We use the Struct_Obj_Entry object,
 * which is still conveniently located at GOT[1]. The linkmap is only used when
 * resolving symbols within the RTLD.
 */
unsigned long
find_link_map_addr(HIJACK *hijack)
{
	unsigned long *addr;
	unsigned long ret;
    
	addr = read_data(hijack, hijack->pltgot + (sizeof(unsigned long)), sizeof(unsigned long));
	if (!(addr))
		return ((unsigned long)NULL);

	if (IsFlagSet(hijack, F_DEBUG) && IsFlagSet(hijack, F_DEBUG_VERBOSE))
		fprintf(stderr,
		    "[*] find_link_map_addr: First Struct_Obj_Entry: 0x%016lx\n",
		    *addr);

	hijack->soe = read_data(hijack, *addr, sizeof(Obj_Entry));
	free(addr);

	return ((unsigned long)NULL);
}

void
freebsd_parse_soe(HIJACK *hijack, struct Struct_Obj_Entry *soe, linkmap_callback callback)
{
	int err=0;
	ElfW(Sym) *libsym=NULL;
	unsigned long numsyms, symaddr=0, i=0;
	char *name;

	numsyms = soe->nchains;
	symaddr = (unsigned long)(soe->symtab);

	do
	{
		free(libsym);

		libsym = (ElfW(Sym) *)read_data(hijack, (unsigned long)symaddr, sizeof(ElfW(Sym)));
		if (libsym == NULL) {
			err = GetErrorCode(hijack);
			goto notfound;
		}

		name = read_str(hijack, (unsigned long)(soe->strtab + libsym->st_name));
		if (name != NULL) {
			if (callback(hijack, soe,
			    ELF64_ST_TYPE(libsym->st_info), name,
			    ((unsigned long)(soe->mapbase) + libsym->st_value),
			    (size_t)(libsym->st_size)) != CONTPROC) {
				free(name);
				break;
			}

			free(name);
		}

		symaddr += sizeof(ElfW(Sym));
	} while (i++ < numsyms);

notfound:
	SetError(hijack, err);
}

CBRESULT
syscall_callback(HIJACK *hijack, void *linkmap,
    unsigned char symtype, char *name, unsigned long vaddr, size_t sz)
{
	unsigned long syscalladdr;
	unsigned int align;
	size_t left;

	if (symtype != STT_FUNC) {
		return (CONTPROC);
	}
 
	align = GetInstructionAlignment();
	left = sz;
	while (left > sizeof(SYSCALLSEARCH) - 1) {
		syscalladdr = search_mem(hijack, vaddr, left, SYSCALLSEARCH, sizeof(SYSCALLSEARCH)-1);
		if (syscalladdr == (unsigned long)NULL)
			break;

		if ((syscalladdr % align) == 0) {
			hijack->syscalladdr = syscalladdr;
			return (TERMPROC);
		}

		left -= (syscalladdr - vaddr);
		vaddr += (syscalladdr - vaddr) + sizeof(SYSCALLSEARCH)-1;
	}
 
	return (CONTPROC);
}

unsigned long
search_mem(HIJACK *hijack, unsigned long funcaddr, size_t funcsz, void *data, size_t datasz)
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
		return ((unsigned long)(funcaddr +
		    (ret - (unsigned long)funcdata)));

	return ((unsigned long)NULL);
}

unsigned long
find_func_addr_in_got(HIJACK *hijack, unsigned long pltaddr, unsigned long addr)
{
	void *p;
	unsigned long got_data;
	unsigned int i;
    
	if (!IsAttached(hijack)) {
		SetError(hijack, ERROR_NOTATTACHED);
		return ((unsigned long)NULL);
	}

	p = read_data(hijack, pltaddr, sizeof(unsigned long));
	if (!(p))
		return ((unsigned long)NULL);

	got_data = *((unsigned long *)p);

	i = 1;
	while (got_data > 0) {
		/* There isn't a way for us to see how big the GOT
		 * is. We simply stop on the first NULL value.
		 */
		free(p);

		if (got_data == addr)
			break;

		if (IsFlagSet(hijack, F_DEBUG_VERBOSE))
			fprintf(stderr, "[*] got[%u]: 0x%08lx\n", i, got_data);

		p = read_data(hijack, pltaddr + ((++i) * sizeof(unsigned long)), sizeof(unsigned long));
		if (!(p))
			return ((unsigned long)NULL);

		got_data = *((unsigned long *)p);
	}
    
	if (!got_data) {
		SetError(hijack, ERROR_NEEDED);
		return ((unsigned long)NULL);
	}
    
	return (pltaddr + (i * sizeof(unsigned long)));
}
