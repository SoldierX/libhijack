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
	
	hijack->shdr.raw = read_data(hijack, ((unsigned long)(hijack->baseaddr) + hijack->ehdr.ehdr->e_shoff), hijack->ehdr.ehdr->e_shentsize * hijack->ehdr.ehdr->e_shnum);
	if (!(hijack->shdr.raw))
		return -1;
	
	return 0;
}

unsigned long find_pltgot(HIJACK *hijack)
{
	unsigned int i;
	ElfW(Dyn) *dyn=NULL;
	
	SetError(hijack, ERROR_NONE);
	
	if (IsFlagSet(hijack, F_DEBUG_VERBOSE))
		fprintf(stderr, "[*] Attempting to find PLT/GOT\n");
	
	for (i=0; i<hijack->ehdr.ehdr->e_phnum; i++)
	{
		if (IsFlagSet(hijack, F_DEBUG_VERBOSE))
		{
			#if defined(i686)
				fprintf(stderr, "[*] Parsing phdr[%u]:\n", i);
				fprintf(stderr, "    [*] p_vaddr:\t0x%08x\n", hijack->phdr.phdr[i].p_vaddr);
				fprintf(stderr, "    [*] p_memsz:\t0x%08x\n", hijack->phdr.phdr[i].p_memsz);
				fprintf(stderr, "    [*] p_type:\t%d\n", hijack->phdr.phdr[i].p_type);
			#elif defined(x86_64)
				fprintf(stderr, "[*] Parsing phdr[%u]:\n", i);
				fprintf(stderr, "    [*] p_vaddr:\t0x%016lx\n", hijack->phdr.phdr[i].p_vaddr);
				fprintf(stderr, "    [*] p_memsz:\t0x%016lx\n", hijack->phdr.phdr[i].p_memsz);
				fprintf(stderr, "    [*] p_type:\t%d\n", hijack->phdr.phdr[i].p_type);
			#endif
		}
		
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
	
	if(IsFlagSet(hijack, F_DEBUG_VERBOSE))
	{
		#if defined(i686)
			fprintf(stderr, "[+] PT_DYNAMIC found @ 0x%08x!\n", hijack->phdr.phdr[i].p_vaddr);
		#elif defined(x86_64)
			fprintf(stderr, "[+] PT_DYNAMIC found @ 0x%016lx!\n", hijack->phdr.phdr[i].p_vaddr);
		#endif
	}
	
	for (i=0; dyn[i].d_tag != DT_NULL; i++)
	{
		if (IsFlagSet(hijack, F_DEBUG_VERBOSE))
		{
			fprintf(stderr, "[*] Parsing dyn[%u]\n", i);
			#if defined(i686)
				fprintf(stderr, "    [*] d_tag:\t%d\n", dyn[i].d_tag);
				fprintf(stderr, "    [*] d_ptr:\t0x%08x\n", dyn[i].d_un.d_ptr);
			#elif defined(x86_64)
				fprintf(stderr, "    [*] d_tag:\t%ld\n", dyn[i].d_tag);
				fprintf(stderr, "    [*] d_ptr:\t0x%016lx\n", dyn[i].d_un.d_ptr);
			#endif
		}
		
		if (dyn[i].d_tag == DT_PLTGOT)
		{
			if (IsFlagSet(hijack, F_DEBUG_VERBOSE))
			{
				#if defined(i686)
					fprintf(stderr, "[+] PLT/GOT found @ 0x%08x!\n", dyn[i].d_un.d_ptr);
				#elif defined(x86_64)
					fprintf(stderr, "[+] PLT/GOT found @ 0x%016lx!\n", dyn[i].d_un.d_ptr);
				#endif
			}
			
			return (unsigned long)(dyn[i].d_un.d_ptr);
		}
	}

	if (IsFlagSet(hijack, F_DEBUG))
		fprintf(stderr, "[*] Could not locate PLT/GOT\n");
	
	SetError(hijack, ERROR_NEEDED);
	return (unsigned long)NULL;
}

unsigned long find_link_map_addr(HIJACK *hijack)
{
	unsigned long *addr;
	unsigned long ret;
	
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

/* XXX This function _really_ needs to be cleaned up prior to 0.2 release */
void parse_linkmap(HIJACK *hijack, struct link_map *linkmap, linkmap_callback callback)
{
	int err;
	ElfW(Dyn) *libdyn=NULL;
	char *libstrtab=NULL;
	ElfW(Sym) *libsym=NULL;
	
	unsigned long dynaddr=0, symaddr=0, hashtable=0, i=0;
	ElfW(Word) numsyms;
	
	char *name, *libname;
	
	if (!(linkmap))
		return;
	
	libname = read_str(hijack, (unsigned long)(linkmap->l_name));
	if (!(libname) || !strlen(libname))
	{
		err = ERROR_NEEDED;
		goto notfound;
	}
	
	dynaddr = (unsigned long)(linkmap->l_ld);
	do
	{
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
	
	if (symaddr == 0 || libstrtab == NULL || hashtable == 0)
	{
		err = SetError(hijack, ERROR_NEEDED);
		goto notfound;
	}
	
	hashtable += sizeof(ElfW(Word));
	memcpy(&numsyms, read_data(hijack, hashtable, sizeof(ElfW(Word))), sizeof(ElfW(Word)));
	
	if (IsFlagSet(hijack, F_DEBUG_VERBOSE))
		fprintf(stderr, "numsyms: %u\n", (unsigned int)numsyms);
	
	symaddr += sizeof(ElfW(Sym));
	
	#if defined(i686)
		do
		{
			libsym = (ElfW(Sym) *)read_data(hijack, (unsigned long)symaddr, sizeof(ElfW(Sym)));
			if (!(libsym))
			{
				err = GetErrorCode(hijack);
				goto notfound;
			}
			
			if (ELF32_ST_TYPE(libsym->st_info) != STT_FUNC)
			{
				symaddr += sizeof(ElfW(Sym));
				continue;
			}
			
			name = read_str(hijack, (unsigned long)(libstrtab + libsym->st_name));
			if (name)
			{
				/* XXX name should be cleaned up. Callback should duplicate (strdup) the name if needed... */
				if (callback(hijack, linkmap, name, ((unsigned long)(linkmap->l_addr) + libsym->st_value), (size_t)(libsym->st_size)) != CONTPROC)
				{
					free(name);
					break;
				}
				
				free(name);
			}
			
			symaddr += sizeof(ElfW(Sym));
		} while (i++ < numsyms);
	#elif defined(x86_64)
		do
		{
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
			if (name)
			{
				if (callback(hijack, linkmap, name, ((unsigned long)(linkmap->l_addr) + libsym->st_value), (size_t)(libsym->st_size)) != CONTPROC)
					break;
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
	if (ret)
		return (unsigned long)(funcaddr + (ret - (unsigned long)funcdata));
	
	if (funcdata)
		free(funcdata);
	
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
	
	if ((hijack->linkhead = get_next_linkmap(hijack, find_link_map_addr(hijack))) == NULL)
		return GetErrorCode(hijack);
	
	return SetError(hijack, ERROR_NONE);
}

unsigned long find_func_addr_in_got(HIJACK *hijack, unsigned long addr)
{
	unsigned long got_data;
	unsigned int i;
	
	if (!IsAttached(hijack))
	{
		SetError(hijack, ERROR_NOTATTACHED);
		return 0;
	}
	
	/* XXX Assume that read_data won't error out, possible NULL pointer dereference */
	got_data = *(unsigned long *)read_data(hijack, hijack->pltgot, sizeof(unsigned long));
	i = 1;
	while (got_data > 0)
	{
		if (got_data == addr)
			break;
		if (IsFlagSet(hijack, F_DEBUG_VERBOSE))
			fprintf(stderr, "[*] got[%u]: 0x%08lx\n", i, got_data);
		got_data = *(unsigned long *)read_data(hijack, hijack->pltgot + ((++i) * sizeof(unsigned long)), sizeof(unsigned long));
	}
	
	if (!got_data)
	{
		SetError(hijack, ERROR_NEEDED);
		return 0;
	}
	
	return hijack->pltgot + (i * sizeof(unsigned long));
}