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
 
#define _BSD_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <elf.h>
#include <link.h>

#include "hijack.h"

static void clean_uncached(HIJACK *);
static void free_func(FUNC *);
static void print_funcs(FUNC *);

static CBRESULT func_found_uncached(HIJACK *, void *, unsigned char,
    char *, unsigned long, size_t);
static CBRESULT func_found(HIJACK *, void *, unsigned char, char *,
    unsigned long, size_t);

/**
 * Find and cache all dynamically loaded functions in process
 * @param hijack Pointer to the HIJACK instance
 * \ingroup libhijack InjectionPrep
 * \warning This function can take a long time!
 */
EXPORTED_SYM int
LocateAllFunctions(HIJACK *hijack)
{
	Obj_Entry *soe;
	
	if (!IsAttached(hijack)) {
		return SetError(hijack, ERROR_NOTATTACHED);
	}

	soe = hijack->soe;
	do {
		freebsd_parse_soe(hijack, soe, func_found);
		soe = read_data(hijack,
		    (unsigned long)TAILQ_NEXT(soe, next),
		    sizeof(Obj_Entry));
	} while (soe != NULL);
	
	return (SetError(hijack, ERROR_NONE));
}

static CBRESULT
func_found(HIJACK *hijack, void *linkmap, unsigned char symtype,
    char *name, unsigned long vaddr, size_t sz)
{
	FUNC *f;

	if (symtype != STT_FUNC) {
		return (CONTPROC);
	}
	
	if (!(linkmap)) {
		return (CONTPROC);
	}
	
	if (hijack->funcs) {
		f = hijack->funcs;
		while (f->next != NULL)
			f = f->next;
		
		f->next = _hijack_malloc(hijack, sizeof(FUNC));
		if (!(f->next)) {
			return (TERMPROC);
		}

		f = f->next;
	} else {
		hijack->funcs = _hijack_malloc(hijack, sizeof(FUNC));
		if (!(hijack->funcs)) {
			return (TERMPROC);
		}
		
		f = hijack->funcs;
	}

	/* linkmap actually points to an Struct_Obj_Entry struct */
	f->libname = read_str(hijack,
	    (unsigned long)(((Obj_Entry *)linkmap)->path));
	f->name = strdup(name);
	f->sz = sz;
	f->vaddr = vaddr;
	
	return (CONTPROC);
}

/**
 * Get location of the PLT in each dynamically-loaded shared object.
 * @param hijack Pointer to the HIJACk instance
 * \ingroup libhijack InjectionPrep
 */
EXPORTED_SYM PLT *
GetAllPLTs(HIJACK *hijack)
{
	struct Struct_Obj_Entry *soe;
	PLT *plt=NULL, *ret=NULL;

	soe = hijack->soe;
	do {
		if (!(plt)) {
			plt = ret = _hijack_malloc(hijack, sizeof(PLT));
			if (!(plt)) {
				return (NULL);
			}
		} else {
			plt->next = _hijack_malloc(hijack, sizeof(PLT));
			if (!(plt->next)) {
				return (ret);
			}
			plt = plt->next;
		}

		plt->libname = read_str(hijack, (unsigned long)(soe->path));
		plt->p.raw = soe->pltgot;
		soe = read_data(hijack,
		    (unsigned long)TAILQ_NEXT(soe, next),
		    sizeof(Obj_Entry));
	} while (soe != NULL);

	return (ret);
}

/**
 * Find all functions with a given name in a process
 * @param hijack Pointer to the HIJACK instance
 * @param name Name of the function to find
 * @param mid If true, use strstr() to find the name, otherwise use strcmp()
 * \ingroup libhijack InjectionPrep
 * \warning This function requires caching the functions, which can take a long time.
 */
EXPORTED_SYM FUNC *
FindAllFunctionsByName(HIJACK *hijack, char *name, bool mid)
{
	FUNC *ret=NULL, *f, *b=NULL;
	bool found;
	
	if (!IsAttached(hijack)) {
		return (NULL);
	}
	
	f = hijack->funcs;
	while (f != NULL) {
		if (mid)
			found = (strstr(f->name, name) != NULL) ? true : false;
		else
			found = (strcmp(f->name, name) == 0) ? true : false;
		
		if (found) {
			if (!(ret)) {
				ret = _hijack_malloc(hijack,
				    sizeof(FUNC));
				if (!(ret)) {
					return (NULL);
				}
				b = ret;
			} else {
				ret->next = _hijack_malloc(hijack,
				    sizeof(FUNC));
				if (!(ret->next)) {
					/*
					 * XXX We should clean up
					 * properly.
					 */
					return (b);
				}
				ret = ret->next;
			}
			
			memcpy(ret, f, sizeof(FUNC));
			ret->next = NULL;
		}
		
		f = f->next;
	}
	
	return (b);
}

/**
 * Find all dynamically loaded functions in a loaded library
 * @param hijack Pointer to the HIJACK instance
 * @param libname Name of library
 * \ingroup libhijack InjectionPrep
 * \warning This function requires caching the functions, which can take a long time.
 */
EXPORTED_SYM FUNC *
FindAllFunctionsByLibraryName(HIJACK *hijack, char *libname)
{
	FUNC *ret=NULL, *f, *b=NULL;
	bool found;
	
	if (!IsAttached(hijack)) {
		return (NULL);
	}
	
	f = hijack->funcs;
	while (f != NULL) {
		found = (strcmp(f->libname, libname) == 0) ? true : false;
		
		if (found) {
			if (!(ret)) {
				ret = _hijack_malloc(hijack,
				    sizeof(FUNC));
				if (!(ret)) {
					return (NULL);
				}
				b = ret;
			} else {
				ret->next = _hijack_malloc(hijack,
				    sizeof(FUNC));
				if (!(ret->next)) {
					/*
					 * XXX We should clean up
					 * properly.
					 */
					return (b);
				}
				ret = ret->next;
			}
			
			memcpy(ret, f, sizeof(FUNC));
			ret->next = NULL;
		}
		
		f = f->next;
	}
	
	return (b);
}

static FUNC *
FindAllFunctionsByLibraryName_uncached_freebsd(HIJACK *hijack,
    char *libname)
{
	char *t_libname;
	struct Struct_Obj_Entry *soe;

	clean_uncached(hijack);

	soe = hijack->soe;
	do {
		t_libname = read_str(hijack, (unsigned long)(soe->path));
		if (!(t_libname) || strstr(t_libname, libname) == NULL) {
			continue;
		}

		freebsd_parse_soe(hijack, soe, func_found_uncached);

		return (hijack->uncached_funcs);
		soe = read_data(hijack,
		    (unsigned long)TAILQ_NEXT(soe, next),
		    sizeof(Obj_Entry));
	} while (soe != NULL);

	return (NULL);
}

/**
 * Find all dynamically loaded functions in a loaded library
 * @param hijack Pointer to the HIJACK instance
 * @param libname Name of the library
 * \ingroup libhijack InjectionPrep
 * \warning Even though this function doesn't use the cache, it can still take a long time
 */
EXPORTED_SYM FUNC *
FindAllFunctionsByLibraryName_uncached(HIJACK *hijack, char *libname)
{
	
	if (!IsAttached(hijack))
		return NULL;
	
	return (FindAllFunctionsByLibraryName_uncached_freebsd(hijack,
	    libname));
}

static FUNC *
FindFunctionInLibraryByName_freebsd(HIJACK *hijack, char *libname, char *funcname)
{
	FUNC *ret=NULL, *next, *prev;

	FindAllFunctionsByLibraryName_uncached(hijack, libname);

	ret = prev = hijack->uncached_funcs;
	while (ret != NULL) {
		next = ret->next;
		if (!(ret->name) || strcmp(ret->name, funcname)) {
			if (ret == hijack->uncached_funcs)
				hijack->uncached_funcs = prev = next;
			else
				prev->next = next;
			
			free_func(ret);
		} else
			prev = ret;
		
		ret = next;
	}

	return (hijack->uncached_funcs);
}

/**
 * Find a function in a dynamically loaded library
 * @param hijack Pointer to the HIJACK instance
 * @param libname Name of the library
 * @param funcname Name of the function
 * \ingroup libhijack InjectionPrep
 * \warning Even though this function doesn't use the cache, it can still take a long time
 */
EXPORTED_SYM FUNC *
FindFunctionInLibraryByName(HIJACK *hijack, char *libname, char *funcname)
{
	
	if (!IsAttached(hijack))
		return NULL;
	
	return (FindFunctionInLibraryByName_freebsd(hijack, libname,
	    funcname));
}

static void
clean_uncached(HIJACK *hijack)
{
	FUNC *cur, *next;
	
	if (!(hijack->uncached_funcs))
		return;
	
	cur = hijack->uncached_funcs;
	while (cur) {
		next = cur->next;
		free_func(cur);
		cur = next;
	}
	
	hijack->uncached_funcs = NULL;
}

static void
free_func(FUNC *f)
{

	if (f->libname)
		free(f->libname);
	if (f->name)
		free(f->name);
	free(f);
}

static CBRESULT
func_found_uncached(HIJACK *hijack, void *linkmap,
    unsigned char symtype, char *name, unsigned long vaddr, size_t sz)
{
	FUNC *f;

	if (symtype != STT_FUNC) {
		return (CONTPROC);
	}
	
	if (!(linkmap)) {
		return (CONTPROC);
	}
	
	if (hijack->uncached_funcs) {
		f = hijack->uncached_funcs;
		while (f->next != NULL)
			f = f->next;
		
		f->next = _hijack_malloc(hijack, sizeof(FUNC));
		if (!(f->next)) {
			return (TERMPROC);
		}
		f = f->next;
	} else {
		hijack->uncached_funcs = _hijack_malloc(hijack,
		    sizeof(FUNC));
		if (!(hijack->uncached_funcs)) {
			return (TERMPROC);
		}
		
		f = hijack->uncached_funcs;
	}
	
	f->libname = read_str(hijack,
	    (unsigned long)(((Obj_Entry *)linkmap)->path));
	f->name = strdup(name);
	f->sz = sz;
	f->vaddr = vaddr;
	
	return (CONTPROC);
}

static void
print_funcs(FUNC *f)
{

	while (f != NULL) {
		fprintf(stderr, "[*] %s\n", f->libname);
		fprintf(stderr, "    [+] %s\n", f->name);
		fprintf(stderr, "    [+] 0x%08lx\n", f->vaddr);
		
		f = f->next;
	}
}
