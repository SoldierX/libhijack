#define _BSD_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <elf.h>
#include <link.h>

#include "hijack.h"
#include "misc.h"
#include "error.h"
#include "hijack_ptrace.h"
#include "hijack_elf.h"
#include "hijack_func.h"

CBRESULT func_found(HIJACK *, struct link_map *, char *, unsigned long, size_t);
void clean_uncached(HIJACK *);
void free_func(FUNC *);
CBRESULT func_found_uncached(HIJACK *, struct link_map *, char *, unsigned long, size_t);
void print_funcs(FUNC *);

EXPORTED_SYM int LocateAllFunctions(HIJACK *hijack)
{
	struct link_map *linkmap;
	
	if (!IsAttached(hijack))
		return SetError(hijack, ERROR_NOTATTACHED);
	
	linkmap = hijack->linkhead;
	do
	{
		if (!(linkmap))
			break;
		if (IsFlagSet(hijack, F_DEBUG_VERBOSE))
			fprintf(stderr, "[*] Loading from %s\n", read_str(hijack, (unsigned long)linkmap->l_name));
		parse_linkmap(hijack, linkmap, func_found);
	} while ((linkmap = get_next_linkmap(hijack, (unsigned long)(linkmap->l_next))) != NULL);
	
	return SetError(hijack, ERROR_NONE);
}

CBRESULT func_found(HIJACK *hijack, struct link_map *linkmap, char *name, unsigned long vaddr, size_t sz)
{
	FUNC *f;
	
	if (!(linkmap))
		return CONTPROC;
	
	if (hijack->funcs)
	{
		f = hijack->funcs;
		while (f->next != NULL)
			f = f->next;
		
		f->next = _hijack_malloc(hijack, sizeof(FUNC));
		if (!(f->next))
			return TERMPROC;
		f = f->next;
	}
	else
	{
		hijack->funcs = _hijack_malloc(hijack, sizeof(FUNC));
		if (!(hijack->funcs))
			return TERMPROC;
		
		f = hijack->funcs;
	}
	
	f->libname = read_str(hijack, (unsigned long)(linkmap->l_name));
	f->name = strdup(name);
	f->sz = sz;
	f->vaddr = vaddr;
	
	return CONTPROC;
}

EXPORTED_SYM FUNC *FindAllFunctionsByName(HIJACK *hijack, char *name, bool mid)
{
	FUNC *ret=NULL, *f, *b=NULL;
	bool found;
	
	if (!IsAttached(hijack))
		return NULL;
	
	f = hijack->funcs;
	while (f != NULL)
	{
		if (mid)
			found = (strstr(f->name, name) != NULL) ? true : false;
		else
			found = (strcmp(f->name, name) == 0) ? true : false;
		
		if (found)
		{
			if (!(ret))
			{
				ret = _hijack_malloc(hijack, sizeof(FUNC));
				if (!(ret))
					return NULL;
				b = ret;
			}
			else
			{
				ret->next = _hijack_malloc(hijack, sizeof(FUNC));
				if (!(ret->next))
					return b; /* Return what we got */
				ret = ret->next;
			}
			
			memcpy(ret, f, sizeof(FUNC));
			ret->next = NULL;
		}
		
		f = f->next;
	}
	
	return b;
}

EXPORTED_SYM FUNC *FindAllFunctionsByLibraryName(HIJACK *hijack, char *libname)
{
	FUNC *ret=NULL, *f, *b=NULL;
	bool found;
	
	if (!IsAttached(hijack))
		return NULL;
	
	f = hijack->funcs;
	while (f != NULL)
	{
		found = (strcmp(f->libname, libname) == 0) ? true : false;
		
		if (found)
		{
			if (!(ret))
			{
				ret = _hijack_malloc(hijack, sizeof(FUNC));
				if (!(ret))
					return NULL;
				b = ret;
			}
			else
			{
				ret->next = _hijack_malloc(hijack, sizeof(FUNC));
				if (!(ret->next))
					return b; /* Return what we got */
				ret = ret->next;
			}
			
			memcpy(ret, f, sizeof(FUNC));
			ret->next = NULL;
		}
		
		f = f->next;
	}
	
	return b;
}

EXPORTED_SYM FUNC *FindFunctionInLibraryByName(HIJACK *hijack, char *libname, char *funcname)
{
	FUNC *ret=NULL, *next, *prev;
	struct link_map *linkmap;
	char *t_libname;
	
	if (!IsAttached(hijack))
		return NULL;
	
	/*
	 * Do this in two steps:
	 * 1) Cache all functions in libraries that have libname in its name
	 * 2) Remove all functions which are not named funcname
	 * This is really more like partially-caching. However, because of existing APIs, it has to be done this way
	 */
	clean_uncached(hijack);
	linkmap = hijack->linkhead;
	for (linkmap = hijack->linkhead; linkmap != NULL; linkmap = get_next_linkmap(hijack, (unsigned long)(linkmap->l_next)))
	{
		t_libname = read_str(hijack, (unsigned long)(linkmap->l_name));
		
		if (!(t_libname) || !strlen(t_libname) || strstr(t_libname, libname) == NULL)
			continue;
			
		if (IsFlagSet(hijack, F_DEBUG_VERBOSE))
			fprintf(stderr, "[*] Loading from %s\n", t_libname);
		
		parse_linkmap(hijack, linkmap, func_found_uncached);
	}
	
	ret = prev = hijack->uncached_funcs;
	while (ret != NULL)
	{
		next = ret->next;
		if (!(ret->name) || strcmp(ret->name, funcname))
		{
			if (ret == hijack->uncached_funcs)
				hijack->uncached_funcs = prev = next;
			else
				prev->next = next;
			
			free_func(ret);
		}
		else
			prev = ret;
		
		ret = next;
	}
	
	return hijack->uncached_funcs;
}

void clean_uncached(HIJACK *hijack)
{
	FUNC *cur, *next;
	
	if (!(hijack->uncached_funcs))
		return;
	
	cur = hijack->uncached_funcs;
	while (cur)
	{
		next = cur->next;
		
		free_func(cur);
		
		cur = next;
	}
	
	hijack->uncached_funcs = NULL;
}

void free_func(FUNC *f)
{
	if (f->libname)
		free(f->libname);
	if (f->name)
		free(f->name);
	free(f);
}

CBRESULT func_found_uncached(HIJACK *hijack, struct link_map *linkmap, char *name, unsigned long vaddr, size_t sz)
{
	FUNC *f;
	
	if (!(linkmap))
		return CONTPROC;
	
	if (hijack->uncached_funcs)
	{
		f = hijack->uncached_funcs;
		while (f->next != NULL)
			f = f->next;
		
		f->next = _hijack_malloc(hijack, sizeof(FUNC));
		if (!(f->next))
			return TERMPROC;
		f = f->next;
	}
	else
	{
		hijack->uncached_funcs = _hijack_malloc(hijack, sizeof(FUNC));
		if (!(hijack->uncached_funcs))
			return TERMPROC;
		
		f = hijack->uncached_funcs;
	}
	
	f->libname = read_str(hijack, (unsigned long)(linkmap->l_name));
	f->name = strdup(name);
	f->sz = sz;
	f->vaddr = vaddr;
	
	return CONTPROC;
}

void print_funcs(FUNC *f)
{
	while (f != NULL)
	{
		fprintf(stderr, "[*] %s\n", f->libname);
		fprintf(stderr, "    [+] %s\n", f->name);
		fprintf(stderr, "    [+] 0x%08lx\n", f->vaddr);
		
		f = f->next;
	}
}
