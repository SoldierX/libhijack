#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
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
#include "so.h"

SO *load_shared_object(HIJACK *hijack, const char *filename)
{
	SO *so;
	
	so = _hijack_malloc(hijack, sizeof(SO));
	if (!(so))
		return NULL;
	
	if (stat(filename, &(so->sb)) < 0)
		return NULL;
	
	so->fd = open(filename, O_RDONLY);
	if (so->fd < 0)
		return NULL;
	
	so->parent_map.p = mmap(NULL, so->sb.st_size, PROT_READ, MAP_ANON | MAP_SHARED, so->fd, 0);
	if (so->parent_map.p == NULL)
		return NULL;
	
	so->ehdr = (ElfW(Ehdr) *)(so->parent_map.p);
	so->phdr = (ElfW(Phdr) *)(so->parent_map.addr + so->ehdr->e_phoff);
	
	/*
	 * Steps (WARNING, may not be correct):
	 *   1) Loop through Program Headers
	 *      a) Find loadables
	 *      b) Map loadables
	 *   2) Find relocs
	 *      a) Do some cool math
	 *      b) Can we rely on the RTLD after mapping/relocs are done?
	 *      c) If so, job is done
	 *      d) If not, perform relocs
	 *   3) Call init routines
	 *   4) Hijack!
	 */
	 
	prepare_maps(hijack, so);
	
	return so;
}

int prepare_maps(HIJACK *hijack, SO *so)
{
	unsigned int i;
	ElfW(Phdr) *phdr;
	
	for (i = 0; i < so->ehdr->e_phnum; i++)
	{
		phdr = &(so->phdr[i]);
	}
	
	return 0;
}
