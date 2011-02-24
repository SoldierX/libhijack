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
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <dlfcn.h>

#include <elf.h>
#include <link.h>

#include "hijack.h"
#include "error.h"
#include "misc.h"
#include "hijack_ptrace.h"
#include "map.h"
#include "hijack_elf.h"
#include "so.h"
#include "hijack_func.h"

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

EXPORTED_SYM int LoadSharedObjectViaDlopen(HIJACK *hijack, const char *filename)
{
	unsigned long dlopen_addr=(unsigned long)NULL;
	struct user_regs_struct regs, *regs_backup;
	size_t len;
	FUNC *funcs;
	void *data;
	unsigned long dlopen_flags=RTLD_NOW, dlopen_filename;
	
	if (!IsAttached(hijack))
		return SetError(hijack, ERROR_NOTATTACHED);
	
	if (!(hijack->funcs))
	{
		funcs = FindFunctionInLibraryByName(hijack, "/lib/libdl.so.2", "dlopen");
		if (!(funcs))
			return SetError(hijack, ERROR_NEEDED);
		
		dlopen_addr = funcs->vaddr;
	}
	else
	{
		funcs = FindAllFunctionsByName(hijack, "dlopen", false);
		if (!(funcs))
			return SetError(hijack, ERROR_NEEDED);
		
		dlopen_addr = funcs->vaddr;
	}
	
	LocateAllFunctions(hijack);
	LocateSystemCall(hijack);
	
	if (dlopen_addr == (unsigned long)NULL)
		return SetError(hijack, ERROR_NEEDED);
	
	regs_backup = GetRegs(hijack);
	memcpy(&regs, regs_backup, sizeof(struct user_regs_struct));
	
	fprintf(stderr, "[*] before MapMemory is called\n");
	dlopen_filename = MapMemory(hijack, (unsigned long)NULL, 4096, MAP_ANONYMOUS | MAP_SHARED, PROT_READ);
	fprintf(stderr, "[*] dlopen_filename: 0x%08lx\n", dlopen_filename);
	
	WriteData(hijack, dlopen_filename, (unsigned char *)filename, strlen(filename));
	
	len = sizeof(unsigned long); /* Return address */
	len += sizeof(unsigned long); /* Address of filename */
	len += sizeof(unsigned long); /* dlopen flags */
	
	data = _hijack_malloc(hijack, len);
	
	memcpy(data+(sizeof(unsigned long)*2), &(regs.eip), sizeof(unsigned long));
	memcpy(data+(sizeof(unsigned long)), &dlopen_filename, sizeof(unsigned long));
	memcpy(data, &dlopen_flags, sizeof(unsigned long));
	
	regs.esp -= len;
	fprintf(stderr, "[*] esp: 0x%08lx\n", regs.esp);
	regs.eip = dlopen_addr;
	
	if (regs.orig_eax >= 0)
	{
		switch (regs.eax)
		{
			case -514: /* -ERESTARTNOHAND */
			case -512: /* -ERESTARTSYS */
			case -513: /* -ERESTARTNOINTR */
			case -516: /* -ERESTART_RESTARTBLOCK */
				regs.eip += strlen(SYSCALLSEARCH);
				break;
		}
	}
	
	SetRegs(hijack, &regs);
	WriteData(hijack, regs.esp, data, len);
	
	return SetError(hijack, ERROR_NONE);
}
