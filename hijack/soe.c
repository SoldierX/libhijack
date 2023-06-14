/*
 * Copyright (c) 2018, Shawn Webb
 * All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include <sys/types.h>
#include <sys/mman.h>

#include "hijack.h"
#include "hijack_prog.h"

static void
fetch_and_print_string(HIJACK *ctx, char *prefix, void *addr)
{
	char *str;

	str = ReadString(ctx, (unsigned long)addr);
	printf("[SOE] %s (0x%016lx): %s\n", prefix,
	    (unsigned long)addr, str ? str : "[NULL]");
	if (str)
		free(str);
}

static void
fetch_and_print_addr(HIJACK *ctx, char *prefix, void *addr)
{
	unsigned long data;

	data = 0;
	if (ReadData(ctx, (unsigned long)addr, (unsigned char *)&data,
	    sizeof(unsigned long))) {
		printf("[SOE] %s: [ERROR (%s)]\n", prefix,
		    GetErrorString(ctx));
	} else {
		printf("[SOE] %s: 0x%016lx\n", prefix, data);
	}
}

CBRESULT
iterate_object_entries(HIJACK *ctx, Obj_Entry *soe)
{

	/*
	 * This list is in the same order as the Obj_Entry structure.
	 * Keep it that way.
	 *
	 * TODO: Loop through the arrays and the sub-objects.
	 */
	printf("------------------------\n");
	fetch_and_print_string(ctx, "path", soe->path);
	fetch_and_print_string(ctx, "origin path", soe->origin_path);
	printf("[SOE] refcount: %d\n", soe->refcount);
	printf("[SOE] holdcount: %d\n", soe->holdcount);
	printf("[SOE] dl_refcount: %d\n", soe->dl_refcount);
	printf("[SOE] mapbase: 0x%016lx\n",
	    (unsigned long)(soe->mapbase));
	printf("[SOE] mapsize: %zu\n", soe->mapsize);
	printf("[SOE] vaddrbase: 0x%016lx\n", soe->vaddrbase);
	printf("[SOE] relocbase: 0x%016lx\n",
	    (unsigned long)(soe->relocbase));
	printf("[SOE] dynamic: 0x%016lx\n",
	    (unsigned long)(soe->dynamic));
	printf("[SOE] entry: 0x%016lx\n",
	    (unsigned long)(soe->entry));
	printf("[SOE] phdr: 0x%016lx\n",
	    (unsigned long)(soe->phdr));
	printf("[SOE] phsize: %zu\n", soe->phsize);
	fetch_and_print_string(ctx, "interp", (void *)(soe->interp));
	printf("[SOE] stack_flags: %x\n", soe->stack_flags);
	printf("[SOE] tlsindex: %d\n", soe->tlsindex);
	printf("[SOE] tlsinit: 0x%016lx\n",
	    (unsigned long)(soe->tlsinit));
	printf("[SOE] tlsinitsize: %zu\n", soe->tlsinitsize);
	printf("[SOE] tlssize: %zu\n", soe->tlssize);
	printf("[SOE] tlsoffset: %zu\n", soe->tlsoffset);
	printf("[SOE] tlsalign: %zu\n", soe->tlsalign);
	printf("[SOE] relro_page: 0x%016lx\n",
	    (unsigned long)(soe->relro_page));
	printf("[SOE] relro_size: %zu\n", soe->relro_size);
	printf("[SOE] pltgot: 0x%016lx\n",
	    (unsigned long)(soe->pltgot));
	printf("[SOE] rel: 0x%016lx\n", (unsigned long)(soe->rel));
	printf("[SOE] relsize: %zu\n", soe->relsize);
	printf("[SOE] rela: 0x%01lx\n", ((unsigned long)(soe->rela)));
	printf("[SOE] relasize: %zu\n", soe->relasize);
	printf("[SOE] pltrel: 0x%016lx\n",
	    (unsigned long)(soe->pltrel));
	printf("[SOE] pltrelsize: %zu\n", soe->pltrelsize);
	printf("[SOE] pltrela: 0x%016lx\n",
	    (unsigned long)(soe->pltrela));
	printf("[SOE] pltrelasize: %zu\n", soe->pltrelasize);
	printf("[SOE] symtab: 0x%016lx\n",
	    (unsigned long)(soe->symtab));
	printf("[SOE] strtab: 0x%016lx\n",
	    (unsigned long)(soe->strtab));
	printf("[SOE] strsize: %lu\n", soe->strsize);
	printf("[SOE] verneed: 0x%016lx\n",
	    (unsigned long)(soe->verneed));
	printf("[SOE] verneednum: %d\n", soe->verneednum);
	printf("[SOE] verdef: 0x%016lx\n",
	    (unsigned long)(soe->verdef));
	printf("[SOE] verdefnum: %d\n", soe->verdefnum);
	printf("[SOE] versyms: 0x%016lx\n",
	    (unsigned long)(soe->versyms));
	printf("[SOE] buckets: 0x%016lx\n",
	    (unsigned long)(soe->buckets));
	printf("[SOE] nbuckets: %lu\n", soe->nbuckets);
	printf("[SOE] chains: 0x%016lx\n",
	    (unsigned long)(soe->chains));
	printf("[SOE] nchains: %lu\n", soe->nchains);
	printf("[SOE] nbuckets_gnu: %d\n", soe->nbuckets_gnu);
	printf("[SOE] symndx_gnu: %d\n", soe->symndx_gnu);
	printf("[SOE] maskwords_bm_gnu: %d\n", soe->maskwords_bm_gnu);
	printf("[SOE] shift2_gnu: %d\n", soe->shift2_gnu);
	printf("[SOE] dynsymcount: %d\n", soe->dynsymcount);
	printf("[SOE] bloom_gnu: 0x%016lx\n",
	    (unsigned long)(soe->bloom_gnu));
	printf("[SOE] buckets_gnu: 0x%016lx\n",
	    (unsigned long)(soe->buckets_gnu));
	printf("[SOE] chain_zero_gnu: 0x%016lx\n",
	    (unsigned long)(soe->chain_zero_gnu));
	fetch_and_print_string(ctx, "rpath", (void *)(soe->rpath));
	fetch_and_print_string(ctx, "runpath", (void *)(soe->runpath));
	printf("[SOE] needed: 0x%016lx\n",
	    (unsigned long)(soe->needed));
	printf("[SOE] needed_filtees: 0x%016lx\n",
	    (unsigned long)(soe->needed_filtees));
	printf("[SOE] needed_aux_filtees: 0x%016lx\n",
	    (unsigned long)(soe->needed_aux_filtees));
	/* XXX names */
	printf("[SOE] vertab: 0x%016lx\n",
	    (unsigned long)(soe->vertab));
	printf("[SOE] vernum: %d\n", soe->vernum);
	printf("[SOE] init: 0x%016lx\n",
	    (unsigned long)(soe->init));
	printf("[SOE] fini: 0x%016lx\n",
	    (unsigned long)(soe->fini));
	printf("[SOE] preinit_array: 0x%016lx\n",
	    (unsigned long)(soe->preinit_array));
	printf("[SOE] init_array: 0x%016lx\n",
	    (unsigned long)(soe->init_array));
	printf("[SOE] fini_array: 0x%016lx\n",
	    (unsigned long)(soe->fini_array));
	printf("[SOE] preinit_array_num: %d\n",
	    soe->preinit_array_num);
	printf("[SOE] init_array_num: %d\n", soe->init_array_num);
	printf("[SOE] fini_array_num: %d\n", soe->fini_array_num);
	printf("[SOE] osrel: %d\n", soe->osrel);
	printf("[SOE] mainprog: %s\n", soe->mainprog ? "true" :
	    "false");
	printf("[SOE] rtld: %s\n", soe->rtld ? "true" :
	    "false");
	printf("[SOE] relocated: %s\n", soe->relocated ? "true" :
	    "false");
	printf("[SOE] ver_checked: %s\n", soe->ver_checked ? "true" :
	    "false");
	printf("[SOE] textrel: %s\n", soe->textrel ? "true" :
	    "false");
	printf("[SOE] symbolic: %s\n", soe->symbolic ? "true" :
	    "false");
	printf("[SOE] bind_now: %s\n", soe->bind_now ? "true" :
	    "false");
	printf("[SOE] traced: %s\n", soe->traced ? "true" :
	    "false");
	printf("[SOE] jmpslots_done: %s\n", soe->jmpslots_done ?
	    "true" : "false");
	printf("[SOE] init_done: %s\n", soe->init_done ? "true" :
	    "false");
	printf("[SOE] phdr_alloc: %s\n", soe->phdr_alloc ? "true" :
	    "false");
	printf("[SOE] z_origin: %s\n", soe->z_origin ? "true" :
	    "false");
	printf("[SOE] z_nodelete: %s\n", soe->z_nodelete ? "true" :
	    "false");
	printf("[SOE] z_noopen: %s\n", soe->z_noopen ? "true" :
	    "false");
	printf("[SOE] z_loadfltr: %s\n", soe->z_loadfltr ? "true" :
	    "false");
	printf("[SOE] z_interpose: %s\n", soe->z_interpose ? "true" :
	    "false");
	printf("[SOE] z_nodeflib: %s\n", soe->z_nodeflib ? "true" :
	    "false");
	printf("[SOE] z_global: %s\n", soe->z_global ? "true" :
	    "false");
	printf("[SOE] ref_nodel: %s\n", soe->ref_nodel ? "true" :
	    "false");
	printf("[SOE] init_scanned: %s\n", soe->init_scanned ? "true" :
	    "false");
	printf("[SOE] on_fini_list: %s\n", soe->on_fini_list ? "true" :
	    "false");
	printf("[SOE] dag_inited: %s\n", soe->dag_inited ? "true" :
	    "false");
	printf("[SOE] filtees_loaded: %s\n", soe->filtees_loaded ?
	    "true" : "false");
	printf("[SOE] irelative: %s\n", soe->irelative ? "true" :
	    "false");
	printf("[SOE] gnu_ifunc: %s\n", soe->gnu_ifunc ? "true" :
	    "false");
	printf("[SOE] non_plt_gnu_ifunc: %s\n",
	    soe->non_plt_gnu_ifunc ? "true" : "false");
	printf("[SOE] crt_no_init: %s\n", soe->crt_no_init ? "true" :
	    "false");
	printf("[SOE] valid_hash_sysv: %s\n", soe->valid_hash_sysv ?
	    "true" : "false");
	printf("[SOE] valid_hash_gnu: %s\n", soe->valid_hash_gnu ?
	    "true" : "false");
	printf("[SOE] dlopened: %s\n", soe->dlopened ? "true" :
	    "false");
	printf("[SOE] marker: %s\n", soe->marker ? "true" :
	    "false");
	printf("[SOE] unholdfree: %s\n", soe->unholdfree ? "true" :
	    "false");
	printf("[SOE] doomed: %s\n", soe->doomed ? "true" :
	    "false");
	/* XXX linkmap */
	/* XXX objlist dldags */
	/* XXX dagmembers */
	/* XXX dev */
	/* XXX ino */
	printf("[SOE] priv: 0x%016lx\n",
	    (unsigned long)(soe->priv));
	return (CONTPROC);
}
