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

#if !defined(_HIJACK_ELF_H)
#define _HIJACK_ELF_H

#if defined(FreeBSD)
    #if defined(amd64)
        #define BASEADDR 0x00400000
        #define SYSCALLSEARCH "\x0f\x05"
        #define MMAPSYSCALL 477
    #endif
#elif defined(Linux)
    #if defined(i686)
    	#define BASEADDR 0x08048000
    	#define SYSCALLSEARCH "\xcd\x80"
    	#define MMAPSYSCALL 90
    #elif defined(x86_64)
    	#define BASEADDR 0x00400000
    	#define SYSCALLSEARCH "\x0f\x05"
    	/* #define SYSCALLSEARCH "\xcd\x80" */
    	#define MMAPSYSCALL 9
    #else
    	#error "Architecture not supported!"
    #endif
#endif

struct _hijack;

typedef enum _cbresult { NONE=0, CONTPROC=1, TERMPROC=2 } CBRESULT;

/* params: &HIJACK, &linkmap, name, vaddr, size */
typedef CBRESULT (*linkmap_callback)(struct _hijack *, void *, char *, unsigned long, size_t);

int init_elf_headers(HIJACK *);
unsigned long find_pltgot(struct _hijack *);
unsigned long find_link_map_addr(HIJACK *);
struct link_map *get_next_linkmap(HIJACK *, unsigned long);
void freebsd_parse_soe(HIJACK *, struct Struct_Obj_Entry *, linkmap_callback);
void parse_linkmap(HIJACK *, struct link_map *, linkmap_callback);
unsigned long search_mem(HIJACK *, unsigned long, size_t, void *, size_t);

CBRESULT syscall_callback(HIJACK *, void *, char *, unsigned long, size_t);

int init_hijack_system(HIJACK *);

unsigned long find_func_addr_in_got(HIJACK *, unsigned long, unsigned long);
#endif
