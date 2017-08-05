/*
 * Copyright (c) 2017, Shawn Webb
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

#if !defined(_HIJACK_H)
#define _HIJACK_H

#include <sys/types.h>
#include <elf.h>
#include <link.h>

#include <machine/reg.h>
#include "rtld.h"

#if defined(amd64)
#define	BASEADDR	0x00400000
#define	SYSCALLSEARCH	"\x0f\x05"
#define	MMAPSYSCALL	477
#else
#error Unsupported architecture
#endif

#define ElfW(type) __ElfN(type)

#define REGS    struct reg

#define EXPORTED_SYM __attribute__((visibility("default")))

#define	ERROR_NONE			0
#define	ERROR_ATTACHED			1
#define	ERROR_NOTATTACHED		2
#define	ERROR_BADPID			3
#define	ERROR_SYSCALL			4
#define	ERROR_NOTIMPLEMENTED		5
#define	ERROR_BADARG			6
#define	ERROR_CHILDERROR		7
#define	ERROR_NEEDED			8

#define	F_NONE			0
#define	F_DEBUG			1
#define	F_DEBUG_VERBOSE		2

#define	V_NONE		0
#define	V_BASEADDR	1

typedef enum _rtld_sym_type { RTLD_SYM_UNKNOWN=0, RTLD_SYM_VAR=1, RTLD_SYM_FUNC=2 } RTLD_SYM_TYPE;

typedef struct _rtld_sym {
    RTLD_SYM_TYPE type;
    char *name; /* Not guarantee to be non-NULL */

    union {
        void *vp;
        unsigned long ulp;
    } p;

    size_t sz;
} RTLD_SYM;

typedef struct _func
{
	char *libname;
	char *name;
	unsigned long vaddr;
	size_t sz;

	struct _func *next;
} FUNC;

typedef struct _plt {
	char *libname;

	union {
		void *raw;
		unsigned char *buf;
		unsigned long ptr;
	} p;

	struct _plt *next;
} PLT;

typedef struct _hijack {
	char *version;
	int pid;
	int lastErrorCode;
	bool isAttached;
	unsigned int flags;
	
	unsigned long baseaddr;
	
	union {
		void *raw;
		unsigned char *buf;
		ElfW(Ehdr) *ehdr;
	} ehdr;
	
	union {
		void *raw;
		unsigned char *buf;
		ElfW(Phdr) *phdr;
	} phdr;
	
	REGS *backup_regs;
	
	unsigned long pltgot;
	struct link_map *linkhead;
	
	unsigned long syscalladdr;
	struct _func *funcs;
	
	/* Because of the limitations of the current API, we need to store the uncached funcs here */
	struct _func *uncached_funcs;

    /* FreeBSD uses struct Struct_Obj_Entry along with struct link_map */
    Obj_Entry *soe;
} HIJACK;

struct mmap_arg_struct {
	unsigned long addr;
	unsigned long len;
	unsigned long prot;
	unsigned long flags;
	unsigned long fd;
	unsigned long offset;
};

typedef enum _cbresult { NONE=0, CONTPROC=1, TERMPROC=2 } CBRESULT;

/* params: &HIJACK, &linkmap, name, vaddr, size */
typedef CBRESULT (*linkmap_callback)(struct _hijack *, void *, char *, unsigned long, size_t);

int GetErrorCode(HIJACK *);
const char *GetErrorString(HIJACK *);
HIJACK *InitHijack(void);
bool IsFlagSet(HIJACK *, unsigned int);
int ToggleFlag(HIJACK *, unsigned int);
void *GetValue(HIJACK *, int);
int SetValue(HIJACK *, int, void *);
bool IsAttached(HIJACK *);
int AssignPid(HIJACK *, pid_t);
int Attach(HIJACK *);
int Detach(HIJACK *);
int LocateSystemCall(HIJACK *);
int ReadData(HIJACK *, unsigned long, unsigned char *, size_t);
int WriteData(HIJACK *, unsigned long , unsigned char *, size_t);
unsigned long MapMemory(HIJACK *, unsigned long, size_t, unsigned long, unsigned long);
int InjectShellcode(HIJACK *, unsigned long, void *, size_t);
REGS *GetRegs(HIJACK *);
int SetRegs(HIJACK *, REGS *);

unsigned long FindFunctionInGot(HIJACK *, unsigned long, unsigned long);
int load_library(HIJACK *, char *);

int LocateAllFunctions(HIJACK *);
FUNC *FindAllFunctionsByName(HIJACK *, char *, bool);
FUNC *FindAllFunctionsByLibraryName_uncached(HIJACK *, char *);
FUNC *FindAllFunctionsByLibraryName(HIJACK *, char *);
FUNC *FindFunctionInLibraryByName(HIJACK *hijack, char *, char *);
PLT *GetAllPLTs(HIJACK *);

RTLD_SYM *resolv_rtld_sym(HIJACK *, char *);

void ClearError(HIJACK *);

#ifdef HIJACK_INTERNAL
int init_elf_headers(HIJACK *);
unsigned long find_pltgot(struct _hijack *);
unsigned long find_link_map_addr(HIJACK *);
void freebsd_parse_soe(HIJACK *, struct Struct_Obj_Entry *, linkmap_callback);
CBRESULT syscall_callback(HIJACK *, void *, char *, unsigned long, size_t);
unsigned long search_mem(HIJACK *, unsigned long, size_t, void *, size_t);
int init_hijack_system(HIJACK *);
unsigned long find_func_addr_in_got(HIJACK *, unsigned long, unsigned long);

int SetError(HIJACK *, int);

unsigned long map_memory(HIJACK *, size_t, unsigned long, unsigned long);
unsigned long map_memory_absolute(HIJACK *, unsigned long, size_t, unsigned long, unsigned long);
unsigned long map_memory_args(HIJACK *, size_t, struct mmap_arg_struct *);
int inject_shellcode_freebsd(HIJACK *, unsigned long, void *, size_t);
int inject_shellcode(HIJACK *, unsigned long, void *, size_t);

void *_hijack_malloc(HIJACK *, size_t);
void _hijack_free(HIJACK *, void *, size_t);

unsigned long find_rtld_linkmap(HIJACK *);

void *read_data(struct _hijack *, unsigned long, size_t);
char *read_str(struct _hijack *, unsigned long);
int write_data(struct _hijack *, unsigned long, void *, size_t);
#endif /* HIJACK_INTERNAL */

#endif
