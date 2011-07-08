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

#if !defined(_HIJACK_H)
#define _HIJACK_H

#include <sys/types.h>
#include <elf.h>
#include <link.h>

#define EXPORTED_SYM __attribute__((visibility("default")))

#define ERROR_NONE				0
#define ERROR_ATTACHED			1
#define ERROR_NOTATTACHED		2
#define ERROR_BADPID			3
#define ERROR_SYSCALL			4
#define ERROR_NOTIMPLEMENTED	5
#define ERROR_BADARG			6
#define ERROR_CHILDERROR		7
#define ERROR_NEEDED			8

#define F_NONE			0
#define F_DEBUG			1
#define F_DEBUG_VERBOSE	2

#define V_NONE		0
#define V_BASEADDR	1

typedef enum _bool {false=0, true=1} bool;

struct _func;

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
	
	union {
		void *raw;
		unsigned char *buf;
		ElfW(Shdr) *shdr;
	} shdr;
	
	struct user_regs_struct *backup_regs;
	
	unsigned long pltgot;
	struct link_map *linkhead;
	
	unsigned long syscalladdr;
	struct _func *funcs;
	
	/* Because of the limitations of the current API, we need to store the uncached funcs here */
	struct _func *uncached_funcs;
} HIJACK;

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
struct user_regs_struct *GetRegs(HIJACK *);
int SetRegs(HIJACK *, struct user_regs_struct *);

unsigned long FindFunctionInGot(HIJACK *, unsigned long, unsigned long);

#endif
