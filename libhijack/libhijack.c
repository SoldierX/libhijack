/*
 * Copyright (c) 2011-2017, Shawn Webb
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
 
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#include <sys/param.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <libprocstat.h>

#include "hijack.h"
#include "hijack_machdep.h"

static int resolve_base_address(HIJACK *);

/**
 * Returns last reported error code
 * @param hijack Pointer to HIJACK instance
 * \ingroup libhijack
 */
EXPORTED_SYM int
GetErrorCode(HIJACK *hijack)
{
	return hijack->lastErrorCode;
}

/**
 * Returns user-friendly error string
 * @param hijack Pointer to HIJACK instance
 * \ingroup libhijack
 */
EXPORTED_SYM const char *
GetErrorString(HIJACK *hijack)
{
	switch (hijack->lastErrorCode) {
	case ERROR_NONE:
		return "No Error";
	case ERROR_ATTACHED:
		return "Already Attached";
	case ERROR_NOTATTACHED:
		return "Not Attached";
	case ERROR_SYSCALL:
		return "System Call Error";
	case ERROR_NOTIMPLEMENTED:
		return "Not Implemented";
	case ERROR_BADARG:
		return "Bad Argument";
	case ERROR_BADPID:
		return "Bad PID";
	case ERROR_CHILDERROR:
		return "Error in Child Process";
	case ERROR_NEEDED:
		return "Needed Object Not Found";
	case ERROR_NOTSUPP:
		return "Not supported";
	default:
		return "Unknown Error";
	}
}

/**
 * Creates and initializes HIJACK instance
 * \ingroup libhijack
 */
EXPORTED_SYM HIJACK *
InitHijack(unsigned int flags)
{
	HIJACK *hijack;
	
	hijack = malloc(sizeof(HIJACK));
	if (!(hijack))
		return NULL;
	
	memset(hijack, 0x00, sizeof(HIJACK));

	if (flags == F_NONE)
		flags = F_DEFAULT;
	
	hijack->version = "0.8.0";
	
	ToggleFlag(hijack, flags);
	
	return (hijack);
}

/**
 * Returns boolean true if flag is set, false if not
 * @param hijack Pointer to HIJACK instance
 * @param flag Flag to check
 * \ingroup libhijack
 */
EXPORTED_SYM bool
IsFlagSet(HIJACK *hijack, unsigned int flag)
{

	return (hijack->flags & flag) == flag;
}

/**
 * Toggle flag on/off
 * @param hijack Pointer to HIJACK instance
 * @param flag Flag to toggle
 * \ingroup libhijack
 */
EXPORTED_SYM int
ToggleFlag(HIJACK *hijack, unsigned int flag)
{

	hijack->flags ^= flag;
	
	return (SetError(hijack, ERROR_NONE));
}

/**
 * Gets libhijack-specific settings
 * @param hijack Pointer to HIJACK instance
 * @param vkey Settings key to get
 * \ingroup libhijack
 */
EXPORTED_SYM void *
GetValue(HIJACK *hijack, int vkey)
{

	switch (vkey) {
	case V_BASEADDR:
		return (&(hijack->baseaddr));
	default:
		return (NULL);
	}
}

/**
 * Sets libhijack-specific settings
 * @param hijack Pointer to HIJACK instance
 * @param vkey Settings key to set
 * @param value Pointer to data containing setting
 * \ingroup libhijack
 */
EXPORTED_SYM int
SetValue(HIJACK *hijack, int vkey, void *value)
{

	switch (vkey) {
	case V_BASEADDR:
		memcpy(&(hijack->baseaddr), value, sizeof(unsigned long));
		return (SetError(hijack, ERROR_NONE));
	default:
		return (SetError(hijack, ERROR_BADARG));
	}
}

/**
 * Returns boolean true if libhijack is attached to a process
 * @param hijack Pointer to HIJACK instance
 * \ingroup libhijack
 */
EXPORTED_SYM bool
IsAttached(HIJACK *hijack)
{

	return (hijack->isAttached);
}

/**
 * Assign PID of process to attach to
 * @param hijack Pointer to HIJACK instance
 * @param pid PID of process
 * \ingroup libhijack
 */
EXPORTED_SYM int
AssignPid(HIJACK *hijack, pid_t pid)
{

	if (IsAttached(hijack))
		return (SetError(hijack, ERROR_ATTACHED));
	
	if (pid <= 1)
		return (SetError(hijack, ERROR_BADPID));
	
	hijack->pid = pid;
	
	return (SetError(hijack, ERROR_NONE));
}

/**
 * Attach to process
 * @param hijack Pointer to HIJACK instance
 * \ingroup libhijack
 */
EXPORTED_SYM int
Attach(HIJACK *hijack)
{
	int status;
	
	if (IsAttached(hijack))
		return (SetError(hijack, ERROR_ATTACHED));
	
	if (hijack->pid <= 1)
		return (SetError(hijack, ERROR_BADPID));
	
	if (IsFlagSet(hijack, F_DEBUG))
		fprintf(stderr, "[*] Attaching...\n");
	
	if (ptrace(PT_ATTACH, hijack->pid, NULL, 0) < 0)
		return (SetError(hijack, ERROR_SYSCALL));
	
	do {
		waitpid(hijack->pid, &status, 0);
	} while (!WIFSTOPPED(status));
	
	hijack->isAttached = true;
	
	hijack->backup_regs = GetRegs(hijack);
	if (init_hijack_system(hijack) != 0)
		return (GetErrorCode(hijack));
	
	if (IsFlagSet(hijack, F_DEBUG))
		fprintf(stderr, "[*] Attached!\n");
	
	return (SetError(hijack, ERROR_NONE));
}

/**
 * Detach from process
 * @param hijack Pointer to HIJACK instance
 * \ingroup libhijack
 */
EXPORTED_SYM int
Detach(HIJACK *hijack)
{
	caddr_t ret;
	REGS *regs;

	if (IsAttached(hijack) == false)
		return SetError(hijack, ERROR_NOTATTACHED);

	ret = (caddr_t)NULL;
	regs = GetRegs(hijack);
	if (regs != NULL) {
		ret = (caddr_t)GetInstructionPointer(regs);
	}
	
	if (ptrace(PT_DETACH, hijack->pid, (caddr_t)1, 0) < 0)
		return SetError(hijack, ERROR_SYSCALL);
	
	hijack->isAttached = false;
	
	return (SetError(hijack, ERROR_NONE));
}

/**
 * Locate where the 32- or 64-bit kernel syscall is
 * @param hijack Pointer to HIJACK instance
 * \ingroup libhijack
 */
EXPORTED_SYM int
LocateSystemCall(HIJACK *hijack)
{
	Obj_Entry *soe, *next;
	
	if (IsAttached(hijack) == false)
		return (SetError(hijack, ERROR_NOTATTACHED));

	if (IsFlagSet(hijack, F_DEBUG))
		fprintf(stderr, "[*] Looking for syscall\n");
	
	soe = hijack->soe;
	do {
		freebsd_parse_soe(hijack, soe, syscall_callback);
		next = TAILQ_NEXT(soe, next);
		if (soe != hijack->soe)
			free(soe);
		if (hijack->syscalladdr != (unsigned long)NULL)
			break;
		soe = read_data(hijack,
		    (unsigned long)next,
		    sizeof(*soe));
	} while (soe != NULL);

	if (hijack->syscalladdr == (unsigned long)NULL) {
		if (IsFlagSet(hijack, F_DEBUG))
			fprintf(stderr, "[-] Could not find the syscall\n");
		return (SetError(hijack, ERROR_NEEDED));
	}

	if (IsFlagSet(hijack, F_DEBUG))
		fprintf(stderr, "[+] syscall found at 0x%016lx\n",
		    hijack->syscalladdr);

	return (SetError(hijack, ERROR_NONE));
}

/**
 * Read data from the process
 * @param hijack Pointer to the HIJACK instance
 * @param addr Address from where to read
 * @param buf Buffer to store what was read
 * @param sz How many bytes to read
 * \ingroup libhijack
 */
EXPORTED_SYM int
ReadData(HIJACK *hijack, unsigned long addr, unsigned char *buf, size_t sz)
{
	void *p;
	
	if (!(buf) || !sz)
		return (SetError(hijack, ERROR_BADARG));
	
	if (IsAttached(hijack) == false)
		return (SetError(hijack, ERROR_NOTATTACHED));
	
	p = read_data(hijack, addr, sz);
	
	if (GetErrorCode(hijack) == ERROR_NONE)
		memcpy(buf, p, sz);
	
	if ((p))
		free(p);
	
	/* XXX Assuming hijack->lastErrorCode is successfully set by read_data() */
	return (GetErrorCode(hijack));
}

EXPORTED_SYM char *
ReadString(HIJACK *hijack, unsigned long base)
{

	return (read_str(hijack, base));
}

/**
 * Write data to the process
 * @param hijack Pointer to the HIJACK instance
 * @param addr Address to which the data will be written
 * @param buf Buffer containing the data
 * @param sz Number of bytes to write
 * \ingroup libhijack
 */
EXPORTED_SYM int
WriteData(HIJACK *hijack, unsigned long addr, unsigned char *buf, size_t sz)
{

	if (!(buf) || !sz)
		return (SetError(hijack, ERROR_BADARG));
	
	if (IsAttached(hijack) == false)
		return (SetError(hijack, ERROR_NOTATTACHED));
	
	return (write_data(hijack, addr, buf, sz));
}

/**
 * Create a new mapping inside a process
 * @param hijack Pointer to the HIJACK instance
 * @param addr Address of the newly created mapping
 * @param sz How many bytes to map (needs to be page-aligned)
 * @param prot Memory mapping prot (man mmap)
 * @param flags Memory mapping flags (man mmap)
 * \ingroup libhijack InjectionPrep
 */
EXPORTED_SYM unsigned long
MapMemory(HIJACK *hijack, unsigned long addr, size_t sz, unsigned long prot, unsigned long flags)
{

	if (!IsAttached(hijack))
		return (SetError(hijack, ERROR_NOTATTACHED));
	
	return (map_memory(hijack, addr, sz, prot, flags));
}

EXPORTED_SYM int
InjectShellcodeAndRun(HIJACK *hijack, unsigned long addr, const char *path, bool push_ret)
{
	struct stat sb;
	int err, fd;
	void *map;

	memset(&sb, 0x00, sizeof(sb));
	map = NULL;
	err = ERROR_NONE;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return (SetError(hijack, ERROR_SYSCALL));

	if (fstat(fd, &sb)) {
		err = ERROR_SYSCALL;
		goto error;
	}

	map = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (map == (void *)MAP_FAILED && errno) {
		perror("mmap");
		map = NULL;
		err = ERROR_SYSCALL;
		goto error;
	}

	err = InjectShellcodeFromMemoryAndRun(hijack, addr, map,
	    sb.st_size, push_ret);
error:
	if (map != NULL)
		munmap(map, sb.st_size);
	if (fd >= 0)
		close(fd);
	return (err);
}

EXPORTED_SYM int
InjectShellcodeFromMemoryAndRun(HIJACK *hijack, unsigned long addr,
    void *map, size_t sz, bool push_ret)
{
	REGS *regs;
	int err;
	register_t stackp, retp;

	err = ERROR_NONE;

	regs = GetRegs(hijack);
	if (regs == NULL) {
		perror("GetRegs");
		err = ERROR_SYSCALL;
		goto error;
	}

	if (write_data(hijack, addr, map, sz)) {
		perror("write_data");
		err = GetErrorCode(hijack);
		goto error;
	}

	if (push_ret) {
		stackp = GetStack(regs) - sizeof(register_t);
		err = SetRegs(hijack, regs);
		if (err) {
			perror("SetRegs");
			goto error;
		}

		retp = GetInstructionPointer(regs);
		if (write_data(hijack, (unsigned long)stackp, &retp, sizeof(retp))) {
			perror("write_data(regs)");
			err = ERROR_SYSCALL;
			goto error;
		}
	}

	SetInstructionPointer(regs, addr);
	err = SetRegs(hijack, regs);
	if (err)
		perror("SetRegs(addr)");

error:
	if (regs != NULL)
		free(regs);
	return (SetError(hijack, err));
}

/**
 * Get the CPU registers
 * @param hijack Pointer to the HIJACK instance
 * \ingroup libhijack
 */
EXPORTED_SYM REGS *
GetRegs(HIJACK *hijack)
{
	REGS *ret;
	
	if (!IsAttached(hijack)) {
		SetError(hijack, ERROR_NOTATTACHED);
		return (NULL);
	}
	
	ret = _hijack_malloc(hijack, sizeof(REGS));
	if (!(ret))
		return (NULL);
	
	if (ptrace(PT_GETREGS, hijack->pid, (caddr_t)ret, 0)) {
		SetError(hijack, ERROR_SYSCALL);
		free(ret);
		return (NULL);
	}
	
	return (ret);
}

/**
 * Set the CPU registers
 * @param hijack Pointer to the HIJACK instance
 * @param regs Pointer to the CPU registers struct
 * \ingroup libhijack
 */
EXPORTED_SYM int
SetRegs(HIJACK *hijack, REGS *regs)
{

	if (!IsAttached(hijack))
		return (SetError(hijack, ERROR_NOTATTACHED));
	
	if (ptrace(PT_SETREGS, hijack->pid, (caddr_t)regs, 0) < 0)
		return (SetError(hijack, ERROR_SYSCALL));
	
	return (SetError(hijack, ERROR_NONE));
}

/**
 * Find the location of a function address in the GOT
 * @param hijack Pointer to the HIJACK instance
 * @param pltaddr The location of the PLT/GOT in which to scan for the addr
 * @param addr Address of the function being looked up
 * \ingroup libhijack
 */
EXPORTED_SYM unsigned long
FindFunctionInGot(HIJACK *hijack, unsigned long pltaddr, unsigned long addr)
{

	return (find_func_addr_in_got(hijack, pltaddr, addr));
}

EXPORTED_SYM int
LoadLibrary(HIJACK *hijack, char *lib)
{

	return (load_library(hijack, lib));
}

EXPORTED_SYM int
IterateObjectEntries(HIJACK *hijack, soe_iterator iterator)
{
	Obj_Entry *soe;
	void *next;

	if (!IsAttached(hijack)) {
		return (SetError(hijack, ERROR_NOTATTACHED));
	}

	soe = hijack->soe;
	do {
		switch (iterator(hijack, soe)) {
			case TERMPROC:
				if (soe != hijack->soe)
					free(soe);
				return (0);
			default:
				break;
		}

		next = TAILQ_NEXT(soe, next);
		if (soe != hijack->soe)
			free(soe);
		if (next != NULL)
			soe = read_data(hijack, (unsigned long)next,
			    sizeof(*soe));
		else
			soe = NULL;
	} while (soe != NULL);

	return (0);
}

static int
resolve_base_address(HIJACK *hijack)
{
	struct procstat *ps;
	struct kinfo_proc *p;
	struct kinfo_vmentry *vm;
	unsigned int i, cnt;
	int err;
	ElfW(Ehdr) *ehdr;

	vm = NULL;
	p = NULL;
	err = ERROR_NONE;
	cnt = 0;

	ps = procstat_open_sysctl();
	if (ps == NULL) {
		SetError(hijack, ERROR_SYSCALL);
		return (-1);
	}

	p = procstat_getprocs(ps, KERN_PROC_PID, hijack->pid, &cnt);
	if (cnt == 0) {
		err = ERROR_SYSCALL;
		goto error;
	}

	cnt = 0;
	vm = procstat_getvmmap(ps, p, &cnt);
	if (cnt == 0) {
		err = ERROR_SYSCALL;
		goto error;
	}

	/*
	 * Look for the first memory mapping that contains a valid ELF
	 * header. This overly simplistic algorithm breaks when the
	 * RTLD is used to execute the application (ie:
	 * /libexec/ld-elf.so.1 /bin/ls)
	 *
	 * Making this algorithm more robust is a task to be completed
	 * later, since the vast majority of use cases do not use the
	 * RTLD to execute applications.
	 */

	for (i = 0; i < cnt; i++) {
		if (vm[i].kve_type != KVME_TYPE_VNODE)
			continue;

		ehdr = read_data(hijack,
		    (unsigned long)(vm[i].kve_start),
		    getpagesize());
		if (ehdr == NULL) {
			goto error;
		}
		if (IS_ELF(*ehdr)) {
			hijack->baseaddr = (unsigned long)(vm[i].kve_start);
			break;
		}
		free(ehdr);
	}

	if (hijack->baseaddr == (unsigned long)NULL)
		err = ERROR_NEEDED;

error:
	if (vm != NULL)
		procstat_freevmmap(ps, vm);
	if (p != NULL)
		procstat_freeprocs(ps, p);
	procstat_close(ps);
	return (err);
}

int
init_hijack_system(HIJACK *hijack)
{
	int err;

	if (!IsAttached(hijack))
		return (SetError(hijack, ERROR_NOTATTACHED));

	if ((hijack->flags & F_DYNAMIC_BASEADDR) == F_DYNAMIC_BASEADDR) {
		err = SetError(hijack, resolve_base_address(hijack));
		if (err)
			return (err);
	} else {
		if (hijack->baseaddr == (unsigned long)NULL)
			hijack->baseaddr = BASEADDR;
	}

	if (init_elf_headers(hijack) != 0)
		return (SetError(hijack, ERROR_SYSCALL));

	if ((hijack->pltgot = find_pltgot(hijack)) == (unsigned long)NULL)
		return (GetErrorCode(hijack));
    
	find_link_map_addr(hijack);
	hijack->linkhead = &(hijack->soe->linkmap);

	return (SetError(hijack, ERROR_NONE));
}
