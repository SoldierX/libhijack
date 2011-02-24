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
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#include "hijack.h"
#include "error.h"
#include "misc.h"
#include "hijack_ptrace.h"
#include "map.h"
#include "hijack_elf.h"

/**
 * Returns last reported error code
 * @param hijack Pointer to HIJACK instance
 * \ingroup libhijack
 */
EXPORTED_SYM int GetErrorCode(HIJACK *hijack)
{
	return hijack->lastErrorCode;
}

/**
 * Returns user-friendly error string
 * @param hijack Pointer to HIJACK instance
 * \ingroup libhijack
 */
EXPORTED_SYM const char *GetErrorString(HIJACK *hijack)
{
	switch (hijack->lastErrorCode)
	{
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
		default:
			return "Unknown Error";
	}
}

/**
 * Creates and initializes HIJACK instance
 * \ingroup libhijack
 */
EXPORTED_SYM HIJACK *InitHijack(void)
{
	HIJACK *hijack;
	unsigned long baseaddr = BASEADDR;
	
	hijack = malloc(sizeof(HIJACK));
	if (!(hijack))
		return NULL;
	
	memset(hijack, 0x00, sizeof(HIJACK));
	
	hijack->version = "0.2";
	
	SetValue(hijack, V_BASEADDR, &baseaddr);
	
	return hijack;
}

/**
 * Returns boolean true if flag is set, false if not
 * @param hijack Pointer to HIJACK instance
 * @param flag Flag to check
 * \ingroup libhijack
 */
EXPORTED_SYM bool IsFlagSet(HIJACK *hijack, unsigned int flag)
{
	return (hijack->flags & flag) == flag;
}

/**
 * Toggle flag on/off
 * @param hijack Pointer to HIJACK instance
 * @param flag Flag to toggle
 * \ingroup libhijack
 */
EXPORTED_SYM int ToggleFlag(HIJACK *hijack, unsigned int flag)
{
	hijack->flags ^= flag;
	
	return SetError(hijack, ERROR_NONE);
}

/**
 * Gets libhijack-specific settings
 * @param hijack Pointer to HIJACK instance
 * @param vkey Settings key to get
 * \ingroup libhijack
 */
EXPORTED_SYM void *GetValue(HIJACK *hijack, int vkey)
{
	switch (vkey)
	{
		case V_BASEADDR:
			return &(hijack->baseaddr);
		default:
			return NULL;
	}
}

/**
 * Sets libhijack-specific settings
 * @param hijack Pointer to HIJACK instance
 * @param vkey Settings key to set
 * @param value Pointer to data containing setting
 * \ingroup libhijack
 */
EXPORTED_SYM int SetValue(HIJACK *hijack, int vkey, void *value)
{
	switch (vkey)
	{
		case V_BASEADDR:
			memcpy(&(hijack->baseaddr), value, sizeof(unsigned long));
			return SetError(hijack, ERROR_NONE);
		default:
			return SetError(hijack, ERROR_BADARG);
	}
}

/**
 * Returns boolean true if libhijack is attached to a process
 * @param hijack Pointer to HIJACK instance
 * \ingroup libhijack
 */
EXPORTED_SYM bool IsAttached(HIJACK *hijack)
{
	return hijack->isAttached;
}

/**
 * Assign PID of process to attach to
 * @param hijack Pointer to HIJACK instance
 * @param pid PID of process
 * \ingroup libhijack
 */
EXPORTED_SYM int AssignPid(HIJACK *hijack, pid_t pid)
{
	if (IsAttached(hijack))
		return SetError(hijack, ERROR_ATTACHED);
	
	if (pid <= 1)
		return SetError(hijack, ERROR_BADPID);
	
	hijack->pid = pid;
	
	return SetError(hijack, ERROR_NONE);
}

/**
 * Attach to process
 * @param hijack Pointer to HIJACK instance
 * \ingroup libhijack
 */
EXPORTED_SYM int Attach(HIJACK *hijack)
{
	int status;
	
	if (IsAttached(hijack))
		return SetError(hijack, ERROR_ATTACHED);
	
	if (hijack->pid <= 1)
		return SetError(hijack, ERROR_BADPID);
	
	if (IsFlagSet(hijack, F_DEBUG))
		fprintf(stderr, "[*] Attaching...\n");
	
	if (ptrace(PTRACE_ATTACH, hijack->pid, NULL, NULL) < 0)
		return SetError(hijack, ERROR_SYSCALL);
	
	do
	{
		waitpid(hijack->pid, &status, 0);
	} while (!WIFSTOPPED(status));
	
	hijack->isAttached = true;
	
	hijack->backup_regs = GetRegs(hijack);
	init_hijack_system(hijack);
	
	if (IsFlagSet(hijack, F_DEBUG))
		fprintf(stderr, "[*] Attached!\n");
	
	return SetError(hijack, ERROR_NONE);
}

/**
 * Detach from process
 * @param hijack Pointer to HIJACK instance
 * \ingroup libhijack
 */
EXPORTED_SYM int Detach(HIJACK *hijack)
{
	if (IsAttached(hijack) == false)
		return SetError(hijack, ERROR_NOTATTACHED);
	
	if (ptrace(PTRACE_DETACH, hijack->pid, NULL, NULL) < 0)
		return SetError(hijack, ERROR_SYSCALL);
	
	hijack->isAttached = false;
	
	return SetError(hijack, ERROR_NONE);
}

/**
 * Locate where the 32- or 64-bit kernel syscall is
 * @param hijack Pointer to HIJACK instance
 * \ingroup libhijack
 */
EXPORTED_SYM int LocateSystemCall(HIJACK *hijack)
{
	struct link_map *map;
	
	if (IsAttached(hijack) == false)
		return SetError(hijack, ERROR_NOTATTACHED);
	
	map = hijack->linkhead;
	do
	{
		parse_linkmap(hijack, map, syscall_callback);
		if (hijack->syscalladdr)
			break;
	} while ((map = get_next_linkmap(hijack, (unsigned long)(map->l_next))) != NULL);
	
	return SetError(hijack, ERROR_NONE);
}

/**
 * Read data from the process
 * @param hijack Pointer to the HIJACK instance
 * @param addr Address from where to read
 * @param buf Buffer to store what was read
 * @param sz How many bytes to read
 * \ingroup libhijack
 */
EXPORTED_SYM int ReadData(HIJACK *hijack, unsigned long addr, unsigned char *buf, size_t sz)
{
	void *p;
	
	if (!(buf) || !sz)
		return SetError(hijack, ERROR_BADARG);
	
	if (IsAttached(hijack) == false)
		return SetError(hijack, ERROR_NOTATTACHED);
	
	p = read_data(hijack, addr, sz);
	
	if (GetErrorCode(hijack) == ERROR_NONE)
		memcpy(buf, p, sz);
	
	if ((p))
		free(p);
	
	/* XXX Assuming hijack->lastErrorCode is successfully set by read_data() */
	return GetErrorCode(hijack);
}

/**
 * Write data to the process
 * @param hijack Pointer to the HIJACK instance
 * @param addr Address to which the data will be written
 * @param buf Buffer containing the data
 * @param sz Number of bytes to write
 * \ingroup libhijack
 */
EXPORTED_SYM int WriteData(HIJACK *hijack, unsigned long addr, unsigned char *buf, size_t sz)
{
	if (!(buf) || !sz)
		return SetError(hijack, ERROR_BADARG);
	
	if (IsAttached(hijack) == false)
		return SetError(hijack, ERROR_NOTATTACHED);
	
	return write_data(hijack, addr, buf, sz);
}

/**
 * Create a new mapping inside a process
 * @param hijack Pointer to the HIJACK instance
 * @param addr Address of the newly created mapping
 * @param sz How many bytes to map (needs to be page-aligned)
 * @param flags Memory mapping flags (man mmap)
 * @param prot Memory mapping prot (man mmap)
 * \ingroup libhijack InjectionPrep
 */
EXPORTED_SYM unsigned long MapMemory(HIJACK *hijack, unsigned long addr, size_t sz, unsigned long flags, unsigned long prot)
{
	if (!IsAttached(hijack))
		return SetError(hijack, ERROR_NOTATTACHED);
	
	return map_memory_absolute(hijack, addr, sz, flags, prot);
}

/**
 * Inject arbitrary code
 * @param hijack Pointer to the HIJACK instance
 * @param addr Address in which to write the arbitrary code
 * @param data The code to be written
 * @param sz Number of bytes to write
 * \ingroup libhijack
 */
EXPORTED_SYM int InjectShellcode(HIJACK *hijack, unsigned long addr, void *data, size_t sz)
{
	if (!IsAttached(hijack))
		return SetError(hijack, ERROR_NOTATTACHED);
	
	return inject_shellcode(hijack, addr, data, sz);
}

/**
 * Get the CPU registers
 * @param hijack Pointer to the HIJACK instance
 * \ingroup libhijack
 */
EXPORTED_SYM struct user_regs_struct *GetRegs(HIJACK *hijack)
{
	struct user_regs_struct *ret;
	
	if (!IsAttached(hijack))
	{
		SetError(hijack, ERROR_NOTATTACHED);
		return NULL;
	}
	
	ret = _hijack_malloc(hijack, sizeof(struct user_regs_struct));
	if (!(ret))
		return NULL;
	
	if (ptrace(PTRACE_GETREGS, hijack->pid, NULL, ret) < 0)
	{
		SetError(hijack, ERROR_SYSCALL);
		free(ret);
		return NULL;
	}
	
	return ret;
}

/**
 * Set the CPU registers
 * @param hijack Pointer to the HIJACK instance
 * @param regs Pointer to the CPU registers struct
 * \ingroup libhijack
 */
EXPORTED_SYM int SetRegs(HIJACK *hijack, struct user_regs_struct *regs)
{
	if (!IsAttached(hijack))
		return SetError(hijack, ERROR_NOTATTACHED);
	
	if (ptrace(PTRACE_SETREGS, hijack->pid, NULL, regs) < 0)
		return SetError(hijack, ERROR_SYSCALL);
	
	return SetError(hijack, ERROR_NONE);
}

/**
 * Find the location of a function address in the GOT
 * @param hijack Pointer to the HIJACK instance
 * @param addr Address of the function being looked up
 * \ingroup libhijack
 */
EXPORTED_SYM unsigned long FindFunctionInGot(HIJACK *hijack, unsigned long addr)
{
	return find_func_addr_in_got(hijack, addr);
}
