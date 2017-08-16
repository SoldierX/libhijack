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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/mman.h>

#include <errno.h>

#include "hijack.h"
#include "hijack_machdep.h"

unsigned long
map_memory(HIJACK *hijack, size_t sz, unsigned long prot, unsigned long flags)
{	

	return (map_memory_absolute(hijack, (unsigned long)NULL, sz, prot, flags));
}

unsigned long
map_memory_absolute(HIJACK *hijack, unsigned long addr, size_t sz, unsigned long prot, unsigned long flags)
{
	/* XXX mamp_arg_struct is only used in 32bit */
	struct mmap_arg_struct mmap_args;
	
	/* Set up arguments to pass to mmap */
	memset(&mmap_args, 0x00, sizeof(struct mmap_arg_struct));
	mmap_args.addr = addr;
	mmap_args.flags = flags;
	mmap_args.prot = prot;
	mmap_args.len = sz;
	
	return (map_memory_args(hijack, sz, &mmap_args));
}

unsigned long
map_memory_args(HIJACK *hijack, size_t sz, struct mmap_arg_struct *mmap_args)
{
	REGS regs_backup, *regs;
	int status;
	int err;
	unsigned long ret;
	unsigned long addr;
	register_t stackp;

	ret = (unsigned long)NULL;
	err = ERROR_NONE;
	
	regs = _hijack_malloc(hijack, sizeof(REGS));
	
	if (ptrace(PT_GETREGS, hijack->pid, (caddr_t)regs, 0) < 0) {
		err = ERROR_SYSCALL;
		goto end;
	}
	memcpy(&regs_backup, regs, sizeof(REGS));

	SetRegister(regs, "syscall", MMAPSYSCALL);
	SetInstructionPointer(regs, hijack->syscalladdr);
	SetRegister(regs, "arg0", mmap_args->addr);
	SetRegister(regs, "arg1", mmap_args->len);
	SetRegister(regs, "arg2", mmap_args->prot);
	SetRegister(regs, "arg3", mmap_args->flags);
	SetRegister(regs, "arg4", -1); /* fd */
	SetRegister(regs, "arg5", 0); /* offset */
	stackp = GetStack(regs) - sizeof(register_t);
	SetStack(regs, stackp);

	if (ptrace(PT_SETREGS, hijack->pid, (caddr_t)regs, 0) < 0) {
		err = ERROR_SYSCALL;
		goto end;
	}

	addr = 0;
	write_data(hijack, stackp, &addr, sizeof(unsigned long));
	
	/* time to run mmap */
	addr = MMAPSYSCALL;
	while (addr == MMAPSYSCALL) {
		if (ptrace(PT_STEP, hijack->pid, (caddr_t)0, 0) < 0)
		err = ERROR_SYSCALL;
		do {
			waitpid(hijack->pid, &status, 0);
		} while (!WIFSTOPPED(status));
			
		ptrace(PT_GETREGS, hijack->pid, (caddr_t)regs, 0);
		addr = GetRegister(regs, "ret");
	}
	
	if ((long)addr == -1) {
		if (IsFlagSet(hijack, F_DEBUG))
			fprintf(stderr, "[-] Could not map address. Calling mmap failed!\n");
		
		ptrace(PT_SETREGS, hijack->pid, (caddr_t)(&regs_backup), 0);
		err = ERROR_CHILDERROR;
		goto end;
	}

end:
	if (ptrace(PT_SETREGS, hijack->pid, (caddr_t)(&regs_backup), 0) < 0)
		err = ERROR_SYSCALL;
	
	if (err == ERROR_NONE)
		ret = addr;
	
	free(regs);
	SetError(hijack, err);
	return (ret);
}

int
inject_shellcode_freebsd(HIJACK *hijack, unsigned long addr, void *data, size_t sz)
{
    REGS origregs;

    if (write_data(hijack, addr, data, sz)) {
	    return (GetErrorCode(hijack));
    }

    if (ptrace(PT_GETREGS, hijack->pid, (caddr_t)(&origregs), 0) < 0)
        return SetError(hijack, ERROR_SYSCALL);

    SetInstructionPointer(&origregs, addr);

    if (ptrace(PT_SETREGS, hijack->pid, (caddr_t)(&origregs), 0) < 0)
        return SetError(hijack, ERROR_SYSCALL);

    return SetError(hijack, ERROR_NONE);
}

int
inject_shellcode(HIJACK *hijack, unsigned long addr, void *data, size_t sz)
{

    return (inject_shellcode_freebsd(hijack, addr, data, sz));
}
