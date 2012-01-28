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
#include "error.h"
#include "misc.h"
#include "hijack_ptrace.h"
#include "hijack_elf.h"
#include "map.h"

unsigned long map_memory(HIJACK *hijack, size_t sz, unsigned long prot, unsigned long flags)
{	
	return map_memory_absolute(hijack, (unsigned long)NULL, sz, prot, flags);
}

unsigned long map_memory_absolute(HIJACK *hijack, unsigned long addr, size_t sz, unsigned long prot, unsigned long flags)
{
	/* XXX mamp_arg_struct is only used in 32bit */
	struct mmap_arg_struct mmap_args;
	
	/* Set up arguments to pass to mmap */
	memset(&mmap_args, 0x00, sizeof(struct mmap_arg_struct));
	mmap_args.addr = addr;
	mmap_args.flags = flags;
	mmap_args.prot = prot;
	mmap_args.len = sz;
	
	return map_memory_args(hijack, sz, &mmap_args);
}

unsigned long map_memory_args(HIJACK *hijack, size_t sz, struct mmap_arg_struct *mmap_args)
{
	REGS regs_backup, *regs;
	int i;
	int err = ERROR_NONE;
	unsigned long ret = (unsigned long)NULL;
	unsigned long addr;
	
	regs = _hijack_malloc(hijack, sizeof(REGS));
	
#if defined(FreeBSD)
    if (ptrace(PTRACE_GETREGS, hijack->pid, regs, NULL) < 0) {
        err = ERROR_SYSCALL;
        goto end;
    }
    memcpy(&regs_backup, regs, sizeof(REGS));

    regs->r_rax = MMAPSYSCALL;
    regs->r_rip = hijack->syscalladdr;
    regs->r_rdi = mmap_args->addr;
    regs->r_rsi = mmap_args->len;
    regs->r_rdx = mmap_args->prot;
    regs->r_r10 = mmap_args->flags;
    regs->r_r8 = -1;
    regs->r_r9 = 0;
    regs->r_rsp -= sizeof(unsigned long);

    if (ptrace(PTRACE_SETREGS, hijack->pid, regs, 0) < 0) {
        err = ERROR_SYSCALL;
        goto end;
    }
    addr = 0;
    write_data(hijack, regs->r_rsp, &addr, sizeof(unsigned long));

#else
	if (ptrace(PTRACE_GETREGS, hijack->pid, NULL, &regs_backup) < 0) {
		err = ERROR_SYSCALL;
		goto end;
	}
	memcpy(regs, &regs_backup, sizeof(REGS));
#endif
	
	#if defined(i686)
		regs->eip = (long)(hijack->syscalladdr);
		regs->eax = MMAPSYSCALL;
		regs->esp -= (sizeof(struct mmap_arg_struct) + (sizeof(struct mmap_arg_struct) % 4));
		regs->ebx = regs->esp;
		addr = regs->esp;
		
		if (ptrace(PTRACE_SETREGS, hijack->pid, NULL, regs) < 0) {
			err = ERROR_SYSCALL;
			goto end;
		}
		
		write_data(hijack, addr, mmap_args, sizeof(struct mmap_arg_struct));
		if (GetErrorCode(hijack) != ERROR_NONE)
		{
			err = GetErrorCode(hijack);
			goto end;
		}
	#elif defined(x86_64)
		regs->rip = hijack->syscalladdr;
		regs->rax = MMAPSYSCALL;
		regs->rdi = mmap_args->addr;
		regs->rsi = mmap_args->len;
		regs->rdx = mmap_args->prot;
		regs->r10 = mmap_args->flags;
		regs->r9 = mmap_args->fd;
		regs->r8 = mmap_args->offset;
		
		if (ptrace(PTRACE_SETREGS, hijack->pid, NULL, regs) < 0) {
			err = ERROR_SYSCALL;
			goto end;
		}
	#endif
	
	/* time to run mmap */
	addr = MMAPSYSCALL;
	while (addr == MMAPSYSCALL) {
#if defined(FreeBSD)
        if (ptrace(PTRACE_SINGLESTEP, hijack->pid, (caddr_t)0, 0) < 0)
            err = ERROR_SYSCALL;
#else
		if (ptrace(PTRACE_SINGLESTEP, hijack->pid, NULL, NULL) < 0)
			err = ERROR_SYSCALL;
#endif
		
		do
		{
			waitpid(hijack->pid, &i, 0);
		} while (!WIFSTOPPED(i));
		
#if defined(FreeBSD)
        ptrace(PTRACE_GETREGS, hijack->pid, regs, 0);
        addr = regs->r_rax;
#else
		ptrace(PTRACE_GETREGS, hijack->pid, NULL, regs);
#endif
		#if defined(i686)
			addr = regs->eax;
		#elif defined(x86_64)
			addr = regs->rax;
			if (IsFlagSet(hijack, F_DEBUG_VERBOSE))
			{
				fprintf(stderr, "[*] rip:\t0x%016lx\n", regs->rip);
				fprintf(stderr, "[*] rax:\t0x%016lx\n", regs->rax);
				fprintf(stderr, "[*] rbx:\t0x%016lx\n", regs->rbx);
				fprintf(stderr, "[*] rcx:\t0x%016lx\n", regs->rcx);
				fprintf(stderr, "[*] rdx:\t0x%016lx\n", regs->rdx);
				fprintf(stderr, "[*] r8:\t0x%016lx\n", regs->r8);
				fprintf(stderr, "[*] r9:\t0x%016lx\n", regs->r9);
				fprintf(stderr, "[*] r10:\t0x%016lx\n", regs->r10);
			}
		#endif
	}
	
	if ((long)addr == -1)
	{
		if (IsFlagSet(hijack, F_DEBUG))
			fprintf(stderr, "[-] Could not map address. Calling mmap failed!\n");
		
#if defined(FreeBSD)
        ptrace(PTRACE_SETREGS, hijack->pid, &regs_backup, 0);
#else
		ptrace(PTRACE_SETREGS, hijack->pid, NULL, &regs_backup);
#endif
		err = ERROR_CHILDERROR;
		goto end;
	}

end:
#if defined(FreeBSD)
    if (ptrace(PTRACE_SETREGS, hijack->pid, &regs_backup, 0) < 0) {
        err = ERROR_SYSCALL;
    }
#else
	if (ptrace(PTRACE_SETREGS, hijack->pid, NULL, &regs_backup) < 0)
		err = ERROR_SYSCALL;
#endif
	
	if (err == ERROR_NONE)
		ret = addr;
	
	free(regs);
	SetError(hijack, err);
	return ret;
}

#if defined(FreeBSD)
int inject_shellcode_freebsd(HIJACK *hijack, unsigned long addr, void *data, size_t sz)
{
    REGS origregs;

    write_data(hijack, addr, data, sz);

    if (ptrace(PTRACE_GETREGS, hijack->pid, &origregs, 0) < 0)
        return SetError(hijack, ERROR_SYSCALL);

    origregs.r_rip = addr;

    if (ptrace(PTRACE_SETREGS, hijack->pid, &origregs, 0) < 0)
        return SetError(hijack, ERROR_SYSCALL);

    return SetError(hijack, ERROR_NONE);
}
#endif

int inject_shellcode(HIJACK *hijack, unsigned long addr, void *data, size_t sz)
{
	REGS origregs;

#if defined(FreeBSD)
    return inject_shellcode_freebsd(hijack, addr, data, sz);
#endif
	
	write_data(hijack, addr, data, sz);
	
	if (ptrace(PTRACE_GETREGS, hijack->pid, NULL, &origregs) < 0)
		return SetError(hijack, ERROR_SYSCALL);
	
	/*
		There's a lot of duplicated logic here for x86 and x86_64.
		It used to be unified, but it looked ugly, so I seperated it out.
	*/
	#if defined(i686)
		origregs.esp -= sizeof(unsigned long);
		if (ptrace(PTRACE_SETREGS, hijack->pid, NULL, &origregs) < 0)
			return SetError(hijack, ERROR_SYSCALL);
		
		write_data(hijack, (unsigned long)(origregs.esp), &(origregs.eip), sizeof(unsigned long));
		origregs.eip = (long)addr;
		
		/*
			EIP might need to be adjusted further, depending on if we interrupted a syscall
			More Info: http://fxr.watson.org/fxr/source/arch/i386/kernel/signal.c?v=linux-2.6#L623
			Link valid on 09 April 2009
		*/
		if (origregs.orig_eax >= 0)
		{
			switch (origregs.eax)
			{
				case -514: /* -ERESTARTNOHAND */
				case -512: /* -ERESTARTSYS */
				case -513: /* -ERESTARTNOINTR */
				case -516: /* -ERESTART_RESTARTBLOCK */
					if (IsFlagSet(hijack, F_DEBUG))
						fprintf(stderr, "[*] Adjusting EIP due to syscall restart.\n");
					
					origregs.eip += strlen(SYSCALLSEARCH);
					break;
			}
		}
	#elif defined(x86_64)
		origregs.rsp -= sizeof(unsigned long);
		if (ptrace(PTRACE_SETREGS, hijack->pid, NULL, &origregs) < 0)
			return SetError(hijack, ERROR_SYSCALL);
		
		if (IsFlagSet(hijack, F_DEBUG_VERBOSE))
			fprintf(stderr, "[*] Pushing RIP: 0x%016lx\n", origregs.rip);
		
		write_data(hijack, origregs.rsp, &(origregs.rip), sizeof(unsigned long));
		origregs.rip = (unsigned long)addr;
		
		/* Above comment about adjusting EIP is valid for x86_64, too. */
		if (origregs.orig_rax >= 0)
		{
			switch (origregs.rax)
			{
				case -514: /* -ERESTARTNOHAND */
				case -512: /* -ERESTARTSYS */
				case -513: /* -ERESTARTNOINTR */
				case -516: /* -ERESTART_RESTARTBLOCK */
					if (IsFlagSet(hijack, F_DEBUG))
						fprintf(stderr, "[*] Adjusting RIP due to syscall restart.\n");
					
					origregs.rip += strlen(SYSCALLSEARCH);
					break;
			}
		}
	#endif
	
	if (ptrace(PTRACE_SETREGS, hijack->pid, NULL, &origregs) < 0)
		return SetError(hijack, ERROR_SYSCALL);
	
	return SetError(hijack, ERROR_NONE);
}
