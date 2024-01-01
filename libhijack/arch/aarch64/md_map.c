/*
 * Copyright (c) 2017-2023, Shawn Webb <shawn.webb@hardenedbsd.org>
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
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include "hijack.h"
#include "hijack_machdep.h"

unsigned long
md_map_memory(HIJACK *hijack, struct mmap_arg_struct *mmap_args)
{
	REGS regs_backup, *regs;
	unsigned long addr, ret;
	register_t stackp;
	int err, status;

	ret = (unsigned long)NULL;
	err = ERROR_NONE;
	
	regs = _hijack_malloc(hijack, sizeof(REGS));
	
	if (ptrace(PT_GETREGS, hijack->pid, (caddr_t)regs, 0) < 0) {
		err = ERROR_SYSCALL;
		goto end;
	}
	memcpy(&regs_backup, regs, sizeof(REGS));

	/* time to run mmap */
	while (ret == (unsigned long)NULL) {
		/*
		 * On arm64, we can't set pc to an arbitrary value
		 * (yet). So we've gotta wait until the application
		 * attempts to make a syscall. This could take a
		 * while depending on what the application is and
		 * does.
		 */
		if (ptrace(PT_TO_SCE, hijack->pid, (caddr_t)1, 0) < 0) {
			perror("ptrace(PT_TO_SCE)");
			err = ERROR_SYSCALL;
			break;
		}

		do {
			waitpid(hijack->pid, &status, 0);
		} while (!WIFSTOPPED(status));

		SetRegister(regs, "syscall", MMAPSYSCALL);
		SetRegister(regs, "arg0", mmap_args->addr);
		SetRegister(regs, "arg1", mmap_args->len);
		SetRegister(regs, "arg2", mmap_args->prot);
		SetRegister(regs, "arg3", mmap_args->flags);
		SetRegister(regs, "arg4", -1); /* fd */
		SetRegister(regs, "arg5", 0); /* offset */

		/*
		 * The terminator isn't needed on amd64, just on
		 * arm64.
		 */
		SetRegister(regs, "terminator", (unsigned long)NULL);

		if (ptrace(PT_SETREGS, hijack->pid, (caddr_t)regs, 0) < 0) {
			perror("ptrace(PT_SETREGS)");
			err = ERROR_SYSCALL;
			goto end;
		}

		if (ptrace(PT_TO_SCX, hijack->pid, (caddr_t)1, 0) < 0) {
			perror("ptrace(PT_TO_SCX)");
			err = ERROR_SYSCALL;
			break;
		}

		do {
			waitpid(hijack->pid, &status, 0);
		} while (!WIFSTOPPED(status));

		ptrace(PT_GETREGS, hijack->pid, (caddr_t)regs, 0);
		ret = GetRegister(regs, "ret");
	}

	if (err != ERROR_NONE) {
		ptrace(PT_SETREGS, hijack->pid, (caddr_t)(&regs_backup), 0);
		goto end;
	}
	
	if ((long)ret == -1) {
		if (IsFlagSet(hijack, F_DEBUG))
			fprintf(stderr, "[-] Could not map address. Calling mmap failed!\n");
		
		ptrace(PT_SETREGS, hijack->pid, (caddr_t)(&regs_backup), 0);
		err = ERROR_CHILDERROR;
		goto end;
	}

end:
	if (ptrace(PT_SETREGS, hijack->pid, (caddr_t)(&regs_backup), 0) < 0)
		err = ERROR_SYSCALL;
	
	free(regs);
	SetError(hijack, err);
	return (ret);
}
