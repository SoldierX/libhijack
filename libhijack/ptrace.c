/*
 * Copyright (c) 2011-2024, Shawn Webb <shawn.webb@hardenedbsd.org>
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
#include <errno.h>

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include "hijack.h"

void *
read_data(HIJACK *hijack, unsigned long start, size_t sz)
{
	struct ptrace_io_desc io;
	void *buf;

	buf = calloc(1, sz);
	if (buf == NULL) {
		SetError(hijack, ERROR_SYSCALL);
		return (NULL);
	}

	io.piod_op = PIOD_READ_D;
	io.piod_offs = (void *)start;
	io.piod_addr = buf;
	io.piod_len = sz;

	if (ptrace(PT_IO, hijack->pid, (caddr_t)&io, 0) < 0) {
		if (IsFlagSet(hijack, F_DEBUG))
			perror("ptrace");
		SetError(hijack, ERROR_SYSCALL);
		free(buf);
		return (NULL);
	}

	if (io.piod_len != sz) {
		if (IsFlagSet(hijack, F_DEBUG))
			perror("ptrace");
		SetError(hijack, ERROR_SYSCALL);
		free(buf);
		return (NULL);
	}

	SetError(hijack, ERROR_NONE);
	return (buf);
}

char *
read_str(HIJACK *hijack, unsigned long base)
{
	char *retval;
	unsigned int bufsz;
	
	bufsz = 1;
	retval = NULL;

	do {
		if (retval)
			free(retval);
		
		retval = read_data(hijack, base, bufsz);
		if (!retval)
			return NULL;
		
	} while (retval[bufsz-1] != 0x00 && ++bufsz);
	
	SetError(hijack, ERROR_NONE);
	return retval;
}

int
write_data(HIJACK *hijack, unsigned long start, void *buf, size_t sz)
{
	struct ptrace_io_desc io;
	int err;

	err = 0;

	io.piod_op = PIOD_WRITE_D;
	io.piod_offs = (void *)start;
	io.piod_addr = buf;
	io.piod_len = sz;

	if (ptrace(PT_IO, hijack->pid, (caddr_t)&io, 0) < 0) {
		err = ERROR_SYSCALL;
	}

	return SetError(hijack, err);
}

EXPORTED_SYM HIJACK_REMOTE_ARGS *
hijack_remote_args_new(HIJACK *hijack, uint64_t flags)
{
	HIJACK_REMOTE_ARGS *args;

	if (hijack == NULL) {
		return (NULL);
	}

	if (!hijack_remote_args_flags_sanity(flags)) {
		return (NULL);
	}

	args = calloc(1, sizeof(*args));
	if (args == NULL) {
		return (NULL);
	}

	args->hra_psr = calloc(1, sizeof(*(args->hra_psr)));
	if (args->hra_psr == NULL) {
		free(args);
		return (NULL);
	}

	args->hra_hijack = hijack;
	args->hra_flags = flags;

	return (args);
}

EXPORTED_SYM void
hijack_remote_args_free(HIJACK_REMOTE_ARGS **argsp, uint64_t free_flags)
{
	HIJACK_REMOTE_ARGS *args;

	if (argsp == NULL || *argsp == NULL) {
		return;
	}

	args = *argsp;
	*argsp = NULL;
	if ((free_flags & HIJACK_REMOTE_FREE_PSR) == HIJACK_REMOTE_FREE_PSR) {
		free(args->hra_psr->pscr_args);
		free(args->hra_psr);
	}
	if ((free_flags & HIJACK_REMOTE_FREE_REGS) ==
	    HIJACK_REMOTE_FREE_REGS) {
		free(args->hra_regs);
	}
	memset(args, 0, sizeof(*args));
	free(args);
}

EXPORTED_SYM int
perform_remote_syscall(HIJACK_REMOTE_ARGS *args)
{
	int status;

	if (args == NULL) {
		return (ERROR_BADARG);
	}
	if (args->hra_psr == NULL) {
		return (SetError(args->hra_hijack, ERROR_NEEDED));
	}

	if (ptrace(PT_TO_SCX, args->hra_hijack->pid, (caddr_t)1, 0) &&
	    errno != EBUSY) {
		return (SetError(args->hra_hijack, ERROR_SYSCALL));
	}

	do {
		status = 0;
		if (waitpid(args->hra_hijack->pid, &status, WNOHANG) < 0) {
			return (SetError(args->hra_hijack, ERROR_SYSCALL));
		}
	} while (!WIFSTOPPED(status));

	if (ptrace(PT_SC_REMOTE, args->hra_hijack->pid,
	    (caddr_t)(args->hra_psr), sizeof(*(args->hra_psr)))) {
		return (SetError(args->hra_hijack, ERROR_SYSCALL));
	}

	if (args->hra_psr->pscr_ret.sr_error) {
		return (SetError(args->hra_hijack, ERROR_CHILDSYSCALL));
	}

	if (ptrace(PT_TO_SCX, args->hra_hijack->pid, (caddr_t)1, 0) &&
	    errno != EBUSY) {
		return (SetError(args->hra_hijack, ERROR_SYSCALL));
	}

	do {
		status = 0;
		if (waitpid(args->hra_hijack->pid, &status, WNOHANG) < 0) {
			return (SetError(args->hra_hijack, ERROR_SYSCALL));
		}
	} while (!WIFSTOPPED(status));

	return (SetError(args->hra_hijack, ERROR_NONE));
}

EXPORTED_SYM bool
hijack_remote_args_flags_sanity(uint64_t flags)
{
	return (flags == 0);
}

EXPORTED_SYM bool
hijack_remote_args_is_flag_set(HIJACK_REMOTE_ARGS *args, uint64_t flag)
{
	if (args == NULL) {
		return (false);
	}

	return ((args->hra_flags & flag) == flag);
}

EXPORTED_SYM uint64_t
hijack_remote_args_get_flags(HIJACK_REMOTE_ARGS *args)
{
	if (args == NULL) {
		return (0);
	}

	return (args->hra_flags);
}

EXPORTED_SYM uint64_t
hijack_remote_args_set_flags(HIJACK_REMOTE_ARGS *args, uint64_t flags)
{
	uint64_t oldflags;

	if (args == NULL) {
		return (0);
	}

	if (!hijack_remote_args_flags_sanity(flags)) {
		return (args->hra_flags);
	}

	oldflags = args->hra_flags;
	args->hra_flags = flags;
	return (oldflags);
}

EXPORTED_SYM uint64_t
hijack_remote_args_set_flag(HIJACK_REMOTE_ARGS *args, uint64_t flag)
{
	uint64_t oldflags;

	if (args == NULL) {
		return (0);
	}

	if (!hijack_remote_args_flags_sanity(args->hra_flags | flag)) {
		return (args->hra_flags);
	}

	oldflags = args->hra_flags;
	args->hra_flags |= flag;
	return (oldflags);
}

EXPORTED_SYM REGS *
hijack_remote_args_get_regs(HIJACK_REMOTE_ARGS *args)
{
	if (args == NULL) {
		return (NULL);
	}

	return (args->hra_regs);
}

EXPORTED_SYM REGS *
hijack_remote_args_set_regs(HIJACK_REMOTE_ARGS *args, REGS *regs,
    bool free_old)
{
	REGS *oldregs;

	if (args == NULL) {
		return (NULL);
	}

	if (free_old) {
		free(args->hra_regs);
		oldregs = NULL;
	} else {
		oldregs = args->hra_regs;
	}

	args->hra_regs = regs;
	return (oldregs);
}

EXPORTED_SYM syscallarg_t *
hijack_remote_args_add_arg(HIJACK_REMOTE_ARGS *args, syscallarg_t arg)
{
	syscallarg_t *newarg;
	void *tmp;

	if (args == NULL) {
		return (NULL);
	}

	tmp = reallocarray(args->hra_psr->pscr_args,
	    args->hra_psr->pscr_nargs + 1, sizeof(arg));
	if (tmp == NULL) {
		return (NULL);
	}
	args->hra_psr->pscr_args = tmp;
	newarg = &(args->hra_psr->pscr_args[args->hra_psr->pscr_nargs]);
	args->hra_psr->pscr_nargs++;
	*newarg = arg;
	return (newarg);
}

EXPORTED_SYM bool
hijack_remote_args_set_syscall(HIJACK_REMOTE_ARGS *args,
    unsigned int syscallnum)
{
	if (args == NULL) {
		return (false);
	}
	if (args->hra_psr == NULL) {
		return (false);
	}

	args->hra_psr->pscr_syscall = syscallnum;
	return (true);
}

EXPORTED_SYM struct ptrace_sc_ret *
hijack_remote_args_get_syscall_ret(HIJACK_REMOTE_ARGS *args)
{
	if (args == NULL) {
		return (NULL);
	}
	if (args->hra_psr == NULL) {
		return (NULL);
	}
	return (&(args->hra_psr->pscr_ret));
}
