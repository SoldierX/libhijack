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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/ptrace.h>

#include "hijack.h"

register_t
GetStack(REGS *regs)
{

	return (regs->r_rsp);
}

void
SetStack(REGS *regs, register_t addr)
{

	regs->r_rsp = addr;
}

register_t
GetInstructionPointer(REGS *regs)
{

	return (regs->r_rip);
}

void
SetInstructionPointer(REGS *regs, register_t addr)
{

	regs->r_rip = addr;
}

register_t
GetRegister(REGS *regs, const char *reg)
{

	if (!strcmp(reg, "syscall"))
		return (regs->r_rax);
	if (!strcmp(reg, "arg0"))
		return (regs->r_rdi);
	if (!strcmp(reg, "arg1"))
		return (regs->r_rsi);
	if (!strcmp(reg, "arg2"))
		return (regs->r_rdx);
	if (!strcmp(reg, "arg3"))
		return (regs->r_r10);
	if (!strcmp(reg, "arg4"))
		return (regs->r_r8);
	if (!strcmp(reg, "arg5"))
		return (regs->r_r9);

	return (register_t)NULL;
}

void
SetRegister(REGS *regs, const char *reg, register_t val)
{

	if (!strcmp(reg, "syscall")) {
		regs->r_rax = val;
		return;
	}
	if (!strcmp(reg, "arg0")) {
		regs->r_rdi = val;
		return;
	}
	if (!strcmp(reg, "arg1")) {
		regs->r_rsi = val;
		return;
	}
	if (!strcmp(reg, "arg2")) {
		regs->r_rdx = val;
		return;
	}
	if (!strcmp(reg, "arg3")) {
		regs->r_r10 = val;
		return;
	}
	if (!strcmp(reg, "arg4")) {
		regs->r_r8 = val;
		return;
	}
	if (!strcmp(reg, "arg5")) {
		regs->r_r9 = val;
		return;
	}
}
