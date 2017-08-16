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

EXPORTED_SYM register_t
GetStack(REGS *regs)
{

	return (regs->sp);
}

EXPORTED_SYM void
SetStack(REGS *regs, register_t addr)
{

	regs->sp = addr;
}

EXPORTED_SYM register_t
GetInstructionPointer(REGS *regs)
{

	return (regs->lr);
}

EXPORTED_SYM void
SetInstructionPointer(REGS *regs, register_t addr)
{

	regs->lr = addr;
}

EXPORTED_SYM register_t
GetRegister(REGS *regs, const char *reg)
{

	if (!strcmp(reg, "syscall"))
		return (regs->x[0]);
	if (!strcmp(reg, "arg0"))
		return (regs->x[1]);
	if (!strcmp(reg, "arg1"))
		return (regs->x[2]);
	if (!strcmp(reg, "arg2"))
		return (regs->x[3]);
	if (!strcmp(reg, "arg3"))
		return (regs->x[4]);
	if (!strcmp(reg, "arg4"))
		return (regs->x[5]);
	if (!strcmp(reg, "arg5"))
		return (regs->x[6]);
	if (!strcmp(reg, "ret"))
		return (regs->x[0]);

	return (register_t)NULL;
}

EXPORTED_SYM void
SetRegister(REGS *regs, const char *reg, register_t val)
{

	if (!strcmp(reg, "syscall")) {
		regs->x[0] = val;
		return;
	}
	if (!strcmp(reg, "arg0")) {
		regs->x[1] = val;
		return;
	}
	if (!strcmp(reg, "arg1")) {
		regs->x[2] = val;
		return;
	}
	if (!strcmp(reg, "arg2")) {
		regs->x[3] = val;
		return;
	}
	if (!strcmp(reg, "arg3")) {
		regs->x[4] = val;
		return;
	}
	if (!strcmp(reg, "arg4")) {
		regs->x[5] = val;
		return;
	}
	if (!strcmp(reg, "arg5")) {
		regs->x[6] = val;
		return;
	}
	if (!strcmp(reg, "ret")) {
		regs->x[0] = val;
		return;
	}
}
