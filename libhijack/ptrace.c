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
#include <errno.h>

#include <sys/types.h>
#include <sys/ptrace.h>

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
