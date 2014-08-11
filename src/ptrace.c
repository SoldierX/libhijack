/*
 * Copyright (c) 2011-2014, Shawn Webb
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *    1) Redistributions of source code must retain the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer.
 *    2) Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials
 *       provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/ptrace.h>

#include "hijack.h"
#include "error.h"
#include "misc.h"
#include "hijack_ptrace.h"

void *read_data(HIJACK *hijack, unsigned long start, size_t sz)
{
	void *data=NULL, *tmpdata;
	long ptracedata;
	size_t readsz=0;
	
	do {
		ptracedata = ptrace(PTRACE_PEEKTEXT, hijack->pid, (void *)((unsigned long)start + readsz), 1);
		if (ptracedata == -1) {
			if (errno) {
				SetError(hijack, ERROR_SYSCALL);
				return data;
			}
		}
		
		tmpdata = realloc(data, readsz+1);
		if (!(tmpdata)) {
			SetError(hijack, ERROR_SYSCALL);
			return data;
		}
		data = tmpdata;
		
		((unsigned char *)data)[readsz] = (unsigned char)(ptracedata & 0x000000ff);
		
	} while (readsz++ < sz);
	
	SetError(hijack, ERROR_NONE);
	return data;
}

char *read_str(HIJACK *hijack, unsigned long base)
{
	char *retval = NULL;
	unsigned int bufsz = 1;
	
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

int write_data(HIJACK *hijack, unsigned long start, void *buf, size_t sz)
{
	size_t i=0;
#if defined(FreeBSD)
    int word;
    int nullarg = 0;
#else
	unsigned long word;
    void *nullarg = NULL;
#endif
	int err = ERROR_NONE;
	
	while (i < sz) {
		if (i + sizeof(word) > sz) {
			word = ptrace(PTRACE_PEEKTEXT, hijack->pid, (void *)(start + i), nullarg);
			memcpy(&word, (void *)((unsigned char *)buf + i), sz-i);
		} else {
			memcpy(&word, (void *)((unsigned char *)buf + i), sizeof(word));
		}
		if (ptrace(PTRACE_POKETEXT, hijack->pid, (void *)(start + i), word) < 0)
			err = ERROR_SYSCALL;
		
		i += sizeof(word);
	}
	
	return SetError(hijack, err);
}
