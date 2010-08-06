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
	
	do
	{
		ptracedata = ptrace(PTRACE_PEEKTEXT, hijack->pid, (void *)((unsigned long)start + readsz), 1);
		if (ptracedata == -1)
		{
			if (errno)
			{
				SetError(hijack, ERROR_SYSCALL);
				return data;
			}
		}
		
		tmpdata = realloc(data, readsz+1);
		if (!(tmpdata))
		{
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
	long word;
	int err = ERROR_NONE;
	
	while (i < sz)
	{
		if (i + sizeof(word) > sz)
		{
			word = ptrace(PTRACE_PEEKTEXT, hijack->pid, (void *)(start + i), NULL);
			memcpy(&word, (void *)((unsigned char *)buf + i), sz-i);
		}
		else
		{
			memcpy(&word, (void *)((unsigned char *)buf + i), sizeof(word));
		}
		if (ptrace(PTRACE_POKETEXT, hijack->pid, (void *)(start + i), word) < 0)
			err = ERROR_SYSCALL;
		
		i += sizeof(word);
	}
	
	return SetError(hijack, err);
}
