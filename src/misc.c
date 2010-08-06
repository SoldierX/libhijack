#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/ptrace.h>

#include "hijack.h"
#include "error.h"
#include "misc.h"

void *_hijack_malloc(HIJACK *hijack, size_t sz)
{
	void *p;
	int err = ERROR_NONE;
	
	p = malloc(sz);
	
	if ((p))
		memset(p, 0x00, sz);
	else
		err = ERROR_SYSCALL;
	
	SetError(hijack, err);
	
	return p;
}
