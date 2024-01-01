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

#include <sys/types.h>

#include "hijack.h"

int
SetError(HIJACK *hijack, int errorCode)
{
	if (hijack == NULL) {
		return (ERROR_BADARG);
	}

	hijack->lastErrorCode = errorCode;
	return (errorCode);
}

/**
 * Clear any set error codes
 * @param hijack Pointer to the HIJACK instance
 * \ingroup libhijack
 */
EXPORTED_SYM void
ClearError(HIJACK *hijack)
{

	hijack->lastErrorCode = ERROR_NONE;
}

EXPORTED_SYM int
GetError(HIJACK *hijack)
{
	if (hijack == NULL) {
		return (ERROR_BADARG);
	}

	return (hijack->lastErrorCode);
}

EXPORTED_SYM const char *
HijackErrorToString(int errcode)
{
	switch (errcode) {
	case ERROR_NONE:
		return ("No error");
	case ERROR_ATTACHED:
		return ("Already attached");
	case ERROR_NOTATTACHED:
		return ("Not attached");
	case ERROR_BADPID:
		return ("Bad PID");
	case ERROR_SYSCALL:
		return ("System call failure");
	case ERROR_NOTIMPLEMENTED:
		return ("Not implemented");
	case ERROR_BADARG:
		return ("Bad argument(s)");
	case ERROR_CHILDERROR:
		return ("Error in child process");
	case ERROR_NEEDED:
		return ("Needed functionality nonfunctional");
	case ERROR_NOTSUPP:
		return ("Not supported");
	case ERROR_NOMEM:
		return ("Out of memory");
	case ERROR_FILEACCESS:
		return ("Could not access file(s)");
	case ERROR_CHILDSYSCALL:
		return ("System call failure in child process");
	}

	return ("Unknown error");
}
