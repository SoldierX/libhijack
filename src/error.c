#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>

#include "hijack.h"
#include "error.h"

int SetError(HIJACK *hijack, int errorCode)
{
	hijack->lastErrorCode = errorCode;
	return errorCode;
}

EXPORTED_SYM void ClearError(HIJACK *hijack)
{
	hijack->lastErrorCode = ERROR_NONE;
}
