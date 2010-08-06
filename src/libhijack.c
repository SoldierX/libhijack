#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#include "hijack.h"
#include "error.h"
#include "misc.h"
#include "hijack_ptrace.h"
#include "map.h"
#include "hijack_elf.h"

int GetErrorCode(HIJACK *hijack)
{
	return hijack->lastErrorCode;
}

const char *GetErrorString(HIJACK *hijack)
{
	switch (hijack->lastErrorCode)
	{
		case ERROR_NONE:
			return "No Error";
		case ERROR_ATTACHED:
			return "Already Attached";
		case ERROR_NOTATTACHED:
			return "Not Attached";
		case ERROR_SYSCALL:
			return "System Call Error";
		case ERROR_NOTIMPLEMENTED:
			return "Not Implemented";
		case ERROR_BADARG:
			return "Bad Argument";
		case ERROR_BADPID:
			return "Bad PID";
		case ERROR_CHILDERROR:
			return "Error in Child Process";
		case ERROR_NEEDED:
			return "Needed Object Not Found";
		default:
			return "Unknown Error";
	}
}

HIJACK *InitHijack(void)
{
	HIJACK *hijack;
	unsigned long baseaddr = BASEADDR;
	
	hijack = malloc(sizeof(HIJACK));
	if (!(hijack))
		return NULL;
	
	memset(hijack, 0x00, sizeof(HIJACK));
	
	hijack->version = "0.2";
	
	SetValue(hijack, V_BASEADDR, &baseaddr);
	
	return hijack;
}

bool IsFlagSet(HIJACK *hijack, unsigned int flag)
{
	return (hijack->flags & flag) == flag;
}

int ToggleFlag(HIJACK *hijack, unsigned int flag)
{
	hijack->flags ^= flag;
	
	return SetError(hijack, ERROR_NONE);
}

void *GetValue(HIJACK *hijack, int vkey)
{
	switch (vkey)
	{
		case V_BASEADDR:
			return &(hijack->baseaddr);
		default:
			return NULL;
	}
}

int SetValue(HIJACK *hijack, int vkey, void *value)
{
	switch (vkey)
	{
		case V_BASEADDR:
			memcpy(&(hijack->baseaddr), value, sizeof(unsigned long));
			return SetError(hijack, ERROR_NONE);
		default:
			return SetError(hijack, ERROR_BADARG);
	}
}

bool IsAttached(HIJACK *hijack)
{
	return hijack->isAttached;
}

int AssignPid(HIJACK *hijack, pid_t pid)
{
	if (IsAttached(hijack))
		return SetError(hijack, ERROR_ATTACHED);
	
	if (pid <= 1)
		return SetError(hijack, ERROR_BADPID);
	
	hijack->pid = pid;
	
	return SetError(hijack, ERROR_NONE);
}

int Attach(HIJACK *hijack)
{
	int status;
	
	if (IsAttached(hijack))
		return SetError(hijack, ERROR_ATTACHED);
	
	if (hijack->pid <= 1)
		return SetError(hijack, ERROR_BADPID);
	
	if (IsFlagSet(hijack, F_DEBUG))
		fprintf(stderr, "[*] Attaching...\n");
	
	if (ptrace(PTRACE_ATTACH, hijack->pid, NULL, NULL) < 0)
		return SetError(hijack, ERROR_SYSCALL);
	
	do
	{
		waitpid(hijack->pid, &status, 0);
	} while (!WIFSTOPPED(status));
	
	hijack->isAttached = true;
	
	hijack->backup_regs = GetRegs(hijack);
	init_hijack_system(hijack);
	
	if (IsFlagSet(hijack, F_DEBUG))
		fprintf(stderr, "[*] Attached!\n");
	
	return SetError(hijack, ERROR_NONE);
}

int Detach(HIJACK *hijack)
{
	if (IsAttached(hijack) == false)
		return SetError(hijack, ERROR_NOTATTACHED);
	
	if (ptrace(PTRACE_DETACH, hijack->pid, NULL, NULL) < 0)
		return SetError(hijack, ERROR_SYSCALL);
	
	hijack->isAttached = false;
	
	return SetError(hijack, ERROR_NONE);
}

int LocateSystemCall(HIJACK *hijack)
{
	struct link_map *map;
	
	if (IsAttached(hijack) == false)
		return SetError(hijack, ERROR_NOTATTACHED);
	
	map = hijack->linkhead;
	do
	{
		parse_linkmap(hijack, map, syscall_callback);
		if (hijack->syscalladdr)
			break;
	} while ((map = get_next_linkmap(hijack, (unsigned long)(map->l_next))) != NULL);
	
	return SetError(hijack, ERROR_NONE);
}

int ReadData(HIJACK *hijack, unsigned long addr, unsigned char *buf, size_t sz)
{
	void *p;
	
	if (!(buf) || !sz)
		return SetError(hijack, ERROR_BADARG);
	
	if (IsAttached(hijack) == false)
		return SetError(hijack, ERROR_NOTATTACHED);
	
	p = read_data(hijack, addr, sz);
	
	if (GetErrorCode(hijack) == ERROR_NONE)
		memcpy(buf, p, sz);
	
	if ((p))
		free(p);
	
	/* XXX Assuming hijack->lastErrorCode is successfully set by read_data() */
	return GetErrorCode(hijack);
}

int WriteData(HIJACK *hijack, unsigned long addr, unsigned char *buf, size_t sz)
{
	if (!(buf) || !sz)
		return SetError(hijack, ERROR_BADARG);
	
	if (IsAttached(hijack) == false)
		return SetError(hijack, ERROR_NOTATTACHED);
	
	return write_data(hijack, addr, buf, sz);
}

unsigned long MapMemory(HIJACK *hijack, unsigned long addr, size_t sz, unsigned long flags, unsigned long prot)
{
	if (!IsAttached(hijack))
		return SetError(hijack, ERROR_NOTATTACHED);
	
	return map_memory_absolute(hijack, addr, sz, flags, prot);
}

int InjectShellcode(HIJACK *hijack, unsigned long addr, void *data, size_t sz)
{
	if (!IsAttached(hijack))
		return SetError(hijack, ERROR_NOTATTACHED);
	
	return inject_shellcode(hijack, addr, data, sz);
}

struct user_regs_struct *GetRegs(HIJACK *hijack)
{
	struct user_regs_struct *ret;
	
	if (!IsAttached(hijack))
	{
		SetError(hijack, ERROR_NOTATTACHED);
		return NULL;
	}
	
	ret = _hijack_malloc(hijack, sizeof(struct user_regs_struct));
	if (!(ret))
		return NULL;
	
	if (ptrace(PTRACE_GETREGS, hijack->pid, NULL, NULL) < 0)
	{
		SetError(hijack, ERROR_SYSCALL);
		free(ret);
		return NULL;
	}
	
	return ret;
}

int SetRegs(HIJACK *hijack, struct user_regs_struct *regs)
{
	if (!IsAttached(hijack))
		return SetError(hijack, ERROR_NOTATTACHED);
	
	if (ptrace(PTRACE_SETREGS, hijack->pid, NULL, regs) < 0)
		return SetError(hijack, ERROR_SYSCALL);
	
	return SetError(hijack, ERROR_NONE);
}

unsigned long FindFunctionInGot(HIJACK *hijack, unsigned long addr)
{
	return find_func_addr_in_got(hijack, addr);
}