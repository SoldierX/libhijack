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

#include <uuid.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include <dlfcn.h>

#include <elf.h>
#include <link.h>

#include "hijack.h"

typedef struct _remote_library {
	unsigned long	 fdlopen_addr;
	unsigned long	 memfd_create_addr;
	unsigned long	 scratch_addr;

	char		*path;
	char		*uuid;
	int		 local_fd;
	int		 remote_fd;

	void		*local_buf;
	struct stat	 sb;

	size_t		 scratch_size;
} remote_library_t;

static remote_library_t *remote_library_new(void);

static void template_prologue(void);
static void template(void);
static void template_epilogue(void);
static bool _continue_and_wait(HIJACK *, REGS *, bool);

EXPORTED_SYM int
LoadLibraryAnonymously(HIJACK *hijack, char *path)
{
	struct ptrace_sc_remote psr;
	unsigned long curaddr, val;
	remote_library_t *library;
	REGS *regs, *regs_backup;
	struct fpreg fpbackup;
	size_t pathlen;
	struct stat sb;
	int fd, status;
	size_t i;

	if (hijack == NULL || path == NULL) {
		printf("hijack or path is null\n");
		return (-1);
	}

	memset(&fpbackup, 0, sizeof(fpbackup));
	if (ptrace(PT_GETFPREGS, hijack->pid, (caddr_t)&fpbackup, 0)) {
		perror("ptrace(get fpregs)");
		return (-1);
	}

	regs_backup = GetRegs(hijack);
	if (regs_backup == NULL) {
		printf("Could not get registers\n");
		return (-1);
	}
#if 0
	if (hijack->funcs == NULL) {
		/* For now, ensure that we've already cached all functions. */
		printf("cache funcs, please\n");
		return (-1);
	}
#endif

	library = remote_library_new();
	if (library == NULL) {
		printf("Could not create new library object\n");
		free(regs_backup);
		return (-1);
	}

	pathlen = strlen(path);
	library->local_fd = open(path, O_RDONLY);
	if (library->local_fd < 0) {
		return (-1);
	}

	memset(&(library->sb), 0, sizeof(library->sb));
	fstat(library->local_fd, &(library->sb));

	library->local_buf = mmap(NULL, library->sb.st_size, PROT_READ,
	    MAP_SHARED, library->local_fd, 0);
	if (library->local_buf == MAP_FAILED) {
		perror("mmap");
		return (-1);
	}

	library->fdlopen_addr = resolv_rtld_sym(hijack,
	    "fdlopen")->p.ulp;
	if (library->fdlopen_addr == (unsigned long)NULL) {
		printf("could not resolve fdlopen\n");
		return (-1);
	}

	/* Step zero: make sure we're at a syscall exit */
	if (_continue_and_wait(hijack, regs_backup, true) == false) {
		printf("could not continue and wait\n");
		return (-1);
	}

	/*
	 * Step one: create scratch memory allocation.
	 */
	library->scratch_size = library->sb.st_size + (getpagesize() * 2);
	library->scratch_addr = MapMemory(hijack, (unsigned long)NULL,
	    library->scratch_size, PROT_READ | PROT_WRITE | PROT_EXEC,
	    MAP_SHARED | MAP_ANON);
	if (library->scratch_addr == (unsigned long)NULL) {
		printf("could not mmap\n");
		return (-1);
	}

	/*
	 * Step two: Create shmfd.
	 */

	if (write_data(hijack, library->scratch_addr, library->uuid,
	    strlen(library->uuid) +1)) {
		perror("ptrace(write_uuid)");
		printf("could not write uuid %s\n", library->uuid);
		return (-1);
	}

	if (write_data(hijack, library->scratch_addr + getpagesize(),
	    library->local_buf, library->sb.st_size)) {
		printf("could not write shared library object\n");
		return (-1);
	}

	memset(&psr, 0, sizeof(psr));
	psr.pscr_syscall = SYS_shm_open2;
	psr.pscr_nargs = 5;
	psr.pscr_args = calloc(psr.pscr_nargs, sizeof(unsigned long));
	if (psr.pscr_args == NULL) {
		perror("calloc");
		return (-1);
	}

	psr.pscr_args[0] = (long)SHM_ANON;
	psr.pscr_args[1] = O_RDWR;
	psr.pscr_args[2] = 0;
	psr.pscr_args[3] = SHM_GROW_ON_WRITE;
	psr.pscr_args[4] = library->scratch_addr;
	if (ptrace(PT_SC_REMOTE, hijack->pid, (caddr_t)&psr, sizeof(psr))) {
		perror("ptrace(remote:__sys_shm_open2)");
		return (-1);
	}

	if (psr.pscr_ret.sr_error) {
		/* shm_open2 failed */
		return (-1);
	}

	if (_continue_and_wait(hijack, regs_backup, true) == false) {
		printf("could not continue and wait\n");
		return (-1);
	}

	library->remote_fd = psr.pscr_ret.sr_retval[0];
	if (library->remote_fd < 0) {
		/* shm_open2 failed in a different way */
		return (-1);
	}

	/* Step three: size the memfd appropriately */

	memset(psr.pscr_args, 0, sizeof(unsigned long) * psr.pscr_nargs);
	psr.pscr_nargs = 2;
	psr.pscr_args[0] = library->remote_fd;
	psr.pscr_args[1] = library->sb.st_size;
	psr.pscr_syscall = SYS_ftruncate;
	if (ptrace(PT_SC_REMOTE, hijack->pid, (caddr_t)&psr, sizeof(psr))) {
		perror("ptrace(remote:SYS_ftruncate)");
		return (-1);
	}

	if (psr.pscr_ret.sr_error) {
		printf("remote truncate failed\n");
		return (-1);
	}

	if (_continue_and_wait(hijack, regs_backup, true) == false) {
		printf("could not continue and wait\n");
		return (-1);
	}

	/* Step four: write to the memfd */

	memset(psr.pscr_args, 0, sizeof(unsigned long) * psr.pscr_nargs);
	memset(&(psr.pscr_ret), 0, sizeof(psr.pscr_ret));
	psr.pscr_nargs = 3;
	psr.pscr_args[0] = library->remote_fd;
	psr.pscr_args[1] = library->scratch_addr + getpagesize();
	psr.pscr_args[2] = library->sb.st_size;
	psr.pscr_syscall = SYS_write;
	if (ptrace(PT_SC_REMOTE, hijack->pid, (caddr_t)&psr, sizeof(psr))) {
		perror("ptrace(remote:SYS_write)");
		return (-1);
	}

	if (psr.pscr_ret.sr_error) {
		printf("remote write failed\n");
		return (-1);
	}

	if (_continue_and_wait(hijack, regs_backup, true) == false) {
		printf("could not continue and wait\n");
		return (-1);
	}

	/* Step five: seek to beginning */

	memset(psr.pscr_args, 0, sizeof(unsigned long) * psr.pscr_nargs);
	psr.pscr_nargs = 3;
	psr.pscr_args[0] = library->remote_fd;
	psr.pscr_args[1] = 0;
	psr.pscr_args[2] = 0;
	psr.pscr_syscall = SYS_lseek;
	if (ptrace(PT_SC_REMOTE, hijack->pid, (caddr_t)&psr, sizeof(psr))) {
		perror("ptrace(remote:SYS_lseek)");
		return (-1);
	}

	if (psr.pscr_ret.sr_error || (ssize_t)psr.pscr_ret.sr_retval[0]) {
		printf("remote lseek failed\n");
		return (-1);
	}

	if (_continue_and_wait(hijack, regs_backup, true) == false) {
		printf("could not continue and wait\n");
		return (-1);
	}

	regs = calloc(1, sizeof(*regs));
	if (regs == NULL) {
		return (-1);
	}
	memmove(regs, regs_backup, sizeof(*regs));

	curaddr = GetInstructionPointer(regs_backup);
	SetInstructionPointer(regs, library->fdlopen_addr);
	SetRegister(regs, "arg0", (register_t)(library->remote_fd));
	SetRegister(regs, "arg1", (register_t)(RTLD_GLOBAL | RTLD_NOW));
	if (!SetReturnAddress(hijack, regs, curaddr)) {
		fprintf(stderr, "Could not set return address\n");
		return (-1);
	}
	if (SetRegs(hijack, regs)) {
		perror("SetRegs");
		return (-1);
	}

	ptrace(PT_CONTINUE, hijack->pid, (caddr_t)1, 0);

	return (0);
}

static remote_library_t *
remote_library_new(void)
{
	remote_library_t *library;
	uint32_t status;
	uuid_t uuid;

	library = calloc(1, sizeof(*library));
	if (library == NULL) {
		return (NULL);
	}

	status = 0;
	memset(&uuid, 0, sizeof(uuid));
	uuid_create(&uuid, &status);
	if (status != uuid_s_ok) {
		free(library);
		return (NULL);
	}
	uuid_to_string(&uuid, &(library->uuid), &status);
	if (status != uuid_s_ok) {
		free(library);
		return (NULL);
	}

	library->local_fd = -1;

	return (library);
}

static bool
_continue_and_wait(HIJACK *hijack, REGS *regs, bool really_continue)
{
	int status;

	if (hijack == NULL) {
		return (false);
	}

	if (really_continue) {
		SetRegs(hijack, regs);

		if (ptrace(PT_TO_SCX, hijack->pid, (caddr_t)1, 0) && errno != EBUSY) {
			perror("ptrace(pt_to_scx)");
			return (false);
		}

		do {
			status = 0;
			if (waitpid(hijack->pid, &status, WNOHANG) < 0) {
				perror("waitpid");
				return (false);
			}
		} while (!WIFSTOPPED(status));
	}

	ptrace(PT_GETREGS, hijack->pid, (caddr_t)regs, 0);

	return (true);
}
