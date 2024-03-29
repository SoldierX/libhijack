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
static void remote_library_free(remote_library_t **);

static void template_prologue(void);
static void template(void);
static void template_epilogue(void);
static bool _continue_and_wait(HIJACK *, REGS *, bool);

EXPORTED_SYM int
LoadLibraryAnonymously(HIJACK *hijack, char *path)
{
	struct ptrace_sc_ret *scret;
	HIJACK_REMOTE_ARGS *scargs;
	unsigned long curaddr, val;
	remote_library_t *library;
	REGS *regs, *regs_backup;
	int error, fd, status;
	struct fpreg fpbackup;
	size_t pathlen;
	struct stat sb;
	size_t i;

	error = ERROR_NONE;
	scargs = NULL;

	if (hijack == NULL || path == NULL) {
		printf("hijack or path is null\n");
		return (SetError(hijack, ERROR_BADARG));
	}

	memset(&fpbackup, 0, sizeof(fpbackup));
	if (ptrace(PT_GETFPREGS, hijack->pid, (caddr_t)&fpbackup, 0)) {
		perror("ptrace(get fpregs)");
		return (SetError(hijack, ERROR_SYSCALL));
	}

	regs_backup = GetRegs(hijack);
	if (regs_backup == NULL) {
		printf("Could not get registers\n");
		return (SetError(hijack, ERROR_SYSCALL));
	}

	library = remote_library_new();
	if (library == NULL) {
		printf("Could not create new library object\n");
		free(regs_backup);
		return (SetError(hijack, ERROR_NOMEM));
	}

	pathlen = strlen(path);
	library->local_fd = open(path, O_RDONLY);
	if (library->local_fd < 0) {
		error = ERROR_FILEACCESS;
		goto end;
	}

	memset(&(library->sb), 0, sizeof(library->sb));
	fstat(library->local_fd, &(library->sb));

	library->local_buf = mmap(NULL, library->sb.st_size, PROT_READ,
	    MAP_SHARED, library->local_fd, 0);
	if (library->local_buf == MAP_FAILED) {
		error = ERROR_NOMEM;
		goto end;
	}

	library->fdlopen_addr = resolv_rtld_sym(hijack,
	    "fdlopen")->p.ulp;
	if (library->fdlopen_addr == (unsigned long)NULL) {
		printf("could not resolve fdlopen\n");
		error = ERROR_CHILDERROR;
		goto end;
	}

	/* Step zero: make sure we're at a syscall exit */
	if (_continue_and_wait(hijack, regs_backup, true) == false) {
		printf("could not continue and wait\n");
		error = ERROR_CHILDERROR;
		goto end;
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
		error = ERROR_CHILDSYSCALL;
		goto end;
	}

	/*
	 * Step two: Create shmfd.
	 */

	if (write_data(hijack, library->scratch_addr, library->uuid,
	    strlen(library->uuid) +1)) {
		error = ERROR_SYSCALL;
		goto end;
	}

	if (write_data(hijack, library->scratch_addr + getpagesize(),
	    library->local_buf, library->sb.st_size)) {
		error = ERROR_SYSCALL;
		goto end;
	}

	scargs = hijack_remote_args_new(hijack, 0);
	if (scargs == NULL) {
		error = ERROR_NOMEM;
		goto end;
	}
	hijack_remote_args_set_syscall(scargs, SYS_shm_open2);
	if (hijack_remote_args_add_arg(scargs,
	    (syscallarg_t)SHM_ANON) == NULL) {
		error = ERROR_NOMEM;
		goto end;
	}
	if (hijack_remote_args_add_arg(scargs, O_RDWR) == NULL) {
		error = ERROR_NOMEM;
		goto end;
	}
	if (hijack_remote_args_add_arg(scargs, 0) == NULL) {
		error = ERROR_NOMEM;
		goto end;
	}
	if (hijack_remote_args_add_arg(scargs, SHM_GROW_ON_WRITE) == NULL) {
		error = ERROR_NOMEM;
		goto end;
	}
	if (hijack_remote_args_add_arg(scargs, library->scratch_addr) == NULL) {
		error = ERROR_NOMEM;
		goto end;
	}
	if (perform_remote_syscall(scargs)) {
		error = GetError(hijack);
		goto end;
	}

	scret = hijack_remote_args_get_syscall_ret(scargs);

	if (scret->sr_error) {
		error = ERROR_CHILDSYSCALL;
		goto end;
	}

	library->remote_fd = scret->sr_retval[0];
	if (library->remote_fd < 0) {
		error = ERROR_CHILDSYSCALL;
		goto end;
	}

	hijack_remote_args_free(&scargs, HIJACK_REMOTE_FREE_DEFAULT);

	/* Step three: size the memfd appropriately */

	scargs = hijack_remote_args_new(hijack, 0);
	if (scargs == NULL) {
		error = ERROR_NOMEM;
		goto end;
	}

	hijack_remote_args_set_syscall(scargs, SYS_ftruncate);

	if (hijack_remote_args_add_arg(scargs, library->remote_fd) == NULL) {
		error = ERROR_NOMEM;
		goto end;
	}

	if (hijack_remote_args_add_arg(scargs, library->sb.st_size) == NULL) {
		error = ERROR_NOMEM;
		goto end;
	}

	if (perform_remote_syscall(scargs)) {
		error = GetError(hijack);
		goto end;
	}

	hijack_remote_args_free(&scargs, HIJACK_REMOTE_FREE_DEFAULT);

	/* Step four: write to the memfd */

	scargs = hijack_remote_args_new(hijack, 0);
	if (scargs == NULL) {
		error = ERROR_NOMEM;
		goto end;
	}

	hijack_remote_args_set_syscall(scargs, SYS_write);

	if (hijack_remote_args_add_arg(scargs, library->remote_fd) == NULL) {
		error = ERROR_NOMEM;
		goto end;
	}

	if (hijack_remote_args_add_arg(scargs,
	    library->scratch_addr + getpagesize()) == NULL) {
		error = ERROR_NOMEM;
		goto end;
	}

	if (hijack_remote_args_add_arg(scargs, library->sb.st_size) == NULL) {
		error = ERROR_NOMEM;
		goto end;
	}

	if (perform_remote_syscall(scargs)) {
		error = GetError(hijack);
		goto end;
	}

	hijack_remote_args_free(&scargs, HIJACK_REMOTE_FREE_DEFAULT);

	/* Step five: seek to beginning */

	scargs = hijack_remote_args_new(hijack, 0);
	if (scargs == NULL) {
		error = ERROR_NOMEM;
		goto end;
	}

	hijack_remote_args_set_syscall(scargs, SYS_lseek);

	if (hijack_remote_args_add_arg(scargs, library->remote_fd) == NULL) {
		error = ERROR_NOMEM;
		goto end;
	}

	if (hijack_remote_args_add_arg(scargs, 0) == NULL) {
		error = ERROR_NOMEM;
		goto end;
	}

	if (hijack_remote_args_add_arg(scargs, 0) == NULL) {
		error = ERROR_NOMEM;
		goto end;
	}

	if (perform_remote_syscall(scargs)) {
		error = GetError(hijack);
		goto end;
	}

	hijack_remote_args_free(&scargs, HIJACK_REMOTE_FREE_DEFAULT);

	regs = calloc(1, sizeof(*regs));
	if (regs == NULL) {
		error = ERROR_NOMEM;
		goto end;
	}
	memmove(regs, regs_backup, sizeof(*regs));

	curaddr = GetInstructionPointer(regs_backup);
	SetInstructionPointer(regs, library->fdlopen_addr);
	SetRegister(regs, "arg0", (register_t)(library->remote_fd));
	SetRegister(regs, "arg1", (register_t)(RTLD_GLOBAL | RTLD_NOW));
	if (!SetReturnAddress(hijack, regs, curaddr)) {
		error = ERROR_CHILDSYSCALL;
		goto end;
	}
	if (SetRegs(hijack, regs)) {
		error = ERROR_SYSCALL;
		goto end;
	}

	ptrace(PT_SETREGS, hijack->pid, (caddr_t)regs, 0);
	ptrace(PT_CONTINUE, hijack->pid, (caddr_t)1, 0);

	/*
	 * TODO: Close remote file descriptor now that fdlopen has loaded the
	 * shared object.
	 */

end:
	hijack_remote_args_free(&scargs, HIJACK_REMOTE_FREE_DEFAULT);
	remote_library_free(&library);
	return (SetError(hijack, error));
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

static void
remote_library_free(remote_library_t **libp)
{
	remote_library_t *lib;

	if (libp == NULL || *libp == NULL) {
		return;
	}

	lib = *libp;
	*libp = NULL;

	free(lib->path);
	free(lib->uuid);
	if (lib->local_buf != NULL) {
		munmap(lib->local_buf, lib->sb.st_size);
		close(lib->local_fd);
	}
	memset(lib, 0, sizeof(*lib));
	free(lib);
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
