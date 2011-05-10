#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>

#include <sys/types.h>
#include <dirent.h>

static void *dl;
void *(*orig_memset)(void *, int, size_t);

__attribute__((constructor)) void stub(void)
{
	dl = dlopen("/lib/libc.so.6", RTLD_LAZY | RTLD_GLOBAL);
	orig_memset = dlsym(dl, "memset");
	
}

void *memset(void *s, int c, size_t n)
{
	FILE *fp;
	char filename[1024+1];
	
	snprintf(filename, sizeof(filename), "/tmp/mal-%d.log", getpid());
	
	fp = fopen(filename, "a");
	if ((fp))
	{
		fprintf(fp, "memset(0x%08lx, %i, %u)\n", (unsigned long)s, c, n);
		fclose(fp);
	}
	
	fprintf(stderr, "memset(0x%08lx, %i, %u)\n", (unsigned long)s, c, n);
	
	return orig_memset(s, c, n);
}
