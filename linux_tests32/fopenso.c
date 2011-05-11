#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>

static void *dl;
FILE *(*orig_fopen)(const char *, const char *);

__attribute__((constructor)) void stub(void)
{
	dl = dlopen("/lib/libc.so.6", RTLD_LAZY | RTLD_GLOBAL);
	orig_fopen = dlsym(dl, "fopen");
	
}

FILE *fopen(const char *path, const char *mode)
{
	FILE *fp;
	char filename[1024+1];
	
	snprintf(filename, sizeof(filename), "/tmp/mal-%d.log", getpid());
	
	fp = orig_fopen(filename, "a");
	if ((fp))
	{
		fprintf(fp, "fopen(\"%s\", \"%s\")\n", path, mode);
		fclose(fp);
	}
	
	fprintf(stderr, "fopen(\"%s\", \"%s\")\n", path, mode);
	
	return orig_fopen(path, mode);
}
