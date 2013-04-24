#include <stdio.h>
#include <dlfcn.h>

static void *dl;
unsigned int (*orig_sleep)(unsigned int);

__attribute__((constructor)) void stub(void)
{
	dl = dlopen("/lib/libc.so.6", RTLD_LAZY | RTLD_GLOBAL);
	orig_sleep = dlsym(dl, "sleep");
}

unsigned int sleep(unsigned int seconds)
{
	printf("sleep intercepted\n");
	return orig_sleep(seconds);
}
