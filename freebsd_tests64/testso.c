#include <stdio.h>
#include <dlfcn.h>

static void *dl;
unsigned int (*orig_sleep)(unsigned int);

__attribute__((constructor)) void stub(void)
{
	dl = dlopen("/lib/libc.so.7", RTLD_LAZY | RTLD_GLOBAL);
	orig_sleep = dlsym(dl, "sleep");
    if (!(orig_sleep)) {
        orig_sleep = dlsym(RTLD_NEXT, "sleep");
    }
}

unsigned int sleep(unsigned int seconds)
{
    static int printed=0;
    if (!printed)
    	printf("sleep intercepted. orig_sleep: %p my sleep: %p\n", orig_sleep, sleep);

    printed = 1;

	return orig_sleep(seconds);
}
