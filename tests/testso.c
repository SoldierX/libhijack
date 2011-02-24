#include <stdio.h>
#include <dlfcn.h>

__attribute__((constructor)) void stub(void)
{
	printf("Stub %d!\n", RTLD_NOW | RTLD_GLOBAL | RTLD_DEEPBIND);
}

unsigned int sleep(unsigned int seconds)
{
	printf("sleep intercepted\n");
	return 0;
}
