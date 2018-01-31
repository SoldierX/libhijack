/*
 * Copyright (c) 2018, Shawn Webb
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials
 *      provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dlfcn.h>

int
main(int argc, char *argv[])
{
	void *handle;
	int (*func)(void);

	if (argc != 2) {
		fprintf(stderr, "USAGE: %s /path/to/injectable.so\n", argv[0]);
		return (1);
	}

	while (printf("%d\n", getpid())) {
		handle = dlopen(argv[1], RTLD_LAZY | RTLD_GLOBAL);
		if (handle == NULL) {
			fprintf(stderr, "[-] Could not open %s: %s\n",
			argv[1], dlerror());
			return (1);
		}
		printf("Before resolution\n");
		sleep(5);
		func = dlsym(handle, "func");
		if (func == NULL) {
			fprintf(stderr, "[-] Could not resolve func: %s\n",
			dlerror());
			return (1);
		}
		func();
		printf("Before close\n");
		sleep(5);
		dlclose(handle);
	}

	return (0);
}
