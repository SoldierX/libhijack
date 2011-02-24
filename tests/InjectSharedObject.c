#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <fcntl.h>

#include <hijack.h>
#include <hijack_func.h>

void usage(const char *name)
{
	fprintf(stderr, "USAGE: %s <pid> <shellcode stub> <shared object>\n", name);
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	HIJACK *hijack;
	FUNC *funcs, *func;
	unsigned long shellcode_addr, filename_addr;
	struct stat sb;
	char *shellcode, *p1;
	int fd;
	struct user_regs_struct *regs;
	
	if (argc != 4)
		usage(argv[0]);
	
	hijack = InitHijack();
	AssignPid(hijack, atoi(argv[1]));
	
	if (Attach(hijack) != ERROR_NONE)
	{
		fprintf(stderr, "[-] Couldn't attach!\n");
		exit(EXIT_FAILURE);
	}
	
	stat(argv[2], &sb);
	shellcode = malloc(sb.st_size);
	
	fd = open(argv[2], O_RDONLY);
	read(fd, shellcode, sb.st_size);
	close(fd);
	
	regs = GetRegs(hijack);
	
	funcs = FindFunctionInLibraryByName(hijack, "/lib/libdl.so.2", "dlopen");
	if (!(funcs))
	{
		fprintf(stderr, "[-] Couldn't locate dlopen!\n");
		exit(EXIT_FAILURE);
	}
	
	if (regs->orig_eax >= 0)
	{
		switch (regs->eax)
		{
			case -514: /* -ERESTARTNOHAND */
			case -512: /* -ERESTARTSYS */
			case -513: /* -ERESTARTNOINTR */
			case -516: /* -ERESTART_RESTARTBLOCK */
				regs->eip += 2;
				break;
		}
	}
	
	p1 = memmem(shellcode, sb.st_size, "\x11\x11\x11\x11", 4);
	memcpy(p1, &(regs->eip), 4);
	
	LocateSystemCall(hijack);
	filename_addr = MapMemory(hijack, (unsigned long)NULL, 4096, MAP_ANONYMOUS | MAP_PRIVATE, PROT_READ | PROT_EXEC | PROT_WRITE);
	
	p1 = memmem(shellcode, sb.st_size, "\x22\x22\x22\x22", 4);
	memcpy(p1, &filename_addr, 4);
	
	shellcode_addr = filename_addr + strlen(argv[3]) + 1;
	printf("filename_addr: 0x%08lx\n", filename_addr);
	printf("shellcode_addr: 0x%08lx\n", shellcode_addr);
	printf("esp: 0x%08lx\n", regs->esp);
	printf("eip: 0x%08lx\n", regs->eip);
	
	p1 = memmem(shellcode, sb.st_size, "\x33\x33\x33\x33", 4);
	memcpy(p1, &shellcode_addr, 4);
	
	WriteData(hijack, filename_addr, (unsigned char *)argv[3], strlen(argv[3]));
	WriteData(hijack, shellcode_addr, (unsigned char *)shellcode, sb.st_size);
	
	regs->eip = shellcode_addr;
	
	if (regs->orig_eax >= 0)
	{
		switch (regs->eax)
		{
			case -514: /* -ERESTARTNOHAND */
			case -512: /* -ERESTARTSYS */
			case -513: /* -ERESTARTNOINTR */
			case -516: /* -ERESTART_RESTARTBLOCK */
				regs->eip += 2;
				break;
		}
	}
	SetRegs(hijack, regs);
	
	Detach(hijack);
	
	return 0;
}
