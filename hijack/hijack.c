#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include "hijack.h"

int
main(int argc, char *argv[])
{
	HIJACK *ctx;
	int ch;
	pid_t pid;

	while ((ch = getopt(argc, argv, "p:")) != -1) {
		switch (ch) {
		case 'p':
			if (sscanf(optarg, "%d", &pid) != 1) {
				printf("lolwut\n");
				exit(1);
			}
			break;
		}
	}

	ctx = InitHijack(F_NONE);
	if (ctx == NULL) {
		fprintf(stderr, "Could not create hijack ctx\n");
		exit(1);
	}

	if (AssignPid(ctx, pid)) {
		fprintf(stderr, "Could not assign the PID\n");
		exit(1);
	}

	if (Attach(ctx)) {
		fprintf(stderr, "Could not attach to the PID: %s\n",
		    GetErrorString(ctx));
		exit(1);
	}

	printf("Base address: 0x%016lx\n", ctx->baseaddr);

	Detach(ctx);

	return (0);
}
