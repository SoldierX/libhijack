CC=gcc
CFLAGS=-I/usr/src/libexec/rtld-elf -I/usr/src/libexec/rtld-elf/amd64 -DDEBUG -g -DFreeBSD -Damd64

all:
	gmake PrintFuncs
	gmake FindSyscall
	gmake MapMemory
	gmake FindFunc
	gmake InjectSharedObject

clean:
	rm -f *.o PrintFuncs FindSyscall

PrintFuncs: PrintFuncs.c
	${CC} -o PrintFuncs ${CFLAGS} -lhijack PrintFuncs.c

FindSyscall: FindSyscall.c
	${CC} -o FindSyscall ${CFLAGS} -lhijack FindSyscall.c

MapMemory: MapMemory.c
	${CC} -o MapMemory ${CFLAGS} -lhijack MapMemory.c

FindFunc: FindFunc.c
	${CC} -o FindFunc ${CFLAGS} -lhijack FindFunc.c

InjectSharedObject: InjectSharedObject.c
	${CC} -o InjectSharedObject ${CFLAGS} -lhijack InjectSharedObject.c
