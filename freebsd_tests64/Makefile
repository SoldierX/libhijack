CC=clang
CFLAGS=-I../include -I/usr/src/libexec/rtld-elf -I/usr/src/libexec/rtld-elf/amd64 -DDEBUG -g -DFreeBSD -Damd64

all:
	gmake InjectSharedObject
	gmake PrintFuncs
	gmake FindSyscall
	gmake MapMemory
	gmake FindFunc
	gmake pid

clean:
	rm -f *.o PrintFuncs FindSyscall

pid: pid.c
	${CC} -o pid pid.c

InjectSharedObject: InjectSharedObject.c
	${CC} -o InjectSharedObject ${CFLAGS} -lhijack InjectSharedObject.c

PrintFuncs: PrintFuncs.c
	${CC} -o PrintFuncs ${CFLAGS} -lhijack PrintFuncs.c

FindSyscall: FindSyscall.c
	${CC} -o FindSyscall ${CFLAGS} -lhijack FindSyscall.c

MapMemory: MapMemory.c
	${CC} -o MapMemory ${CFLAGS} -lhijack MapMemory.c

FindFunc: FindFunc.c
	${CC} -o FindFunc ${CFLAGS} -lhijack FindFunc.c
