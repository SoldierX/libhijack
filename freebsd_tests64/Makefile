CC=gcc
LIBHIJACK_PREFIX=/usr/local
CFLAGS=-I${LIBHIJACK_PREFIX}/include -I/usr/src/libexec/rtld-elf -I/usr/src/libexec/rtld-elf/amd64 -DDEBUG -g -DFreeBSD -Damd64

all:
	gmake PrintFuncs
	gmake FindSyscall
	gmake MapMemory
	gmake FindFunc
	gmake InjectSharedObject
	gmake pid

clean:
	rm -f *.o PrintFuncs FindSyscall InjectSharedObject MapMemory FindFunc pid

pid: pid.c
	${CC} -o pid ${CFLAGS} -lpcap pid.c

PrintFuncs: PrintFuncs.c
	${CC} -o PrintFuncs ${CFLAGS} -L${LIBHIJACK_PREFIX}/lib -lhijack PrintFuncs.c

FindSyscall: FindSyscall.c
	${CC} -o FindSyscall ${CFLAGS} -L${LIBHIJACK_PREFIX}/lib -lhijack FindSyscall.c

MapMemory: MapMemory.c
	${CC} -o MapMemory ${CFLAGS} -L${LIBHIJACK_PREFIX}/lib -lhijack MapMemory.c

FindFunc: FindFunc.c
	${CC} -o FindFunc ${CFLAGS} -L${LIBHIJACK_PREFIX}/lib -lhijack FindFunc.c

InjectSharedObject: InjectSharedObject.c
	${CC} -o InjectSharedObject ${CFLAGS} -L${LIBHIJACK_PREFIX}/lib -lhijack InjectSharedObject.c
