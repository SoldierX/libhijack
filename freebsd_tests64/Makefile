CC=clang
CFLAGS=-I../include -I/usr/src/libexec/rtld-elf -I/usr/src/libexec/rtld-elf/amd64 -DDEBUG -g -DFreeBSD -Damd64 -L/usr/local/lib

all:
	gmake InjectSharedObject
	gmake PrintFuncs
	gmake FindSyscall
	gmake MapMemory
	gmake FindFunc
	gmake pid
	gmake NewInject

clean:
	rm -f *.o PrintFuncs FindSyscall InjectSharedObject MapMemory FindFunc pid

pid: pid.c
	${CC} -o pid ${CFLAGS} -lpcap pid.c

InjectSharedObject: InjectSharedObject.c
	${CC} -o InjectSharedObject ${CFLAGS} -lhijack InjectSharedObject.c

NewInject: NewInject.c
	${CC} -o NewInject ${CFLAGS} -lhijack NewInject.c

Resolv: Resolv.c
	${CC} -o Resolv ${CFLAGS} -lhijack Resolv.c

PrintFuncs: PrintFuncs.c
	${CC} -o PrintFuncs ${CFLAGS} -L${LIBHIJACK_PREFIX}/lib -lhijack PrintFuncs.c

FindSyscall: FindSyscall.c
	${CC} -o FindSyscall ${CFLAGS} -L${LIBHIJACK_PREFIX}/lib -lhijack FindSyscall.c

MapMemory: MapMemory.c
	${CC} -o MapMemory ${CFLAGS} -L${LIBHIJACK_PREFIX}/lib -lhijack MapMemory.c

FindFunc: FindFunc.c
	${CC} -o FindFunc ${CFLAGS} -L${LIBHIJACK_PREFIX}/lib -lhijack FindFunc.c
