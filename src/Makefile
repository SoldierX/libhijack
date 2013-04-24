TARGET=libhijack.so.0.6
SONAME=libhijack.so.0
SRCS=libhijack.c error.c misc.c ptrace.c map.c elf.c func.c rtld.c os_resolv.c
OBJS=libhijack.o error.o misc.o ptrace.o map.o elf.o func.o rtld.o os_resolv.o
CC=clang
ARCH=$(shell uname -m)
OS=$(shell uname -s)
CFLAGS=-fPIC -g -Wall -DDEBUG -D${ARCH} -D${OS} -I../include -fvisibility=hidden

ifeq (${OS}, FreeBSD)
	CFLAGS += -I/usr/src/libexec/rtld-elf -I/usr/src/libexec/rtld-elf/${ARCH}
	PREFIX=/usr/local
endif

${TARGET}: ${OBJS}
	${CC} -shared -Wl,-soname,${SONAME} -o ${TARGET} ${OBJS}

install: ${TARGET}
	cp ${TARGET} ${PREFIX}/lib
	ln -sf ${PREFIX}/lib/${TARGET} ${PREFIX}/lib/libhijack.so.0
	ln -sf ${PREFIX}/lib/${TARGET} ${PREFIX}/lib/libhijack.so
	cp ../include/hijack.h ${PREFIX}/include
	cp ../include/hijack_func.h ${PREFIX}/include

deinstall:
	rm ${PREFIX}/lib/libhijack.so.0
	rm ${PREFIX}/lib/libhijack.so
	rm ${PREFIX}/lib/${TARGET}
	rm ${PREFIX}/include/hijack.h
	rm ${PREFIX}/include/hijack_func.h

depends:
	mkdep ${CFLAGS} ${SRCS}

clean:
	rm -f *.o

distclean:
	pmake clean
	rm -f ${TARGET}
