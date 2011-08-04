TARGET=libhijack.so.0.5
SONAME=libhijack.so.0
CC=gcc
ARCH=i686
CFLAGS=-fPIC -g -Wall -DDEBUG -D${ARCH} -I../include -fvisibility=hidden
SRCS=libhijack.c error.c misc.c ptrace.c map.c elf.c func.c
OBJS=libhijack.o error.o misc.o ptrace.o map.o elf.o func.o

${TARGET}: ${OBJS}
	${CC} -shared -Wl,-soname,${SONAME} -o ${TARGET} ${OBJS}

install: ${TARGET}
	cp ${TARGET} /usr/lib
	ln -sf /usr/lib/${TARGET} /usr/lib/libhijack.so.0
	ln -sf /usr/lib/${TARGET} /usr/lib/libhijack.so
	cp ../include/hijack.h /usr/include
	cp ../include/hijack_func.h /usr/include

deinstall:
	rm /usr/lib/libhijack.so.0
	rm /usr/lib/libhijack.so
	rm /usr/lib/${TARGET}
	rm /usr/include/hijack.h
	rm /usr/include/hijack_func.h

depends:
	mkdep ${CFLAGS} ${SRCS}

clean:
	rm -f *.o

distclean:
	pmake clean
	rm -f ${TARGET}
