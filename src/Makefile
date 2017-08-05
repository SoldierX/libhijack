.sinclude <src.opts.mk>

SHLIB=		hijack
SHLIB_MAJOR=	0
SRCS=	\
	elf.c \
	elf.c \
	error.c \
	func.c \
	libhijack.c \
	map.c \
	misc.c \
	os_resolv.c \
	ptrace.c \
	rtld.c

.if !defined(TARGET_ARCH)
TARGET_ARCH!=uname -p
.endif

.if !defined(TARGET)
TARGET!=uname -m
.endif

CFLAGS+=	-I${.CURDIR}/../include \
		-I/usr/src/libexec/rtld-elf \
		-I/usr/src/libexec/rtld-elf/${TARGET_ARCH} \
		-DFreeBSD \
		-D${TARGET}
MAN=

.include <bsd.lib.mk>
