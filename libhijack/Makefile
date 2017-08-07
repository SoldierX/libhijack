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

CFLAGS+=	-I${.CURDIR}/../include \
		-I/usr/src/libexec/rtld-elf \
		-I/usr/src/libexec/rtld-elf/${MACHINE_ARCH} \
		-D${MACHINE_ARCH} \
		-DHIJACK_INTERNAL

LDADD=	-lprocstat
MAN=

.if defined(PREFIX)
LIBDIR?=	${PREFIX}/lib
.endif

.include <bsd.lib.mk>
