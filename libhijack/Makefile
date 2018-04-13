.sinclude <src.opts.mk>

.include "${.CURDIR}/../Makefile.inc"

SHLIB=		hijack
SHLIB_MAJOR=	2
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
		-I${SRCDIR}/libexec/rtld-elf \
		-I${SRCDIR}/libexec/rtld-elf/${MACHINE_ARCH} \
		-I${.CURDIR}/arch/${MACHINE_ARCH} \
		-DHIJACK_INTERNAL

.PATH: ${.CURDIR}/arch/${MACHINE_ARCH}
SRCS+=	inst.c md_map.c regs.c

LDADD=	-lprocstat
MAN=

.if defined(PREFIX)
LIBDIR?=	${PREFIX}/lib
.endif

.include <bsd.lib.mk>
