.sinclude <src.opts.mk>

PROG=	hijack
SRCS=	hijack.c
MAN=

.if defined(PREFIX)
BINDIR?=	${PREFIX}/sbin
.else
BINDIR?=	/usr/sbin
.endif

CFLAGS+=	-I${.CURDIR}/../include \
		-I/usr/src/libexec/rtld-elf \
		-I/usr/src/libexec/rtld-elf/${MACHINE_ARCH} \
		-D${MACHINE_ARCH}
LDFLAGS+=	-L${.CURDIR}/../libhijack/obj

LDADD+=		-lhijack

.include <bsd.prog.mk>
