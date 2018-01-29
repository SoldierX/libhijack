.sinclude <src.opts.mk>

.include "${.CURDIR}/../Makefile.inc"

PROG=	hijack
SRCS=	hijack.c soe.c
MAN=

.if defined(PREFIX)
BINDIR?=	${PREFIX}/sbin
.else
BINDIR?=	/usr/sbin
.endif

CFLAGS+=	-I${.CURDIR}/../include \
		-I${SRCDIR}/libexec/rtld-elf \
		-I${SRCDIR}/libexec/rtld-elf/${MACHINE_ARCH} \
		-D${MACHINE_ARCH}
LDFLAGS+=	-L${.CURDIR}/../libhijack/obj

LDADD+=		-lhijack

.include <bsd.prog.mk>
