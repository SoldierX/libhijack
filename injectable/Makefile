.sinclude <src.opts.mk>

PROG=	injectable
SRCS=	injectable.c
MAN=

.if defined(PREFIX)
BINDIR?=	${PREFIX}/sbin
.else
BINDIR?=	/usr/sbin
.endif

.include <bsd.prog.mk>
