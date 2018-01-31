.sinclude <src.opts.mk>

SHLIB=		dummyso
SHLIB_MAJOR=	0
SRCS=	\
	dummyso.c

.if defined(PREFIX)
LIBDIR?=	${PREFIX}/lib
.endif

.include <bsd.lib.mk>
