AC_INIT([libhijack], [0.7], [lattera@gmail.com])

AC_CONFIG_SRCDIR([src/elf.c])
AC_CONFIG_HEADERS([include/config.h])

# Prefer clang
AC_PROG_CC([clang gcc])
AC_PROG_INSTALL

AC_CHECK_HEADERS([stdlib.h elf.h link.h])

AC_CONFIG_FILES([Makefile
                 src/Makefile])

AC_OUTPUT
