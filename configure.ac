AC_INIT([libhijack], [0.7], [lattera@gmail.com])
AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE

AC_CONFIG_SRCDIR([src/elf.c])
AC_CONFIG_HEADERS([include/config.h])

# Prefer clang
AC_PROG_CC([clang gcc])
AC_PROG_INSTALL
AC_PROG_RANLIB

case "$target_os" in
freebsd*)
    CPPFLAGS="$CPPFLAGS -DFreeBSD"
    ;;
linux*)
    CPPFLAGS="$CPPFLAGS -DLinux"
    ;;
*)
    echo "Unsupported OS"
    exit 1
    ;;
esac

echo "target_cpu: $target_cpu"

case "$target_cpu" in
i*86*)
    CPPFLAGS="$CPPFLAGS -Di386"
    ;;
amd64|x86_64)
    CPPFLAGS="$CPPFLAGS -Damd64 -Dx86_64"
    ;;
*)
    echo "Unsupported Architecture"
    exit 1
    ;;
esac

AC_CHECK_HEADERS([stdlib.h elf.h link.h])

AC_CONFIG_FILES([Makefile
                 src/Makefile])

AC_OUTPUT
