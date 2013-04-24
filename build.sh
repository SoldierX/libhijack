#!/usr/bin/env bash

OS=$(uname -s)
ARCH=$(uname -m)

# Prefer clang, deprecate gcc
CC=$(which clang)
#CC=$(which gcc)
if [ ${#CC} -eq 0 ]; then
    CC="gcc"
fi

PREFIX="/usr"
if [ ${OS} = "FreeBSD" ]; then
    PREFIX="/usr/local"
fi

MAKE="make"
if [ ${OS} = "FreeBSD" ]; then
    MAKE="gmake"
fi

build() {
    cd src

    ${MAKE} PREFIX=${PREFIX} OS=${OS} ARCH=${ARCH} CC=${CC} $1
    ret=$?

    cd ..
    return $ret
}

install() {
    if [ ${UID} -gt 0 ]; then
        echo "ERROR: Must be root to install. Exiting."
        return 1
    fi

    build install
    return $?
}

uninstall() {
    if [ ${UID} -gt 0 ]; then
        echo "ERROR: Must be root to deinstall. Exiting."
        return 1
    fi

    build deinstall
    return $?
}

case $1 in
    build)
        build
        exit $?
        ;;
    install)
        install
        exit $?
        ;;
    clean)
        build clean
        exit $?
        ;;
    deinstall|uninstall)
        uninstall
        exit $?
        ;;
    help)
        echo "USAGE: ${0} [build|install|deinstall]"
        exit 1
        ;;
    *)
        build clean
        if [ ! $? -eq 0 ]; then
            exit $?
        fi
        build
        exit $?
        ;;
esac
