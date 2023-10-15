#!/bin/sh

if [ $(id -u) -gt 0 ]; then
	echo "[-] Please run this as root" >&2
	exit 1
fi

sysctl \
	hardening.harden_rtld=0 \
	hardening.harden_shm=1 \
	hardening.pax.aslr.status=1 \
	hardening.pax.mprotect.status=1 \
	hardening.pax.pageexec.status=1 \
	hardening.prohibit_ptrace_capsicum=1 \
	hardening.prohibit_ptrace_syscall=0 \
	security.bsd.allow_ptrace=1 \
	security.bsd.unprivileged_proc_debug=1
res=${?}
if [ ${res} -gt 0 ]; then
	exit ${res}
fi
