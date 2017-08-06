Libhijack - FreeBSD Code Injection Swiss Army Knife
===================================================

Libhijack is a tool that enables easy injection of arbitrary code
during runtime. Injection is done into newly-created anonymous memory
mappings, providing stealth. An API is provided for hooking the
PLT/GOT, hence the "hijack" part of libhijack.

*NOTE*: libhijack is undergoing a major revamp. Please do not consider
the ABI or API as stable for the moment.

Please note also that the freebsd_tests64 directory is not in a usable
state. It's simply there for historical purposes. At some point of
time in the near future, once the `hijack` application becomes
fully-featured, the freebsd_tests64 directory will be deleted.

Building libhijack
==================

```
# make depend all install
```
