Libhijack - FreeBSD Code Injection Swiss Army Knife
===================================================

Libhijack is a tool that enables easy injection of arbitrary code
during runtime. Injection is done into newly-created anonymous memory
mappings, providing stealth. An API is provided for hooking the
PLT/GOT, hence the "hijack" part of libhijack.

*NOTE*: libhijack is undergoing a major revamp. Please do not consider
the ABI or API as stable for the moment.

Supported Architectures
-----------------------

* amd64
* arm64

Prerequisites
-------------

* FreeBSD source code in /usr/src matching the system libhijack is to
  target.

Building libhijack
------------------

```
# make depend all install
```
