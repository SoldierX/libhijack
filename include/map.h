#if !defined(_HIJACK_MAP_H)
#define _HIJACK_MAP_H

struct _hijack;

struct mmap_arg_struct {
	unsigned long addr;
	unsigned long len;
	unsigned long prot;
	unsigned long flags;
	unsigned long fd;
	unsigned long offset;
};

unsigned long map_memory(HIJACK *, size_t, unsigned long, unsigned long);
unsigned long map_memory_absolute(HIJACK *, unsigned long, size_t, unsigned long, unsigned long);
unsigned long map_memory_args(HIJACK *, size_t, struct mmap_arg_struct *);
int inject_shellcode(HIJACK *, unsigned long, void *, size_t);

#endif
