#if !defined(_HIJACK_SO_H)
#define _HIJACK_SO_H

typedef struct _so_map
{
	unsigned long vaddr;
	unsigned long mmaped_vaddr;
	unsigned int perms;
	
	struct _so_map *next;
} MAP;

typedef struct _shared_object
{
	char *name;
	int fd;
	struct stat sb;
	
	union
	{
		unsigned char *buf;
		void *p;
		unsigned long addr;
	} parent_map;
	
	ElfW(Ehdr) *ehdr;
	ElfW(Phdr) *phdr;
	ElfW(Shdr) *shdr;
	
	MAP *maps;
} SO;

SO *load_shared_object(HIJACK *, const char *);
int prepare_maps(HIJACK *, SO *);

#endif
