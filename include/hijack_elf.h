#if !defined(_HIJACK_ELF_H)
#define _HIJACK_ELF_H

#if defined(i686)
	#define BASEADDR 0x08048000
	#define SYSCALLSEARCH "\xcd\x80"
	#define MMAPSYSCALL 90
#elif defined(x86_64)
	#define BASEADDR 0x00400000
	#define SYSCALLSEARCH "\x0f\x05"
	/* #define SYSCALLSEARCH "\xcd\x80" */
	#define MMAPSYSCALL 9
#else
	#error "Architecture not supported!"
#endif

struct _hijack;

typedef enum _cbresult { NONE=0, CONTPROC=1, TERMPROC=2 } CBRESULT;

/* params: &HIJACK, &linkmap, name, vaddr, size */
typedef CBRESULT (*linkmap_callback)(struct _hijack *, struct link_map *, char *, unsigned long, size_t);

int init_elf_headers(HIJACK *);
unsigned long find_pltgot(struct _hijack *);
unsigned long find_link_map_addr(HIJACK *);
struct link_map *get_next_linkmap(HIJACK *, unsigned long);
void parse_linkmap(HIJACK *, struct link_map *, linkmap_callback);
unsigned long search_mem(HIJACK *, unsigned long, size_t, void *, size_t);

CBRESULT syscall_callback(HIJACK *, struct link_map *, char *, unsigned long, size_t);

int init_hijack_system(HIJACK *);

unsigned long find_func_addr_in_got(HIJACK *, unsigned long);
#endif
