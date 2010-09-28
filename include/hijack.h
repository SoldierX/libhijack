#if !defined(_HIJACK_H)
#define _HIJACK_H

#include <sys/types.h>
#include <elf.h>
#include <link.h>

#define EXPORTED_SYM __attribute__((visibility("default")))

#define ERROR_NONE				0
#define ERROR_ATTACHED			1
#define ERROR_NOTATTACHED		2
#define ERROR_BADPID			3
#define ERROR_SYSCALL			4
#define ERROR_NOTIMPLEMENTED	5
#define ERROR_BADARG			6
#define ERROR_CHILDERROR		7
#define ERROR_NEEDED			8

#define F_NONE			0
#define F_DEBUG			1
#define F_DEBUG_VERBOSE	2

#define V_NONE		0
#define V_BASEADDR	1

typedef enum _bool {false=0, true=1} bool;

struct _func;

typedef struct _hijack {
	char *version;
	int pid;
	int lastErrorCode;
	bool isAttached;
	unsigned int flags;
	
	unsigned long baseaddr;
	
	union {
		void *raw;
		unsigned char *buf;
		ElfW(Ehdr) *ehdr;
	} ehdr;
	
	union {
		void *raw;
		unsigned char *buf;
		ElfW(Phdr) *phdr;
	} phdr;
	
	union {
		void *raw;
		unsigned char *buf;
		ElfW(Shdr) *shdr;
	} shdr;
	
	struct user_regs_struct *backup_regs;
	
	unsigned long pltgot;
	struct link_map *linkhead;
	
	unsigned long syscalladdr;
	struct _func *funcs;
	
	/* Because of the limitations of the current API, we need to store the uncached funcs here */
	struct _func *uncached_funcs;
} HIJACK;

int GetErrorCode(HIJACK *);
const char *GetErrorString(HIJACK *);
HIJACK *InitHijack(void);
bool IsFlagSet(HIJACK *, unsigned int);
int ToggleFlag(HIJACK *, unsigned int);
void *GetValue(HIJACK *, int);
int SetValue(HIJACK *, int, void *);
bool IsAttached(HIJACK *);
int AssignPid(HIJACK *, pid_t);
int Attach(HIJACK *);
int Detach(HIJACK *);
int LocateSystemCall(HIJACK *);
int ReadData(HIJACK *, unsigned long, unsigned char *, size_t);
int WriteData(HIJACK *, unsigned long , unsigned char *, size_t);
unsigned long MapMemory(HIJACK *, unsigned long, size_t, unsigned long, unsigned long);
int InjectShellcode(HIJACK *, unsigned long, void *, size_t);
struct user_regs_struct *GetRegs(HIJACK *);
int SetRegs(HIJACK *, struct user_regs_struct *);

unsigned long FindFunctionInGot(HIJACK *, unsigned long);

#endif
