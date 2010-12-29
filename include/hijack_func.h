#if !defined(_HIJAC_FUNC_H)
#define _HIJACK_FUNC_H

typedef struct _func
{
	char *libname;
	char *name;
	unsigned long vaddr;
	size_t sz;

	struct _func *next;
} FUNC;

int LocateAllFunctions(HIJACK *);
FUNC *FindAllFunctionsByName(HIJACK *, char *, bool);
FUNC *FindAllFunctionsByLibraryName_uncached(HIJACK *, char *);
FUNC *FindAllFunctionsByLibraryName(HIJACK *, char *);
FUNC *FindFunctionInLibraryByName(HIJACK *hijack, char *, char *);

#endif
