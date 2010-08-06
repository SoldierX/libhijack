#if !defined(_HIJACK_PTRACE_H)
#define _HIJACK_PTRACE_H

struct _hijack;

void *read_data(struct _hijack *, unsigned long, size_t);
char *read_str(struct _hijack *, unsigned long);
int write_data(struct _hijack *, unsigned long, void *, size_t);

#endif
