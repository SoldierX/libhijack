#if !defined(_OS_RESOLV_H)
#define _OS_RESOLV_H

typedef enum _rtld_sym_type { UNKNOWN=0, VAR=1, FUNC=2 } RTLD_SYM_TYPE;

typedef struct _rtld_sym {
    RTLD_SYM_TYPE type;
    char *name; /* Not guarantee to be non-NULL */

    union {
        void *vp;
        unsigned long ulp;
    } p;

    size_t sz;
} RTLD_SYM;

unsigned long find_rtld_linkmap(HIJACK *);
RTLD_SYM *resolv_rtld_sym(HIJACK *, char *);

#endif
