#ifndef __common_h
#define __common_h

double percentage(unsigned long long int, unsigned long long int);
int str_comp(const void *, const void *);
int int_comp(const void *, const void *);
char *grep_awk(FILE *, char *, int, char *);
char *squeeze(char *, char *);
char *cpslib_strdup(char *s );

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "config.h"

// TODO use strtok_s, strcpy_s, __strdup and strerror_s per default on windows

#ifndef max
#define max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })
#endif

#ifndef min
#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })
#endif

#ifndef HAVE_STRDUP
# ifdef HAVE__STRDUP
#  define strdup _strdup
# else
#  define strdup cpslib_strdup
# endif
#endif

#if defined(_WIN32) || defined(_WIN64)
#  define snprintf _snprintf
#  define vsnprintf _vsnprintf
#  define strcasecmp _stricmp
#  define strncasecmp _strnicmp
#endif

#ifdef NDEBUG
#define debug(M, ...)
#else
#define debug(M, ...) fprintf(stderr, "DEBUG %s:%d: " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#endif

//#if defined(_WIN32) || defined(_WIN64)
char* clean_errno();
//#else
//#  define clean_errno() (errno == 0 ? "None" : strerror(errno))
//#endif

#define log_err(M, ...) fprintf(stderr, "[ERROR] (%s:%d:%s: errno: %s) " M "\n", __FILE__, __LINE__, __FUNCTION__, clean_errno(), ##__VA_ARGS__)
#define log_warn(M, ...) fprintf(stderr, "[WARN] (%s:%d: errno: %s) " M "\n", __FILE__, __LINE__, clean_errno(), ##__VA_ARGS__)
#define log_info(M, ...) fprintf(stderr, "[INFO] (%s:%d) " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)


#define check(A, M, ...) if (!(A)) {log_err(M, ##__VA_ARGS__); errno=0; goto error; }

#define sentinel(M, ...) { log_err(M, ##__VA_ARGS__); errno = 0; goto error; }

#define check_mem(A) check((A), "Out of memory.")

#define check_debug(A, M, ...) if (!(A)) { debug(M, ##__VA_ARGS__); errno=0; goto error; }

#endif
