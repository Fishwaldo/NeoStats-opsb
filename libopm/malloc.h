#ifndef MALLOC_H
#define MALLOC_H

#ifdef WIN32
#include "modconfigwin32.h"
#else
#include "modconfig.h"
#endif

#ifdef STDC_HEADERS
# include <stdlib.h>
#endif

#define MyMalloc(SIZE) libopm_MyMalloc(SIZE)
#define MyFree(X) libopm_MyFree((void **) &X)

void *libopm_MyMalloc(size_t bytes);
void libopm_MyFree(void **var);

#endif /* MALLOC_H */
