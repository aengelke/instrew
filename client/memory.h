
#ifndef _INSTREW_MEMORY_H
#define _INSTREW_MEMORY_H

#include <common.h>

int mem_init(void);
void* mem_alloc(size_t size);
int mem_free(void* addr, size_t size);

#endif
