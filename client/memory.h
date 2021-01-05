
#ifndef _INSTREW_MEMORY_H
#define _INSTREW_MEMORY_H

#include <common.h>

int mem_init(void);

void* mem_alloc_data(size_t size, size_t alignment);

void* mem_alloc_code(size_t size, size_t alignment);
int mem_write_code(void* dst, const void* src, size_t size);

#endif
