
#ifndef _INSTREW_RTLD_H
#define _INSTREW_RTLD_H

#include <common.h>

typedef struct {
    uintptr_t addr;
    void* entry;
    void* base;
    size_t size;
} RtldObject;
struct Rtld {
    void* addrspace;
    size_t addrspace_size;

    RtldObject* objects;
    size_t objects_idx;
    size_t objects_cap;

    void* plt;
};
typedef struct Rtld Rtld;

int rtld_init(Rtld* r);
int rtld_resolve(Rtld* r, uintptr_t addr, void** out_entry);

int rtld_add_object(Rtld* r, uintptr_t addr, void* obj_base, size_t obj_size, void** out_entry);

#endif
