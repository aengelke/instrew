
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
    int perfmap_fd;

    RtldObject* objects;
    size_t objects_idx;
    size_t objects_cap;

    void* plt;

    void* server_funcs[16];
};
typedef struct Rtld Rtld;

struct RtldPatchData;

int rtld_init(Rtld* r, int perfmap_fd);
int rtld_resolve(Rtld* r, uintptr_t addr, void** out_entry);

int rtld_add_object(Rtld* r, void* obj_base, size_t obj_size);

void rtld_patch(struct RtldPatchData* patch_data, void* sym);

#endif
