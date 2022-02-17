
#ifndef _INSTREW_RTLD_H
#define _INSTREW_RTLD_H

#include <common.h>
#include <dispatcher-info.h>

typedef struct RtldObject RtldObject;
struct Rtld {
    int perfmap_fd;
    const struct DispatcherInfo* disp_info;

    RtldObject* objects;
    size_t objects_idx;
    size_t objects_cap;

    void* plt;

    void* server_funcs[16];
};
typedef struct Rtld Rtld;

struct RtldPatchData {
    uint64_t sym_addr;
    unsigned rel_type;
    unsigned rel_size;
    int64_t addend;
    uintptr_t patch_addr;
};

int rtld_init(Rtld* r, int perfmap_fd, const struct DispatcherInfo* disp_info);
int rtld_resolve(Rtld* r, uintptr_t addr, void** out_entry);

int rtld_add_object(Rtld* r, void* obj_base, size_t obj_size, uint64_t skew);

void rtld_patch(struct RtldPatchData* patch_data, void* sym);

#endif
