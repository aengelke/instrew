
#ifndef _INSTREW_DISPATCHER_INFO_H
#define _INSTREW_DISPATCHER_INFO_H

#include <common.h>

struct DispatcherInfo {
    void (*loop_func)(uint64_t* cpu_regs);
    void (*quick_dispatch_func)();
    void (*full_dispatch_func)();
};

#endif
