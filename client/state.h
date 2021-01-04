
#ifndef _INSTREW_STATE_H
#define _INSTREW_STATE_H

#include <common.h>
#include <rtld.h>
#include <translator.h>

struct State {
    /// Points to the CPU state. There are additional 64 bytes available
    /// immediately *before* this address. The *last* 8 bytes are used
    /// internally to store a reference to this State structure. The other 56
    /// bytes can be used freely by instrumentation tools.
    void* cpu;

    Rtld rtld;
    Translator translator;

    uint64_t rew_time;

    struct {
        int perfmap_fd;
        bool print_trace;
        bool print_regs;
        bool profile_rewriting;
    } config;

    struct TranslatorConfig tc;
};

#define STATE_FROM_CPU_STATE(cpu_state) (*((struct State**) (cpu_state) - 1))
#define QTLB_FROM_CPU_STATE(cpu_state) (*((uint64_t (**)[2]) (cpu_state) - 2))

#endif
