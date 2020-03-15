
#ifndef _INSTREW_STATE_H
#define _INSTREW_STATE_H

#include <common.h>
#include <rtld.h>
#include <translator.h>

struct State {
    void* cpu;

    Rtld rtld;
    Translator translator;

    uint64_t rew_time;

    struct {
        int perfmap_fd;
        bool print_trace;
        bool print_regs;
        int opt_level;
        bool profile_rewriting;
        bool profile_llvm_passes;
        bool native_segment_regs;
        bool opt_unsafe_callret;
        bool verbose;
        bool d_dump_objects;
    } config;
};

#define STATE_FROM_CPU_STATE(cpu_state) (*((struct State**) (cpu_state) - 1))

#endif
