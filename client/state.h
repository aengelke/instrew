
#ifndef _INSTREW_STATE_H
#define _INSTREW_STATE_H

#include <common.h>
#include <rtld.h>
#include <translator.h>

struct State {
    Rtld rtld;
    Translator translator;

    uint64_t rew_time;

    struct {
        int perfmap_fd;
        bool print_trace;
        bool print_regs;
        bool profile_rewriting;
    } config;

    struct TranslatorServerConfig tsc;
    struct TranslatorConfig tc;
};

#define QUICK_TLB_BITS 10

struct CpuState {
    struct CpuState* self;
    struct State* state;
    uintptr_t _unused[6];

    _Alignas(64) uint8_t regdata[0x400];

    _Alignas(64) uint64_t quick_tlb[1 << QUICK_TLB_BITS][2];
};

#define CPU_STATE_REGDATA_OFFSET 0x40
_Static_assert(offsetof(struct CpuState, regdata) == CPU_STATE_REGDATA_OFFSET,
               "CPU_STATE_REGDATA_OFFSET mismatch");

#define CPU_STATE_QTLB_OFFSET 0x440
_Static_assert(offsetof(struct CpuState, quick_tlb) == CPU_STATE_QTLB_OFFSET,
               "CPU_STATE_QTLB_OFFSET mismatch");

#define CPU_STATE_FROM_REGS(regdata) ((struct CpuState*) \
                                   ((char*) regdata - CPU_STATE_REGDATA_OFFSET))

#endif
