
#ifndef _INSTREW_EMULATE_H
#define _INSTREW_EMULATE_H

#include <common.h>

void emulate_cpuid(uint64_t* cpu_state);
void emulate_syscall(uint64_t* cpu_state);

#endif
