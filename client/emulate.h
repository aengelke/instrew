
#ifndef _INSTREW_EMULATE_H
#define _INSTREW_EMULATE_H

#include <common.h>

void emulate_cpuid(uint64_t* cpu_state);
void emulate_syscall(uint64_t* cpu_state);
__int128 emulate___divti3(__int128, __int128);
unsigned __int128 emulate___udivti3(unsigned __int128, unsigned __int128);
__int128 emulate___modti3(__int128, __int128);
unsigned __int128 emulate___umodti3(unsigned __int128, unsigned __int128);

#endif
