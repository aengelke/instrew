
#ifndef _INSTREW_DISPATCH_H
#define _INSTREW_DISPATCH_H

#include <common.h>
#include <state.h>

int dispatch_loop(struct State* state, uintptr_t ip, uintptr_t sp);

#endif
