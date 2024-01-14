
#ifndef _INSTREW_SERVER_OPTIMIZER_H
#define _INSTREW_SERVER_OPTIMIZER_H

#include <llvm/IR/Function.h>
#include <cstddef>
#include <cstdio>
#include <cstdint>


class Optimizer {
public:
    void Optimize(llvm::Function* fn);
};

#endif
