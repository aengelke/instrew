
#ifndef _INSTREW_SERVER_OPTIMIZER_H
#define _INSTREW_SERVER_OPTIMIZER_H

#include <llvm/IR/Function.h>
#include <cstddef>
#include <cstdio>
#include <cstdint>


struct InstrewConfig;

class Optimizer {
private:
    InstrewConfig& instrew_cfg;

public:
    Optimizer(InstrewConfig& instrew_cfg) : instrew_cfg(instrew_cfg) {}

    void Optimize(llvm::Function* fn);
};

#endif
