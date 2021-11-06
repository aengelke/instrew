
#ifndef _INSTREW_SERVER_OPTIMIZER_H
#define _INSTREW_SERVER_OPTIMIZER_H

#include <llvm/IR/Function.h>
#include <llvm/IR/LegacyPassManager.h>
#include <cstddef>
#include <cstdio>
#include <cstdint>


struct InstrewConfig;

class Optimizer {
private:
    std::unique_ptr<llvm::legacy::PassManager> legacy_pm;
    InstrewConfig& instrew_cfg;

public:
    Optimizer(InstrewConfig& instrew_cfg);

    void Optimize(llvm::Function* fn);
};

#endif
