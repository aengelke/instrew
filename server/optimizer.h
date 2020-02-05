
#ifndef _INSTREW_SERVER_OPTIMIZER_H
#define _INSTREW_SERVER_OPTIMIZER_H

#include <llvm/IR/Function.h>
#include <llvm/IR/LegacyPassManager.h>
#include <cstddef>
#include <cstdio>
#include <cstdint>


struct ServerConfig;

class Optimizer {
private:
    std::unique_ptr<llvm::legacy::PassManager> legacy_pm;
    ServerConfig& server_config;

public:
    Optimizer(ServerConfig& server_config);

    void Optimize(llvm::Function* fn);
};

#endif
