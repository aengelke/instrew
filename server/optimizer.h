
#ifndef _INSTREW_SERVER_OPTIMIZER_H
#define _INSTREW_SERVER_OPTIMIZER_H

#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/Function.h>
#include <cstddef>
#include <cstdio>
#include <cstdint>


class Optimizer {
public:
    void Optimize(llvm::Function* fn);

    /// Dump optimizer configuration into the buffer.
    void appendConfig(llvm::SmallVectorImpl<uint8_t>& buffer) const;
};

#endif
