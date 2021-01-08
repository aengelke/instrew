
#ifndef _INSTREW_SERVER_CALLCONV_H
#define _INSTREW_SERVER_CALLCONV_H

#include <llvm/IR/Function.h>


enum class CallConv {
    CDECL,
    HHVM,
    RV64_X86_HHVM,
};

llvm::Function* ChangeCallConv(llvm::Function* fn, CallConv cc);

#endif
