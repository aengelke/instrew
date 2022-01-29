
#ifndef _INSTREW_SERVER_CALLCONV_H
#define _INSTREW_SERVER_CALLCONV_H

#include <llvm/IR/Function.h>


enum class CallConv {
    CDECL,
    HHVM,
    RV64_X86_HHVM,
    AARCH64_X86_HHVM,
    X86_AARCH64_X,
};

CallConv GetFastCC(int host_arch, int guest_arch);
int GetCallConvClientNumber(CallConv cc);
llvm::Function* ChangeCallConv(llvm::Function* fn, CallConv cc);

#endif
