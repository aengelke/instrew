
#ifndef _INSTREW_SERVER_CALLCONV_H
#define _INSTREW_SERVER_CALLCONV_H

#include <llvm/IR/Function.h>


enum class CallConv {
    CDECL,
#if LL_LLVM_MAJOR < 17
    // LLVM 17 droped hhvmcc
    HHVM,
    RV64_X86_HHVM,
    AARCH64_X86_HHVM,
#endif
    X86_X86_REGCALL,
    RV64_X86_REGCALL,
    AARCH64_X86_REGCALL,
    X86_AARCH64_X,
    AARCH64_AARCH64_X,
};

CallConv GetFastCC(int host_arch, int guest_arch);
int GetCallConvClientNumber(CallConv cc);
llvm::Function* ChangeCallConv(llvm::Function* fn, CallConv cc);

#endif
