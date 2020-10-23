
#include <instrew-api.h>

#include <llvm/IR/CallSite.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

#include <cstdio>
#include <vector>

namespace {

class Instrumenter {
private:
    llvm::Function* syscall_fn;
    llvm::Function* wrap_fn;

    void InitSyscallWrapper(llvm::Module* mod) {
        syscall_fn = mod->getFunction("syscall");

        llvm::IRBuilder<> irb(mod->getContext());
        auto dprintf_ty = llvm::FunctionType::get(irb.getVoidTy(), true);
        llvm::Function* dprintf_fn = llvm::Function::Create(dprintf_ty,
                                            llvm::GlobalValue::ExternalLinkage,
                                            "dprintf", mod);

        wrap_fn = llvm::Function::Create(syscall_fn->getFunctionType(),
                                         llvm::GlobalValue::ExternalLinkage,
                                         "syscall_strace", mod);
        llvm::BasicBlock* bb = llvm::BasicBlock::Create(mod->getContext(), "",
                                                        wrap_fn);
        irb.SetInsertPoint(bb);

        llvm::Value* sptr = &wrap_fn->arg_begin()[0];
        unsigned sptr_as = sptr->getType()->getPointerAddressSpace();
        llvm::Type* i64p_sptr = irb.getInt64Ty()->getPointerTo(sptr_as);
        llvm::Value* rax_ptr = irb.CreateConstGEP1_64(sptr, 0x8);
        rax_ptr = irb.CreatePointerCast(rax_ptr, i64p_sptr);
        llvm::Value* rax = irb.CreateLoad(irb.getInt64Ty(), rax_ptr);

        const char* fmt_str = "syscall %u(...)\n";
        llvm::Constant* syscall_pre_fmt = irb.CreateGlobalStringPtr(fmt_str);
        irb.CreateCall(dprintf_fn, {irb.getInt64(2), syscall_pre_fmt, rax});

        irb.CreateCall(syscall_fn, {sptr});
        irb.CreateRetVoid();
    }

public:
    Instrumenter(const char* config, llvm::Module* mod,
                 InstrewDesc* out_desc) {
        InitSyscallWrapper(mod);

        // Fields instrument and finalize are filled out below.
        out_desc->magic = 0xAEDB1000;
        out_desc->flags = INSTREW_DESC_OPTIMIZE | INSTREW_DESC_SUPPORTS_HHVM |
                          INSTREW_DESC_CACHABLE;
        out_desc->name = "Strace";
        out_desc->uuid = "58211e41-b2be-44eb-9d52-806059aa01f4";
    }

    ~Instrumenter() {}

    llvm::Function* Instrument(llvm::Function* fn) {
        for (llvm::BasicBlock& bb : *fn)
            for (llvm::Instruction& instr : bb)
                if (auto call = llvm::dyn_cast<llvm::CallInst>(&instr))
                    if (call->getCalledFunction() == syscall_fn)
                        call->setCalledFunction(wrap_fn);

        return fn;
    }
};

} // anonymous namespace

void* instrew_init_instrumenter(const char* config, LLVMModuleRef mod,
                                struct InstrewDesc* out_desc) {
    auto* cls = new Instrumenter(config, llvm::unwrap(mod), out_desc);
    out_desc->instrument = [](void* handle, LLVMValueRef fn) {
        auto* cls = static_cast<Instrumenter*>(handle);
        return llvm::wrap(cls->Instrument(llvm::unwrap<llvm::Function>(fn)));
    };
    out_desc->finalize = [](void* handle) {
        delete static_cast<Instrumenter*>(handle);
    };
    return cls;
}
