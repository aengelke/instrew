
#include <instrew-api.h>

#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>

namespace {

class InstrumenterNone {
public:
    InstrumenterNone(const char* config, llvm::Module* mod,
                     InstrewDesc* out_desc) {
        // Fields instrument and finalize are filled out below.
        out_desc->magic = 0xAEDB1000;
        out_desc->flags = INSTREW_DESC_OPTIMIZE | INSTREW_DESC_SUPPORTS_HHVM |
                          INSTREW_DESC_CACHABLE;
        out_desc->name = "None";
        out_desc->uuid = "e023b8a9-b7e3-485f-9da3-916abd356798";
    }

    ~InstrumenterNone() {}

    llvm::Function* Instrument(llvm::Function* fn) {
        // Do nothing.
        return fn;
    }
};

} // anonymous namespace

void* instrew_init_instrumenter(const char* config, LLVMModuleRef mod,
                                struct InstrewDesc* out_desc) {
    auto* cls = new InstrumenterNone(config, llvm::unwrap(mod), out_desc);
    out_desc->instrument = [](void* handle, LLVMValueRef fn) {
        auto* cls = static_cast<InstrumenterNone*>(handle);
        return llvm::wrap(cls->Instrument(llvm::unwrap<llvm::Function>(fn)));
    };
    out_desc->finalize = [](void* handle) {
        delete static_cast<InstrumenterNone*>(handle);
    };
    return cls;
}
