
#include "callconv.h"
#include "codegenerator.h"
#include "config.h"
#include "connection.h"
#include "instrew-server-config.h"
#include "optimizer.h"

#include <instrew-api.h>
#include <rellume/rellume.h>

#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassTimingInfo.h>
#include <llvm/Support/CommandLine.h>

#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <dlfcn.h>
#include <elf.h>
#include <fstream>
#include <iostream>
#include <unistd.h>
#include <sstream>
#include <unordered_map>


#define SPTR_ADDR_SPACE 1

static llvm::Function* CreateFunc(llvm::LLVMContext& ctx,
                                  const std::string name) {
    llvm::Type* sptr = llvm::Type::getInt8PtrTy(ctx, SPTR_ADDR_SPACE);
    llvm::Type* void_ty = llvm::Type::getVoidTy(ctx);
    auto* fn_ty = llvm::FunctionType::get(void_ty, {sptr}, false);
    auto linkage = llvm::GlobalValue::ExternalLinkage;
    return llvm::Function::Create(fn_ty, linkage, name);
}

static llvm::GlobalVariable* CreatePcBase(llvm::LLVMContext& ctx) {
    llvm::Type* i64 = llvm::Type::getInt64Ty(ctx);
    auto* pc_base_var = new llvm::GlobalVariable(i64, false,
                                                 llvm::GlobalValue::ExternalLinkage);
    pc_base_var->setName("instrew_baseaddr");
    llvm::Constant* lim_val = llvm::ConstantInt::get(i64, -1);
    llvm::Metadata* lim = llvm::ConstantAsMetadata::get(lim_val);
    llvm::MDNode* node = llvm::MDNode::get(ctx, {lim, lim});
    pc_base_var->setMetadata("absolute_symbol", node);
    return pc_base_var;
}

class InstrumenterTool {
private:
    void* dl_handle;
    void* tool_handle;
    InstrewDesc desc;

public:
    InstrumenterTool() : dl_handle(nullptr), desc{} {}
    ~InstrumenterTool() {
        if (desc.finalize)
            desc.finalize(tool_handle);
        if (dl_handle)
            dlclose(dl_handle);
    }

    int Init(const InstrewConfig& instrew_cfg, llvm::Module* mod) {
        if (instrew_cfg.tool == "") {
            desc.flags = INSTREW_DESC_OPTIMIZE | INSTREW_DESC_CACHABLE;
            return 0;
        }

        std::string tool_lib = instrew_cfg.tool;
        if (tool_lib.find('/') == std::string::npos) {
            std::stringstream ss;
            ss << INSTREW_TOOL_PATH << "/tool-" << instrew_cfg.tool << ".so";
            tool_lib = ss.str();
        }
        dl_handle = dlopen(tool_lib.c_str(), RTLD_NOW);
        if (!dl_handle) {
            std::cerr << "error: could not open tool: " << dlerror() << std::endl;
            return -ELIBBAD;
        }
        decltype(instrew_init_instrumenter)* tool_func;
        *((void**) &tool_func) = dlsym(dl_handle, "instrew_init_instrumenter");
        if (!tool_func) {
            std::cerr << "error: could not open tool: " << dlerror() << std::endl;
            return -ELIBBAD;
        }

        tool_handle = tool_func(instrew_cfg.tool.c_str(),
                                llvm::wrap(mod), &desc);
        if (desc.magic != 0xAEDB1000) {
            std::cerr << "error: incompatible tool" << std::endl;
            return -EINVAL;
        }

        return 0;
    }

    llvm::Function* Instrument(llvm::Function* fn) {
        if (!desc.instrument)
            return fn;
        LLVMValueRef new_fn = desc.instrument(tool_handle, llvm::wrap(fn));
        return llvm::unwrap<llvm::Function>(new_fn);
    }

    bool Optimize() {
        return !!(desc.flags & INSTREW_DESC_OPTIMIZE);
    }
    bool MarkInstrs() {
        return !!(desc.flags & INSTREW_DESC_MARK_INSTRS);
    }
};


struct IWState {
private:
    IWConnection* iwc;
    const IWServerConfig* iwsc = nullptr;
    IWClientConfig* iwcc = nullptr;
    const InstrewConfig instrew_cfg;
    CallConv instrew_cc = CallConv::CDECL;

    LLConfig* rlcfg;
    llvm::LLVMContext ctx;
    llvm::Constant* pc_base;
    llvm::SmallVector<llvm::Function*, 8> helper_fns;
    std::unique_ptr<llvm::Module> mod;

    InstrumenterTool tool;

    Optimizer optimizer;
    llvm::SmallVector<char, 4096> obj_buffer;
    CodeGenerator codegen;

    std::chrono::steady_clock::duration dur_lifting{};
    std::chrono::steady_clock::duration dur_instrument{};
    std::chrono::steady_clock::duration dur_llvm_opt{};
    std::chrono::steady_clock::duration dur_llvm_codegen{};

public:

    IWState(IWConnection* iwc, unsigned argc, const char* const* argv)
            : instrew_cfg(argc - 1, argv + 1), optimizer(instrew_cfg),
              codegen(*iw_get_sc(iwc), instrew_cfg, obj_buffer) {
        this->iwc = iwc;
        iwsc = iw_get_sc(iwc);
        iwcc = iw_get_cc(iwc);

        iw_set_dumpobj(iwc, instrew_cfg.dumpobj);

        llvm::cl::ParseEnvironmentOptions(argv[0], "INSTREW_SERVER_LLVM_OPTS");
        llvm::TimePassesIsEnabled = instrew_cfg.timepasses;

        rlcfg = ll_config_new();
        ll_config_enable_verify_ir(rlcfg, false);
        ll_config_set_call_ret_clobber_flags(rlcfg, !instrew_cfg.safecallret);
        ll_config_enable_full_facets(rlcfg, instrew_cfg.fullfacets);
        ll_config_set_sptr_addrspace(rlcfg, SPTR_ADDR_SPACE);
        ll_config_enable_overflow_intrinsics(rlcfg, false);
        if (instrew_cfg.callret) {
            auto call_fn = CreateFunc(ctx, "instrew_call_cdecl");
            helper_fns.push_back(call_fn);
            ll_config_set_tail_func(rlcfg, llvm::wrap(call_fn));
            ll_config_set_call_func(rlcfg, llvm::wrap(call_fn));
        }
        if (iwsc->tsc_guest_arch == EM_X86_64) {
            ll_config_set_architecture(rlcfg, "x86-64");
            iwcc->tc_callconv = 0; // cdecl
            // TODO: check host arch
            if (instrew_cfg.callconv == 2) {
                instrew_cc = CallConv::HHVM;
                iwcc->tc_callconv = 1;
            } else if (instrew_cfg.callconv == 3) {
                instrew_cc = CallConv::X86_X86_RC;
                iwcc->tc_callconv = 2;
            } else if (instrew_cfg.callconv == 5) {
                instrew_cc = CallConv::X86_AARCH64_X;
                iwcc->tc_callconv = 3;
            }

            auto syscall_fn = CreateFunc(ctx, "syscall");
            helper_fns.push_back(syscall_fn);
            ll_config_set_syscall_impl(rlcfg, llvm::wrap(syscall_fn));

            // cpuinfo function is CPUID on x86-64.
            llvm::Type* i32 = llvm::Type::getInt32Ty(ctx);
            llvm::Type* i64 = llvm::Type::getInt64Ty(ctx);
            auto i64_i64 = llvm::StructType::get(i64, i64);
            auto cpuinfo_fn_ty = llvm::FunctionType::get(i64_i64, {i32, i32}, false);
            auto linkage = llvm::GlobalValue::ExternalLinkage;
            auto cpuinfo_fn = llvm::Function::Create(cpuinfo_fn_ty, linkage, "cpuid");
            helper_fns.push_back(cpuinfo_fn);
            ll_config_set_cpuinfo_func(rlcfg, llvm::wrap(cpuinfo_fn));
        } else if (iwsc->tsc_guest_arch == EM_RISCV) {
            ll_config_set_architecture(rlcfg, "rv64");
            if (iwsc->tsc_host_arch == EM_X86_64 && instrew_cfg.callconv == 2) {
                instrew_cc = CallConv::RV64_X86_HHVM;
                iwcc->tc_callconv = 1;
            }

            auto syscall_fn = CreateFunc(ctx, "syscall_rv64");
            helper_fns.push_back(syscall_fn);
            ll_config_set_syscall_impl(rlcfg, llvm::wrap(syscall_fn));
        } else {
            std::cerr << "error: unsupported architecture" << std::endl;
            abort();
        }

        llvm::GlobalVariable* pc_base_var = CreatePcBase(ctx);
        pc_base = llvm::ConstantExpr::getPtrToInt(pc_base_var,
                                                  llvm::Type::getInt64Ty(ctx));

        mod = std::make_unique<llvm::Module>("mod", ctx);
        llvm::Type* i8p_ty = llvm::Type::getInt8PtrTy(ctx);
        llvm::SmallVector<llvm::Constant*, 8> used;
        mod->getGlobalList().push_back(pc_base_var);
        used.push_back(pc_base_var);
        for (const auto& helper_fn : helper_fns) {
            mod->getFunctionList().push_back(helper_fn);
            used.push_back(llvm::ConstantExpr::getPointerCast(helper_fn, i8p_ty));
        }
        llvm::ArrayType* used_ty = llvm::ArrayType::get(i8p_ty, used.size());
        llvm::GlobalVariable* llvm_used = new llvm::GlobalVariable(
                *mod, used_ty, /*const=*/false,
                llvm::GlobalValue::AppendingLinkage,
                llvm::ConstantArray::get(used_ty, used), "llvm.used");
        llvm_used->setSection("llvm.metadata");

        // if (tool.Init(instrew_cfg, &mod) != 0)
        //     abort();
        // if (tool.MarkInstrs())
        //     ll_config_set_instr_marker(rlcfg, llvm::wrap(marker_fn));

        // // Rename all tool-defined functions appropriately.
        // uint64_t zval_cnt = 1ull << 63;
        // for (llvm::Function& fn : mod->functions()) {
        //     if (fn.empty())
        //         continue;
        //     std::stringstream namebuf;
        //     namebuf << "Z" << std::oct << zval_cnt++ << "_";
        //     fn.setName(llvm::Twine(namebuf.str() + fn.getName()));
        // }

        // codegen.GenerateCode(mod);

        // for (llvm::Function& fn : init_mod.functions()) {
        //     if (!fn.hasExternalLinkage() || fn.empty())
        //         continue;
        //     fn.deleteBody();
        //     helper_fns.push_back(&fn);
        // }
    }
    ~IWState() {
        if (instrew_cfg.profile) {
            std::cerr << "Server profile: "
                      << std::chrono::duration_cast<std::chrono::milliseconds>(dur_lifting).count()
                      << "ms lifting; "
                      << std::chrono::duration_cast<std::chrono::milliseconds>(dur_instrument).count()
                      << "ms instrumentation; "
                      << std::chrono::duration_cast<std::chrono::milliseconds>(dur_llvm_opt).count()
                      << "ms llvm_opt; "
                      << std::chrono::duration_cast<std::chrono::milliseconds>(dur_llvm_codegen).count()
                      << "ms llvm_codegen"
                      << std::endl;
        }
        if (instrew_cfg.timepasses)
            llvm::reportAndResetTimings(&llvm::errs());
    }

private:
    llvm::Function* Lift(uintptr_t addr) {
        // Optionally generate position-independent code, where the offset
        // can be adjusted using relocations. For now, this is always zero.
        if (instrew_cfg.pic)
            ll_config_set_pc_base(rlcfg, 0, llvm::wrap(pc_base));

        LLFunc* rlfn = ll_func_new(llvm::wrap(mod.get()), rlcfg);
        bool decode_fail = ll_func_decode_cfg(rlfn, addr,
            [](size_t addr, uint8_t* buf, size_t buf_sz, void* user_arg) {
                auto* iwc = static_cast<IWConnection*>(user_arg);
                return iw_readmem(iwc, addr, addr + buf_sz, buf);
            },
            iwc);
        if (decode_fail) {
            std::cerr << "error: could not decode at 0x" << std::hex << addr
                      << std::endl;
            return nullptr;
        }
        llvm::Function* fn = llvm::unwrap<llvm::Function>(ll_func_lift(rlfn));
        ll_func_dispose(rlfn);

        std::stringstream namebuf;
        namebuf << "Z" << std::oct << addr << "_" << std::hex << addr;
        fn->setName(namebuf.str());

        return fn;
    }

public:
    IWObject Translate(uintptr_t addr) {
        auto time_lifting_start = std::chrono::steady_clock::now();
        llvm::Function* fn = Lift(addr);
        if (!fn)
            return IWObject{};
        if (instrew_cfg.dumpir & 1)
            mod->print(llvm::errs(), nullptr);

        auto time_instrument_start = std::chrono::steady_clock::now();
        fn = tool.Instrument(fn);
        fn = ChangeCallConv(fn, instrew_cc);
        if (instrew_cfg.dumpir & 2)
            mod->print(llvm::errs(), nullptr);

        auto time_llvm_opt_start = std::chrono::steady_clock::now();
        optimizer.Optimize(fn);
        if (instrew_cfg.dumpir & 4)
            mod->print(llvm::errs(), nullptr);

        auto time_llvm_codegen_start = std::chrono::steady_clock::now();
        codegen.GenerateCode(mod.get());
        if (instrew_cfg.dumpir & 8)
            mod->print(llvm::errs(), nullptr);

        // Remove unused functions and dead prototypes. Having many prototypes
        // causes some compile-time overhead.
        for (auto& glob_fn : llvm::make_early_inc_range(*mod))
            if (glob_fn.use_empty())
                glob_fn.eraseFromParent();

        if (instrew_cfg.profile) {
            dur_lifting += time_instrument_start - time_lifting_start;
            dur_instrument += time_llvm_opt_start - time_instrument_start;
            dur_llvm_opt += time_llvm_codegen_start - time_llvm_opt_start;
            dur_llvm_codegen += std::chrono::steady_clock::now() - time_llvm_codegen_start;
        }

        return IWObject{obj_buffer.data(), obj_buffer.size()};
    }
};


int main(int argc, char** argv) {
    static const IWFunctions iwf = {
        /*.init=*/[](IWConnection* iwc, unsigned argc, const char* const* argv) {
            return new IWState(iwc, argc, argv);
        },
        /*.translate=*/[](IWState* state, uintptr_t addr) {
            return state->Translate(addr);
        },
        /*.finalize=*/[](IWState* state) {
            delete state;
        },
    };

    return iw_run_server(&iwf, argc, argv);
}
