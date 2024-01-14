
#include "callconv.h"
#include "codegenerator.h"
#include "config.h"
#include "connection.h"
#include "instrew-server-config.h"
#include "optimizer.h"

#include <rellume/rellume.h>

#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassTimingInfo.h>
#include <llvm/Pass.h>
#include <llvm/Support/CommandLine.h>
#include <openssl/sha.h>

#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <deque>
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

struct IWState {
private:
    IWConnection* iwc;
    const IWServerConfig* iwsc = nullptr;
    IWClientConfig* iwcc = nullptr;
    const InstrewConfig& instrew_cfg;
    CallConv instrew_cc = CallConv::CDECL;

    LLConfig* rlcfg;
    llvm::LLVMContext ctx;
    llvm::Constant* pc_base;
    llvm::SmallVector<llvm::Function*, 8> helper_fns;
    std::unique_ptr<llvm::Module> mod;

    Optimizer optimizer;
    llvm::SmallVector<char, 4096> obj_buffer;
    CodeGenerator codegen;

    uint8_t config_hash[SHA_DIGEST_LENGTH];
    llvm::SmallVector<uint8_t, 256> range_buffer;

    std::chrono::steady_clock::duration dur_predecode{};
    std::chrono::steady_clock::duration dur_lifting{};
    std::chrono::steady_clock::duration dur_instrument{};
    std::chrono::steady_clock::duration dur_llvm_opt{};
    std::chrono::steady_clock::duration dur_llvm_codegen{};

public:

    IWState(IWConnection* iwc, const InstrewConfig& cfg)
            : instrew_cfg(cfg), optimizer(instrew_cfg),
              codegen(*iw_get_sc(iwc), instrew_cfg, obj_buffer) {
        this->iwc = iwc;
        iwsc = iw_get_sc(iwc);
        iwcc = iw_get_cc(iwc);

        llvm::TimePassesIsEnabled = instrew_cfg.timepasses;

        rlcfg = ll_config_new();
        ll_config_enable_verify_ir(rlcfg, instrew_cfg.verify);
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

            auto syscall_fn = CreateFunc(ctx, "syscall_rv64");
            helper_fns.push_back(syscall_fn);
            ll_config_set_syscall_impl(rlcfg, llvm::wrap(syscall_fn));
        } else if (iwsc->tsc_guest_arch == EM_AARCH64) {
            ll_config_set_architecture(rlcfg, "aarch64");

            auto syscall_fn = CreateFunc(ctx, "syscall_aarch64");
            helper_fns.push_back(syscall_fn);
            ll_config_set_syscall_impl(rlcfg, llvm::wrap(syscall_fn));
        } else {
            std::cerr << "error: unsupported architecture" << std::endl;
            abort();
        }

        // Backward compatibility -- only one fast CC per guest--host pair now.
        if (instrew_cfg.callconv >= 1 && instrew_cfg.callconv < 6)
            instrew_cc = GetFastCC(iwsc->tsc_host_arch, iwsc->tsc_guest_arch);
        else
            instrew_cc = CallConv::CDECL;
        iwcc->tc_callconv = GetCallConvClientNumber(instrew_cc);
        iwcc->tc_profile = cfg.profile;
        iwcc->tc_perf = cfg.perf;
        iwcc->tc_print_trace = cfg.trace;

        llvm::GlobalVariable* pc_base_var = CreatePcBase(ctx);
        pc_base = llvm::ConstantExpr::getPtrToInt(pc_base_var,
                                                  llvm::Type::getInt64Ty(ctx));

        mod = std::make_unique<llvm::Module>("mod", ctx);
#if LL_LLVM_MAJOR >= 13
        if (iwsc->tsc_stack_alignment != 0)
            mod->setOverrideStackAlignment(iwsc->tsc_stack_alignment);
#endif

#if LL_LLVM_MAJOR < 17
        mod->getGlobalList().push_back(pc_base_var);
#else
        mod->insertGlobalVariable(pc_base_var);
#endif
        for (const auto& helper_fn : helper_fns)
            mod->getFunctionList().push_back(helper_fn);

        llvm::Type* i8p_ty = llvm::Type::getInt8PtrTy(ctx);
        llvm::SmallVector<llvm::Constant*, 8> used;
        used.push_back(pc_base_var);

        for (llvm::Function& fn : mod->functions())
            used.push_back(llvm::ConstantExpr::getPointerCast(&fn, i8p_ty));

        llvm::ArrayType* used_ty = llvm::ArrayType::get(i8p_ty, used.size());
        llvm::GlobalVariable* llvm_used = new llvm::GlobalVariable(
                *mod, used_ty, /*const=*/false,
                llvm::GlobalValue::AppendingLinkage,
                llvm::ConstantArray::get(used_ty, used), "llvm.used");
        llvm_used->setSection("llvm.metadata");

        codegen.GenerateCode(mod.get());
        iw_sendobj(iwc, 0, obj_buffer.data(), obj_buffer.size(), nullptr);

        for (llvm::Function& fn : mod->functions())
            if (fn.hasExternalLinkage() && !fn.empty())
                fn.deleteBody();

        SHA_CTX config_sha;
        SHA1_Init(&config_sha);
        SHA1_Update(&config_sha, &instrew_cfg.targetopt, sizeof instrew_cfg.targetopt);
        SHA1_Update(&config_sha, &instrew_cfg.extrainstcombine, sizeof instrew_cfg.extrainstcombine);
        SHA1_Update(&config_sha, &instrew_cfg.safecallret, sizeof instrew_cfg.safecallret);
        SHA1_Update(&config_sha, &instrew_cfg.fullfacets, sizeof instrew_cfg.fullfacets);
        SHA1_Update(&config_sha, &instrew_cfg.callret, sizeof instrew_cfg.callret);
        SHA1_Update(&config_sha, &instrew_cfg.pic, sizeof instrew_cfg.pic);
        SHA1_Update(&config_sha, &iwsc->tsc_guest_arch, sizeof iwsc->tsc_guest_arch);
        SHA1_Update(&config_sha, &iwsc->tsc_host_arch, sizeof iwsc->tsc_host_arch);
        SHA1_Update(&config_sha, &iwsc->tsc_host_cpu_features, sizeof iwsc->tsc_host_cpu_features);
        SHA1_Update(&config_sha, &iwsc->tsc_stack_alignment, sizeof iwsc->tsc_stack_alignment);
        SHA1_Update(&config_sha, &iwcc->tc_callconv, sizeof iwcc->tc_callconv);
        SHA1_Final(config_hash, &config_sha);
    }
    ~IWState() {
        if (instrew_cfg.profile) {
            std::cerr << "Server profile: " << std::dec
                      << std::chrono::duration_cast<std::chrono::milliseconds>(dur_predecode).count()
                      << "ms predecode; "
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
        ll_config_free(rlcfg);
    }

    void Translate(uintptr_t addr) {
        auto time_predecode_start = std::chrono::steady_clock::now();

        // Optionally generate position-independent code, where the offset
        // can be adjusted using relocations.
        if (instrew_cfg.pic)
            ll_config_set_pc_base(rlcfg, addr, llvm::wrap(pc_base));

        LLFunc* rlfn = ll_func_new(llvm::wrap(mod.get()), rlcfg);
        RellumeMemAccessCb accesscb = [](size_t addr, uint8_t* buf, size_t bufsz, void* user_arg) {
            auto iwc = reinterpret_cast<IWConnection*>(user_arg);
            return iw_readmem(iwc, addr, addr + bufsz, buf);
        };
        int fail = ll_func_decode_cfg(rlfn, addr, accesscb, reinterpret_cast<void*>(iwc));
        if (fail) {
            std::cerr << "error: decode failed 0x" << std::hex << addr << std::endl;
            ll_func_dispose(rlfn);
            iw_sendobj(iwc, addr, nullptr, 0, nullptr);
            return;
        }

        SHA_CTX sha;
        SHA1_Init(&sha);
        SHA1_Update(&sha, config_hash, sizeof config_hash);
        // Non-PIC: store address, predecode only stores offsets to start addr.
        uint64_t hash_addr = instrew_cfg.pic ? 0 : addr;
        SHA1_Update(&sha, &hash_addr, sizeof hash_addr);
        const struct RellumeCodeRange* ranges = ll_func_ranges(rlfn);
        for (; ranges->start || ranges->end; ranges++) {
            uint64_t rel_start = ranges->start - hash_addr;
            uint64_t size = ranges->end - ranges->start;
            SHA1_Update(&sha, &rel_start, sizeof rel_start);
            SHA1_Update(&sha, &size, sizeof size);
            range_buffer.resize_for_overwrite(size);
            iw_readmem(iwc, ranges->start, ranges->end, range_buffer.data());
            SHA1_Update(&sha, range_buffer.data(), size);
        }
        uint8_t hash[SHA_DIGEST_LENGTH];
        SHA1_Final(hash, &sha);

        if (iw_cache_probe(iwc, addr, hash)) {
            ll_func_dispose(rlfn);
            if (instrew_cfg.profile)
                dur_predecode += std::chrono::steady_clock::now() - time_predecode_start;
            return;
        }

        auto time_lifting_start = std::chrono::steady_clock::now();
        LLVMValueRef fn_wrapped = !fail ? ll_func_lift(rlfn) : nullptr;
        if (!fn_wrapped) {
            std::cerr << "error: lift failed 0x" << std::hex << addr << "\n";
            ll_func_dispose(rlfn);
            iw_sendobj(iwc, addr, nullptr, 0, nullptr);
            return;
        }

        llvm::Function* fn = llvm::unwrap<llvm::Function>(fn_wrapped);
        fn->setName("S0");
        ll_func_dispose(rlfn);

        if (instrew_cfg.dumpir & 1)
            mod->print(llvm::errs(), nullptr);

        auto time_instrument_start = std::chrono::steady_clock::now();
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

        iw_sendobj(iwc, addr, obj_buffer.data(), obj_buffer.size(), hash);

        // Remove unused functions and dead prototypes. Having many prototypes
        // causes some compile-time overhead.
        for (auto& glob_fn : llvm::make_early_inc_range(*mod))
            if (glob_fn.use_empty())
                glob_fn.eraseFromParent();

        if (instrew_cfg.profile) {
            dur_predecode += time_lifting_start - time_predecode_start;
            dur_lifting += time_instrument_start - time_lifting_start;
            dur_instrument += time_llvm_opt_start - time_instrument_start;
            dur_llvm_opt += time_llvm_codegen_start - time_llvm_opt_start;
            dur_llvm_codegen += std::chrono::steady_clock::now() - time_llvm_codegen_start;
        }
    }
};


int main(int argc, char** argv) {
    static const IWFunctions iwf = {
        /*.init=*/[](IWConnection* iwc, const InstrewConfig& cfg) {
            return new IWState(iwc, cfg);
        },
        /*.translate=*/[](IWState* state, uintptr_t addr) {
            state->Translate(addr);
        },
        /*.finalize=*/[](IWState* state) {
            delete state;
        },
    };

    return iw_run_server(&iwf, argc, argv);
}
