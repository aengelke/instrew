
#include "codegenerator.h"
#include "config.h"
#include "connection.h"
#include "instrew-server-config.h"
#include "optimizer.h"

#include <fadec.h>
#include <instrew-api.h>
#include <rellume/rellume.h>

#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassTimingInfo.h>

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

struct StructOff {
    struct Entry {
        unsigned off;
        unsigned size;
        llvm::Value* PtrTo(llvm::IRBuilder<>& irb, llvm::Value* base) const {
            llvm::Type* ty = irb.getIntNTy(8*size)->getPointerTo(SPTR_ADDR_SPACE);
            return irb.CreatePointerCast(irb.CreateConstGEP1_64(base, off), ty);
        }
    };

#define RELLUME_PUBLIC_REG(name,nameu,sz,off) \
            inline static constexpr Entry nameu = Entry{ off, sz };
#include <rellume/cpustruct-x86_64.inc>
#undef RELLUME_PUBLIC_REG
};

static llvm::Function* CreateFunc(llvm::LLVMContext& ctx,
                                  const std::string name, bool hhvm = false,
                                  bool external = true) {
    llvm::Type* sptr = llvm::Type::getInt8PtrTy(ctx, SPTR_ADDR_SPACE);

    llvm::FunctionType* fn_ty;
    unsigned sptr_idx;
    if (!hhvm) {
        llvm::Type* void_ty = llvm::Type::getVoidTy(ctx);
        fn_ty = llvm::FunctionType::get(void_ty, {sptr}, false);
        sptr_idx = 0;
    } else {
        llvm::Type* i64 = llvm::Type::getInt64Ty(ctx);
        auto ret_ty = llvm::StructType::get(i64, i64, i64, i64, i64, i64, i64,
                                            i64, i64, i64, i64, i64, i64, i64);
        fn_ty = llvm::FunctionType::get(ret_ty, {i64, sptr, i64, i64, i64, i64,
                                                 i64, i64, i64, i64, i64, i64,
                                                 i64, i64}, false);
        sptr_idx = 1;
    }

    auto linkage = external ? llvm::GlobalValue::ExternalLinkage
                            : llvm::GlobalValue::PrivateLinkage;
    auto fn = llvm::Function::Create(fn_ty, linkage, name);
    fn->setCallingConv(hhvm ? llvm::CallingConv::HHVM : llvm::CallingConv::C);
    fn->addParamAttr(sptr_idx, llvm::Attribute::NoAlias);
    fn->addParamAttr(sptr_idx, llvm::Attribute::NoCapture);
    fn->addParamAttr(sptr_idx, llvm::Attribute::getWithAlignment(ctx, 16));

    return fn;
}

template<typename F>
static llvm::Function* CreateFuncImpl(llvm::LLVMContext& ctx,
                                      const std::string name, const F& f) {
    llvm::Function* fn = CreateFunc(ctx, name, /*hhvm=*/false,
                                    /*external=*/false);
    fn->addFnAttr(llvm::Attribute::AlwaysInline);

    llvm::BasicBlock* bb = llvm::BasicBlock::Create(ctx, "", fn);
    llvm::IRBuilder<> irb(bb);
    f(irb, fn->arg_begin());
    return fn;
}

static llvm::Function* CreateNoopFn(llvm::LLVMContext& ctx) {
    return CreateFuncImpl(ctx, "noop_stub", [](llvm::IRBuilder<>& irb, llvm::Value* arg) {
        irb.CreateRetVoid();
    });
}

static llvm::Function* CreateRdtscFn(llvm::LLVMContext& ctx) {
    return CreateFuncImpl(ctx, "rdtsc", [](llvm::IRBuilder<>& irb, llvm::Value* arg) {
        irb.CreateStore(irb.getInt64(0), StructOff::RAX.PtrTo(irb, arg));
        irb.CreateStore(irb.getInt64(0), StructOff::RDX.PtrTo(irb, arg));
        irb.CreateRetVoid();
    });
}

static llvm::Function* CreateMarkerFn(llvm::LLVMContext& ctx) {
    auto marker_fn_ty = llvm::FunctionType::get(llvm::Type::getVoidTy(ctx),
            {llvm::Type::getInt64Ty(ctx), llvm::Type::getMetadataTy(ctx)},
            false);
    return llvm::Function::Create(marker_fn_ty,
                                  llvm::GlobalValue::PrivateLinkage,
                                  "instrew_instr_marker");
}

class RemoteMemory {
private:
    const static size_t PAGE_SIZE = 0x1000;
    using Page = std::array<uint8_t, PAGE_SIZE>;
    std::unordered_map<uint64_t, std::unique_ptr<Page>> page_cache;
    Conn& conn;

public:
    RemoteMemory(Conn& c) : conn(c) {}

private:
    Page* GetPage(size_t page_addr) {
        const auto& page_it = page_cache.find(page_addr);
        if (page_it != page_cache.end())
            return page_it->second.get();

        struct { uint64_t addr; size_t buf_sz; } send_buf{page_addr, PAGE_SIZE};
        conn.SendMsg(Msg::S_MEMREQ, send_buf);

        Msg::Id msgid = conn.RecvMsg();
        std::size_t msgsz = conn.Remaining();

        // Sanity checks.
        if (msgid != Msg::C_MEMBUF)
            return nullptr;
        if (msgsz != PAGE_SIZE + 1)
            return nullptr;

        auto page = std::make_unique<Page>();
        conn.Read(page->data(), page->size());

        uint8_t failed = conn.Read<uint8_t>();
        if (failed)
            return nullptr;

        page_cache[page_addr] = std::move(page);

        return page_cache[page_addr].get();
    };

public:
    size_t Get(size_t start, size_t end, uint8_t* buf) {
        size_t start_page = start & ~(PAGE_SIZE - 1);
        size_t end_page = end & ~(PAGE_SIZE - 1);
        size_t bytes_written = 0;
        for (size_t cur = start_page; cur <= end_page; cur += PAGE_SIZE) {
            Page* page = GetPage(cur);
            if (!page)
                break;
            size_t start_off = cur < start ? (start & (PAGE_SIZE - 1)) : 0;
            size_t end_off = cur + PAGE_SIZE > end ? (end & (PAGE_SIZE - 1)) : PAGE_SIZE;
            std::copy(page->data() + start_off, page->data() + end_off, buf + bytes_written);
            bytes_written += end_off - start_off;
        }
        return bytes_written;
    }
};

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

    int Init(const ServerConfig& server_config, llvm::Module* mod) {
        if (server_config.tool == "") {
            std::cerr << "error: no tool specified" << std::endl;
            return -EINVAL;
        }

        std::string tool_lib = server_config.tool;
        if (tool_lib.find('/') == std::string::npos) {
            std::stringstream ss;
            ss << INSTREW_TOOL_PATH << "/tool-" << server_config.tool << ".so";
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

        tool_handle = tool_func(server_config.tool_config.c_str(),
                                llvm::wrap(mod), &desc);
        if (desc.magic != 0xAEDB1000) {
            std::cerr << "error: incompatible tool" << std::endl;
            return -EINVAL;
        }

        return 0;
    }

    llvm::Function* Instrument(llvm::Function* fn) {
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

int main(int argc, char** argv) {
    if (argc > 1) {
        std::cerr << "usage: " << argv[0] << std::endl;
        std::cerr << "all configuration is done by the client." << std::endl;
        return 1;
    }

    // Set stdio to unbuffered
    std::setbuf(stdin, nullptr);
    std::setbuf(stdout, nullptr);

    // Measured times
    std::chrono::steady_clock::duration dur_lifting{};
    std::chrono::steady_clock::duration dur_instrument{};
    std::chrono::steady_clock::duration dur_llvm_opt{};
    std::chrono::steady_clock::duration dur_llvm_codegen{};

    Conn conn; // uses stdio

    ServerConfig server_config;
    if (conn.RecvMsg() != Msg::C_INIT) {
        std::cerr << "error: expected C_INIT message" << std::endl;
        return 1;
    }
    server_config.ReadFromConn(conn);

    RemoteMemory remote_memory(conn);

    llvm::cl::ParseEnvironmentOptions(argv[0], "INSTREW_SERVER_LLVM_OPTS");
    llvm::TimePassesIsEnabled = server_config.debug_time_passes;

    // Initialize optimizer according to configuration
    Optimizer optimizer(server_config);

    // Create code generator to write code into our buffer
    llvm::SmallVector<char, 4096> obj_buffer;
    CodeGenerator codegen(server_config, obj_buffer);

    // Create module, functions will be deleted after code generation.
    llvm::LLVMContext ctx;

    llvm::SmallVector<llvm::Function*, 8> helper_fns;
    llvm::SmallVector<llvm::Function*, 2> lift_fns;

    // This isn't added to lift_fns, here! Only, when the tool requires it.
    auto marker_fn = CreateMarkerFn(ctx);

    // Create rellume config
    LLConfig* rlcfg = ll_config_new();
    ll_config_enable_verify_ir(rlcfg, false);
    ll_config_set_call_ret_clobber_flags(rlcfg, server_config.opt_unsafe_callret);
    ll_config_enable_full_facets(rlcfg, server_config.opt_full_facets);
    ll_config_set_position_independent_code(rlcfg, false);
    ll_config_set_sptr_addrspace(rlcfg, SPTR_ADDR_SPACE);
    ll_config_enable_overflow_intrinsics(rlcfg, false);
    if (server_config.opt_callret_lifting) {
        const char* tail_fn_name =
            server_config.hhvm ? "instrew_tail_hhvm" : "instrew_tail_cdecl";
        auto tail_fn = CreateFunc(ctx, tail_fn_name, server_config.hhvm);
        helper_fns.push_back(tail_fn);
        ll_config_set_tail_func(rlcfg, llvm::wrap(tail_fn));

        const char* call_fn_name =
            server_config.hhvm ? "instrew_call_hhvm" : "instrew_call_cdecl";
        auto call_fn = CreateFunc(ctx, call_fn_name, server_config.hhvm);
        helper_fns.push_back(call_fn);
        ll_config_set_call_func(rlcfg, llvm::wrap(call_fn));
    }
    if (server_config.guest_arch == EM_X86_64) {
        ll_config_set_architecture(rlcfg, "x86-64");
        ll_config_set_use_native_segment_base(rlcfg, server_config.native_segments);
        ll_config_set_hhvm(rlcfg, server_config.hhvm);

        auto syscall_fn = CreateFunc(ctx, "syscall");
        helper_fns.push_back(syscall_fn);
        ll_config_set_syscall_impl(rlcfg, llvm::wrap(syscall_fn));

        auto noop_fn = CreateNoopFn(ctx);
        lift_fns.push_back(noop_fn);
        auto rdtsc_fn = CreateRdtscFn(ctx);
        lift_fns.push_back(rdtsc_fn);
        auto cpuid_fn = CreateFunc(ctx, "cpuid");
        helper_fns.push_back(cpuid_fn);
        ll_config_set_instr_impl(rlcfg, FDI_CPUID, llvm::wrap(cpuid_fn));
        ll_config_set_instr_impl(rlcfg, FDI_RDTSC, llvm::wrap(rdtsc_fn));
        ll_config_set_instr_impl(rlcfg, FDI_FLDCW, llvm::wrap(noop_fn));
        ll_config_set_instr_impl(rlcfg, FDI_LDMXCSR, llvm::wrap(noop_fn));
    } else if (server_config.guest_arch == EM_RISCV) {
        ll_config_set_architecture(rlcfg, "rv64");

        auto syscall_fn = CreateFunc(ctx, "syscall_rv64");
        helper_fns.push_back(syscall_fn);
        ll_config_set_syscall_impl(rlcfg, llvm::wrap(syscall_fn));
    } else {
        std::cerr << "error: unsupported architecture" << std::endl;
        return 1;
    }

    InstrumenterTool tool;
    {
        llvm::Module init_mod("mod", ctx);

        for (const auto& helper_fn : helper_fns)
            init_mod.getFunctionList().push_back(helper_fn);
        init_mod.getFunctionList().push_back(marker_fn);

        llvm::Type* i8p_ty = llvm::Type::getInt8PtrTy(ctx);
        llvm::SmallVector<llvm::Constant*, 8> used;
        for (const auto& helper_fn : helper_fns)
            used.push_back(llvm::ConstantExpr::getPointerCast(helper_fn, i8p_ty));
        llvm::ArrayType* used_ty = llvm::ArrayType::get(i8p_ty, used.size());
        llvm::GlobalVariable* llvm_used = new llvm::GlobalVariable(
                init_mod, used_ty, /*const=*/false,
                llvm::GlobalValue::AppendingLinkage,
                llvm::ConstantArray::get(used_ty, used), "llvm.used");
        llvm_used->setSection("llvm.metadata");

        if (tool.Init(server_config, &init_mod) != 0)
            return 1;
        if (tool.MarkInstrs()) {
            lift_fns.push_back(marker_fn);
            marker_fn->removeFromParent();
            ll_config_set_instr_marker(rlcfg, llvm::wrap(marker_fn));
        } else {
            // Remove useless marker function if tool doesn't require it.
            marker_fn->eraseFromParent();
        }

        // Rename all tool-defined functions appropriately.
        uint64_t zval_cnt = 1ull << 63;
        for (llvm::Function& fn : init_mod.functions()) {
            if (fn.empty())
                continue;
            std::stringstream namebuf;
            namebuf << "Z" << std::oct << zval_cnt++ << "_";
            fn.setName(llvm::Twine(namebuf.str() + fn.getName()));
        }

        codegen.GenerateCode(&init_mod);
        conn.SendMsg(Msg::S_OBJECT, obj_buffer.data(), obj_buffer.size());

        for (llvm::Function& fn : init_mod.functions()) {
            if (!fn.hasExternalLinkage() || fn.empty())
                continue;
            fn.deleteBody();
            helper_fns.push_back(&fn);
        }

        for (const auto& helper_fn : helper_fns)
            helper_fn->removeFromParent();
    }

    llvm::Module mod("mod", ctx);
    {
        for (const auto& helper_fn : helper_fns)
            mod.getFunctionList().push_back(helper_fn);

        llvm::Type* i8p_ty = llvm::Type::getInt8PtrTy(ctx);
        llvm::SmallVector<llvm::Constant*, 8> used;
        for (const auto& helper_fn : helper_fns)
            used.push_back(llvm::ConstantExpr::getPointerCast(helper_fn, i8p_ty));
        llvm::ArrayType* used_ty = llvm::ArrayType::get(i8p_ty, used.size());
        llvm::GlobalVariable* llvm_used = new llvm::GlobalVariable(
                mod, used_ty, /*const=*/false,
                llvm::GlobalValue::AppendingLinkage,
                llvm::ConstantArray::get(used_ty, used), "llvm.used");
        llvm_used->setSection("llvm.metadata");
    }

    while (true) {
        Msg::Id msgid = conn.RecvMsg();
        if (msgid == Msg::C_EXIT) {
            if (server_config.debug_profile_server) {
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
            // if (server_config.debug_time_passes)
            //     llvm::reportAndResetTimings(&llvm::errs());
            return 0;
        } else if (msgid == Msg::C_TRANSLATE) {
            auto addr = conn.Read<uint64_t>();

            ////////////////////////////////////////////////////////////////////
            // STEP 1: lift function to LLVM-IR using Rellume.

            std::chrono::steady_clock::time_point time_lifting_start;
            if (server_config.debug_profile_server)
                time_lifting_start = std::chrono::steady_clock::now();

            for (const auto& lift_fn : lift_fns)
                mod.getFunctionList().push_back(lift_fn);

            LLFunc* rlfn = ll_func_new(llvm::wrap(&mod), rlcfg);
            bool decode_fail = ll_func_decode_cfg(rlfn, addr,
                [](size_t addr, uint8_t* buf, size_t buf_sz, void* user_arg) {
                    auto* rm = static_cast<RemoteMemory*>(user_arg);
                    return rm->Get(addr, addr + buf_sz, buf);
                },
                &remote_memory);
            if (decode_fail) {
                std::cerr << "error: could not decode at 0x" << std::hex << addr
                          << std::endl;
                return 1;
            }
            llvm::Function* fn = llvm::unwrap<llvm::Function>(ll_func_lift(rlfn));
            ll_func_dispose(rlfn);

            std::stringstream namebuf;
            namebuf << "Z" << std::oct << addr << "_" << std::hex << addr;

            fn->setName(namebuf.str());

            if (server_config.debug_profile_server)
                dur_lifting += std::chrono::steady_clock::now() - time_lifting_start;

            // Print IR before optimizations
            if (server_config.debug_dump_ir)
                fn->print(llvm::errs());

            ////////////////////////////////////////////////////////////////////
            // STEP 2: perform instrumentation

            std::chrono::steady_clock::time_point time_instrument_start;
            if (server_config.debug_profile_server)
                time_instrument_start = std::chrono::steady_clock::now();

            fn = tool.Instrument(fn);

            // Remove functions required for lifting before optimization. This
            // includes the instr marker, which will either get optimized away,
            // or be passed to code generation, causing compilation failure.
            for (auto* lift_fn : lift_fns)
                lift_fn->removeFromParent();

            if (server_config.debug_profile_server)
                dur_instrument += std::chrono::steady_clock::now() - time_instrument_start;

            // Print IR before target-specific transformations
            if (server_config.debug_dump_ir)
                fn->print(llvm::errs());

            ////////////////////////////////////////////////////////////////////
            // STEP 3: optimize lifted LLVM-IR, optionally using the new pass
            //   manager of LLVM

            std::chrono::steady_clock::time_point time_llvm_opt_start;
            if (server_config.debug_profile_server)
                time_llvm_opt_start = std::chrono::steady_clock::now();

            // Remove unused helper functions to prevent erasure during opt.
            for (const auto& helper_fn : helper_fns)
                if (helper_fn->user_empty())
                    helper_fn->removeFromParent();

            if (tool.Optimize())
                optimizer.Optimize(fn);

            if (server_config.debug_profile_server)
                dur_llvm_opt += std::chrono::steady_clock::now() - time_llvm_opt_start;

            // Print IR before target-specific transformations
            if (server_config.debug_dump_ir)
                fn->print(llvm::errs());

            ////////////////////////////////////////////////////////////////////
            // STEP 4: generate machine code

            std::chrono::steady_clock::time_point time_llvm_codegen_start;
            if (server_config.debug_profile_server)
                time_llvm_codegen_start = std::chrono::steady_clock::now();

            codegen.GenerateCode(&mod);

            if (server_config.debug_profile_server)
                dur_llvm_codegen += std::chrono::steady_clock::now() - time_llvm_codegen_start;

            // Print IR after all optimizations are done
            if (server_config.debug_dump_ir)
                fn->print(llvm::errs());

            ////////////////////////////////////////////////////////////////////
            // STEP 5: send object file to the client, and clean-up.

            conn.SendMsg(Msg::S_OBJECT, obj_buffer.data(), obj_buffer.size());

            if (server_config.debug_dump_objects) {
                std::stringstream debug_out1_name;
                debug_out1_name << std::hex << "func_" << addr << ".elf";

                std::ofstream debug_out1;
                debug_out1.open(debug_out1_name.str(), std::ios::binary);
                debug_out1.write(obj_buffer.data(), obj_buffer.size());
                debug_out1.close();
            }

            fn->eraseFromParent();

        } else {
            std::cerr << "unexpected msg " << msgid << std::endl;
            return 1;
        }
    }
}
