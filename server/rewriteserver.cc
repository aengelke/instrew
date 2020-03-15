
#include "codegenerator.h"
#include "config.h"
#include "connection.h"
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
#include <rellume/cpustruct.inc>
#undef RELLUME_PUBLIC_REG
};

static llvm::Function* CreateFunc(llvm::Module* mod, const std::string name,
                                  bool external = true) {
    llvm::LLVMContext& ctx = mod->getContext();
    llvm::Type* void_type = llvm::Type::getVoidTy(ctx);
    llvm::Type* i8p_type = llvm::Type::getInt8PtrTy(ctx, SPTR_ADDR_SPACE);
    auto fn_ty = llvm::FunctionType::get(void_type, {i8p_type}, false);
    auto linkage = external ? llvm::GlobalValue::ExternalLinkage
                            : llvm::GlobalValue::PrivateLinkage;
    return llvm::Function::Create(fn_ty, linkage, name, mod);
}

template<typename F>
static llvm::Function* CreateFuncImpl(llvm::Module* mod, const std::string name,
                                      const F& f) {
    llvm::Function* fn = CreateFunc(mod, name, /*external=*/false);
    fn->addFnAttr(llvm::Attribute::AlwaysInline);

    llvm::BasicBlock* bb = llvm::BasicBlock::Create(mod->getContext(), "", fn);
    llvm::IRBuilder<> irb(bb);
    f(irb, fn->arg_begin());
    return fn;
}

static llvm::Function* CreateNoopFn(llvm::Module* mod) {
    return CreateFuncImpl(mod, "noop_stub", [](llvm::IRBuilder<>& irb, llvm::Value* arg) {
        irb.CreateRetVoid();
    });
}

static llvm::Function* CreateRdtscFn(llvm::Module* mod) {
    return CreateFuncImpl(mod, "rdtsc", [](llvm::IRBuilder<>& irb, llvm::Value* arg) {
        irb.CreateStore(irb.getInt64(0), StructOff::RAX.PtrTo(irb, arg));
        irb.CreateStore(irb.getInt64(0), StructOff::RDX.PtrTo(irb, arg));
        irb.CreateRetVoid();
    });
}

static llvm::Function* CreateMarkerFn(llvm::Module* mod) {
    llvm::LLVMContext& ctx = mod->getContext();
    auto marker_fn_ty = llvm::FunctionType::get(llvm::Type::getVoidTy(ctx),
            {llvm::Type::getInt64Ty(ctx), llvm::Type::getMetadataTy(ctx)},
            false);
    return llvm::Function::Create(marker_fn_ty,
                                  llvm::GlobalValue::PrivateLinkage,
                                  "instrew_instr_marker", mod);
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
        dl_handle = dlopen(server_config.tool.c_str(), RTLD_NOW);
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
    llvm::Module mod("mod", ctx);

    // Add declarations (and definitions) of helper functions to module. We do
    // this before initializing the tool to give tools a chance to cache
    // references or modify such functions globally.
    auto syscall_fn = CreateFunc(&mod, "syscall");
    auto noop_fn = CreateNoopFn(&mod);
    auto cpuid_fn = CreateFunc(&mod, "cpuid");
    auto rdtsc_fn = CreateRdtscFn(&mod);
    auto marker_fn = CreateMarkerFn(&mod);

    InstrumenterTool tool;
    if (tool.Init(server_config, &mod) != 0)
        return 1;

    // Create rellume config
    LLConfig* rlcfg = ll_config_new();
    ll_config_enable_verify_ir(rlcfg, false);
    ll_config_set_call_ret_clobber_flags(rlcfg, server_config.opt_unsafe_callret);
    ll_config_set_use_native_segment_base(rlcfg, server_config.native_segments);
    ll_config_set_position_independent_code(rlcfg, false);
    ll_config_set_hhvm(rlcfg, server_config.hhvm);
    ll_config_set_sptr_addrspace(rlcfg, SPTR_ADDR_SPACE);
    ll_config_enable_overflow_intrinsics(rlcfg, false);
    if (tool.MarkInstrs())
        ll_config_set_instr_marker(rlcfg, llvm::wrap(marker_fn));
    else // Remove useless marker function if tool doesn't require it.
        marker_fn->eraseFromParent();
    ll_config_set_syscall_impl(rlcfg, llvm::wrap(syscall_fn));
    ll_config_set_instr_impl(rlcfg, FDI_CPUID, llvm::wrap(cpuid_fn));
    ll_config_set_instr_impl(rlcfg, FDI_RDTSC, llvm::wrap(rdtsc_fn));
    ll_config_set_instr_impl(rlcfg, FDI_FLDCW, llvm::wrap(noop_fn));
    ll_config_set_instr_impl(rlcfg, FDI_LDMXCSR, llvm::wrap(noop_fn));

    // Store all helper functions in a vector, so that we can easily remove them
    // before optimizations/code generation and add them back afterwards.
    std::vector<llvm::Function*> helper_fns;
    helper_fns.reserve(mod.size());
    for (llvm::Function& fn : mod.functions())
        helper_fns.push_back(&fn);

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
            namebuf << std::hex << "func_" << addr;

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

            // Re-add helper functions removed previously
            for (const auto& helper_fn : helper_fns)
                if (!helper_fn->getParent())
                    mod.getFunctionList().push_back(helper_fn);
        } else {
            std::cerr << "unexpected msg " << msgid << std::endl;
            return 1;
        }
    }
}
