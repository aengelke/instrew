
#include "codegenerator.h"

#include "config.h"

#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/Host.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Target/TargetMachine.h>

#include <cstdlib>
#include <elf.h>
#include <iostream>


class CodeGenerator::impl {
private:
    llvm::SmallVectorImpl<char>& obj_buffer;
    llvm::raw_svector_ostream obj_stream;
    llvm::MCContext* mc_ctx;
    llvm::TargetMachine* target;
    llvm::legacy::PassManager mc_pass_manager;

public:
    impl(const ServerConfig& server_config, const InstrewConfig& cfg,
         llvm::SmallVectorImpl<char> &o)
            : obj_buffer(o), obj_stream(o), mc_ctx(nullptr), mc_pass_manager() {
        llvm::InitializeNativeTarget();
        llvm::InitializeNativeTargetAsmPrinter();
        llvm::InitializeNativeTargetAsmParser();

        llvm::TargetOptions target_options;
        target_options.EnableFastISel = 1; // Use FastISel for CodeGenOpt::None
        if (server_config.tsc_stack_alignment != 0)
            target_options.StackAlignmentOverride = server_config.tsc_stack_alignment;

        std::string triple;
        switch (server_config.tsc_host_arch) {
        case EM_X86_64:
            triple = "x86_64-unknown-linux-gnu";
            break;
        case EM_AARCH64:
            triple = "aarch64-unknown-linux-gnu";
            break;
        default:
            std::cerr << "unknown host architecture" << std::endl;
            abort();
        }

        std::string error;
        const llvm::Target* the_target = llvm::TargetRegistry::lookupTarget(triple, error);
        if (!the_target) {
            std::cerr << "could not get target: " << error << std::endl;
            abort();
        }

        target = the_target->createTargetMachine(
            /*TT=*/triple, /*CPU=*/"",
            /*Features=*/"", /*Options=*/target_options,
            /*RelocModel=*/llvm::Reloc::Static,
            /*CodeModel=*/llvm::CodeModel::Medium,
            /*OptLevel=*/static_cast<llvm::CodeGenOpt::Level>(cfg.targetopt),
            /*JIT=*/true
        );
        if (!target) {
            std::cerr << "could not allocate target machine" << std::endl;
            abort();
        }

        if (target->addPassesToEmitMC(mc_pass_manager, mc_ctx, obj_stream, false)) {
            std::cerr << "target doesn't support code gen" << std::endl;
            abort();
        }
    }

    void GenerateCode(llvm::Module* mod) {
        obj_buffer.clear();
        mc_pass_manager.run(*mod);
    }
};

CodeGenerator::CodeGenerator(const ServerConfig& sc, const InstrewConfig& ic,
                             llvm::SmallVectorImpl<char>& o)
        : pimpl{std::make_unique<impl>(sc, ic, o)} {}
CodeGenerator::~CodeGenerator() {}
void CodeGenerator::GenerateCode(llvm::Module* m) { pimpl->GenerateCode(m); }
