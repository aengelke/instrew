
#include "codegenerator.h"

#include "config.h"

#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Target/TargetMachine.h>

#include <cstdlib>
#include <iostream>


class CodeGenerator::impl {
private:
    llvm::SmallVectorImpl<char>& obj_buffer;
    llvm::raw_svector_ostream obj_stream;
    llvm::MCContext* mc_ctx;
    llvm::TargetMachine* target;
    llvm::legacy::PassManager mc_pass_manager;

public:
    impl(ServerConfig& server_config, llvm::SmallVectorImpl<char> &o)
            : obj_buffer(o), obj_stream(o), mc_ctx(nullptr), mc_pass_manager() {
        llvm::InitializeNativeTarget();
        llvm::InitializeNativeTargetAsmPrinter();
        llvm::InitializeNativeTargetAsmParser();

        llvm::TargetOptions target_options;
        target_options.EnableFastISel = 1; // Use FastISel for CodeGenOpt::None

        std::string triple = server_config.triple;
        if (triple == "")
            triple = llvm::sys::getProcessTriple();

        std::string error;
        const llvm::Target* the_target = llvm::TargetRegistry::lookupTarget(triple, error);
        if (!the_target) {
            std::cerr << "could not get target: " << error << std::endl;
            abort();
        }

        target = the_target->createTargetMachine(
            /*TT=*/triple, /*CPU=*/server_config.cpu,
            /*Features=*/server_config.cpu_features, /*Options=*/target_options,
            /*RelocModel=*/llvm::Reloc::DynamicNoPIC,
            /*CodeModel=*/llvm::CodeModel::Small,
            /*OptLevel=*/static_cast<llvm::CodeGenOpt::Level>(server_config.opt_code_gen),
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

CodeGenerator::CodeGenerator(ServerConfig& sc, llvm::SmallVectorImpl<char>& o)
        : pimpl{std::make_unique<impl>(sc, o)} {}
CodeGenerator::~CodeGenerator() {}
void CodeGenerator::GenerateCode(llvm::Module* m) { pimpl->GenerateCode(m); }
