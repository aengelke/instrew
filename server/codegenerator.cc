
#include "codegenerator.h"

#include "connection.h"
#include "config.h"

#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/Host.h>
// LLVM < 13 has TargetRegistry.h in Support/
#if __has_include(<llvm/MC/TargetRegistry.h>)
#include <llvm/MC/TargetRegistry.h>
#else
#include <llvm/Support/TargetRegistry.h>
#endif
#include <llvm/Support/TargetSelect.h>
#include <llvm/Target/TargetMachine.h>

#include <cstdlib>
#include <elf.h>
#include <iostream>


namespace {

llvm::cl::opt<unsigned> targetopt("targetopt", llvm::cl::init(2),
                       llvm::cl::desc("Back-end optimization level (default: 2)"),
                       llvm::cl::value_desc("0/1/2/3"),
                       llvm::cl::cat(CodeGenCategory));

} // end anonymous namespace

class CodeGenerator::impl {
private:
    llvm::SmallVectorImpl<char>& obj_buffer;
    llvm::raw_svector_ostream obj_stream;
    llvm::MCContext* mc_ctx;
    std::unique_ptr<llvm::TargetMachine> target;
    llvm::legacy::PassManager mc_pass_manager;

public:
    impl(const IWServerConfig& server_config, bool pic,
         llvm::SmallVectorImpl<char> &o)
            : obj_buffer(o), obj_stream(o), mc_ctx(nullptr), mc_pass_manager() {
        llvm::InitializeNativeTarget();
        llvm::InitializeNativeTargetAsmPrinter();
        llvm::InitializeNativeTargetAsmParser();

        llvm::TargetOptions target_options;
        target_options.EnableFastISel = targetopt == 0; // Use FastISel for CodeGenOpt::None
#if LL_LLVM_MAJOR < 13
        // In LLVM13+, Module::setOverrideStackAlignment is used instead.
        if (server_config.tsc_stack_alignment != 0)
            target_options.StackAlignmentOverride = server_config.tsc_stack_alignment;
#endif

        std::string triple;
        llvm::CodeModel::Model cm;
        switch (server_config.tsc_host_arch) {
        case EM_X86_64:
            triple = "x86_64-unknown-linux-gnu";
            cm = pic ? llvm::CodeModel::Medium : llvm::CodeModel::Small;
            break;
        case EM_AARCH64:
            triple = "aarch64-unknown-linux-gnu";
            // The AArch64 target doesn't support the medium code model.
            cm = pic ? llvm::CodeModel::Large : llvm::CodeModel::Small;
            break;
        default:
            std::cerr << "unknown host architecture" << std::endl;
            abort();
        }

        llvm::Reloc::Model rm = llvm::Reloc::Static;
        // For non-PIC code, we use the small code model. Since we don't link
        // objects to 32-bit addresses, these must be addressed PC-relative.
        if (!pic)
            rm = llvm::Reloc::PIC_;

        std::string error;
        const llvm::Target* the_target = llvm::TargetRegistry::lookupTarget(triple, error);
        if (!the_target) {
            std::cerr << "could not get target: " << error << std::endl;
            abort();
        }

        target = std::unique_ptr<llvm::TargetMachine>(the_target->createTargetMachine(
            /*TT=*/triple, /*CPU=*/"",
            /*Features=*/"", /*Options=*/target_options,
            /*RelocModel=*/rm,
            /*CodeModel=*/cm,
            /*OptLevel=*/static_cast<llvm::CodeGenOpt::Level>(unsigned(targetopt)),
            /*JIT=*/true
        ));
        if (!target) {
            std::cerr << "could not allocate target machine" << std::endl;
            abort();
        }

        if (target->addPassesToEmitMC(mc_pass_manager, mc_ctx, obj_stream,
                                      /*DisableVerify=*/true)) {
            std::cerr << "target doesn't support code gen" << std::endl;
            abort();
        }
    }

    void GenerateCode(llvm::Module* mod) {
        mod->setDataLayout(target->createDataLayout());
        obj_buffer.clear();
        mc_pass_manager.run(*mod);
    }
};

CodeGenerator::CodeGenerator(const IWServerConfig& sc, bool pic,
                             llvm::SmallVectorImpl<char>& o)
        : pimpl{std::make_unique<impl>(sc, pic, o)} {}
CodeGenerator::~CodeGenerator() {}
void CodeGenerator::GenerateCode(llvm::Module* m) { pimpl->GenerateCode(m); }

void CodeGenerator::appendConfig(llvm::SmallVectorImpl<uint8_t>& buffer) const {
    struct {
        uint32_t version = 1;
        uint32_t targetopt = targetopt;
    } config;

    std::size_t start = buffer.size();
    buffer.resize_for_overwrite(buffer.size() + sizeof(config));
    std::memcpy(&buffer[start], &config, sizeof(config));
}
