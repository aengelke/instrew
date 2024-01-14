
#include "optimizer.h"

#include "config.h"

#include <llvm/Analysis/AliasAnalysis.h>
#include <llvm/IR/IRPrintingPasses.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Transforms/AggressiveInstCombine/AggressiveInstCombine.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Scalar/ADCE.h>
#include <llvm/Transforms/Scalar/CorrelatedValuePropagation.h>
#include <llvm/Transforms/Scalar/DCE.h>
// #include <llvm/Transforms/Scalar/DeadStoreElimination.h>
#include <llvm/Transforms/Scalar/EarlyCSE.h>
// #include <llvm/Transforms/Scalar/GVN.h>
#include <llvm/Transforms/Scalar/MemCpyOptimizer.h>
#include <llvm/Transforms/Scalar/MergedLoadStoreMotion.h>
// #include <llvm/Transforms/Scalar/NewGVN.h>
#include <llvm/Transforms/Scalar/Reassociate.h>
#include <llvm/Transforms/Scalar/SCCP.h>
#include <llvm/Transforms/Scalar/SimplifyCFG.h>


void Optimizer::Optimize(llvm::Function* fn) {
    llvm::PassBuilder pb;
    llvm::FunctionPassManager fpm{};

    llvm::LoopAnalysisManager lam{};
    llvm::FunctionAnalysisManager fam{};
    llvm::CGSCCAnalysisManager cgam{};
    llvm::ModuleAnalysisManager mam{};

    // Register the AA manager first so that our version is the one used.
    fam.registerPass([&] { return pb.buildDefaultAAPipeline(); });
    // Register analysis passes...
    pb.registerModuleAnalyses(mam);
    pb.registerCGSCCAnalyses(cgam);
    pb.registerFunctionAnalyses(fam);
    pb.registerLoopAnalyses(lam);
    pb.crossRegisterProxies(lam, fam, cgam, mam);

    // fpm = pb.buildFunctionSimplificationPipeline(llvm::PassBuilder::O3, llvm::PassBuilder::ThinLTOPhase::None, false);

    // fpm.addPass(llvm::ADCEPass());
    fpm.addPass(llvm::DCEPass());
    fpm.addPass(llvm::EarlyCSEPass(/*MemorySSA=*/false));
    // fpm.addPass(llvm::NewGVNPass());
    // fpm.addPass(llvm::DSEPass());

    // This is tricky. For LLVM <=9, the parameter indicates "expensive
    // combines" -- which is what we want to be false. For LLVM 11+, however,
    // the parameter suddenly means NumIterations, and if we pass "false",
    // InstCombine does zero iterations -- which is not what we want. So we go
    // with the default option, which brings useless "expensive combines" (they
    // were, thus, removed in later LLVM versions), but makes LLVM 11 work.
    fpm.addPass(llvm::InstCombinePass());
    fpm.addPass(llvm::CorrelatedValuePropagationPass());
    // if (instrew_cfg.extrainstcombine)
    fpm.addPass(llvm::SimplifyCFGPass());
    // fpm.addPass(llvm::AggressiveInstCombinePass());
    // fpm.addPass(llvm::ReassociatePass());
    // fpm.addPass(llvm::MergedLoadStoreMotionPass());
    fpm.addPass(llvm::MemCpyOptPass());
    // if (instrew_cfg.extrainstcombine)
        // fpm.addPass(llvm::InstCombinePass());
    // fpm.addPass(llvm::SCCPPass());
    // fpm.addPass(llvm::AAEvaluator());
    fpm.run(*fn, fam);
}

void Optimizer::appendConfig(llvm::SmallVectorImpl<uint8_t>& buffer) const {
    struct {
        uint32_t version = 1;
    } config;

    std::size_t start = buffer.size();
    buffer.resize_for_overwrite(buffer.size() + sizeof(config));
    std::memcpy(&buffer[start], &config, sizeof(config));
}
