
#include "optimizer.h"

#include "config.h"

#include <llvm/IR/IRPrintingPasses.h>
#include <llvm/IR/LegacyPassManager.h>
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


Optimizer::Optimizer(ServerConfig& server_config)
        : server_config(server_config) {
    if (server_config.opt_new_pass_manager) {
        legacy_pm = nullptr;
    } else {
        unsigned opt_level = server_config.opt_pass_pipeline;

        auto pm = std::make_unique<llvm::legacy::PassManager>();
        // Start of function pass.
        // Break up aggregate allocas, using SSAUpdater.
        // pm->add(llvm::createPrintFunctionPass(llvm::errs()));
        if (opt_level >= 2)
            pm->add(llvm::createDeadStoreEliminationPass());  // Delete dead stores
        // pm->add(llvm::createSROAPass());
        // pm->add(llvm::createPrintFunctionPass(llvm::errs()));
        pm->add(llvm::createAggressiveDCEPass());         // Delete dead instructions
        if (opt_level >= 2)
            pm->add(llvm::createEarlyCSEPass(true /* Enable mem-ssa. */)); // Catch trivial redundancies
        else
            pm->add(llvm::createEarlyCSEPass(false /* Enable mem-ssa. */)); // Catch trivial redundancies
        // pm->add(llvm::createPrintFunctionPass(llvm::errs()));

        pm->add(llvm::createCorrelatedValuePropagationPass()); // Propagate conditionals
        // pm->add(llvm::createPrintFunctionPass(llvm::errs()));
        // if (opt_level >= 2)
            pm->add(llvm::createCFGSimplificationPass());     // Merge & remove BBs
        // Combine silly seq's
        // pm->add(llvm::createPrintFunctionPass(llvm::errs()));
        pm->add(llvm::createAggressiveInstCombinerPass());
        // pm->add(llvm::createPrintFunctionPass(llvm::errs()));
        pm->add(llvm::createInstructionCombiningPass(true /* ExpensiveCombines */));
        // pm->add(llvm::createPrintFunctionPass(llvm::errs()));
        pm->add(llvm::createReassociatePass());           // Reassociate expressions

        if (opt_level >= 2)
            pm->add(llvm::createMergedLoadStoreMotionPass()); // Merge ld/st in diamonds
        if (opt_level >= 2)
            pm->add(llvm::createNewGVNPass()); // Remove redundancies
        pm->add(llvm::createMergedLoadStoreMotionPass()); // Merge ld/st in diamonds
        pm->add(llvm::createMemCpyOptPass());             // Remove memcpy / form memset
        pm->add(llvm::createSCCPPass());                  // Constant prop with SCCP

        // // Delete dead bit computations (instcombine runs after to fold away the dead
        // // computations, and then ADCE will run later to exploit any new DCE
        // // opportunities that creates).
        // pm->add(llvm::createBitTrackingDCEPass());        // Delete dead bit computations

        // Run instcombine after redundancy elimination to exploit opportunities
        // opened up by them.
        if (opt_level >= 2)
            pm->add(llvm::createInstructionCombiningPass(true /* ExpensiveCombines */));
        pm->add(llvm::createCorrelatedValuePropagationPass());
        if (opt_level >= 2)
            pm->add(llvm::createDeadStoreEliminationPass());  // Delete dead stores

        // pm->add(llvm::createAggressiveDCEPass());         // Delete dead instructions
        // pm->add(llvm::createCFGSimplificationPass()); // Merge & remove BBs
        // pm->add(llvm::createInstructionCombiningPass(true /* ExpensiveCombines */));
        legacy_pm = std::move(pm);
    }
}

void Optimizer::Optimize(llvm::Function* fn) {
    if (legacy_pm) {
        legacy_pm->run(*(fn->getParent()));
        return;
    }

    llvm::PassBuilder pb;
    llvm::FunctionPassManager fpm(false);

    llvm::LoopAnalysisManager lam(false);
    llvm::FunctionAnalysisManager fam(false);
    llvm::CGSCCAnalysisManager cgam(false);
    llvm::ModuleAnalysisManager mam(false);

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
    fpm.addPass(llvm::EarlyCSEPass(server_config.opt_pass_pipeline >= 2));
    // fpm.addPass(llvm::NewGVNPass());
    // fpm.addPass(llvm::DSEPass());
    fpm.addPass(llvm::InstCombinePass(true));
    fpm.addPass(llvm::CorrelatedValuePropagationPass());
    // if (server_config.opt_pass_pipeline >= 2)
    fpm.addPass(llvm::SimplifyCFGPass());
    // fpm.addPass(llvm::AggressiveInstCombinePass());
    // fpm.addPass(llvm::ReassociatePass());
    // fpm.addPass(llvm::MergedLoadStoreMotionPass());
    fpm.addPass(llvm::MemCpyOptPass());
    fpm.addPass(llvm::InstCombinePass(false));
    // fpm.addPass(llvm::SCCPPass());
    // fpm.addPass(llvm::AAEvaluator());
    fpm.run(*fn, fam);
}
