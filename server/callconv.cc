
#include "callconv.h"

#include "config.h"

#include <llvm/Analysis/ValueTracking.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <chrono>
#include <unistd.h>
#include <bitset>
#include <iostream>


static uint64_t pointerOffset(llvm::Value* base, llvm::Value* ptr,
                             const llvm::DataLayout& DL) {
    ptr = ptr->stripPointerCasts();
    uint64_t offset = 0;
    if (auto GEP = llvm::dyn_cast<llvm::GEPOperator>(ptr)) {
        if (GEP->getNumOperands() > 2)
            assert(false && "unsupported GEP (idx)");
        auto op = llvm::dyn_cast<llvm::ConstantInt>(GEP->getOperand(1));
        assert(op);
        uint64_t tysz = DL.getTypeAllocSize(GEP->getSourceElementType());
        offset += tysz * op->getSExtValue();
        ptr = GEP->getOperand(0)->stripPointerCasts();
    }
    assert(ptr == base);
    return offset;
}

static constexpr unsigned SPTR_MAX_OFF = 13*8;

llvm::Function* ChangeCallConv(llvm::Function* fn, CallConv cc) {
    if (cc == CallConv::CDECL)
        return fn;

    llvm::Module* mod = fn->getParent();
    const llvm::DataLayout& DL = mod->getDataLayout();
    llvm::LLVMContext& ctx = mod->getContext();
    llvm::Type* sptr_ty = fn->arg_begin()[0].getType();
    unsigned sptr_as = sptr_ty->getPointerAddressSpace();
    llvm::Type* i64 = llvm::Type::getInt64Ty(ctx);

    const short* arg_map;
    const short* ret_map;
    llvm::StructType* ret_ty;
    llvm::FunctionType* fn_ty;
    llvm::Function* nfn;
    llvm::Value* sptr;
    auto linkage = fn->getLinkage();

    switch (cc) {
    case CallConv::HHVM: {
        static const short hhvm_args[] = {
            0, /*sptr*/ -1, 4*8, 5*8, 8*8, 7*8, 3*8, 2*8, 9*8, 10*8, 1*8, 11*8,
            12*8, 6*8,
        };
        static const short hhvm_ret[] = {
            0, 4*8, 8*8, 7*8, 3*8, 2*8, 9*8, 10*8, 1*8, 11*8, 12*8, 6*8,
            /*unused*/ -1, 5*8,
        };
        arg_map = hhvm_args;
        ret_map = hhvm_ret;
        ret_ty = llvm::StructType::get(i64, i64, i64, i64, i64, i64, i64,
                                       i64, i64, i64, i64, i64, i64, i64);
        fn_ty = llvm::FunctionType::get(ret_ty,
                {i64, sptr_ty, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64,
                 i64, i64}, false);

        nfn = llvm::Function::Create(fn_ty, linkage, fn->getName() + "_hhvm", mod);
        nfn->copyAttributesFrom(fn);
        llvm::AttributeList al = nfn->getAttributes();
        al = al.addParamAttributes(ctx, 1, al.getParamAttributes(0));
        nfn->setAttributes(al.removeParamAttributes(ctx, 0));
        nfn->setCallingConv(llvm::CallingConv::HHVM);
        nfn->addParamAttr(1, llvm::Attribute::NoAlias);
        nfn->addParamAttr(1, llvm::Attribute::NoCapture);
        nfn->addParamAttr(1, llvm::Attribute::getWithAlignment(ctx, 16));
        sptr = &nfn->arg_begin()[1];
        break;
    }
    case CallConv::CDECL:
    default:
        assert(false && "unsupported Instrew calling convention!");
    }

    // Move basic blocks from one function to another. Because all code is
    // unoptimized at this point, copying (either by CloneFunctionInto or
    // InlineFunction) is very expensive; and we also throw away the old
    // function anyway.
    {
        llvm::SmallVector<llvm::BasicBlock*, 32> bbs;
        for (llvm::BasicBlock& bb : *fn)
            bbs.push_back(&bb);
        for (llvm::BasicBlock* bb : bbs) {
            bb->removeFromParent();
            nfn->getBasicBlockList().push_back(bb);
        }
    }
    fn->arg_begin()[0].replaceAllUsesWith(sptr);
    fn->eraseFromParent();
    fn = nullptr;

    llvm::BasicBlock* entry_bb = &nfn->getEntryBlock();
    llvm::IRBuilder<> irb(entry_bb);

    // First fold known loads.
    llvm::SmallVector<llvm::Instruction*, 16> deadinsts;
    for (llvm::Instruction& instr : *entry_bb) {
        if (instr.mayWriteToMemory())
            break;
        llvm::LoadInst* load = llvm::dyn_cast<llvm::LoadInst>(&instr);
        if (!load)
            continue;
        if (load->getPointerAddressSpace() != sptr_as)
            continue;
        // TODO: use llvm::isPointerOffset
        auto off = pointerOffset(sptr, load->getPointerOperand(), DL);
        if (off >= SPTR_MAX_OFF)
            continue;
        for (unsigned ai = 0; ai < nfn->arg_size(); ai++) {
            if (arg_map[ai] != off)
                continue;
            llvm::Value* arg = nfn->arg_begin() + ai;
            if (load->getType() == arg->getType()) {
                load->replaceAllUsesWith(arg);
                deadinsts.push_back(load);
            }
            break;
        }
    }
    for (auto* load : deadinsts)
        load->eraseFromParent();
    deadinsts.clear();

    std::bitset<SPTR_MAX_OFF> mapped_bytes;
    for (unsigned ai = 0; ai < nfn->arg_size(); ai++) {
        llvm::Value* arg = nfn->arg_begin() + ai;
        uint64_t tysz = DL.getTypeAllocSize(arg->getType());
        for (uint64_t b = arg_map[ai]; b < arg_map[ai] + tysz; b++)
            mapped_bytes.set(b);
    }

    // Now find all bytes which are still read and written somewhere during
    // the function, and check whether sptr escapes the function.
    std::bitset<SPTR_MAX_OFF> read_bytes;
    std::bitset<SPTR_MAX_OFF> written_bytes;
    bool sptr_escapes = false;

    llvm::DenseMap<llvm::Value*, unsigned> visited;
    llvm::SmallVector<llvm::Value*, 16> queue;
    visited[sptr] = 0;
    queue.push_back(sptr);
    while (!queue.empty()) {
        llvm::SmallVector<llvm::Value*, 16> new_queue;
        for (llvm::Value* val : queue) {
            unsigned off = visited[val];
            for (const auto& user : val->users()) {
                auto inst = llvm::dyn_cast<llvm::Instruction>(user);
                if (!inst)
                    continue;
                if (inst->getOpcode() == llvm::Instruction::Store) {
                    auto store = llvm::cast<llvm::StoreInst>(inst);
                    if (store->getPointerAddressSpace() != sptr_as) {
                        sptr_escapes = true;
                        goto end_escape;
                    }
                    uint64_t tysz = DL.getTypeAllocSize(store->getValueOperand()->getType());
                    for (uint64_t b = off; b < off + tysz && b < SPTR_MAX_OFF; b++)
                        written_bytes.set(b);
                    break;
                } else if (inst->getOpcode() == llvm::Instruction::Load) {
                    uint64_t tysz = DL.getTypeAllocSize(inst->getType());
                    for (uint64_t b = off; b < off + tysz && b < SPTR_MAX_OFF; b++)
                        read_bytes.set(b);
                    break;
                } else if (inst->isCast()) {
                    llvm::Type* dstty = inst->getType();
                    if (!dstty->isPointerTy() || dstty->getPointerAddressSpace() != sptr_as) {
                        sptr_escapes = true;
                        goto end_escape;
                    }
                    visited[inst] = off;
                    new_queue.push_back(inst);
                } else if (inst->getOpcode() == llvm::Instruction::GetElementPtr) {
                    auto GEP = llvm::cast<llvm::GEPOperator>(inst);
                    if (GEP->getNumOperands() > 2)
                        assert(false && "unsupported GEP (idx)");
                    auto op = llvm::cast<llvm::ConstantInt>(GEP->getOperand(1));
                    uint64_t tysz = DL.getTypeAllocSize(GEP->getSourceElementType());
                    visited[inst] = off + tysz * op->getSExtValue();
                    new_queue.push_back(inst);
                } else if (inst->getOpcode() == llvm::Instruction::Call) {
                    sptr_escapes = true;
                    goto end_escape;
                } else {
                    inst->print(llvm::errs());
                    assert(false);
                }
            }
        }
        queue = std::move(new_queue);
    }
end_escape:

    // Useful for debugging escape analysis.
    // std::cerr << mapped_bytes << "\n" << read_bytes << "\n" << written_bytes
    //           << "\n" << sptr_escapes << std::endl;

    read_bytes &= mapped_bytes;
    written_bytes &= mapped_bytes;
    if (read_bytes.any() || sptr_escapes) {
        // We must add all loads in beginning
        irb.SetInsertPoint(entry_bb, entry_bb->getFirstInsertionPt());
        for (unsigned ai = 0; ai < nfn->arg_size(); ai++) {
            if (arg_map[ai] < 0) // we can ignore the sptr, it never changes
                continue;
            llvm::Value* arg = nfn->arg_begin() + ai;
            llvm::Value* gep = irb.CreateConstGEP1_64(sptr, arg_map[ai]);
            llvm::Type* ptr_ty = arg->getType()->getPointerTo(sptr_as);
            irb.CreateStore(arg, irb.CreatePointerCast(gep, ptr_ty));
        }
    }

    // Then, fold known stores. There should be at most one returning BB.
    for (llvm::BasicBlock& bb : *nfn) {
        auto* ret = llvm::dyn_cast<llvm::ReturnInst>(bb.getTerminator());
        if (!ret)
            continue;

        ret->eraseFromParent();
        irb.SetInsertPoint(&bb);

        llvm::SmallVector<llvm::Value*, 16> ret_vals;
        ret_vals.resize(ret_ty->getNumElements());
        // First try to get return values from the last stores in that block.
        for (auto it = bb.rbegin(); it != bb.rend(); ++it) {
            if (llvm::dyn_cast<llvm::LoadInst>(&*it))
                break;
            if (llvm::dyn_cast<llvm::ReturnInst>(&*it))
                continue;
            auto store = llvm::dyn_cast<llvm::StoreInst>(&*it);
            if (!store || store->getPointerAddressSpace() != sptr_as)
                break;
            llvm::Value* stval = store->getValueOperand();
            auto off = pointerOffset(sptr, store->getPointerOperand(), DL);
            for (unsigned ri = 0; ri < ret_vals.size(); ri++) {
                if (!ret_vals[ri] && ret_map[ri] == off &&
                    stval->getType() == ret_ty->getElementType(ri)) {
                    ret_vals[ri] = stval;
                    deadinsts.push_back(store);
                    break;
                }
            }
        }
        for (auto* store : deadinsts)
            store->eraseFromParent();
        deadinsts.clear();

        // For the return values that are still missing, there can be two cases:
        //  - The value was never modified, so we return the parameter.
        //  - The value was eventually modified, so load the latest value.
        for (unsigned i = 0; i < ret_vals.size(); i++) {
            if (ret_vals[i])
                continue;
            llvm::Type* elem_ty = ret_ty->getElementType(i);
            if (ret_map[i] < 0) {
                ret_vals[i] = llvm::UndefValue::get(elem_ty);
                continue;
            }
            uint64_t tysz = DL.getTypeAllocSize(elem_ty);
            auto elem_map = (written_bytes >> ret_map[i]) << (SPTR_MAX_OFF - tysz);
            if (elem_map.any() || sptr_escapes) {
                // Need to load
                llvm::Value* gep = irb.CreateConstGEP1_64(sptr, ret_map[i]);
                llvm::Value* ptr = irb.CreatePointerCast(gep, elem_ty->getPointerTo(sptr_as));
                ret_vals[i] = irb.CreateLoad(elem_ty, ptr);
            } else {
                // Forward parameter to return value
                for (unsigned ai = 0; ai < nfn->arg_size(); ai++) {
                    if (arg_map[ai] != ret_map[i])
                        continue;
                    ret_vals[i] = nfn->arg_begin() + ai;
                    break;
                }
            }
        }
        irb.CreateAggregateRet(ret_vals.data(), ret_vals.size());
    }

    return nfn;
}
