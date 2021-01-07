
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

// Note: replace with C++20 std::span.
template<typename T>
class span {
    T* ptr;
    std::size_t len;
public:
    constexpr span() noexcept : ptr(nullptr), len(0) {}
    template<std::size_t N>
    constexpr span(T (&arr)[N]) noexcept : ptr(arr), len(N) {}
    constexpr span           (const span&) noexcept = default;
    constexpr span& operator=(const span&) noexcept = default;
    constexpr std::size_t size() const noexcept { return len; }
    constexpr T* begin() const { return &ptr[0]; }
    constexpr T* end() const { return &ptr[len]; }
    constexpr T& operator[](std::size_t idx) const { return ptr[idx]; }
};

struct SptrField {
    unsigned offset;
    uint8_t size;
    uint8_t argidx;
    uint8_t retidx;
};

static constexpr unsigned SPTR_MAX_CNT = 16;
static constexpr unsigned SPTR_MAX_OFF = 13*8;

using SptrFieldSet = std::bitset<SPTR_MAX_CNT>;
using SptrFieldMap = std::array<char, SPTR_MAX_OFF>;
static constexpr SptrFieldMap CreateSptrMap(const span<const SptrField> fields) {
    SptrFieldMap res{};
    for (unsigned i = 0; i < fields.size(); i++) {
        const SptrField field = fields[i];
        res[field.offset] = i + 1;
        for (unsigned j = field.offset + 1; j < field.offset + field.size; j++)
            res[j] = -1;
    }
    return res;
}

struct CCState {
    const llvm::DataLayout& DL;
    llvm::Function* nfn;
    llvm::Argument* sptr;
    const SptrFieldMap& fieldmap;
    span<const SptrField> fields;

    SptrFieldMap::value_type GetFieldIdx(size_t idx) {
        return idx < fieldmap.size() ? fieldmap[idx] : 0;
    }

    llvm::Value* GetValue(const SptrField& field, llvm::Instruction* call,
                          llvm::IRBuilder<> irb) {
        if (call)
            return irb.CreateExtractValue(call, field.retidx);
        else
            return nfn->arg_begin() + field.argidx;
    }

    void FoldLoads(llvm::Instruction* call) {
        llvm::IRBuilder<> irb(nfn->getContext());
        llvm::BasicBlock::iterator it, end;
        if (!call)
            it = nfn->getEntryBlock().begin(), end = nfn->getEntryBlock().end();
        else
            it = ++call->getIterator(), end = call->getParent()->end();

        llvm::SmallVector<llvm::Instruction*, 64> deadinsts;
        for (; it != end; ++it) {
            if (it->mayWriteToMemory())
                break;
            llvm::LoadInst* load = llvm::dyn_cast<llvm::LoadInst>(it);
            if (!load)
                continue;
            if (load->getPointerAddressSpace() != sptr->getType()->getPointerAddressSpace())
                continue;
            // TODO: use llvm::isPointerOffset
            auto off = pointerOffset(sptr, load->getPointerOperand(), DL);
            if (GetFieldIdx(off) <= 0)
                continue;
            irb.SetInsertPoint(load);
            llvm::Value* repl = GetValue(fields[fieldmap[off] - 1], call, irb);
            if (load->getType() == repl->getType()) {
                load->replaceAllUsesWith(repl);
                deadinsts.push_back(load);
            }
        }
        for (auto* inst : deadinsts)
            inst->eraseFromParent();
    }

    void CreateStores(llvm::CallInst* call) {
        if (call && call->isMustTailCall())
            return;
        llvm::IRBuilder<> irb(nfn->getContext());
        if (call)
            irb.SetInsertPoint(call->getParent(), ++call->getIterator());
        else
            irb.SetInsertPoint(&nfn->getEntryBlock(), nfn->getEntryBlock().getFirstInsertionPt());
        unsigned sptr_as = sptr->getType()->getPointerAddressSpace();
        for (unsigned i = 0; i < fields.size(); i++) {
            llvm::Value* val = GetValue(fields[i], call, irb);
            llvm::Value* gep = irb.CreateConstGEP1_64(sptr, fields[i].offset);
            llvm::Type* ptr_ty = val->getType()->getPointerTo(sptr_as);
            irb.CreateStore(val, irb.CreatePointerCast(gep, ptr_ty));
        }
    }

    void FoldStores(llvm::Instruction* callret, bool sptr_escapes,
                    const SptrFieldSet& written_fields) {
        llvm::IRBuilder<> irb(callret);
        auto ret_ty = llvm::cast<llvm::StructType>(nfn->getReturnType());
        unsigned sptr_as = sptr->getType()->getPointerAddressSpace();

        llvm::SmallVector<llvm::Instruction*, SPTR_MAX_CNT> deadinsts;
        llvm::SmallVector<llvm::Value*, SPTR_MAX_CNT> vals;
        vals.resize(fields.size());
        auto end = callret->getParent()->rend();
        for (auto it = ++callret->getReverseIterator(); it != end; ++it) {
            auto store = llvm::dyn_cast<llvm::StoreInst>(&*it);
            if (!store || store->getPointerAddressSpace() != sptr_as)
                break;
            llvm::Value* stval = store->getValueOperand();
            auto off = pointerOffset(sptr, store->getPointerOperand(), DL);
            int fieldidx = GetFieldIdx(off);
            if (fieldidx > 0 && !vals[fieldidx - 1]) {
                vals[fieldidx - 1] = stval;
                if (!sptr_escapes)
                    deadinsts.push_back(store);
            }
        }

        for (unsigned i = 0; i < fields.size(); i++) {
            if (vals[i])
                continue;
            if (written_fields[i] || sptr_escapes) {
                // Need to load
                llvm::Value* gep = irb.CreateConstGEP1_64(sptr, fields[i].offset);
                llvm::Type* elem_ty = ret_ty->getElementType(fields[i].retidx);
                llvm::Value* ptr = irb.CreatePointerCast(gep, elem_ty->getPointerTo(sptr_as));
                vals[i] = irb.CreateLoad(elem_ty, ptr);
            } else {
                // TODO: adapt so that for callret values are propagated using
                // PHI nodes.
                vals[i] = nfn->arg_begin() + fields[i].argidx;
            }
        }

        if (auto call = llvm::dyn_cast<llvm::CallInst>(callret)) {
            llvm::Function* tgt = call->getCalledFunction();
            llvm::FunctionType* tgt_ty = tgt->getFunctionType();
            llvm::SmallVector<llvm::Value*, SPTR_MAX_CNT+1> params;
            params.resize(tgt_ty->getNumParams());
            params[sptr->getArgNo()] = sptr;
            for (unsigned i = 0; i < fields.size(); i++)
                params[fields[i].argidx] = vals[i];

            auto newcall = irb.CreateCall(tgt_ty, tgt, params);
            newcall->setTailCallKind(call->getTailCallKind());
            newcall->setCallingConv(tgt->getCallingConv());
            newcall->setAttributes(tgt->getAttributes());
            call->replaceAllUsesWith(newcall);
        } else {
            llvm::Value* ret_val = llvm::UndefValue::get(ret_ty);
            for (unsigned i = 0; i < fields.size(); i++)
                ret_val = irb.CreateInsertValue(ret_val, vals[i], {fields[i].retidx});
            irb.CreateRet(ret_val);
        }

        for (auto* inst : deadinsts)
            inst->eraseFromParent();
        callret->eraseFromParent();
    }
};

llvm::Function* ChangeCallConv(llvm::Function* fn, CallConv cc) {
    if (cc == CallConv::CDECL)
        return fn;

    llvm::Module* mod = fn->getParent();
    const llvm::DataLayout& DL = mod->getDataLayout();
    llvm::LLVMContext& ctx = mod->getContext();
    llvm::Type* sptr_ty = fn->arg_begin()[0].getType();
    unsigned sptr_as = sptr_ty->getPointerAddressSpace();
    llvm::Type* i64 = llvm::Type::getInt64Ty(ctx);

    llvm::Function* call_fn_cdecl = mod->getFunction("instrew_call_cdecl");
    llvm::Function* tail_fn = nullptr;
    llvm::Function* call_fn = nullptr;

    const SptrFieldMap* fieldmap;
    span<const SptrField> fields;
    llvm::StructType* ret_ty;
    llvm::FunctionType* fn_ty;
    llvm::Function* nfn;
    llvm::Argument* sptr;
    auto linkage = fn->getLinkage();

    switch (cc) {
    case CallConv::HHVM: {
        static const SptrField hhvm_fields[] = {
            { 0x00, 8, 0,  0  },
            { 0x08, 8, 10, 8  },
            { 0x10, 8, 7,  5  },
            { 0x18, 8, 6,  4  },
            { 0x20, 8, 2,  1  },
            { 0x28, 8, 3,  13 },
            { 0x30, 8, 13, 11 },
            { 0x38, 8, 5,  3  },
            { 0x40, 8, 4,  2  },
            { 0x48, 8, 8,  6  },
            { 0x50, 8, 9,  7  },
            { 0x58, 8, 11, 9  },
            { 0x60, 8, 12, 10 },
        };
        static const constexpr SptrFieldMap hhvm_fieldmap = CreateSptrMap(hhvm_fields);
        fields = hhvm_fields;
        fieldmap = &hhvm_fieldmap;
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
        sptr = &nfn->arg_begin()[1];

        if (call_fn_cdecl) {
            tail_fn = llvm::cast<llvm::Function>(mod->getOrInsertFunction("instrew_tail_hhvm", fn_ty).getCallee());
            tail_fn->copyAttributesFrom(nfn);
            call_fn = llvm::cast<llvm::Function>(mod->getOrInsertFunction("instrew_call_hhvm", fn_ty).getCallee());
            call_fn->copyAttributesFrom(nfn);
        }
        break;
    }
    case CallConv::CDECL:
    default:
        assert(false && "unsupported Instrew calling convention!");
    }

    CCState ccs{DL, nfn, sptr, *fieldmap, fields};

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

    llvm::SmallVector<llvm::Instruction*, 16> deadinsts;

    // Find all calls to call/tail functions.
    llvm::SmallVector<llvm::CallInst*, 16> callret_calls;
    if (call_fn_cdecl) {
        for (auto* user : call_fn_cdecl->users())
            if (auto call = llvm::dyn_cast<llvm::CallInst>(user))
                if (call->getCalledFunction() == call_fn_cdecl)
                    callret_calls.push_back(call);
        for (size_t i = 0; i < callret_calls.size(); i++) {
            llvm::CallInst* call = callret_calls[i];
            auto tgt = call->isMustTailCall() ? tail_fn : call_fn;
            auto newcall = llvm::CallInst::Create(fn_ty, tgt, "", call);
            newcall->setTailCallKind(call->getTailCallKind());
            newcall->setCallingConv(tgt->getCallingConv());
            newcall->setAttributes(tgt->getAttributes());
            call->eraseFromParent();
            callret_calls[i] = newcall;
        }
    }

    // First fold known loads.
    ccs.FoldLoads(nullptr);
    for (auto* call : callret_calls)
        ccs.FoldLoads(call);

    // Now find all bytes which are still read and written somewhere during
    // the function, and check whether sptr escapes the function.
    bool sptr_escapes = false;
    SptrFieldSet written_fields;

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
                    if (store->getPointerOperand() != val)
                        goto end_escape;
                    uint64_t tysz = DL.getTypeAllocSize(store->getValueOperand()->getType());
                    if (off >= SPTR_MAX_OFF)
                        continue;
                    int fieldidx = ccs.GetFieldIdx(off);
                    if (fieldidx <= 0) {
                        // Check for partial overwrites
                        for (unsigned i = off; i < off + tysz; i++)
                            if (ccs.GetFieldIdx(i))
                                goto end_escape;
                        continue;
                    } else {
                        if (tysz != fields[fieldidx - 1].size)
                            goto end_escape;
                        written_fields.set(fieldidx - 1);
                    }
                } else if (inst->getOpcode() == llvm::Instruction::Load) {
                    uint64_t tysz = DL.getTypeAllocSize(inst->getType());
                    // Check for partial or unremoved reads
                    for (unsigned i = off; i < off + tysz; i++)
                        if (ccs.GetFieldIdx(i))
                            goto end_escape;
                } else if (inst->isCast()) {
                    llvm::Type* dstty = inst->getType();
                    if (!dstty->isPointerTy() || dstty->getPointerAddressSpace() != sptr_as)
                        goto end_escape;
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
                    // call/tail calls currently have no arguments
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
    // If we aborted the loop, the queue is not empty.
    sptr_escapes = !queue.empty();

    // Check whether we must add necessary stores for all or specific fields.
    // TODO: If unwritten fields are propagated, this is only necessary on escape
    if (!callret_calls.empty() || sptr_escapes) {
        ccs.CreateStores(nullptr);
        for (auto* call : callret_calls)
            ccs.CreateStores(call);
    }

    // Then, fold known stores. There should be at most one returning BB.
    for (llvm::BasicBlock& bb : *nfn) {
        auto* ret = llvm::dyn_cast<llvm::ReturnInst>(bb.getTerminator());
        if (!ret)
            continue;
        if (llvm::CallInst* tailcall = bb.getTerminatingMustTailCall()) {
            if (!tailcall->getType()->isVoidTy()) {
                llvm::ReturnInst::Create(ctx, tailcall, ret);
                ret->eraseFromParent();
            }
            continue;
        }

        ccs.FoldStores(ret, !callret_calls.empty() || sptr_escapes, written_fields);
    }
    for (auto* call : callret_calls)
        ccs.FoldStores(call, !callret_calls.empty() || sptr_escapes, written_fields);

    return nfn;
}
