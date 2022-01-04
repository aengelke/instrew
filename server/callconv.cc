
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
#include <optional>
#include <sstream>


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

static std::optional<std::string> FuncConstName(llvm::Value* pc) {
    if (auto* tgt_cnst = llvm::dyn_cast<llvm::ConstantInt>(pc)) {
        std::stringstream namebuf;
        namebuf << "Z" << std::oct << tgt_cnst->getZExtValue();
        return namebuf.str();
    }
    if (auto* expr = llvm::dyn_cast<llvm::ConstantExpr>(pc)) {
        if (expr->getOpcode() != llvm::Instruction::Add)
            return std::nullopt;
        auto* lhs = llvm::dyn_cast<llvm::ConstantExpr>(expr->getOperand(0));
        auto* rhs = llvm::dyn_cast<llvm::ConstantInt>(expr->getOperand(1));
        if (lhs && rhs && lhs->getOpcode() == llvm::Instruction::PtrToInt &&
            llvm::isa<llvm::GlobalVariable>(lhs->getOperand(0)) &&
            lhs->getOperand(0)->getName() == "instrew_baseaddr") {
            std::stringstream namebuf;
            namebuf << "S" << std::oct << rhs->getZExtValue();
            return namebuf.str();
        }
    }
    return std::nullopt;
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
static constexpr unsigned SPTR_MAX_OFF = 0x1a0;

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
    int sptr_ret_idx;
    llvm::Function* call_fn;
    llvm::Function* tail_fn;

    SptrFieldMap::value_type GetFieldIdx(size_t idx) {
        return idx < fieldmap.size() ? fieldmap[idx] : 0;
    }

    llvm::Value* GetValue(const SptrField& field, llvm::Instruction* call,
                          llvm::IRBuilder<>& irb) {
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
            if (load->getType() != repl->getType())
                repl = irb.CreateBitCast(repl, load->getType());
            load->replaceAllUsesWith(repl);
            deadinsts.push_back(load);
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

    using FoldedStores = llvm::SmallVector<llvm::Value*, SPTR_MAX_CNT>;
    FoldedStores FoldStores(llvm::Instruction* callret,
                           llvm::DenseMap<llvm::StoreInst*, unsigned>& stores) {
        llvm::IRBuilder<> irb(callret);
        unsigned sptr_as = sptr->getType()->getPointerAddressSpace();

        llvm::SmallVector<llvm::Instruction*, SPTR_MAX_CNT> deadinsts;
        FoldedStores vals;
        vals.resize(fields.size());
        auto end = callret->getParent()->rend();
        for (auto it = ++callret->getReverseIterator(); it != end; ++it) {
            if (auto call = llvm::dyn_cast<llvm::CallInst>(&*it)) {
                // Check whether sptr escapes here.
                for (const auto& arg : call->args()) {
                    llvm::Type* at = arg->getType();
                    if (at->isPointerTy() && at->getPointerAddressSpace() == sptr_as)
                        goto end_collect;
                }
                if (call->getCalledFunction() != call_fn &&
                    call->getCalledFunction() != tail_fn)
                    continue;
                // This code path should be working, but is untested. The lifter
                // currently only generates at most one call/tail per block.
                // Tails naturally have nothing following them; calls need an
                // immediately following check that the PC matches the expected
                // address. For now, abort whenever this assumption changes.
                assert(false && "more than one call/tail in a block!");
                // Propagate values from last call/tail call.
                for (unsigned i = 0; i < fields.size(); i++)
                    if (!vals[i])
                        vals[i] = GetValue(fields[i], call, irb);
                break;
            }
            if (auto load = llvm::dyn_cast<llvm::LoadInst>(&*it)) {
                if (load->getPointerAddressSpace() == sptr_as)
                    break;
            }
            auto store = llvm::dyn_cast<llvm::StoreInst>(&*it);
            if (!store || store->getPointerAddressSpace() != sptr_as)
                continue;
            llvm::Value* stval = store->getValueOperand();
            auto off = pointerOffset(sptr, store->getPointerOperand(), DL);
            int fieldidx = GetFieldIdx(off);
            if (fieldidx > 0) {
                assert(!vals[fieldidx - 1] && "dead store");
                vals[fieldidx - 1] = stval;
                stores.erase(store);
                deadinsts.push_back(store);
            }
        }
    end_collect:
        for (auto* inst : deadinsts)
            inst->eraseFromParent();
        return vals;
    }

    void UpdateCallRet(llvm::Instruction* callret, bool sptr_escapes,
                       FoldedStores& vals) {
        llvm::IRBuilder<> irb(callret);
        auto ret_ty = llvm::cast<llvm::StructType>(nfn->getReturnType());
        unsigned sptr_as = sptr->getType()->getPointerAddressSpace();
        for (unsigned i = 0; i < fields.size(); i++) {
            llvm::Type* elem_ty = ret_ty->getElementType(fields[i].retidx);
            if (vals[i]) {
                if (vals[i]->getType() != elem_ty)
                    vals[i] = irb.CreateBitCast(vals[i], elem_ty);
                continue;
            }
            // Need to load
            llvm::Value* gep = irb.CreateConstGEP1_64(sptr, fields[i].offset);
            llvm::Value* ptr = irb.CreatePointerCast(gep, elem_ty->getPointerTo(sptr_as));
            vals[i] = irb.CreateLoad(elem_ty, ptr);
        }

        if (auto call = llvm::dyn_cast<llvm::CallInst>(callret)) {
            llvm::Function* tgt = call->getCalledFunction();
            llvm::FunctionType* tgt_ty = tgt->getFunctionType();
            llvm::SmallVector<llvm::Value*, SPTR_MAX_CNT+1> params;
            params.resize(tgt_ty->getNumParams());
            params[sptr->getArgNo()] = sptr;
            for (unsigned i = 0; i < fields.size(); i++)
                params[fields[i].argidx] = vals[i];

            if (auto name = FuncConstName(params[0])) {
                auto fnc = tgt->getParent()->getOrInsertFunction(*name, tgt_ty);
                tgt = llvm::cast<llvm::Function>(fnc.getCallee());
                tgt->copyAttributesFrom(nfn);
                tgt->setDSOLocal(true);
                params[0] = llvm::UndefValue::get(params[0]->getType());
            }

            auto newcall = irb.CreateCall(tgt_ty, tgt, params);
            newcall->setTailCallKind(call->getTailCallKind());
            newcall->setCallingConv(tgt->getCallingConv());
            newcall->setAttributes(tgt->getAttributes());
            call->replaceAllUsesWith(newcall);
        } else {
            llvm::Value* ret_val = llvm::UndefValue::get(ret_ty);
            if (sptr_ret_idx >= 0)
                ret_val = irb.CreateInsertValue(ret_val, sptr, {sptr_ret_idx});
            for (unsigned i = 0; i < fields.size(); i++)
                ret_val = irb.CreateInsertValue(ret_val, vals[i], {fields[i].retidx});
            irb.CreateRet(ret_val);
        }

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
    llvm::Type* v2i64 = llvm::VectorType::get(i64, 2);

    llvm::Function* call_fn_cdecl = mod->getFunction("instrew_call_cdecl");
    llvm::Function* tail_fn = nullptr;
    llvm::Function* call_fn = nullptr;

    const SptrFieldMap* fieldmap;
    span<const SptrField> fields;
    llvm::StructType* ret_ty;
    llvm::FunctionType* fn_ty;
    llvm::Function* nfn;
    llvm::Argument* sptr;
    int sptr_ret_idx = -1;
    auto linkage = fn->getLinkage();

    switch (cc) {
    case CallConv::X86_AARCH64_X: {
        static const SptrField aapcsx_fields[] = {
            { 0x00,  8,  0,  0  },
            { 0x08,  8,  1,  1  },
            { 0x10,  8,  2,  2  },
            { 0x18,  8,  3,  3  },
            { 0x20,  8,  4,  4  },
            { 0x28,  8,  5,  5  },
            { 0x38,  8,  6,  6  },
            { 0x40,  8,  7,  7  },
        };
        static const constexpr SptrFieldMap aapcsx_fieldmap = CreateSptrMap(aapcsx_fields);
        fields = aapcsx_fields;
        fieldmap = &aapcsx_fieldmap;
        ret_ty = llvm::StructType::get(i64, i64, i64, i64, i64, i64, i64, i64);
        fn_ty = llvm::FunctionType::get(ret_ty,
                {i64, i64, i64, i64, i64, i64, i64, i64, sptr_ty}, false);

        nfn = llvm::Function::Create(fn_ty, linkage, fn->getName() + "_aapcsx", mod);
        nfn->copyAttributesFrom(fn);
        llvm::AttributeList al = nfn->getAttributes();
        al = al.addParamAttributes(ctx, 8, al.getParamAttributes(0));
        nfn->setAttributes(al.removeParamAttributes(ctx, 0));
        nfn->addParamAttr(8, llvm::Attribute::SwiftSelf);
        sptr = &nfn->arg_begin()[8];

        if (call_fn_cdecl) {
            tail_fn = llvm::cast<llvm::Function>(mod->getOrInsertFunction("instrew_quick_dispatch", fn_ty).getCallee());
            tail_fn->copyAttributesFrom(nfn);
            tail_fn->setDSOLocal(true);
            call_fn = tail_fn;
        }
        break;
    }
    case CallConv::X86_X86_RC: {
        static const SptrField rc_fields[] = {
            { 0x00,  8,  0,  0  },
            { 0x08,  8,  1,  1  },
            { 0x10,  8,  2,  2  },
            { 0x18,  8,  3,  3  },
            { 0x20,  8,  4,  4  },
            { 0x28,  8,  5,  5  },
            { 0x30,  8,  6,  6  },
            { 0x38,  8,  8,  8  },
            { 0x40,  8,  9,  9  },
            { 0x48,  8,  10, 10 },
            { 0x0a0, 16, 11, 11 },
            { 0x0b0, 16, 12, 12 },
            { 0x0c0, 16, 13, 13 },
            { 0x0d0, 16, 14, 14 },
            { 0x0e0, 16, 15, 15 },
            { 0x0f0, 16, 16, 16 },
            { 0x100, 16, 17, 17 },
            { 0x110, 16, 18, 18 },
            { 0x120, 16, 19, 19 },
            { 0x130, 16, 20, 20 },
            { 0x140, 16, 21, 21 },
            { 0x150, 16, 22, 22 },
            { 0x160, 16, 23, 23 },
            { 0x170, 16, 24, 24 },
            { 0x180, 16, 25, 25 },
            // Note: while regcallcc allows for 16 XMM parameters/return values,
            // one must remain available for the register allocator.
        };
        static const constexpr SptrFieldMap rc_fieldmap = CreateSptrMap(rc_fields);
        fields = rc_fields;
        fieldmap = &rc_fieldmap;
        ret_ty = llvm::StructType::get(i64, i64, i64, i64, i64, i64, i64,
                                       sptr_ty, i64, i64, i64,
                                       v2i64, v2i64, v2i64, v2i64,
                                       v2i64, v2i64, v2i64, v2i64,
                                       v2i64, v2i64, v2i64, v2i64,
                                       v2i64, v2i64, v2i64);
        fn_ty = llvm::FunctionType::get(ret_ty,
                {i64, i64, i64, i64, i64, i64, i64, sptr_ty, i64, i64, i64,
                 v2i64, v2i64, v2i64, v2i64, v2i64, v2i64, v2i64, v2i64,
                 v2i64, v2i64, v2i64, v2i64, v2i64, v2i64, v2i64}, false);
    callconv_x86_rc_common:

        nfn = llvm::Function::Create(fn_ty, linkage, fn->getName() + "_rc", mod);
        nfn->copyAttributesFrom(fn);
        llvm::AttributeList al = nfn->getAttributes();
        al = al.addParamAttributes(ctx, 7, al.getParamAttributes(0));
        nfn->setAttributes(al.removeParamAttributes(ctx, 0));
        nfn->setCallingConv(llvm::CallingConv::X86_RegCall);
        sptr = &nfn->arg_begin()[7];
        sptr_ret_idx = 7;

        if (call_fn_cdecl) {
            tail_fn = llvm::cast<llvm::Function>(mod->getOrInsertFunction("instrew_dispatch_x86", fn_ty).getCallee());
            tail_fn->copyAttributesFrom(nfn);
            tail_fn->setDSOLocal(true);
            call_fn = tail_fn;
        }
        break;
    }
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
    callconv_hhvm_common:
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
    case CallConv::RV64_X86_HHVM: {
        static const SptrField hhvm_fields[] = {
            { 0x00, 8, 0,  0  }, // pc
            { 0x98, 8, 10, 8  }, // x18
            { 0x10, 8, 7,  5  }, // x1/ra
            { 0x18, 8, 6,  4  }, // x2/sp; must be 0x18 due initialization
            { 0x48, 8, 2,  1  }, // x8
            { 0x50, 8, 3,  13 }, // x9
            { 0x58, 8, 13, 11 }, // x10
            { 0x60, 8, 5,  3  }, // x11
            { 0x68, 8, 4,  2  }, // x12
            { 0x70, 8, 8,  6  }, // x13
            { 0x78, 8, 9,  7  }, // x14
            { 0x80, 8, 11, 9  }, // x15
            { 0x90, 8, 12, 10 }, // x17
        };
        static const constexpr SptrFieldMap hhvm_fieldmap = CreateSptrMap(hhvm_fields);
        fields = hhvm_fields;
        fieldmap = &hhvm_fieldmap;
        goto callconv_hhvm_common;
    }
    case CallConv::CDECL:
    default:
        assert(false && "unsupported Instrew calling convention!");
    }

    CCState ccs{DL, nfn, sptr, *fieldmap, fields, sptr_ret_idx, call_fn, tail_fn};

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

    llvm::DenseMap<llvm::StoreInst*, unsigned> stores;
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
                        stores[store] = fieldidx - 1;
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
    sptr_escapes = !queue.empty();// || !callret_calls.empty();

    // Then, fold known stores.
    llvm::SmallVector<std::pair<llvm::Instruction*, CCState::FoldedStores>, 20> callret_stores;
    callret_stores.reserve(callret_calls.size() + 4);

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

        callret_stores.push_back(std::make_pair(ret, ccs.FoldStores(ret, stores)));
    }
    for (auto* call : callret_calls)
        callret_stores.push_back(std::make_pair(call, ccs.FoldStores(call, stores)));

    // By now, all stores should be gone. If there are still stores left,
    // we know that folding was unsuccessful and we must be conservative.
    sptr_escapes |= !stores.empty();
    if (!sptr_escapes) {
        // There may be cases where some values are not found. If we have no
        // call/tail calls, we can simply use the arguments. Otherwise we need
        // to wire PHI nodes through the function.
        llvm::DenseMap<std::pair<llvm::BasicBlock*, unsigned>, llvm::PHINode*> phimap;
        llvm::DenseMap<llvm::BasicBlock*, llvm::Instruction*> last_producer;
        // Producer of the entry block are the function parameters.
        last_producer[&nfn->getEntryBlock()] = nullptr;
        for (auto& [callret, vals] : callret_stores) {
            llvm::BasicBlock* bb = callret->getParent();
            if (!last_producer.try_emplace(bb, callret).second)
                assert(false && "multiple producer in single block");
            llvm::IRBuilder<> irb(bb->getFirstNonPHI());
            for (unsigned i = 0; i < fields.size(); i++) {
                if (vals[i])
                    continue;
                if (callret_calls.empty()) {
                    vals[i] = nfn->arg_begin() + fields[i].argidx;
                } else {
                    llvm::Type* elem_ty = ret_ty->getElementType(fields[i].retidx);
                    auto phi = irb.CreatePHI(elem_ty, 2);
                    vals[i] = phi;
                    phimap[std::make_pair(bb, i)] = phi;
                }
            }
        }

        llvm::SmallVector<std::pair<unsigned, llvm::PHINode*>, 64> phi_queue;
        phi_queue.reserve(phimap.size() * 2);
        for (const auto& [bi, phi] : phimap)
            phi_queue.push_back(std::make_pair(bi.second, phi));
        while (!phi_queue.empty()) {
            auto [fieldidx, phi] = phi_queue[phi_queue.size() - 1];
            phi_queue.pop_back();
            auto it = pred_begin(phi->getParent());
            auto end = pred_end(phi->getParent());
            for (; it != end; ++it) {
                llvm::BasicBlock* pred = *it;
                llvm::IRBuilder<> irb(pred->getTerminator());
                auto producer = last_producer.find(pred);
                if (producer != last_producer.end()) {
                    auto value = ccs.GetValue(fields[fieldidx], producer->second, irb);
                    phi->addIncoming(value, pred);
                    continue;
                }
                auto parent_phi = phimap.find(std::make_pair(pred, fieldidx));
                if (parent_phi != phimap.end()) {
                    phi->addIncoming(parent_phi->second, pred);
                } else {
                    irb.SetInsertPoint(pred->getFirstNonPHI());
                    llvm::Type* elem_ty = ret_ty->getElementType(fields[fieldidx].retidx);
                    auto nphi = irb.CreatePHI(elem_ty, 2);
                    phimap[std::make_pair(pred, fieldidx)] = nphi;
                    phi_queue.push_back(std::make_pair(fieldidx, nphi));
                    phi->addIncoming(nphi, pred);
                }
            }
        }
    }

    // Check whether we must add necessary stores for all or specific fields.
    if (sptr_escapes) {
        ccs.CreateStores(nullptr);
        for (auto* call : callret_calls)
            ccs.CreateStores(call);
    }

    for (auto& [callret, stores] : callret_stores)
        ccs.UpdateCallRet(callret, sptr_escapes, stores);

    return nfn;
}
