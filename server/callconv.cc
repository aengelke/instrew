
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
#include <elf.h>
#include <iostream>
#include <optional>
#include <sstream>


CallConv GetFastCC(int host_arch, int guest_arch) {
    if (host_arch == EM_X86_64 && guest_arch == EM_X86_64)
        return CallConv::HHVM;
    if (host_arch == EM_X86_64 && guest_arch == EM_RISCV)
        return CallConv::RV64_X86_HHVM;
    if (host_arch == EM_X86_64 && guest_arch == EM_AARCH64)
        return CallConv::AARCH64_X86_HHVM;
    if (host_arch == EM_AARCH64 && guest_arch == EM_X86_64)
        return CallConv::X86_AARCH64_X;
    if (host_arch == EM_AARCH64 && guest_arch == EM_AARCH64)
        return CallConv::AARCH64_AARCH64_X;
    return CallConv::CDECL;
}

int GetCallConvClientNumber(CallConv cc) {
    switch (cc) {
    case CallConv::CDECL: return 0;
    case CallConv::HHVM: return 1;
    case CallConv::RV64_X86_HHVM: return 1;
    case CallConv::AARCH64_X86_HHVM: return 1;
    case CallConv::X86_AARCH64_X: return 3;
    case CallConv::AARCH64_AARCH64_X: return 3;
    default: return 0;
    }
}

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

    struct OffSize {
        unsigned offset;
        uint8_t size;
    };

    constexpr SptrField(OffSize os, uint8_t argidx, uint8_t retidx)
            : offset(os.offset), size(os.size), argidx(argidx), retidx(retidx) {}
};

namespace SptrFields::x86_64 {
#define RELLUME_PUBLIC_REG(name,nameu,sz,off) \
        constexpr SptrField::OffSize nameu{off,sz};
#include <rellume/cpustruct-x86_64.inc>
#undef RELLUME_PUBLIC_REG
}

namespace SptrFields::rv64 {
#define RELLUME_PUBLIC_REG(name,nameu,sz,off) \
        constexpr SptrField::OffSize nameu{off,sz};
#include <rellume/cpustruct-rv64.inc>
#undef RELLUME_PUBLIC_REG
}

namespace SptrFields::aarch64 {
#define RELLUME_PUBLIC_REG(name,nameu,sz,off) \
        constexpr SptrField::OffSize nameu{off,sz};
#include <rellume/cpustruct-aarch64.inc>
#undef RELLUME_PUBLIC_REG
}

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
            llvm::Type* i8 = irb.getInt8Ty();
            llvm::Value* gep = irb.CreateConstGEP1_64(i8, sptr, fields[i].offset);
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

    void UpdateCallRet(llvm::Instruction* callret, FoldedStores& vals) {
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
            llvm::Type* i8 = irb.getInt8Ty();
            llvm::Value* gep = irb.CreateConstGEP1_64(i8, sptr, fields[i].offset);
            llvm::Value* ptr = irb.CreatePointerCast(gep, elem_ty->getPointerTo(sptr_as));
            vals[i] = irb.CreateLoad(elem_ty, ptr);
        }

        if (auto call = llvm::dyn_cast<llvm::CallInst>(callret)) {
            llvm::Function* tgt = call->getCalledFunction();
            llvm::FunctionType* tgt_ty = tgt->getFunctionType();
            llvm::SmallVector<llvm::Value*, SPTR_MAX_CNT+1> params;
            params.resize(tgt_ty->getNumParams());
            for (unsigned i = 0; i < params.size(); i++)
                params[i] = llvm::UndefValue::get(tgt_ty->getParamType(i));
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
            if (sptr_ret_idx >= 0) {
                unsigned idx_u = static_cast<unsigned>(sptr_ret_idx);
                ret_val = irb.CreateInsertValue(ret_val, sptr, {idx_u});
            }
            uint32_t rv_set = 0;
            for (unsigned i = 0; i < fields.size(); i++) {
                ret_val = irb.CreateInsertValue(ret_val, vals[i], {fields[i].retidx});
                rv_set |= 1 << fields[i].retidx;
            }
            // This is an *EXTREMELY UGLY HACK* to work around some bugs in LLVM
            // when RBP is a parameter register. So first of all, we lowered the
            // stack alignment to 8, because HHVMCC functions cannot be called
            // due to the skewed stack alignment (Bug 1). Some code needs stack
            // stack realignments. The HHVMCC uses RBP for parameters/return
            // values, but stack realignment routines use RBP to hold the old
            // stack pointer value unconditionally. This leads to broken code:
            //
            //     push rbp; mov rbp, rsp; and rsp, -16; ...
            //     (parameter is now clobbered/gone -- whoops!)
            //     (rbp is modified, trashing the old RSP -- whoops!)
            //     ...; mov rsp, rbp; pop rbp; ret
            // (Bug 2)
            //
            // Disabling that with "no-realign-stack" doesn't work either,
            // because lowering some instructions (e.g., extractelement with a
            // variable index) simply assumes a suitably aligned stack (Bug 3).
            //
            // Now the options to work around this situation are:
            // - Inlineasm for calls containing "sub rsp, 8; call; add rsp 8"
            //   (not good for performance)
            // - Not generating code that needs stack alignment (impossible)
            // - Implementing proper support for custom CCs upstream (hard work)
            // - Fixing any of the LLVM bugs mentioned above.
            //   (consequence: Instrew would need a patched LLVM to work)
            // - Always returning the original RBP to emulate a callee-saved reg
            //   (this is what we do here)
            //
            // For now, we do this only for AArch64 guests, the problem wasn't
            // encountered with other guest architectures.
            //
            // RBP is parameter (zero-indexed) 2 and return index 1.
            if (nfn->getCallingConv() == llvm::CallingConv::HHVM && !(rv_set & 2))
                ret_val = irb.CreateInsertValue(ret_val, nfn->arg_begin() + 2, {1});
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
        static constexpr SptrField aapcsx_fields[] = {
            { SptrFields::x86_64::RIP,  0,  0  },
            { SptrFields::x86_64::RAX,  1,  1  },
            { SptrFields::x86_64::RCX,  2,  2  },
            { SptrFields::x86_64::RDX,  3,  3  },
            { SptrFields::x86_64::RBX,  4,  4  },
            { SptrFields::x86_64::RSP,  5,  5  },
            { SptrFields::x86_64::RSI,  6,  6  },
            { SptrFields::x86_64::RDI,  7,  7  },
        };
        static const constexpr SptrFieldMap aapcsx_fieldmap = CreateSptrMap(aapcsx_fields);
        fields = aapcsx_fields;
        fieldmap = &aapcsx_fieldmap;
    callconv_aapcsx_common:
        ret_ty = llvm::StructType::get(i64, i64, i64, i64, i64, i64, i64, i64);
        fn_ty = llvm::FunctionType::get(ret_ty,
                {i64, i64, i64, i64, i64, i64, i64, i64, sptr_ty}, false);

        nfn = llvm::Function::Create(fn_ty, linkage, fn->getName() + "_aapcsx", mod);
        nfn->copyAttributesFrom(fn);
        llvm::AttributeList al = nfn->getAttributes();
#if LL_LLVM_MAJOR < 14
        al = al.addParamAttributes(ctx, 8, al.getParamAttributes(0));
#else
        llvm::AttrBuilder ab(ctx, al.getParamAttrs(0));
        al = al.addParamAttributes(ctx, 8, ab);
#endif
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
    case CallConv::AARCH64_AARCH64_X: {
        static constexpr SptrField aapcsx_fields[] = {
            { SptrFields::aarch64::PC,  0,  0  },
            { SptrFields::aarch64::X0,  1,  1  },
            { SptrFields::aarch64::X1,  2,  2  },
            { SptrFields::aarch64::X2,  3,  3  },
            { SptrFields::aarch64::X3,  4,  4  },
            { SptrFields::aarch64::X4,  5,  5  },
            { SptrFields::aarch64::X30, 6,  6  },
            { SptrFields::aarch64::X6,  7,  7  }, // TODO: map SP
        };
        static const constexpr SptrFieldMap aapcsx_fieldmap = CreateSptrMap(aapcsx_fields);
        fields = aapcsx_fields;
        fieldmap = &aapcsx_fieldmap;
        goto callconv_aapcsx_common;
    }
    case CallConv::HHVM: {
        static constexpr SptrField hhvm_fields[] = {
            { SptrFields::x86_64::RIP, 0,  0  },
            { SptrFields::x86_64::RAX, 10, 8  },
            { SptrFields::x86_64::RCX, 7,  5  },
            { SptrFields::x86_64::RDX, 6,  4  },
            // TBD: determine whether we can safely map to RBP
            { SptrFields::x86_64::RBX, 2,  1  },
            { SptrFields::x86_64::RSP, 3,  13 },
            { SptrFields::x86_64::RBP, 13, 11 },
            { SptrFields::x86_64::RSI, 5,  3  },
            { SptrFields::x86_64::RDI, 4,  2  },
            { SptrFields::x86_64::R8,  8,  6  },
            { SptrFields::x86_64::R9,  9,  7  },
            { SptrFields::x86_64::R10, 11, 9  },
            { SptrFields::x86_64::R11, 12, 10 },
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
#if LL_LLVM_MAJOR < 14
        al = al.addParamAttributes(ctx, 1, al.getParamAttributes(0));
#else
        llvm::AttrBuilder ab(ctx, al.getParamAttrs(0));
        al = al.addParamAttributes(ctx, 1, ab);
#endif
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
        static constexpr SptrField hhvm_fields[] = {
            { SptrFields::rv64::RIP, 0,  0  },
            { SptrFields::rv64::X18, 10, 8  },
            { SptrFields::rv64::X1,  7,  5  },
            { SptrFields::rv64::X2,  6,  4  }, // sp; has to be at this index due to initialization
            // TBD: determine whether we can safely map to RBP
            { SptrFields::rv64::X8,  2,  1  },
            { SptrFields::rv64::X9,  3,  13 },
            { SptrFields::rv64::X10, 13, 11 },
            { SptrFields::rv64::X11, 5,  3  },
            { SptrFields::rv64::X12, 4,  2  },
            { SptrFields::rv64::X13, 8,  6  },
            { SptrFields::rv64::X14, 9,  7  },
            { SptrFields::rv64::X15, 11, 9  },
            { SptrFields::rv64::X17, 12, 10 },
        };
        static const constexpr SptrFieldMap hhvm_fieldmap = CreateSptrMap(hhvm_fields);
        fields = hhvm_fields;
        fieldmap = &hhvm_fieldmap;
        goto callconv_hhvm_common;
    }
    case CallConv::AARCH64_X86_HHVM: {
        static constexpr SptrField hhvm_fields[] = {
            { SptrFields::aarch64::PC,  0,  0  },
            { SptrFields::aarch64::X0,  10, 8  },
            { SptrFields::aarch64::X1,  7,  5  },
            { SptrFields::aarch64::X2,  6,  4  },
            // Can't map to RBP (2,1), see above for a detailed discussion
            { SptrFields::aarch64::X3,  3,  13 },
            { SptrFields::aarch64::X4,  13, 11 },
            { SptrFields::aarch64::X5,  5,  3  },
            { SptrFields::aarch64::X6,  4,  2  },
            { SptrFields::aarch64::X7,  8,  6  },
            { SptrFields::aarch64::X8,  9,  7  },
            { SptrFields::aarch64::X30, 11, 9  },
            { SptrFields::aarch64::X9,  12, 10 }, // TODO: map SP
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
#if LL_LLVM_MAJOR < 16
            nfn->getBasicBlockList().push_back(bb);
#else
            nfn->insert(nfn->end(), bb);
#endif
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
            auto newcall = llvm::CallInst::Create(fn_ty, tgt, {}, "", call);
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
        ccs.UpdateCallRet(callret, stores);

    return nfn;
}
