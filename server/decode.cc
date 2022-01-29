
#include "decode.h"

#include <fadec.h>
#include <frvdec.h>
#include <farmdec.h>

DecodeResult DecodeX86_64(uintptr_t addr, size_t bufsz, const uint8_t* buf) {
    DecodeResult res{DecodeResult::FAILED, 0, 0};
    FdInstr fd;
    int ret = fd_decode(buf, bufsz, 64, 0, &fd);
    if (ret < 0)
        return res;

    res.size = ret;

    switch (FD_TYPE(&fd)) {
    case FDI_JO:
    case FDI_JNO:
    case FDI_JC:
    case FDI_JNC:
    case FDI_JZ:
    case FDI_JNZ:
    case FDI_JBE:
    case FDI_JA:
    case FDI_JS:
    case FDI_JNS:
    case FDI_JP:
    case FDI_JNP:
    case FDI_JL:
    case FDI_JGE:
    case FDI_JLE:
    case FDI_JG:
    case FDI_JCXZ:
    case FDI_LOOP:
    case FDI_LOOPZ:
    case FDI_LOOPNZ:
        res.result = DecodeResult::COND_BRANCH;
        res.branch_target = addr + res.size + FD_OP_IMM(&fd, 0);
        break;
    case FDI_JMP:
        if (FD_OP_TYPE(&fd, 0) == FD_OT_OFF) {
            res.result = DecodeResult::BRANCH;
            res.branch_target = addr + res.size + FD_OP_IMM(&fd, 0);
        } else {
            res.result = DecodeResult::UNKNOWN_TGT;
        }
        break;
    case FDI_CALL:
        res.result = DecodeResult::CALL;
        break;
    case FDI_RET:
    case FDI_SYSCALL:
    case FDI_INT:
    case FDI_INT3:
    case FDI_INTO:
    case FDI_UD0:
    case FDI_UD1:
    case FDI_UD2:
    case FDI_HLT:
        res.result = DecodeResult::UNKNOWN_TGT;
        break;
    default:
        res.result = DecodeResult::NORMAL;
        break;
    }
    return res;
}

DecodeResult DecodeRV64(uintptr_t addr, size_t bufsz, const uint8_t* buf) {
    DecodeResult res{DecodeResult::FAILED, 0, 0};
    FrvInst frv;
    int ret = frv_decode(bufsz, buf, FRV_RV64, &frv);
    if (ret < 0)
        return res;

    res.size = ret;

    switch (frv.mnem) {
    case FRV_BEQ:
    case FRV_BNE:
    case FRV_BLT:
    case FRV_BGE:
    case FRV_BLTU:
    case FRV_BGEU:
        res.result = DecodeResult::COND_BRANCH;
        res.branch_target = addr + frv.imm;
        break;
    case FRV_JAL:
        res.result = frv.rd ? DecodeResult::CALL : DecodeResult::BRANCH;
        res.branch_target = addr + frv.imm;
        break;
    case FRV_JALR:
        res.result = frv.rd ? DecodeResult::CALL : DecodeResult::UNKNOWN_TGT;
        break;
    case FRV_ECALL:
        res.result = DecodeResult::UNKNOWN_TGT;
        break;
    default:
        res.result = DecodeResult::NORMAL;
        break;
    }
    return res;
}

DecodeResult DecodeAArch64(uintptr_t addr, size_t bufsz, const uint8_t* buf) {
    DecodeResult res{DecodeResult::FAILED, 0, 0};
    farmdec::Inst fad;
    if (bufsz < 4)
        return res;
    uint32_t binst = buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
    fad_decode(&binst, 1, &fad);
    if (fad.op == farmdec::A64_ERROR || fad.op == farmdec::A64_UNKNOWN)
        return res;

    res.size = 4;

    switch (fad.op) {
    case farmdec::A64_BCOND:
    case farmdec::A64_CBZ:
    case farmdec::A64_CBNZ:
        res.result = DecodeResult::COND_BRANCH;
        res.branch_target = addr + fad.offset;
        break;
    case farmdec::A64_TBZ:
    case farmdec::A64_TBNZ:
        res.result = DecodeResult::COND_BRANCH;
        res.branch_target = addr + fad.tbz.offset;
        break;
    case farmdec::A64_B:
        res.result = DecodeResult::BRANCH;
        res.branch_target = addr + fad.offset;
        break;
    case farmdec::A64_BL:
    case farmdec::A64_BLR:
        res.result = DecodeResult::CALL;
        break;
    case farmdec::A64_BR:
    case farmdec::A64_RET:
    case farmdec::A64_SVC:
    case farmdec::A64_HVC:
    case farmdec::A64_SMC:
    case farmdec::A64_BRK:
    case farmdec::A64_HLT:
    case farmdec::A64_DCPS1:
    case farmdec::A64_DCPS2:
    case farmdec::A64_DCPS3:
        res.result = DecodeResult::UNKNOWN_TGT;
        break;
    default:
        res.result = DecodeResult::NORMAL;
        break;
    }
    return res;
}
