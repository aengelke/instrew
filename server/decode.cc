
#include "decode.h"

#include <fadec.h>
#include <frvdec.h>

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
