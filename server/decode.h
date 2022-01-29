
#ifndef _INSTREW_SERVER_DECODE_H
#define _INSTREW_SERVER_DECODE_H

#include <cstddef>
#include <cstdint>

struct DecodeResult {
    enum {
        FAILED = 0,
        NORMAL,
        BRANCH,
        COND_BRANCH,
        CALL,
        UNKNOWN_TGT,
    } result;
    std::uint8_t size;
    std::uint64_t branch_target;
};

DecodeResult DecodeX86_64(uintptr_t addr, size_t bufsz, const uint8_t* buf);
DecodeResult DecodeRV64(uintptr_t addr, size_t bufsz, const uint8_t* buf);
DecodeResult DecodeAArch64(uintptr_t addr, size_t bufsz, const uint8_t* buf);

#endif
