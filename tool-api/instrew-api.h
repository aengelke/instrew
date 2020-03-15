
#ifndef _INSTREW_INSTREW_API_H
#define _INSTREW_INSTREW_API_H

#include <llvm-c/Core.h>

#ifdef __cplusplus
extern "C" {
#endif

enum InstrewDescFlags {
    /// Indicate that some standard optimization passes are run after
    /// instrumentation. Otherwise, running optimizations during instrumentation
    /// is strongly recommended for performance.
    INSTREW_DESC_OPTIMIZE = 1 << 0,

    /// Indicates that the HHVM calling convention is supported on x86-64.
    INSTREW_DESC_SUPPORTS_HHVM = 1 << 1,

    /// If set, the instrumented IR or the generated machine code ay be cached.
    /// A recompilation is guaranteed to be triggered, if the instrumenter UUID
    /// or the configuration string changes.
    INSTREW_DESC_CACHABLE = 1 << 2,

    /// Whether to add calls to a marker function (named `instrew_instr_marker`)
    /// before each instruction. The first argument is the `rip` (pointing to
    /// the end of the instruction), the second argument is the decoded FdInstr.
    /// The end of the instruction in the LLVM-IR is either indicated by another
    /// call to this function or the exit basic block. All calls to this
    /// function must be removed during instrumentation.
    INSTREW_DESC_MARK_INSTRS = 1 << 3,

    /// Whether to add calls to a marker function (named `instrew_write_sp`)
    /// whenever the stack pointer (`rsp`) is written. The arguments are the old
    /// and new value, respectively. All calls to this function must be removed
    /// during instrumentation.
    INSTREW_DESC_TRACK_SP = 1 << 4,
};

struct InstrewDesc {
    /// Magic number, must be 0xAEDB1000
    uint32_t magic;

    /// A combination of InstrewDescFlags.
    uint32_t flags;

    /// The name of the instrumenter.
    const char* name;

    /// The unique identifier for the instrumenter. A new version of the
    /// instrumenter must change the uuid.
    const char* uuid;

    /// The destructor for the instrumenter
    void( *finalize)(void* handle);

    /// This function is called after lifting and before code generation. This
    /// function may run optimization passes. It may return the old function or
    /// create a new one with changed semantics. In the second case the API must
    /// be identical and the old function must be deleted. This function must
    /// not add new LLVM functions to the module.
    LLVMValueRef( *instrument)(void* handle, LLVMValueRef function);
};

/// Configure the rewriter with a given configuration fill out the descriptor
/// structure. This function can add new global functions to the module. The
/// return value is passed to the virtual functions as first parameter.
void* instrew_init_instrumenter(const char* config, LLVMModuleRef mod,
                                struct InstrewDesc* out_desc);

#ifdef __cplusplus
}
#endif

#endif
