
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

    /// If not NULL, a call to this function (`void %fn(metadata fd_instr)`)
    /// gets inserted before a machine instruction. The end of the instruction
    /// in the LLVM-IR is either indicated by another call to this function or
    /// the end of the basic block.
    LLVMValueRef hook_instr;
    /// If not NULL, a call to this function (`void %fn(metadata fd_instrs)`)
    /// gets inserted at the beginning of a basic block. The end of the
    /// architectural basic block is either indicated by another call to this
    /// function or by the exit block, which can be identified by being ended
    /// with a `ret` instruction.
    LLVMValueRef hook_basic_block;
    /// If not NULL, a call to this function (`void %fn(i64 old, i64 new)`) gets
    /// inserted when the stack pointer is modified.
    LLVMValueRef hook_sp_write;
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
