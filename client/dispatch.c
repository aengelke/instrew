
#include <common.h>

#include <dispatch.h>

#include <elf.h>

#include <dispatcher-info.h>
#include <memory.h>
#include <rtld.h>
#include <state.h>
#include <translator.h>


// Prototype to make compilers happy. This is used in the assembly HHVM
// dispatcher on x86-64 below.
uintptr_t resolve_func(struct CpuState*, uintptr_t, struct RtldPatchData*);

static void
print_trace(struct CpuState* cpu_state, uintptr_t addr) {
    uint64_t* cpu_regs = (uint64_t*) cpu_state->regdata;
    dprintf(2, "Trace 0x%lx\n", addr);
    if (cpu_state->state->config.print_regs) {
        dprintf(2, "RAX=%lx RBX=%lx RCX=%lx RDX=%lx\n", cpu_regs[1], cpu_regs[4], cpu_regs[2], cpu_regs[3]);
        dprintf(2, "RSI=%lx RDI=%lx RBP=%lx RSP=%lx\n", cpu_regs[7], cpu_regs[8], cpu_regs[6], cpu_regs[5]);
        dprintf(2, "R8 =%lx R9 =%lx R10=%lx R11=%lx\n", cpu_regs[9], cpu_regs[10], cpu_regs[11], cpu_regs[12]);
        dprintf(2, "R12=%lx R13=%lx R14=%lx R15=%lx\n", cpu_regs[13], cpu_regs[14], cpu_regs[15], cpu_regs[16]);
        dprintf(2, "RIP=%lx\n", addr);
        dprintf(2, "XMM0=%lx:%lx XMM1=%lx:%lx\n", cpu_regs[18], cpu_regs[19], cpu_regs[20], cpu_regs[21]);
        dprintf(2, "XMM2=%lx:%lx XMM3=%lx:%lx\n", cpu_regs[22], cpu_regs[23], cpu_regs[24], cpu_regs[25]);
        dprintf(2, "XMM4=%lx:%lx XMM5=%lx:%lx\n", cpu_regs[26], cpu_regs[27], cpu_regs[28], cpu_regs[29]);
        dprintf(2, "XMM6=%lx:%lx XMM7=%lx:%lx\n", cpu_regs[30], cpu_regs[31], cpu_regs[32], cpu_regs[33]);
    }
}

#define QUICK_TLB_BITS 10
#define QUICK_TLB_BITOFF 4 // must be either 1, 2, 3, or 4
#define QUICK_TLB_IDXSCALE (1 << (4-QUICK_TLB_BITOFF))
#define QUICK_TLB_HASH(addr) (((addr) >> QUICK_TLB_BITOFF) & ((1 << QUICK_TLB_BITS) - 1))

uintptr_t
resolve_func(struct CpuState* cpu_state, uintptr_t addr,
             struct RtldPatchData* patch_data) {
    struct State* state = cpu_state->state;

    void* func;
    int retval = rtld_resolve(&state->rtld, addr, &func);
    if (UNLIKELY(retval < 0)) {
        struct timespec start_time;
        struct timespec end_time;
        if (UNLIKELY(state->config.profile_rewriting))
            clock_gettime(CLOCK_MONOTONIC, &start_time);

        void* obj_base;
        size_t obj_size;
        retval = translator_get(&state->translator, addr, &obj_base, &obj_size);
        if (retval < 0)
            goto error;

        retval = rtld_add_object(&state->rtld, obj_base, obj_size);
        if (retval < 0)
            goto error;
        retval = rtld_resolve(&state->rtld, addr, &func);
        if (retval < 0)
            goto error;

        if (UNLIKELY(state->config.profile_rewriting)) {
            clock_gettime(CLOCK_MONOTONIC, &end_time);
            size_t time_ns = (end_time.tv_sec - start_time.tv_sec) * 1000000000
                             + (end_time.tv_nsec - start_time.tv_nsec);
            state->rew_time += time_ns;
        }
    }

    // If we want a trace, don't update quick TLB. This forces a full resolve on
    // every dispatch, yielding a complete trace. Tracing is slow anyway, so we
    // don't care about performance when tracing is active.
    if (LIKELY(!state->config.print_trace)) {
        // If possible, patch code which caused us to get here.
        rtld_patch(patch_data, func);

        // Update quick TLB
        uintptr_t hash = QUICK_TLB_HASH(addr);
        cpu_state->quick_tlb[hash][0] = addr;
        cpu_state->quick_tlb[hash][1] = (uintptr_t) func;
    } else {
        print_trace(cpu_state, addr);
    }

    return (uintptr_t) func;

error:
    dprintf(2, "error resolving address %lx: %u\n", addr, -retval);
    _exit(retval);
}

// Used for PLT.
void dispatch_cdecl(uint64_t*);

inline void dispatch_cdecl(uint64_t* cpu_regs) {
    struct CpuState* cpu_state = CPU_STATE_FROM_REGS(cpu_regs);

    uintptr_t addr = cpu_regs[0];
    uintptr_t hash = QUICK_TLB_HASH(addr);

    uintptr_t func = cpu_state->quick_tlb[hash][1];
    if (UNLIKELY(cpu_state->quick_tlb[hash][0] != addr))
        func = resolve_func(cpu_state, addr, NULL);

    void(* func_p)(void*);
    *((void**) &func_p) = (void*) func;
    func_p(cpu_regs);
}

static void
dispatch_cdecl_loop(uint64_t* cpu_regs) {
    while (true)
        dispatch_cdecl(cpu_regs);
}

#ifdef __x86_64__

__attribute__((noreturn)) extern void dispatch_hhvm(uint64_t* cpu_state);
__attribute__((noreturn)) extern void dispatch_regcall_loop(uint64_t* cpu_state);
void dispatch_regcall();
void dispatch_regcall_fullresolve();

#define QUICK_TLB_OFFSET_ASM(dest_reg, addr_reg) \
        lea dest_reg, [addr_reg * 4]; \
        and dest_reg, ((1 << QUICK_TLB_BITS) - 1) << (2 + QUICK_TLB_BITOFF);

ASM_BLOCK(
    .intel_syntax noprefix;

    .align 16;
    .global dispatch_regcall;
    .type dispatch_regcall, @function;
dispatch_regcall:
    mov r11, rax;
    and r11, ((1 << QUICK_TLB_BITS) - 1) << QUICK_TLB_BITOFF;
    cmp rax, [r12 + QUICK_TLB_IDXSCALE*r11 - CPU_STATE_REGDATA_OFFSET + CPU_STATE_QTLB_OFFSET];
    jne 1f;
    jmp [r12 + QUICK_TLB_IDXSCALE*r11 - CPU_STATE_REGDATA_OFFSET + CPU_STATE_QTLB_OFFSET + 8];
    ud2;
1:  xor r11, r11; // zero patch data
    jmp dispatch_regcall_fullresolve;
    .size dispatch_regcall, .-dispatch_regcall;

    .align 16;
    .type dispatch_regcall_loop, @function;
dispatch_regcall_loop:
    push rax;
    mov r12, rdi; // cpu_state
    mov rax, [r12]; // addr
    mov r8, [r12+0x28]; // rsp
    xor edi, edi; // atexit handler
    jmp 2f;

    .align 16;
1:  call [r12 + QUICK_TLB_IDXSCALE*r11 - CPU_STATE_REGDATA_OFFSET + CPU_STATE_QTLB_OFFSET + 8];
2:  mov r11, rax;
    and r11, ((1 << QUICK_TLB_BITS) - 1) << QUICK_TLB_BITOFF;
    cmp rax, [r12 + QUICK_TLB_IDXSCALE*r11 - CPU_STATE_REGDATA_OFFSET + CPU_STATE_QTLB_OFFSET];
    je 1b;

    xor r11, r11; // zero patch data
    call dispatch_regcall_fullresolve;
    jmp 2b;
    .size dispatch_regcall_loop, .-dispatch_regcall_loop;

    .align 16;
    .type dispatch_regcall_fullresolve, @function;
dispatch_regcall_fullresolve:
    // Save all cdecl caller-saved registers.
    push rax;
    push rcx;
    push rdx;
    push rsi;
    push rdi;
    push r8;
    push r9;
    push r10;
    push r11; // for alignment
    sub rsp, 16 * 16;
    movaps [rsp + 16*0], xmm0;
    movaps [rsp + 16*1], xmm1;
    movaps [rsp + 16*2], xmm2;
    movaps [rsp + 16*3], xmm3;
    movaps [rsp + 16*4], xmm4;
    movaps [rsp + 16*5], xmm5;
    movaps [rsp + 16*6], xmm6;
    movaps [rsp + 16*7], xmm7;
    movaps [rsp + 16*8], xmm8;
    movaps [rsp + 16*9], xmm9;
    movaps [rsp + 16*10], xmm10;
    movaps [rsp + 16*11], xmm11;
    movaps [rsp + 16*12], xmm12;
    movaps [rsp + 16*13], xmm13;
    movaps [rsp + 16*14], xmm14;
    movaps [rsp + 16*15], xmm15;
    mov rdi, [r12 - CPU_STATE_REGDATA_OFFSET]; // cpu_state
    mov rsi, rax; // addr
    mov rdx, r11; // patch data
    call resolve_func;
    // pop r11;
    movaps xmm0, [rsp + 16*0];
    movaps xmm1, [rsp + 16*1];
    movaps xmm2, [rsp + 16*2];
    movaps xmm3, [rsp + 16*3];
    movaps xmm4, [rsp + 16*4];
    movaps xmm5, [rsp + 16*5];
    movaps xmm6, [rsp + 16*6];
    movaps xmm7, [rsp + 16*7];
    movaps xmm8, [rsp + 16*8];
    movaps xmm9, [rsp + 16*9];
    movaps xmm10, [rsp + 16*10];
    movaps xmm11, [rsp + 16*11];
    movaps xmm12, [rsp + 16*12];
    movaps xmm13, [rsp + 16*13];
    movaps xmm14, [rsp + 16*14];
    movaps xmm15, [rsp + 16*15];
    add rsp, 8 + 16*16;
    mov r11, rax;
    pop r10;
    pop r9;
    pop r8;
    pop rdi;
    pop rsi;
    pop rdx;
    pop rcx;
    pop rax;
    jmp r11;
    .size dispatch_regcall_fullresolve, .-dispatch_regcall_fullresolve;

    // Stores result in r14, preserves all other registers
    .align 16;
    .type dispatch_hhvm_resolve, @function;
dispatch_hhvm_resolve: // stack alignment: hhvm
    // Save all cdecl caller-saved registers.
    push rax; // For alignment
    push rax;
    push rcx;
    push rdx;
    push rsi;
    push rdi;
    push r8;
    push r9;
    push r10;
    push r11;
    mov rdi, [r12 - CPU_STATE_REGDATA_OFFSET]; // cpu_state
    mov rsi, rbx; // addr
    xor edx, edx; // patch data
    call resolve_func;
    mov r14, rax; // return value
    // Restore callee-saved registers.
    pop r11;
    pop r10;
    pop r9;
    pop r8;
    pop rdi;
    pop rsi;
    pop rdx;
    pop rcx;
    pop rax;
    pop rax;
    ret;
    .size dispatch_hhvm_resolve, .-dispatch_hhvm_resolve;

    .align 16;
    .global dispatch_hhvm_tail;
    .type dispatch_hhvm_tail, @function;
dispatch_hhvm_tail: // stack alignment: cdecl
    mov r14, rbx;
    and r14, ((1 << QUICK_TLB_BITS) - 1) << QUICK_TLB_BITOFF;
    cmp rbx, [r12 + QUICK_TLB_IDXSCALE*r14 - CPU_STATE_REGDATA_OFFSET + CPU_STATE_QTLB_OFFSET];
    jne 1f;
    jmp [r12 + QUICK_TLB_IDXSCALE*r14 - CPU_STATE_REGDATA_OFFSET + CPU_STATE_QTLB_OFFSET + 8];
    .align 16;
1:  push rax; // for stack alignment
    call dispatch_hhvm_resolve;
    pop rax;
    jmp r14;
    .size dispatch_hhvm_tail, .-dispatch_hhvm_tail;

    .align 16;
    .global dispatch_hhvm_call;
    .type dispatch_hhvm_call, @function;
dispatch_hhvm_call: // stack alignment: hhvm
    mov r14, rbx;
    and r14, ((1 << QUICK_TLB_BITS) - 1) << QUICK_TLB_BITOFF;
    cmp rbx, [r12 + QUICK_TLB_IDXSCALE*r14 - CPU_STATE_REGDATA_OFFSET + CPU_STATE_QTLB_OFFSET];
    jne 1f;
    call [r12 + QUICK_TLB_IDXSCALE*r14 - CPU_STATE_REGDATA_OFFSET + CPU_STATE_QTLB_OFFSET + 8];
    ret;
    .align 16;
1:  call dispatch_hhvm_resolve;
    call r14;
    ret;
    .size dispatch_hhvm_call, .-dispatch_hhvm_call;

    .align 16;
    .global dispatch_hhvm;
    .type dispatch_hhvm, @function;
dispatch_hhvm:
    mov r12, rdi; // cpu_regs
    // Load HHVM registers
    mov rbx, [r12 + 0 * 8];
    mov rax, [r12 + 1 * 8];
    mov rcx, [r12 + 2 * 8];
    mov rdx, [r12 + 3 * 8];
    mov rbp, [r12 + 4 * 8];
    mov r15, [r12 + 5 * 8];
    mov r13, [r12 + 6 * 8];
    mov rsi, [r12 + 7 * 8];
    mov rdi, [r12 + 8 * 8];
    mov r8, [r12 + 9 * 8];
    mov r9, [r12 + 10 * 8];
    mov r10, [r12 + 11 * 8];
    mov r11, [r12 + 12 * 8];

    jmp 4f;

    .align 16;
    // This is the quick_tlb hot loop.
2:  call [r12 + QUICK_TLB_IDXSCALE*r14 - CPU_STATE_REGDATA_OFFSET + CPU_STATE_QTLB_OFFSET + 8];
3:  mov r14, rbx;
    and r14, ((1 << QUICK_TLB_BITS) - 1) << QUICK_TLB_BITOFF;
    cmp rbx, [r12 + QUICK_TLB_IDXSCALE*r14 - CPU_STATE_REGDATA_OFFSET + CPU_STATE_QTLB_OFFSET];
    je 2b;

    // This code isn't exactly cold, but should be executed not that often.
    // If we don't have addr in the quick_tlb, do a full resolve.
4:  call dispatch_hhvm_resolve;
    call r14; // can't deduplicate call because we don't get the qtlb pointer.
    jmp 3b;
    .size dispatch_hhvm, .-dispatch_hhvm;

    .att_syntax;
);

#endif // defined(__x86_64__)

const struct DispatcherInfo*
dispatch_get(struct State* state) {
    static const struct DispatcherInfo infos[] = {
        [0] = {
            .loop_func = dispatch_cdecl_loop,
            .quick_dispatch_func = dispatch_cdecl,
            .full_dispatch_func = dispatch_cdecl,
            .patch_data_reg = 6, // rsi
        },
#if defined(__x86_64__)
        [1] = {
            .loop_func = dispatch_hhvm,
            .quick_dispatch_func = NULL, // HHVM doesn't support this...
            .full_dispatch_func = NULL,
            .patch_data_reg = 14, // r14
        },
        [2] = {
            .loop_func = dispatch_regcall_loop,
            .quick_dispatch_func = dispatch_regcall,
            .full_dispatch_func = dispatch_regcall_fullresolve,
            .patch_data_reg = 11, // r11
        },
#endif // defined(__x86_64__)
    };

    unsigned callconv = state->tc.tc_callconv;
    if (callconv < sizeof infos / sizeof infos[0])
        return &infos[callconv];
    return NULL;
}
