
#include <common.h>

#include <dispatch.h>

#include <rtld.h>
#include <state.h>
#include <translator.h>


// Prototype to make compilers happy. This is used in the assembly HHVM
// dispatcher on x86-64 below.
uintptr_t resolve_func(struct State*, uintptr_t);

uintptr_t
resolve_func(struct State* state, uintptr_t addr) {
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

    return (uintptr_t) func;

error:
    dprintf(2, "error resolving address %lx: %u\n", addr, -retval);
    _exit(retval);
}

#define QUICK_TLB_BITS 10
#define QUICK_TLB_HASH(addr) (((addr) >> 2) & ((1 << QUICK_TLB_BITS) - 1))

static void
print_trace(struct State* state, uintptr_t addr) {
    uint64_t* cpu_state = (uint64_t*) state->cpu;
    if (state->config.print_trace) {
        dprintf(2, "Trace 0x%lx\n", addr);
        if (state->config.print_regs) {
            dprintf(2, "RAX=%lx RBX=%lx RCX=%lx RDX=%lx\n", cpu_state[1], cpu_state[4], cpu_state[2], cpu_state[3]);
            dprintf(2, "RSI=%lx RDI=%lx RBP=%lx RSP=%lx\n", cpu_state[7], cpu_state[8], cpu_state[6], cpu_state[5]);
            dprintf(2, "R8 =%lx R9 =%lx R10=%lx R11=%lx\n", cpu_state[9], cpu_state[10], cpu_state[11], cpu_state[12]);
            dprintf(2, "R12=%lx R13=%lx R14=%lx R15=%lx\n", cpu_state[13], cpu_state[14], cpu_state[15], cpu_state[16]);
            dprintf(2, "RIP=%lx\n", addr);
            dprintf(2, "XMM0=%lx:%lx XMM1=%lx:%lx\n", cpu_state[18], cpu_state[19], cpu_state[20], cpu_state[21]);
            dprintf(2, "XMM2=%lx:%lx XMM3=%lx:%lx\n", cpu_state[22], cpu_state[23], cpu_state[24], cpu_state[25]);
            dprintf(2, "XMM4=%lx:%lx XMM5=%lx:%lx\n", cpu_state[26], cpu_state[27], cpu_state[28], cpu_state[29]);
            dprintf(2, "XMM6=%lx:%lx XMM7=%lx:%lx\n", cpu_state[30], cpu_state[31], cpu_state[32], cpu_state[33]);
        }
    }
}

// Used for PLT.
void dispatch_cdecl(uint64_t*);

inline void dispatch_cdecl(uint64_t* cpu_state) {
    struct State* state = STATE_FROM_CPU_STATE(cpu_state);
    uint64_t(* quick_tlb)[2] = QTLB_FROM_CPU_STATE(cpu_state);

    uintptr_t addr = cpu_state[0];
    uintptr_t hash = QUICK_TLB_HASH(addr);

    print_trace(state, addr);

    uintptr_t func = quick_tlb[hash][1];
    if (UNLIKELY(quick_tlb[hash][0] != addr)) {
        func = resolve_func(state, addr);

        // Store in TLB
        quick_tlb[hash][0] = addr;
        quick_tlb[hash][1] = func;
    }

    void(* func_p)(void*);
    *((void**) &func_p) = (void*) func;
    func_p(cpu_state);
}

#ifdef __x86_64__

__attribute__((noreturn)) extern void dispatch_hhvm(uint64_t* cpu_state);

#define QUICK_TLB_OFFSET_ASM(dest_reg, addr_reg) \
        lea dest_reg, [addr_reg * 4]; \
        and dest_reg, ((1 << QUICK_TLB_BITS) - 1) << 4;

ASM_BLOCK(
    .intel_syntax noprefix;

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
    mov rdi, [r12 - 0x08]; // state
    mov rsi, rbx; // addr
    call resolve_func;

    QUICK_TLB_OFFSET_ASM(rdx, rbx); // Compute quick_tlb hash to rdx
    add rdx, [r12 - 0x10]; // rdx = quick_tlb entry
    mov [rdx], rbx; // addr
    mov [rdx + 8], rax; // func
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
    QUICK_TLB_OFFSET_ASM(r14, rbx); // Compute quick_tlb hash to r14
    add r14, [r12 - 0x10]; // r14 = quick_tlb entry
    cmp rbx, [r14];
    jne 1f;
    jmp [r14 + 8];
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
    QUICK_TLB_OFFSET_ASM(r14, rbx); // Compute quick_tlb hash to r14
    add r14, [r12 - 0x10]; // r14 = quick_tlb entry
    cmp rbx, [r14];
    jne 1f;
    call [r14 + 8];
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
    mov r12, rdi; // cpu_state
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
2:  call [r14 + 8];
3:  QUICK_TLB_OFFSET_ASM(r14, rbx); // Compute quick_tlb hash to r14
    add r14, [r12 - 0x10]; // r14 = quick_tlb entry
    cmp rbx, [r14];
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

__attribute__((noreturn))
void dispatch_loop(struct State* state) {
    uint64_t quick_tlb[1 << QUICK_TLB_BITS][2] = {0};
    QTLB_FROM_CPU_STATE(state->cpu) = quick_tlb;

    switch (state->tc.tc_callconv) {
    case 0: {
        uint64_t* cpu_state = state->cpu;
        while (true)
            dispatch_cdecl(cpu_state);
    }
#if defined(__x86_64__)
    case 1:
        dispatch_hhvm(state->cpu);
#endif // defined(__x86_64__)
    default:
        puts("error: unsupported calling convention");
        _exit(-EOPNOTSUPP);
    }
}
