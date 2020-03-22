
#include <common.h>

#include <dispatch.h>

#include <rtld.h>
#include <state.h>
#include <translator.h>


static uintptr_t
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

        retval = rtld_add_object(&state->rtld, addr, obj_base, obj_size, &func);
        if (retval < 0)
            goto error;

        if (UNLIKELY(state->config.profile_rewriting)) {
            clock_gettime(CLOCK_MONOTONIC, &end_time);
            size_t time_ns = (end_time.tv_sec - start_time.tv_sec) * 1000000000
                             + (end_time.tv_nsec - start_time.tv_nsec);
            state->rew_time += time_ns;
        }

        if (UNLIKELY(state->config.perfmap_fd >= 0)) {
            dprintf(state->config.perfmap_fd, "%lx %lx src_%lx\n",
                    (uintptr_t) obj_base, obj_size, addr);
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

__attribute__((noreturn))
static void cdecl_dispatch(struct State* state) {
    uint64_t quick_tlb[1 << QUICK_TLB_BITS][2] = {0};
    uint64_t* cpu_state = (uint64_t*) state->cpu;

    while (true) {
        uintptr_t addr = cpu_state[0];
        uintptr_t hash = QUICK_TLB_HASH(addr);

        print_trace(state, addr);

        uintptr_t func;
        if (LIKELY(quick_tlb[hash][0] == addr)) {
            func = quick_tlb[hash][1];
        } else {
            func = resolve_func(state, addr);

            // Store in TLB
            quick_tlb[hash][0] = addr;
            quick_tlb[hash][1] = func;
        }

        void(* func_p)(void*);
        *((void**) &func_p) = (void*) func;
        func_p(cpu_state);
    }
}

#ifdef __x86_64__

__attribute__((noinline))
__attribute__((noreturn))
static void hhvm_dispatch(struct State* state) {
    uint64_t quick_tlb[1 << QUICK_TLB_BITS][2] = {0};

    uintptr_t addr;
    uintptr_t func;
    uintptr_t hash;

    uint64_t* cpu_state = (uint64_t*) state->cpu;
    addr = cpu_state[0];

resolve:
    if (state->config.print_trace)
        print_trace(state, addr);

    hash = QUICK_TLB_HASH(addr);
    func = resolve_func(state, addr);

    // Store in TLB
    quick_tlb[hash][0] = addr;
    quick_tlb[hash][1] = func;

    // Don't use TLB, so we get full traces.
    if (state->config.print_trace)
        quick_tlb[hash][0] = 0;

    register uintptr_t reg_r12 __asm__("r12") = (uintptr_t) cpu_state;
    register uintptr_t reg_r11 __asm__("r11") = (uintptr_t) quick_tlb;
    register uintptr_t reg_rbx __asm__("rbx") = addr;
    register uintptr_t reg_r14 __asm__("r14") = (uintptr_t) &quick_tlb[hash];
    register uint64_t guest_rax __asm__("rax") = cpu_state[1];
    register uint64_t guest_rcx __asm__("rcx") = cpu_state[2];
    register uint64_t guest_rdx __asm__("rdx") = cpu_state[3];
    register uint64_t guest_rbx __asm__("rbp") = cpu_state[4];
    register uint64_t guest_rsp __asm__("r15") = cpu_state[5];
    register uint64_t guest_rbp __asm__("r13") = cpu_state[6];
    register uint64_t guest_rsi __asm__("rsi") = cpu_state[7];
    register uint64_t guest_rdi __asm__("rdi") = cpu_state[8];
    register uint64_t guest_r8 __asm__("r8") = cpu_state[9];
    register uint64_t guest_r9 __asm__("r9") = cpu_state[10];
    register uint64_t guest_r10 __asm__("r10") = cpu_state[11];
    __asm__ volatile(
            "push %%r11;"
            "mov 0x60(%%r12), %%r11;" // Load guest r11
            ".align 16;"
        "1:"
            "call *8(%%r14);" // New RIP stored in rbx
            "lea (,%%rbx,4), %%r14;"
            "and %[quick_tlb_mask], %%r14;"
            "add (%%rsp), %%r14;" // r14 is now the pointer to the TLB entry
            "cmp %%rbx, (%%r14);"
            "je 1b;"

            "mov %%r11, 0x60(%%r12);" // Store guest r11
            "pop %%r11;"
        : "+r"(reg_rbx), "+r"(reg_r14),
          "+r"(guest_rax), "+r"(guest_rcx), "+r"(guest_rdx), "+r"(guest_rbx),
          "+r"(guest_rsp), "+r"(guest_rbp), "+r"(guest_rsi), "+r"(guest_rdi),
          "+r"(guest_r8), "+r"(guest_r9), "+r"(guest_r10)
        : "r"(reg_r11), "r"(reg_r12),
          [quick_tlb_mask] "i"(((1 << QUICK_TLB_BITS) - 1) << 4)
        : "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
          "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
          "cc", "memory"
    );

    addr = reg_rbx;
    cpu_state[1] = guest_rax;
    cpu_state[2] = guest_rcx;
    cpu_state[3] = guest_rdx;
    cpu_state[4] = guest_rbx;
    cpu_state[5] = guest_rsp;
    cpu_state[6] = guest_rbp;
    cpu_state[7] = guest_rsi;
    cpu_state[8] = guest_rdi;
    cpu_state[9] = guest_r8;
    cpu_state[10] = guest_r9;
    cpu_state[11] = guest_r10;

    goto resolve;
}

#endif // defined(__x86_64__)

__attribute__((noreturn))
void dispatch_loop(struct State* state) {
    if (state->config.hhvm) {
#if defined(__x86_64__)
        hhvm_dispatch(state);
#else // !defined(__x86_64__)
        puts("error: hhvm_dispatch only supported on x86-64");
        _exit(-EOPNOTSUPP);
#endif // defined(__x86_64__)
    } else {
        cdecl_dispatch(state);
    }
}
