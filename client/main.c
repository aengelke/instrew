
#include <common.h>
#include <elf.h>
#include <linux/fcntl.h>
#include <linux/mman.h>

#include <elf-loader.h>
#include <memory.h>
#include <rtld.h>
#include <state.h>
#include <translator.h>

#include "instrew-client-config.h"

#define PLATFORM_STRING "x86_64"
#define PAGESIZE ((size_t) 0x1000)



static int open_perfmap(void) {
    int pid = getpid();

    char filename[32];
    snprintf(filename, sizeof(filename), "/tmp/perf-%u.map", pid);

    return open(filename, O_CREAT|O_TRUNC|O_NOFOLLOW|O_WRONLY|O_CLOEXEC, 0600);
}

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
            return retval;

        retval = rtld_add_object(&state->rtld, addr, obj_base, obj_size, &func);
        if (retval < 0)
            return retval;

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

static int
cdecl_dispatch(struct State* state) {
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
            if (UNLIKELY(BAD_ADDR(func)))
                return (int) func;

            // Store in TLB
            quick_tlb[hash][0] = addr;
            quick_tlb[hash][1] = func;
        }

        void(* func_p)(void*);
        *((void**) &func_p) = (void*) func;
        func_p(cpu_state);
    }
}

static int
__attribute__((noinline))
fast_dispatch(struct State* state) {
#ifdef __x86_64__
    int retval = 0;

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
    if (UNLIKELY(BAD_ADDR(func))) {
        retval = func;
        goto out;
    }

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
            "mov 8(%%r14), %%r14;" // Load new addr from quick_tlb, keep rbx
            "call *%%r14;" // Old RIP and new RIP stored in rbx
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

out:
    return retval;
#else
    puts("note: hhvm_dispatch only supported on x86-64");
    (void) state;
    return -EOPNOTSUPP;
#endif
}

int main(int argc, char** argv) {
    int i;
    int retval;

    BinaryInfo info = {0};

    uint8_t cpu_state_buffer[0x40 + 0x400] __attribute__((aligned(64))) = {0};

    // Initialize state.
    struct State state = {0};
    state.cpu = cpu_state_buffer + 0x40;
    state.config.perfmap_fd = -1;
    state.config.opt_level = 1;
    state.config.opt_unsafe_callret = true;

    STATE_FROM_CPU_STATE(state.cpu) = &state;

    const char* server_path = INSTREW_DEFAULT_SERVER;
    const char* tool_path = "none";
    const char* tool_config = "";

    while (argc > 1) {
        --argc;
        char* arg = *(++argv);
        if (strcmp(arg, "-perfmap") == 0) {
            state.config.perfmap_fd = open_perfmap();
        } else if (strcmp(arg, "-trace") == 0) {
            state.config.print_trace = true;
        } else if (strcmp(arg, "-regs") == 0) {
            state.config.print_regs = true;
        } else if (strcmp(arg, "-profile") == 0) {
            state.config.profile_rewriting = true;
        } else if (strcmp(arg, "-opt") == 0) {
            state.config.opt_level = 2;
        } else if (strcmp(arg, "-safe") == 0) {
            state.config.opt_unsafe_callret = false;
        } else if (strcmp(arg, "-time-passes") == 0) {
            state.config.profile_llvm_passes = true;
        } else if (strcmp(arg, "-v") == 0) {
            state.config.verbose = true;
        } else if (strcmp(arg, "-ddump-objects") == 0) {
            state.config.d_dump_objects = true;
        } else if (strncmp(arg, "-server=", 8) == 0) {
            server_path = arg + 8;
        } else if (strncmp(arg, "-tool=", 6) == 0) {
            tool_path = arg + 6;
            char* colon = strchr(tool_path, ':');
            if (colon != NULL) {
                *colon = '\0';
                tool_config = colon + 1;
            }
        } else {
            break;
        }
    }

    if (argc < 1) {
        puts("usage: [OPTIONS] EXECUTABLE [ARGS...]");
        return 1;
    }

    retval = mem_init();
    if (retval < 0) {
        puts("error: failed to initialize heap");
        return retval;
    }

    if (server_path == NULL) {
        puts("error: no server specified, use -server=<path>");
        return 1;
    }

    if (state.config.verbose)
        printf("note: using server %s\n", server_path);

    retval = translator_init(&state.translator, server_path);
    if (retval != 0) {
        puts("error: could not spawn rewriting server");
        return retval;
    }

    bool hhvm_dispatch = false;

    retval = translator_config_begin(&state.translator);
    retval = translator_config_tool(&state.translator, tool_path);
    retval = translator_config_tool_config(&state.translator, tool_config);
    retval = translator_config_opt_pass_pipeline(&state.translator, state.config.opt_level);
    retval = translator_config_opt_code_gen(&state.translator, 3);
    retval = translator_config_opt_unsafe_callret(&state.translator, state.config.opt_unsafe_callret);
    retval = translator_config_debug_profile_server(&state.translator, state.config.profile_rewriting);
    retval = translator_config_debug_dump_ir(&state.translator, state.config.verbose);
    retval = translator_config_debug_dump_objects(&state.translator, state.config.d_dump_objects);
    retval = translator_config_debug_time_passes(&state.translator, state.config.profile_llvm_passes);
#ifdef __x86_64__
    retval |= translator_config_triple(&state.translator, "x86_64-unknown-linux-gnu");
    retval |= translator_config_cpu(&state.translator, "x86-64");
    retval |= translator_config_cpu_features(&state.translator, "+nopl");
    retval |= translator_config_native_segments(&state.translator, true);
    state.config.native_segment_regs = true; // TODO: fetch from S_INIT
    retval |= translator_config_hhvm(&state.translator, true);
    hhvm_dispatch = true; // TODO: fetch from S_INIT
#endif
    retval = translator_config_end(&state.translator);
    if (retval != 0) {
        puts("error: could not configure tool");
        return 1;
    }

    retval = load_elf_binary(argv[0], &info);
    if (retval != 0) {
        puts("error: could not load file");
        return retval;
    }

    // TODO: don't hardcode stack size
    // TODO: support execstack
#define STACK_SIZE 0x1000000
    int stack_prot = PROT_READ|PROT_WRITE;
    int stack_flags = MAP_PRIVATE|MAP_ANONYMOUS|MAP_GROWSDOWN|MAP_STACK;
    void* stack = mmap(NULL, STACK_SIZE, stack_prot, stack_flags, -1, 0);
    if (BAD_ADDR(stack)) {
        puts("error: failed to allocate stack");
        retval = (int) (uintptr_t) stack;
        goto out;
    }

    //memset(stack, 0xcc, STACK_SIZE);
    mprotect(stack, 0x1000, PROT_NONE);

    // Initialize stack according to ABI
    size_t* stack_top = (size_t*) ((uint8_t*) stack + STACK_SIZE);

    // Stack alignment
    if (argc & 1)
        --stack_top;

    // Set auxiliary values
    *(--stack_top) = 0; // Null auxiliary vector entry

    *(--stack_top) = (uintptr_t) info.entry; *(--stack_top) = AT_ENTRY;
    *(--stack_top) = (uintptr_t) info.phdr; *(--stack_top) = AT_PHDR;
    *(--stack_top) = info.phent; *(--stack_top) = AT_PHENT;
    *(--stack_top) = info.phnum; *(--stack_top) = AT_PHNUM;
    *(--stack_top) = (size_t) PLATFORM_STRING; *(--stack_top) = AT_PLATFORM;
    *(--stack_top) = getauxval(AT_RANDOM); *(--stack_top) = AT_RANDOM;
    *(--stack_top) = getauxval(AT_UID); *(--stack_top) = AT_UID;
    *(--stack_top) = getauxval(AT_EUID); *(--stack_top) = AT_EUID;
    *(--stack_top) = getauxval(AT_GID); *(--stack_top) = AT_GID;
    *(--stack_top) = getauxval(AT_EGID); *(--stack_top) = AT_EGID;
    *(--stack_top) = getauxval(AT_CLKTCK); *(--stack_top) = AT_CLKTCK;
    *(--stack_top) = PAGESIZE; *(--stack_top) = AT_PAGESZ;
    *(--stack_top) = 0x8001; *(--stack_top) = AT_HWCAP;
    *(--stack_top) = 0; *(--stack_top) = AT_HWCAP2;
    *(--stack_top) = 0; *(--stack_top) = AT_SECURE;

    *(--stack_top) = 0; // End of environment pointers
    // TODO: environment
    *(--stack_top) = 0; // End of argument pointers
    stack_top -= argc;
    for (i = 0; i < argc; i++)
        stack_top[i] = (size_t) argv[i];
    *(--stack_top) = argc; // Argument Count

    // TODO: align stack to 16 bytes

    *((uint64_t*) state.cpu) = (uint64_t) info.entry;
    *((uint64_t*) state.cpu + 5) = (uint64_t) stack_top;

    retval = rtld_init(&state.rtld);
    if (retval < 0) {
        puts("error: could not initialize runtime linker");
        return retval;
    }

    if (hhvm_dispatch)
        retval = fast_dispatch(&state);
    else
        retval = cdecl_dispatch(&state);

out:
    return retval;
}
