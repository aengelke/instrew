
#include <common.h>
#include <elf.h>
#include <linux/fcntl.h>
#include <linux/mman.h>

#include <dispatch.h>
#include <elf-loader.h>
#include <emulate.h>
#include <memory.h>
#include <rtld.h>
#include <state.h>
#include <translator.h>

#define PLATFORM_STRING "x86_64"


int main(int argc, char** argv) {
    int i;
    int retval;

    BinaryInfo info = {0};

    // Initialize state.
    struct State state = {0};

    if (argc < 3) {
        puts("usage: CONFSTR EXECUTABLE [ARGS...]");
        return 1;
    }

    char* server_config = argv[1];
    argc -= 2;
    argv += 2;

    signal_init(&state);

    retval = mem_init();
    if (retval < 0) {
        puts("error: failed to initialize heap");
        return retval;
    }

    // Load binary first, because we need to know the architecture.
    retval = load_elf_binary(argv[0], &info);
    if (retval != 0) {
        puts("error: could not load file");
        return retval;
    }

    state.tsc.tsc_guest_arch = info.machine;
#ifdef __x86_64__
    state.tsc.tsc_host_arch = EM_X86_64;
    state.tsc.tsc_stack_alignment = 8;
#elif defined(__aarch64__)
    state.tsc.tsc_host_arch = EM_AARCH64;
#else
#error "Unsupported architecture!"
#endif

    retval = translator_init(&state.translator, server_config, &state.tsc);
    if (retval != 0) {
        puts("error: could not spawn rewriting server");
        return retval;
    }

    retval = translator_config_fetch(&state.translator, &state.tc);
    if (retval != 0) {
        puts("error: could not fetch client configuration");
        return 1;
    }

    const struct DispatcherInfo* disp_info = dispatch_get(&state);
    if (!disp_info || !disp_info->loop_func) {
        puts("error: unsupported calling convention");
        return -EOPNOTSUPP;
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
    size_t* stack_top = (size_t*) stack + STACK_SIZE/sizeof(size_t);

    // Stack alignment
    int envc = 0;
    while (environ[envc])
        envc++;
    stack_top -= (argc + envc) & 1; // auxv has even number of entries

    // Set auxiliary values
    *(--stack_top) = 0; // Null auxiliary vector entry

    *(--stack_top) = (uintptr_t) info.elf_entry; *(--stack_top) = AT_ENTRY;
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
    *(--stack_top) = getauxval(AT_PAGESZ); *(--stack_top) = AT_PAGESZ;
    *(--stack_top) = 0x8001; *(--stack_top) = AT_HWCAP;
    *(--stack_top) = 0; *(--stack_top) = AT_HWCAP2;
    *(--stack_top) = 0; *(--stack_top) = AT_SECURE;

    *(--stack_top) = 0; // End of environment pointers
    stack_top -= envc;
    for (i = 0; i < envc; i++)
        stack_top[i] = (uintptr_t) environ[i];
    *(--stack_top) = 0; // End of argument pointers
    stack_top -= argc;
    for (i = 0; i < argc; i++)
        stack_top[i] = (size_t) argv[i];
    *(--stack_top) = argc; // Argument Count

    retval = rtld_init(&state.rtld, disp_info);
    if (retval < 0) {
        puts("error: could not initialize runtime linker");
        return retval;
    }

    retval = rtld_perf_init(&state.rtld, state.tc.tc_perf);
    if (retval < 0) {
        puts("warning: could not initialize perf support");
    }

    void* initobj;
    size_t initobj_size;
    retval = translator_get_object(&state.translator, &initobj, &initobj_size);
    if (retval < 0) {
        puts("error: could not get initial object");
        return retval;
    }
    if (initobj_size > 0) {
        retval = rtld_add_object(&state.rtld, initobj, initobj_size, 0);
        if (retval < 0) {
            puts("error: could not get initial object");
            return retval;
        }
    }

    struct CpuState* cpu_state = mem_alloc_data(sizeof(struct CpuState),
                                                _Alignof(struct CpuState));
    // TODO: check for BAD_ADDR(cpu_state)
    memset(cpu_state, 0, sizeof(*cpu_state));
    cpu_state->self = cpu_state;
    cpu_state->state = &state;

    retval = set_thread_area(cpu_state);
    if (retval) {
        puts("error: could not set thread area");
        return retval;
    }

    uint64_t* cpu_regs = (uint64_t*) &cpu_state->regdata;

    cpu_regs[0] = (uintptr_t) info.exec_entry;
    if (state.tsc.tsc_guest_arch == EM_X86_64) {
        cpu_regs[5] = (uintptr_t) stack_top;
    } else if (state.tsc.tsc_guest_arch == EM_RISCV) {
        cpu_regs[3] = (uintptr_t) stack_top;
    } else if (state.tsc.tsc_guest_arch == EM_AARCH64) {
        cpu_regs[33] = (uintptr_t) stack_top;
    } else {
        // well... -.-
        puts("error: unsupported architecture");
        return -ENOEXEC;
    }

    disp_info->loop_func(cpu_regs);

out:
    return retval;
}
