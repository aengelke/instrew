
#include <common.h>
#include <elf.h>
#include <linux/fcntl.h>
#include <linux/mman.h>

#include <dispatch.h>
#include <elf-loader.h>
#include <memory.h>
#include <rtld.h>
#include <state.h>
#include <translator.h>

#include "instrew-client-config.h"

#define PLATFORM_STRING "x86_64"


static int open_perfmap(void) {
    int pid = getpid();

    char filename[32];
    snprintf(filename, sizeof(filename), "/tmp/perf-%u.map", pid);

    return open(filename, O_CREAT|O_TRUNC|O_NOFOLLOW|O_WRONLY|O_CLOEXEC, 0600);
}

int main(int argc, char** argv) {
    int i;
    int retval;

    BinaryInfo info = {0};

    // Initialize state.
    struct State state = {0};
    state.config.perfmap_fd = -1;

    const char* server_argv[64] = { INSTREW_DEFAULT_SERVER };
    unsigned server_argc = 1;
    unsigned server_maxargs = sizeof(server_argv) / sizeof(server_argv[0]) - 2;

    bool delay_server = false;

    while (argc > 1) {
        --argc;
        char* arg = *(++argv);
        if (arg[0] != '-' || !strcmp(arg, "--"))
            break;

        if (strncmp(arg, "-C", 2) == 0) {
            arg += 2;
            do {
                char* current = arg;
                arg = strchr(arg, ',');
                if (arg)
                    *arg++ = 0;

                if (!strcmp(current, "perfmap")) {
                    state.config.perfmap_fd = open_perfmap();
                } else if (!strcmp(current, "trace")) {
                    state.config.print_trace = true;
                } else if (!strcmp(current, "regs")) {
                    state.config.print_regs = true;
                } else if (!strcmp(current, "profile")) {
                    state.config.profile_rewriting = true;
                } else if (!strcmp(current, "delay")) {
                    delay_server = true;
                } else {
                    dprintf(2, "ignoring unknown client arg %s\n", current);
                }
            } while (arg);
        } else if (strncmp(arg, "-server=", 8) == 0) {
            server_argv[0] = arg + 8;
        } else {
            if (server_argc >= server_maxargs) {
                puts("error: too many server arguments");
                return -ENOSPC;
            }
            server_argv[server_argc++] = arg;
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

    // Load binary first, because we need to know the architecture.
    retval = load_elf_binary(argv[0], &info);
    if (retval != 0) {
        puts("error: could not load file");
        return retval;
    }

    if (server_argv[0] == NULL) {
        puts("error: no server specified, use -server=<path>");
        return 1;
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

    retval = translator_init(&state.translator, server_argv, &state.tsc);
    if (retval != 0) {
        puts("error: could not spawn rewriting server");
        return retval;
    }

    // Add a short delay to allow attaching a debugger to the server
    if (delay_server)
        nanosleep(&(struct timespec) { 1, 0 }, NULL);

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
    size_t* stack_top = (size_t*) ((uint8_t*) stack + STACK_SIZE);

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

    retval = rtld_init(&state.rtld, state.config.perfmap_fd, disp_info);
    if (retval < 0) {
        puts("error: could not initialize runtime linker");
        return retval;
    }

    void* initobj;
    size_t initobj_size;
    retval = translator_get_object(&state.translator, &initobj, &initobj_size);
    if (retval < 0) {
        puts("error: could not get initial object");
        return retval;
    }
    if (initobj_size > 0) {
        retval = rtld_add_object(&state.rtld, initobj, initobj_size);
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

    uint64_t* cpu_regs = (uint64_t*) &cpu_state->regdata;

    cpu_regs[0] = (uintptr_t) info.exec_entry;
    if (state.tsc.tsc_guest_arch == EM_X86_64) {
        cpu_regs[5] = (uintptr_t) stack_top;
    } else if (state.tsc.tsc_guest_arch == EM_RISCV) {
        cpu_regs[3] = (uintptr_t) stack_top;
    } else {
        // well... -.-
        puts("error: unsupported architecture");
        return -ENOEXEC;
    }

    disp_info->loop_func(cpu_regs);

out:
    return retval;
}
