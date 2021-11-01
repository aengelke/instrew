
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

    uint8_t cpu_state_buffer[0x40 + 0x400] __attribute__((aligned(64))) = {0};

    // Initialize state.
    struct State state = {0};
    state.cpu = cpu_state_buffer + 0x40;
    state.config.perfmap_fd = -1;


    STATE_FROM_CPU_STATE(state.cpu) = &state;

    const char* server_path = INSTREW_DEFAULT_SERVER;
    const char* tool_path = "none";
    const char* tool_config = "";
    int sc_opt_level = 1;
    bool sc_profile_rewriting = false;
    bool sc_profile_llvm_passes = false;
    bool sc_opt_full_facets = true;
    bool sc_opt_unsafe_callret = true;
    bool sc_opt_callret_lifting = true;
    bool sc_verbose = false;
    bool sc_d_dump_objects = false;
    int sc_callconv = 0;
#ifdef __x86_64__
    sc_callconv = 2;
#endif

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
            sc_profile_rewriting = true;
            state.config.profile_rewriting = true;
        } else if (strcmp(arg, "-opt") == 0) {
            sc_opt_level = 2;
        } else if (strcmp(arg, "-nofacets") == 0) {
            sc_opt_full_facets = false;
        } else if (strcmp(arg, "-safe") == 0) {
            sc_opt_unsafe_callret = false;
        } else if (strcmp(arg, "-time-passes") == 0) {
            sc_profile_llvm_passes = true;
        } else if (strcmp(arg, "-v") == 0) {
            sc_verbose = true;
        } else if (strcmp(arg, "-ddump-objects") == 0) {
            sc_d_dump_objects = true;
        } else if (strncmp(arg, "-cconv=", 7) == 0) {
            if (strcmp(arg + 7, "c") == 0) {
                sc_callconv = 0;
            } else if (strcmp(arg + 7, "hhvmrl") == 0) {
                sc_callconv = 1;
            } else if (strcmp(arg + 7, "hhvm") == 0) {
                sc_callconv = 2;
            } else if (strcmp(arg + 7, "rc") == 0) {
                sc_callconv = 3;
            } else {
                dprintf(2, "unknown calling convention\n");
                return 1;
            }
        } else if (strcmp(arg, "-nocallret") == 0) {
            sc_opt_callret_lifting = false;
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

    // Load binary first, because we need to know the architecture.
    retval = load_elf_binary(argv[0], &info);
    if (retval != 0) {
        puts("error: could not load file");
        return retval;
    }

    if (server_path == NULL) {
        puts("error: no server specified, use -server=<path>");
        return 1;
    }

    if (sc_verbose)
        printf("note: using server %s\n", server_path);

    retval = translator_config_init(&state.tsc, server_path);
    retval |= translator_config_tool(&state.tsc, tool_path);
    retval |= translator_config_tool_config(&state.tsc, tool_config);
    retval |= translator_config_opt_pass_pipeline(&state.tsc, sc_opt_level);
    retval |= translator_config_opt_code_gen(&state.tsc, 3);
    retval |= translator_config_opt_full_facets(&state.tsc, sc_opt_full_facets);
    retval |= translator_config_opt_unsafe_callret(&state.tsc, sc_opt_unsafe_callret);
    retval |= translator_config_opt_callret_lifting(&state.tsc, sc_opt_callret_lifting);
    retval |= translator_config_debug_profile_server(&state.tsc, sc_profile_rewriting);
    retval |= translator_config_debug_dump_ir(&state.tsc, sc_verbose);
    retval |= translator_config_debug_dump_objects(&state.tsc, sc_d_dump_objects);
    retval |= translator_config_debug_time_passes(&state.tsc, sc_profile_llvm_passes);
    retval |= translator_config_guest_arch(&state.tsc, info.machine);
    retval |= translator_config_opt_callconv(&state.tsc, sc_callconv);
#ifdef __x86_64__
    retval |= translator_config_triple(&state.tsc, "x86_64-unknown-linux-gnu");
    retval |= translator_config_cpu(&state.tsc, "x86-64");
    retval |= translator_config_cpu_features(&state.tsc, "+nopl");
    retval |= translator_config_native_segments(&state.tsc, true);
#elif defined(__aarch64__)
    retval |= translator_config_triple(&state.tsc, "aarch64-unknown-linux-gnu");
#else
#error "Unsupported architecture!"
#endif
    if (retval != 0) {
        puts("error: could not setup configuration");
        return 1;
    }

    retval = translator_init(&state.translator, &state.tsc);
    if (retval != 0) {
        puts("error: could not spawn rewriting server");
        return retval;
    }

    retval = translator_config_fetch(&state.translator, &state.tc);
    if (retval != 0) {
        puts("error: could not fetch client configuration");
        return 1;
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
    *(--stack_top) = getauxval(AT_PAGESZ); *(--stack_top) = AT_PAGESZ;
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
    if (info.machine == EM_X86_64) {
        *((uint64_t*) state.cpu + 5) = (uint64_t) stack_top;
    } else if (info.machine == EM_RISCV) {
        *((uint64_t*) state.cpu + 3) = (uint64_t) stack_top;
    } else {
        puts("error: unsupported architecture");
        return -ENOEXEC;
    }

    retval = rtld_init(&state.rtld, state.config.perfmap_fd);
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
    retval = rtld_add_object(&state.rtld, initobj, initobj_size);
    if (retval < 0) {
        puts("error: could not get initial object");
        return retval;
    }

    dispatch_loop(&state);

out:
    return retval;
}
