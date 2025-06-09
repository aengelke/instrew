PLT_ENTRY("syscall", emulate_syscall) // emulate.c
PLT_ENTRY("syscall_rv64", emulate_rv64_syscall) // emulate.c
PLT_ENTRY("syscall_aarch64", emulate_aarch64_syscall) // emulate.c
PLT_ENTRY("cpuid", emulate_cpuid) // emulate.c
PLT_ENTRY("__divti3", __divti3) // libgcc
PLT_ENTRY("__udivti3", __udivti3) // libgcc
PLT_ENTRY("__modti3", __modti3) // libgcc
PLT_ENTRY("__umodti3", __umodti3) // libgcc
#if defined(__riscv)
PLT_ENTRY("__muldi3", __muldi3) // libgcc
PLT_ENTRY("__multi3", __multi3) // libgcc
PLT_ENTRY("__umoddi3", __umoddi3) // libgcc
PLT_ENTRY("__udivdi3", __udivdi3) // libgcc
PLT_ENTRY("__divdi3", __divdi3) // libgcc
PLT_ENTRY("__moddi3", __moddi3) // libgcc
PLT_ENTRY("__atomic_fetch_add_4", __atomic_fetch_add_4)
PLT_ENTRY("__atomic_fetch_add_8", __atomic_fetch_add_8)
PLT_ENTRY("__atomic_fetch_sub_4", __atomic_fetch_sub_4)
PLT_ENTRY("__atomic_fetch_sub_8", __atomic_fetch_sub_8)
PLT_ENTRY("__atomic_fetch_or_4", __atomic_fetch_or_4)
PLT_ENTRY("__atomic_fetch_or_8", __atomic_fetch_or_8)
PLT_ENTRY("__atomic_exchange_4", __atomic_exchange_4)
PLT_ENTRY("__atomic_exchange_8", __atomic_exchange_8)
PLT_ENTRY("__atomic_compare_exchange_4", __atomic_compare_exchange_4)
PLT_ENTRY("__atomic_compare_exchange_8", __atomic_compare_exchange_8)
#endif //defined(__riscv)
PLT_ENTRY("floorf", floorf) // math.c
PLT_ENTRY("floor", floor) // math.c
PLT_ENTRY("ceilf", ceilf) // math.c
PLT_ENTRY("ceil", ceil) // math.c
PLT_ENTRY("roundf", roundf) // math.c
PLT_ENTRY("round", round) // math.c
PLT_ENTRY("truncf", truncf) // math.c
PLT_ENTRY("trunc", trunc) // math.c
PLT_ENTRY("fmaf", fmaf) // math.c
PLT_ENTRY("fma", fma) // math.c
PLT_ENTRY("instrew_tail_cdecl", dispatch_cdecl) // dispatch.c
PLT_ENTRY("instrew_call_cdecl", dispatch_cdecl) // dispatch.c
#if defined(__x86_64__)
PLT_ENTRY("instrew_tail_hhvm", dispatch_hhvm_tail) // dispatch.c
PLT_ENTRY("instrew_call_hhvm", dispatch_hhvm_tail) // dispatch.c
#endif // defined(__x86_64__)
PLT_ENTRY("memset", memset) // minilibc.c
PLT_ENTRY("dprintf", dprintf) // minilibc.c
