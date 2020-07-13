
#include <common.h>

#include <emulate.h>

#include <asm/stat.h>

#include <state.h>



void
emulate_cpuid(uint64_t* cpu_state) {
    uint64_t rax = cpu_state[1], rcx = cpu_state[2];
    if (rax == 0) {
        cpu_state[1] = 7; // eax = max input value for basic CPUID
        cpu_state[2] = 0x6c65746e; // ecx = "ntel"
        cpu_state[3] = 0x49656e69; // edx = "ineI"
        cpu_state[4] = 0x756e6547; // ebx = "Genu"
    } else if (rax == 1) { // page 1 (feature information)
        cpu_state[1] = 0; // eax = <not implemented>
        cpu_state[2] = 0x00400000; // ecx = movbe
        cpu_state[3] = 0x07008040; // edx = pae+cmov+fxsr+sse+sse2
        cpu_state[4] = 0; // ebx = <not implemented>
    } else if (rax == 2) { // page 2 (TLB/cache/prefetch information)
        // TODO: retrieve actual cache information
        cpu_state[1] = 0x80000001; // eax = reserved (with al=01)
        cpu_state[2] = 0x80000000; // ecx = reserved
        cpu_state[3] = 0x80000000; // edx = reserved
        cpu_state[4] = 0x80000000; // ebx = reserved
    } else if (rax == 3) { // page 3 (processor serial number; not supported)
        cpu_state[1] = 0x00000000; // eax = reserved
        cpu_state[2] = 0x00000000; // ecx = reserved
        cpu_state[3] = 0x00000000; // edx = reserved
        cpu_state[4] = 0x00000000; // ebx = reserved
    } else if (rax == 4) { // page 4 (deterministic cache params; not implemented)
        cpu_state[1] = 0x00000000; // eax = reserved
        cpu_state[2] = 0x00000000; // ecx = reserved
        cpu_state[3] = 0x00000000; // edx = reserved
        cpu_state[4] = 0x00000000; // ebx = reserved
    } else if (rax == 5) { // page 5 (monitor/mwait; mot implemented)
        cpu_state[1] = 0x00000000; // eax = reserved
        cpu_state[2] = 0x00000000; // ecx = reserved
        cpu_state[3] = 0x00000000; // edx = reserved
        cpu_state[4] = 0x00000000; // ebx = reserved
    } else if (rax == 6) { // page 6 (thermal and power management; not supported)
        cpu_state[1] = 0x00000000; // eax = reserved
        cpu_state[2] = 0x00000000; // ecx = reserved
        cpu_state[3] = 0x00000000; // edx = reserved
        cpu_state[4] = 0x00000000; // ebx = reserved
    } else { // page 7 (structured extended feature flags)
        if (rcx == 0) {
            cpu_state[1] = 0; // eax = maximum subleave supported
            cpu_state[2] = 0x00000000; // ecx = reserved
            cpu_state[3] = 0x00000000; // edx = reserved
            cpu_state[4] = 0x00002200; // ebx = erms+deprecate fpu-cs/ds
        } else {
            cpu_state[1] = 0x00000000; // eax = reserved
            cpu_state[2] = 0x00000000; // ecx = reserved
            cpu_state[3] = 0x00000000; // edx = reserved
            cpu_state[4] = 0x00000000; // ebx = reserved
        }
    }
}

void
emulate_syscall(uint64_t* cpu_state) {
    struct State* state = STATE_FROM_CPU_STATE(cpu_state);

    uint64_t arg0 = cpu_state[8], arg1 = cpu_state[7], arg2 = cpu_state[3],
             arg3 = cpu_state[11], arg4 = cpu_state[9], arg5 = cpu_state[10];
    uint64_t nr = cpu_state[1];
    ssize_t res = -ENOSYS;

    switch (nr) {
    native:
        res = syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
        break;

    default:
    unhandled:
        dprintf(2, "unhandled syscall %u (%lx %lx %lx %lx %lx %lx)\n",
                nr, arg0, arg1, arg2, arg3, arg4, arg5);
        _exit(1);
        break;

    // Some syscalls are easy.
    case 0: nr = __NR_read; goto native;
    case 1: nr = __NR_write; goto native;
    case 3: nr = __NR_close; goto native;
    case 8: nr = __NR_lseek; goto native;
    case 9: nr = __NR_mmap; goto native; // TODO: catch dangerous maps
    case 10: nr = __NR_mprotect; goto native; // TODO: catch dangerous maps
    case 11: nr = __NR_munmap; goto native; // TODO: catch dangerous maps
    case 12: nr = __NR_brk; goto native; // TODO: catch dangerous maps
    case 16: nr = __NR_ioctl; goto native; // TODO: can something strange happen?
    case 20: nr = __NR_writev; goto native;
#ifdef __x86_64__
    case 23: nr = __NR_select; goto native;
#endif
    case 25: nr = __NR_mremap; goto native;
    case 32: nr = __NR_dup; goto native;
    case 39: nr = __NR_getpid; goto native;
    case 41: nr = __NR_socket; goto native;
    case 42: nr = __NR_connect; goto native;
    // case 58: nr = __NR_fork; goto native; // Treat vfork as fork.
    case 63: nr = __NR_uname; goto native;
    case 76: nr = __NR_truncate; goto native;
    case 77: nr = __NR_ftruncate; goto native;
    case 78: nr = __NR_getdents; goto native;
    case 79: nr = __NR_getcwd; goto native;
    case 80: nr = __NR_chdir; goto native;
    case 84: nr = __NR_rmdir; goto native;
    case 96: nr = __NR_gettimeofday; goto native;
    case 97: nr = __NR_getrlimit; goto native;
    case 99: nr = __NR_sysinfo; goto native;
    case 102: nr = __NR_getuid; goto native;
    case 104: nr = __NR_getgid; goto native;
    case 107: nr = __NR_geteuid; goto native;
    case 108: nr = __NR_getegid; goto native;
    case 115: nr = __NR_getgroups; goto native;
    case 116: nr = __NR_setgroups; goto native;
    case 137: nr = __NR_statfs; goto native; // FIXME: handle buffer argument
    case 191: nr = __NR_getxattr; goto native;
    case 192: nr = __NR_lgetxattr; goto native;
    case 193: nr = __NR_fgetxattr; goto native;
#ifdef __x86_64__
    case 201: nr = __NR_time; goto native;
#endif
    case 202: nr = __NR_futex; goto native;
    case 217: nr = __NR_getdents64; goto native;
    case 218: nr = __NR_set_tid_address; goto native;
    case 228: nr = __NR_clock_gettime; goto native;
    case 257: nr = __NR_openat; goto native;
    case 270: nr = __NR_pselect6; goto native;
    case 273: nr = __NR_set_robust_list; goto native;
    case 274: nr = __NR_get_robust_list; goto native;
    case 293: nr = __NR_pipe2; goto native;
    case 302: nr = __NR_prlimit64; goto native;
    case 318: nr = __NR_getrandom; goto native;

    // Some are too old to work on newer platforms, but have replacements.
    case 2: // open
        res = syscall(__NR_openat, AT_FDCWD, arg0, arg1, arg2, 0, 0);
        break;
    case 21: // access
        res = syscall(__NR_faccessat, AT_FDCWD, arg0, arg1, 0, 0, 0);
        break;
    case 22: // pipe
        res = syscall(__NR_pipe2, arg0, 0, 0, 0, 0, 0);
        break;
    case 82: // rename
        res = syscall(__NR_renameat, AT_FDCWD, arg0, AT_FDCWD, arg1, 0, 0);
        break;
    case 83: // mkdir
        res = syscall(__NR_mkdirat, AT_FDCWD, arg0, arg1, 0, 0, 0);
        break;
    case 87: // unlink
        res = syscall(__NR_unlinkat, AT_FDCWD, arg0, 0, 0, 0, 0);
        break;
    case 89: // readlink
        res = syscall(__NR_readlinkat, AT_FDCWD, arg0, arg1, arg2, 0, 0);
        break;
    case 92: // chown
        res = syscall(__NR_fchownat, AT_FDCWD, arg0, arg1, arg2, 0, 0);
        break;

    // And some syscalls need special handling, e.g. to different structs.
    case 4: // stat
    case 5: // fstat
    case 6: { // lstat
        struct stat tmp_struct;
        struct {
            unsigned long           st_dev;
            unsigned long           st_ino;
            unsigned long           st_nlink;

            unsigned int            st_mode;
            unsigned int            st_uid;
            unsigned int            st_gid;
            unsigned int            __pad0;
            unsigned long           st_rdev;
            long                    st_size;
            long                    st_blksize;
            long                    st_blocks;

            unsigned long           st_atime;
            unsigned long           st_atime_nsec;
            unsigned long           st_mtime;
            unsigned long           st_mtime_nsec;
            unsigned long           st_ctime;
            unsigned long           st_ctime_nsec;
            long                    __unused[3];
        } __attribute__((packed))* tgt = (void*) arg1;

        uintptr_t tmp_addr = (uintptr_t) &tmp_struct;
        if (nr == 4) // stat
            res = syscall(__NR_newfstatat, AT_FDCWD, arg0, tmp_addr, 0, 0, 0);
        else if (nr == 5) // fstat
            res = syscall(__NR_fstat, arg0, tmp_addr, 0, 0, 0, 0);
        else if (nr == 6) // lstat
            res = syscall(__NR_newfstatat, AT_FDCWD, arg0, tmp_addr, AT_SYMLINK_NOFOLLOW, 0, 0);
        if (res == 0) {
            tgt->st_dev = tmp_struct.st_dev;
            tgt->st_ino = tmp_struct.st_ino;
            tgt->st_nlink = tmp_struct.st_nlink;
            tgt->st_mode = tmp_struct.st_mode;
            tgt->st_uid = tmp_struct.st_uid;
            tgt->st_gid = tmp_struct.st_gid;
            tgt->st_rdev = tmp_struct.st_rdev;
            tgt->st_size = tmp_struct.st_size;
            tgt->st_blksize = tmp_struct.st_blksize;
            tgt->st_blocks = tmp_struct.st_blocks;
            tgt->st_atime = tmp_struct.st_atime;
            tgt->st_atime_nsec = tmp_struct.st_atime_nsec;
            tgt->st_mtime = tmp_struct.st_mtime;
            tgt->st_mtime_nsec = tmp_struct.st_mtime_nsec;
            tgt->st_ctime = tmp_struct.st_ctime;
            tgt->st_ctime_nsec = tmp_struct.st_ctime_nsec;
        }
        break;
    }
    case 33: // dup2
        if (arg0 == arg1) { // If oldfd == newfd return EBADF if oldfd is invalid
            res = syscall(__NR_fcntl, arg0, F_GETFL, 0, 0, 0, 0);
            if (res >= 0)
                res = arg1;
            goto end;
        }
        res = syscall(__NR_dup3, arg0, arg1, 0, 0, 0, 0);
        break;

    case 72: // fcntl
        switch (arg0) {
        case F_DUPFD:
        case F_GETFD:
        case F_SETFD:
        case F_GETFL:
        case F_SETFL:
        case F_GETLK: nr = __NR_fcntl; goto native;
        default: goto unhandled;
        }

    case 158: // arch_prctl
#ifdef __x86_64__
        if (state->config.native_segment_regs) {
            nr = __NR_arch_prctl;
            goto native;
        }
#endif
        switch (arg0) {
        default:
            res = -EINVAL;
            break;
        case 0x1001: // ARCH_SET_GS
            cpu_state[19] = arg1;
            res = 0;
            break;
        case 0x1002: // ARCH_SET_FS
            cpu_state[18] = arg1;
            res = 0;
            break;
        }
        break;

    case 231: {
        if (UNLIKELY(state->config.profile_rewriting)) {
            dprintf(2, "Rewriting %u bytes took %u ms\n",
                    (uint32_t) state->translator.written_bytes,
                    (uint32_t) (state->rew_time / 1000000));
        }
        // dprintf(2, "counter value: 0x%lx\n", cpu_state[-2]);

        nr = __NR_exit_group;
        goto native;
    }


    // Finally, some syscalls are not supported yet.
    case 13: // rt_sigaction
    case 14: // rt_sigprocmask
    case 15: // rt_sigreturn
    case 131: // sigaltstack
        // dprintf(2, "unsupported syscall %u, ignoring\n", nr);
        res = -ENOSYS;
        break;
    }

end:
    // dprintf(2, "syscall %u (%lx %lx %lx %lx %lx %lx) = 0x%lx(%u)\n",
    //         nr, arg0, arg1, arg2, arg3, arg4, arg5, res, res);

    cpu_state[1] = res;
}

__int128
emulate___divti3(__int128 a, __int128 b) {
    return a / b;
}

unsigned __int128
emulate___udivti3(unsigned __int128 a, unsigned __int128 b) {
    return a / b;
}

__int128
emulate___modti3(__int128 a, __int128 b) {
    return a % b;
}

unsigned __int128
emulate___umodti3(unsigned __int128 a, unsigned __int128 b) {
    return a % b;
}
