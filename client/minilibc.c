
#include <common.h>

#include <elf.h>


extern int main(int argc, char** argv);
void __start_main(const size_t* initial_stack, const size_t* dynv);

#if UINTPTR_MAX == 0xffffffff
#define ELF_R_TYPE ELF32_R_TYPE
#define Elf_Phdr Elf32_Phdr
#else
#define ELF_R_TYPE ELF64_R_TYPE
#define Elf_Phdr Elf64_Phdr
#endif

#if defined(__x86_64__)
#define R_RELATIVE R_X86_64_RELATIVE

ASM_BLOCK(
    .intel_syntax noprefix;
    .weak _DYNAMIC;
    .hidden _DYNAMIC;
    .global _start;
_start:
    xor ebp, ebp;
    mov rdi, rsp;
    lea rsi, [rip+_DYNAMIC];
    and rsp, 0xfffffffffffffff0;
    call __start_main;
    .att_syntax;
);

ASM_BLOCK(
    .intel_syntax noprefix;
    .global __clone;
    .type   __clone, @function;
__clone:
    and rsi, -16; // store arg on child stack
    sub rsi, 8;
    mov [rsi], rcx;
    mov r11, rdi; // temporarily store func in r11

    mov rdi, rdx; // flags
    // rsi is stack
    mov rdx, r8; // ptid
    mov r10, [rsp + 8]; // newtls
    mov r8, r9; // ctid

    mov r9, r11; // r11 is clobbered by the syscall instruction

    mov eax, 56; // __NR_clone
    syscall;
    test eax, eax;
    jnz 1f;

    pop rdi; // in child
    call r9;
    mov edi, eax;
    mov eax, 60; // __NR_exit
    syscall;

 1: ret;
    .att_syntax;
);

static size_t syscall0(int syscall_number) {
    size_t retval = syscall_number;
    __asm__ volatile("syscall" : "+a"(retval) : : "memory", "rcx", "r11");
    return retval;
}

static size_t syscall1(int syscall_number, size_t a1) {
    size_t retval = syscall_number;
    __asm__ volatile("syscall" : "+a"(retval) :
                     "D"(a1) :
                     "memory", "rcx", "r11");
    return retval;
}

static size_t syscall2(int syscall_number, size_t a1, size_t a2) {
    size_t retval = syscall_number;
    __asm__ volatile("syscall" : "+a"(retval) :
                     "D"(a1), "S"(a2) :
                     "memory", "rcx", "r11");
    return retval;
}

static size_t syscall3(int syscall_number, size_t a1, size_t a2, size_t a3) {
    size_t retval = syscall_number;
    __asm__ volatile("syscall" : "+a"(retval) :
                     "D"(a1), "S"(a2), "d"(a3) :
                     "memory", "rcx", "r11");
    return retval;
}

static size_t syscall4(int syscall_number, size_t a1, size_t a2, size_t a3,
                       size_t a4) {
    size_t retval = syscall_number;
    register size_t r10 __asm__("r10") = a4;
    __asm__ volatile("syscall" : "+a"(retval) :
                     "D"(a1),"S"(a2),"d"(a3),"r"(r10) :
                     "memory","rcx","r11");
    return retval;
}

static size_t syscall6(int syscall_number, size_t a1, size_t a2, size_t a3,
                       size_t a4, size_t a5, size_t a6) {
    size_t retval = syscall_number;
    register size_t r8 __asm__("r8") = a5;
    register size_t r9 __asm__("r9") = a6;
    register size_t r10 __asm__("r10") = a4;
    __asm__ volatile("syscall" : "+a"(retval) :
                     "D"(a1),"S"(a2),"d"(a3),"r"(r8),"r"(r9),"r"(r10) :
                     "memory","rcx","r11");
    return retval;
}

#elif defined(__aarch64__)
#define R_RELATIVE R_AARCH64_RELATIVE

ASM_BLOCK(
    .weak _DYNAMIC;
    .hidden _DYNAMIC;
    .global _start;
_start:
    mov x0, sp;
    adrp x1, _DYNAMIC;
    add x1, x1, #:lo12:_DYNAMIC;
    and sp, x0, #0xfffffffffffffff0;
    bl __start_main;
);

ASM_BLOCK(
    .global __clone;
    .type   __clone, @function;
__clone:
    and x1, x1, -16; // store arg on child stack
    stp x0, x3, [x1, -16]!;

    uxtw x0, w2;
    mov x2, x4;
    mov x3, x5;
    mov x4, x6;
    mov x8, 220; // __NR_clone
    svc 0;
    cbnz x0, 1f;

    ldp x1, x0, [sp], 16;
    blr x1;
    mov x8, 93; // __NR_exit
    svc 0;

 1: ret;
);

static
size_t
syscall0(int syscall_number)
{
    register size_t num __asm__("x8") = syscall_number;
    register size_t retval __asm__("x0");
    __asm__ volatile("svc #0" : "=r"(retval) : "r"(num) : "memory");
    return retval;
}

static
size_t
syscall1(int syscall_number, size_t arg1)
{
    register size_t p0 __asm__("x0") = arg1;
    register size_t num __asm__("x8") = syscall_number;
    register size_t retval __asm__("x0");
    __asm__ volatile("svc #0" : "=r"(retval) : "r"(num),"r"(p0) : "memory");
    return retval;
}

static
size_t
syscall2(int syscall_number, size_t arg1, size_t arg2)
{
    register size_t p0 __asm__("x0") = arg1;
    register size_t p1 __asm__("x1") = arg2;
    register size_t num __asm__("x8") = syscall_number;
    register size_t retval __asm__("x0");
    __asm__ volatile("svc #0" : "=r"(retval) :
                     "r"(num),"r"(p0),"r"(p1) : "memory");
    return retval;
}

static
size_t
syscall3(int syscall_number, size_t arg1, size_t arg2, size_t arg3)
{
    register size_t p0 __asm__("x0") = arg1;
    register size_t p1 __asm__("x1") = arg2;
    register size_t p2 __asm__("x2") = arg3;
    register size_t num __asm__("x8") = syscall_number;
    register size_t retval __asm__("x0");
    __asm__ volatile("svc #0" : "=r"(retval) :
                     "r"(num),"r"(p0),"r"(p1),"r"(p2) : "memory");
    return retval;
}

static
size_t
syscall4(int syscall_number, size_t arg1, size_t arg2, size_t arg3,
         size_t arg4)
{
    register size_t p0 __asm__("x0") = arg1;
    register size_t p1 __asm__("x1") = arg2;
    register size_t p2 __asm__("x2") = arg3;
    register size_t p3 __asm__("x3") = arg4;
    register size_t num __asm__("x8") = syscall_number;
    register size_t retval __asm__("x0");
    __asm__ volatile("svc #0" : "=r"(retval) :
                     "r"(num),"r"(p0),"r"(p1),"r"(p2),"r"(p3) : "memory");
    return retval;
}

static
size_t
syscall6(int syscall_number, size_t arg1, size_t arg2, size_t arg3,
         size_t arg4, size_t arg5, size_t arg6)
{
    register size_t p0 __asm__("x0") = arg1;
    register size_t p1 __asm__("x1") = arg2;
    register size_t p2 __asm__("x2") = arg3;
    register size_t p3 __asm__("x3") = arg4;
    register size_t p4 __asm__("x4") = arg5;
    register size_t p5 __asm__("x5") = arg6;
    register size_t num __asm__("x8") = syscall_number;
    register size_t retval __asm__("x0");
    __asm__ volatile("svc #0" : "=r"(retval) :
                     "r"(num),"r"(p0),"r"(p1),"r"(p2),"r"(p3),"r"(p4),"r"(p5) :
                     "memory");
    return retval;
}

#else
#error
#endif

char** environ;
static const size_t* __auxvptr;
static size_t pagesize;

inline long syscall(long number, long a1, long a2, long a3, long a4, long a5,
                    long a6) {
    return syscall6(number, a1, a2, a3, a4, a5, a6);
}

int getpid(void) {
    return syscall0(__NR_getpid);
}
int open(const char* pathname, int flags, int mode) {
    return openat(AT_FDCWD, pathname, flags, mode);
}
int openat(int dirfd, const char* pathname, int flags, int mode) {
    return syscall4(__NR_openat, dirfd, (size_t) pathname, flags, mode);
}
off_t lseek(int fd, off_t offset, int whence) {
    return syscall3(__NR_lseek, fd, offset, whence);
}
ssize_t read(int fd, void* buf, size_t count) {
    return syscall3(__NR_read, fd, (size_t) buf, count);
}
ssize_t write(int fd, const void* buf, size_t count) {
    return syscall3(__NR_write, fd, (size_t) buf, count);
}
int close(int fd) {
    return syscall1(__NR_close, fd);
}

ssize_t read_full(int fd, void* buf, size_t nbytes) {
    size_t total_read = 0;
    uint8_t* buf_cp = buf;
    while (total_read < nbytes) {
        ssize_t bytes_read = read(fd, buf_cp + total_read, nbytes - total_read);
        if (bytes_read < 0)
            return bytes_read;
        if (bytes_read == 0)
            return -EIO;
        total_read += bytes_read;
    }
    return total_read;
}
ssize_t write_full(int fd, const void* buf, size_t nbytes) {
    size_t total_written = 0;
    const uint8_t* buf_cp = buf;
    while (total_written < nbytes) {
        ssize_t bytes_written = write(fd, buf_cp + total_written, nbytes - total_written);
        if (bytes_written < 0)
            return bytes_written;
        if (bytes_written == 0)
            return -EIO;
        total_written += bytes_written;
    }
    return total_written;
}

void*
mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset) {
#if __SIZEOF_POINTER__ == 8
    return (void*) syscall6(__NR_mmap, (size_t) addr, length, prot, flags, fd,
                            offset);
#else
    return (void*) syscall6(__NR_mmap2, (size_t) addr, length, prot, flags, fd,
                            offset >> 12);
#endif
}
int mprotect(void* addr, size_t len, int prot) {
    return syscall3(__NR_mprotect, (size_t) addr, len, prot);
}
int munmap(void* addr, size_t length) {
    return syscall2(__NR_munmap, (size_t) addr, length);
}

int clock_gettime(int clk_id, struct timespec* tp) {
    return syscall2(__NR_clock_gettime, clk_id, (size_t) tp);
}

__attribute__((noreturn))
void _exit(int status) {
    syscall1(__NR_exit, status);
    __builtin_unreachable();
}

int execve(const char* filename, const char* const argv[], const char* const envp[]) {
    return syscall3(__NR_execve, (uintptr_t) filename, (uintptr_t) argv,
                    (uintptr_t) envp);
}
int dup2(int oldfd, int newfd) {
    if (oldfd == newfd) {
        int ret = syscall2(__NR_fcntl, oldfd, F_GETFL);
        return ret < 0 ? ret : newfd;
    }
    return syscall3(__NR_dup3, oldfd, newfd, 0);
}
int pipe2(int pipefd[2], int flags) {
    return syscall2(__NR_pipe2, (uintptr_t) pipefd, flags);
}

size_t strlen(const char* s) {
    size_t len = 0;
    for (; *s != '\0'; ++len, ++s);
    return len;
}
int strcmp(const char* s1, const char* s2) {
    for (; *s1 && *s1 == *s2; s1++, s2++);
    return *(const unsigned char*) s1 - *(const unsigned char*) s2;
}
int strncmp(const char* s1, const char* s2, size_t n) {
    if (n > 0) {
        for (; --n && *s1 && *s1 == *s2; s1++, s2++);
        return *(const unsigned char*) s1 - *(const unsigned char*) s2;
    }
    return 0;
}
char* strchr(const char* s, int c) {
    for (; *s != '\0' && *s != c; s++);
    return *s == c ? (char*) s : NULL;
}

int puts(const char* s) {
    write(1, s, strlen(s));
    write(1, "\n", 1);
    return 0;
}

typedef void (*PrintfWriteFunc)(void*, const char*, size_t);

static
size_t
printf_driver(PrintfWriteFunc write_func, void* data, const char* format,
              va_list args) {
    size_t bytes_written = 0;

    char buffer[32] = {0};
    int buflen;

    while (*format != '\0') {
        char* next_format = strchr(format, '%');
        if (next_format == NULL) {
            int len = strlen(format);
            write_func(data, format, len);
            bytes_written += len;
            format += len;
            break;
        }
        else if (next_format != format) {
            write_func(data, format, next_format - format);
            bytes_written += next_format - format;
            format = next_format;
        }

        // Skip '%'
        format++;

        char format_spec = *format;
        if (format_spec == '\0') {
            write_func(data, "%", 1);
            bytes_written++;
            break;
        }

        format++;
        if (format_spec == 's') {
            const char* str = va_arg(args, const char*);
            size_t len = strlen(str);
            write_func(data, str, len);
            bytes_written += len;
        }
        else if (format_spec == 'c') {
            int chr = va_arg(args, int);
            write_func(data, (char*) &chr, 1);
            bytes_written += 1;
        }
        else if (format_spec == 'p') {
            uintptr_t value = va_arg(args, uintptr_t);
            if (value == 0) {
                write_func(data, "(nil)", 5);
                bytes_written += 5;
                continue;
            }

            buffer[0] = '0';
            buffer[1] = 'x';
            buflen = 2;

            int highest_bit = 8 * sizeof(uintptr_t) - __builtin_clzl(value);
            int nibbles = (highest_bit + 3) >> 2;
            for (int i = nibbles - 1; i >= 0; i--) {
                uint8_t nibble = (value >> (4 * i)) & 0xf;
                buffer[buflen++] = "0123456789abcdef"[nibble];
            }

            write_func(data, buffer, buflen);
            bytes_written += buflen;
        }
        else if (format_spec == 'u') {
            uint32_t value = va_arg(args, uint32_t);
            size_t buf_idx = sizeof(buffer) - 1;
            if (value == 0) {
                buffer[buf_idx] = '0';
            }
            else {
                while (value > 0) {
                    uint32_t digit = value % 10;
                    buffer[buf_idx--] = '0' + digit;
                    value /= 10;
                }
                buf_idx++;
            }
            write_func(data, buffer + buf_idx, sizeof(buffer) - buf_idx);
            bytes_written += sizeof(buffer) - buf_idx;
        }
        else if (format_spec == 'x') {
            uint32_t value = va_arg(args, uint32_t);
            int nibbles = 1;
            if (value != 0) {
                int highest_bit = 8 * sizeof(uint32_t) - __builtin_clz(value);
                nibbles = (highest_bit + 3) >> 2;
            }
            buflen = 0;
            for (int i = nibbles - 1; i >= 0; i--) {
                uint8_t nibble = (value >> (4 * i)) & 0xf;
                buffer[buflen++] = "0123456789abcdef"[nibble];
            }

            write_func(data, buffer, buflen);
            bytes_written += buflen;
        }
        else if (format_spec == 'l' && *format == 'x') {
            format++;

            size_t value = va_arg(args, size_t);
            int nibbles = 1;
            if (value != 0) {
                int highest_bit = 8 * sizeof(size_t) - __builtin_clzl(value);
                nibbles = (highest_bit + 3) >> 2;
            }
            buflen = 0;
            for (int i = nibbles - 1; i >= 0; i--) {
                uint8_t nibble = (value >> (4 * i)) & 0xf;
                buffer[buflen++] = "0123456789abcdef"[nibble];
            }

            write_func(data, buffer, buflen);
            bytes_written += buflen;
        }
    }

    return bytes_written;

}

struct SPrintfHelperData {
    char* buf;
    size_t len;
};

static
void
sprintf_helper(struct SPrintfHelperData* data, const char* buf, size_t len)
{
    if (data->len == 0)
    {
        memcpy(data->buf, buf, len);
        data->buf += len;
    }
    else if (data->len > len)
    {
        memcpy(data->buf, buf, len);
        data->buf += len;
        data->len -= len;
    }
    else
    {
        memcpy(data->buf, buf, data->len - 1);
        data->buf += data->len - 1;
        data->len = 1;
    }
}

int
vsnprintf(char* str, size_t size, const char* format, va_list args)
{
    struct SPrintfHelperData data = { str, size };

    int result = printf_driver((PrintfWriteFunc) sprintf_helper, &data, format,
                               args);

    *data.buf = '\0';

    return result;
}

__attribute__((externally_visible))
int
snprintf(char* str, size_t size, const char* format, ...)
{
    va_list args;
    va_start(args, format);

    int result = vsnprintf(str, size, format, args);

    va_end(args);

    return result;
}

static
void
dprintf_helper(void* fd, const void* buf, size_t count)
{
    write((int) (size_t) fd, buf, count);
}

int
vdprintf(int fd, const char* format, va_list args)
{
    return printf_driver((PrintfWriteFunc) dprintf_helper, (void*) (size_t) fd,
                         format, args);
}

int
dprintf(int fd, const char* format, ...)
{
    va_list args;
    va_start(args, format);

    int result = vdprintf(fd, format, args);

    va_end(args);

    return result;
}

int
printf(const char* format, ...)
{
    va_list args;
    va_start(args, format);

    int result = vdprintf(1, format, args);

    va_end(args);

    return result;
}

unsigned long getauxval(unsigned long type) {
    for (const size_t* aux = __auxvptr; *aux != 0; aux += 2)
        if (*aux == type)
            return aux[1];
    return 0;
}

size_t getpagesize(void) {
    return pagesize;
}

__attribute__((externally_visible))
void* memset(void* s, int c, size_t n) {
    unsigned char* sptr = s;
    for (; n > 0; n--, sptr++)
        *sptr = c;
    return s;
}

int memcmp(const void* s1, const void* s2, size_t n) {
    const uint8_t* s1ptr = s1;
    const uint8_t* s2ptr = s2;
    for (; n > 0; n--, s1ptr++, s2ptr++)
        if (*s1ptr != *s2ptr)
            return *s1ptr - *s2ptr;
    return 0;
}

__attribute__((externally_visible))
void* memcpy(void* dest, const void* src, size_t n) {
    uint8_t* s1ptr = dest;
    const uint8_t* s2ptr = src;
    for (; n > 0; n--)
        *(s1ptr++) = *(s2ptr++);
    return dest;
}

__attribute__((noreturn))
__attribute__((externally_visible))
void
__start_main(const size_t* initial_stack, const size_t* dynv)
{
    int argc = (int) initial_stack[0];
    char** local_environ = (char**) &initial_stack[argc + 2];

    const size_t* aux = &initial_stack[argc + 2];
    for (; *aux != 0; ++aux) {}
    __auxvptr = (const size_t*) ++aux;

    pagesize = getauxval(AT_PAGESZ);

    // Process relocations, if present.
    if (dynv) {
        uintptr_t base = 0;

        size_t phnum = getauxval(AT_PHNUM);
        size_t phent = getauxval(AT_PHENT);
        Elf_Phdr* phdr = (void*) getauxval(AT_PHDR);
        if (sizeof(*phdr) != phent)
            _exit(-ENOEXEC);
        for (unsigned i = 0; i != phnum; i++) {
            if (phdr[i].p_type == PT_DYNAMIC) {
                base = (uintptr_t) dynv - phdr[i].p_vaddr;
                break;
            }
        }

        size_t* rel = NULL, * rela = NULL;
        size_t relsz = 0, relasz = 0;
        for (; dynv[0]; dynv += 2) {
            switch (dynv[0]) {
            case DT_REL: rel = (void*) (base + dynv[1]); break;
            case DT_RELA: rela = (void*) (base + dynv[1]); break;
            case DT_RELSZ: relsz = dynv[1]; break;
            case DT_RELASZ: relasz = dynv[1]; break;
            default: break;
            }
        }

        for (; relsz; rel += 2, relsz -= 2*sizeof(size_t)) {
            if (ELF_R_TYPE(rel[1]) != R_RELATIVE)
                _exit(-ENOEXEC);
            *((size_t*) (base + rel[0])) += base;
        }
        for (; relasz; rela += 3, relasz -= 3*sizeof(size_t)) {
            if (ELF_R_TYPE(rela[1]) != R_RELATIVE)
                _exit(-ENOEXEC);
            *((size_t*) (base + rela[0])) = base + rela[2];
        }
    }

    __asm__ volatile("" ::: "memory"); // memory barrier for compiler
    environ = local_environ;

    int retval = main(initial_stack[0], (char**) (initial_stack + 1));
    _exit(retval);
}
