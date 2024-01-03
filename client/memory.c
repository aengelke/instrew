
#include <common.h>
#include <elf.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/mman.h>

#include <memory.h>


#define MEM_BASE ((void*) 0x0000400000000000ull)
#define MEM_CODE_SIZE 0x40000000
#define MEM_DATA_SIZE 0x01000000

typedef struct Arena Arena;
struct Arena {
    char* start;
    char* end;
    char* brk;
    char* brkp;
};

static int
arena_init(Arena* arena, void* base, size_t size) {
    void* mem = mmap(base, size, PROT_NONE,
                     MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0);
    if (BAD_ADDR(mem))
        return (int) (uintptr_t) mem;

    arena->start = mem;
    arena->end = (char*) mem + size;
    arena->brk = mem;
    arena->brkp = mem;

    return 0;
}

static void*
arena_alloc(Arena* arena, size_t size, size_t alignment, bool exec) {
    if (alignment < 0x40)
        alignment = 0x40;
    if (alignment & (alignment - 1))
        return (void*) (uintptr_t) -EINVAL;
    char* brk_al = (char*) ALIGN_UP((uintptr_t) arena->brk, alignment);
    if (brk_al + size <= arena->brkp) { // easy case.
        arena->brk = brk_al + size;
        return brk_al;
    }
    size_t newpgsz = ALIGN_UP(size - (arena->brkp - brk_al), getpagesize());
    if (arena->brk + newpgsz > arena->end)
        return (void*) (uintptr_t) -ENOMEM;
    int prot = PROT_READ|PROT_WRITE | (exec ? PROT_EXEC : 0);
    int ret = mprotect(arena->brkp, newpgsz, prot);
    if (ret < 0)
        return (void*) (uintptr_t) ret;
    arena->brkp += newpgsz;
    arena->brk = brk_al + size;
    return brk_al;
}

Arena main_arena_code;
Arena main_arena_data;

int
mem_init(void) {
    int ret = arena_init(&main_arena_data, MEM_BASE, MEM_DATA_SIZE);
    if (ret)
        return ret;
    void* code_arena_base = (void*) ((uintptr_t) MEM_BASE + MEM_DATA_SIZE);
    ret = arena_init(&main_arena_code, code_arena_base, MEM_CODE_SIZE);
    if (ret)
        return ret;
    return 0;
}

void*
mem_alloc_data(size_t size, size_t alignment) {
    return arena_alloc(&main_arena_data, size, alignment, /*exec=*/false);
}

void*
mem_alloc_code(size_t size, size_t alignment) {
    return arena_alloc(&main_arena_code, size, alignment, /*exec=*/true);
}

int
mem_write_code(void* dst, const void* src, size_t size) {
    // Note: if W^X is enforced, the pages need to be mapped somewhere else for
    // writing (e.g., using memfd).
    memcpy(dst, src, size);

    // Flush ICache, except for x86-64.
#if defined(__x86_64__)
    // Do nothing; x86-64 flushes ICache automatically.
#elif defined(__aarch64__)
    uintptr_t dstu = (uintptr_t) dst;
    // Procedure from AArch64 Manual, B2.4.4
    uint64_t ctr_el0 = 0;
    __asm__("mrs %0, ctr_el0" : "=r"(ctr_el0));
    // Encoding of cache line sizes is log2(#words), one word is 4 bytes.
    size_t dc_line_sz = 4 << ((ctr_el0 >> 16) & 0xf); // DCache min line size
    size_t ic_line_sz = 4 << ((ctr_el0 >> 0) & 0xf); // ICache min line size

    if (!(ctr_el0 & (1 << 28))) { // IDC == 0 => DC invalidation required
        for (uintptr_t p = dstu & ~dc_line_sz; p < dstu + size; p += dc_line_sz)
            __asm__ volatile("dc cvau, %0" : : "r"(p));
        __asm__ volatile("dsb ish");
    }
    if (!(ctr_el0 & (1 << 29))) { // DIC == 0 => IC invalidation required
        for (uintptr_t p = dstu & ~ic_line_sz; p < dstu + size; p += ic_line_sz)
            __asm__ volatile("ic ivau, %0" : : "r"(p));
        __asm__ volatile("dsb ish");
    }
    __asm__ volatile("isb");
#else
#error "Implement ICache flush for unknown target"
#endif
    return 0;
}
