
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
arena_alloc(Arena* arena, size_t size, size_t alignment) {
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
    int ret = mprotect(arena->brkp, newpgsz, PROT_READ|PROT_WRITE);
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
    return arena_alloc(&main_arena_data, size, alignment);
}

void*
mem_alloc_code(size_t size, size_t alignment) {
    return arena_alloc(&main_arena_code, size, alignment);
}

int
mem_write_code(void* dst, const void* src, size_t size) {
    char* pgstart = (char*) ALIGN_DOWN((uintptr_t) dst, getpagesize());
    char* pgend = (char*) ALIGN_UP((uintptr_t) dst + size, getpagesize());
    int ret = mprotect(pgstart, pgend - pgstart, PROT_READ|PROT_WRITE);
    if (ret < 0)
        return ret;
    memcpy(dst, src, size);
    return mprotect(pgstart, pgend - pgstart, PROT_READ|PROT_EXEC);
}
