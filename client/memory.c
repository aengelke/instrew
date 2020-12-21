
#include <common.h>
#include <elf.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/mman.h>

#include <memory.h>


#define ADDRSPACE_DEFAULT_BASE ((void*) 0x0000400000000000ull)
#define ADDRSPACE_DEFAULT_SIZE 0x40000000


struct Arena {
    struct Arena* next;
    size_t size;
    size_t curoff;
};

typedef struct Arena Arena;

Arena* main_arena;

static Arena*
arena_create(void) {
    void* arena = mmap(ADDRSPACE_DEFAULT_BASE, ADDRSPACE_DEFAULT_SIZE, PROT_NONE,
                       MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0);
    if (BAD_ADDR(arena))
        return arena;

    int ret = mprotect(arena, ALIGN_UP(sizeof(Arena), getpagesize()),
                       PROT_READ|PROT_WRITE);
    if (ret < 0)
        return (Arena*) (uintptr_t) ret;

    Arena* arena_p = arena;
    arena_p->next = NULL;
    arena_p->size = ADDRSPACE_DEFAULT_SIZE;
    arena_p->curoff = ALIGN_UP(sizeof(Arena), getpagesize());

    main_arena = arena;

    return arena;
}

int
mem_init(void) {
    Arena* arena = arena_create();
    if (BAD_ADDR(arena))
        return (int) (uintptr_t) arena;

    main_arena = arena;
    return 0;
}

void*
mem_alloc(size_t size) {
    size = ALIGN_UP(size, getpagesize());

    Arena* arena = main_arena;
    while (arena != NULL && arena->curoff + size >= arena->size)
        arena = arena->next;
    if (arena == NULL)
        return (void*) (uintptr_t) -ENOMEM;

    void* new_addr = (void*) ((uintptr_t) arena + arena->curoff);
    int ret = mprotect(new_addr, size, PROT_READ|PROT_WRITE);
    if (ret < 0)
        return (void*) (uintptr_t) ret;

    arena->curoff += size;

    return new_addr;
}

int
mem_free(void* addr, size_t size) {
    size = ALIGN_UP(size, getpagesize());
    void* ret = mmap(addr, size, PROT_NONE,
                     MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED|MAP_NORESERVE, -1, 0);
    if (BAD_ADDR(ret))
        return (int) (uintptr_t) ret;

    if (ret != addr)
        return -EINVAL;
    return 0;
}
