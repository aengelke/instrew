
#include <stdatomic.h>
#include <common.h>
#include <elf.h>
#include <limits.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/mman.h>

#include <rtld.h>

#include <memory.h>


// Old elf.h don't include unwind sections
#if !defined(SHT_X86_64_UNWIND)
#define SHT_X86_64_UNWIND 0x70000001
#endif // !defined(SHT_X86_64_UNWIND)

#if defined(__x86_64__)
#define EM_CURRENT EM_X86_64
#elif defined(__aarch64__)
#define EM_CURRENT EM_AARCH64
#endif
#define elf_check_arch(x) ((x)->e_machine == EM_CURRENT)

#define CHECK_SIGNED_BITS(val,bits) \
            ((val) >= -(1ll << (bits-1)) && (val) < (1ll << (bits-1))-1)
#define CHECK_UNSIGNED_BITS(val,bits) ((val) < (1ull << (bits))-1)

static bool
rtld_elf_signed_range(int64_t val, unsigned bits, const char* relinfo) {
    if (!CHECK_SIGNED_BITS(val, bits)) {
        dprintf(2, "relocation offset out of range (%s): %lx\n", relinfo, val);
        return false;
    }
    return true;
}

static bool
rtld_elf_unsigned_range(uint64_t val, unsigned bits, const char* relinfo) {
    if (!CHECK_UNSIGNED_BITS(val, bits)) {
        dprintf(2, "relocation offset out of range (%s): %lx\n", relinfo, val);
        return false;
    }
    return true;
}

static void
rtld_blend(void* tgt, uint64_t mask, uint64_t data) {
    if (mask > UINT32_MAX)
        *(uint64_t*) tgt = (data & mask) | (*(uint64_t*) tgt & ~mask);
    else if (mask > UINT16_MAX)
        *(uint32_t*) tgt = (data & mask) | (*(uint32_t*) tgt & ~mask);
    else if (mask > UINT8_MAX)
        *(uint16_t*) tgt = (data & mask) | (*(uint16_t*) tgt & ~mask);
    else
        *(uint8_t*) tgt = (data & mask) | (*(uint8_t*) tgt & ~mask);
}

#define RTLD_HASH_BITS 17
#define RTLD_HASH_MASK ((1 << RTLD_HASH_BITS) - 1)
#define RTLD_HASH(addr) (((addr >> 2)) & RTLD_HASH_MASK)

struct PltEntry {
    const char* name;
    uintptr_t func;
};

// Declare functions, but avoid name collision in C.
#define PLT_ENTRY(name, func) \
        extern void PASTE(rtld_plt_, func)() __asm__(STRINGIFY(func));
#include "plt.inc"
#undef PLT_ENTRY

static const struct PltEntry plt_entries[] = {
    { "instrew_quick_dispatch", 0 }, // dynamically set below
    { "instrew_full_dispatch", 0 }, // dynamically set below
#define PLT_ENTRY(name, func) { name, (uintptr_t) &(PASTE(rtld_plt_, func)) },
#include "plt.inc"
#undef PLT_ENTRY
    { NULL, 0 }
};

#if defined(__x86_64__)
#define PLT_FUNC_SIZE 8
#elif defined(__aarch64__)
#define PLT_FUNC_SIZE 8
#else
#error "currently unsupported architecture"
#endif

static int
plt_create(const struct DispatcherInfo* disp_info, void** out_plt) {
    size_t plt_entry_count = sizeof(plt_entries) / sizeof(plt_entries[0]) - 1;
    size_t code_size = plt_entry_count * PLT_FUNC_SIZE;
    size_t data_offset = ALIGN_UP(code_size, 0x40u);
    size_t data_size = plt_entry_count * sizeof(uintptr_t);
    size_t plt_size = data_offset + data_size;

    uintptr_t plt[ALIGN_UP(plt_size, sizeof(uintptr_t)) / sizeof(uintptr_t)];

    for (size_t i = 0; i < plt_entry_count; i++) {
        void* code_ptr = (uint8_t*) plt + i * PLT_FUNC_SIZE;
        uintptr_t* data_ptr = &plt[data_offset / sizeof(uintptr_t) + i];
        ptrdiff_t offset = (char*) data_ptr - (char*) code_ptr;

        if (i == 0)
            *data_ptr = disp_info->quick_dispatch_func;
        else if (i == 1)
            *data_ptr = disp_info->full_dispatch_func;
        else
            *data_ptr = plt_entries[i].func;
#if defined(__x86_64__)
        // This is: "jmp [rip + offset]; ud2"
        *((uint64_t*) code_ptr) = 0x0b0f0000000025ff | ((offset - 6) << 16);
#elif defined(__aarch64__)
        *((uint32_t*) code_ptr+0) = 0x58000011 | (offset << 3); // ldr x17, [pc+off]
        *((uint32_t*) code_ptr+1) = 0xd61f0220; // br x17
#else
#error
#endif // defined(__x86_64__)
    }

    void* pltcode = mem_alloc_code(sizeof(plt), 0x40);
    if (BAD_ADDR(pltcode))
        return (int) (uintptr_t) pltcode;
    int ret = mem_write_code(pltcode, plt, sizeof(plt));
    if (ret < 0)
        return ret;
    *out_plt = pltcode;

    return 0;
}

static int
rtld_patch_create_stub(Rtld* rtld, const struct RtldPatchData* patch_data,
                       uintptr_t* out_stub) {
    _Static_assert(_Alignof(struct RtldPatchData) <= 0x10,
                   "patch data alignment too big");
    _Alignas(0x10) uint8_t stcode[0x10 + sizeof(*patch_data)];

    void* stub = mem_alloc_code(sizeof(stcode), 0x40);
    if (BAD_ADDR(stub))
        return (int) (uintptr_t) stub;

    uintptr_t jmptgt = (uintptr_t) rtld->plt + 1 * PLT_FUNC_SIZE;
    ptrdiff_t jmptgtdiff = jmptgt - (uintptr_t) stub;
    unsigned pdr = rtld->disp_info->patch_data_reg;

#if defined(__x86_64__)
    uint8_t tmpl[] = {
        0x48 + 4*(pdr>=8), 0x8d, 5+((pdr&7)<<3), 9, 0, 0, 0, // lea rXX, [rip+9]
        0xe9, // jmp ...
    };
    memcpy(stcode, tmpl, sizeof tmpl);
    *(uint32_t*) (stcode + 8) = jmptgtdiff - 12;
    *(uint32_t*) (stcode + 12) = 0x0b0f0b0f; // ud2
#elif defined(__aarch64__)
    *(uint32_t*) (stcode) = 0x10000080 + pdr; // ADR xXX, pc + 0x10
    *(uint32_t*) (stcode + 4) = 0x14000000; // B ...
    if (!rtld_elf_signed_range(jmptgtdiff - 4, 28, "R_AARCH64_JUMP26"))
        return -EINVAL;
    rtld_blend(stcode + 4, 0x03ffffff, (jmptgtdiff - 4) >> 2);
#else
#error "missing patch stub"
#endif

    memcpy(stcode+sizeof(stcode)-sizeof(*patch_data), patch_data, sizeof(*patch_data));

    int ret = mem_write_code(stub, stcode, sizeof(stcode));
    if (ret < 0)
        return ret;

    *out_stub = (uintptr_t) stub;
    return 0;
}


struct RtldObject {
    _Atomic uintptr_t addr;
    void* entry;
    void* base;
    size_t size;
};

struct RtldElf {
    uint8_t* base;
    size_t size;
    uint64_t skew;
    Elf64_Ehdr* re_ehdr;
    Elf64_Shdr* re_shdr;

    // Global PLT
    Rtld* rtld;
};
typedef struct RtldElf RtldElf;

static int
rtld_elf_init(RtldElf* re, void* obj_base, size_t obj_size, uint64_t skew,
              Rtld* rtld) {
    if (obj_size < sizeof(Elf64_Ehdr))
        goto err;

    re->base = obj_base;
    re->size = obj_size;
    re->skew = skew;
    re->re_ehdr = obj_base;
    re->rtld = rtld;

    if (memcmp(re->re_ehdr, ELFMAG, SELFMAG) != 0)
        goto err;
    if (re->re_ehdr->e_type != ET_REL)
        goto err;
    if (re->re_ehdr->e_ident[EI_CLASS] != ELFCLASS64)
        goto err;
    if (!elf_check_arch(re->re_ehdr))
        goto err;

    if (re->re_ehdr->e_shentsize != sizeof(Elf64_Shdr))
        goto err;
    if (obj_size < re->re_ehdr->e_shoff + re->re_ehdr->e_shentsize * re->re_ehdr->e_shnum)
        goto err;

    re->re_shdr = (Elf64_Shdr*) ((uint8_t*) obj_base + re->re_ehdr->e_shoff);

    return 0;

err:
    return -EINVAL;
}

static int
rtld_elf_decode_name(RtldElf* re, const char* name, uintptr_t* out_addr) {
    uintptr_t addr = 0;
    if (name[0] != 'Z' && name[0] != 'S')
        return -EINVAL;
    for (unsigned k = 1; name[k] && name[k] != '_'; k++) {
        if (name[k] < '0' || name[k] >= '8')
            return 0;
        addr = (addr << 3) | (name[k] - '0');
    }
    if (name[0] == 'S')
        addr += re->skew;
    *out_addr = addr;
    return 0;
}

static int
rtld_elf_resolve_str(RtldElf* re, size_t strtab_idx, size_t str_idx, const char** out_addr) {
    if (strtab_idx == 0 || strtab_idx >= re->re_ehdr->e_shnum)
        return -EINVAL;
    Elf64_Shdr* str_shdr = re->re_shdr + strtab_idx;
    if (str_shdr->sh_type != SHT_STRTAB)
        return -EINVAL;
    if (str_idx >= str_shdr->sh_size)
        return -EINVAL;

    *out_addr = (const char*) (re->base + str_shdr->sh_offset) + str_idx;

    return 0;
}

static int
rtld_elf_resolve_sym(RtldElf* re, size_t symtab_idx, size_t sym_idx,
                     struct RtldPatchData* patch_data, uintptr_t* out_addr) {
    if (symtab_idx == 0 || symtab_idx >= re->re_ehdr->e_shnum)
        return -EINVAL;
    Elf64_Shdr* sym_shdr = re->re_shdr + symtab_idx;
    if (sym_shdr->sh_type != SHT_SYMTAB)
        return -EINVAL;
    if (sym_shdr->sh_entsize != sizeof(Elf64_Sym))
        return -EINVAL;
    if (sym_idx == 0 || sym_idx >= sym_shdr->sh_size / sizeof(Elf64_Sym))
        return -EINVAL;

    Elf64_Sym* sym = (Elf64_Sym*) (re->base + sym_shdr->sh_offset) + sym_idx;
    if (sym->st_shndx == SHN_UNDEF) {
        const char* name = "<unknown>";
        rtld_elf_resolve_str(re, sym_shdr->sh_link, sym->st_name, &name);
        if (!strncmp(name, "glob_", 5)) {
            dprintf(2, "undefined symbol reference to %s\n", name);
            return -EINVAL;
        } else if (!strcmp(name, "instrew_baseaddr")) {
            *out_addr = re->skew;
            return 0;
        } else {
            uintptr_t addr = 0;
            if (!rtld_elf_decode_name(re, name, &addr)) {
                if (!rtld_resolve(re->rtld, addr, (void**) out_addr))
                    return 0; // we got it already
                // Create a stub. We cannot use the normal dispatcher, as the
                // target address is not necessarily set.
                patch_data->sym_addr = addr;
                return rtld_patch_create_stub(re->rtld, patch_data, out_addr);
            }

            // Search through PLT
            for (size_t i = 0; plt_entries[i].name; i++) {
                if (!strcmp(name, plt_entries[i].name)) {
                    *out_addr = (uintptr_t) re->rtld->plt + i * PLT_FUNC_SIZE;
                    return 0;
                }
            }

            dprintf(2, "undefined symbol reference to %s\n", name);
            return -EINVAL;
        }
    } else if (sym->st_shndx == SHN_ABS) {
        *out_addr = sym->st_value;
    } else if (sym->st_shndx < re->re_ehdr->e_shnum) {
        Elf64_Shdr* tgt_shdr = re->re_shdr + sym->st_shndx;
        *out_addr = tgt_shdr->sh_addr + sym->st_value;
    } else {
        return -EINVAL;
    }

    return 0;
}

#if defined(__aarch64__)
static int
rtld_elf_add_stub(uintptr_t sym, uintptr_t* out_stub) {
    uint32_t stcode[] = {
        0xd2800010 | (((sym >> 0) & 0xffff) << 5), // movz x16, ...
        0xf2a00010 | (((sym >> 16) & 0xffff) << 5), // movk x16, ..., lsl 16
        0xf2c00010 | (((sym >> 32) & 0xffff) << 5), // movk x16, ..., lsl 32
        0xf2e00010 | (((sym >> 48) & 0xffff) << 5), // movk x16, ..., lsl 48
        0xd61f0200, // br x16
    };

    void* stub = mem_alloc_code(sizeof(stcode), 0x40);
    if (BAD_ADDR(stub))
        return (int) (uintptr_t) stub;
    int ret = mem_write_code(stub, stcode, sizeof(stcode));
    if (ret < 0)
        return ret;

    *out_stub = (uintptr_t) stub;
    return 0;
}
#endif

static int
rtld_reloc_at(const struct RtldPatchData* patch_data, void* tgt, void* sym) {
    uint64_t syma = (uintptr_t) sym + patch_data->addend;
    uint64_t pc = patch_data->patch_addr;
    int64_t prel_syma = syma - (int64_t) pc;

    switch (patch_data->rel_type) {
#if defined(__x86_64__)
    case R_X86_64_PC64:
        rtld_blend(tgt, UINT64_MAX, prel_syma);
        break;
    case R_X86_64_64:
        rtld_blend(tgt, UINT64_MAX, syma);
        break;
    case R_X86_64_PC32:
        if (!rtld_elf_signed_range(prel_syma, 32, "R_X86_64_PC32"))
            return -EINVAL;
        rtld_blend(tgt, 0xffffffff, prel_syma);
        break;
    case R_X86_64_PLT32:
        if (!rtld_elf_signed_range(prel_syma, 32, "R_X86_64_PLT32"))
            return -EINVAL;
        rtld_blend(tgt, 0xffffffff, prel_syma);
        break;
    case R_X86_64_32S:
        if (!rtld_elf_signed_range(syma, 32, "R_X86_64_32S"))
            return -EINVAL;
        rtld_blend(tgt, 0xffffffff, syma);
        break;
    case R_X86_64_32:
        if (!rtld_elf_unsigned_range(syma, 32, "R_X86_64_32S"))
            return -EINVAL;
        rtld_blend(tgt, 0xffffffff, syma);
        break;
#elif defined(__aarch64__)
    case R_AARCH64_PREL64:
        rtld_blend(tgt, UINT64_MAX, prel_syma);
        break;
    case R_AARCH64_PREL32:
        if (!rtld_elf_signed_range(prel_syma, 32, "R_AARCH64_PREL32"))
            return -EINVAL;
        rtld_blend(tgt, 0xffffffff, prel_syma);
        break;
    case R_AARCH64_JUMP26:
    case R_AARCH64_CALL26:
        if (!CHECK_SIGNED_BITS(prel_syma, 28)) {
            // Ok, let's create a stub.
            // TODO: make stubs more compact/efficient
            uintptr_t stub = 0;
            int ret = rtld_elf_add_stub(syma, &stub);
            if (ret < 0)
                return ret;
            prel_syma = stub - pc;
        }
        if (!rtld_elf_signed_range(prel_syma, 28, "R_AARCH64_JUMP26"))
            return -EINVAL;
        rtld_blend(tgt, 0x03ffffff, prel_syma >> 2);
        break;
    case R_AARCH64_ADR_PREL_PG_HI21:
        prel_syma = ALIGN_DOWN(syma, 1<<12) - ALIGN_DOWN(pc, 1<<12);
        prel_syma >>= 12;
        if (!rtld_elf_signed_range(prel_syma, 21, "R_AARCH64_PG_HI21"))
            return -EINVAL;
        rtld_blend(tgt, 0x60ffffe0, ((prel_syma & 3) << 29) |
                                    (((prel_syma >> 2) & 0x7ffff) << 5));
        break;
    case R_AARCH64_ADD_ABS_LO12_NC:
        rtld_blend(tgt, 0xfff << 10, syma << 10);
        break;
    case R_AARCH64_LDST8_ABS_LO12_NC:
        rtld_blend(tgt, 0xfff << 10, syma << 10);
        break;
    case R_AARCH64_LDST16_ABS_LO12_NC:
        rtld_blend(tgt, 0xfff >> 1 << 10, syma >> 1 << 10);
        break;
    case R_AARCH64_LDST32_ABS_LO12_NC:
        rtld_blend(tgt, 0xfff >> 2 << 10, syma >> 2 << 10);
        break;
    case R_AARCH64_LDST64_ABS_LO12_NC:
        rtld_blend(tgt, 0xfff >> 3 << 10, syma >> 3 << 10);
        break;
    case R_AARCH64_LDST128_ABS_LO12_NC:
        rtld_blend(tgt, 0xfff >> 4 << 10, syma >> 4 << 10);
        break;
    case R_AARCH64_MOVW_UABS_G0_NC:
        rtld_blend(tgt, 0xffff << 5, syma >> 0 << 5);
        break;
    case R_AARCH64_MOVW_UABS_G1_NC:
        rtld_blend(tgt, 0xffff << 5, syma >> 16 << 5);
        break;
    case R_AARCH64_MOVW_UABS_G2_NC:
        rtld_blend(tgt, 0xffff << 5, syma >> 32 << 5);
        break;
    case R_AARCH64_MOVW_UABS_G3:
        rtld_blend(tgt, 0xffff << 5, syma >> 48 << 5);
        break;
#endif
    default:
        dprintf(2, "unhandled relocation %u\n", patch_data->rel_type);
        return -EINVAL;
    }

    return 0;
}

static int
rtld_elf_process_rela(RtldElf* re, int rela_idx) {
    if (rela_idx == 0 || rela_idx >= re->re_ehdr->e_shnum)
        return -EINVAL;
    Elf64_Shdr* rela_shdr = re->re_shdr + rela_idx;
    if (rela_shdr->sh_type != SHT_RELA)
        return -EINVAL;
    if (rela_shdr->sh_entsize != sizeof(Elf64_Rela))
        return -EINVAL;

    Elf64_Rela* elf_rela = (Elf64_Rela*) ((uint8_t*) re->base + rela_shdr->sh_offset);
    Elf64_Rela* elf_rela_end = elf_rela + rela_shdr->sh_size / sizeof(Elf64_Rela);

    if (rela_shdr->sh_info == 0 || rela_shdr->sh_info >= re->re_ehdr->e_shnum)
        return -EINVAL;
    Elf64_Shdr* tgt_shdr = &re->re_shdr[rela_shdr->sh_info];
    if (!(tgt_shdr->sh_flags & SHF_ALLOC))
        return -EINVAL;

    uint8_t* sec_write_addr = re->base + tgt_shdr->sh_offset;

    unsigned symtab_idx = rela_shdr->sh_link;

    for (; elf_rela != elf_rela_end; ++elf_rela) {
        // TODO: ensure that size doesn't overflow
        if (elf_rela->r_offset >= tgt_shdr->sh_size)
            return -EINVAL;

        struct RtldPatchData reloc_patch = {
            .rel_type = ELF64_R_TYPE(elf_rela->r_info),
            .rel_size = 8, // TODO: be more accurate
            .addend = elf_rela->r_addend,
            .patch_addr = tgt_shdr->sh_addr + elf_rela->r_offset,
        };

        unsigned sym_idx = ELF64_R_SYM(elf_rela->r_info);
        uint64_t sym;
        if (rtld_elf_resolve_sym(re, symtab_idx, sym_idx, &reloc_patch, &sym) < 0)
            return -EINVAL;

        uint8_t* tgt = sec_write_addr + elf_rela->r_offset;
        int retval = rtld_reloc_at(&reloc_patch, tgt, (void*) sym);
        if (retval < 0)
            return retval;
    }

    return 0;
}

static int rtld_set(Rtld* r, uintptr_t addr, void* entry, void* obj_base,
                    size_t obj_size) {
    // Note: not thread-safe. We first find a spot, then populate the data, and
    // then write the address, so that concurrent readers only ever see valid
    // data. However, a concurrent call to add an entry might cause them to
    // write to the same spot.

    if (!addr) // 0 is reserved for "empty"
        return -EINVAL;
    size_t hash = RTLD_HASH(addr);
    for (size_t i = 0; i <= RTLD_HASH_MASK; i++) {
        RtldObject* obj = &r->objects[(hash + i) & RTLD_HASH_MASK];
        uintptr_t obj_addr = atomic_load_explicit(&obj->addr, memory_order_relaxed);
        if (obj_addr == addr)
            return -EEXIST;
        if (!obj_addr) {
            obj->entry = entry;
            obj->base = obj_base;
            obj->size = obj_size;
            atomic_store_explicit(&obj->addr, addr, memory_order_release);
            return 0;
        }
    }

    return -ENOSPC;
}

// Perf support for simple maps and jitdump files.
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/perf/Documentation/jit-interface.txt
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/perf/Documentation/jitdump-specification.txt

struct RtldPerfJitHeader {
    uint32_t magic;
    uint32_t version;
    uint32_t total_size;
    uint32_t elf_mach;
    uint32_t pad1;
    uint32_t pid;
    uint64_t timestamp;
    uint64_t flags;
};

struct RtldPerfJitRecordHeader {
    uint32_t id;
    uint32_t total_size;
    uint64_t timestamp;
};

struct RtldPerfJitRecordCodeLoad {
    struct RtldPerfJitRecordHeader header;
    uint32_t pid;
    uint32_t tid;
    uint64_t vma;
    uint64_t code_addr;
    uint64_t code_size;
    uint64_t code_index;
};

static uint64_t
rtld_perf_timestamp(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
        return (uint64_t) ts.tv_sec * 1000000000 + (uint64_t) ts.tv_nsec;
    return 0;
}

static void
rtld_perf_notify(Rtld* r, uintptr_t addr, void* entry, size_t codesize,
                 const char* name) {
    if (UNLIKELY(r->perfmap_fd >= 0)) {
        dprintf(r->perfmap_fd, "%lx %lx %lx_%s\n",
                (uintptr_t) entry, codesize, addr, name);
    }

    if (UNLIKELY(r->perfdump_fd >= 0)) {
        char namebuf[64];
        size_t namelen = snprintf(namebuf, sizeof(namebuf), "%lx_%s", addr, name);
        if (namelen >= sizeof(namebuf))
            namelen = sizeof(namebuf) - 1;

        struct RtldPerfJitRecordCodeLoad record = {
            .header = {
                .id = 0 /* JIT_CODE_LOAD */,
                .total_size = (uint32_t) (sizeof(record) + namelen + 1 + codesize),
                .timestamp = rtld_perf_timestamp(),
            },
            .pid = (uint32_t) getpid(),
            .tid = (uint32_t) gettid(),
            .vma = (uint64_t) entry,
            .code_addr = (uint64_t) entry,
            .code_size = codesize,
            .code_index = addr, // unique index, use guest virtual address
        };
        write_full(r->perfdump_fd, &record, sizeof(record));
        write_full(r->perfdump_fd, namebuf, namelen + 1);
        write_full(r->perfdump_fd, entry, codesize);
    }
}

int
rtld_perf_init(Rtld* r, int mode) {
    if (mode < 1)
        return 0;

    int pid = getpid();

    char name[32];
    snprintf(name, sizeof(name), "/tmp/perf-%u.map", pid);
    int map_fd = open(name, O_CREAT|O_TRUNC|O_NOFOLLOW|O_WRONLY|O_CLOEXEC, 0600);
    if (map_fd < 0)
        return map_fd;

    r->perfmap_fd = map_fd;

    if (mode < 2)
        return 0;

    snprintf(name, sizeof(name), "/tmp/jit-%u.dump", pid);
    int dump_fd = open(name, O_CREAT|O_TRUNC|O_NOFOLLOW|O_RDWR|O_CLOEXEC, 0600);
    if (dump_fd < 0)
        return dump_fd;

    struct RtldPerfJitHeader header = {
        .magic = 0x4A695444, // ASCII "JiTD"
        .version = 1,
        .total_size = sizeof(header),
        .elf_mach = EM_CURRENT,
        .pad1 = 0,
        .pid = (uint32_t) getpid(),
        .timestamp = rtld_perf_timestamp(),
        .flags = 0,
    };
    if (write_full(dump_fd, &header, sizeof(header)) < 0) {
        close(dump_fd);
        return -EIO;
    }
    void* marker = mmap(NULL, getpagesize(), PROT_READ|PROT_EXEC, MAP_PRIVATE,
                        dump_fd, 0);
    if (BAD_ADDR(marker)) {
        close(dump_fd);
        return -EIO;
    }

    r->perfdump_fd = dump_fd;

    return 0;
}

int rtld_add_object(Rtld* r, void* obj_base, size_t obj_size, uint64_t skew) {
    int retval;

    RtldElf re;
    if ((retval = rtld_elf_init(&re, obj_base, obj_size, skew, r)) < 0)
        goto out;

    int i;
    Elf64_Shdr* elf_shnt;

    // First, check flags and determine total allocation size and alignment
    size_t totsz = 0;
    size_t totalign = 1;
    for (i = 0, elf_shnt = re.re_shdr; i < re.re_ehdr->e_shnum; i++, elf_shnt++) {
        // We don't support more flags
        if (elf_shnt->sh_flags & ~(SHF_ALLOC|SHF_EXECINSTR|SHF_MERGE|SHF_STRINGS|SHF_INFO_LINK)) {
            dprintf(2, "unsupported section flags\n");
            return -EINVAL;
        }
        if (elf_shnt->sh_flags & SHF_ALLOC) {
            totsz = ALIGN_UP(totsz, elf_shnt->sh_addralign);
            elf_shnt->sh_addr = totsz; // keep offset into allocation
            totsz += elf_shnt->sh_size;
            if (totalign < elf_shnt->sh_addralign)
                totalign = elf_shnt->sh_addralign;
        }
    }

    char* base = mem_alloc_code(totsz, totalign);
    if (BAD_ADDR(base))
        return (int) (uintptr_t) base;

    for (i = 0, elf_shnt = re.re_shdr; i < re.re_ehdr->e_shnum; i++, elf_shnt++)
        if (elf_shnt->sh_flags & SHF_ALLOC)
            elf_shnt->sh_addr += (uintptr_t) base;

    // Second pass to resolve relocations, now that all sections are allocated.
    for (i = 0, elf_shnt = re.re_shdr; i < re.re_ehdr->e_shnum; i++, elf_shnt++) {
        if (elf_shnt->sh_type != SHT_RELA)
            continue;
        retval = rtld_elf_process_rela(&re, i);
        if (retval < 0)
            goto out;
    }

    // Third pass to actually copy code into target allocation
    for (i = 0, elf_shnt = re.re_shdr; i < re.re_ehdr->e_shnum; i++, elf_shnt++) {
        if (elf_shnt->sh_type != SHT_PROGBITS)
            continue;
        uint8_t* src = re.base + elf_shnt->sh_offset;
        void* dst = (void*) elf_shnt->sh_addr;
        if ((retval = mem_write_code(dst, src, elf_shnt->sh_size)) < 0)
            goto out;
    }

    // Last pass to store final addresses in the hash table. This is done after
    // the code is put into its final place to avoid storing invalid addresses.
    for (i = 0, elf_shnt = re.re_shdr; i < re.re_ehdr->e_shnum; i++, elf_shnt++) {
        if (elf_shnt->sh_type != SHT_SYMTAB)
            continue;

        retval = -EINVAL;
        if (elf_shnt->sh_entsize != sizeof(Elf64_Sym))
            goto out;
        Elf64_Sym* elf_sym = (Elf64_Sym*) ((uint8_t*) obj_base + elf_shnt->sh_offset);
        Elf64_Sym* elf_sym_end = elf_sym + elf_shnt->sh_size / sizeof(Elf64_Sym);
        for (; elf_sym != elf_sym_end; elf_sym++) {
            if (ELF64_ST_BIND(elf_sym->st_info) != STB_GLOBAL)
                continue;
            if (ELF64_ST_TYPE(elf_sym->st_info) != STT_FUNC)
                continue;
            if (ELF64_ST_VISIBILITY(elf_sym->st_other) != STV_DEFAULT)
                continue;
            if (elf_sym->st_shndx == SHN_UNDEF)
                continue;
            retval = -EINVAL;
            if (elf_sym->st_shndx >= re.re_ehdr->e_shnum)
                goto out;
            uintptr_t entry = re.re_shdr[elf_sym->st_shndx].sh_addr + elf_sym->st_value;

            // Determine address from name, encoded in Z<octaladdr>_ignored
            const char* name = NULL;
            rtld_elf_resolve_str(&re, elf_shnt->sh_link, elf_sym->st_name, &name);
            if (!name)
                goto out;
            uintptr_t addr = 0;
            retval = rtld_elf_decode_name(&re, name, &addr);
            if (retval < 0 || addr == 0) {
                dprintf(2, "invalid function name %s\n", name);
                goto out;
            }
            retval = rtld_set(r, addr, (void*) entry, obj_base, obj_size);
            if (retval < 0)
                goto out;

            rtld_perf_notify(r, addr, (void*) entry, elf_sym->st_size, name);
        }
    }

    return 0;

out:
    // TODO: deallocate memory on failure
    return retval;
}

int
rtld_init(Rtld* r, const struct DispatcherInfo* disp_info) {
    size_t table_size = sizeof(RtldObject) * (1 << RTLD_HASH_BITS);
    RtldObject* objects = mem_alloc_data(table_size, getpagesize());
    if (BAD_ADDR(objects))
        return (int) (uintptr_t) objects;

    r->objects = objects;
    r->perfmap_fd = -1;
    r->perfdump_fd = -1;
    r->disp_info = disp_info;

    int retval = plt_create(disp_info, &r->plt);
    if (retval < 0)
        return retval;

    return 0;
}

int
rtld_resolve(Rtld* r, uintptr_t addr, void** out_entry) {
    if (!addr) // 0 is reserved for "empty"
        return -ENOENT;
    size_t hash = RTLD_HASH(addr);
    for (size_t i = 0; i <= RTLD_HASH_MASK; i++) {
        RtldObject* obj = &r->objects[(hash + i) & RTLD_HASH_MASK];
        uintptr_t obj_addr = atomic_load_explicit(&obj->addr, memory_order_acquire);
        if (!obj_addr)
            break;
        if (obj_addr == addr) {
            *out_entry = obj->entry;
            return 0;
        }
    }

    return -ENOENT;
}

void
rtld_patch(struct RtldPatchData* patch_data, void* sym) {
    // Ignore relocations failures and cases where nothing is to patch.
    char reloc_buf[8];
    if (!patch_data)
        return;
    if (patch_data->rel_size > sizeof reloc_buf)
        return;
    memcpy(reloc_buf, (void*) patch_data->patch_addr, patch_data->rel_size);
    (void) rtld_reloc_at(patch_data, reloc_buf, sym);
    mem_write_code((void*) patch_data->patch_addr, reloc_buf, patch_data->rel_size);
}
