
#include <common.h>
#include <elf.h>
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
#define elf_check_arch(x) ((x)->e_machine == EM_X86_64)
#elif defined(__aarch64__)
#define elf_check_arch(x) ((x)->e_machine == EM_AARCH64)
#else
#define elf_check_arch(x) (0)
#endif

#define PAGESIZE ((size_t) 0x1000)

#define CHECK_SIGNED_BITS(val,bits) \
            ((val) >= -(1ll << (bits)) && (val) < (1ll << bits)-1)

#define RTLD_HASH_BITS 17
#define RTLD_HASH_MASK ((1 << RTLD_HASH_BITS) - 1)
#define RTLD_HASH(addr) (((addr >> 2)) & RTLD_HASH_MASK)

struct PltEntry {
    const char* name;
    uintptr_t func;
};

// Declare functions, but avoid name collision in C.
#define PLT_ENTRY(name, func) \
        extern char PASTE(rtld_plt_, func) __asm__(STRINGIFY(func));
#include "plt.inc"
#undef PLT_ENTRY

static const struct PltEntry plt_entries[] = {
#define PLT_ENTRY(name, func) { name, (uintptr_t) &(PASTE(rtld_plt_, func)) },
#include "plt.inc"
#undef PLT_ENTRY
    { NULL, 0 }
};

#if defined(__x86_64__)
#define PLT_FUNC_SIZE 8
#else
#error "currently unsupported architecture"
#endif

static int
plt_create(void** out_plt) {
    size_t plt_entry_count = sizeof(plt_entries) / sizeof(plt_entries[0]) - 1;
    size_t code_size = plt_entry_count * PLT_FUNC_SIZE;
    size_t data_offset = ALIGN_UP(code_size, 0x40);
    size_t data_size = plt_entry_count * sizeof(uintptr_t);
    size_t plt_size = data_offset + data_size;

    uint8_t* plt = mem_alloc(plt_size);
    if (BAD_ADDR(plt))
        return (int) (uintptr_t) plt;

    for (size_t i = 0; i < plt_entry_count; i++) {
        uint8_t* code_ptr = plt + i * PLT_FUNC_SIZE;
        uint8_t* data_ptr = plt + data_offset + i * sizeof(uintptr_t);

        *((uintptr_t*) data_ptr) = plt_entries[i].func;
#if defined(__x86_64__)
        uint64_t offset = data_ptr - code_ptr - 6;
        // This is: "jmp [rip + offset]; ud2"
        *((uint64_t*) code_ptr) = 0x0b0f0000000025ff | (offset << 16);
#else
#error
#endif // defined(__x86_64__)
    }

    int retval = mprotect(plt, plt_size, PROT_READ|PROT_EXEC);
    if (retval < 0)
        return retval;

    *out_plt = plt;
    return 0;
}

static uintptr_t
rtld_decode_name(const char* name) {
    if (name[0] != 'Z')
        return 0;
    uintptr_t addr = 0;
    for (unsigned k = 1; name[k] && name[k] != '_'; k++) {
        if (name[k] < '0' || name[k] >= '8')
            return 0;
        addr = (addr << 3) | (name[k] - '0');
    }
    return addr;
}

static RtldObject*
rtld_hash_lookup(Rtld* r, uintptr_t addr) {
    size_t hash = RTLD_HASH(addr);
    size_t end = ((hash-1) & RTLD_HASH_MASK);
    if (hash == end)
        __builtin_unreachable();
    for (size_t i = hash; i != end; i = (i+1) & RTLD_HASH_MASK) {
        RtldObject* obj = &r->objects[i];
        if (LIKELY(obj->addr == addr || obj->addr == 0))
            return obj;
        // dprintf(2, "! Collision for %lx: %lx\n", addr, obj->addr);
    }
    dprintf(2, "hashtable full!\n");
    return NULL;
}

struct RtldElf {
    uint8_t* base;
    size_t size;
    Elf64_Ehdr* re_ehdr;
    Elf64_Shdr* re_shdr;

    // Global PLT
    Rtld* rtld;
};
typedef struct RtldElf RtldElf;

static int
rtld_elf_init(RtldElf* re, void* obj_base, size_t obj_size, Rtld* rtld) {
    if (obj_size < sizeof(Elf64_Ehdr))
        goto err;

    re->base = obj_base;
    re->size = obj_size;
    re->re_ehdr = obj_base;
    re->rtld = rtld;

    if (memcmp(re->re_ehdr, ELFMAG, SELFMAG) != 0)
        goto err;
    if (re->re_ehdr->e_type != ET_REL)
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
rtld_elf_resolve_sym(RtldElf* re, size_t symtab_idx, size_t sym_idx, uintptr_t* out_addr) {
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
        } else {
            // Search through PLT
            for (size_t i = 0; plt_entries[i].name; i++) {
                if (!strcmp(name, plt_entries[i].name)) {
                    *out_addr = (uintptr_t) re->rtld->plt + i * PLT_FUNC_SIZE;
                    return 0;
                }
            }

            uintptr_t addr = rtld_decode_name(name);
            if (addr && !rtld_resolve(re->rtld, addr, (void**) out_addr))
                return 0;

            dprintf(2, "undefined symbol reference to %s\n", name);
            return -EINVAL;
        }
    } else if (sym->st_shndx == SHN_ABS) {
        *out_addr = sym->st_value;
    } else if (sym->st_shndx < re->re_ehdr->e_shnum) {
        Elf64_Shdr* tgt_shdr = re->re_shdr + sym->st_shndx;
        *out_addr = (uintptr_t) re->base + tgt_shdr->sh_offset + sym->st_value;
    } else {
        return -EINVAL;
    }

    return 0;
}

static int
rtld_elf_add_stub(uintptr_t sym, uintptr_t* out_stub) {
#if defined(__aarch64__)
    uint32_t* stub = mem_alloc(5 * sizeof(uint32_t));
    if (BAD_ADDR(stub))
        return (int) (uintptr_t) stub;

    stub[0] = 0xd2800010 | (((sym >> 0) & 0xffff) << 5); // movz x16, ...
    stub[1] = 0xf2a00010 | (((sym >> 16) & 0xffff) << 5); // movk x16, ..., lsl 16
    stub[2] = 0xf2c00010 | (((sym >> 32) & 0xffff) << 5); // movk x16, ..., lsl 32
    stub[3] = 0xf2e00010 | (((sym >> 48) & 0xffff) << 5); // movk x16, ..., lsl 48
    stub[4] = 0xd61f0200; // br x16

    int retval = mprotect(stub, 5 * sizeof(uint32_t), PROT_READ|PROT_EXEC);
    if (retval < 0)
        return retval;

    *out_stub = (uintptr_t) stub;
    return 0;
#else
    (void) sym;
    (void) out_stub;
    return -EOPNOTSUPP;
#endif
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
    uint8_t* tgt_sec_addr = re->base + tgt_shdr->sh_offset;

    unsigned symtab_idx = rela_shdr->sh_link;

    for (; elf_rela != elf_rela_end; ++elf_rela) {
        // TODO: ensure that size doesn't overflow
        if (elf_rela->r_offset >= tgt_shdr->sh_size)
            return -EINVAL;

        unsigned sym_idx = ELF64_R_SYM(elf_rela->r_info);
        uint8_t* tgt = tgt_sec_addr + elf_rela->r_offset;

        switch (ELF64_R_TYPE(elf_rela->r_info)) {
        case R_X86_64_64: {
            uint64_t sym;
            if (rtld_elf_resolve_sym(re, symtab_idx, sym_idx, &sym) < 0)
                return -EINVAL;
            *((uint64_t*) tgt) = sym + elf_rela->r_addend;
            break;
        }
        case R_X86_64_PC32: {
            uint64_t sym;
            if (rtld_elf_resolve_sym(re, symtab_idx, sym_idx, &sym) < 0)
                return -EINVAL;
            int64_t off = sym + elf_rela->r_addend - (uint64_t) tgt;
            if (!CHECK_SIGNED_BITS(off, 32)) {
                dprintf(2, "relocation offset too large (pc32): %lx\n", off);
                return -EINVAL;
            }
            *((int32_t*) tgt) = off;
            break;
        }
        case R_X86_64_PLT32: {
            uint64_t sym;
            if (rtld_elf_resolve_sym(re, symtab_idx, sym_idx, &sym) < 0)
                return -EINVAL;
            int64_t off = sym + elf_rela->r_addend - (uint64_t) tgt;
            if (!CHECK_SIGNED_BITS(off, 32)) {
                dprintf(2, "relocation offset too large (plt32): %lx\n", off);
                return -EINVAL;
            }
            *((int32_t*) tgt) = off;
            break;
        }
        case R_X86_64_32S: {
            uint64_t sym;
            if (rtld_elf_resolve_sym(re, symtab_idx, sym_idx, &sym) < 0)
                return -EINVAL;
            int64_t val = sym + elf_rela->r_addend;
            if (!CHECK_SIGNED_BITS(val, 32)) {
                dprintf(2, "relocation offset too large (32s): %lx\n", val);
                return -EINVAL;
            }
            *((int32_t*) tgt) = val;
            break;
        }
        case R_X86_64_PC64: {
            uint64_t sym;
            if (rtld_elf_resolve_sym(re, symtab_idx, sym_idx, &sym) < 0)
                return -EINVAL;
            *((uint64_t*) tgt) = sym + elf_rela->r_addend - (uint64_t) tgt;
            break;
        }
        case R_AARCH64_PREL32: {
            uint64_t sym;
            if (rtld_elf_resolve_sym(re, symtab_idx, sym_idx, &sym) < 0)
                return -EINVAL;
            ptrdiff_t off = sym + elf_rela->r_addend - (uint64_t) tgt;
            if (!CHECK_SIGNED_BITS(off >> 2, 32)) {
                dprintf(2, "relocation offset too large (prel32): %lx\n", off);
                return -EINVAL;
            }
            *((int32_t*) tgt) = (int32_t) (off);
            break;
        }
        case R_AARCH64_CALL26: {
            uint64_t sym;
            if (rtld_elf_resolve_sym(re, symtab_idx, sym_idx, &sym) < 0)
                return -EINVAL;
            ptrdiff_t off = sym + elf_rela->r_addend - (uint64_t) tgt;
            if (off & 3) {
                dprintf(2, "relocation offset misaligned (call26): %lx\n", off);
                return -EINVAL;
            }
            if (!CHECK_SIGNED_BITS(off >> 2, 26)) {
                // Ok, let's create a stub.
                uintptr_t stub = 0;
                int ret = rtld_elf_add_stub(sym + elf_rela->r_addend, &stub);
                if (ret < 0)
                    return ret;
                off = stub - (uintptr_t) tgt;
                if (!CHECK_SIGNED_BITS(off >> 2, 26)) {
                    dprintf(2, "relocation offset too large (call26,stub): %lx\n", off);
                    return -EINVAL;
                }
            }
            uint32_t insn = (*(uint32_t*) tgt) & 0xfc000000;
            *((uint32_t*) tgt) = insn | ((off >> 2) & 0x3ffffff);
            break;
        }
        case R_AARCH64_MOVW_UABS_G0_NC: {
            uint64_t sym;
            if (rtld_elf_resolve_sym(re, symtab_idx, sym_idx, &sym) < 0)
                return -EINVAL;
            sym += elf_rela->r_addend;
            *((int32_t*) tgt) |= (int32_t) ((sym & 0xffff) << 5);
            break;
        }
        case R_AARCH64_MOVW_UABS_G1_NC: {
            uint64_t sym;
            if (rtld_elf_resolve_sym(re, symtab_idx, sym_idx, &sym) < 0)
                return -EINVAL;
            sym += elf_rela->r_addend;
            *((int32_t*) tgt) |= (int32_t) (((sym >> 16) & 0xffff) << 5);
            break;
        }
        case R_AARCH64_MOVW_UABS_G2_NC: {
            uint64_t sym;
            if (rtld_elf_resolve_sym(re, symtab_idx, sym_idx, &sym) < 0)
                return -EINVAL;
            sym += elf_rela->r_addend;
            *((int32_t*) tgt) |= (int32_t) (((sym >> 32) & 0xffff) << 5);
            break;
        }
        case R_AARCH64_MOVW_UABS_G3: {
            uint64_t sym;
            if (rtld_elf_resolve_sym(re, symtab_idx, sym_idx, &sym) < 0)
                return -EINVAL;
            sym += elf_rela->r_addend;
            *((int32_t*) tgt) |= (int32_t) (((sym >> 48) & 0xffff) << 5);
            break;
        }
        default:
            dprintf(2, "unhandled relocation %u\n", ELF64_R_TYPE(elf_rela->r_info));
            return -EINVAL;
        }
    }

    return 0;
}

static int rtld_set(Rtld* r, uintptr_t addr, void* entry, void* obj_base,
                    size_t obj_size) {
    RtldObject* obj = rtld_hash_lookup(r, addr);
    if (obj == NULL)
        return -ENOSPC;
    if (obj->addr != 0)
        return -EEXIST;

    obj->addr = addr;
    obj->entry = entry;
    obj->base = obj_base;
    obj->size = obj_size;
    return 0;
}

int rtld_add_object(Rtld* r, void* obj_base, size_t obj_size) {
    // "Link" (fix) given ELF file.
    //  - check that all sections are non-writable
    //  - check that there is no GOT/PLT (we would have to really link stuff
    //    if that happens, but we are lazy)
    //  - apply relocations
    //  - find a single, visible and linkable function
    //  - TBD: check that sections don't overlap (?)

    int retval;

    RtldElf re;
    if ((retval = rtld_elf_init(&re, obj_base, obj_size, r)) < 0)
        goto out;

    uintptr_t entry = 0;

    int i, j;
    Elf64_Shdr* elf_shnt;
    for (i = 0, elf_shnt = re.re_shdr; i < re.re_ehdr->e_shnum; i++, elf_shnt++) {
        retval = -EINVAL;
        switch (elf_shnt->sh_type) {
        case SHT_SYMTAB:
            // Requires handling: extract symbol
            // look for a single entry "FUNC GLOBAL DEFAULT"
            if (elf_shnt->sh_entsize != sizeof(Elf64_Sym))
                goto out;
            Elf64_Sym* elf_sym = (Elf64_Sym*) ((uint8_t*) obj_base + elf_shnt->sh_offset);
            Elf64_Sym* elf_sym_end = elf_sym + elf_shnt->sh_size / sizeof(Elf64_Sym);
            for (j = 0; elf_sym != elf_sym_end; j++, elf_sym++) {
                if (ELF64_ST_BIND(elf_sym->st_info) != STB_GLOBAL)
                    continue;
                if (ELF64_ST_TYPE(elf_sym->st_info) != STT_FUNC)
                    continue;
                if (ELF64_ST_VISIBILITY(elf_sym->st_other) != STV_DEFAULT)
                    continue;
                if (rtld_elf_resolve_sym(&re, i, j, &entry) < 0)
                    goto out;

                // Determine address from name, encoded in Z<octaladdr>_ignored
                const char* name = NULL;
                rtld_elf_resolve_str(&re, elf_shnt->sh_link, elf_sym->st_name, &name);
                if (!name)
                    goto out;
                uintptr_t addr = rtld_decode_name(name);
                if (!addr) {
                    dprintf(2, "invalid function name %s\n", name);
                    goto out;
                }
                retval = rtld_set(r, addr, (void*) entry, obj_base, obj_size);
                if (retval < 0)
                    goto out;
            }
            break;
        case SHT_RELA:
            if (rtld_elf_process_rela(&re, i) < 0)
                goto out;
            break;
        case SHT_NULL:
        case SHT_PROGBITS:
        case SHT_STRTAB:
        case SHT_X86_64_UNWIND:
            // don't care too much
            if (elf_shnt->sh_flags & SHF_WRITE)
                goto out;
            break;
        case SHT_NOBITS: // .bss not supported
        default: // unhandled section header
            goto out;
        }
    }

    // Remap object file as executable
    retval = mprotect(obj_base, obj_size, PROT_READ|PROT_EXEC);
    if (retval < 0)
        goto out;

    retval = 0;

out:
    return retval;
}

int
rtld_init(Rtld* r) {
    RtldObject* objects = mem_alloc(sizeof(RtldObject) * (1 << RTLD_HASH_BITS));
    if (BAD_ADDR(objects))
        return (int) (uintptr_t) objects;

    r->objects = objects;

    int retval = plt_create(&r->plt);
    if (retval < 0)
        return retval;

    return 0;
}

int
rtld_resolve(Rtld* r, uintptr_t addr, void** out_entry) {
    RtldObject* obj = rtld_hash_lookup(r, addr);
    if (obj != NULL && obj->addr == addr) {
        *out_entry = obj->entry;
        return 0;
    }

    return -ENOENT;
}
