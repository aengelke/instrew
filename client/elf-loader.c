
#include <common.h>
#include <elf.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/mman.h>
#include <linux/param.h>

#include <elf-loader.h>


static Elf_Phdr* load_elf_phdrs(Elf_Ehdr* elf_ex, int fd) {
    Elf_Phdr* phdata = NULL;
    int err = -1;

    if (elf_ex->e_phentsize != sizeof(Elf_Phdr))
        goto out;

    if (elf_ex->e_phnum < 1 || elf_ex->e_phnum > 65536U / sizeof(Elf_Phdr))
        goto out;

    size_t size = sizeof(Elf_Phdr) * elf_ex->e_phnum;
    if (size > 0x1000)
        goto out;

    phdata = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE,
                  MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (BAD_ADDR(phdata)) {
        phdata = NULL;
        goto out;
    }

    if (lseek(fd, elf_ex->e_phoff, SEEK_SET) == -1)
        goto out;

    if (read_full(fd, phdata, size) == -1)
        goto out;

    err = 0;

out:
    if (err && phdata != NULL) {
        munmap(phdata, 0x1000);
        phdata = NULL;
    }

    return phdata;
}

static size_t elf_mapping_size(Elf_Phdr* elf_phdata, size_t num_ph) {
    unsigned has_first = 0;
    uintptr_t start = 0;
    uintptr_t end = 0;
    for (size_t i = 0; i < num_ph; i++) {
        if (elf_phdata[i].p_type != PT_LOAD)
            continue;
        if (!has_first) {
            has_first = 1;
            start = ALIGN_DOWN(elf_phdata[i].p_vaddr, getpagesize());
        }
        end = elf_phdata[i].p_vaddr + elf_phdata[i].p_memsz;
    }
    return end - start;
}

static int
elf_map(uintptr_t addr, Elf_Phdr* elf_ppnt, int fd) {
    int retval;

    int prot = 0;
    if (elf_ppnt->p_flags & PF_R)
        prot |= PROT_READ;
    if (elf_ppnt->p_flags & PF_W)
        prot |= PROT_WRITE;
    if (elf_ppnt->p_flags & PF_X) {
        // Never map code as executable, since the host can't execute it.
    }

    size_t pagesz = getpagesize();

    uintptr_t mapstart = ALIGN_DOWN(addr, pagesz);
    uintptr_t mapend = ALIGN_UP(addr + elf_ppnt->p_filesz, pagesz);
    uintptr_t dataend = addr + elf_ppnt->p_filesz;
    uintptr_t allocend = addr + elf_ppnt->p_memsz;
    // Note: technically, the ALIGN_UP() is not necessary; but some ld versions
    // generate faulty PT_LOAD entries where zero-ing up to the page end is
    // assumed.
    if (prot & PROT_WRITE)
        allocend = ALIGN_UP(allocend, pagesz);
    uintptr_t mapoff = ALIGN_DOWN(elf_ppnt->p_offset, pagesz);

    if ((elf_ppnt->p_vaddr & (pagesz - 1)) != (elf_ppnt->p_offset & (pagesz - 1))) {
        printf("mapoff (%lx %lx pgsz=%lx)\n", elf_ppnt->p_vaddr,
               elf_ppnt->p_offset, pagesz);
        return -ENOEXEC;
    }

    if (mapend > mapstart) {
        void* mapret = mmap((void*) mapstart, mapend - mapstart, prot,
                            MAP_PRIVATE|MAP_FIXED, fd, mapoff);
        if (BAD_ADDR(mapret)) {
            puts("map (file)");
            retval = (int) (uintptr_t) mapret;
            goto out;
        }
    }

    if (allocend > dataend)
    {
        uintptr_t zeropage = ALIGN_UP(dataend, pagesz);
        if (allocend < zeropage)
            zeropage = allocend;

        if (zeropage > dataend)
        {
            // We have data at the last page of the segment that has to be
            // zeroed. If necessary, we have to give write privileges
            // temporarily.
            if ((prot & PROT_WRITE) == 0) {
                puts("zero (page end)");
                retval = mprotect((void*) ALIGN_DOWN(dataend, pagesz),
                                  pagesz, prot | PROT_WRITE);
                if (retval < 0)
                    goto out;
            }
            memset((void*) dataend, 0, zeropage - dataend);
            if ((prot & PROT_WRITE) == 0) {
                mprotect((void*) ALIGN_DOWN(dataend, pagesz), pagesz,
                         prot);
            }
        }

        // We have entire pages that have to be zeroed.
        if (allocend > zeropage) {
            void* mapret = mmap((void*) zeropage, allocend - zeropage, prot,
                                MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0);
            if (BAD_ADDR(mapret)) {
                puts("map (zero)");
                retval = (int) (uintptr_t) mapret;
                goto out;
            }
        }
    }

    retval = 0;

out:
    return retval;
}

// static int
// load_elf_interp(const char* filename)

int load_elf_binary(const char* filename, BinaryInfo* out_info) {
    int retval;
    int i;
    Elf_Phdr* elf_ppnt;

    int fd = open(filename, O_RDONLY, 0);
    if (fd < 0)     {
        retval = fd;
        goto out;
    }

    Elf_Ehdr elfhdr_ex;
    retval = read_full(fd, &elfhdr_ex, sizeof(Elf_Ehdr));
    if (retval < 0)
        goto out_close;

    retval = -ENOEXEC;
    if (memcmp(&elfhdr_ex, ELFMAG, SELFMAG) != 0)
        goto out_close;

    if (elfhdr_ex.e_ident[EI_CLASS] != ELFCLASS64)
        goto out_close;

    if (elfhdr_ex.e_type != ET_EXEC && elfhdr_ex.e_type != ET_DYN)
        goto out_close;

    Elf_Phdr* elf_phdata = load_elf_phdrs(&elfhdr_ex, fd);
    if (elf_phdata == NULL) {
        puts("Could not load phdata");
        goto out_close;
    }

    for (i = 0, elf_ppnt = elf_phdata; i < elfhdr_ex.e_phnum; i++, elf_ppnt++) {
        if (elf_ppnt->p_type == PT_INTERP) {
            // TODO: Support ELF interpreters
            puts("INTERP must not be set");
            goto out_free_ph;
        }
    }

    uintptr_t load_addr = 0;
    unsigned load_addr_set = 0;
    uintptr_t load_bias = 0;

    // TODO: Support GNU_STACK and architecture specific program headers
    // TODO: Support executable stack

    for (i = 0, elf_ppnt = elf_phdata; i < elfhdr_ex.e_phnum; i++, elf_ppnt++) {
        if (elf_ppnt->p_type != PT_LOAD)
            continue;

        if (elfhdr_ex.e_type == ET_DYN && !load_addr_set) {
            // TODO: handle the case where we have an ELF interpreter.
            // if (interpreter) {
            // } else {
            // Get a memory region that is large enough to hold the whole binary
            uintptr_t total_size = elf_mapping_size(elf_phdata, elfhdr_ex.e_phnum);
            if (total_size == 0) {
                retval = -ENOEXEC;
                goto out_free_ph;
            }

            void* load_bias_ptr = mmap(NULL, total_size, PROT_NONE,
                                       MAP_PRIVATE|MAP_NORESERVE|MAP_ANONYMOUS,
                                       -1, 0);
            if (BAD_ADDR(load_bias_ptr)) {
                retval = (int) (uintptr_t) load_bias_ptr;
                goto out_free_ph;
            }
            munmap(load_bias_ptr, total_size);

            load_bias = (uintptr_t) load_bias_ptr;
            // }
            load_bias = ALIGN_DOWN(load_bias - elf_ppnt->p_vaddr, getpagesize());
        }

        if (!load_addr_set) {
            load_addr_set = 1;
            load_addr = (elf_ppnt->p_vaddr-elf_ppnt->p_offset) + load_bias;
        }

        retval = elf_map(load_bias + elf_ppnt->p_vaddr, elf_ppnt, fd);
        if (retval < 0)
            goto out_free_ph;
    }

    if (out_info != NULL) {
        out_info->entry = (void*) (load_bias + elfhdr_ex.e_entry);
        out_info->machine = elfhdr_ex.e_machine;
        out_info->phdr = (Elf_Phdr*) (load_addr + elfhdr_ex.e_phoff);
        out_info->phnum = elfhdr_ex.e_phnum;
        out_info->phent = elfhdr_ex.e_phentsize;
    }

    retval = 0;

out_free_ph:
    munmap(elf_phdata, 0x1000);

out_close:
    close(fd);

out:
    return retval;
}
