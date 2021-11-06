
#include <common.h>
#include <elf.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/limits.h>
#include <linux/mman.h>
#include <linux/param.h>

#include <elf-loader.h>


static int
elf_read(int fd, size_t off, void* buf, size_t nbytes) {
    if (lseek(fd, off, SEEK_SET) == -1)
        return -1;
    if (read_full(fd, buf, nbytes) == -1)
        return -1;
    return 0;
}

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

    if (elf_read(fd, elf_ex->e_phoff, phdata, size) == -1)
        goto out;

    err = 0;

out:
    if (err && phdata != NULL) {
        munmap(phdata, 0x1000);
        phdata = NULL;
    }

    return phdata;
}

static uintptr_t
elf_determine_load_bias(size_t num_ph, const Elf_Phdr elf_phdata[num_ph]) {
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
    if (start >= end)
        return (uintptr_t) -ENOEXEC;

    size_t total_size = end - start;
    void* load_bias_ptr = mmap(NULL, total_size, PROT_NONE,
                               MAP_PRIVATE|MAP_NORESERVE|MAP_ANONYMOUS,
                               -1, 0);
    if (BAD_ADDR(load_bias_ptr))
        return (uintptr_t) load_bias_ptr;
    munmap(load_bias_ptr, total_size);

    return (uintptr_t) load_bias_ptr - start;
}

static int
elf_map(uintptr_t addr, const Elf_Phdr* elf_ppnt, int fd) {
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

static uintptr_t
load_elf_interp(const Elf_Ehdr* interp_ehdr, const Elf_Phdr interp_phdata[],
                int interp_fd) {
    const Elf_Phdr* ppnt;
    int i;

    uintptr_t load_bias = 0;
    if (interp_ehdr->e_type == ET_DYN) {
        load_bias = elf_determine_load_bias(interp_ehdr->e_phnum, interp_phdata);
        if (BAD_ADDR(load_bias))
            return load_bias;
    }

    for (i = 0, ppnt = interp_phdata; i < interp_ehdr->e_phnum; i++, ppnt++) {
        if (ppnt->p_type != PT_LOAD)
            continue;

        int retval = elf_map(load_bias + ppnt->p_vaddr, ppnt, interp_fd);
        if (retval < 0)
            return retval;
    }

    return load_bias;
}

int load_elf_binary(const char* filename, BinaryInfo* out_info) {
    int retval;
    int i;
    Elf_Phdr* elf_ppnt;

    int interp_fd = -1;
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

    Elf_Ehdr interp_ehdr;
    Elf_Phdr* interp_phdata = NULL;
    for (i = 0, elf_ppnt = elf_phdata; i < elfhdr_ex.e_phnum; i++, elf_ppnt++) {
        if (elf_ppnt->p_type != PT_INTERP)
            continue;
        if (elf_ppnt->p_filesz > PATH_MAX || elf_ppnt->p_filesz < 2)
            goto out_free_ph;

        char interp_name[PATH_MAX];
        retval = elf_read(fd, elf_ppnt->p_offset, interp_name, elf_ppnt->p_filesz);
        if (retval < 0)
            goto out_free_ph;
        if (interp_name[elf_ppnt->p_filesz] != 0) {
            retval = -ENOEXEC;
            goto out_free_ph;
        }

        interp_fd = open(interp_name, O_RDONLY|O_CLOEXEC, 0);
        if (interp_fd < 0) {
            retval = fd;
            goto out_free_ph;
        }
        retval = elf_read(interp_fd, 0, &interp_ehdr, sizeof(Elf_Ehdr));
        if (retval < 0)
            goto out_free_ph;

        retval = -ELIBBAD;
        if (memcmp(&interp_ehdr, ELFMAG, SELFMAG) != 0)
            goto out_free_ph;
        if (interp_ehdr.e_ident[EI_CLASS] != ELFCLASS64)
            goto out_free_ph;
        if (interp_ehdr.e_type != ET_EXEC && interp_ehdr.e_type != ET_DYN)
            goto out_free_ph;
        if (interp_ehdr.e_machine != elfhdr_ex.e_machine)
            goto out_free_ph;

        interp_phdata = load_elf_phdrs(&interp_ehdr, interp_fd);
        if (interp_phdata == NULL) {
            puts("Could not load interp phdata");
            goto out_free_ph;
        }

        break;
    }

    uintptr_t load_bias = 0;
    if (elfhdr_ex.e_type == ET_DYN) {
        load_bias = elf_determine_load_bias(elfhdr_ex.e_phnum, elf_phdata);
        if (BAD_ADDR(load_bias)) {
            retval = (int) load_bias;
            goto out_free_ph;
        }
    }

    // TODO: Support GNU_STACK and architecture specific program headers
    // TODO: Support executable stack

    uintptr_t load_addr = 0;
    unsigned load_addr_set = 0;
    for (i = 0, elf_ppnt = elf_phdata; i < elfhdr_ex.e_phnum; i++, elf_ppnt++) {
        if (elf_ppnt->p_type != PT_LOAD)
            continue;

        if (!load_addr_set) {
            load_addr_set = 1;
            load_addr = (elf_ppnt->p_vaddr-elf_ppnt->p_offset) + load_bias;
        }

        retval = elf_map(load_bias + elf_ppnt->p_vaddr, elf_ppnt, fd);
        if (retval < 0)
            goto out_free_ph;
    }

    uintptr_t elf_entry = load_bias + elfhdr_ex.e_entry;
    uintptr_t entry = elf_entry;

    if (interp_fd >= 0) {
        uintptr_t interp_load_bias = load_elf_interp(&interp_ehdr, interp_phdata, interp_fd);
        if (BAD_ADDR(interp_load_bias)) {
            retval = interp_load_bias;
            goto out_free_ph;
        }

        entry = interp_load_bias + interp_ehdr.e_entry;
    }

    if (out_info != NULL) {
        out_info->elf_entry = (void*) elf_entry;
        out_info->exec_entry = (void*) entry;
        out_info->machine = elfhdr_ex.e_machine;
        out_info->phdr = (Elf_Phdr*) (load_addr + elfhdr_ex.e_phoff);
        out_info->phnum = elfhdr_ex.e_phnum;
        out_info->phent = elfhdr_ex.e_phentsize;
    }

    retval = 0;

out_free_ph:
    munmap(elf_phdata, 0x1000);
    if (interp_phdata)
        munmap(interp_phdata, 0x1000);

out_close:
    close(fd);
    if (interp_fd >= 0)
        close(interp_fd);

out:
    return retval;
}
