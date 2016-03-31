/**
 * This file is part of x64vcpu.
 *
 * Copyright (C) 2016 Bogdan Blagaila <bogdan.blagaila@gmail.com>.
 * All rights reserved.
 * 
 * x64cpu is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 * 
 * x64cpu is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with x64cpu. If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "ElfLoader.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <vector>


/* ------------------------------------------------------------------------- */
ElfLoader::ElfLoader() {
}
/* ------------------------------------------------------------------------- */
ElfLoader::~ElfLoader() {
}
/* ------------------------------------------------------------------------- */
int ElfLoader::loadProcess(Process *proc, struct elf_file *elf, const char *module_name,
                            Thread **out_main_thread) {
    int ret = -1;
    ElfLoader *self = NULL;
    struct LoadData load_data;

    /* Check ELF headers */
    if (elf->header.num_bits == ELF_CLASS_64 && elf->header.machine == ELF_MACHINE_X86_64) {
    }
#if 0
    else if (elf->header.num_bits == ELF_CLASS_32 && elf->header.machine == ELF_MACHINE_I386) {
    }
#endif
    else {
        /* Arch not supported */
        ret = ERROR_NOT_SUPPORTED_ARCH;
        goto _err;
    }

    self = new ElfLoader();
    self->proc = proc;
    self->pdata = (struct EnvLinux::ProcessData*)proc->user_data;
    self->env = (EnvLinux*)proc->getEnvironment();

    ret = self->loadImage(elf, module_name, 1, &load_data, NULL);
    if (ret != 0) {
        goto _err;
    }

    /* Create main thread */
    self->thread = proc->createThread(load_data.start_rip);

    ret = self->buildEnv(&load_data, self->thread, elf, module_name);
    if (ret != 0) {
        goto _err;
    }

    /* Success */
    ret = 0;

    if (out_main_thread) {
        (*out_main_thread) = self->thread;
    }

_err:
    return ret;
}
/* ------------------------------------------------------------------------- */
static int stack_push_64(Process *proc, Thread *th, uint64_t value) {
    int rc;
    uint64_t rsp;

    th->saved_regs.rsp -= 8;
    rsp = th->saved_regs.rsp;

    rc = x64cpu_vmem_write(&proc->memory, rsp, (uint8_t*)&value, sizeof(value),
                            (enum x64cpu_mem_access_flags)0, NULL);
    if (rc != 0) {
        return -1;
    }

    return 0;
}

static int stack_push_string(Process *proc, Thread *th, const char *str) {
    int rc;
    size_t len;
    uint64_t rsp;

    rsp = th->saved_regs.rsp;
    len = strlen(str) + 1;
    rsp -= len;

    rc = x64cpu_vmem_copyto(&proc->memory, rsp, (uint8_t*)str, len);
    if (rc != len) {
        return -1;
    }

    th->saved_regs.rsp = rsp;

    return 0;
}

#define AT_NULL   0	/* end of vector */
#define AT_IGNORE 1	/* entry should be ignored */
#define AT_EXECFD 2	/* file descriptor of program */
#define AT_PHDR   3	/* program headers for program */
#define AT_PHENT  4	/* size of program header entry */
#define AT_PHNUM  5	/* number of program headers */
#define AT_PAGESZ 6	/* system page size */
#define AT_BASE   7	/* base address of interpreter */
#define AT_FLAGS  8	/* flags */
#define AT_ENTRY  9	/* entry point of program */
#define AT_NOTELF 10	/* program is not ELF */
#define AT_UID    11	/* real uid */
#define AT_EUID   12	/* effective uid */
#define AT_GID    13	/* real gid */
#define AT_EGID   14	/* effective gid */
#define AT_PLATFORM 15  /* string identifying CPU for optimizations */
#define AT_HWCAP  16    /* arch dependent hints at CPU capabilities */
#define AT_CLKTCK 17	/* frequency at which times() increments */
/* AT_* values 18 through 22 are reserved */
#define AT_SECURE 23   /* secure mode boolean */
#define AT_BASE_PLATFORM 24	/* string identifying real platform, may
				 * differ from AT_PLATFORM. */
#define AT_RANDOM 25	/* address of 16 random bytes */
#define AT_HWCAP2 26	/* extension of AT_HWCAP */

#define AT_EXECFN  31	/* filename of program */

#define AT_SYSINFO           32
#define AT_SYSINFO_EHDR      33


#define NEW_AUX_ENT(id, val) \
    do {\
        elf_info[el_index++] = id; \
        elf_info[el_index++] = val; \
    } while (0);

#define _push(val) { if (stack_push_64(proc, th, (val)) != 0) { env->log("[*] ElfLoader: Error pushing stack value. rsp: 0x%lx.", th->saved_regs.rsp); } }
#define _push_s(val) { if (stack_push_string(proc, th, (val)) != 0) { env->log("[*] ElfLoader: Error pushing stack value. rsp: 0x%lx.", th->saved_regs.rsp); } }
#define _align(rsp) { (rsp) = ((rsp) & (~0x07)); }

int ElfLoader::buildEnv(struct LoadData *load_data, Thread *th, struct elf_file *elf, const char *binary_path) {
    int ret = -1;

    uint64_t elf_info[256];
    uint64_t el_index = 0;

    uint64_t cpu_capability = 0x178bfbff; /* TODO: what should this be ? */
    uint64_t execfn_addr = 0x00;
    uint64_t platform_addr = 0x00;
    uint64_t random_bytes_addr = 0x00;
    int64_t i;
    ssize_t j;

    std::vector<uint64_t> a_env;
    std::vector<uint64_t> a_argv;

    _push(0x00);

    _push_s(binary_path);
    execfn_addr = th->saved_regs.rsp;

    /* Push environment variables */
    {
        Process::EnvironmentMap::iterator itr = proc->environment_variables.begin();

        for ( ; itr != proc->environment_variables.end(); itr++) {
            std::string tmp;

            tmp = itr->first;
            tmp += "=";
            tmp += itr->second;

            _push_s(tmp.c_str());
            a_env.push_back(th->saved_regs.rsp);
        }
    }

    /* Push arguments */
    {
        Process::ArgumentList::iterator itr = proc->arguments.begin();

        for ( ; itr != proc->arguments.end(); itr++) {
            _push_s((*itr).c_str());
            a_argv.push_back(th->saved_regs.rsp);
        }
    }

    _align(th->saved_regs.rsp);

    _push_s("x86_64");
    platform_addr = th->saved_regs.rsp;
    _push(0x1234);
    random_bytes_addr = th->saved_regs.rsp;

    memset(&elf_info, 0, sizeof(elf_info));

    /* Load Aux Table */
    // NEW_AUX_ENT(AT_SYSINFO_EHDR, vdso_addr);

    NEW_AUX_ENT(AT_HWCAP, cpu_capability);
    NEW_AUX_ENT(AT_PAGESZ, X64CPU_VMEM_PAGE_SIZE);
    NEW_AUX_ENT(AT_CLKTCK, 100);
    NEW_AUX_ENT(AT_PHDR, load_data->header_addr);
    NEW_AUX_ENT(AT_PHENT, elf->header.ph_ent_size);
    NEW_AUX_ENT(AT_PHNUM, elf->header.ph_num);
    NEW_AUX_ENT(AT_BASE, load_data->interp_load_addr);
    NEW_AUX_ENT(AT_FLAGS, 0);
    NEW_AUX_ENT(AT_ENTRY, elf->header.entry_pointer);
    NEW_AUX_ENT(AT_UID, pdata->uid);
    NEW_AUX_ENT(AT_EUID, pdata->euid);
    NEW_AUX_ENT(AT_GID, pdata->gid);
    NEW_AUX_ENT(AT_EGID, pdata->egid);
    NEW_AUX_ENT(AT_SECURE, 0);
    NEW_AUX_ENT(AT_RANDOM, random_bytes_addr);
    NEW_AUX_ENT(AT_EXECFN, execfn_addr);
    NEW_AUX_ENT(AT_PLATFORM, platform_addr);

    NEW_AUX_ENT(AT_NULL, 0);

    _align(th->saved_regs.rsp);
    for (i = el_index - 1; i >= 0; i--) {
        _push(elf_info[i]);
    }

    _push(0);
    for (j = a_env.size() - 1; j >= 0; j--) {
        _push(a_env[j]);
    }

    _push(0);
    for (j = a_argv.size() - 1; j >= 0; j--) {
        _push(a_argv[j]);
    }
    _push(a_argv.size());


    env->log("[*] ElfLoader: Start stack ptr: 0x%016lx", th->saved_regs.rsp);
    env->log("[*] ElfLoader: Heap base at: 0x%016lx", pdata->heap_base);

    /* Success */
    ret = 0;

_err:
    return ret;
}
/* ------------------------------------------------------------------------- */
int ElfLoader::loadImage(struct elf_file *elf, const char *module_name,
                            int main_module, struct LoadData *load_data,
                            uint64_t *out_base_offset) {
    int ret = -1;
    uint16_t i;
    uint64_t start_rip = 0;
    uint64_t header_addr = 0;
    uint64_t heap_base = 0;
    uint64_t interp_offset = 0;

    uint64_t base_offset = 0;
    struct elf_file *interp_elf = NULL;

    if (!main_module) {
        ret = proc->findAddrForSegment(pdata->maps_arena, elf->memory_size,
                                                1, 0x1000, &base_offset);
        if (ret != 0) {
            /* Out of memory ? */
            ret = -1;
            goto _err;
        }
    }

    start_rip = elf->header.entry_pointer;

    for (i = 0; i < elf->header.ph_num; i++) {
        struct elf_program_header *ph = &elf->p_header[i];

        switch (ph->type) {
            case ELF_SEGMENT_TYPE_NULL:
            case ELF_SEGMENT_TYPE_NOTE:
                break;

            case ELF_SEGMENT_TYPE_INTERP: {
                    char *name = NULL;

                    if (!main_module) {
                        continue;
                    }

                    name = (char*)(ph->data);

                    env->log("[*] ElfLoader: Using interpreter: %s.", name);

                    // TODO: get interp elf
                    ret = loadElfFromFile(name, &interp_elf);
                    if (ret != 0) {
                        goto _err;
                    }

                    ret = loadImage(interp_elf, name, 0, NULL, &interp_offset);
                    if (ret != 0) {
                        goto _err;
                    }

                    start_rip = interp_offset + interp_elf->header.entry_pointer;

                    env->log("[*] ElfLoader: Interpreter loaded at 0x%lx.", interp_offset);
                }
                break;

            case ELF_SEGMENT_TYPE_PHDR:
                header_addr = ph->p_vaddr;
                break;

            case ELF_SEGMENT_TYPE_LOAD: {
                    uint64_t aligned_address, align_mask = -1, aligned_size = 0, vaddr = 0;
                    int flags;
                    struct Process::Segment *segment = NULL;

                    // TODO: sanity checks
                    if (ph->p_memsz == 0) {
                        continue;
                    }

                    if (ph->p_filesz > ph->p_memsz) {
                        env->log("[*] ElfLoader: Invalid section. filesz > memsz.");
                        ret = -1;
                        goto _err;
                    }

                    flags = Process::PROT_READ | Process::PROT_WRITE | Process::PROT_EXEC;

                    vaddr = ph->p_vaddr + base_offset;
#if 0
                    if (ph->alignment > 0) {
                        align_mask = (~(ph->alignment - 1));
                    }
#else
                    align_mask = X64CPU_VMEM_PAGE_ADDR_MASK;
#endif
                    aligned_address = (vaddr & align_mask);
                    aligned_size = (ph->p_memsz + (vaddr - aligned_address));

                    segment = proc->addSegment(aligned_address, (aligned_address + aligned_size),
                                                flags, module_name, NULL);
                    if (segment == NULL) {
                        /* Out of memory ? */
                        ret = -1;
                        goto _err;
                    }

                    /* Adjust heap base */
                    if (main_module && ((aligned_address + aligned_size) > heap_base)) {
                        heap_base = ((aligned_address + aligned_size) & X64CPU_VMEM_PAGE_ADDR_MASK);
                        heap_base += X64CPU_VMEM_PAGE_SIZE;
                    }

                    /* Load data */
                    if (ph->p_filesz > 0) {
                        int rc;

                        rc = x64cpu_vmem_copyto(&proc->memory, vaddr, ph->data, ph->p_filesz);
                        if (rc < ph->p_filesz) {
                            /* Page Fault ? */
                            ret = -1;
                            goto _err;
                        }
                    }
                }
                break;

            default:
                /* Ignore */
                break;
        }
    }

    /* Success */
    ret = 0;

    if (out_base_offset) {
        (*out_base_offset) = base_offset;
    }

    if (load_data) {
        load_data->header_addr = header_addr;
        load_data->ph_ent = elf->header.ph_ent_size;
        load_data->ph_num = elf->header.ph_num;
        load_data->interp_load_addr = interp_offset;
        load_data->entry_point = elf->header.entry_pointer;
        load_data->start_rip = start_rip;
    }

    if (main_module) {
        pdata->heap_base = heap_base;
        pdata->heap_top = heap_base;
    }

_err:
    if (interp_elf) {
        elf_file_destroy(interp_elf);
    }
    return ret;
}
/* ------------------------------------------------------------------------- */
struct __io_ctx {
    FILE *fd;
    int err;
};

int __elf_io(enum elf_file_io_adapter_op op, void *user_data, void *buffer, int n) {
    struct __io_ctx *ctx = (struct __io_ctx*)user_data;
    int rc = -1;

    switch (op) {
        case ELF_FILE_IO_OP_SEEK: rc = fseek(ctx->fd, n, SEEK_SET); break;
        case ELF_FILE_IO_OP_READ: rc = fread(buffer, 1, n, ctx->fd); break;
    }

    if (rc < n) {
        ctx->err = errno;
    }

    return rc;
}

int ElfLoader::loadElfFromFile(const char *filename, struct elf_file **out_elf) {
    int ret = -1;
    struct __io_ctx ctx = {
        .fd = NULL,
        .err = 0
    };

    ctx.fd = fopen(filename, "rb");
    if (ctx.fd == NULL) {
        ret = -errno;
        goto _err;
    }

    ret = elf_file_load(__elf_io, (void*)&ctx, 1, out_elf);
    if (ret == -1) {
        if (ctx.err != 0) {
            ret = -errno;
        }
        else {
            ret = -1;
        }
    }
    else {
        ret = 0;
    }

_err:
    if (ctx.fd) {
        fclose(ctx.fd);
    }
    return ret;
}
/* ------------------------------------------------------------------------- */

