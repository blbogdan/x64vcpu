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

#include "elf-file.h"

#include <stdlib.h>
#include <string.h>


struct elf_file_io_ctx {
    elf_file_io_adapter_t fn;
    void *user_data;
};

#define READ(buf, size) {\
    int rc = io->fn(ELF_FILE_IO_OP_READ, io->user_data, (buf), (size)); \
    if (rc < 0) { \
        goto _err; \
    } \
}

#define SEEK(offset) {\
    int rc = io->fn(ELF_FILE_IO_OP_SEEK, io->user_data, NULL, (offset)); \
    if (rc < 0) { \
        goto _err; \
    } \
}

#define CHECK(cond, err) {\
    if (!(cond)) {\
        ret = (err); \
        goto _err; \
    }\
}


static int elf_file_read_header(struct elf_file_io_ctx *io, struct elf_file *elf) {
    int ret = -1;

    struct elf_header hdr;

    memset(&hdr, 0, sizeof(hdr));

    SEEK(0);

    /* Read first offsets; until 0x10 not affected by endianness */
    READ(&hdr.magic[0], 4);
    READ(&hdr.num_bits, 1);
    READ(&hdr.endianness, 1);
    READ(&hdr.elf_version, 1);
    READ(&hdr.os_abi, 1);
    READ(&hdr.os_abi_version, 1);
    READ(&hdr.__padding1[0], 7);

    /* Check Magic */
    CHECK(strncmp((char*)hdr.magic, "\x7F""ELF", 4) == 0, -1);

    /* Check endianness */
    CHECK(hdr.endianness == ELF_ENDIANNESS_LITTLE, -1);

    /* Check version */
    CHECK(hdr.elf_version == 1, -1);

    /* Read remaining header data */
    READ(&hdr.type, 2);
    READ(&hdr.machine, 2);
    READ(&hdr.elf_version2, 4);
    if (hdr.num_bits == ELF_CLASS_64) {
        READ(&hdr.entry_pointer, 8);
        READ(&hdr.ph_offset, 8);
        READ(&hdr.sh_offset, 8);
    }
    else if (hdr.num_bits == ELF_CLASS_32) {
        READ(&hdr.entry_pointer, 4);
        READ(&hdr.ph_offset, 4);
        READ(&hdr.sh_offset, 4);
    }
    else {
        /* Unsupported class */
        ret = -1;
        goto _err;
    }
    READ(&hdr.flags, 4);
    READ(&hdr.eh_size, 2);
    READ(&hdr.ph_ent_size, 2);
    READ(&hdr.ph_num, 2);
    READ(&hdr.sh_ent_size, 2);
    READ(&hdr.sh_num, 2);
    READ(&hdr.sh_str_index, 2);

    CHECK(hdr.elf_version2 == 1, -1);

    /* Check header size */
    if (hdr.num_bits == ELF_CLASS_64) {
        CHECK(hdr.eh_size == 64, -1);
    }
    else if (hdr.num_bits == ELF_CLASS_32) {
        CHECK(hdr.eh_size == 52, -1);
    }
    else {
        /* Unsupported class */
        ret = -1;
        goto _err;
    }

    /* Success */
    elf->header = hdr;
    ret = 0;

_err:
    return ret;
}

static int elf_file_read_ph(struct elf_file_io_ctx *io, struct elf_file *elf) {
    int ret = -1;
    struct elf_program_header *p_header = NULL;
    uint16_t ph_num = elf->header.ph_num;
    uint16_t ph_ent_size = elf->header.ph_ent_size;
    uint16_t i;
    off_t hdr_offset = elf->header.ph_offset;
    uint64_t end_addr;

    p_header = malloc(ph_num * sizeof(struct elf_program_header)); // ph_ent_size);
    if (p_header == NULL) {
        goto _end;
    }
    memset(p_header, 0, (ph_num * sizeof(struct elf_program_header))); // ph_ent_size));

    /* Seek offset */
    SEEK(hdr_offset);

    for (i = 0; i < ph_num; i++) {
        struct elf_program_header *ph = &p_header[i];

        ph->data = NULL;

        READ(&ph->type, 4);
        if (elf->header.num_bits == ELF_CLASS_32) {
            READ(&ph->p_offset, 4);
            READ(&ph->p_vaddr, 4);
            READ(&ph->p_paddr, 4);
            READ(&ph->p_filesz, 4);
            READ(&ph->p_memsz, 4);
            READ(&ph->flags, 4);
            READ(&ph->alignment, 4);
        }
        else {
            READ(&ph->flags, 4);
            READ(&ph->p_offset, 8);
            READ(&ph->p_vaddr, 8);
            READ(&ph->p_paddr, 8);
            READ(&ph->p_filesz, 8);
            READ(&ph->p_memsz, 8);
            READ(&ph->alignment, 8);
        }

        end_addr = ph->p_vaddr + ph->p_memsz;
        if (ph->p_vaddr < elf->mem_min_addr) {
            elf->mem_min_addr = ph->p_vaddr;
        }
        if (end_addr > elf->mem_max_addr) {
            elf->mem_max_addr = end_addr;
        }
    }

    /* Success */
    elf->p_header = p_header;
    p_header = NULL;
    ret = 0;

_err:
_end:
    if (p_header) {
        free(p_header);
    }
    return ret;
}

static int elf_file_read_sh(struct elf_file_io_ctx *io, struct elf_file *elf) {
    int ret = -1;
    struct elf_section_header *headers = NULL;
    uint16_t sh_num = elf->header.sh_num;
    uint16_t sh_ent_size = elf->header.sh_ent_size;
    uint16_t i;
    off_t hdr_offset = elf->header.sh_offset;

    headers = malloc(sh_num * sh_ent_size);
    if (headers == NULL) {
        goto _end;
    }
    memset(headers, 0, (sh_num * sh_ent_size));

    /* Seek offset */
    SEEK(hdr_offset);

    for (i = 0; i < sh_num; i++) {
        struct elf_section_header *sh = &headers[i];

        if (elf->header.num_bits == ELF_CLASS_32) {
            READ(&sh->name_index, 4);
            READ(&sh->type, 4);
            READ(&sh->flags, 4);
            READ(&sh->addr, 4);
            READ(&sh->offset, 4);
            READ(&sh->size, 4);
            READ(&sh->link, 4);
            READ(&sh->info, 4);
            READ(&sh->addr_align, 4);
            READ(&sh->ent_size, 4);
        }
        else if (elf->header.num_bits == ELF_CLASS_64) {
            READ(&sh->name_index, 4);
            READ(&sh->type, 4);
            READ(&sh->flags, 8);
            READ(&sh->addr, 8);
            READ(&sh->offset, 8);
            READ(&sh->size, 8);
            READ(&sh->link, 4);
            READ(&sh->info, 4);
            READ(&sh->addr_align, 8);
            READ(&sh->ent_size, 8);
        }
        else {
            goto _err;
        }
    }

    /* Success */
    elf->s_header = headers;
    headers = NULL;
    ret = 0;

_err:
_end:
    if (headers) {
        free(headers);
    }
    return ret;
}

static int elf_file_load_sections(struct elf_file_io_ctx *io, struct elf_file *elf) {
    int ret = -1;
    uint16_t ph_num = elf->header.ph_num;
    uint16_t i;

    for (i = 0; i < ph_num; i++) {
        struct elf_program_header *ph = &elf->p_header[i];
        uint64_t offset = ph->p_offset;
        uint64_t size = ph->p_filesz;

        SEEK(offset);

        ph->data = malloc(size);
        if (ph->data == NULL) {
            goto _err;
        }

        READ(ph->data, size);
    }

    /* Success */
    ret = 0;

_err:
    return ret;
}

int elf_file_load(elf_file_io_adapter_t io_adapter, void* io_user_data,
                    int load_section_data, struct elf_file **out_elf) {
    struct elf_file_io_ctx io = {
        .fn = io_adapter,
        .user_data = io_user_data
    };
    struct elf_file *elf = NULL;
    int rc;

    elf = calloc(1, sizeof(struct elf_file));
    if (elf == NULL) {
        return -1;
    }

    elf->mem_min_addr = 0xffffffffffffffff;
    elf->mem_max_addr = 0x00;

    rc = elf_file_read_header(&io, elf);
    if (rc != 0) {
        goto _end;
    }
    rc = elf_file_read_ph(&io, elf);
    if (rc != 0) {
        goto _end;
    }
    rc = elf_file_read_sh(&io, elf);
    if (rc != 0) {
        goto _end;
    }

    elf->memory_size = elf->mem_max_addr - elf->mem_min_addr;

    if (load_section_data) {
        rc = elf_file_load_sections(&io, elf);
        if (rc != 0) {
            goto _end;
        }
    }

    /* Success */
    rc = 0;

_end:
    if (rc == 0) {
        if (out_elf) {
            (*out_elf) = elf;
        }
    }
    else {
        if (elf) {
            elf_file_destroy(elf);
        }
    }
    return rc;
}

void elf_file_destroy(struct elf_file *elf) {
    uint16_t ph_num = elf->header.ph_num;
    uint16_t i;

    if (elf == NULL) {
        return;
    }
    if (elf->p_header) {
        free(elf->p_header);
    }

    for (i = 0; i < ph_num; i++) {
        struct elf_program_header *ph = &elf->p_header[i];
        if (ph->data) {
            free(ph->data);
        }
    }

    if (elf->s_header) {
        free(elf->s_header);
    }
    free(elf);  /*!<-- Dobby is free ! */
}

