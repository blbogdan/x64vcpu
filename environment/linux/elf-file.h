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

#ifndef __ELF_FILE_H__
#define __ELF_FILE_H__

#include <stdint.h>


enum elf_class {
    ELF_CLASS_NONE      = 0,
    ELF_CLASS_32        = 0x01,
    ELF_CLASS_64        = 0x02
};

enum elf_endianness {
    ELF_ENDIANNESS_NONE     = 0,
    ELF_ENDIANNESS_LITTLE   = 0x01,
    ELF_ENDIANNESS_BIG      = 0x02,
};

enum elf_type {
    ELF_TYPE_NONE           = 0,
    ELF_TYPE_RELOCATABLE    = 0x01,
    ELF_TYPE_EXECUTABLE     = 0x02,
    ELF_TYPE_SHARED         = 0x03,
    ELF_TYPE_CORE           = 0x04
};

enum elf_machine {
    ELF_MACHINE_NONE        = 0,
    ELF_MACHINE_ARM         = 0x28,
    ELF_MACHINE_X86_64      = 0x3E,
};

struct elf_header {
    uint8_t     magic[4];           /*!< Must be (0x7F "ELF") */
    union {
        uint8_t     num_bits;           /*!< 1 - 32bit, 2 - 64bit */
        enum elf_class num_bits_e;
    };
    uint8_t     endianness;          /*!< 1 - little, 2 - big */
    uint8_t     elf_version;        /*!< 1 - version of ELF */
    uint8_t     os_abi;             /*!< 0 - systemv, 3 - linux */
    uint8_t     os_abi_version;     /*!< 0 - unused ? */
    uint8_t     __padding1[7];      /*!< Unused / Padding */
    uint16_t    type;               /*!< 1 - relocatable, 2 - executable, 3 - shared, 4 - core */
    uint16_t    machine;            /*!< 0x00 - none, 0x28 - ARM, 0x3E - x86-64 */
    uint32_t    elf_version2;       /*!< 1 - version of ELF */

    /* 32bit/64bit - serializer will take care of it */
    uint64_t    entry_pointer;      /*!< Execution entry point */
    uint64_t    ph_offset;          /*!< Program header offset */
    uint64_t    sh_offset;          /*!< Section header offset */
    uint32_t    flags;              /*!< Interpretation depends on target architecture */
    uint16_t    eh_size;            /*!< Size of this header: 64 bytes for 64bit, 52 bytes for 32bit */
    uint16_t    ph_ent_size;        /*!< Program header entry size */
    uint16_t    ph_num;             /*!< Program header num entries */
    uint16_t    sh_ent_size;        /*!< Section header entry size */
    uint16_t    sh_num;             /*!< Section header num entries */
    uint16_t    sh_str_index;       /*!< Index in section header that contains the section names */
};

enum elf_segment_type {
    ELF_SEGMENT_TYPE_NULL       = 0x00,
    ELF_SEGMENT_TYPE_LOAD       = 0x01,     /*!< Create zero'd segment and load bytes from file */
    ELF_SEGMENT_TYPE_DYNAMIC    = 0x02,     /*!< Requires dynamic linking */
    ELF_SEGMENT_TYPE_INTERP     = 0x03,     /*!< Contains a file path to interpreter executable */
    ELF_SEGMENT_TYPE_NOTE       = 0x04,     /*!< Notes section */
    ELF_SEGMENT_TYPE_SHLIB      = 0x05,     /*!< Reserved */
    ELF_SEGMENT_TYPE_PHDR       = 0x06,     /*!< Program Header */

    ELF_SEGMENT_TYPE_GNU_EH_FRAME   = 0x6474e550,
    ELF_SEGMENT_TYPE_GNU_STACK      = 0x6474e551,
    ELF_SEGMENT_TYPE_GNU_RELRO      = 0x6474e552,
};

enum elf_segment_flags {
    ELF_SEGMENT_FLAGS_NONE      = 0x00,
    ELF_SEGMENT_FLAGS_E         = 0x01,     /*!< Executable */
    ELF_SEGMENT_FLAGS_W         = 0x02,     /*!< Writable */
    ELF_SEGMENT_FLAGS_R         = 0x04,     /*!< Readable */
};

struct elf_program_header {
    uint32_t    type;               /*!< Segment type */
    uint32_t    flags;              /*!< Segment flags */
    uint64_t    p_offset;           /*!< Offset to segment in file image */
    uint64_t    p_vaddr;            /*!< Virtual address of segment */
    uint64_t    p_paddr;            /*!< Physical address of segment */
    uint64_t    p_filesz;           /*!< Segment size in file image */
    uint64_t    p_memsz;            /*!< Segment size in memory */
    uint64_t    alignment;          /*!< The required alignment; must be power of 2 */

    uint8_t     *data;              /*!< Section data buffer */
};

enum elf_section_type {
    ELF_SECTION_TYPE_NULL       = 0x00,
    ELF_SECTION_TYPE_PROGBITS   = 0x01,
    ELF_SECTION_TYPE_SYMTAB     = 0x02,
    ELF_SECTION_TYPE_STRTAB     = 0x03,
    ELF_SECTION_TYPE_RELA       = 0x04,
    ELF_SECTION_TYPE_HASH       = 0x05,
    ELF_SECTION_TYPE_DYNAMIC    = 0x06,
    ELF_SECTION_TYPE_NOTE       = 0x07,
    ELF_SECTION_TYPE_NOBITS     = 0x08,
    ELF_SECTION_TYPE_REL        = 0x09,
    ELF_SECTION_TYPE_SHLIB      = 0x0A,
    ELF_SECTION_TYPE_DYNSYM     = 0x0B,
    ELF_SECTION_TYPE_LOPROC     = 0x70000000,
    ELF_SECTION_TYPE_HIPROC     = 0x7fffffff,
    ELF_SECTION_TYPE_LOUSER     = 0x80000000,
    ELF_SECTION_TYPE_HIUSER     = 0xffffffff
};

struct elf_section_header {
    uint32_t    name_index;         /*!< Section name index */
    uint32_t    type;               /*!< Section type */
    uint64_t    flags;              /*!< Section flags */
    uint64_t    addr;               /*!< Address in memory image of process */
    uint64_t    offset;             /*!< Section offset in file */
    uint64_t    size;               /*!< Section size in file */
    uint32_t    link;               /*!< Section header table link ? */
    uint32_t    info;               /*!< Interpretation depends on section type */
    uint64_t    addr_align;         /*!< Address align restriction; must be power of 2 */
    uint64_t    ent_size;           /*!< Section table size */
};

struct elf_file {
    struct elf_header           header;
    struct elf_program_header   *p_header;
    struct elf_section_header   *s_header;

    uint64_t mem_min_addr;
    uint64_t mem_max_addr;
    uint64_t memory_size;
};


enum elf_file_io_adapter_op {
    ELF_FILE_IO_OP_NONE = 0,
    ELF_FILE_IO_OP_READ,
    ELF_FILE_IO_OP_SEEK
};

typedef int (*elf_file_io_adapter_t)(enum elf_file_io_adapter_op op, void *user_data,
                                        void *buffer, int n);


int elf_file_load(elf_file_io_adapter_t io_adapter, void* io_user_data,
                    int load_section_data, struct elf_file **out_elf);

void elf_file_destroy(struct elf_file *elf);

#endif /* __ELF_FILE_H__ */

