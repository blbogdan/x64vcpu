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


#ifndef __VIRTUAL_MEMORY_H__
#define __VIRTUAL_MEMORY_H__

#include "cpu.h"

#include <stdint.h>


enum x64cpu_vmem_page_flags {
    X64CPU_VMEM_PAGE_FLAG_P      = (1 << 0), /*!< Present */
    X64CPU_VMEM_PAGE_FLAG_RW     = (1 << 1), /*!< Read/Write */
    X64CPU_VMEM_PAGE_FLAG_U      = (1 << 2), /*!< User/Supervisor */
    X64CPU_VMEM_PAGE_FLAG_W      = (1 << 3), /*!< Write Through */
    X64CPU_VMEM_PAGE_FLAG_C      = (1 << 4), /*!< Cache disabled */
    X64CPU_VMEM_PAGE_FLAG_A      = (1 << 5), /*!< Accessed */
    X64CPU_VMEM_PAGE_FLAG_D      = (1 << 6), /*!< Dirty */
    X64CPU_VMEM_PAGE_FLAG_S      = (1 << 7), /*!< Page Size (0 for 4kb) */
    X64CPU_VMEM_PAGE_FLAG_G      = (1 << 8), /*!< Ignored */

    X64CPU_VMEM_PAGE_FLAG_ALLOC  = (1 << 15), /*!< Implementation internal. Reserved */
};

enum x64cpu_vmem_map_level {
    X64CPU_VMEM_MAP_PML4,
    X64CPU_VMEM_MAP_PDP,
    X64CPU_VMEM_MAP_PD,
    X64CPU_VMEM_MAP_PT
};

#define X64CPU_VMEM_PAGE_ADDR_MASK   (0xfffffffffffff000)
#define X64CPU_VMEM_PAGE_OFFSET_MASK (0x0000000000000fff)
#define X64CPU_VMEM_PAGE_SIZE        (0x1000)                /*!< 4K */

// 00000000 00000000 11111111 10000000 00000000 00000000 00000000 00000000
#define X64CPU_VMEM_PML4_SPLIT       (0x0000ff8000000000)
// 00000000 00000000 00000000 01111111 11000000 00000000 00000000 00000000
#define X64CPU_VMEM_PDP_SPLIT        (0x0000007fc0000000)
// 00000000 00000000 00000000 00000000 00111111 11100000 00000000 00000000
#define X64CPU_VMEM_PD_SPLIT         (0x000000003fe00000)
// 00000000 00000000 00000000 00000000 00000000 00011111 11110000 00000000
#define X64CPU_VMEM_PT_SPLIT         (0x00000000001ff000)

struct x64cpu_vmem_page_directory {
    union {
        struct x64cpu_vmem_page_directory *pml4[512];
        struct x64cpu_vmem_page_directory *pdp[512];
        struct x64cpu_vmem_page_directory *pd[512];
        struct x64cpu_vmem_page *pt[512];
    };
    uint16_t num_entries;
};

struct x64cpu_vmem_page {
    uint8_t *data;
    uint8_t allocated;
    uint16_t flags;
};

struct x64cpu_vmem {
    struct x64cpu_vmem_page_directory page_directory;
    uint64_t vm_size;
    uint64_t ph_size;
};


/* Returns the number of pages allocated ; if less than needed then an allocation failure has ocurred */
int x64cpu_vmem_map(struct x64cpu_vmem *memory, uint64_t start_address, uint64_t size, uint16_t flags,
                            uint8_t *physical_page, int zero_pages);

void x64cpu_vmem_unmap(struct x64cpu_vmem *memory, uint64_t start_address, uint64_t size);


int x64cpu_vmem_read(struct x64cpu_vmem *memory, uint64_t address, uint8_t *data, uint8_t size,
                                enum x64cpu_mem_access_flags access_flags, uint64_t *fault_address);

int x64cpu_vmem_write(struct x64cpu_vmem *memory, uint64_t address, uint8_t *data, uint8_t size,
                                enum x64cpu_mem_access_flags access_flags, uint64_t *fault_address);



int x64cpu_vmem_read_cpu_glue(struct x64cpu *ignored, struct x64cpu_vmem *memory, uint64_t address, uint8_t *data, uint8_t size,
                                enum x64cpu_mem_access_flags access_flags, uint64_t *fault_address);
int x64cpu_vmem_write_cpu_glue(struct x64cpu *ignored, struct x64cpu_vmem *memory, uint64_t address, uint8_t *data, uint8_t size,
                                enum x64cpu_mem_access_flags access_flags, uint64_t *fault_address);


/* Helpers for SWIG wrappers */
#define X64CPU_DEFINE_VMEM_PROTO(type) \
    int x64cpu_vmem_read_##type (struct x64cpu_vmem *memory, uint64_t address, type *data, enum x64cpu_mem_access_flags flags, uint64_t *fault_address); \
    inline int x64cpu_vmem_write_##type (struct x64cpu_vmem *memory, uint64_t address, type data, enum x64cpu_mem_access_flags flags, uint64_t *fault_address); \

#define X64CPU_DEFINE_VMEM_IMPL(type) \
    int x64cpu_vmem_read_##type (struct x64cpu_vmem *memory, uint64_t address, type *data, enum x64cpu_mem_access_flags flags, uint64_t *fault_address) { \
        return x64cpu_vmem_read(memory, address, (uint8_t*)data, sizeof(type), flags, fault_address); \
    } \
    \
    int x64cpu_vmem_write_##type (struct x64cpu_vmem *memory, uint64_t address, type data, enum x64cpu_mem_access_flags flags, uint64_t *fault_address) { \
        return x64cpu_vmem_write(memory, address, (uint8_t*)&data, sizeof(type), flags, fault_address); \
    }

X64CPU_DEFINE_VMEM_PROTO(uint8_t);
X64CPU_DEFINE_VMEM_PROTO(uint16_t);
X64CPU_DEFINE_VMEM_PROTO(uint32_t);
X64CPU_DEFINE_VMEM_PROTO(uint64_t);

/* Returns the amount of bytes read / written ; if differs from size parameter then a page fault ocurred */
uint64_t x64cpu_vmem_copyfrom(struct x64cpu_vmem *memory, uint64_t address, uint8_t *dest, uint64_t byte_count);

uint64_t x64cpu_vmem_copyto(struct x64cpu_vmem *memory, uint64_t address, uint8_t *src, uint64_t byte_count);


void x64cpu_vmem_dump(struct x64cpu_vmem *memory, char *output);

#endif /* __VIRTUAL_MEMORY_H__ */

