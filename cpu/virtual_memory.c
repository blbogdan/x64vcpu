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


#include "virtual_memory.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>


#define INTERNAL_ERROR()    {(*((char*)0)) = 1; }

#define ASSERT(c) {\
    if (!(c)) {\
        fprintf(stderr, "Assertion failed at %s:%d in %s. Condition: " #c "\n", __FILE__, __LINE__, __PRETTY_FUNCTION__);\
        INTERNAL_ERROR();\
    }\
}

X64CPU_DEFINE_VMEM_IMPL(uint8_t);
X64CPU_DEFINE_VMEM_IMPL(uint16_t);
X64CPU_DEFINE_VMEM_IMPL(uint32_t);
X64CPU_DEFINE_VMEM_IMPL(uint64_t);

static int x64cpu_pagemap_address_to_index(uint64_t address, enum x64cpu_vmem_map_level pagemap_level) {
    int ret = -1;

    switch (pagemap_level) {
        case X64CPU_VMEM_MAP_PML4: ret = (address & X64CPU_VMEM_PML4_SPLIT) >> 39; break;
        case X64CPU_VMEM_MAP_PDP: ret = (address & X64CPU_VMEM_PDP_SPLIT) >> 30; break;
        case X64CPU_VMEM_MAP_PD: ret = (address & X64CPU_VMEM_PD_SPLIT) >> 21; break;
        case X64CPU_VMEM_MAP_PT: ret = (address & X64CPU_VMEM_PT_SPLIT) >> 12; break;

        default:
            INTERNAL_ERROR();
            break;
    }

    return ret;
}

static struct x64cpu_vmem_page_directory* x64cpu_page_get_internal(struct x64cpu_vmem *memory,
                                                                struct x64cpu_vmem_page_directory *table,
                                                                uint64_t address,
                                                                enum x64cpu_vmem_map_level pagemap_level,
                                                                int create_on_nonexist) {
    struct x64cpu_vmem_page_directory *ret = NULL;
    int index = -1;

    ASSERT(table != NULL);

    ASSERT(pagemap_level != X64CPU_VMEM_MAP_PT);

    index = x64cpu_pagemap_address_to_index(address, pagemap_level);
    ASSERT(index >= 0 && index < 512);
    ret = table->pd[index];
    if (ret == NULL) {
        if (create_on_nonexist == 0) {
            return NULL;
        }

        ret = malloc(sizeof(struct x64cpu_vmem_page_directory));
        memset(ret, 0, sizeof(struct x64cpu_vmem_page_directory));

        table->pd[index] = ret;
        table->num_entries += 1;

        memory->ph_size += sizeof(struct x64cpu_vmem_page_directory);
    }

    return ret;
}

static struct x64cpu_vmem_page* x64cpu_page_get_by_address(struct x64cpu_vmem *memory,
                                                                struct x64cpu_vmem_page_directory *pagemap,
                                                                uint64_t address) {
    struct x64cpu_vmem_page *ret = NULL;
    struct x64cpu_vmem_page_directory *table = NULL;

    /* Last 48-63 bits must be the same as bit 47 */
    if (((address & 0x0000800000000000) != 0) != ((address & 0xffff000000000000) != 0)) {
        /* Page Fault */
        return NULL;
    }

    table = pagemap;

    table = x64cpu_page_get_internal(memory, table, address, X64CPU_VMEM_MAP_PML4, 0);
    if (table == NULL) {
            return NULL;
    }

    table = x64cpu_page_get_internal(memory, table, address, X64CPU_VMEM_MAP_PDP, 0);
    if (table == NULL) {
            return NULL;
    }

    table = x64cpu_page_get_internal(memory, table, address, X64CPU_VMEM_MAP_PD, 0);
    if (table == NULL) {
            return NULL;
    }

    ret = table->pt[x64cpu_pagemap_address_to_index(address, X64CPU_VMEM_MAP_PT)];

    return ret;
}

static struct x64cpu_vmem_page* x64cpu_page_create(struct x64cpu_vmem *memory, uint64_t address, uint16_t flags,
                                                        uint8_t *physical_page) {
    struct x64cpu_vmem_page *page = NULL;
    uint16_t page_index;
    struct x64cpu_vmem_page_directory *table = &memory->page_directory;

    /* Last 48-63 bits must be the same as bit 47 */
    if (((address & 0x0000800000000000) != 0) != ((address & 0xffff000000000000) != 0)) {
        /* Page Fault */
        return NULL;
    }

    table = x64cpu_page_get_internal(memory, table, address, X64CPU_VMEM_MAP_PML4, 1);
    if (table == NULL) {
            /* Allocation failure; out of memory ? */
            return NULL;
    }

    table = x64cpu_page_get_internal(memory, table, address, X64CPU_VMEM_MAP_PDP, 1);
    if (table == NULL) {
            /* Allocation failure; out of memory ? */
            return NULL;
    }

    table = x64cpu_page_get_internal(memory, table, address, X64CPU_VMEM_MAP_PD, 1);
    if (table == NULL) {
            /* Allocation failure; out of memory ? */
            return NULL;
    }

    page_index = x64cpu_pagemap_address_to_index(address, X64CPU_VMEM_MAP_PT);

    page = table->pt[page_index];
    if (page == NULL) {
        /* Create the page */
        page = calloc(1, sizeof(struct x64cpu_vmem_page));

        memory->vm_size += X64CPU_VMEM_PAGE_SIZE;

        page->flags = ((flags) | (X64CPU_VMEM_PAGE_FLAG_P));

        /* Map an existing physical page or allocate new memory ? */
        if (physical_page == NULL) {
            page->data = calloc(1, X64CPU_VMEM_PAGE_SIZE);
            page->allocated = 1;

            memory->ph_size += X64CPU_VMEM_PAGE_SIZE;
        }
        else {
            page->data = physical_page;
            page->allocated = 0;
        }

        table->pt[page_index] = page;
    }
    else if (physical_page != NULL) {
        /* Not supported yet */
        INTERNAL_ERROR();
    }

    return page;
}

static void x64cpu_page_release(struct x64cpu_vmem *memory, uint64_t address) {
    struct x64cpu_vmem_page_directory *table[4] = { 0, };
    uint64_t index[4] = { -1 };
    struct x64cpu_vmem_page *page = NULL;
    uint16_t page_index;

    table[0] = &memory->page_directory;

    /* Last 48-63 bits must be the same as bit 47 */
    if (((address & 0x0000800000000000) != 0) != ((address & 0xffff000000000000) != 0)) {
        /* Page Fault */
        return;
    }

    index[1] = x64cpu_pagemap_address_to_index(address, X64CPU_VMEM_MAP_PML4);
    ASSERT(index[1] >= 0 && index[1] < 512);
    table[1] = table[0]->pml4[index[1]];
    if (table[1] == NULL) {
            return;
    }

    index[2] = x64cpu_pagemap_address_to_index(address, X64CPU_VMEM_MAP_PDP);
    ASSERT(index[2] >= 0 && index[2] < 512);
    table[2] = table[1]->pdp[index[2]];
    if (table[2] == NULL) {
            return;
    }

    index[3] = x64cpu_pagemap_address_to_index(address, X64CPU_VMEM_MAP_PD);
    ASSERT(index[3] >= 0 && index[3] < 512);
    table[3] = table[2]->pd[index[3]];
    if (table[3] == NULL) {
            return;
    }

    page_index = x64cpu_pagemap_address_to_index(address, X64CPU_VMEM_MAP_PT);

    page = table[3]->pt[page_index];
    if (page != NULL) {
        /* Release page */
        if (page->allocated) {
            free(page->data);
            memory->ph_size -= X64CPU_VMEM_PAGE_SIZE;
        }

        free(page);
        memory->vm_size -= X64CPU_VMEM_PAGE_SIZE;

        table[3]->pt[page_index] = NULL;
        table[3]->num_entries -= 1;
    }

    /* Release unused page directories */
    ASSERT(table[3]->num_entries >= 0);
    if (table[3]->num_entries <= 0) {
        free(table[3]);
        table[2]->pd[index[3]] = NULL;
        table[2]->num_entries -= 1;
        memory->ph_size -= sizeof(struct x64cpu_vmem_page_directory);
    }

    ASSERT(table[2]->num_entries >= 0);
    if (table[2]->num_entries <= 0) {
        free(table[2]);
        table[1]->pdp[index[2]] = NULL;
        table[1]->num_entries -= 1;
        memory->ph_size -= sizeof(struct x64cpu_vmem_page_directory);
    }

    ASSERT(table[1]->num_entries >= 0);
    if (table[1]->num_entries <= 0) {
        free(table[1]);
        table[0]->pml4[index[1]] = NULL;
        table[0]->num_entries -= 1;
        memory->ph_size -= sizeof(struct x64cpu_vmem_page_directory);
    }

    ASSERT(table[0]->num_entries >= 0);
}

int x64cpu_vmem_map(struct x64cpu_vmem *memory, uint64_t start_address, uint64_t size, uint16_t flags,
                            uint8_t *physical_page, int zero_pages) {
    int ret = 0;
    uint64_t end_address = start_address + size;
    uint64_t i;
    struct x64cpu_vmem_page *tmp = NULL;
    uint8_t *physical_page_ptr = physical_page;

    for (i = start_address; i < end_address; i += X64CPU_VMEM_PAGE_SIZE) {
        tmp = x64cpu_page_create(memory, i, flags, physical_page_ptr);
        if (tmp == NULL) {
            /* Allocation failure; out of memory ? */
            return ret;
        }
        if (physical_page_ptr == NULL && zero_pages) {
            memset(tmp->data, 0, X64CPU_VMEM_PAGE_SIZE);
        }
        if (physical_page_ptr != NULL) {
            physical_page_ptr += X64CPU_VMEM_PAGE_SIZE;
        }
        ret += 1;
    }

    return ret;
}

void x64cpu_vmem_unmap(struct x64cpu_vmem *memory, uint64_t start_address, uint64_t size) {
    uint64_t end_address = start_address + size;
    uint64_t i;

    for (i = start_address; i < end_address; i += X64CPU_VMEM_PAGE_SIZE) {
        x64cpu_page_release(memory, i);
    }
}

static int x64cpu_memory_access(struct x64cpu_vmem *memory, uint64_t address, uint8_t *data, uint8_t size, int write,
                                enum x64cpu_mem_access_flags access_flags, uint64_t *fault_address) {
    struct x64cpu_vmem_page *page = NULL;
    uint16_t offset = 0;
    int rc = 0;

    ASSERT(size >= 1 && size <= 16);

    /* Check un-aligned access across pages */
    if ((address & X64CPU_VMEM_PAGE_ADDR_MASK) != ((address + size - 1) & X64CPU_VMEM_PAGE_ADDR_MASK)) {
        uint64_t addr1 = address;
        uint64_t addr2 = ((address + size - 1) & X64CPU_VMEM_PAGE_ADDR_MASK);
        uint8_t size1 = (addr2 - address);
        uint8_t size2 = ((address + size) - addr2);

        rc = x64cpu_memory_access(memory, addr1, data, size1, write, access_flags, fault_address);
        if (rc != X64CPU_MEM_ACCESS_SUCCESS) {
            return rc;
        }

        rc = x64cpu_memory_access(memory, addr2, data + size1, size2, write, access_flags, fault_address);
        if (rc != X64CPU_MEM_ACCESS_SUCCESS) {
            return rc;
        }

        return X64CPU_MEM_ACCESS_SUCCESS;
    }

    page = x64cpu_page_get_by_address(memory, &memory->page_directory, address);
    if (page == NULL) {
        /* Page fault - not existing */
        if (fault_address != NULL) {
            (*fault_address) = address;
        }
        return X64CPU_MEM_ACCESS_PF;
    }

    if ((access_flags & X64CPU_MEM_ACCESS_WRITE) && !(page->flags & X64CPU_VMEM_PAGE_FLAG_RW)) {
        /* Protection Fault */
        if (fault_address != NULL) {
            (*fault_address) = address;
        }
        return X64CPU_MEM_ACCESS_GP;
    }
/* TODO: NX bit */
#if 0
    else if ((access_flags & X64CPU_MEM_ACCESS_EXECUTE) && !(page->flags & X64CPU_VMEM_PAGE_FLAG_?)) {
        /* Protection Fault */
        if (fault_address != NULL) {
            (*fault_address) = address;
        }
        return X64CPU_MEM_ACCESS_GP;
    }
#endif

    offset = (address & X64CPU_VMEM_PAGE_OFFSET_MASK);

    if (write == 0) {
        memcpy(data, &page->data[offset], size);
    }
    else {
        memcpy(&page->data[offset], data, size);
    }

    return X64CPU_MEM_ACCESS_SUCCESS;
}

int x64cpu_vmem_read(struct x64cpu_vmem *memory, uint64_t address, uint8_t *data, uint8_t size,
                                enum x64cpu_mem_access_flags access_flags, uint64_t *fault_address) {
    return x64cpu_memory_access(memory, address, data, size, 0, access_flags, fault_address);
}

int x64cpu_vmem_write(struct x64cpu_vmem *memory, uint64_t address, uint8_t *data, uint8_t size,
                                enum x64cpu_mem_access_flags access_flags, uint64_t *fault_address) {
    return x64cpu_memory_access(memory, address, data, size, 1, access_flags, fault_address);
}

int x64cpu_vmem_read_cpu_glue(struct x64cpu *ignored, struct x64cpu_vmem *memory, uint64_t address, uint8_t *data, uint8_t size,
                                enum x64cpu_mem_access_flags access_flags, uint64_t *fault_address) {
    return x64cpu_memory_access(memory, address, data, size, 0, access_flags, fault_address);
}

int x64cpu_vmem_write_cpu_glue(struct x64cpu *ignored, struct x64cpu_vmem *memory, uint64_t address, uint8_t *data, uint8_t size,
                                enum x64cpu_mem_access_flags access_flags, uint64_t *fault_address) {
    return x64cpu_memory_access(memory, address, data, size, 1, access_flags, fault_address);
}


uint64_t x64cpu_vmem_copyfrom(struct x64cpu_vmem *memory, uint64_t address, uint8_t *dest, uint64_t byte_count) {
    uint64_t i, o, count;
    uint64_t *buffer = NULL;
    uint64_t tmp;
    uint64_t rc, ret = 0;
    uint64_t fault_addr = 0;

    /* Load data - 8 bytes at a time */
    count = byte_count / 8;
    buffer = (uint64_t*)dest;

    for (o = address, i = 0; i < count; i++, o += 8) {
        rc = x64cpu_vmem_read(memory, o, (uint8_t*)&tmp, 8, 0, &fault_addr);
        if (rc != 0) {
            /* Page fault */
            return ret;
        }
        buffer[i] = tmp;
        ret += 8;
    }

    /* The rest, 1 byte */
    for (i = count * 8; i < byte_count; i++, o++) {
        tmp = 0;
        if (x64cpu_vmem_read(memory, o, (uint8_t*)&tmp, 1, 0, &fault_addr) != 0) {
            /* Page fault */
            return ret;
        }
        dest[i] = tmp;
        ret += 1;
    }

    return ret;
}

uint64_t x64cpu_vmem_copyto(struct x64cpu_vmem *memory, uint64_t address, uint8_t *src, uint64_t byte_count) {
    uint64_t i, o, count;
    uint64_t *buffer = NULL;
    uint64_t tmp;
    uint64_t rc, ret = 0;
    uint64_t fault_addr = 0;

    /* Load data - 8 bytes at a time */
    count = byte_count / 8;
    buffer = (uint64_t*)src;

    for (o = address, i = 0; i < count; i++, o += 8) {
        tmp = buffer[i];
        rc = x64cpu_vmem_write(memory, o, (uint8_t*)&tmp, 8, 0, &fault_addr);
        if (rc != 0) {
            /* Page fault */
            return ret;
        }
        ret += 8;
    }

    /* The rest, 1 byte */
    for (i = count * 8; i < byte_count; i++, o++) {
        tmp = src[i];
        if (x64cpu_vmem_write(memory, o, (uint8_t*)&tmp, 1, 0, &fault_addr) != 0) {
            /* Page fault */
            return ret;
        }
        ret += 1;
    }

    return ret;
}


#define append(str, ...) {if (buffer_k < (sizeof(buffer) - 1)) { buffer_k += snprintf(&buffer[buffer_k], sizeof(buffer) - buffer_k, str, ##__VA_ARGS__);}}

#define print_page(first_addr, last_addr) {\
    if (last_addr > first_addr) {\
        append("\t0x%016lx -> 0x%016lx\tsize: 0x%016lx (%5f MB) (%ld pages)\n", first_addr, last_addr, \
                (last_addr - first_addr), \
                ((last_addr - first_addr) / (1024.0f * 1024)), \
                (last_addr - first_addr) >> 12 \
        );\
    }\
}

void x64cpu_vmem_dump(struct x64cpu_vmem *memory, char *output) {
    char buffer[8192];
    size_t buffer_k = 0;
    uint64_t i1, i2, i3, i4;
    struct x64cpu_vmem_page_directory *pagemap, *ptr1, *ptr2, *ptr3;
    uint64_t addr1, addr2, addr3, addr4;

    uint64_t first_addr = -1;
    uint64_t last_addr = 0;

    pagemap = &memory->page_directory;

    append("[*] Memory pages:\n");

    for (i1 = 0; i1 < 512; i1++) {
        ptr1 = pagemap->pml4[i1];
        if (ptr1 == NULL) {
            continue;
        }
        addr1 = (i1 << 39);
        if (i1 > 255) {
            addr1 |= 0xffff000000000000;
        }

        for (i2 = 0; i2 < 512; i2++) {
            ptr2 = ptr1->pdp[i2];
            if (ptr2 == NULL) {
                continue;
            }
            addr2 = addr1 | (i2 << 30);

            for (i3 = 0; i3 < 512; i3++) {
                ptr3 = ptr2->pd[i3];
                if (ptr3 == NULL) {
                    continue;
                }
                addr3 = addr2 | (i3 << 21);

                for (i4 = 0; i4 < 512; i4++) {
                    if (ptr3->pt[i4] == NULL) {
                        continue;
                    }
                    addr4 = addr3 | (i4 << 12);

                    if ((last_addr + 1) == addr4) {
                        last_addr = addr4 + X64CPU_VMEM_PAGE_SIZE - 1;
                        continue;
                    }
                    else {
                        print_page(first_addr, last_addr);

                        first_addr = addr4;
                        last_addr = addr4 + X64CPU_VMEM_PAGE_SIZE - 1;
                    }
                }
            }
        }
    }

    print_page(first_addr, last_addr);

    memcpy(output, buffer, buffer_k);
    output[buffer_k] = '\0';
}

