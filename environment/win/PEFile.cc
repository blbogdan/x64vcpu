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

#include "PEFile.h"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>

#define INTERNAL_ERROR()    {(*((char*)0)) = 1; }

#define ASSERT(c) {\
    if (!(c)) {\
        fprintf(stderr, "Assertion failed at %s:%d in %s. Condition: " #c "\n", __FILE__, __LINE__, __PRETTY_FUNCTION__);\
        INTERNAL_ERROR();\
    }\
}


/* ------------------------------------------------------------------------- */
PEFile::PEFile(const char *name, io_callback io_fn, void *io_user_data) {
    this->name = (name != NULL) ? name : "";
    this->sections = NULL;

    this->io_fn = io_fn;
    this->io_user_data = io_user_data;
}
/* ------------------------------------------------------------------------- */
PEFile* PEFile::loadPE(const char *name, io_callback io_fn, void *io_user_data) {
    PEFile *pe = NULL;

    pe = new PEFile(name, io_fn, io_user_data);

    pe->parse_result = pe->parse();

    return pe;
}
/* ------------------------------------------------------------------------- */
PEFile::~PEFile() {
    int i;

    if (this->sections != NULL) {
        for (i = 0; i < coff_header.number_of_sections; i++) {
            if (sections[i].data != NULL) {
                free(sections[i].data);
                sections[i].data = NULL;
            }
        }

        free(this->sections);
        this->sections = NULL;
    }
}
/* ------------------------------------------------------------------------- */
int PEFile::logError(const char *fmt, ...) {
    int ret = -1;
    va_list vargs;
    char buffer[8192];
    char buffer2[8192];

    va_start(vargs, fmt);
    ret = vsnprintf(buffer, sizeof(buffer) - 1, fmt, vargs);
    va_end(vargs);

    snprintf(buffer2, sizeof(buffer2), "PEFile: %s", buffer);

    this->writeLog(buffer2);

    return ret;
}
/* ------------------------------------------------------------------------- */
void PEFile::writeLog(const char *msg) {
    if (this->_logger != NULL) {
        this->_logger(this->log_user_data, msg);
    }
    else {
        fprintf(stderr, "%s.\n", msg);
    }
}
/* ------------------------------------------------------------------------- */

#define READ(buf, size) {\
    rc = this->io_fn(IO_CB_OP_READ, this->io_user_data, (buf), (size)); \
    if (rc < 0) { \
        this->logError("I/O error while reading input %d: %s.", rc, strerror(rc)); \
        goto _err; \
    } \
}

#define SEEK(offset) {\
    rc = this->io_fn(IO_CB_OP_SEEK, this->io_user_data, NULL, (offset)); \
    if (rc < 0) { \
        this->logError("I/O error while reading input %d: %s.", rc, strerror(rc)); \
        goto _err; \
    } \
}

int PEFile::parse() {
    int ret = -1;
    int rc;
    uint32_t i;
    char dos_header[0x40];
    uint32_t e_lfanew = 0;
    uint32_t raw_header_size = 0;

    if (this->sections != NULL) {
        free(this->sections);
        this->sections = NULL;
    }

    memset(&coff_header, 0, sizeof(coff_header));
    memset(&coff_optional_header, 0, sizeof(coff_optional_header));
    memset(&pe_header, 0, sizeof(pe_header));
    memset(&pe_header.data_directory[0], 0, sizeof(pe_header.data_directory));


    /* Read DOS header */
    SEEK(0);
    READ(dos_header, sizeof(dos_header));

    /* Check DOS header */
    if (dos_header[0] != 0x4d || dos_header[1] != 0x5a) {
        this->logError("Not a DOS header: 0x%02x 0x%02x.", dos_header[0], dos_header[1]);
        goto _err;
    }

    /* Find main header */
    e_lfanew = *((uint32_t*)(&dos_header[0x3c]));
    /* Sanity check */
    if (e_lfanew < 0x40 || e_lfanew > 0xffff) {
        this->logError("Invalid e_lfanew number: 0x%08x (constraint >= 0x40 && < 0xffff ; update code if wrong).", e_lfanew);
        goto _err;
    }

    /* Load main COFF header */
    SEEK(e_lfanew);
    READ(&coff_header, sizeof(coff_header));

    /* Check signature */
    if (memcmp(coff_header.signature, "PE\x00\x00", sizeof(coff_header.signature)) != 0) {
        this->logError("COFF header not found (not PE file ?). Signature: 0x%02x 0x%02x 0x%02x 0x%02x.",
                        coff_header.signature[0], coff_header.signature[1],
                        coff_header.signature[2], coff_header.signature[3]);
        goto _err;
    }

    /* Read COFF optional header ; without the PE32 specific field */
    READ(&coff_optional_header, sizeof(coff_optional_header) - sizeof(uint32_t));

    /* Check magic */
    if (coff_optional_header.magic != PE_PE32 && 
            coff_optional_header.magic != PE_PE32_PLUS) {
        this->logError("Invalid COFF optional header: 0x%04x.", coff_optional_header.magic);
        goto _err;
    }

    if (coff_optional_header.magic == PE_PE32) {
        READ(&coff_optional_header.base_of_data, sizeof(uint32_t));
    }

    /* Read PE specific header */
    if (coff_optional_header.magic == PE_PE32) {
        READ(&pe_header.image_base, sizeof(uint32_t));
    }
    else if (coff_optional_header.magic == PE_PE32_PLUS) {
        READ(&pe_header.image_base, sizeof(uint64_t));
    }
    else {
        INTERNAL_ERROR();
    }

    READ(&pe_header.section_alignment, sizeof(pe_header.section_alignment));
    READ(&pe_header.file_alignment, sizeof(pe_header.file_alignment));
    READ(&pe_header.major_os_version, sizeof(pe_header.major_os_version));
    READ(&pe_header.minor_os_version, sizeof(pe_header.minor_os_version));
    READ(&pe_header.major_image_version, sizeof(pe_header.major_image_version));
    READ(&pe_header.minor_image_version, sizeof(pe_header.minor_image_version));
    READ(&pe_header.major_subsystem_version, sizeof(pe_header.major_subsystem_version));
    READ(&pe_header.minor_subsystem_version, sizeof(pe_header.minor_subsystem_version));
    READ(&pe_header.win32_version_value, sizeof(pe_header.win32_version_value));
    READ(&pe_header.size_of_image, sizeof(pe_header.size_of_image));
    READ(&pe_header.size_of_headers, sizeof(pe_header.size_of_headers));
    READ(&pe_header.checksum, sizeof(pe_header.checksum));
    READ(&pe_header.subsystem, sizeof(pe_header.subsystem));
    READ(&pe_header.dll_characteristics, sizeof(pe_header.dll_characteristics));

    if (coff_optional_header.magic == PE_PE32) {
        READ(&pe_header.size_of_stack_reserve, sizeof(uint32_t));
        READ(&pe_header.size_of_stack_commit, sizeof(uint32_t));
        READ(&pe_header.size_of_heap_reserve, sizeof(uint32_t));
        READ(&pe_header.size_of_heap_commit, sizeof(uint32_t));
    }
    else if (coff_optional_header.magic == PE_PE32_PLUS) {
        READ(&pe_header.size_of_stack_reserve, sizeof(pe_header.size_of_stack_reserve));
        READ(&pe_header.size_of_stack_commit, sizeof(pe_header.size_of_stack_commit));
        READ(&pe_header.size_of_heap_reserve, sizeof(pe_header.size_of_heap_reserve));
        READ(&pe_header.size_of_heap_commit, sizeof(pe_header.size_of_heap_commit));
    }
    else {
        INTERNAL_ERROR();
    }

    READ(&pe_header.loader_flags, sizeof(pe_header.loader_flags));
    READ(&pe_header.number_of_rva_and_sizes, sizeof(pe_header.number_of_rva_and_sizes));

    /* Read data directory entries */
    for (i = 0; i < pe_header.number_of_rva_and_sizes && i < PE_DATA_LAST; i++) {
        READ(&pe_header.data_directory[i], sizeof(pe_header.data_directory[i]));
    }

    /* Jump over and discard extra Data Directory entries */
    if (pe_header.number_of_rva_and_sizes > PE_DATA_LAST) {
        struct PEImageDataDirectory dummy;
        for (i = PE_DATA_LAST; i < pe_header.number_of_rva_and_sizes; i++) {
            READ(&dummy, sizeof(dummy));
        }
    }

    /* Read Section tables */
    sections = (struct PESection*)calloc(coff_header.number_of_sections, sizeof(struct PESection));
    for (i = 0; i < coff_header.number_of_sections; i++) {
        READ(&sections[i], sizeof(struct PESectionTable));
    }

    /* Load sections' data */
    for (i = 0; i < coff_header.number_of_sections; i++) {
        SEEK(sections[i].pointer_to_raw_data);

        uint8_t *data = (uint8_t*)malloc(sections[i].size_of_raw_data);
        READ(data, sections[i].size_of_raw_data);

        sections[i].data = data;
    }

    /* Load raw header */
    SEEK(0);
    this->raw_header.length = e_lfanew + sizeof(coff_header) + coff_header.size_of_optional_header;
    this->raw_header.data = (uint8_t*)malloc(this->raw_header.length);
    READ(this->raw_header.data, this->raw_header.length);

    /* Read imports */
    if (this->readImports() < 0) {
        goto _end;
    }

    /* Read exports */
    if (this->readExports() < 0) {
        goto _end;
    }

    /* Read relocations */
    if (this->readRelocations() < 0) {
        goto _end;
    }

    /* Success */
    ret = 0;
    goto _end;

_err:
    // TODO: cleanup
_end:
    return ret;
}
/* ------------------------------------------------------------------------- */
uint64_t PEFile::getMemorySize() const {
    size_t i;
    uint64_t base = -1, top = 0;

    if (coff_header.number_of_sections < 1) {
        return 0;
    }

    for (i = 0; i < coff_header.number_of_sections; i++) {
        if (sections[i].virtual_address < base) {
            base = sections[i].virtual_address;
        }

        if ((sections[i].virtual_address + sections[i].virtual_size) > top) {
            top = (sections[i].virtual_address + sections[i].virtual_size);
        }
    }

    return top - base;
}
/* ------------------------------------------------------------------------- */
int PEFile::readImports() {
    int ret = -1;
    uint32_t i, j;
    uint64_t idt_offset = 0;
    uint8_t *buffer = NULL;
    uint64_t buffer_size = 0;
    struct PESection *section = NULL;
    struct PEImportDirectoryTable import_directory;
    struct PEImportLookupTable lookup_table;
    uint8_t ilt_size = 0;
    uint64_t data_import_table_offset, data_import_table_end;

    if (PE_DATA_IMPORT_TABLE > pe_header.number_of_rva_and_sizes) {
        /* No import table in file */
        return 0;
    }

    /* Find .idata section */
    data_import_table_offset = pe_header.data_directory[PE_DATA_IMPORT_TABLE].virtual_address;
    data_import_table_end = data_import_table_offset + pe_header.data_directory[PE_DATA_IMPORT_TABLE].size;
    for (i = 0; i < coff_header.number_of_sections; i++) {
        if (data_import_table_offset >= sections[i].virtual_address
                && data_import_table_offset < (sections[i].virtual_address + sections[i].virtual_size)) {
            section = &sections[i];
            break;
        }
    }

    if (section == NULL) {
        /* No import table in file */
        return 0;
    }

    /* Determine Import Lookup Table entry size */
    if (coff_optional_header.magic == PE_PE32) {
        ilt_size = 4;
    }
    else if (coff_optional_header.magic == PE_PE32_PLUS) {
        ilt_size = 8;
    }
    else {
        INTERNAL_ERROR();
    }

    /* Buffer section */
    buffer = section->data;
    buffer_size = section->size_of_raw_data;

    idt_offset = pe_header.data_directory[PE_DATA_IMPORT_TABLE].virtual_address - section->virtual_address;

    for (i = 0 ; ; i++) {
        std::string dll_name;
        uint64_t dll_name_ptr;
        uint64_t max_dll_name_length;
        uint64_t ilt_offset;
        DllImportList import_list;

        if (idt_offset < 0 || (idt_offset + sizeof(import_directory)) >= buffer_size) {
            this->logError("Invalid Import Directory Table offset: %p.", idt_offset);
            goto _err;
        }

        memcpy(&import_directory, &buffer[idt_offset], sizeof(import_directory));
        idt_offset += sizeof(import_directory);

        if (import_directory.lookup_table_rva == 0x00) {
            break;
        }

        dll_name_ptr = import_directory.name_rva - section->virtual_address;
        max_dll_name_length = (buffer_size - dll_name_ptr) - 1;
        if (dll_name_ptr < 0 || dll_name_ptr >= buffer_size 
                || strnlen((char*)&buffer[dll_name_ptr], max_dll_name_length) >= max_dll_name_length) {
            /* Invalid DLL name in imports */
            this->logError("Malformed name in imports at idt_offset: %p.", idt_offset);
            goto _err;
        }

        dll_name = (char*)&buffer[dll_name_ptr];

        /* Process lookup table */
        ilt_offset = import_directory.lookup_table_rva - section->virtual_address;

        for (j = 0; ; j++) {
            uint64_t name_table_offset;
            
            if (ilt_offset < 0 || (ilt_offset + ilt_size) >= buffer_size) {
                this->logError("Invalid Import Lookup Table offset: %p.", ilt_offset);
                goto _err;
            }

            memcpy(&lookup_table, &buffer[ilt_offset], sizeof(lookup_table));
            ilt_offset += sizeof(lookup_table);

            if (lookup_table.flag32 == 0) {
                break;
            }

            /* By ordinal ? */
            if ((ilt_size == 4 && lookup_table.flag32 < 0) || (ilt_size == 8 && lookup_table.flag64 < 0)) {
                struct PEImport import = { .ordinal = lookup_table.ordinal, .hint = 0, .name = "" };
                import_list.push_back(import);
            }
            /* By name ? */
            else {
                name_table_offset = lookup_table.table_rva - section->virtual_address;

                if (name_table_offset < 0 || (name_table_offset + sizeof(struct PEHintNameTable)) >= buffer_size) {
                    this->logError("Invalid Hint/Name Table offset: %p.", name_table_offset);
                    goto _err;
                }

                struct PEHintNameTable *name_table = (struct PEHintNameTable*)&buffer[name_table_offset];
                uint32_t max_name_len;

                max_name_len = buffer_size - ((char*)&name_table->name[0] - (char*)buffer) - 1;

                if (strnlen(name_table->name, max_name_len) >= max_name_len) {
                    this->logError("Invalid import name at offset: %p.", (&name_table->name[0]));
                    goto _err;
                }

                struct PEImport import = { .ordinal = 0, .hint = name_table->hint, .name = name_table->name };
                import_list.push_back(import);
            }
        }

        this->imports[dll_name] = import_list;
        // this->imports_address_table[dll_name] = import_directory.address_table_rva;
        this->imports_address_table[import_directory.address_table_rva].push_back(dll_name);
        import_list.clear();
    }

    /* Success */
    ret = 0;
    goto _end;
    
_err:
    ret = -1;
_end:
    return ret;
}
/* ------------------------------------------------------------------------- */
int PEFile::readExports() {
    int ret = -1;
    uint32_t i;
    uint8_t *buffer = NULL;
    uint64_t buffer_size = 0;
    struct PESection *section = NULL;
    struct PEExportDirectoryTable directory_table;
    uint64_t data_export_table_offset = 0;
    uint64_t data_export_table_end = 0;
    uint64_t edt_offset = 0;
    uint64_t eat_offset = 0;
    uint64_t enpt_offset = 0;
    uint64_t eot_offset = 0;

    if (PE_DATA_EXPORT_TABLE > pe_header.number_of_rva_and_sizes) {
        /* No export table in file */
        return 0;
    }

    /* Find .edata section */
    data_export_table_offset = pe_header.data_directory[PE_DATA_EXPORT_TABLE].virtual_address;
    data_export_table_end = data_export_table_offset + pe_header.data_directory[PE_DATA_EXPORT_TABLE].size;
    if (data_export_table_offset == 0) {
        /* No export table in file */
        return 0;
    }

    for (i = 0; i < coff_header.number_of_sections; i++) {
        if (data_export_table_offset >= sections[i].virtual_address
                && data_export_table_offset < (sections[i].virtual_address + sections[i].virtual_size)) {
            section = &sections[i];
            break;
        }
    }

    if (section == NULL || section->size_of_raw_data == 0) {
        /* No export table in file */
        return 0;
    }

    /* Buffer section */
    buffer = section->data;
    buffer_size = section->size_of_raw_data;

    edt_offset = pe_header.data_directory[PE_DATA_EXPORT_TABLE].virtual_address - section->virtual_address;

    if (edt_offset < 0 || (edt_offset + sizeof(directory_table)) >= buffer_size) {
        this->logError("Invalid Export Directory Table offset: %p.", edt_offset);
        goto _err;
    }

    memcpy(&directory_table, &buffer[edt_offset], sizeof(directory_table));

    exports.export_flags = directory_table.export_flags;
    exports.time_date_stamp = directory_table.time_date_stamp;
    exports.major_version = directory_table.major_version;
    exports.minor_version = directory_table.minor_version;
    exports.ordinal_base = directory_table.ordinal_base;

    eat_offset = directory_table.export_address_table_rva - section->virtual_address;
    for (i = 0; i < directory_table.address_table_entries; i++) {
        struct PEExportAddressTable *atable = &((struct PEExportAddressTable*)(&buffer[eat_offset]))[i];

        if (atable->export_rva >= data_export_table_offset && atable->export_rva < data_export_table_end) {
            /* Forwarder RVA */
            uint32_t forwarder_ptr = (atable->export_rva - section->virtual_address);
            char *forwarder = (char*)&buffer[forwarder_ptr];
            uint32_t max_length = (section->size_of_raw_data - forwarder_ptr) - 1;

            if (strnlen(forwarder, max_length) >= max_length) {
                this->logError("Invalid forwarder string in export RVA at: %p.", eat_offset);
                goto _err;
            }

            struct PEExportedSymbol exported;
            exported.is_forwarder = 1;
            exported.forwarder = forwarder;
            exports.exports.push_back(exported);
        }
        else {
            /* Internal Symbol RVA */
            struct PEExportedSymbol exported;
            exported.is_forwarder = 0;
            exported.address = atable->export_rva;
            exports.exports.push_back(exported);
        }
    }

    enpt_offset = directory_table.name_pointer_rva - section->virtual_address;
    eot_offset = directory_table.ordinal_table_rva - section->virtual_address;
    for (i = 0; i < directory_table.number_of_name_pointers; i++) {
        struct PEExportNamePointerTable *ntable = &((struct PEExportNamePointerTable*)(&buffer[enpt_offset]))[i];
        struct PEExportOrdinalTable *otable = &((struct PEExportOrdinalTable*)(&buffer[eot_offset]))[i];

        uint32_t name_ptr = (ntable->name_rva - section->virtual_address);
        char *name = (char*)&buffer[name_ptr];
        uint32_t max_length = (section->size_of_raw_data - name_ptr) - 1;

        if (strnlen(name, max_length) >= max_length) {
            this->logError("Invalid export name string at eot offset: %p", eot_offset);
            goto _err;
        }

        exports.names[name] = otable->ordinal;
        exports.ordinal_to_name[otable->ordinal] = name;

        /* Name to export */
        struct PEExportedSymbol exported = exports.exports[otable->ordinal];

        exports.name_to_export[name] = exported;

        /* Address to name */
        if (otable->ordinal < exports.exports.size()) {
            uint32_t symbol_address = exports.exports[otable->ordinal].address;
            exports.address_to_name[symbol_address] = name;
        }
    }

    /* Success */
    ret = 0;
    goto _end;

_err:
    ret = -1;
_end:
    return ret;
}
/* ------------------------------------------------------------------------- */
int PEFile::readRelocations() {
    int ret = -1;
    int i;
    uint8_t *buffer = NULL;
    uint64_t buffer_size = 0;
    uint64_t reloc_table_offset = 0;
    uint64_t reloc_table_end = 0;
    uint64_t reloc_table_size = 0;
    uint64_t rt_offset = 0;
    struct PESection *section = NULL;
    struct PEBaseRelocationBlock *r_block = NULL;
    uint64_t num_entries = 0;

uint16_t *entries;

    if (PE_DATA_BASE_RELOCATION_TABLE > pe_header.number_of_rva_and_sizes) {
        /* No relocation info in file */
        return 0;
    }

    /* Find .reloc section */
    reloc_table_offset = pe_header.data_directory[PE_DATA_BASE_RELOCATION_TABLE].virtual_address;
    reloc_table_size = pe_header.data_directory[PE_DATA_BASE_RELOCATION_TABLE].size;
    reloc_table_end = reloc_table_offset + reloc_table_size;
    if (reloc_table_offset == 0) {
        /* No export table in file */
        return 0;
    }

    for (i = 0; i < coff_header.number_of_sections; i++) {
        if (reloc_table_offset >= sections[i].virtual_address
                && reloc_table_end <= (sections[i].virtual_address + sections[i].virtual_size)) {
            section = &sections[i];
            break;
        }
    }

    if (section == NULL || section->size_of_raw_data == 0) {
        /* No export table in file */
        return 0;
    }

    buffer = section->data;
    buffer_size = section->size_of_raw_data;

    rt_offset = pe_header.data_directory[PE_DATA_BASE_RELOCATION_TABLE].virtual_address - section->virtual_address;

    if (rt_offset < 0 || (rt_offset + sizeof(struct PEBaseRelocationBlock)) >= buffer_size) {
        this->logError("Invalid Base Relocation Block offset: %p.", rt_offset);
        goto _err;
    }

    for ( ; rt_offset < reloc_table_size; ) {
        r_block = (struct PEBaseRelocationBlock*)&buffer[rt_offset];

        /* Sanity check */
        if ((rt_offset + (r_block->block_size * sizeof(uint16_t))) >= reloc_table_end) {
            this->logError("Invalid Base Relocation Block size: %d.", r_block->block_size);
            goto _err;
        }

        num_entries = (r_block->block_size - sizeof(struct PEBaseRelocationBlock)) / sizeof(uint16_t);

        entries = (uint16_t*)(((uint8_t*)&buffer[rt_offset]) + sizeof(struct PEBaseRelocationBlock));

        for (i = 0; i < num_entries; i++) {
            uint16_t type = entries[i] >> 12;
            uint16_t offset = entries[i] & (0x0fff);
            uint64_t address = ((uint64_t)r_block->page_rva) + offset;

            this->relocations[address] = (enum PEBaseRelocationType)type;
        }

        rt_offset += r_block->block_size;
    }

    /* Success */
    ret = 0;
    goto _end;

_err:
_end:
    return ret;
}
/* ------------------------------------------------------------------------- */
#define append(fmt, ...) { \
    char buffer[8192]; \
    snprintf(buffer, sizeof(buffer) - 1, fmt, ##__VA_ARGS__); \
    dump_output += buffer; \
}
#define prnt_flag(val, flag) { \
    if ((val) & (flag)) { \
        append(" %s", #flag); \
    } \
}
#define prnt_enum(val, e) { \
    if ((val) == (e)) { \
        append(" %s", #e); \
    } \
}
std::string PEFile::dump() {
    size_t i;
    std::string dump_output = "";

    append("Name: %s\n", name.c_str());

    append("COFF Header:\n");
    {
        append("\tSignature: %x %x %x %x (\"%.*s\")\n",
                coff_header.signature[0],
                coff_header.signature[1],
                coff_header.signature[2],
                coff_header.signature[3],
                4, coff_header.signature);

        append("\tMachine: 0x%08x: ", coff_header.machine);
        prnt_enum(coff_header.machine, PE_MACHINE_AMD64);
        prnt_enum(coff_header.machine, PE_MACHINE_ARM);
        prnt_enum(coff_header.machine, PE_MACHINE_ARMNT);
        prnt_enum(coff_header.machine, PE_MACHINE_ARM64);
        prnt_enum(coff_header.machine, PE_MACHINE_EBC);
        prnt_enum(coff_header.machine, PE_MACHINE_I386);
        append("\n");

        append("\tNumber of sections: %d.\n", (int)coff_header.number_of_sections);
        append("\tTime date stamp: %d.\n", coff_header.time_date_stamp);
        append("\tPointer to symbol table: 0x%08x.\n", coff_header.pointer_to_symbol_table);
        append("\tNumber of symbols: %d.\n", coff_header.number_of_symbols);
        append("\tSize of optional header: %d.\n", (int)coff_header.size_of_optional_header);

        append("\tPECharacteristics: 0x%04x: ", coff_header.characteristics);
        prnt_flag(coff_header.characteristics, PE_RELOCS_STRIPPED);
        prnt_flag(coff_header.characteristics, PE_EXECUTABLE_IMAGE);
        prnt_flag(coff_header.characteristics, PE_LINE_NUM_STRIPPED);
        prnt_flag(coff_header.characteristics, PE_LOCAL_SYMS_STRIPPED);
        prnt_flag(coff_header.characteristics, PE_AGGRESSIVE_WS_TRIM);
        prnt_flag(coff_header.characteristics, PE_LARGE_ADDRESS_AWARE);
        prnt_flag(coff_header.characteristics, PE_RESERVED);
        prnt_flag(coff_header.characteristics, PE_BYTES_REVERSED_LO);
        prnt_flag(coff_header.characteristics, PE_32BIT_MACHINE);
        prnt_flag(coff_header.characteristics, PE_DEBUG_STRIPPED);
        prnt_flag(coff_header.characteristics, PE_REMOVABLE_RUN_FROM_SWAP);
        prnt_flag(coff_header.characteristics, PE_SYSTEM);
        prnt_flag(coff_header.characteristics, PE_DLL);
        prnt_flag(coff_header.characteristics, PE_UP_SYSTEM_ONLY);
        prnt_flag(coff_header.characteristics, PE_BYTES_REVERSED_HI);
        append("\n");
    }

    append("COFF Optional Header:\n");
    {
        append("\tMagic: 0x%04x: ", coff_optional_header.magic);
        prnt_enum(coff_optional_header.magic, PE_PE32);
        prnt_enum(coff_optional_header.magic, PE_PE32_PLUS);
        prnt_enum(coff_optional_header.magic, PE_ROM);
        append("\n");

        append("\tMajor linker version: %d.\n", (int)coff_optional_header.major_linker_version);
        append("\tMinor linker version: %d.\n", (int)coff_optional_header.minor_linker_version);
        append("\tSize of code: %d.\n", coff_optional_header.size_of_code);
        append("\tSize of initialized data: %d.\n", coff_optional_header.size_of_initialized_data);
        append("\tSize of uninitialized data: %d.\n", coff_optional_header.size_of_uninitialized_data);
        append("\tAddress of entry point: 0x%08x.\n", coff_optional_header.address_of_entry_point);
        append("\tBase of code: 0x%08x.\n", coff_optional_header.base_of_code);
        append("\tBase of data: 0x%08x.\n", coff_optional_header.base_of_data);
    }

    append("PE Header:\n");
    {
        append("\tImage base: %p.\n", (void*)pe_header.image_base);
        append("\tSection alignment: 0x%08x.\n", pe_header.section_alignment);
        append("\tFile alignment: 0x%08x.\n", pe_header.file_alignment);
        append("\tMajor OS version: %d.\n", pe_header.major_os_version);
        append("\tMinor OS version: %d.\n", pe_header.minor_os_version);
        append("\tMajor image version: %d.\n", pe_header.major_image_version);
        append("\tMinor image version: %d.\n", pe_header.minor_image_version);
        append("\tMajor subsystem version: %d.\n", pe_header.major_subsystem_version);
        append("\tMinor subsystem version: %d.\n", pe_header.minor_subsystem_version);
        append("\tWin32 version: %d.\n", pe_header.win32_version_value);
        append("\tSize of image: %d.\n", pe_header.size_of_image);
        append("\tSize of headers: %d.\n", pe_header.size_of_headers);
        append("\tChecksum: 0x%08x.\n", pe_header.checksum);

        append("\tSubsystem: 0x%04x: ", pe_header.subsystem);
        prnt_enum(pe_header.subsystem, PE_SUBSYSTEM_UNKNOWN);
        prnt_enum(pe_header.subsystem, PE_SUBSYSTEM_NATIVE);
        prnt_enum(pe_header.subsystem, PE_SUBSYSTEM_WINDOWS_GUI);
        prnt_enum(pe_header.subsystem, PE_SUBSYSTEM_WINDOWS_CUI);
        prnt_enum(pe_header.subsystem, PE_SUBSYSTEM_POSIX_CUI);
        prnt_enum(pe_header.subsystem, PE_SUBSYSTEM_WINDOW_CE_GUI);
        prnt_enum(pe_header.subsystem, PE_SUBSYSTEM_EFI_APPLICATION);
        prnt_enum(pe_header.subsystem, PE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER);
        prnt_enum(pe_header.subsystem, PE_SUBSYSTEM_EFI_RUNTIME_DRIVER);
        prnt_enum(pe_header.subsystem, PE_SUBSYSTEM_EFI_ROM);
        prnt_enum(pe_header.subsystem, PE_SUBSYSTEM_XBOX);
        append("\n");

        append("\tDLL characteristics: 0x%04x: ", pe_header.dll_characteristics);
        prnt_flag(pe_header.dll_characteristics, PE_DLL_CHARACTERISTICS_RESERVED1);
        prnt_flag(pe_header.dll_characteristics, PE_DLL_CHARACTERISTICS_RESERVED2);
        prnt_flag(pe_header.dll_characteristics, PE_DLL_CHARACTERISTICS_RESERVED3);
        prnt_flag(pe_header.dll_characteristics, PE_DLL_CHARACTERISTICS_RESERVED4);
        prnt_flag(pe_header.dll_characteristics, PE_DLL_CHARACTERISTICS_DYNAMIC_BASE);
        prnt_flag(pe_header.dll_characteristics, PE_DLL_CHARACTERISTICS_FORCE_INTEGRITY);
        prnt_flag(pe_header.dll_characteristics, PE_DLL_CHARACTERISTICS_NX_COMPAT);
        prnt_flag(pe_header.dll_characteristics, PE_DLL_CHARACTERISTICS_NO_ISOLATION);
        prnt_flag(pe_header.dll_characteristics, PE_DLL_CHARACTERISTICS_NO_SEH);
        prnt_flag(pe_header.dll_characteristics, PE_DLL_CHARACTERISTICS_NO_BIND);
        prnt_flag(pe_header.dll_characteristics, PE_DLL_CHARACTERISTICS_RESERVED5);
        prnt_flag(pe_header.dll_characteristics, PE_DLL_CHARACTERISTICS_WDM_DRIVER);
        prnt_flag(pe_header.dll_characteristics, PE_DLL_CHARACTERISTICS_TERMINAL_SERVER_AWARE);
        append("\n");

        append("\tSize of stack reserve: %ld.\n", pe_header.size_of_stack_reserve);
        append("\tSize of stack commit: %ld.\n", pe_header.size_of_stack_commit);
        append("\tSize of heap reserve: %ld.\n", pe_header.size_of_heap_reserve);
        append("\tSize of heap commit: %ld.\n", pe_header.size_of_heap_commit);
        append("\tLoader flags: 0x%08x.\n", pe_header.loader_flags);
        append("\tNumber of RVA and sizes: %d.\n", pe_header.number_of_rva_and_sizes);
    }

    append("Data directories: \n");
    {
        size_t i;
        for (i = 0; i < pe_header.number_of_rva_and_sizes && i < PE_DATA_LAST; i++) {
            append("\tAddress: 0x%016x Size: 0x%016x : ", 
                        pe_header.data_directory[i].virtual_address,
                        pe_header.data_directory[i].size
            );
            prnt_enum(i, PE_DATA_EXPORT_TABLE);
            prnt_enum(i, PE_DATA_IMPORT_TABLE);
            prnt_enum(i, PE_DATA_RESOURCE_TABLE);
            prnt_enum(i, PE_DATA_EXCEPTION_TABLE);
            prnt_enum(i, PE_DATA_CERTIFICATE_TABLE);
            prnt_enum(i, PE_DATA_BASE_RELOCATION_TABLE);
            prnt_enum(i, PE_DATA_DEBUG);
            prnt_enum(i, PE_DATA_ARCHITECTURE);
            prnt_enum(i, PE_DATA_GLOBAL_PTR);
            prnt_enum(i, PE_DATA_TLS_TABLE);
            prnt_enum(i, PE_DATA_LOAD_CONFIG_TABLE);
            prnt_enum(i, PE_DATA_BOUND_IMPORT);
            prnt_enum(i, PE_DATA_IAT);
            prnt_enum(i, PE_DATA_DELAY_IMPORT);
            prnt_enum(i, PE_DATA_CLR_RUNTIME_HEADER);
            prnt_enum(i, PE_DATA_RESERVED);
            append("\n");
        }
    }

    append("Sections:\n");
    for (i = 0; i < coff_header.number_of_sections; i++) {
        PESection *section = &sections[i];
        int name_len = 8;

        append("\tName: \"%.*s\"\n", name_len, section->name);
        append("\tVirtual size: 0x%08x (%d bytes).\n", section->virtual_size, section->virtual_size);
        append("\tVirtual addr: 0x%08x.\n", section->virtual_address);
        append("\tSize of raw data: 0x%08x (%f MB).\n", section->size_of_raw_data, (section->size_of_raw_data / (1024.0 * 1024)));
        append("\tRaw data offset: 0x%08x.\n", section->pointer_to_raw_data);
        append("\tRelocations offset: 0x%08x.\n", section->pointer_to_relocations);
        append("\tLine numbers: 0x%08x.\n", section->pointer_to_line_numbers);
        append("\tNumber of relocations: %d.\n", section->number_of_relocations);
        append("\tNumber of line numbers: %d.\n", section->number_of_line_numbers);

        append("\tCharacteristics: ");
        {
            prnt_flag(section->characteristics, PE_SCN_TYPE_NO_PAD);
            prnt_flag(section->characteristics, PE_SCN_CNT_CODE);
            prnt_flag(section->characteristics, PE_SCN_CNT_INITIALIZED_DATA);
            prnt_flag(section->characteristics, PE_SCN_CNT_UNINITIALIZED_DATA);
            prnt_flag(section->characteristics, PE_SCN_LNK_OTHER);
            prnt_flag(section->characteristics, PE_SCN_GPREL);
            prnt_flag(section->characteristics, PE_SCN_MEM_PURGEABLE);
            prnt_flag(section->characteristics, PE_SCN_MEM_16BIT);
            prnt_flag(section->characteristics, PE_SCN_LNK_NRELOC_OVFL);
            prnt_flag(section->characteristics, PE_SCN_MEM_DISCARDABLE);
            prnt_flag(section->characteristics, PE_SCN_MEM_NOT_CACHED);
            prnt_flag(section->characteristics, PE_SCN_MEM_NOT_PAGED);
            prnt_flag(section->characteristics, PE_SCN_MEM_SHARED);
            prnt_flag(section->characteristics, PE_SCN_MEM_EXECUTE);
            prnt_flag(section->characteristics, PE_SCN_MEM_READ);
            prnt_flag(section->characteristics, PE_SCN_MEM_WRITE);
        }
        append(".\n");

        append("\n");
    }

    append("Imports:\n");
    Imports::iterator itr1 = imports.begin();
    for ( ; itr1 != imports.end(); itr1++) {
        append("\tDLL %s:\n", (itr1->first).c_str());

        DllImportList::iterator itr2 = (itr1->second).begin();
        for ( ; itr2 != (itr1->second).end(); itr2++) {
            struct PEImport import = *itr2;

            append("\t\t[%9d]: %9d -> %s\n", import.ordinal, import.hint, import.name.c_str());
        }
        append("\n");
    }

    append("Exports (ordinal base %d):\n", exports.ordinal_base);
    for (i = 0; i < exports.exports.size(); i++) {
        const char *name = "";
        int index = (i + exports.ordinal_base);
        OrdinalToName::iterator itr3;

        itr3 = exports.ordinal_to_name.find(i);
        // itr3 = exports.ordinal_to_name.find(index);
        if (itr3 == exports.ordinal_to_name.end()) {
            name = "<none>";
        }
        else {
            name = (itr3->second).c_str();
        }

        append("\t[%6d]: %-40s: ", index, name);

        struct PEExportedSymbol exported = exports.exports[i];

        if (exported.is_forwarder) {
            append(" ---> %s", exported.forwarder);
        }
        else {
            append(" %p", (void*)(uint64_t)exported.address);
        }

        append("\n");
    }

    return dump_output;
}
/* ------------------------------------------------------------------------- */

