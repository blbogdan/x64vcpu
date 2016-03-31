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

#ifndef __PE_FILE_H__
#define __PE_FILE_H__

#include <stdint.h>

#include <string>
#include <list>
#include <map>
#include <vector>

enum PEMachineType {
    PE_MACHINE_UNKNOWN      = 0x00,

    PE_MACHINE_AMD64        = 0x8664,   /* x64 */
    PE_MACHINE_ARM          = 0x1c0,    /* ARM little endian */
    PE_MACHINE_ARMNT        = 0x1c4,    /* ARMv7 (or higher) Thumb mode only */
    PE_MACHINE_ARM64        = 0xaa64,   /* ARMv8 in 64-bit mode */
    PE_MACHINE_EBC          = 0xebc,    /* EFI byte code */
    PE_MACHINE_I386         = 0x14c,    /* I386 */

    /* Other types are not needed / specified */

    PE_MACHINE_LAST
};

enum PECharacteristics {
    PE_RELOCS_STRIPPED          = 0x0001,
    PE_EXECUTABLE_IMAGE         = 0x0002,
    PE_LINE_NUM_STRIPPED        = 0x0004,   /* Deprecated */
    PE_LOCAL_SYMS_STRIPPED      = 0x0008,   /* Deprecated */
    PE_AGGRESSIVE_WS_TRIM       = 0x0010,   /* Obsolete */
    PE_LARGE_ADDRESS_AWARE      = 0x0020,
    PE_RESERVED                 = 0x0040,   /* Reserved */
    PE_BYTES_REVERSED_LO        = 0x0080,   /* Deprecated */
    PE_32BIT_MACHINE            = 0x0100,
    PE_DEBUG_STRIPPED           = 0x0200,
    PE_REMOVABLE_RUN_FROM_SWAP  = 0x0400,
    PE_SYSTEM                   = 0x1000,
    PE_DLL                      = 0x2000,
    PE_UP_SYSTEM_ONLY           = 0x4000,   /* Should be run only be uniprocessor machine */
    PE_BYTES_REVERSED_HI        = 0x8000,   /* Deprecated */
};

enum PEOptionalHeaderMagic {
    PE_PE32                     = 0x10b,
    PE_PE32_PLUS                = 0x20b,
    PE_ROM                      = 0x107, /* ?? */
};

enum PEWindowsSubsystem {
    PE_SUBSYSTEM_UNKNOWN             = 0x00,
    PE_SUBSYSTEM_NATIVE              = 0x01,     /* Device drivers and native Windows processes */
    PE_SUBSYSTEM_WINDOWS_GUI         = 0x02,     /* GUI subsystem */
    PE_SUBSYSTEM_WINDOWS_CUI         = 0x03,     /* Character subsystem */
    PE_SUBSYSTEM_POSIX_CUI           = 0x07,     /* Posix character subsystem */
    PE_SUBSYSTEM_WINDOW_CE_GUI       = 0x09,     /* Windows CE */
    PE_SUBSYSTEM_EFI_APPLICATION     = 0x10,     /* EFI Application */
    PE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 0x11, /* EFI driver with boot services */
    PE_SUBSYSTEM_EFI_RUNTIME_DRIVER  = 0x12,     /* EFI driver with run-time services */
    PE_SUBSYSTEM_EFI_ROM             = 0x13,     /* EFI ROM Image */
    PE_SUBSYSTEM_XBOX                = 0x14,     /* XBOX */
};

enum PEDllPECharacteristics {
    PE_DLL_CHARACTERISTICS_RESERVED1         = 0x0001,
    PE_DLL_CHARACTERISTICS_RESERVED2         = 0x0002,
    PE_DLL_CHARACTERISTICS_RESERVED3         = 0x0004,
    PE_DLL_CHARACTERISTICS_RESERVED4         = 0x0008,
    PE_DLL_CHARACTERISTICS_DYNAMIC_BASE      = 0x0040,
    PE_DLL_CHARACTERISTICS_FORCE_INTEGRITY   = 0x0080,
    PE_DLL_CHARACTERISTICS_NX_COMPAT         = 0x0100,
    PE_DLL_CHARACTERISTICS_NO_ISOLATION      = 0x0200,
    PE_DLL_CHARACTERISTICS_NO_SEH            = 0x0400,
    PE_DLL_CHARACTERISTICS_NO_BIND           = 0x0800,
    PE_DLL_CHARACTERISTICS_RESERVED5         = 0x1000,
    PE_DLL_CHARACTERISTICS_WDM_DRIVER        = 0x2000,
    PE_DLL_CHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000,
};

enum PEDataDirectories {
    PE_DATA_EXPORT_TABLE           = 0,
    PE_DATA_IMPORT_TABLE,
    PE_DATA_RESOURCE_TABLE,
    PE_DATA_EXCEPTION_TABLE,
    PE_DATA_CERTIFICATE_TABLE,
    PE_DATA_BASE_RELOCATION_TABLE,
    PE_DATA_DEBUG,
    PE_DATA_ARCHITECTURE,
    PE_DATA_GLOBAL_PTR,
    PE_DATA_TLS_TABLE,
    PE_DATA_LOAD_CONFIG_TABLE,
    PE_DATA_BOUND_IMPORT,
    PE_DATA_IAT,
    PE_DATA_DELAY_IMPORT,
    PE_DATA_CLR_RUNTIME_HEADER,
    PE_DATA_RESERVED,

    PE_DATA_LAST
};

enum PESectionFlags {
    PE_SCN_TYPE_NO_PAD               = 0x00000008,
    PE_SCN_CNT_CODE                  = 0x00000020,
    PE_SCN_CNT_INITIALIZED_DATA      = 0x00000040,
    PE_SCN_CNT_UNINITIALIZED_DATA    = 0x00000080,
    PE_SCN_LNK_OTHER                 = 0x00000100,   /* Reserved */
    PE_SCN_GPREL                     = 0x00008000,
    PE_SCN_MEM_PURGEABLE             = 0x00020000,   /* Reserved */
    PE_SCN_MEM_16BIT                 = 0x00020000,   /* Reserved ; for ARM Thumb code */
    PE_SCN_LNK_NRELOC_OVFL           = 0x01000000,
    PE_SCN_MEM_DISCARDABLE           = 0x02000000,
    PE_SCN_MEM_NOT_CACHED            = 0x04000000,
    PE_SCN_MEM_NOT_PAGED             = 0x08000000,
    PE_SCN_MEM_SHARED                = 0x10000000,
    PE_SCN_MEM_EXECUTE               = 0x20000000,
    PE_SCN_MEM_READ                  = 0x40000000,
    PE_SCN_MEM_WRITE                 = 0x80000000,
};

enum PEBaseRelocationType {
    PE_REL_BASED_ABSOLUTE            = 0,
    PE_REL_BASED_HIGH                = 1,
    PE_REL_BASED_LOW                 = 2,
    PE_REL_BASED_HIGHLOW             = 3,
    PE_REL_BASED_HIGHADJ             = 4,
    PE_REL_BASED_MIP_JMPADDR         = 5,
    PE_REL_BASED_ARM_MOV32A          = 5,
    PE_REL_BASED_RESERVED1           = 6,
    PE_REL_BASED_ARM_MOV32T          = 7,
    PE_REL_BASED_MIPS_JMPADDR16      = 9,
    PE_REL_BASED_DIR64               = 10,
};

struct PECOFFHeader {
    uint8_t         signature[4];
    uint16_t        machine;
    uint16_t        number_of_sections;
    uint32_t        time_date_stamp;
    uint32_t        pointer_to_symbol_table;
    uint32_t        number_of_symbols;
    uint16_t        size_of_optional_header;
    uint16_t        characteristics;
};

struct PECOFFOptionalHeader {
    uint16_t        magic;
    uint8_t         major_linker_version;
    uint8_t         minor_linker_version;
    uint32_t        size_of_code;
    uint32_t        size_of_initialized_data;
    uint32_t        size_of_uninitialized_data;
    uint32_t        address_of_entry_point;
    uint32_t        base_of_code;

    /* Absent in PE32+ */
    uint32_t        base_of_data;
};

struct PEImageDataDirectory {
    uint32_t        virtual_address;
    uint32_t        size;
};

/* PE-specific COFF optional header */
struct PEHeader {
    uint64_t        image_base;                 /* 32 - PE32, 64 - PE32+ */
    uint32_t        section_alignment;
    uint32_t        file_alignment;
    uint16_t        major_os_version;
    uint16_t        minor_os_version;
    uint16_t        major_image_version;
    uint16_t        minor_image_version;
    uint16_t        major_subsystem_version;
    uint16_t        minor_subsystem_version;
    uint32_t        win32_version_value;        /* Reserved, must be 0 */
    uint32_t        size_of_image;
    uint32_t        size_of_headers;
    uint32_t        checksum;
    uint16_t        subsystem;
    uint16_t        dll_characteristics;
    uint64_t        size_of_stack_reserve;      /* 32 - PE32, 64 - PE32+ */
    uint64_t        size_of_stack_commit;      /* 32 - PE32, 64 - PE32+ */
    uint64_t        size_of_heap_reserve;       /* 32 - PE32, 64 - PE32+ */
    uint64_t        size_of_heap_commit;        /* 32 - PE32, 64 - PE32+ */
    uint32_t        loader_flags;               /* Reserved, must be 0 */
    uint32_t        number_of_rva_and_sizes;

    struct PEImageDataDirectory data_directory[PE_DATA_LAST];
};

/* Section table */
struct PESectionTable {
    char            name[8];                    /* NO NULL BYTE IF 8 CHARS LONG */
    uint32_t        virtual_size;
    uint32_t        virtual_address;
    uint32_t        size_of_raw_data;
    uint32_t        pointer_to_raw_data;
    uint32_t        pointer_to_relocations;
    uint32_t        pointer_to_line_numbers;
    uint16_t        number_of_relocations;
    uint16_t        number_of_line_numbers;
    uint32_t        characteristics;
};

struct PESection : public PESectionTable {
    uint8_t*        data;   /* Section data loaded from file */
};


class PEFile {
public:
    enum io_callback_op {
        IO_CB_OP_SEEK,
        IO_CB_OP_READ
    };
    /**
     * I/O callback method, used by PEFile to parse the input.
     *
     * @param buffer The buffer to read into (if NULL, seek to n).
     * @param n Number of bytes to read (if buffer is NULL, seek to this position).
     *
     * @return >= 0 on success ; -errno on error
     */
    typedef int (*io_callback)(enum io_callback_op op, void *user_data, void *buffer, int n);

public:

    /* Import Directory Table */
    struct PEImportDirectoryTable {
        uint32_t        lookup_table_rva;
        uint32_t        timestamp;
        uint32_t        forwarder_chain;
        uint32_t        name_rva;
        uint32_t        address_table_rva;
    };

    /* Import Lookup Table */
    struct PEImportLookupTable {
        union {
            uint16_t        ordinal;
            uint32_t        table_rva;
            int32_t         flag32;
            int64_t         flag64;
        };
    };

    /* HintName Table */
    struct PEHintNameTable {
        uint16_t            hint;
        char                name[];
    };

    /* Export Directory Table */
    struct PEExportDirectoryTable {
        uint32_t            export_flags;       /* Reserved, must be 0 */
        uint32_t            time_date_stamp;
        uint16_t            major_version;
        uint16_t            minor_version;
        uint32_t            name_rva;
        uint32_t            ordinal_base;
        uint32_t            address_table_entries;
        uint32_t            number_of_name_pointers;
        uint32_t            export_address_table_rva;
        uint32_t            name_pointer_rva;
        uint32_t            ordinal_table_rva;
    };

    /* Export Address Table */
    struct PEExportAddressTable {
        union {
            uint32_t            export_rva;
            uint32_t            forwarder_rva;
        };
    };

    /* Export Name Pointer Table */
    struct PEExportNamePointerTable {
        uint32_t            name_rva;
    };

    /* Export Ordinal Table */
    struct PEExportOrdinalTable {
        uint16_t            ordinal;
    };


    /* Base relocation block */
    struct PEBaseRelocationBlock {
        uint32_t            page_rva;
        uint32_t            block_size;
    };


    /* Imports */
    struct PEImport {
        uint16_t        ordinal;
        uint16_t        hint;
        std::string     name;
    };
    typedef std::list<struct PEImport> DllImportList;
    typedef std::map<std::string, DllImportList> Imports;
    typedef std::map<uint64_t, std::vector<std::string> > ImportsAddressTable;


    /* Exports */
    struct PEExportedSymbol {
        union {
            uint32_t        address;
            const char*     forwarder;
        };
        uint8_t is_forwarder;
    };

    typedef std::map<std::string, uint16_t> NameToOrdinal;
    typedef std::map<std::string, struct PEExportedSymbol> NameToExport;
    typedef std::map<uint32_t, std::string> AddressToName;
    typedef std::map<uint16_t, std::string> OrdinalToName;

    struct PEExport {
        uint32_t                        export_flags;
        uint32_t                        time_date_stamp;
        uint16_t                        major_version;
        uint16_t                        minor_version;

        std::vector<PEExportedSymbol>     exports;
        NameToOrdinal                   names;
        OrdinalToName                   ordinal_to_name;
        uint32_t                        ordinal_base;

        NameToExport                    name_to_export;
        AddressToName                   address_to_name;
    };
    typedef struct PEExport Exports;

    /* Relocations */
    typedef std::map<uint64_t, enum PEBaseRelocationType> Relocations;
    

public:
    struct {
        uint8_t *data;
        uint64_t length;
    } raw_header;

    struct PECOFFHeader coff_header;
    struct PECOFFOptionalHeader coff_optional_header;
    struct PEHeader pe_header;
    struct PESection* sections;

    Imports imports;
    ImportsAddressTable imports_address_table;
    Exports exports;
    Relocations relocations;

    std::string name;

protected:
    PEFile(const char *name, io_callback io_fn, void *io_user_data);

    int parse();

public:
    static PEFile* loadPE(const char *name, io_callback io_fn, void *io_user_data);
    int parse_result;

    virtual ~PEFile();

public:
    uint64_t getMemorySize() const;

    std::string dump();

    void *log_user_data;
    int (*_logger)(void *user_data, const char *msg);

protected:
    int logError(const char *fmt, ...);

    virtual void writeLog(const char *msg);

    int readImports();

    int readExports();

    int readRelocations();

private:
    io_callback io_fn;
    void *io_user_data;

};

#endif /* __PE_FILE_H__ */

