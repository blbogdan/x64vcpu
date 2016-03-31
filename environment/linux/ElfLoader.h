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

#ifndef __ENV_LINUX_ELF_LOADER_H__
#define __ENV_LINUX_ELF_LOADER_H__

#include "EnvLinux.h"

extern "C" {
#include "elf-file.h"
}

class ElfLoader {
public:
    enum Error {
        ERROR_NONE = 0,
        ERROR_NOT_SUPPORTED_ARCH,
    };

protected:
    ElfLoader();

public:
    virtual ~ElfLoader();

public:
    static int loadProcess(Process *proc, struct elf_file *elf, const char *module_name,
                            Thread **out_main_thread);

    struct LoadData {
        uint64_t header_addr;
        uint64_t ph_ent;
        uint64_t ph_num;
        uint64_t interp_load_addr;
        uint64_t entry_point;
        uint64_t start_rip;
    };

    int buildEnv(struct LoadData *load_data, Thread *th, struct elf_file *elf, const char *binary_path);
    int loadImage(struct elf_file *elf, const char *module_name,
                            int main_module, struct LoadData *load_data,
                            uint64_t *out_base_offset);

    static int loadElfFromFile(const char *filename, struct elf_file **out_elf);

protected:
    EnvLinux *env;
    Process *proc;
    struct EnvLinux::ProcessData *pdata;
    Thread *thread;
    std::string module_name;

};

#endif /* __ENV_LINUX_ELF_LOADER_H__ */

