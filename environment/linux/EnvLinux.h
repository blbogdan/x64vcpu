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

#ifndef __ENVIRONMENT_LINUX_H__
#define __ENVIRONMENT_LINUX_H__

#include "../Environment.h"

#include "EnvLinuxIO.h"

class EnvLinux : public Environment {
public:
    typedef uint64_t (*syscall_handler_t)(uint64_t number, EnvLinux *env,
                        Process* proc, Thread *thread, uint64_t params[6]);

    struct ProcessData {
        uint32_t exit_code;

        int uid, gid;
        int euid, egid;

        uint64_t stack_size;
        uint64_t stack_arena;
        uint64_t maps_arena;

        uint64_t heap_base;
        uint64_t heap_top;

        syscall_handler_t syscall_handlers[256];

        EnvLinuxIO *io_manager;
        typedef std::map<int, EnvLinuxIOFile*> FileDescriptorMap;
        FileDescriptorMap file_descriptors;
        int next_fd;
    };

public:
    EnvLinux();

    virtual ~EnvLinux();

public:
    virtual void handleProcessNew(Process *process);
    virtual void handleProcessDestroy(Process *process);
    virtual void handleThreadNew(Thread *thread);
    virtual void handleThreadDestroy(Thread *thread);

    virtual void handleProcessMemoryFault(Thread *thread, int code, uint64_t address);
    virtual bool handleProcessSyscall(Thread *thread);

public:
    uint64_t threadCreateStack(Thread *thread);

    void installStdinStderr(Process *process);

};

#endif /* __ENVIRONMENT_LINUX_H__ */

