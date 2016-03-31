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

#include "EnvLinux.h"
#include "EnvLinuxSyscall.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>

#define DECL_PDATA(source) \
    struct ProcessData *pdata = (struct ProcessData*)((source)->user_data);

/* ------------------------------------------------------------------------- */
EnvLinux::EnvLinux() {
}
/* ------------------------------------------------------------------------- */
EnvLinux::~EnvLinux() {
}
/* ------------------------------------------------------------------------- */
void EnvLinux::handleProcessNew(Process *process) {
    struct ProcessData *pdata = new struct ProcessData();
    process->user_data = pdata;

    pdata->stack_size = 136 * 1024;
    pdata->stack_arena = 0x7ffffffff000;
    pdata->maps_arena = 0x7ffff7fff000;

    EnvLinuxSyscall::installSyscalls(pdata->syscall_handlers);

    installStdinStderr(process);
    pdata->io_manager = new EnvLinuxIO();
    pdata->next_fd = 3;
}
/* ------------------------------------------------------------------------- */
void EnvLinux::handleProcessDestroy(Process *process) {
    delete (struct ProcessData*)(process->user_data);
}
/* ------------------------------------------------------------------------- */
void EnvLinux::handleThreadNew(Thread *thread) {
    uint64_t rsp;

    rsp = this->threadCreateStack(thread);
    if (rsp != 0) {
        thread->saved_regs.rsp = rsp;
        thread->saved_regs.rbp = thread->saved_regs.rsp;
    }
}
/* ------------------------------------------------------------------------- */
void EnvLinux::handleThreadDestroy(Thread *thread) {
}
/* ------------------------------------------------------------------------- */
void EnvLinux::handleProcessMemoryFault(Thread *thread, int code, uint64_t address) {
}
/* ------------------------------------------------------------------------- */
bool EnvLinux::handleProcessSyscall(Thread *thread) {
    uint64_t ret = -1;
    Process *proc = thread->getProcess();
    DECL_PDATA(proc);

    /* Get syscall index */
    uint64_t index = cpu->regs.rax;

    if (index < 0 || index >= 256) {
        return false;
    }

    /* Params */
    uint64_t params[6] = {
        cpu->regs.rdi,
        cpu->regs.rsi,
        cpu->regs.rdx,
        cpu->regs.r10,
        cpu->regs.r8,
        cpu->regs.r9
    };

    syscall_handler_t handler = pdata->syscall_handlers[index];
    if (handler == NULL) {
        return false;
    }

    ret = handler(index, this, proc, thread, params);

if (0 && cpu->regs.rax == 0x09) {
    std::string tmp = proc->dumpSegments();
    fprintf(stdout, "%s\n", tmp.c_str());
}

    cpu->regs.rax = ret;

if (log_syscalls) { log("  returned 0x%016lx", ret); }

    cpu->is_halted = 0;

    return true;
}
/* ------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------- */
uint64_t EnvLinux::threadCreateStack(Thread *thread) {
    uint64_t ret = 0;
    Process *proc = thread->getProcess();
    DECL_PDATA(proc);
    struct Process::Segment *segment;
    int flags = Process::PROT_READ | Process::PROT_WRITE;
    uint64_t stack_top, stack_bottom;
    char name[128];

    snprintf(name, sizeof(name), "[stack.0x%lx]", thread->getId());

    ret = proc->findAddrForSegment(pdata->stack_arena, pdata->stack_size, 1, 0, &stack_top);
    if (ret != 0) {
        /* Failed ... out of memory ? */
        ret = -1;
        return ret;
    }

    stack_bottom = stack_top + pdata->stack_size;

    segment = proc->addSegment(stack_top, stack_bottom, flags, name, NULL);
    if (segment == NULL) {
        /* TODO: failed ... */
        /* Failed ... out of memory ? */
        ret = -1;
        return ret;
    }

    ret = segment->end;

    return ret;
}
/* ------------------------------------------------------------------------- */
class StdIOFile : public EnvLinuxIOFile {
public:
    StdIOFile(EnvLinux *env, int fd) { this->env = env; this->fd = fd; }
    virtual ~StdIOFile() { }

public:
    void close() {
    }

    ssize_t read(void *buf, size_t count) {
        return 0;
    }

    ssize_t write(void *buf, size_t count) {
#if 1
        fprintf(stdout, "%.*s", count, buf);
#else
        return env->log("%d> %.*s", this->fd, count, buf, this->fd);
#endif
    }

    int fstat(struct stat *statbuf) {
        return ::fstat(this->fd, statbuf);
    }

    ssize_t seek(off_t offset, int whence) {
        return 0;
    }

    int ioctl(unsigned long request, void *argp) {
        switch (request) {
            /* TCGETS - struct termios* */
            case 0x5401: {
                // TODO
                break;
            }
        }

        return -1;
    }

private:
    EnvLinux *env;
    int fd;

};

void EnvLinux::installStdinStderr(Process *proc) {
    StdIOFile *out = NULL, *err = NULL;
    DECL_PDATA(proc);

    out = new StdIOFile(this, 1);
    err = new StdIOFile(this, 2);

    pdata->file_descriptors[1] = out;
    pdata->file_descriptors[2] = err;
}
/* ------------------------------------------------------------------------- */

