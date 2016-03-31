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

#include "Environment.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------- */
int Environment::LogInterface::log(const char *msg) {
    return fprintf(stderr, "%s\n", msg);
}
/* ------------------------------------------------------------------------- */
Environment::Environment() {
    /* Allocate and initialize CPU */
    this->cpu = x64cpu_create();

    /* Clear pointers */
    this->log_interface = NULL;

    /* Set memory callbacks */
    this->cpu->user_data = this;
    this->cpu->mem_read = Environment::_memory_read;
    this->cpu->mem_write = Environment::_memory_write;

    /* Process list */
    this->current_memory = NULL;
    this->current_thread = NULL;

    /* pids */
    this->next_pid = 100;

    // TODO: debug
    this->log_syscalls = 1;
}
/* ------------------------------------------------------------------------- */
Environment::~Environment() {
    x64cpu_destroy(this->cpu);
}
/* ------------------------------------------------------------------------- */
uint64_t Environment::getNewPid() {
    return ++this->next_pid;
}
/* ------------------------------------------------------------------------- */
void Environment::handleProcessNew(Process *process) {
}
/* ------------------------------------------------------------------------- */
void Environment::handleProcessDestroy(Process *process) {
}
/* ------------------------------------------------------------------------- */
void Environment::handleThreadNew(Thread *thread) {
}
/* ------------------------------------------------------------------------- */
void Environment::handleThreadDestroy(Thread *thread) {
}
/* ------------------------------------------------------------------------- */
void Environment::handleProcessMemoryFault(Thread *thread, int code, uint64_t address) {
}
/* ------------------------------------------------------------------------- */
bool Environment::handleProcessSyscall(Thread *thread) {
    return false;
}
/* ------------------------------------------------------------------------- */
bool Environment::handleProcessSoftInt(Thread *thread, int number) {
    return false;
}
/* ------------------------------------------------------------------------- */
bool Environment::handleProcessCPUException(Thread *thread) {
    return false;
}
/* ------------------------------------------------------------------------- */
Process* Environment::createProcess() {
    Process *process = NULL;

    process = new Process(this, this->getNewPid());

    /* Add to process list */
    // TODO: avoid duplicates
    this->processes[process->getId()] = process;

    /* Notity environment */
    this->handleProcessNew(process);

    return process;
}
/* ------------------------------------------------------------------------- */
int Environment::step(Thread *thread) {
    int ret = -1;
    Process* process = NULL;

    if (thread == NULL) {
        thread = this->current_thread;
    }
    else if (thread != this->current_thread) {
        this->setCurrentThread(thread);
    }

    process = thread->getProcess();

    if (cpu->is_halted) {
        return 1;
    }

    switch (process->state) {
        case Process::SUSPEND:
        case Process::ZOMBIE:
            return 1;
    }
          
    ret = x64cpu_execute(cpu);
    if (ret != 0) {
        /* Check for syscall */
        if (ret == X64CPU_RES_SYSCALL) {
            if (this->handleProcessSyscall(thread) == false) {
                /* Unhandled */
                log("Environment didn't handle 'syscall' rax %016lx.", cpu->regs.rax);
                process->state = Process::SUSPEND;
            }
            else {
                ret = 0;
            }
        }
        /* Check for interrupts */
        else if (ret == X64CPU_RES_SOFTINT) {
            if (this->handleProcessSoftInt(thread, cpu->interrupt_number) == false) {
                /* Unhandled */
                log("Environment didn't handle interrupt 0x%02x.",
                    cpu->interrupt_number);
                process->state = Process::SUSPEND;
            }
            else {
                ret = 0;
            }
        }
        /* Check for exception */
        else if (ret == X64CPU_RES_EXCEPTION) {
            if (this->handleProcessCPUException(thread) == false) {
                /* Unhandled */
                log("Unhandled CPU Exception (%d): [%d] %s at RIP 0x%016lx in thread %d process %d.",
                    cpu->execution_result,
                    cpu->cpu_exception.code, x64cpu_exception_name(cpu->cpu_exception.code),
                    cpu->cpu_exception.rip,
                    thread->getId(), process->getId()
                );
                process->state = Process::SUSPEND;
            }
            else {
                ret = 0;
            }
        }
        else {
            /* Unknown CPU error */
            log("Unknown CPU error code %d.", ret);
            process->state = Process::SUSPEND;
        }
    }

    /* Save thread state when stepping; to allow inspection */
    this->threadSaveState(thread);

    return ret;
}
/* ------------------------------------------------------------------------- */
void Environment::threadSaveState(Thread *thread) {
    /* Save register state to the thread */
    memcpy(&thread->saved_regs, &this->cpu->regs, sizeof(thread->saved_regs));
}
/* ------------------------------------------------------------------------- */
void Environment::threadLoadState(Thread *thread) {
    /* Load register state from the thread */
    memcpy(&this->cpu->regs, &thread->saved_regs, sizeof(thread->saved_regs));
}
/* ------------------------------------------------------------------------- */
void Environment::setCurrentThread(Thread *thread) {
    if (thread == this->current_thread) {
        return;
    }

    if (this->current_thread) {
        this->threadSaveState(this->current_thread);
        this->current_memory = NULL;
    }
    this->current_thread = thread;
    if (this->current_thread) {
        this->threadLoadState(this->current_thread);
        this->current_memory = &(thread->getProcess()->memory);
    }
}
/* ------------------------------------------------------------------------- */
int Environment::log(const char* fmt, ...) {
    int rc;
    char *buffer = NULL;

    va_list va_args;
    va_start(va_args, fmt);
    rc = vasprintf(&buffer, fmt, va_args);
    va_end(va_args);

    if (this->log_interface) {
        rc = this->log_interface->log(buffer);
    }
    else {
        rc = fprintf(stderr, "%s\n", buffer);
    }

    free(buffer);
    return rc;
}
/* ------------------------------------------------------------------------- */
int Environment::_memory_access(int write, struct x64cpu *cpu,
                        uint64_t address, uint8_t *data, uint8_t size,
                        enum x64cpu_mem_access_flags access,
                        uint64_t *fault_addr_ptr) {
    struct x64cpu_vmem *mem = NULL;
    int rc;
    uint64_t fault_addr = 0;

    mem = this->current_memory;

    if (mem == NULL) {
        if (fault_addr_ptr != NULL) {
            (*fault_addr_ptr) = address;
        }
        return X64CPU_MEM_ACCESS_PF;
    }

    if (write == 0) {
        rc = x64cpu_vmem_read(mem, address, data, size, access, &fault_addr);
    }
    else {
        rc = x64cpu_vmem_write(mem, address, data, size, access, &fault_addr);
    }

    if (rc != X64CPU_MEM_ACCESS_SUCCESS) {
        if (fault_addr_ptr != NULL) {
            (*fault_addr_ptr) = fault_addr;
        }

        this->handleProcessMemoryFault(getCurrentThread(), rc, fault_addr);

        // TODO: suspend process
        getCurrentThread()->getProcess()->state = Process::SUSPEND;
    }

    return rc;
}
/* ------------------------------------------------------------------------- */
int Environment::_memory_read(struct x64cpu *cpu, void *user_data,
                        uint64_t address, uint8_t *data, uint8_t size,
                        enum x64cpu_mem_access_flags access,
                        uint64_t *fault_addr) {
    Environment *env = (Environment*)user_data;

    return env->_memory_access(0, cpu, address, data, size, access, fault_addr);
}
/* ------------------------------------------------------------------------- */
int Environment::_memory_write(struct x64cpu *cpu, void *user_data,
                        uint64_t address, uint8_t *data, uint8_t size,
                        enum x64cpu_mem_access_flags access,
                        uint64_t *fault_addr) {
    Environment *env = (Environment*)user_data;

    return env->_memory_access(1, cpu, address, data, size, access, fault_addr);
}
/* ------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------- */
Process::Process(Environment *environment, uint64_t id) {
    this->environment = environment;
    this->id = id;

    this->last_thread_id = 1;

    /* One big free memory segment */
    segments.insert(segments.end(), (struct Segment) {
        .free = 1,
        .start = 0x00,
        .end = 0xffffffffffffffff,
        .protection = PROT_NONE
    });
}
/* ------------------------------------------------------------------------- */
Thread* Process::createThread(uint64_t start_rip) {
    Thread *thread = NULL;

    thread = new Thread(this, /* TODO: thread id */ last_thread_id++);

    memset(&thread->saved_regs, 0, sizeof(thread->saved_regs));
    thread->saved_regs.rip = start_rip;

    /* Add to thread list */
    // TODO: avoid duplicates
    this->threads[thread->getId()] = thread;

    /* Notify environment */
    this->environment->handleThreadNew(thread);

    return thread;
}
/* ------------------------------------------------------------------------- */
int Process::findAddrForSegment(uint64_t start, uint64_t size,
                            int grow_down, uint64_t padding,
                            uint64_t *out_address) {
    int ret = -1;
    uint64_t address;

    if (!grow_down) {
    }
    else {
        SegmentList::reverse_iterator itr;
        uint64_t actual_size = size + padding;

        if ((actual_size & X64CPU_VMEM_PAGE_OFFSET_MASK) != 0) {
            actual_size += X64CPU_VMEM_PAGE_SIZE;
            actual_size &= X64CPU_VMEM_PAGE_ADDR_MASK;
        }

        for (itr = segments.rbegin(); itr != segments.rend(); itr++) {
            struct Segment *s = &(*itr);

            if (s->free == 0 || ((s->end - s->start) < actual_size) || (s->start > start)) {
                continue;
            }

            if ((s->start + actual_size) > start) {
                continue;
            }

            if (s->end > start) {
                address = start - actual_size;
            }
            else {
                address = s->end - actual_size;
            }

            ret = 0;
            break;
        }
    }

    if (ret == 0) {
        (*out_address) = address;
    }

_err:
    return ret;
}
/* ------------------------------------------------------------------------- */
struct Process::Segment* Process::addSegment(uint64_t start, uint64_t end,
                                int protection, std::string name,
                                void* physical_page) {
    struct Segment *ret = NULL;
    SegmentList::iterator itr;
    uint64_t size;

    if ((start & X64CPU_VMEM_PAGE_OFFSET_MASK) != 0) {
        return NULL;
    }

    size = (end - start);

    if ((size & X64CPU_VMEM_PAGE_OFFSET_MASK) != 0) {
        size += X64CPU_VMEM_PAGE_SIZE;
        size &= X64CPU_VMEM_PAGE_ADDR_MASK;
    }

    end += (size - (end - start));

    for (itr = segments.begin(); itr != segments.end(); itr++) {
        struct Segment *s = &(*itr);

        if (s->free == 0) {
            continue;
        }

        if (!((s->start <= start) && (s->end >= end))) {
            continue;
        }

        if (s->start < start) {
            segments.insert(itr, (struct Segment) {
                .free = 1,
                .start = s->start,
                .end = start,
                .protection = PROT_NONE,
                .name = ""
            });
        }
        if (s->end > end) {
            itr++;
            segments.insert(itr, (struct Segment) {
                .free = 1,
                .start = end,
                .end = s->end,
                .protection = PROT_NONE,
                .name = ""
            });
        }

        s->free = 0;
        s->start = start;
        s->end = end;
        s->protection = protection;
        s->name = name;

        ret = s;
        break;
    }

    /* Segment successfully added ? Map memory */
    if (ret != NULL) {
        int rc, flags;
        uint64_t pages = (ret->end - ret->start) / X64CPU_VMEM_PAGE_SIZE;

        flags = X64CPU_VMEM_PAGE_FLAG_U;
        if ((protection & PROT_READ) != 0) {
            flags |= X64CPU_VMEM_PAGE_FLAG_P;
        }
        if ((protection & PROT_WRITE) != 0) {
            flags |= X64CPU_VMEM_PAGE_FLAG_RW;
        }
        if ((protection & PROT_EXEC) != 0) {
            /* TODO: no flag yet */
        }

        rc = x64cpu_vmem_map(&memory, ret->start, (ret->end - ret->start), flags,
                                (uint8_t*)physical_page, 1);
        if (rc < pages) {
            /* TODO: problem ... */
            return NULL;
        }
    }

    return ret;
}
/* ------------------------------------------------------------------------- */
int Process::removeSegment(uint64_t start, uint64_t end) {
    int ret = -1;
    SegmentList::iterator itr;
    uint64_t size;

    if ((start & X64CPU_VMEM_PAGE_OFFSET_MASK) != 0) {
        return -1;
    }

    size = (end - start);

    if ((size & X64CPU_VMEM_PAGE_OFFSET_MASK) != 0) {
        size += X64CPU_VMEM_PAGE_SIZE;
        size &= X64CPU_VMEM_PAGE_ADDR_MASK;
    }

    end += (size - (end - start));

    for (itr = segments.begin(); itr != segments.end(); itr++) {
        struct Segment *s = &(*itr);

        if (s->start == start && s->end == end) {
            if (s->free == 1) {
                break;
            }

            /* Unmap and remove segment */
            x64cpu_vmem_unmap(&memory, s->start, (s->end - s->start));

            s->protection = PROT_NONE;
            s->name = "";
            s->free = 1;
            break;
        }
        else if (end > s->start && start < s->end) {
            /* This might hit 2 existing segments */

            if (s->free == 1) {
                continue;
            }

            /* Must split ? */
            if (s->start < start) {
                /* A piece before */
                segments.insert(itr, (struct Segment) {
                    .free = s->free,

                    .start = s->start,
                    .end = start,
                    .protection = s->protection,
                    .name = s->name
                });
            }
            if (s->end > end) {
                /* A piece after */
                segments.insert(++itr, (struct Segment) {
                    .free = s->free,

                    .start = end,
                    .end = s->end,
                    .protection = s->protection,
                    .name = s->name
                });
            }

            /* Unmap and remove segment */
            x64cpu_vmem_unmap(&memory, start, (end - start));

            s->start = start;
            s->end = end;
            s->protection = PROT_NONE;
            s->name = "";
            s->free = 1;
            continue;
        }
    }

    /* Reglue free regions */
    // todo: ...

    /* Success */
    ret = 0;

_end:
    return ret;
}
/* ------------------------------------------------------------------------- */
std::string Process::dumpSegments(bool show_free) {
    std::string ret;
    SegmentList::iterator itr;
    char buf[1024];

    snprintf(buf, sizeof(buf),
             "%18s    %18s    %18s    %6s    %1s%1s%1s    %s\n",
             "START", "END", "SIZE", "STATE", "", "", "", "NAME"
    );
    ret = buf;
    ret += "---------------------------------------------------------------------------------------\n";

    for (itr = segments.begin(); itr != segments.end(); itr++) {
        struct Segment *s = &(*itr);

        if (s->free && !show_free) {
            continue;
        }

        snprintf(buf, sizeof(buf),
                 "0x%016lx    0x%016lx    0x%016lx    %6s    %1s%1s%1s    %s\n",
                s->start, s->end, (s->end - s->start),
                (s->free ? "FREE" : "COMMIT"),
                ((s->protection & PROT_READ) ? "R": " "),
                ((s->protection & PROT_WRITE) ? "W": " "),
                ((s->protection & PROT_EXEC) ? "X": " "),
                s->name.c_str()
        );

        ret += buf;
    }

    return ret;
}
/* ------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------- */
Thread::Thread(Process *process, uint64_t id) {
    this->process = process;
    this->id = id;
}
/* ------------------------------------------------------------------------- */

