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

#ifndef __ENVIRONMENT_H__
#define __ENVIRONMENT_H__

extern "C" {
#include "../cpu/cpu.h"
#include "../cpu/virtual_memory.h"
}

#include <string>
#include <map>
#include <list>

class Thread;
class Process;

class Environment {
public:
    class LogInterface {
    public:
        virtual int log(const char *msg);
    };

public:
    Environment();
    virtual ~Environment();

public:
    virtual uint64_t getNewPid();
    virtual void handleProcessNew(Process *process);
    virtual void handleProcessDestroy(Process *process);
    virtual void handleThreadNew(Thread *thread);
    virtual void handleThreadDestroy(Thread *thread);

    virtual void handleProcessMemoryFault(Thread *thread, int code, uint64_t address);
    virtual bool handleProcessSyscall(Thread *thread);
    virtual bool handleProcessSoftInt(Thread *thread, int number);
    virtual bool handleProcessCPUException(Thread *thread);

public:
    Process* createProcess();

    int step(Thread *thread = NULL);

    void threadSaveState(Thread *thread);
    void threadLoadState(Thread *thread);

    void setCurrentThread(Thread *thread);
    inline Thread* getCurrentThread() const { return current_thread; }

public:
    LogInterface *log_interface;
    int log(const char* fmt, ...);

    int log_syscalls;

    typedef std::map<uint64_t, Process*> ProcessMap;
    ProcessMap processes;

    Thread *current_thread;

    struct x64cpu *cpu;
    struct x64cpu_vmem *current_memory;
    int _memory_access(int write, struct x64cpu *cpu,
                            uint64_t address, uint8_t *data, uint8_t size,
                            enum x64cpu_mem_access_flags access,
                            uint64_t *fault_addr);
    static int _memory_read(struct x64cpu *cpu, void *user_data,
                            uint64_t address, uint8_t *data, uint8_t size,
                            enum x64cpu_mem_access_flags access,
                            uint64_t *fault_addr);
    static int _memory_write(struct x64cpu *cpu, void *user_data,
                            uint64_t address, uint8_t *data, uint8_t size,
                            enum x64cpu_mem_access_flags access,
                            uint64_t *fault_addr);


protected:
    uint64_t next_pid;

};

class Process {
public:
    enum State {
        NOT_STARTED     = 0,
        ZOMBIE,
        SUSPEND,
        SLEEPING,
        RUNNING,
    };

    enum Prot {
        PROT_NONE   = 0,
        PROT_READ   = 4,
        PROT_WRITE  = 2,
        PROT_EXEC   = 1,
    };

    struct Segment {
        int free;
        
        uint64_t start;
        uint64_t end;
        int protection;
        std::string name;
    };

    typedef std::list<struct Segment> SegmentList;
    SegmentList segments;

public:
    Process(Environment* environment, uint64_t id);

public:
    Environment* getEnvironment() const { return environment; }
    inline uint64_t getId() const { return id; }

    Thread* createThread(uint64_t start_rip);

    int findAddrForSegment(uint64_t start, uint64_t size,
                                int grow_down, uint64_t padding,
                                uint64_t *out_address);

    struct Segment* addSegment(uint64_t start, uint64_t end,
                                int protection, std::string name,
                                void* physical_page);

    int removeSegment(uint64_t start, uint64_t end);

public:
    void* user_data;

    struct x64cpu_vmem memory;

    State state;

    typedef std::map<uint64_t, Thread*> ThreadMap;
    ThreadMap threads;

    typedef std::list<std::string> ArgumentList;
    ArgumentList arguments;
    typedef std::map<std::string, std::string> EnvironmentMap;
    EnvironmentMap environment_variables;

public:
    std::string dumpSegments(bool show_free = false);

private:
    Environment *environment;
    uint64_t id;

    uint64_t last_thread_id;

};

class Thread {
public:
    Thread(Process *process, uint64_t id);

public:
    Process* getProcess() const { return process; }
    inline uint64_t getId() const { return id; }
public:
    void* user_data;

    struct x64cpu_regs saved_regs;

private:
    Process *process;
    uint64_t id;

};


#endif /* __ENVIRONMENT_H__ */

