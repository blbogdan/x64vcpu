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

#include "../Debugger.h"

extern "C" {
#include "../../cpu/cpu.h"
#include "../../cpu/opcode_decoder.h"
}

#include <list>

/* ------------------------------------------------------------------------- */
class CallStack : public Debugger::Module {
public:
    CallStack() {
        this->init = false;
    }

    int update() {
        std::list<uint64_t>::iterator itr;
#ifdef _WINENV
        WinProcess* proc = dbg->getProcess();
#else
        Process* proc = dbg->getProcess();
#endif

        console->clear();

        console->printf("[*] Call stack:\n");
        for (itr = this->call_stack.begin(); itr != this->call_stack.end(); itr++) {
            uint64_t address = (*itr);
            std::string name = "";

#ifdef _WINENV
            if (proc->findSymbolAtAddress(address, name) == 0) {
            }
#endif

            console->printf("\t0x%016lx: <%s>\n", address, name.c_str());
        }

        console->flush();
        return 0;
    }

    int prestep() {
        struct x64cpu *cpu = this->dbg->getCPU();
        this->old_rip = cpu->regs.rip;
    }

    int poststep() {
        struct x64cpu *cpu = this->dbg->getCPU();
        int i;

        if (this->init == false) {
            this->call_stack.push_back(this->old_rip);
            this->init = true;
            return 0;
        }

        switch (cpu->current_operation) {
            case X64CPU_OP_CALL:
            case X64CPU_OP_CALL_I:
                this->call_stack.push_back(cpu->regs.rip);
                break;

            case X64CPU_OP_RETN:
            case X64CPU_OP_RETF:
                this->call_stack.pop_back();
                break;

        }
    }

protected:
    bool init;
    uint64_t old_rip;
    std::list<uint64_t> call_stack;

};
/* ------------------------------------------------------------------------- */
static CallStack _call_stack;

Debugger::Module* getCallStack() {
    return (Debugger::Module*)&_call_stack;
}
/* ------------------------------------------------------------------------- */

