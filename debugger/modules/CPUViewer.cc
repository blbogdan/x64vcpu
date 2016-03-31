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


/* ------------------------------------------------------------------------- */
class CPUViewer : public Debugger::Module {
public:
    CPUViewer() {
    }

    ~CPUViewer() {
    }

public:
    int init() {
        return 0;
    }

    int update() {
        this->update_view();
        return 0;
    }

    int key(int ch) {
        return 0;
    }

protected:
    void update_view() {
        struct x64cpu *cpu = this->dbg->getCPU();
        char flags_buf[64] = "";
        int flags_k = 0;

        console->clear();

        #define print(str, ...) { console->printf(str, ## __VA_ARGS__); }
        #define preg(name, var) { console->printf("%-5s %016lx  ", (name), (var)); }
        #define pnl() { console->printf("\n"); }
        #define flag(flag, name) { if (((cpu->regs.rflags) & (flag)) != 0) {\
            flags_k += snprintf(&flags_buf[flags_k], sizeof(flags_buf) - flags_k, "%s ", (name)); \
        }}

        preg("RIP", cpu->regs.rip);
        preg("RFLAGS", cpu->regs.rflags);
        flag(X64FLAG_CF, "CF");
        flag(X64FLAG_PF, "PF");
        flag(X64FLAG_AF, "AF");
        flag(X64FLAG_ZF, "ZF");
        flag(X64FLAG_SF, "SF");
        flag(X64FLAG_SF, "TF");
        flag(X64FLAG_SF, "IF");
        flag(X64FLAG_DF, "DF");
        flag(X64FLAG_OF, "OF");
        flag(X64FLAG_ID, "ID");
        print("%-32s", flags_buf);
        print("Num Instr: %d", cpu->instruction_counter);
        pnl();

        preg("RAX", cpu->regs.rax);
        preg("RBX", cpu->regs.rbx);
        preg("RCX", cpu->regs.rcx);
        preg("RDX", cpu->regs.rdx);
        pnl();

        preg("RSP", cpu->regs.rsp);
        preg("RBP", cpu->regs.rbp);
        preg("RSI", cpu->regs.rsi);
        preg("RDI", cpu->regs.rdi);
        pnl();

        preg("R8 ", cpu->regs.r8);
        preg("R9 ", cpu->regs.r9);
        preg("R10", cpu->regs.r10);
        preg("R11", cpu->regs.r11);
        pnl();

        preg("R12", cpu->regs.r12);
        preg("R13", cpu->regs.r13);
        preg("R14", cpu->regs.r14);
        preg("R15", cpu->regs.r15);

        console->flush();
    }

};
/* ------------------------------------------------------------------------- */
static CPUViewer _cpu_viewer;

Debugger::Module* getCPUViewer() {
    return (Debugger::Module*)&_cpu_viewer;
}
/* ------------------------------------------------------------------------- */

