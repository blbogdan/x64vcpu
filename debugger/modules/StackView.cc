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

#include "../debugger.h"

extern "C" {
#include "../../cpu/cpu.h"
#include "../../cpu/virtual_memory.h"
}

/* ------------------------------------------------------------------------- */
class StackView : public Debugger::Module {
public:
    StackView() {
        start_address = 0;
        view_rsp = true;
    }

    int update() {
        struct x64cpu *cpu = this->dbg->getCPU();
        struct x64cpu_vmem *mem = dbg->getMemory();

        if (mem == NULL) {
            console->clear();
            console->printf(" <no process>");
        }
        else {
            if (view_rsp) {
                dump(cpu->regs.rsp, mem);
            }
            else {
                dump(start_address, mem);
            }
        }

        console->flush();

        return 0;
    }

protected:
    bool view_rsp;

    uint64_t start_address;

    void dump(uint64_t start_address, struct x64cpu_vmem *mem) {
        uint64_t address;
        uint8_t buffer[64];
        int output_k = 0;
        char output[256];
        int lines = this->console->getHeight() - 2;
        int per_row = 8;
        int i, rc;

        console->reset_pos();

        for (address = start_address; lines >= 0; lines--, address += per_row) {
            output_k = 0;

            rc = x64cpu_vmem_read(mem, address, buffer, per_row, X64CPU_MEM_ACCESS_NONE, NULL);
            if (rc != 0) {
                snprintf(output, sizeof(output), "%-35s", "  <page fault>");
            }
            else {
                for (i = 0; i < per_row; i++) {
                    output_k += snprintf(&output[output_k], sizeof(output) - output_k, " %02x", buffer[i]);
                }
                output_k += snprintf(&output[output_k], sizeof(output) - output_k, "  ");
                for (i = 0; i < per_row; i++) {
                    char c = buffer[i];

                    if (c < 32 || c > 127) {
                        c = '.';
                    }

                    output_k += snprintf(&output[output_k], sizeof(output) - output_k, "%c", c);
                }
            }

            console->printf("%016lx%s\n", address, output);
        }
    }

};
/* ------------------------------------------------------------------------- */
static StackView _stack_view;

StackView* getStackView() {
    return &_stack_view;
}
/* ------------------------------------------------------------------------- */

