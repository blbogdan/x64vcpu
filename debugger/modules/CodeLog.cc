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
#include "../../cpu/disasm.h"
}

#include <string>
#include <map>
#include <queue>

/* ------------------------------------------------------------------------- */
class CodeLog : public Debugger::Module {
public:
    int update() {
        console->flush();
        return 0;
    }

    int prestep() {
        struct x64cpu *target_cpu = this->dbg->getCPU();
        struct x64cpu dummy_cpu;
        struct x64cpu *cpu = &dummy_cpu;
        struct x64cpu_vmem *mem = dbg->getMemory();
        char output[64];
        int i;

        x64cpu_disasm_current(target_cpu, 0, output, sizeof(output) - 1, cpu);

        console->printf("%016lx: %-36s\n", cpu->regs.rip, output);

        for (i = 0; i < 4; i++) {
            if (cpu->op[i].type == X64CPU_OPT_IMMEDIATE) {
                console->printf("\t%d:$%016lx\n", i, ((uint64_t)cpu->op[i].immediate));
            }
            else if (cpu->op[i].type == X64CPU_OPT_REGISTER) {
                console->printf("\t%d:[%016lx]\n", i, *((uint64_t*)cpu->op[i].reg));
            }
            else if (cpu->op[i].type == X64CPU_OPT_REGISTER_POINTER) {
                uint64_t addr = *((uint64_t*)cpu->op[i].reg);
                uint64_t tmp = 0;
                int rc;

                rc = x64cpu_vmem_read(mem, addr, (uint8_t*)&tmp, sizeof(tmp),
                                        X64CPU_MEM_ACCESS_NONE, NULL);
                if (rc == 0) {
                    console->printf("\t%d:[%016lx] <%016lx>\n", i, addr, tmp);
                }
                else {
                    console->printf("\t%d:[%016lx] <pfault>\n", i, addr);
                }
            }
            else if (cpu->op[i].type == X64CPU_OPT_MEMORY_ACCESS) {
                uint64_t base = (cpu->op[i].base_reg) ? (*((uint64_t*)cpu->op[i].base_reg)) : 0;
                uint64_t scaled = (cpu->op[i].scaled_reg) ? (*((uint64_t*)cpu->op[i].scaled_reg)) : 0;
                uint8_t scale = cpu->op[i].scale;
                int64_t displacement = cpu->op[i].displacement;
                uint64_t segment_offset = cpu->op[i].segment_offset;
                uint64_t addr = cpu->op[i].address;
                uint64_t tmp = 0;

                console->printf("\t%d:[", i);

                if (displacement < 0) {
                    console->printf("-%lx", (0 - displacement));
                }
                else {
                    console->printf("%lx", displacement);
                }

                console->printf("+ %lx + %lx * %d : %lx][%016lx]",
                    base, scaled, (int)scale, segment_offset, addr);

                if (x64cpu_vmem_read(mem, addr, (uint8_t*)&tmp, sizeof(tmp),
                                        X64CPU_MEM_ACCESS_NONE, NULL) == 0) {
                    console->printf("<%lx>", tmp);
                }
                else {
                    console->printf("<pfault>");
                }

                console->printf("\n");
            }
        }

        console->flush();
    }

};
/* ------------------------------------------------------------------------- */
static CodeLog _code_log;

Debugger::Module* getCodeLog() {
    return (Debugger::Module*)&_code_log;
}
/* ------------------------------------------------------------------------- */

