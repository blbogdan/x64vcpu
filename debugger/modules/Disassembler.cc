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
#include "../../cpu/disasm.h"
#include "../../cpu/opcode_decoder.h"
}

#include <string>
#include <map>
#include <queue>

/* ------------------------------------------------------------------------- */
class Disassembler : public Debugger::Module {
public:
    int update() {
        struct x64cpu *cpu = this->dbg->getCPU();

        if (instruction_cache.size() == 0 || !in_cache(cpu->regs.rip)) {
            /* Force refresh */
            start_address = cpu->regs.rip;

            instruction_cache.clear();
            this->disassemble(cpu, start_address, this->console->getHeight());
        }

        this->update_view(cpu->regs.rip);
        return 0;
    }

protected:
    uint64_t start_address;

    typedef std::map<uint64_t, std::string> Cache;
    Cache instruction_cache;

    inline bool in_cache(uint64_t address) {
        if (instruction_cache.find(address) == instruction_cache.end()) {
            return false;
        }
        return true;
    }

    void disassemble(struct x64cpu *cpu, uint64_t start_address, int count) {
        std::queue<uint64_t> todo;
        char output[256];
        char output2[256];
        char extra[256];
        char result[1024];
        std::string disassembled;
        uint64_t address, len, rel_rip;
        int i;
        struct x64cpu state;
        Process *proc = dbg->getProcess();

        todo.push(start_address);

        while (todo.size() > 0) {
            address = todo.front();
            todo.pop();

            if (this->in_cache(address)) {
                continue;
            }

            rel_rip = (address - cpu->regs.rip);

            len = x64cpu_disasm_current(cpu, rel_rip, output, sizeof(output), &state);
            if (count > 0) {
                todo.push(address + len);
                count--;
            }

            for (i = 0; i < len; i++) {
                snprintf(&output2[i * 3], 4, "%02x ", (int)state.instruction[i]);
            }

            extra[0] = '\0';
            for (i = 0; i < 4; i++) {
                uint64_t ptr_address = 0;

                if (x64cpu_disasm_operand_is_static_ptr(&state, i, &ptr_address) != 0) {
                    std::string symbol_name = "";

                    switch (state.current_operation) {
                        case X64CPU_OP_CALL:
                        case X64CPU_OP_JMP:
                        case X64CPU_OP_CJMP:
#if 0
                            if (proc->findSymbolAtAddress(ptr_address, symbol_name) == 0) {
                                snprintf(extra, sizeof(extra), "    ; <%s>",
                                            symbol_name.c_str());
                            }
#endif
                            break;

                        default:
#if 0
                            if (proc->findSymbolAtAddress(ptr_address, symbol_name) == 0) {
                                snprintf(extra, sizeof(extra), "    ; 0x%016lx <%s>",
                                            ptr_address, symbol_name.c_str());
                            }
                            else 
#endif
                            {
                                snprintf(extra, sizeof(extra), "    ; 0x%016lx", ptr_address);
                            }
                            break;
                    }

                    break;
                }
            }

            snprintf(result, sizeof(result), "%-36s %-36s%s", output2, output, extra);

            instruction_cache[address] = result;
        }
    }

    void update_view(uint64_t current_address) {
        Cache::iterator itr;
        int i, height = this->console->getHeight();
        const char *mark1, *mark2;

        console->reset_pos();

        itr = instruction_cache.begin();
        for (i = 0; i < height && itr != instruction_cache.end(); itr++, i++) {
            if (itr->first == current_address) {
                mark1 = "=>";
                mark2 = "<=";
            }
            else {
                mark1 = "  ";
                mark2 = "  ";
            }

            if (i > 0) {
                console->printf("\n");
            }
            console->printf("%016lx%2s%-73s%2s", itr->first, mark1, itr->second.c_str(), mark2);
        }

        console->flush();
    }

};
/* ------------------------------------------------------------------------- */
static Disassembler _disassembler;

Debugger::Module* getDisassembler() {
    return (Debugger::Module*)&_disassembler;
}
/* ------------------------------------------------------------------------- */

