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
class MemoryViewer : public Debugger::Module {
public:
    MemoryViewer() {
        this->show_segments = true;
        this->scroll_amount = 100;
    }

public:
    int update() {
#ifdef _WINENV
        WinProcess *proc = dbg->getProcess();
#else
        Process *proc = dbg->getProcess();
#endif

        console->clear();

        if (proc == NULL) {
            console->printf(" <no process>");
        }
        else {
            if (this->show_segments == true) {
                dumpSegments(proc);
            }
            else {
                struct x64cpu_vmem *mem = dbg->getMemory();
                dumpMemory(this->address, mem);
            }
        }

        console->flush();

        return 0;
    }

    int key(int ch) {
        switch (ch) {
            case 'x':
                this->show_segments = true;
                return 1;
                break;

            case 'a': {
                    dbg->log("Address > 0x");
                    echo();
                    dbg->getConsole()->scanw("%lx", &this->address);
                    noecho();
                    dbg->log("MemViewer: Going to address 0x%016lx\n", this->address);
                    this->show_segments = false;
                    return 1;
                }
                break;

            case KEY_UP: this->address -= this->scroll_amount; return 1; break;
            case KEY_DOWN: this->address += this->scroll_amount; return 1; break;
        }

        return 0;
    }

protected:
    bool show_segments;
    uint64_t address;
    uint64_t scroll_amount;

    void dumpMemory(uint64_t start_address, struct x64cpu_vmem *mem) {
        uint64_t address;
        uint8_t buffer[64];
        int output_k = 0;
        char output[256];
        int lines = this->console->getHeight() - 2;
        int per_row = 8;
        int i, rc;
        int len;

        per_row = (this->console->getWidth() - (16 + 2)) / 4;
        if (per_row > 64) {
            per_row = 64;
        }
        per_row = (per_row / 16) * 16;
        this->scroll_amount = per_row * (this->console->getHeight() - 1);

        console->reset_pos();

        for (address = start_address; lines >= 0; lines--, address += per_row) {
            output_k = 0;

#if 0
            rc = x64cpu_vmem_read(mem, address, buffer, per_row, X64CPU_MEM_ACCESS_NONE, NULL);
            if (rc != 0) {
#else
            rc = x64cpu_vmem_copyfrom(mem, address, buffer, per_row);
            if (rc == 0) {
#endif
                snprintf(output, sizeof(output), "%-35s", "  <page fault>");
            }
            else {
                len = rc;
                for (i = 0; i < len; i++) {
                    output_k += snprintf(&output[output_k], sizeof(output) - output_k, " %02x", buffer[i]);
                }
                output_k += snprintf(&output[output_k], sizeof(output) - output_k, "  ");
                for (i = 0; i < len; i++) {
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

    void dumpSegments(Process *proc) {
        Process::Segment *segment;
        int i;
        uint64_t size;

        console->printf("[*] Process memory segments:\n");

        Process::SegmentList::iterator itr;
        itr = proc->segments.begin();
        for ( ; itr != proc->segments.end(); itr++) {
            segment = &(*itr);

            if (segment->free) {
                continue;
            }

            size = segment->end - segment->start;

            console->printf("\t0x%016lx -> 0x%016lx    size: 0x%016lx (%7.6f MB): %s\n",
                            segment->start, segment->end, size,
                            (size * 1.0f / (1024 * 1024)), segment->name.c_str());
        }
    }

};
/* ------------------------------------------------------------------------- */
static MemoryViewer _memory_viewer;

MemoryViewer* getMemoryViewer() {
    return &_memory_viewer;
}
/* ------------------------------------------------------------------------- */

