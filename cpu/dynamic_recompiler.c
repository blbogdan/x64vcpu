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

/**
 * TODO : !!! NOT WORKING !!! IN PROGRESS !!!
 */

#include "dynamic_recompiler.h"
#include "opcode_decoder.h"

#include <string.h>


static int decode(struct x64cpu *in, struct x64cpu *out, int *length) {
#if 0
    memcpy(out, in, sizeof(*out));
    return x64cpu_debug_decode_instruction(out, length);
#else
    return -1;
#endif
}

#define _NONE       X64CPU_OPT_NONE
#define _IMM        X64CPU_OPT_IMMEDIATE
#define _REGISTER   X64CPU_OPT_REGISTER

#define MATCH(ta, tb, tc, td) (\
    (a->type == (ta)) && \
    (b->type == (tb)) && \
    (c->type == (tc)) && \
    (d->type == (td))    \
)

#define append(x) { output[k++] = (x); }
#define append_n(x, n) { memcpy(&output[k], (x), n); k += n; }

int x64cpu_translate_next(struct x64cpu *cpu, uint8_t *output, int output_len) {
    int ret = -1;
#if 0
    int rc;
    struct x64cpu state;
    int length;
    int k = 0;
    
    rc = decode(cpu, &state, &length);

int test[] = {
    [1 ... 6] = 2,
    [7] = 3,
    [9] = 4
};

    // ---
    struct x64cpu_operand *a = &(cpu->op[0]);
    struct x64cpu_operand *b = &(cpu->op[1]);
    struct x64cpu_operand *c = &(cpu->op[2]);
    struct x64cpu_operand *d = &(cpu->op[3]);

    if (b->type == _IMM) {
        if (b->size == 8) {
        }
        else {
            append(0xC7);
            append(0x00); // imm, rax
            append_n((uint8_t*)&(b->immediate), b->size);
        }
    }
    else if (b->type == _REGISTER) {
        if (b->size == 8) {
        }
        else {
            append(0x89);
            append(0x43); // rbx + disp8, rax
            append( (((uint8_t*)a->reg) - ((uint8_t*)cpu)) );
        }
    }

    switch (state.current_operation) {
        case X64CPU_OP_XOR: {
                append(0x31);
            }
            break;
    }

#if 0
    if (MATCH(_REGISTER, _IMM, _NONE, _NONE)) {
        /* Look for operation with E, I */
        int i;
        for (i = 0; i < 0xff; i++) {
            const struct x64cpu_opcode_definition *def = &x64cpu_opcode_def_1byte[i];

            if (def->operation != state.current_operation) {
                continue;
            }

            if (def->parameters[0].type == X64CPU_PT_E && def->parameters[1].type == X64CPU_PT_I) {
                append(i);
                append(0x43); // rbx + disp8
                append( (((uint8_t*)a->reg) - ((uint8_t*)cpu)) );
                append_n((uint8_t*)&(b->immediate), b->size);
                
                ret = 0;
                break;
            }
        }
    }
#endif
#endif
    return ret;
}

