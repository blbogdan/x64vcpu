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


#include "opcode_decoder.h"

/* 1-byte opcodes */
const struct x64cpu_opcode_definition x64cpu_opcode_32_def_1byte[] = {
    /* 0x0_ */
    /* 0x00 */ { X64CPU_OP_ADD, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_G, X64CPU_PS_b } } },
    /* 0x01 */ { X64CPU_OP_ADD, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_G, X64CPU_PS_v } } },
    /* 0x02 */ { X64CPU_OP_ADD, 1, { { X64CPU_PT_G, X64CPU_PS_b }, { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x03 */ { X64CPU_OP_ADD, 1, { { X64CPU_PT_G, X64CPU_PS_v }, { X64CPU_PT_E, X64CPU_PS_v } } },
    /* 0x04 */ { X64CPU_OP_ADD, 0, { { X64CPU_PT_RAX, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0x05 */ { X64CPU_OP_ADD, 0, { { X64CPU_PT_RAX, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_v } } },
    /* 0x06 */ { X64CPU_OP_PUSH, 0, { { X64CPU_PT_rES, X64CPU_PS_w } } },
    /* 0x07 */ { X64CPU_OP_POP,  0, { { X64CPU_PT_rES, X64CPU_PS_w } } },
    /* 0x0_ */
    /* 0x08 */ { X64CPU_OP_OR, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_G, X64CPU_PS_b } } },
    /* 0x09 */ { X64CPU_OP_OR, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_G, X64CPU_PS_v } } },
    /* 0x0A */ { X64CPU_OP_OR, 1, { { X64CPU_PT_G, X64CPU_PS_b }, { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x0B */ { X64CPU_OP_OR, 1, { { X64CPU_PT_G, X64CPU_PS_v }, { X64CPU_PT_E, X64CPU_PS_v } } },
    /* 0x0C */ { X64CPU_OP_OR, 0, { { X64CPU_PT_RAX, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0x0D */ { X64CPU_OP_OR, 0, { { X64CPU_PT_RAX, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_v } } },
    /* 0x0E */ { X64CPU_OP_PUSH, 0, { { X64CPU_PT_rCS, X64CPU_PS_w } } },
    /* 0x0F */ { X64CPU_OP_INVALID },

    /* 0x1_ */
    /* 0x10 */ { X64CPU_OP_ADC, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_G, X64CPU_PS_b } } },
    /* 0x11 */ { X64CPU_OP_ADC, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_G, X64CPU_PS_v } } },
    /* 0x12 */ { X64CPU_OP_ADC, 1, { { X64CPU_PT_G, X64CPU_PS_b }, { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x13 */ { X64CPU_OP_ADC, 1, { { X64CPU_PT_G, X64CPU_PS_v }, { X64CPU_PT_E, X64CPU_PS_v } } },
    /* 0x14 */ { X64CPU_OP_ADC, 0, { { X64CPU_PT_RAX, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0x15 */ { X64CPU_OP_ADC, 0, { { X64CPU_PT_RAX, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_v } } },
    /* 0x16 */ { X64CPU_OP_PUSH, 0, { { X64CPU_PT_rSS, X64CPU_PS_w } } },
    /* 0x17 */ { X64CPU_OP_POP,  0, { { X64CPU_PT_rSS, X64CPU_PS_w } } },
    /* 0x1_ */
    /* 0x18 */ { X64CPU_OP_SBB, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_G, X64CPU_PS_b } } },
    /* 0x19 */ { X64CPU_OP_SBB, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_G, X64CPU_PS_v } } },
    /* 0x1A */ { X64CPU_OP_SBB, 1, { { X64CPU_PT_G, X64CPU_PS_b }, { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x1B */ { X64CPU_OP_SBB, 1, { { X64CPU_PT_G, X64CPU_PS_v }, { X64CPU_PT_E, X64CPU_PS_v } } },
    /* 0x1C */ { X64CPU_OP_SBB, 0, { { X64CPU_PT_RAX, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0x1D */ { X64CPU_OP_SBB, 0, { { X64CPU_PT_RAX, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_v } } },
    /* 0x1E */ { X64CPU_OP_PUSH, 0, { { X64CPU_PT_rDS, X64CPU_PS_w } } },
    /* 0x1F */ { X64CPU_OP_POP,  0, { { X64CPU_PT_rDS, X64CPU_PS_w } } },

    /* 0x2_ */
    /* 0x20 */ { X64CPU_OP_AND, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_G, X64CPU_PS_b } } },
    /* 0x21 */ { X64CPU_OP_AND, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_G, X64CPU_PS_v } } },
    /* 0x22 */ { X64CPU_OP_AND, 1, { { X64CPU_PT_G, X64CPU_PS_b }, { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x23 */ { X64CPU_OP_AND, 1, { { X64CPU_PT_G, X64CPU_PS_v }, { X64CPU_PT_E, X64CPU_PS_v } } },
    /* 0x24 */ { X64CPU_OP_AND, 0, { { X64CPU_PT_RAX, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0x25 */ { X64CPU_OP_AND, 0, { { X64CPU_PT_RAX, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_v } } },
    /* 0x26 */ { X64CPU_OP_PREFIX }, /* ES prefix */
    /* 0x27 */ { X64CPU_OP_DAA, 0, { { X64CPU_PT_RAX, X64CPU_PS_b } } },
    /* 0x2_ */
    /* 0x28 */ { X64CPU_OP_SUB, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_G, X64CPU_PS_b } } },
    /* 0x29 */ { X64CPU_OP_SUB, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_G, X64CPU_PS_v } } },
    /* 0x2A */ { X64CPU_OP_SUB, 1, { { X64CPU_PT_G, X64CPU_PS_b }, { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x2B */ { X64CPU_OP_SUB, 1, { { X64CPU_PT_G, X64CPU_PS_v }, { X64CPU_PT_E, X64CPU_PS_v } } },
    /* 0x2C */ { X64CPU_OP_SUB, 0, { { X64CPU_PT_RAX, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0x2D */ { X64CPU_OP_SUB, 0, { { X64CPU_PT_RAX, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_v } } },
    /* 0x2E */ { X64CPU_OP_PREFIX }, /* CS prefix */
    /* 0x2F */ { X64CPU_OP_DAS, 0, { { X64CPU_PT_RAX, X64CPU_PS_b } } },

    /* 0x3_ */
    /* 0x30 */ { X64CPU_OP_XOR, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_G, X64CPU_PS_b } } },
    /* 0x31 */ { X64CPU_OP_XOR, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_G, X64CPU_PS_v } } },
    /* 0x32 */ { X64CPU_OP_XOR, 1, { { X64CPU_PT_G, X64CPU_PS_b }, { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x33 */ { X64CPU_OP_XOR, 1, { { X64CPU_PT_G, X64CPU_PS_v }, { X64CPU_PT_E, X64CPU_PS_v } } },
    /* 0x34 */ { X64CPU_OP_XOR, 0, { { X64CPU_PT_RAX, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0x35 */ { X64CPU_OP_XOR, 0, { { X64CPU_PT_RAX, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_v } } },
    /* 0x36 */ { X64CPU_OP_PREFIX }, /* SS prefix */
    /* 0x37 */ { X64CPU_OP_AAA, 0, { { X64CPU_PT_RAX, X64CPU_PS_b }, { X64CPU_PT_RAX, X64CPU_PS_w } } },
    /* 0x3_ */
    /* 0x38 */ { X64CPU_OP_CMP, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_G, X64CPU_PS_b } } },
    /* 0x39 */ { X64CPU_OP_CMP, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_G, X64CPU_PS_v } } },
    /* 0x3A */ { X64CPU_OP_CMP, 1, { { X64CPU_PT_G, X64CPU_PS_b }, { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x3B */ { X64CPU_OP_CMP, 1, { { X64CPU_PT_G, X64CPU_PS_v }, { X64CPU_PT_E, X64CPU_PS_v } } },
    /* 0x3C */ { X64CPU_OP_CMP, 0, { { X64CPU_PT_RAX, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0x3D */ { X64CPU_OP_CMP, 0, { { X64CPU_PT_RAX, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_v } } },
    /* 0x3E */ { X64CPU_OP_PREFIX }, /* DS prefix */
    /* 0x3F */ { X64CPU_OP_PREFIX }, /* TODO: Branch TAKEN prefix ??? */

    /* 0x4_ */
    /* 0x40 */ { X64CPU_OP_INC, 0, { { X64CPU_PT_RAX, X64CPU_PS_v } } },
    /* 0x41 */ { X64CPU_OP_INC, 0, { { X64CPU_PT_RCX, X64CPU_PS_v } } },
    /* 0x42 */ { X64CPU_OP_INC, 0, { { X64CPU_PT_RDX, X64CPU_PS_v } } },
    /* 0x43 */ { X64CPU_OP_INC, 0, { { X64CPU_PT_RBX, X64CPU_PS_v } } },
    /* 0x44 */ { X64CPU_OP_INC, 0, { { X64CPU_PT_RSP, X64CPU_PS_v } } },
    /* 0x45 */ { X64CPU_OP_INC, 0, { { X64CPU_PT_RBP, X64CPU_PS_v } } },
    /* 0x46 */ { X64CPU_OP_INC, 0, { { X64CPU_PT_RSI, X64CPU_PS_v } } },
    /* 0x47 */ { X64CPU_OP_INC, 0, { { X64CPU_PT_RDI, X64CPU_PS_v } } },
    /* 0x4_ */
    /* 0x48 */ { X64CPU_OP_DEC, 0, { { X64CPU_PT_RAX, X64CPU_PS_v } } },
    /* 0x49 */ { X64CPU_OP_DEC, 0, { { X64CPU_PT_RCX, X64CPU_PS_v } } },
    /* 0x4A */ { X64CPU_OP_DEC, 0, { { X64CPU_PT_RDX, X64CPU_PS_v } } },
    /* 0x4B */ { X64CPU_OP_DEC, 0, { { X64CPU_PT_RBX, X64CPU_PS_v } } },
    /* 0x4C */ { X64CPU_OP_DEC, 0, { { X64CPU_PT_RSP, X64CPU_PS_v } } },
    /* 0x4D */ { X64CPU_OP_DEC, 0, { { X64CPU_PT_RBP, X64CPU_PS_v } } },
    /* 0x4E */ { X64CPU_OP_DEC, 0, { { X64CPU_PT_RSI, X64CPU_PS_v } } },
    /* 0x4F */ { X64CPU_OP_DEC, 0, { { X64CPU_PT_RDI, X64CPU_PS_v } } },

    /* 0x5_ */
    /* 0x50 */ { X64CPU_OP_PUSH, 0, { { X64CPU_PT_RAX, X64CPU_PS_v } } },
    /* 0x51 */ { X64CPU_OP_PUSH, 0, { { X64CPU_PT_RCX, X64CPU_PS_v } } },
    /* 0x52 */ { X64CPU_OP_PUSH, 0, { { X64CPU_PT_RDX, X64CPU_PS_v } } },
    /* 0x53 */ { X64CPU_OP_PUSH, 0, { { X64CPU_PT_RBX, X64CPU_PS_v } } },
    /* 0x54 */ { X64CPU_OP_PUSH, 0, { { X64CPU_PT_RSP, X64CPU_PS_v } } },
    /* 0x55 */ { X64CPU_OP_PUSH, 0, { { X64CPU_PT_RBP, X64CPU_PS_v } } },
    /* 0x56 */ { X64CPU_OP_PUSH, 0, { { X64CPU_PT_RSI, X64CPU_PS_v } } },
    /* 0x57 */ { X64CPU_OP_PUSH, 0, { { X64CPU_PT_RDI, X64CPU_PS_v } } },
    /* 0x5_ */
    /* 0x58 */ { X64CPU_OP_POP, 0, { { X64CPU_PT_RAX, X64CPU_PS_v } } },
    /* 0x59 */ { X64CPU_OP_POP, 0, { { X64CPU_PT_RCX, X64CPU_PS_v } } },
    /* 0x5A */ { X64CPU_OP_POP, 0, { { X64CPU_PT_RDX, X64CPU_PS_v } } },
    /* 0x5B */ { X64CPU_OP_POP, 0, { { X64CPU_PT_RBX, X64CPU_PS_v } } },
    /* 0x5C */ { X64CPU_OP_POP, 0, { { X64CPU_PT_RSP, X64CPU_PS_v } } },
    /* 0x5D */ { X64CPU_OP_POP, 0, { { X64CPU_PT_RBP, X64CPU_PS_v } } },
    /* 0x5E */ { X64CPU_OP_POP, 0, { { X64CPU_PT_RSI, X64CPU_PS_v } } },
    /* 0x5F */ { X64CPU_OP_POP, 0, { { X64CPU_PT_RDI, X64CPU_PS_v } } },

    /* 0x6_ */
    /* 0x60 */ { X64CPU_OP_PUSHA },
    /* 0x61 */ { X64CPU_OP_POPA },
    /* 0x62 */ { X64CPU_OP_BOUND, 1, { { X64CPU_PT_G, X64CPU_PS_v }, { X64CPU_PT_M, X64CPU_PS_a } } },
    /* 0x63 */ { X64CPU_OP_ARPL, 1, { { X64CPU_PT_E, X64CPU_PS_w }, { X64CPU_PT_G, X64CPU_PS_w } } },
    /* 0x64 */ { X64CPU_OP_PREFIX }, /* FS prefix */
    /* 0x65 */ { X64CPU_OP_PREFIX }, /* GS prefix */
    /* 0x66 */ { X64CPU_OP_PREFIX }, /* Operand-size prefix */
    /* 0x67 */ { X64CPU_OP_PREFIX }, /* Address-size prefix */
    /* 0x6_ */
    /* 0x68 */ { X64CPU_OP_PUSH, 0, { { X64CPU_PT_I, X64CPU_PS_vs } } },
    /* 0x69 */ { X64CPU_OP_IMUL3, 1, { { X64CPU_PT_G, X64CPU_PS_v }, { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_v } } },
    /* 0x6A */ { X64CPU_OP_PUSH, 0, { { X64CPU_PT_I, X64CPU_PS_bss } } },
    /* 0x6B */ { X64CPU_OP_IMUL3, 1, { { X64CPU_PT_G, X64CPU_PS_v }, { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_bs } } },
    /* 0x6C */ { X64CPU_OP_INS,  0, { { X64CPU_PT_Y, X64CPU_PS_b }, { X64CPU_PT_RDX, X64CPU_PS_w } } },
    /* 0x6D */ { X64CPU_OP_INS,  0, { { X64CPU_PT_Y, X64CPU_PS_v }, { X64CPU_PT_RDX, X64CPU_PS_w } } },
    /* 0x6E */ { X64CPU_OP_OUTS, 0, { { X64CPU_PT_RDX, X64CPU_PS_w }, { X64CPU_PT_X, X64CPU_PS_b } } },
    /* 0x6F */ { X64CPU_OP_OUTS, 0, { { X64CPU_PT_RDX, X64CPU_PS_w }, { X64CPU_PT_X, X64CPU_PS_v } } },

    /* 0x7_ */
    /* 0x70 */ { X64CPU_OP_CJMP, 0, { { X64CPU_PT_J, X64CPU_PS_b } } },
    /* 0x71 */ { X64CPU_OP_CJMP, 0, { { X64CPU_PT_J, X64CPU_PS_b } } },
    /* 0x72 */ { X64CPU_OP_CJMP, 0, { { X64CPU_PT_J, X64CPU_PS_b } } },
    /* 0x73 */ { X64CPU_OP_CJMP, 0, { { X64CPU_PT_J, X64CPU_PS_b } } },
    /* 0x74 */ { X64CPU_OP_CJMP, 0, { { X64CPU_PT_J, X64CPU_PS_b } } },
    /* 0x75 */ { X64CPU_OP_CJMP, 0, { { X64CPU_PT_J, X64CPU_PS_b } } },
    /* 0x76 */ { X64CPU_OP_CJMP, 0, { { X64CPU_PT_J, X64CPU_PS_b } } },
    /* 0x77 */ { X64CPU_OP_CJMP, 0, { { X64CPU_PT_J, X64CPU_PS_b } } },
    /* 0x7_ */
    /* 0x78 */ { X64CPU_OP_CJMP, 0, { { X64CPU_PT_J, X64CPU_PS_b } } },
    /* 0x79 */ { X64CPU_OP_CJMP, 0, { { X64CPU_PT_J, X64CPU_PS_b } } },
    /* 0x7A */ { X64CPU_OP_CJMP, 0, { { X64CPU_PT_J, X64CPU_PS_b } } },
    /* 0x7B */ { X64CPU_OP_CJMP, 0, { { X64CPU_PT_J, X64CPU_PS_b } } },
    /* 0x7C */ { X64CPU_OP_CJMP, 0, { { X64CPU_PT_J, X64CPU_PS_b } } },
    /* 0x7D */ { X64CPU_OP_CJMP, 0, { { X64CPU_PT_J, X64CPU_PS_b } } },
    /* 0x7E */ { X64CPU_OP_CJMP, 0, { { X64CPU_PT_J, X64CPU_PS_b } } },
    /* 0x7F */ { X64CPU_OP_CJMP, 0, { { X64CPU_PT_J, X64CPU_PS_b } } },

    /* 0x8_ */
    /* 0x80 */ { X64CPU_OP_GROUP, 1, .group = (struct x64cpu_opcode_definition[])
                {
                  [0] = { X64CPU_OP_ADD, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [1] = { X64CPU_OP_OR,  1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [2] = { X64CPU_OP_ADC, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [3] = { X64CPU_OP_SBB, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [4] = { X64CPU_OP_AND, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [5] = { X64CPU_OP_SUB, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [6] = { X64CPU_OP_XOR, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [7] = { X64CPU_OP_CMP, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
                }
               },
    /* 0x81 */ { X64CPU_OP_GROUP, 1, .group = (struct x64cpu_opcode_definition[])
                {
                  [0] = { X64CPU_OP_ADD, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_v } } },
                  [1] = { X64CPU_OP_OR,  1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_v } } },
                  [2] = { X64CPU_OP_ADC, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_v } } },
                  [3] = { X64CPU_OP_SBB, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_v } } },
                  [4] = { X64CPU_OP_AND, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_v } } },
                  [5] = { X64CPU_OP_SUB, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_v } } },
                  [6] = { X64CPU_OP_XOR, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_v } } },
                  [7] = { X64CPU_OP_CMP, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_v } } },
                }
               },
    /* 0x82 */ { X64CPU_OP_GROUP, 1, .group = (struct x64cpu_opcode_definition[])
                {
                  [0] = { X64CPU_OP_ADD, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [1] = { X64CPU_OP_OR,  1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [2] = { X64CPU_OP_ADC, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [3] = { X64CPU_OP_SBB, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [4] = { X64CPU_OP_AND, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [5] = { X64CPU_OP_SUB, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [6] = { X64CPU_OP_XOR, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [7] = { X64CPU_OP_CMP, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
                }
               },
    /* 0x83 */ { X64CPU_OP_GROUP, 1, .group = (struct x64cpu_opcode_definition[])
                {
                  [0] = { X64CPU_OP_ADD, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_bs } } },
                  [1] = { X64CPU_OP_OR,  1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_bs } } },
                  [2] = { X64CPU_OP_ADC, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_bs } } },
                  [3] = { X64CPU_OP_SBB, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_bs } } },
                  [4] = { X64CPU_OP_AND, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_bs } } },
                  [5] = { X64CPU_OP_SUB, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_bs } } },
                  [6] = { X64CPU_OP_XOR, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_bs } } },
                  [7] = { X64CPU_OP_CMP, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_bs } } },
                }
               },
    /* 0x84 */ { X64CPU_OP_TEST, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_G, X64CPU_PS_b } } },
    /* 0x85 */ { X64CPU_OP_TEST, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_G, X64CPU_PS_v } } },
    /* 0x86 */ { X64CPU_OP_XCHG, 1, { { X64CPU_PT_G, X64CPU_PS_b }, { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x87 */ { X64CPU_OP_XCHG, 1, { { X64CPU_PT_G, X64CPU_PS_v }, { X64CPU_PT_E, X64CPU_PS_v } } },
    /* 0x8_ */
    /* 0x88 */ { X64CPU_OP_MOV, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_G, X64CPU_PS_b } } },
    /* 0x89 */ { X64CPU_OP_MOV, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_G, X64CPU_PS_v } } },
    /* 0x8A */ { X64CPU_OP_MOV, 1, { { X64CPU_PT_G, X64CPU_PS_b }, { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x8B */ { X64CPU_OP_MOV, 1, { { X64CPU_PT_G, X64CPU_PS_v }, { X64CPU_PT_E, X64CPU_PS_v } } },
    /* 0x8C */ { X64CPU_OP_MOV, 1, { { X64CPU_PT_E, X64CPU_PS_vMw }, { X64CPU_PT_S, X64CPU_PS_w } } },
    /* 0x8D */ { X64CPU_OP_LEA, 1, { { X64CPU_PT_G, X64CPU_PS_v }, { X64CPU_PT_M, X64CPU_PS_v } } },
    /* 0x8E */ { X64CPU_OP_MOV, 1, { { X64CPU_PT_S, X64CPU_PS_w }, { X64CPU_PT_E, X64CPU_PS_w } } },
    /* 0x8F */ { X64CPU_OP_POP, 1, { { X64CPU_PT_E, X64CPU_PS_v } } },

    /* 0x9_ */
    /* 0x90 */ { X64CPU_OP_NOOP },
    /* 0x91 */ { X64CPU_OP_XCHG, 0, { { X64CPU_PT_RCX_R9, X64CPU_PS_v }, { X64CPU_PT_RAX, X64CPU_PS_v } } },
    /* 0x92 */ { X64CPU_OP_XCHG, 0, { { X64CPU_PT_RDX_R10, X64CPU_PS_v }, { X64CPU_PT_RAX, X64CPU_PS_v } } },
    /* 0x93 */ { X64CPU_OP_XCHG, 0, { { X64CPU_PT_RBX_R11, X64CPU_PS_v }, { X64CPU_PT_RAX, X64CPU_PS_v } } },
    /* 0x94 */ { X64CPU_OP_XCHG, 0, { { X64CPU_PT_RSP_R12, X64CPU_PS_v }, { X64CPU_PT_RAX, X64CPU_PS_v } } },
    /* 0x95 */ { X64CPU_OP_XCHG, 0, { { X64CPU_PT_RBP_R13, X64CPU_PS_v }, { X64CPU_PT_RAX, X64CPU_PS_v } } },
    /* 0x96 */ { X64CPU_OP_XCHG, 0, { { X64CPU_PT_RSI_R14, X64CPU_PS_v }, { X64CPU_PT_RAX, X64CPU_PS_v } } },
    /* 0x97 */ { X64CPU_OP_XCHG, 0, { { X64CPU_PT_RDI_R15, X64CPU_PS_v }, { X64CPU_PT_RAX, X64CPU_PS_v } } },
    /* 0x9_ */
    /* 0x98 */ { X64CPU_OP_CONV },
    /* 0x99 */ { X64CPU_OP_CONV2 },
    /* 0x9A */ { X64CPU_OP_CALL_FAR, 0, { { X64CPU_PT_A, X64CPU_PS_p } } },
    /* 0x9B */ { X64CPU_OP_PREFIX }, /* FWAIT prefix */
    /* 0x9C */ { X64CPU_OP_PUSH, 0, { { X64CPU_PT_F, X64CPU_PS_v } } },
    /* 0x9D */ { X64CPU_OP_POP, 0, { { X64CPU_PT_F, X64CPU_PS_v } } },
    /* 0x9E */ { X64CPU_OP_SAHF },
    /* 0x9F */ { X64CPU_OP_LAHF },

    /* 0xA_ */
    /* 0xA0 */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RAX, X64CPU_PS_b }, { X64CPU_PT_O, X64CPU_PS_b } } },
    /* 0xA1 */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RAX, X64CPU_PS_v }, { X64CPU_PT_O, X64CPU_PS_v } } },
    /* 0xA2 */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_O, X64CPU_PS_b }, { X64CPU_PT_RAX, X64CPU_PS_b } } },
    /* 0xA3 */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_O, X64CPU_PS_v }, { X64CPU_PT_RAX, X64CPU_PS_v } } },
    /* 0xA4 */ { X64CPU_OP_MOVS, 0, { { X64CPU_PT_Y, X64CPU_PS_b }, { X64CPU_PT_X, X64CPU_PS_b } } },
    /* 0xA5 */ { X64CPU_OP_MOVS, 0, { { X64CPU_PT_Y, X64CPU_PS_v }, { X64CPU_PT_X, X64CPU_PS_v } } },
    /* 0xA6 */ { X64CPU_OP_CMPS, 0, { { X64CPU_PT_Y, X64CPU_PS_b }, { X64CPU_PT_X, X64CPU_PS_b } } },
    /* 0xA7 */ { X64CPU_OP_CMPS, 0, { { X64CPU_PT_Y, X64CPU_PS_v }, { X64CPU_PT_X, X64CPU_PS_v } } },
    /* 0xA_ */
    /* 0xA8 */ { X64CPU_OP_TEST, 0, { { X64CPU_PT_RAX, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0xA9 */ { X64CPU_OP_TEST, 0, { { X64CPU_PT_RAX, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_v } } },
    /* 0xAA */ { X64CPU_OP_STOS, 0, { { X64CPU_PT_Y, X64CPU_PS_b }, { X64CPU_PT_RAX, X64CPU_PS_b } } },
    /* 0xAB */ { X64CPU_OP_STOS, 0, { { X64CPU_PT_Y, X64CPU_PS_v }, { X64CPU_PT_RAX, X64CPU_PS_v } } },
    /* 0xAC */ { X64CPU_OP_LODS, 0, { { X64CPU_PT_RAX, X64CPU_PS_b }, { X64CPU_PT_X, X64CPU_PS_b } } },
    /* 0xAD */ { X64CPU_OP_LODS, 0, { { X64CPU_PT_RAX, X64CPU_PS_v }, { X64CPU_PT_X, X64CPU_PS_v } } },
    /* 0xAE */ { X64CPU_OP_SCAS, 0, { { X64CPU_PT_Y, X64CPU_PS_b }, { X64CPU_PT_RAX, X64CPU_PS_b } } },
    /* 0xAF */ { X64CPU_OP_SCAS, 0, { { X64CPU_PT_Y, X64CPU_PS_v }, { X64CPU_PT_RAX, X64CPU_PS_v } } },

    /* 0xB_ */
    /* 0xB0 */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RAX, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0xB1 */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RCX, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0xB2 */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RDX, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0xB3 */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RBX, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0xB4 */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RAH, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0xB5 */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RCH, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0xB6 */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RDH, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0xB7 */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RBH, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0xB_ */
    /* 0xB8 */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RAX, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_v } } },
    /* 0xB9 */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RCX, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_v } } },
    /* 0xBA */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RDX, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_v } } },
    /* 0xBB */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RBX, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_v } } },
    /* 0xBC */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RSP, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_v } } },
    /* 0xBD */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RBP, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_v } } },
    /* 0xBE */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RSI, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_v } } },
    /* 0xBF */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RDI, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_v } } },

    /* 0xC_ */
    /* 0xC0 */ { X64CPU_OP_GROUP, 1, .group = (struct x64cpu_opcode_definition[])
                {
                  [0] = { X64CPU_OP_ROL, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [1] = { X64CPU_OP_ROR, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [2] = { X64CPU_OP_RCL, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [3] = { X64CPU_OP_RCR, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [4] = { X64CPU_OP_SHL, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [5] = { X64CPU_OP_SHR, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [6] = { X64CPU_OP_SHL, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [7] = { X64CPU_OP_SAR, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
                }
               },
    /* 0xC1 */ { X64CPU_OP_GROUP, 1, .group = (struct x64cpu_opcode_definition[])
                {
                  [0] = { X64CPU_OP_ROL, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [1] = { X64CPU_OP_ROR, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [2] = { X64CPU_OP_RCL, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [3] = { X64CPU_OP_RCR, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [4] = { X64CPU_OP_SHL, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [5] = { X64CPU_OP_SHR, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [6] = { X64CPU_OP_SHL, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [7] = { X64CPU_OP_SAR, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_b } } },
                }
               },
    /* 0xC2 */ { X64CPU_OP_RETN, 0, { { X64CPU_PT_I, X64CPU_PS_w } } },
    /* 0xC3 */ { X64CPU_OP_RETN, 0, },
    /* 0xC4 */ { X64CPU_OP_LES, 1, { { X64CPU_PT_G, X64CPU_PS_v }, { X64CPU_PT_M, X64CPU_PS_p } } },
    /* 0xC5 */ { X64CPU_OP_LDS, 1, { { X64CPU_PT_G, X64CPU_PS_v }, { X64CPU_PT_M, X64CPU_PS_p } } },
    /* 0xC6 */ { X64CPU_OP_MOV, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0xC7 */ { X64CPU_OP_MOV, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_v } } },
    /* 0xC_ */
    /* 0xC8 */ { X64CPU_OP_ENTER, 0, { { X64CPU_PT_I, X64CPU_PS_w }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0xC9 */ { X64CPU_OP_LEAVE, 0 },
    /* 0xCA */ { X64CPU_OP_RETF, 0, { { X64CPU_PT_I, X64CPU_PS_w } } },
    /* 0xCB */ { X64CPU_OP_RETF, 0 },
    /* 0xCC */ { X64CPU_OP_INT, 0, { { X64CPU_PT_3, X64CPU_PS_b } } },
    /* 0xCD */ { X64CPU_OP_INT, 0, { { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0xCE */ { X64CPU_OP_INTO },
    /* 0xCF */ { X64CPU_OP_IRET, 0 },

    /* 0xD_ */
    /* 0xD0 */ { X64CPU_OP_GROUP, 1, .group = (struct x64cpu_opcode_definition[])
                {
                  [0] = { X64CPU_OP_ROL, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_1, X64CPU_PS_b } } },
                  [1] = { X64CPU_OP_ROR, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_1, X64CPU_PS_b } } },
                  [2] = { X64CPU_OP_RCL, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_1, X64CPU_PS_b } } },
                  [3] = { X64CPU_OP_RCR, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_1, X64CPU_PS_b } } },
                  [4] = { X64CPU_OP_SHL, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_1, X64CPU_PS_b } } },
                  [5] = { X64CPU_OP_SHR, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_1, X64CPU_PS_b } } },
                  [6] = { X64CPU_OP_SHL, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_1, X64CPU_PS_b } } },
                  [7] = { X64CPU_OP_SAR, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_1, X64CPU_PS_b } } },
                }
               },
    /* 0xD1 */ { X64CPU_OP_GROUP, 1, .group = (struct x64cpu_opcode_definition[])
                {
                  [0] = { X64CPU_OP_ROL, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_1, X64CPU_PS_b } } },
                  [1] = { X64CPU_OP_ROR, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_1, X64CPU_PS_b } } },
                  [2] = { X64CPU_OP_RCL, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_1, X64CPU_PS_b } } },
                  [3] = { X64CPU_OP_RCR, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_1, X64CPU_PS_b } } },
                  [4] = { X64CPU_OP_SHL, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_1, X64CPU_PS_b } } },
                  [5] = { X64CPU_OP_SHR, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_1, X64CPU_PS_b } } },
                  [6] = { X64CPU_OP_SHL, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_1, X64CPU_PS_b } } },
                  [7] = { X64CPU_OP_SAR, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_1, X64CPU_PS_b } } },
                }
               },
    /* 0xD2 */ { X64CPU_OP_GROUP, 1, .group = (struct x64cpu_opcode_definition[])
                {
                  [0] = { X64CPU_OP_ROL, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_RCX, X64CPU_PS_b } } },
                  [1] = { X64CPU_OP_ROR, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_RCX, X64CPU_PS_b } } },
                  [2] = { X64CPU_OP_RCL, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_RCX, X64CPU_PS_b } } },
                  [3] = { X64CPU_OP_RCR, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_RCX, X64CPU_PS_b } } },
                  [4] = { X64CPU_OP_SHL, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_RCX, X64CPU_PS_b } } },
                  [5] = { X64CPU_OP_SHR, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_RCX, X64CPU_PS_b } } },
                  [6] = { X64CPU_OP_SHL, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_RCX, X64CPU_PS_b } } },
                  [7] = { X64CPU_OP_SAR, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_RCX, X64CPU_PS_b } } },
                }
               },
    /* 0xD3 */ { X64CPU_OP_GROUP, 1, .group = (struct x64cpu_opcode_definition[])
                {
                  [0] = { X64CPU_OP_ROL, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_RCX, X64CPU_PS_b } } },
                  [1] = { X64CPU_OP_ROR, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_RCX, X64CPU_PS_b } } },
                  [2] = { X64CPU_OP_RCL, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_RCX, X64CPU_PS_b } } },
                  [3] = { X64CPU_OP_RCR, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_RCX, X64CPU_PS_b } } },
                  [4] = { X64CPU_OP_SHL, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_RCX, X64CPU_PS_b } } },
                  [5] = { X64CPU_OP_SHR, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_RCX, X64CPU_PS_b } } },
                  [6] = { X64CPU_OP_SHL, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_RCX, X64CPU_PS_b } } },
                  [7] = { X64CPU_OP_SAR, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_RCX, X64CPU_PS_b } } },
                }
               },
    /* 0xD4 */ { X64CPU_OP_AAM, 0, { { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0xD5 */ { X64CPU_OP_AAD, 0, { { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0xD6 */ { X64CPU_OP_SETALC },
    /* 0xD7 */ { X64CPU_OP_XLAT, 0 },
    /* 0xD_ */ 
    /* 0xD8 */ { X64CPU_OP_FPU, 1 },
    /* 0xD9 */ { X64CPU_OP_FPU, 1 },
    /* 0xDA */ { X64CPU_OP_FPU, 1 },
    /* 0xDB */ { X64CPU_OP_FPU, 1 },
    /* 0xDC */ { X64CPU_OP_FPU, 1 },
    /* 0xDD */ { X64CPU_OP_FPU, 1 },
    /* 0xDE */ { X64CPU_OP_FPU, 1 },
    /* 0xDF */ { X64CPU_OP_FPU, 1 },

    /* 0xE_ */
    /* 0xE0 */ { X64CPU_OP_LOOPNE, 0, { { X64CPU_PT_J, X64CPU_PS_bs } } },
    /* 0xE1 */ { X64CPU_OP_LOOPE, 0, { { X64CPU_PT_J, X64CPU_PS_bs } } },
    /* 0xE2 */ { X64CPU_OP_LOOP, 0, { { X64CPU_PT_J, X64CPU_PS_bs } } },
    /* 0xE3 */ { X64CPU_OP_JRCX, 0, { { X64CPU_PT_J, X64CPU_PS_bs }, { X64CPU_PT_RCX, X64CPU_PS_v } } },
    /* 0xE4 */ { X64CPU_OP_IN, 0, { { X64CPU_PT_RAX, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0xE5 */ { X64CPU_OP_IN, 0, { { X64CPU_PT_RAX, X64CPU_PS_d }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0xE6 */ { X64CPU_OP_OUT, 0, { { X64CPU_PT_I, X64CPU_PS_b }, { X64CPU_PT_RAX, X64CPU_PS_b } } },
    /* 0xE7 */ { X64CPU_OP_OUT, 0, { { X64CPU_PT_I, X64CPU_PS_b }, { X64CPU_PT_RAX, X64CPU_PS_d } } },
    /* 0xE_ */
    /* 0xE8 */ { X64CPU_OP_CALL, 0, { { X64CPU_PT_J, X64CPU_PS_v } } },
    /* 0xE9 */ { X64CPU_OP_JMP, 0, { { X64CPU_PT_J, X64CPU_PS_v } } },
    /* 0xEA */ { X64CPU_OP_JMP_FAR, 0, { { X64CPU_PT_A, X64CPU_PS_p } } },
    /* 0xEB */ { X64CPU_OP_JMP, 0, { { X64CPU_PT_J, X64CPU_PS_bs } } },
    /* 0xEC */ { X64CPU_OP_IN, 0, { { X64CPU_PT_RAX, X64CPU_PS_b }, { X64CPU_PT_RDX, X64CPU_PS_w } } },
    /* 0xED */ { X64CPU_OP_IN, 0, { { X64CPU_PT_RAX, X64CPU_PS_d }, { X64CPU_PT_RDX, X64CPU_PS_w } } },
    /* 0xEE */ { X64CPU_OP_OUT, 0, { { X64CPU_PT_RDX, X64CPU_PS_w }, { X64CPU_PT_RAX, X64CPU_PS_b } } },
    /* 0xEF */ { X64CPU_OP_OUT, 0, { { X64CPU_PT_RDX, X64CPU_PS_w }, { X64CPU_PT_RAX, X64CPU_PS_d } } },

    /* 0xF_ */
    /* 0xF0 */ { X64CPU_OP_PREFIX }, /* LOCK: */
    /* 0xF1 */ { X64CPU_OP_INT, 0, { { X64CPU_PT_1, X64CPU_PS_b } } },
    /* 0xF2 */ { X64CPU_OP_PREFIX }, /* REPNE: */
    /* 0xF3 */ { X64CPU_OP_PREFIX }, /* REPE: */
    /* 0xF4 */ { X64CPU_OP_HLT },
    /* 0xF5 */ { X64CPU_OP_CMC },
    /* 0xF6 */ { X64CPU_OP_GROUP, 1, .group = (struct x64cpu_opcode_definition[])
                {
                  [0] = { X64CPU_OP_TEST, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [1] = { X64CPU_OP_TEST, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [2] = { X64CPU_OP_NOT,  1, { { X64CPU_PT_E, X64CPU_PS_b } } },
                  [3] = { X64CPU_OP_NEG,  1, { { X64CPU_PT_E, X64CPU_PS_b } } },
                  [4] = { X64CPU_OP_MUL, 1, { { X64CPU_PT_RAX, X64CPU_PS_w, .hide = 1 }, { X64CPU_PT_RAX, X64CPU_PS_b, .hide = 1 }, { X64CPU_PT_E, X64CPU_PS_b } } },
                  [5] = { X64CPU_OP_IMUL, 1, { { X64CPU_PT_RAX, X64CPU_PS_w, .hide = 1 }, { X64CPU_PT_RAX, X64CPU_PS_b, .hide = 1 }, { X64CPU_PT_E, X64CPU_PS_b } } },
                  [6] = { X64CPU_OP_DIV, 1, { { X64CPU_PT_RAX, X64CPU_PS_b, .hide = 1 }, { X64CPU_PT_RAH, X64CPU_PS_b, .hide = 1 }, { X64CPU_PT_RAX, X64CPU_PS_w, .hide = 1 }, { X64CPU_PT_E, X64CPU_PS_b } } },
                  [7] = { X64CPU_OP_IDIV, 1, { { X64CPU_PT_RAX, X64CPU_PS_b, .hide = 1 }, { X64CPU_PT_RAH, X64CPU_PS_b, .hide = 1 }, { X64CPU_PT_RAX, X64CPU_PS_w, .hide = 1 }, { X64CPU_PT_E, X64CPU_PS_b } } },
                }
               },
    /* 0xF7 */ { X64CPU_OP_GROUP, 1, .group = (struct x64cpu_opcode_definition[])
                {
                  [0] = { X64CPU_OP_TEST, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_vds } } },
                  [1] = { X64CPU_OP_TEST, 1, { { X64CPU_PT_E, X64CPU_PS_v }, { X64CPU_PT_I, X64CPU_PS_vds } } },
                  [2] = { X64CPU_OP_NOT,  1, { { X64CPU_PT_E, X64CPU_PS_v } } },
                  [3] = { X64CPU_OP_NEG,  1, { { X64CPU_PT_E, X64CPU_PS_v } } },
                  [4] = { X64CPU_OP_MUL1, 1, { { X64CPU_PT_RAX, X64CPU_PS_v, .hide = 1 }, { X64CPU_PT_RDX, X64CPU_PS_v, .hide = 1 }, { X64CPU_PT_E, X64CPU_PS_v } } },
                  [5] = { X64CPU_OP_IMUL1, 1, { { X64CPU_PT_RAX, X64CPU_PS_v, .hide = 1 }, { X64CPU_PT_RDX, X64CPU_PS_v, .hide = 1 }, { X64CPU_PT_E, X64CPU_PS_v } } },
                  [6] = { X64CPU_OP_DIV, 1, { { X64CPU_PT_RAX, X64CPU_PS_v, .hide = 1 }, { X64CPU_PT_RDX, X64CPU_PS_v, .hide = 1 }, { X64CPU_PT_RAX, X64CPU_PS_v, .hide = 1 }, { X64CPU_PT_E, X64CPU_PS_v } } },
                  [7] = { X64CPU_OP_IDIV, 1, { { X64CPU_PT_RAX, X64CPU_PS_v, .hide = 1 }, { X64CPU_PT_RDX, X64CPU_PS_v, .hide = 1 }, { X64CPU_PT_RAX, X64CPU_PS_v, .hide = 1 }, { X64CPU_PT_E, X64CPU_PS_v } } },
                }
               },
    /* 0xF_ */
    /* 0xF8 */ { X64CPU_OP_CLC },
    /* 0xF9 */ { X64CPU_OP_STC },
    /* 0xFA */ { X64CPU_OP_CLI },
    /* 0xFB */ { X64CPU_OP_STI },
    /* 0xFC */ { X64CPU_OP_CLD },
    /* 0xFD */ { X64CPU_OP_STD },
    /* 0xFE */ { X64CPU_OP_GROUP, 1, .group = (struct x64cpu_opcode_definition[])
                {
                  [0] = { X64CPU_OP_INC, 1, { { X64CPU_PT_E, X64CPU_PS_b } } },
                  [1] = { X64CPU_OP_DEC, 1, { { X64CPU_PT_E, X64CPU_PS_b } } },
                }
               },
    /* 0xFF */ { X64CPU_OP_GROUP, 1, .group = (struct x64cpu_opcode_definition[])
                {
                  [0] = { X64CPU_OP_INC, 1, { { X64CPU_PT_E, X64CPU_PS_v } } },
                  [1] = { X64CPU_OP_DEC, 1, { { X64CPU_PT_E, X64CPU_PS_v } } },
                  [2] = { X64CPU_OP_CALL_I, 1, { { X64CPU_PT_E, X64CPU_PS_v } } },
                  [3] = { X64CPU_OP_CALL_I_FAR, 1, { { X64CPU_PT_M, X64CPU_PS_p } } },
                  [4] = { X64CPU_OP_JMP_I, 1, { { X64CPU_PT_E, X64CPU_PS_v } } },
                  [5] = { X64CPU_OP_JMP_I_FAR, 1, { { X64CPU_PT_M, X64CPU_PS_p } } },
                  [6] = { X64CPU_OP_PUSH, 1, { { X64CPU_PT_E, X64CPU_PS_v } } },
                  [7] = { X64CPU_OP_INVALID },
                }
               },
};

