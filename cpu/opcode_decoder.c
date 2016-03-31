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
const struct x64cpu_opcode_definition x64cpu_opcode_def_1byte[] = {
    /* 0x0_ */
    /* 0x00 */ { X64CPU_OP_ADD, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_G, X64CPU_PS_b } } },
    /* 0x01 */ { X64CPU_OP_ADD, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_G, X64CPU_PS_vqp } } },
    /* 0x02 */ { X64CPU_OP_ADD, 1, { { X64CPU_PT_G, X64CPU_PS_b }, { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x03 */ { X64CPU_OP_ADD, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_vqp } } },
    /* 0x04 */ { X64CPU_OP_ADD, 0, { { X64CPU_PT_RAX, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0x05 */ { X64CPU_OP_ADD, 0, { { X64CPU_PT_RAX, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_vds } } },
    /* 0x06 */ { X64CPU_OP_INVALID },
    /* 0x07 */ { X64CPU_OP_INVALID },
    /* 0x0_ */
    /* 0x08 */ { X64CPU_OP_OR, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_G, X64CPU_PS_b } } },
    /* 0x09 */ { X64CPU_OP_OR, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_G, X64CPU_PS_vqp } } },
    /* 0x0A */ { X64CPU_OP_OR, 1, { { X64CPU_PT_G, X64CPU_PS_b }, { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x0B */ { X64CPU_OP_OR, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_vqp } } },
    /* 0x0C */ { X64CPU_OP_OR, 0, { { X64CPU_PT_RAX, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0x0D */ { X64CPU_OP_OR, 0, { { X64CPU_PT_RAX, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_vds } } },
    /* 0x0E */ { X64CPU_OP_INVALID },
    /* 0x0F */ { X64CPU_OP_INVALID },

    /* 0x1_ */
    /* 0x10 */ { X64CPU_OP_ADC, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_G, X64CPU_PS_b } } },
    /* 0x11 */ { X64CPU_OP_ADC, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_G, X64CPU_PS_vqp } } },
    /* 0x12 */ { X64CPU_OP_ADC, 1, { { X64CPU_PT_G, X64CPU_PS_b }, { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x13 */ { X64CPU_OP_ADC, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_vqp } } },
    /* 0x14 */ { X64CPU_OP_ADC, 0, { { X64CPU_PT_RAX, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0x15 */ { X64CPU_OP_ADC, 0, { { X64CPU_PT_RAX, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_vds } } },
    /* 0x16 */ { X64CPU_OP_INVALID },
    /* 0x17 */ { X64CPU_OP_INVALID },
    /* 0x1_ */
    /* 0x18 */ { X64CPU_OP_SBB, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_G, X64CPU_PS_b } } },
    /* 0x19 */ { X64CPU_OP_SBB, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_G, X64CPU_PS_vqp } } },
    /* 0x1A */ { X64CPU_OP_SBB, 1, { { X64CPU_PT_G, X64CPU_PS_b }, { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x1B */ { X64CPU_OP_SBB, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_vqp } } },
    /* 0x1C */ { X64CPU_OP_SBB, 0, { { X64CPU_PT_RAX, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0x1D */ { X64CPU_OP_SBB, 0, { { X64CPU_PT_RAX, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_vds } } },
    /* 0x1E */ { X64CPU_OP_INVALID },
    /* 0x1F */ { X64CPU_OP_INVALID },

    /* 0x2_ */
    /* 0x20 */ { X64CPU_OP_AND, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_G, X64CPU_PS_b } } },
    /* 0x21 */ { X64CPU_OP_AND, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_G, X64CPU_PS_vqp } } },
    /* 0x22 */ { X64CPU_OP_AND, 1, { { X64CPU_PT_G, X64CPU_PS_b }, { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x23 */ { X64CPU_OP_AND, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_vqp } } },
    /* 0x24 */ { X64CPU_OP_AND, 0, { { X64CPU_PT_RAX, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0x25 */ { X64CPU_OP_AND, 0, { { X64CPU_PT_RAX, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_vds } } },
    /* 0x26 */ { X64CPU_OP_INVALID },
    /* 0x27 */ { X64CPU_OP_INVALID },
    /* 0x2_ */
    /* 0x28 */ { X64CPU_OP_SUB, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_G, X64CPU_PS_b } } },
    /* 0x29 */ { X64CPU_OP_SUB, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_G, X64CPU_PS_vqp } } },
    /* 0x2A */ { X64CPU_OP_SUB, 1, { { X64CPU_PT_G, X64CPU_PS_b }, { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x2B */ { X64CPU_OP_SUB, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_vqp } } },
    /* 0x2C */ { X64CPU_OP_SUB, 0, { { X64CPU_PT_RAX, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0x2D */ { X64CPU_OP_SUB, 0, { { X64CPU_PT_RAX, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_vds } } },
    /* 0x2E */ { X64CPU_OP_INVALID },
    /* 0x2F */ { X64CPU_OP_INVALID },

    /* 0x3_ */
    /* 0x30 */ { X64CPU_OP_XOR, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_G, X64CPU_PS_b } } },
    /* 0x31 */ { X64CPU_OP_XOR, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_G, X64CPU_PS_vqp } } },
    /* 0x32 */ { X64CPU_OP_XOR, 1, { { X64CPU_PT_G, X64CPU_PS_b }, { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x33 */ { X64CPU_OP_XOR, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_vqp } } },
    /* 0x34 */ { X64CPU_OP_XOR, 0, { { X64CPU_PT_RAX, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0x35 */ { X64CPU_OP_XOR, 0, { { X64CPU_PT_RAX, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_vds } } },
    /* 0x36 */ { X64CPU_OP_INVALID },
    /* 0x37 */ { X64CPU_OP_INVALID },
    /* 0x3_ */
    /* 0x38 */ { X64CPU_OP_CMP, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_G, X64CPU_PS_b } } },
    /* 0x39 */ { X64CPU_OP_CMP, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_G, X64CPU_PS_vqp } } },
    /* 0x3A */ { X64CPU_OP_CMP, 1, { { X64CPU_PT_G, X64CPU_PS_b }, { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x3B */ { X64CPU_OP_CMP, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_vqp } } },
    /* 0x3C */ { X64CPU_OP_CMP, 0, { { X64CPU_PT_RAX, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0x3D */ { X64CPU_OP_CMP, 0, { { X64CPU_PT_RAX, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_vds } } },
    /* 0x3E */ { X64CPU_OP_INVALID },
    /* 0x3F */ { X64CPU_OP_INVALID },

    /* 0x4_ */ /* 0x4_ - REX Flags */
    /* 0x40 */ { X64CPU_OP_PREFIX },
    /* 0x41 */ { X64CPU_OP_PREFIX },
    /* 0x42 */ { X64CPU_OP_PREFIX },
    /* 0x43 */ { X64CPU_OP_PREFIX },
    /* 0x44 */ { X64CPU_OP_PREFIX },
    /* 0x45 */ { X64CPU_OP_PREFIX },
    /* 0x46 */ { X64CPU_OP_PREFIX },
    /* 0x47 */ { X64CPU_OP_PREFIX },
    /* 0x4_ */
    /* 0x48 */ { X64CPU_OP_PREFIX },
    /* 0x49 */ { X64CPU_OP_PREFIX },
    /* 0x4A */ { X64CPU_OP_PREFIX },
    /* 0x4B */ { X64CPU_OP_PREFIX },
    /* 0x4C */ { X64CPU_OP_PREFIX },
    /* 0x4D */ { X64CPU_OP_PREFIX },
    /* 0x4E */ { X64CPU_OP_PREFIX },
    /* 0x4F */ { X64CPU_OP_PREFIX },

    /* 0x5_ */
    /* 0x50 */ { X64CPU_OP_PUSH, 0, { { X64CPU_PT_RAX_R8, X64CPU_PS_vq } } },
    /* 0x51 */ { X64CPU_OP_PUSH, 0, { { X64CPU_PT_RCX_R9, X64CPU_PS_vq } } },
    /* 0x52 */ { X64CPU_OP_PUSH, 0, { { X64CPU_PT_RDX_R10, X64CPU_PS_vq } } },
    /* 0x53 */ { X64CPU_OP_PUSH, 0, { { X64CPU_PT_RBX_R11, X64CPU_PS_vq } } },
    /* 0x54 */ { X64CPU_OP_PUSH, 0, { { X64CPU_PT_RSP_R12, X64CPU_PS_vq } } },
    /* 0x55 */ { X64CPU_OP_PUSH, 0, { { X64CPU_PT_RBP_R13, X64CPU_PS_vq } } },
    /* 0x56 */ { X64CPU_OP_PUSH, 0, { { X64CPU_PT_RSI_R14, X64CPU_PS_vq } } },
    /* 0x57 */ { X64CPU_OP_PUSH, 0, { { X64CPU_PT_RDI_R15, X64CPU_PS_vq } } },
    /* 0x5_ */
    /* 0x58 */ { X64CPU_OP_POP, 0, { { X64CPU_PT_RAX_R8, X64CPU_PS_vq } } },
    /* 0x59 */ { X64CPU_OP_POP, 0, { { X64CPU_PT_RCX_R9, X64CPU_PS_vq } } },
    /* 0x5A */ { X64CPU_OP_POP, 0, { { X64CPU_PT_RDX_R10, X64CPU_PS_vq } } },
    /* 0x5B */ { X64CPU_OP_POP, 0, { { X64CPU_PT_RBX_R11, X64CPU_PS_vq } } },
    /* 0x5C */ { X64CPU_OP_POP, 0, { { X64CPU_PT_RSP_R12, X64CPU_PS_vq } } },
    /* 0x5D */ { X64CPU_OP_POP, 0, { { X64CPU_PT_RBP_R13, X64CPU_PS_vq } } },
    /* 0x5E */ { X64CPU_OP_POP, 0, { { X64CPU_PT_RSI_R14, X64CPU_PS_vq } } },
    /* 0x5F */ { X64CPU_OP_POP, 0, { { X64CPU_PT_RDI_R15, X64CPU_PS_vq } } },

    /* 0x6_ */
    /* 0x60 */ { X64CPU_OP_INVALID },
    /* 0x61 */ { X64CPU_OP_INVALID },
    /* 0x62 */ { X64CPU_OP_INVALID },
    /* 0x63 */ { X64CPU_OP_MOVSXD, 1, { { X64CPU_PT_G, X64CPU_PS_dqp }, { X64CPU_PT_E, X64CPU_PS_d } } },
    /* 0x64 */ { X64CPU_OP_PREFIX }, /* FS prefix */
    /* 0x65 */ { X64CPU_OP_PREFIX }, /* GS prefix */
    /* 0x66 */ { X64CPU_OP_PREFIX }, /* Operand-size prefix */
    /* 0x67 */ { X64CPU_OP_PREFIX }, /* Address-size prefix */
    /* 0x6_ */
    /* 0x68 */ { X64CPU_OP_PUSH, 0, { { X64CPU_PT_I, X64CPU_PS_vs } } },
    /* 0x69 */ { X64CPU_OP_IMUL3, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_vds } } },
    /* 0x6A */ { X64CPU_OP_PUSH, 0, { { X64CPU_PT_I, X64CPU_PS_bss } } },
    /* 0x6B */ { X64CPU_OP_IMUL3, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_bs } } },
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
                  [0] = { X64CPU_OP_ADD, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_vds } } },
                  [1] = { X64CPU_OP_OR,  1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_vds } } },
                  [2] = { X64CPU_OP_ADC, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_vds } } },
                  [3] = { X64CPU_OP_SBB, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_vds } } },
                  [4] = { X64CPU_OP_AND, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_vds } } },
                  [5] = { X64CPU_OP_SUB, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_vds } } },
                  [6] = { X64CPU_OP_XOR, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_vds } } },
                  [7] = { X64CPU_OP_CMP, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_vds } } },
                }
               },
    /* 0x82 */ { X64CPU_OP_INVALID },
    /* 0x83 */ { X64CPU_OP_GROUP, 1, .group = (struct x64cpu_opcode_definition[])
                {
                  [0] = { X64CPU_OP_ADD, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_bs } } },
                  [1] = { X64CPU_OP_OR,  1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_bs } } },
                  [2] = { X64CPU_OP_ADC, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_bs } } },
                  [3] = { X64CPU_OP_SBB, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_bs } } },
                  [4] = { X64CPU_OP_AND, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_bs } } },
                  [5] = { X64CPU_OP_SUB, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_bs } } },
                  [6] = { X64CPU_OP_XOR, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_bs } } },
                  [7] = { X64CPU_OP_CMP, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_bs } } },
                }
               },
    /* 0x84 */ { X64CPU_OP_TEST, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_G, X64CPU_PS_b } } },
    /* 0x85 */ { X64CPU_OP_TEST, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_G, X64CPU_PS_vqp } } },
    /* 0x86 */ { X64CPU_OP_XCHG, 1, { { X64CPU_PT_G, X64CPU_PS_b }, { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x87 */ { X64CPU_OP_XCHG, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_vqp } } },
    /* 0x8_ */
    /* 0x88 */ { X64CPU_OP_MOV, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_G, X64CPU_PS_b } } },
    /* 0x89 */ { X64CPU_OP_MOV, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_G, X64CPU_PS_vqp } } },
    /* 0x8A */ { X64CPU_OP_MOV, 1, { { X64CPU_PT_G, X64CPU_PS_b }, { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x8B */ { X64CPU_OP_MOV, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_vqp } } },
    /* 0x8C */ { X64CPU_OP_MOV, 1, { { X64CPU_PT_E, X64CPU_PS_vqpMw }, { X64CPU_PT_S, X64CPU_PS_w } } },
    /* 0x8D */ { X64CPU_OP_LEA, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_M, X64CPU_PS_vqp } } },
    /* 0x8E */ { X64CPU_OP_MOV, 1, { { X64CPU_PT_S, X64CPU_PS_w }, { X64CPU_PT_E, X64CPU_PS_w } } },
    /* 0x8F */ { X64CPU_OP_POP, 1, { { X64CPU_PT_E, X64CPU_PS_vq } } },

    /* 0x9_ */
    /* 0x90 */ { X64CPU_OP_NOOP },
    /* 0x91 */ { X64CPU_OP_XCHG, 0, { { X64CPU_PT_RCX_R9, X64CPU_PS_vqp }, { X64CPU_PT_RAX, X64CPU_PS_vqp } } },
    /* 0x92 */ { X64CPU_OP_XCHG, 0, { { X64CPU_PT_RDX_R10, X64CPU_PS_vqp }, { X64CPU_PT_RAX, X64CPU_PS_vqp } } },
    /* 0x93 */ { X64CPU_OP_XCHG, 0, { { X64CPU_PT_RBX_R11, X64CPU_PS_vqp }, { X64CPU_PT_RAX, X64CPU_PS_vqp } } },
    /* 0x94 */ { X64CPU_OP_XCHG, 0, { { X64CPU_PT_RSP_R12, X64CPU_PS_vqp }, { X64CPU_PT_RAX, X64CPU_PS_vqp } } },
    /* 0x95 */ { X64CPU_OP_XCHG, 0, { { X64CPU_PT_RBP_R13, X64CPU_PS_vqp }, { X64CPU_PT_RAX, X64CPU_PS_vqp } } },
    /* 0x96 */ { X64CPU_OP_XCHG, 0, { { X64CPU_PT_RSI_R14, X64CPU_PS_vqp }, { X64CPU_PT_RAX, X64CPU_PS_vqp } } },
    /* 0x97 */ { X64CPU_OP_XCHG, 0, { { X64CPU_PT_RDI_R15, X64CPU_PS_vqp }, { X64CPU_PT_RAX, X64CPU_PS_vqp } } },
    /* 0x9_ */
    /* 0x98 */ { X64CPU_OP_CONV },
    /* 0x99 */ { X64CPU_OP_CONV2 },
    /* 0x9A */ { X64CPU_OP_INVALID },
    /* 0x9B */ { X64CPU_OP_PREFIX }, /* FWAIT prefix */
    /* 0x9C */ { X64CPU_OP_PUSH, 0, { { X64CPU_PT_F, X64CPU_PS_vqp } } },
    /* 0x9D */ { X64CPU_OP_POP, 0, { { X64CPU_PT_F, X64CPU_PS_vqp } } },
    /* 0x9E */ { X64CPU_OP_SAHF },
    /* 0x9F */ { X64CPU_OP_LAHF },

    /* 0xA_ */
    /* 0xA0 */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RAX, X64CPU_PS_b }, { X64CPU_PT_O, X64CPU_PS_b } } },
    /* 0xA1 */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RAX, X64CPU_PS_vqp }, { X64CPU_PT_O, X64CPU_PS_vqp } } },
    /* 0xA2 */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_O, X64CPU_PS_b }, { X64CPU_PT_RAX, X64CPU_PS_b } } },
    /* 0xA3 */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_O, X64CPU_PS_vqp }, { X64CPU_PT_RAX, X64CPU_PS_vqp } } },
    /* 0xA4 */ { X64CPU_OP_MOVS, 0, { { X64CPU_PT_Y, X64CPU_PS_b }, { X64CPU_PT_X, X64CPU_PS_b } } },
    /* 0xA5 */ { X64CPU_OP_MOVS, 0, { { X64CPU_PT_Y, X64CPU_PS_vqp }, { X64CPU_PT_X, X64CPU_PS_vqp } } },
    /* 0xA6 */ { X64CPU_OP_CMPS, 0, { { X64CPU_PT_Y, X64CPU_PS_b }, { X64CPU_PT_X, X64CPU_PS_b } } },
    /* 0xA7 */ { X64CPU_OP_CMPS, 0, { { X64CPU_PT_Y, X64CPU_PS_vqp }, { X64CPU_PT_X, X64CPU_PS_vqp } } },
    /* 0xA_ */
    /* 0xA8 */ { X64CPU_OP_TEST, 0, { { X64CPU_PT_RAX, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0xA9 */ { X64CPU_OP_TEST, 0, { { X64CPU_PT_RAX, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_vds } } },
    /* 0xAA */ { X64CPU_OP_STOS, 0, { { X64CPU_PT_Y, X64CPU_PS_b }, { X64CPU_PT_RAX, X64CPU_PS_b } } },
    /* 0xAB */ { X64CPU_OP_STOS, 0, { { X64CPU_PT_Y, X64CPU_PS_vqp }, { X64CPU_PT_RAX, X64CPU_PS_vqp } } },
    /* 0xAC */ { X64CPU_OP_LODS, 0, { { X64CPU_PT_RAX, X64CPU_PS_b }, { X64CPU_PT_X, X64CPU_PS_b } } },
    /* 0xAD */ { X64CPU_OP_LODS, 0, { { X64CPU_PT_RAX, X64CPU_PS_vqp }, { X64CPU_PT_X, X64CPU_PS_vqp } } },
    /* 0xAE */ { X64CPU_OP_SCAS, 0, { { X64CPU_PT_Y, X64CPU_PS_b }, { X64CPU_PT_RAX, X64CPU_PS_b } } },
    /* 0xAF */ { X64CPU_OP_SCAS, 0, { { X64CPU_PT_Y, X64CPU_PS_vqp }, { X64CPU_PT_RAX, X64CPU_PS_vqp } } },

    /* 0xB_ */
    /* 0xB0 */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RAX_R8, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0xB1 */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RCX_R9, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0xB2 */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RDX_R10, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0xB3 */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RBX_R11, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0xB4 */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RAH_R12, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0xB5 */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RCH_R13, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0xB6 */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RDH_R14, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0xB7 */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RBH_R15, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0xB_ */
    /* 0xB8 */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RAX_R8, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_vqp } } },
    /* 0xB9 */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RCX_R9, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_vqp } } },
    /* 0xBA */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RDX_R10, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_vqp } } },
    /* 0xBB */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RBX_R11, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_vqp } } },
    /* 0xBC */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RSP_R12, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_vqp } } },
    /* 0xBD */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RBP_R13, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_vqp } } },
    /* 0xBE */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RSI_R14, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_vqp } } },
    /* 0xBF */ { X64CPU_OP_MOV, 0, { { X64CPU_PT_RDI_R15, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_vqp } } },

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
                  [0] = { X64CPU_OP_ROL, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [1] = { X64CPU_OP_ROR, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [2] = { X64CPU_OP_RCL, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [3] = { X64CPU_OP_RCR, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [4] = { X64CPU_OP_SHL, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [5] = { X64CPU_OP_SHR, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [6] = { X64CPU_OP_SHL, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [7] = { X64CPU_OP_SAR, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_b } } },
                }
               },
    /* 0xC2 */ { X64CPU_OP_RETN, 0, { { X64CPU_PT_I, X64CPU_PS_w } } },
    /* 0xC3 */ { X64CPU_OP_RETN, 0, },
    /* 0xC4 */ { X64CPU_OP_INVALID }, /* TODO: VEX3 */
    /* 0xC5 */ { X64CPU_OP_INVALID }, /* TODO: VEX2 */
    /* 0xC6 */ { X64CPU_OP_MOV, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0xC7 */ { X64CPU_OP_MOV, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_vds } } },
    /* 0xC_ */
    /* 0xC8 */ { X64CPU_OP_ENTER, 0, { { X64CPU_PT_I, X64CPU_PS_w }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0xC9 */ { X64CPU_OP_LEAVE, 0 },
    /* 0xCA */ { X64CPU_OP_RETF, 0, { { X64CPU_PT_I, X64CPU_PS_w } } },
    /* 0xCB */ { X64CPU_OP_RETF, 0 },
    /* 0xCC */ { X64CPU_OP_INT, 0, { { X64CPU_PT_3, X64CPU_PS_b } } },
    /* 0xCD */ { X64CPU_OP_INT, 0, { { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0xCE */ { X64CPU_OP_INVALID }, /* TODO: INTO instruction on 64 bit ? */
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
                  [0] = { X64CPU_OP_ROL, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_1, X64CPU_PS_b } } },
                  [1] = { X64CPU_OP_ROR, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_1, X64CPU_PS_b } } },
                  [2] = { X64CPU_OP_RCL, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_1, X64CPU_PS_b } } },
                  [3] = { X64CPU_OP_RCR, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_1, X64CPU_PS_b } } },
                  [4] = { X64CPU_OP_SHL, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_1, X64CPU_PS_b } } },
                  [5] = { X64CPU_OP_SHR, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_1, X64CPU_PS_b } } },
                  [6] = { X64CPU_OP_SHL, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_1, X64CPU_PS_b } } },
                  [7] = { X64CPU_OP_SAR, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_1, X64CPU_PS_b } } },
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
                  [0] = { X64CPU_OP_ROL, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_RCX, X64CPU_PS_b } } },
                  [1] = { X64CPU_OP_ROR, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_RCX, X64CPU_PS_b } } },
                  [2] = { X64CPU_OP_RCL, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_RCX, X64CPU_PS_b } } },
                  [3] = { X64CPU_OP_RCR, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_RCX, X64CPU_PS_b } } },
                  [4] = { X64CPU_OP_SHL, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_RCX, X64CPU_PS_b } } },
                  [5] = { X64CPU_OP_SHR, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_RCX, X64CPU_PS_b } } },
                  [6] = { X64CPU_OP_SHL, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_RCX, X64CPU_PS_b } } },
                  [7] = { X64CPU_OP_SAR, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_RCX, X64CPU_PS_b } } },
                }
               },
    /* 0xD4 */ { X64CPU_OP_INVALID },
    /* 0xD5 */ { X64CPU_OP_INVALID },
    /* 0xD6 */ { X64CPU_OP_INVALID },
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
    /* 0xE3 */ { X64CPU_OP_JRCX, 0, { { X64CPU_PT_J, X64CPU_PS_bs }, { X64CPU_PT_RCX, X64CPU_PS_vqp } } },
    /* 0xE4 */ { X64CPU_OP_IN, 0, { { X64CPU_PT_RAX, X64CPU_PS_b }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0xE5 */ { X64CPU_OP_IN, 0, { { X64CPU_PT_RAX, X64CPU_PS_d }, { X64CPU_PT_I, X64CPU_PS_b } } },
    /* 0xE6 */ { X64CPU_OP_OUT, 0, { { X64CPU_PT_I, X64CPU_PS_b }, { X64CPU_PT_RAX, X64CPU_PS_b } } },
    /* 0xE7 */ { X64CPU_OP_OUT, 0, { { X64CPU_PT_I, X64CPU_PS_b }, { X64CPU_PT_RAX, X64CPU_PS_d } } },
    /* 0xE_ */
    /* 0xE8 */ { X64CPU_OP_CALL, 0, { { X64CPU_PT_J, X64CPU_PS_vds } } },
    /* 0xE9 */ { X64CPU_OP_JMP, 0, { { X64CPU_PT_J, X64CPU_PS_vds } } },
    /* 0xEA */ { X64CPU_OP_INVALID },
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
                  [0] = { X64CPU_OP_TEST, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_vds } } },
                  [1] = { X64CPU_OP_TEST, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_vds } } },
                  [2] = { X64CPU_OP_NOT,  1, { { X64CPU_PT_E, X64CPU_PS_vqp } } },
                  [3] = { X64CPU_OP_NEG,  1, { { X64CPU_PT_E, X64CPU_PS_vqp } } },
                  [4] = { X64CPU_OP_MUL1, 1, { { X64CPU_PT_RAX, X64CPU_PS_vqp, .hide = 1 }, { X64CPU_PT_RDX, X64CPU_PS_vqp, .hide = 1 }, { X64CPU_PT_E, X64CPU_PS_vqp } } },
                  [5] = { X64CPU_OP_IMUL1, 1, { { X64CPU_PT_RAX, X64CPU_PS_vqp, .hide = 1 }, { X64CPU_PT_RDX, X64CPU_PS_vqp, .hide = 1 }, { X64CPU_PT_E, X64CPU_PS_vqp } } },
                  [6] = { X64CPU_OP_DIV, 1, { { X64CPU_PT_RAX, X64CPU_PS_vqp, .hide = 1 }, { X64CPU_PT_RDX, X64CPU_PS_vqp, .hide = 1 }, { X64CPU_PT_RAX, X64CPU_PS_vqp, .hide = 1 }, { X64CPU_PT_E, X64CPU_PS_vqp } } },
                  [7] = { X64CPU_OP_IDIV, 1, { { X64CPU_PT_RAX, X64CPU_PS_vqp, .hide = 1 }, { X64CPU_PT_RDX, X64CPU_PS_vqp, .hide = 1 }, { X64CPU_PT_RAX, X64CPU_PS_vqp, .hide = 1 }, { X64CPU_PT_E, X64CPU_PS_vqp } } },
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
                  [0] = { X64CPU_OP_INC, 1, { { X64CPU_PT_E, X64CPU_PS_vqp } } },
                  [1] = { X64CPU_OP_DEC, 1, { { X64CPU_PT_E, X64CPU_PS_vqp } } },
                  [2] = { X64CPU_OP_CALL_I, 1, { { X64CPU_PT_E, X64CPU_PS_q } } },
                  [3] = { X64CPU_OP_CALLF_I, 1, { { X64CPU_PT_M, X64CPU_PS_vq } } },
                  [4] = { X64CPU_OP_JMP_I, 1, { { X64CPU_PT_E, X64CPU_PS_q } } },
                  [5] = { X64CPU_OP_JMPF_I, 1, { { X64CPU_PT_M, X64CPU_PS_vq } } },
                  [6] = { X64CPU_OP_PUSH, 1, { { X64CPU_PT_E, X64CPU_PS_vq } } },
                  [7] = { X64CPU_OP_INVALID },
                }
               },
};

/* Instructions from FPU set - first one used when modrmbyte.mod != 3, second one otherwise */

/* 0xD8 */
const struct x64cpu_opcode_definition_fpu x64cpu_opcode_def_fpu_0[] = {
    /* 0x00 */ {{
                { X64CPU_OP_FPU_FADD, 0, { { X64CPU_PT_M, X64CPU_PS_sr } } },
                { X64CPU_OP_FPU_FADD, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
               }},
    /* 0x01 */ {{
                { X64CPU_OP_FPU_FMUL, 0, { { X64CPU_PT_M, X64CPU_PS_sr } } },
                { X64CPU_OP_FPU_FMUL, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
               }},
    /* 0x02 */ {{
                { X64CPU_OP_FPU_FCOM, 0, { { X64CPU_PT_M, X64CPU_PS_sr } } },
                { X64CPU_OP_FPU_FCOM, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
               }},
    /* 0x03 */ {{
                { X64CPU_OP_FPU_FCOMP, 0, { { X64CPU_PT_M, X64CPU_PS_sr } } },
                { X64CPU_OP_FPU_FCOMP, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
               }},
    /* 0x04 */ {{
                { X64CPU_OP_FPU_FSUB, 0, { { X64CPU_PT_M, X64CPU_PS_sr } } },
                { X64CPU_OP_FPU_FSUB, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
               }},
    /* 0x05 */ {{
                { X64CPU_OP_FPU_FSUBR, 0, { { X64CPU_PT_M, X64CPU_PS_sr } } },
                { X64CPU_OP_FPU_FSUBR, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
               }},
    /* 0x06 */ {{
                { X64CPU_OP_FPU_FDIV, 0, { { X64CPU_PT_M, X64CPU_PS_sr } } },
                { X64CPU_OP_FPU_FDIV, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
               }},
    /* 0x07 */ {{
                { X64CPU_OP_FPU_FDIVR, 0, { { X64CPU_PT_M, X64CPU_PS_sr } } },
                { X64CPU_OP_FPU_FDIVR, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
               }},
};

/* 0xD9 */
const struct x64cpu_opcode_definition_fpu x64cpu_opcode_def_fpu_1[] = {
    /* 0x00 */ {{
                { X64CPU_OP_FPU_FLD, 0, { { X64CPU_PT_M, X64CPU_PS_sr } } },
                { X64CPU_OP_FPU_FLD, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
               }},
    /* 0x01 */ {{
                { X64CPU_OP_INVALID }, /* No FXCH with memory here */
                { X64CPU_OP_FPU_FXCH, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
               }},
    /* 0x02 */ {{
                { X64CPU_OP_FPU_FST, 0, { { X64CPU_PT_M, X64CPU_PS_sr } } },
                { X64CPU_OP_NOOP }, /* TODO: Although FST with other register than ST(0) is invalid */
               }},
    /* 0x03 */ {{
                { X64CPU_OP_FPU_FSTP, 0, { { X64CPU_PT_M, X64CPU_PS_sr }  } },
                { X64CPU_OP_FPU_FSTP, 0, { { X64CPU_PT_EST, X64CPU_PS_er }  } },
               }},
    /* 0x04 */ {{
                { X64CPU_OP_FPU_FLDENV, 0, { { X64CPU_PT_M, X64CPU_PS_e } } },
                { X64CPU_OP_EGROUP, 0, .egroup = (struct x64cpu_opcode_definition[])
                 {
                  [0] = { X64CPU_OP_FPU_FCHS, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
                  [1] = { X64CPU_OP_FPU_FABS, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
                  [4] = { X64CPU_OP_FPU_FTST, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
                  [5] = { X64CPU_OP_FPU_FXAM, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
                 }
                }
               }},
    /* 0x05 */ {{
                { X64CPU_OP_FPU_FLDCW, 0, { { X64CPU_PT_M, X64CPU_PS_w } } },
                { X64CPU_OP_EGROUP, 0, .egroup = (struct x64cpu_opcode_definition[])
                 {
                  [0] = { X64CPU_OP_FPU_FLD1, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
                  [1] = { X64CPU_OP_FPU_FLDL2T, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
                  [2] = { X64CPU_OP_FPU_FLDL2E, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
                  [3] = { X64CPU_OP_FPU_FLDPI, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
                  [4] = { X64CPU_OP_FPU_FLDLG2, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
                  [5] = { X64CPU_OP_FPU_FLDLN2, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
                  [6] = { X64CPU_OP_FPU_FLDZ, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
                 }
                }
               }},
    /* 0x06 */ {{
                { X64CPU_OP_FPU_FSTENV, 0, { { X64CPU_PT_M, X64CPU_PS_e } } },
                { X64CPU_OP_EGROUP, 0, .egroup = (struct x64cpu_opcode_definition[])
                 {
                  [0] = { X64CPU_OP_FPU_F2XM1, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
                  [1] = { X64CPU_OP_FPU_FYL2X, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
                  [2] = { X64CPU_OP_FPU_FPTAN, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
                  [3] = { X64CPU_OP_FPU_FPATAN, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
                  [4] = { X64CPU_OP_FPU_FXTRACT, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
                  [5] = { X64CPU_OP_FPU_FPREM1, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
                  [6] = { X64CPU_OP_FPU_FDECSTP, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
                  [7] = { X64CPU_OP_FPU_FINCSTP, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
                 }
                }
               }},
    /* 0x07 */ {{
                { X64CPU_OP_FPU_FSTCW, 0, { { X64CPU_PT_M, X64CPU_PS_w } } },
                { X64CPU_OP_EGROUP, 0, .egroup = (struct x64cpu_opcode_definition[])
                 {
                  [0] = { X64CPU_OP_FPU_FPREM, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
                  [1] = { X64CPU_OP_FPU_FYL2XP1, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
                  [2] = { X64CPU_OP_FPU_FSQRT, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
                  [3] = { X64CPU_OP_FPU_FSINCOS, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
                  [4] = { X64CPU_OP_FPU_FRNDINT, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
                  [5] = { X64CPU_OP_FPU_FSCALE, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
                  [6] = { X64CPU_OP_FPU_FSIN, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
                  [7] = { X64CPU_OP_FPU_FCOS, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
                 }
                }
               }},
};

/* 0xDA */
const struct x64cpu_opcode_definition_fpu x64cpu_opcode_def_fpu_2[] = {
    /* 0x00 */ {{
                { X64CPU_OP_FPU_FIADD, 0, { { X64CPU_PT_M, X64CPU_PS_di } } },
                { X64CPU_OP_FPU_FCMOVB, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
               }},
    /* 0x01 */ {{
                { X64CPU_OP_FPU_FIMUL, 0, { { X64CPU_PT_M, X64CPU_PS_di } } },
                { X64CPU_OP_FPU_FCMOVE, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
               }},
    /* 0x02 */ {{
                { X64CPU_OP_FPU_FICOM, 0, { { X64CPU_PT_M, X64CPU_PS_di } } },
                { X64CPU_OP_FPU_FCMOVBE, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
               }},
    /* 0x03 */ {{
                { X64CPU_OP_FPU_FICOMP, 0, { { X64CPU_PT_M, X64CPU_PS_di } } },
                { X64CPU_OP_FPU_FCMOVU, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
               }},
    /* 0x04 */ {{
                { X64CPU_OP_FPU_FISUB, 0, { { X64CPU_PT_M, X64CPU_PS_di } } },
                { X64CPU_OP_INVALID },
               }},
    /* 0x05 */ {{
                { X64CPU_OP_FPU_FISUBR, 0, { { X64CPU_PT_M, X64CPU_PS_di } } },
                { X64CPU_OP_FPU_FUCOMPP /* ST, ST(1) */ }, /* TODO: invalid for other register */
               }},
    /* 0x06 */ {{
                { X64CPU_OP_FPU_FIDIV, 0, { { X64CPU_PT_M, X64CPU_PS_di } } },
                { X64CPU_OP_INVALID },
               }},
    /* 0x07 */ {{
                { X64CPU_OP_FPU_FIDIVR, 0, { { X64CPU_PT_M, X64CPU_PS_di } } },
                { X64CPU_OP_INVALID },
               }},
};

/* 0xDB */
const struct x64cpu_opcode_definition_fpu x64cpu_opcode_def_fpu_3[] = {
    /* 0x00 */ {{
                { X64CPU_OP_FPU_FILD, 0, { { X64CPU_PT_M, X64CPU_PS_di } } },
                { X64CPU_OP_FPU_FCMOVNB, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
               }},
    /* 0x01 */ {{
                { X64CPU_OP_FPU_FISTTP, 0, { { X64CPU_PT_M, X64CPU_PS_di } } },
                { X64CPU_OP_FPU_FCMOVNE, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
               }},
    /* 0x02 */ {{
                { X64CPU_OP_FPU_FIST, 0, { { X64CPU_PT_M, X64CPU_PS_di } } },
                { X64CPU_OP_FPU_FCMOVNBE, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
               }},
    /* 0x03 */ {{
                { X64CPU_OP_FPU_FISTP, 0, { { X64CPU_PT_M, X64CPU_PS_di } } },
                { X64CPU_OP_FPU_FCMOVNU, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
               }},
    /* 0x04 */ {{
                { X64CPU_OP_INVALID },
                { X64CPU_OP_EGROUP, 0, .egroup = (struct x64cpu_opcode_definition[])
                 {
                  [0] = { X64CPU_OP_FPU_FENI },
                  [1] = { X64CPU_OP_FPU_FDISI },
                  [2] = { X64CPU_OP_FPU_FCLEX },
                  [3] = { X64CPU_OP_FPU_FINIT },
                  [4] = { X64CPU_OP_FPU_FSETPM },
                 }
                }
               }},
    /* 0x05 */ {{
                { X64CPU_OP_FPU_FLD, 0, { { X64CPU_PT_M, X64CPU_PS_er } } },
                { X64CPU_OP_FPU_FUCOMI, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
               }},
    /* 0x06 */ {{
                { X64CPU_OP_INVALID },
                { X64CPU_OP_FPU_FCOMI, 0, { { X64CPU_PT_EST, X64CPU_PS_er } } },
               }},
    /* 0x07 */ {{
                { X64CPU_OP_FPU_FISTP, 0, { { X64CPU_PT_M, X64CPU_PS_er } } },
                { X64CPU_OP_INVALID },
               }},
};

/* 0xDC */
const struct x64cpu_opcode_definition_fpu x64cpu_opcode_def_fpu_4[] = {
    /* 0x00 */ {{
                { X64CPU_OP_FPU_FADD, 0, { { X64CPU_PT_M, X64CPU_PS_dr } } },
                { X64CPU_OP_FPU_FADD, 0, { { X64CPU_PT_EST, X64CPU_PS_dr } } },
               }},
    /* 0x01 */ {{
                { X64CPU_OP_FPU_FMUL, 0, { { X64CPU_PT_M, X64CPU_PS_dr } } },
                { X64CPU_OP_FPU_FMUL, 0, { { X64CPU_PT_EST, X64CPU_PS_dr } } },
               }},
    /* 0x02 */ {{
                { X64CPU_OP_FPU_FCOM, 0, { { X64CPU_PT_M, X64CPU_PS_dr } } },
                { X64CPU_OP_FPU_FCOM, 0, { { X64CPU_PT_EST, X64CPU_PS_dr } } },
               }},
    /* 0x03 */ {{
                { X64CPU_OP_FPU_FCOMP, 0, { { X64CPU_PT_M, X64CPU_PS_dr } } },
                { X64CPU_OP_FPU_FCOMP, 0, { { X64CPU_PT_EST, X64CPU_PS_dr } } },
               }},
    /* 0x04 */ {{
                { X64CPU_OP_FPU_FSUB, 0, { { X64CPU_PT_M, X64CPU_PS_dr } } },
                { X64CPU_OP_FPU_FSUBR, 0, { { X64CPU_PT_EST, X64CPU_PS_dr } } },
               }},
    /* 0x05 */ {{
                { X64CPU_OP_FPU_FSUBR, 0, { { X64CPU_PT_M, X64CPU_PS_dr } } },
                { X64CPU_OP_FPU_FSUB, 0, { { X64CPU_PT_EST, X64CPU_PS_dr } } },
               }},
    /* 0x06 */ {{
                { X64CPU_OP_FPU_FDIV, 0, { { X64CPU_PT_M, X64CPU_PS_dr } } },
                { X64CPU_OP_FPU_FDIVR, 0, { { X64CPU_PT_EST, X64CPU_PS_dr } } },
               }},
    /* 0x07 */ {{
                { X64CPU_OP_FPU_FDIVR, 0, { { X64CPU_PT_M, X64CPU_PS_dr } } },
                { X64CPU_OP_FPU_FDIV, 0, { { X64CPU_PT_EST, X64CPU_PS_dr } } },
               }},
};

/* 0xDD */
const struct x64cpu_opcode_definition_fpu x64cpu_opcode_def_fpu_5[] = {
    /* 0x00 */ {{
                { X64CPU_OP_FPU_FLD, 0, { { X64CPU_PT_M, X64CPU_PS_dr } } },
                { X64CPU_OP_FPU_FFREE, 0, { { X64CPU_PT_EST, X64CPU_PS_dr } } },
               }},
    /* 0x01 */ {{
                { X64CPU_OP_FPU_FISTTP, 0, { { X64CPU_PT_M, X64CPU_PS_qi } } },
                { X64CPU_OP_FPU_FXCH, 0, { { X64CPU_PT_EST, X64CPU_PS_dr } } },
               }},
    /* 0x02 */ {{
                { X64CPU_OP_FPU_FST, 0, { { X64CPU_PT_M, X64CPU_PS_dr } } },
                { X64CPU_OP_FPU_FST, 0, { { X64CPU_PT_EST, X64CPU_PS_dr } } },
               }},
    /* 0x03 */ {{
                { X64CPU_OP_FPU_FSTP, 0, { { X64CPU_PT_M, X64CPU_PS_dr } } },
                { X64CPU_OP_FPU_FSTP, 0, { { X64CPU_PT_EST, X64CPU_PS_dr } } },
               }},
    /* 0x04 */ {{
                { X64CPU_OP_FPU_FRSTOR, 0, { { X64CPU_PT_M, X64CPU_PS_dr } } },
                { X64CPU_OP_FPU_FUCOM, 0, { { X64CPU_PT_EST, X64CPU_PS_dr } } },
               }},
    /* 0x05 */ {{
                { X64CPU_OP_INVALID },
                { X64CPU_OP_FPU_FUCOMP, 0, { { X64CPU_PT_EST, X64CPU_PS_dr } } },
               }},
    /* 0x06 */ {{
                { X64CPU_OP_FPU_FSAVE, 0, { { X64CPU_PT_M, X64CPU_PS_dr } } },
                { X64CPU_OP_INVALID },
               }},
    /* 0x07 */ {{
                { X64CPU_OP_FPU_FSTSW, 0, { { X64CPU_PT_M, X64CPU_PS_dr } } },
                { X64CPU_OP_INVALID },
               }},
};

/* 0xDE */
const struct x64cpu_opcode_definition_fpu x64cpu_opcode_def_fpu_6[] = {
    /* 0x00 */ {{
                { X64CPU_OP_FPU_FIADD, 0, { { X64CPU_PT_M, X64CPU_PS_wi } } },
                { X64CPU_OP_FPU_FADDP, 0, { { X64CPU_PT_EST, X64CPU_PS_dr } } },
               }},
    /* 0x01 */ {{
                { X64CPU_OP_FPU_FIMUL, 0, { { X64CPU_PT_M, X64CPU_PS_wi } } },
                { X64CPU_OP_FPU_FMULP, 0, { { X64CPU_PT_EST, X64CPU_PS_dr } } },
               }},
    /* 0x02 */ {{
                { X64CPU_OP_FPU_FICOM, 0, { { X64CPU_PT_M, X64CPU_PS_wi } } },
                { X64CPU_OP_FPU_FCOMP, 0, { { X64CPU_PT_EST, X64CPU_PS_dr } } },
               }},
    /* 0x03 */ {{
                { X64CPU_OP_FPU_FICOMP, 0, { { X64CPU_PT_M, X64CPU_PS_wi } } },
                { X64CPU_OP_FPU_FCOMPP, 0, { { X64CPU_PT_EST, X64CPU_PS_dr } } },
               }},
    /* 0x04 */ {{
                { X64CPU_OP_FPU_FISUB, 0, { { X64CPU_PT_M, X64CPU_PS_wi } } },
                { X64CPU_OP_FPU_FSUBRP, 0, { { X64CPU_PT_EST, X64CPU_PS_dr } } },
               }},
    /* 0x05 */ {{
                { X64CPU_OP_FPU_FISUBR, 0, { { X64CPU_PT_M, X64CPU_PS_wi } } },
                { X64CPU_OP_FPU_FSUBP, 0, { { X64CPU_PT_EST, X64CPU_PS_dr } } },
               }},
    /* 0x06 */ {{
                { X64CPU_OP_FPU_FIDIV, 0, { { X64CPU_PT_M, X64CPU_PS_wi } } },
                { X64CPU_OP_FPU_FIDIVRP, 0, { { X64CPU_PT_EST, X64CPU_PS_dr } } },
               }},
    /* 0x07 */ {{
                { X64CPU_OP_FPU_FIDIVR, 0, { { X64CPU_PT_M, X64CPU_PS_wi } } },
                { X64CPU_OP_FPU_FIDIVP, 0, { { X64CPU_PT_EST, X64CPU_PS_dr } } },
               }},
};

/* 0xDF */
const struct x64cpu_opcode_definition_fpu x64cpu_opcode_def_fpu_7[] = {
    /* 0x00 */ {{
                { X64CPU_OP_FPU_FILD, 0, { { X64CPU_PT_M, X64CPU_PS_wi } } },
                { X64CPU_OP_FPU_FFREEP, 0, { { X64CPU_PT_EST, X64CPU_PS_dr } } },
               }},
    /* 0x01 */ {{
                { X64CPU_OP_FPU_FISTTP, 0, { { X64CPU_PT_M, X64CPU_PS_wi } } },
                { X64CPU_OP_FPU_FXCH, 0, { { X64CPU_PT_EST, X64CPU_PS_dr } } },
               }},
    /* 0x02 */ {{
                { X64CPU_OP_FPU_FIST, 0, { { X64CPU_PT_M, X64CPU_PS_wi } } },
                { X64CPU_OP_FPU_FSTP, 0, { { X64CPU_PT_EST, X64CPU_PS_dr } } },
               }},
    /* 0x03 */ {{
                { X64CPU_OP_FPU_FISTP, 0, { { X64CPU_PT_M, X64CPU_PS_wi } } },
                { X64CPU_OP_FPU_FSTP, 0, { { X64CPU_PT_EST, X64CPU_PS_dr } } },
               }},
    /* 0x04 */ {{
                { X64CPU_OP_FPU_FBLD, 0, { { X64CPU_PT_M, X64CPU_PS_bcd } } },
                { X64CPU_OP_FPU_FSTSW }
               }},
    /* 0x05 */ {{
                { X64CPU_OP_FPU_FILD, 0, { { X64CPU_PT_M, X64CPU_PS_qi } } },
                { X64CPU_OP_FPU_FUCOMIP, 0, { { X64CPU_PT_EST, X64CPU_PS_dr } } },
               }},
    /* 0x06 */ {{
                { X64CPU_OP_FPU_FBSTP, 0, { { X64CPU_PT_M, X64CPU_PS_bcd } } },
                { X64CPU_OP_FPU_FCOMIP, 0, { { X64CPU_PT_EST, X64CPU_PS_dr } } },
               }},
    /* 0x07 */ {{
                { X64CPU_OP_FPU_FISTP, 0, { { X64CPU_PT_M, X64CPU_PS_qi } } },
                { X64CPU_OP_INVALID },
               }},
};


/* 0x0F prefix - 2 byte opcodes */
const struct x64cpu_opcode_definition x64cpu_opcode_def_0F_2byte[] = {
    /* 0x0_ */
    /* 0x00 */ { X64CPU_OP_TODO }, /* Group #6 */
    /* 0x01 */ { X64CPU_OP_TODO }, /* Group #7 */
    /* 0x02 */ { X64CPU_OP_TODO }, /* LAR Gv, Ew */
    /* 0x03 */ { X64CPU_OP_TODO }, /* LSL Gv, Ew */
    /* 0x04 */ { X64CPU_OP_TODO }, /* Nothing ??? */
    /* 0x05 */ { X64CPU_OP_SYSCALL }, /* SYSCALL RCX, R11, SS, ... */
    /* 0x06 */ { X64CPU_OP_TODO }, /* CTLS CR0 - clear task-switched flag in CR0 */
    /* 0x07 */ { X64CPU_OP_TODO }, /* SYSRET SS, Fd, R11, ... */
    /* 0x0_ */
    /* 0x08 */ { X64CPU_OP_TODO }, /* INVD - invalidate internal caches */
    /* 0x09 */ { X64CPU_OP_TODO }, /* WBIND - write back and invalidate caches */
    /* 0x0A */ { X64CPU_OP_TODO }, /* CL1INVMB ??? */
    /* 0x0B */ { X64CPU_OP_TODO }, /* UD1 / UD2 ??? */
    /* 0x0C */ { X64CPU_OP_TODO }, /* UD1 / UD2 ??? */
    /* 0x0D */ { X64CPU_OP_NOOP, 1, { { X64CPU_PT_E, X64CPU_PS_v } } }, /* NOOP Ev ??? */
    /* 0x0E */ { X64CPU_OP_TODO }, /* 3DNow! ??? */
    /* 0x0F */ { X64CPU_OP_TODO }, /* 3DNow! ??? */

    /* 0x1_ */
    /* 0x10 */ { X64CPU_OP_SSE, 1, .sse_group = (struct x64cpu_opcode_definition[])
                {
                    { X64CPU_OP_SSE_MOVUP,   1, { { X64CPU_PT_V, X64CPU_PS_ps }, { X64CPU_PT_W, X64CPU_PS_ps } } },
          /* 0xF3 */{ X64CPU_OP_SSE_MOVSS,   1, { { X64CPU_PT_V, X64CPU_PS_ss }, { X64CPU_PT_W, X64CPU_PS_ss } } },
          /* 0x66 */{ X64CPU_OP_SSE_MOVUP,   1, { { X64CPU_PT_V, X64CPU_PS_pd }, { X64CPU_PT_W, X64CPU_PS_pd } } },
          /* 0xF2 */{ X64CPU_OP_SSE_MOVSD,   1, { { X64CPU_PT_V, X64CPU_PS_sd }, { X64CPU_PT_W, X64CPU_PS_sd } } },
                }
               },
    /* 0x11 */ { X64CPU_OP_SSE, 1, .sse_group = (struct x64cpu_opcode_definition[])
                {
                    { X64CPU_OP_SSE_MOVUP,   1, { { X64CPU_PT_W, X64CPU_PS_ps }, { X64CPU_PT_V, X64CPU_PS_ps } } },
          /* 0xF3 */{ X64CPU_OP_SSE_MOVSS,   1, { { X64CPU_PT_W, X64CPU_PS_ss }, { X64CPU_PT_V, X64CPU_PS_ss } } },
          /* 0x66 */{ X64CPU_OP_SSE_MOVUP,   1, { { X64CPU_PT_W, X64CPU_PS_pd }, { X64CPU_PT_V, X64CPU_PS_pd } } },
          /* 0xF2 */{ X64CPU_OP_SSE_MOVSD,   1, { { X64CPU_PT_W, X64CPU_PS_sd }, { X64CPU_PT_V, X64CPU_PS_sd } } },
                }
               },
    /* 0x12 */ { X64CPU_OP_SSE, 1, .sse_group = (struct x64cpu_opcode_definition[])
                {
                    { 0 },
          /* 0xF3 */{ 0 },
          /* 0x66 */{ X64CPU_OP_SSE_MOVLPD,   1, { { X64CPU_PT_V, X64CPU_PS_pd }, { X64CPU_PT_M, X64CPU_PS_pd } } },
          /* 0xF2 */{ 0 },
                }
               },
    /* 0x13 */ { X64CPU_OP_SSE, 1, .sse_group = (struct x64cpu_opcode_definition[])
                {
                }
               },
    /* 0x14 */ { X64CPU_OP_SSE, 1, .sse_group = (struct x64cpu_opcode_definition[])
                {
                }
               },
    /* 0x15 */ { X64CPU_OP_SSE, 1, .sse_group = (struct x64cpu_opcode_definition[])
                {
                }
               },
    /* 0x16 */ { X64CPU_OP_SSE, 1, .sse_group = (struct x64cpu_opcode_definition[])
                {
                    { 0 },
          /* 0xF3 */{ 0 },
          /* 0x66 */{ X64CPU_OP_SSE_MOVHPD,   1, { { X64CPU_PT_V, X64CPU_PS_pd }, { X64CPU_PT_M, X64CPU_PS_pd } } },
          /* 0xF2 */{ 0 },
                }
               },
    /* 0x17 */ { X64CPU_OP_SSE, 1, .sse_group = (struct x64cpu_opcode_definition[])
                {
                }
               },
    /* 0x1_ */
    /* 0x18 */ { X64CPU_OP_TODO }, /* Group 16 */
    /* 0x19 */ { X64CPU_OP_NOOP }, /* Hintable noop; Group 16 */
    /* 0x1A */ { X64CPU_OP_NOOP }, /* Hintable noop; Group 16 */
    /* 0x1B */ { X64CPU_OP_NOOP }, /* Hintable noop; Group 16 */
    /* 0x1C */ { X64CPU_OP_NOOP }, /* Hintable noop; Group 16 */
    /* 0x1D */ { X64CPU_OP_NOOP }, /* Hintable noop; Group 16 */
    /* 0x1E */ { X64CPU_OP_NOOP }, /* Hintable noop; Group 16 */
    /* 0x1F */ { X64CPU_OP_NOOP, 1 }, /* Hintable noop; Group 16 */

    /* 0x2_ */
    /* 0x20 */ { X64CPU_OP_TODO }, /* MOV Rq, Cq - MOV Control Registers */
    /* 0x21 */ { X64CPU_OP_TODO }, /* MOV Rq, Cq - MOV Control Registers */
    /* 0x22 */ { X64CPU_OP_TODO }, /* MOV Rq, Cq - MOV Control Registers */
    /* 0x23 */ { X64CPU_OP_TODO }, /* MOV Rq, Cq - MOV Control Registers */
    /* 0x24 */ { X64CPU_OP_TODO }, /* MOV Rq, Cq - MOV Control Registers */
    /* 0x25 */ { X64CPU_OP_INVALID },
    /* 0x26 */ { X64CPU_OP_TODO }, /* MOV Rq, Cq - MOV Control Registers */
    /* 0x27 */ { X64CPU_OP_INVALID },
    /* 0x2_ */
    /* 0x28 */ { X64CPU_OP_SSE, 1, .sse_group = (struct x64cpu_opcode_definition[])
                {
                    { X64CPU_OP_SSE_MOVAPS,   1, { { X64CPU_PT_V, X64CPU_PS_ps }, { X64CPU_PT_W, X64CPU_PS_ps } } },
          /* 0xF3 */{ 0 },
          /* 0x66 */{ X64CPU_OP_SSE_MOVAPD,   1, { { X64CPU_PT_V, X64CPU_PS_pd }, { X64CPU_PT_W, X64CPU_PS_pd } } },
          /* 0xF2 */{ 0 },
                }
               },
    /* 0x29 */ { X64CPU_OP_TODO }, /* MOVA, etc - SSE2 */
    /* 0x2A */ { X64CPU_OP_TODO }, /* MOVA, etc - SSE2 */
    /* 0x2B */ { X64CPU_OP_TODO }, /* MOVA, etc - SSE2 */
    /* 0x2C */ { X64CPU_OP_TODO }, /* MOVA, etc - SSE2 */
    /* 0x2D */ { X64CPU_OP_TODO }, /* MOVA, etc - SSE2 */
    /* 0x2E */ { X64CPU_OP_TODO }, /* MOVA, etc - SSE2 */
    /* 0x2F */ { X64CPU_OP_TODO }, /* MOVA, etc - SSE2 */

    /* 0x3_ */
    /* 0x30 */ { X64CPU_OP_TODO }, /* WRMSR MSR, rCX, rAX, rDX */
    /* 0x31 */ { X64CPU_OP_RDTSC }, /* RDTSC */
    /* 0x32 */ { X64CPU_OP_TODO }, /* RDMSR MSR, rCX, rAX, rDX */
    /* 0x33 */ { X64CPU_OP_TODO }, /* RDPMC */
    /* 0x34 */ { X64CPU_OP_TODO }, /* SYSENTER SS, ESP, ... */
    /* 0x35 */ { X64CPU_OP_TODO }, /* SYSEXIT SS, ESP, ... */
    /* 0x36 */ { X64CPU_OP_INVALID },
    /* 0x37 */ { X64CPU_OP_TODO }, /* GETSEC - smx */
    /* 0x3_ */
    /* 0x38 */ { X64CPU_OP_TODO }, /* ssse3 group */
    /* 0x39 */ { X64CPU_OP_INVALID },
    /* 0x3A */ { X64CPU_OP_TODO }, /* ssse41 group */
    /* 0x3B */ { X64CPU_OP_INVALID },
    /* 0x3C */ { X64CPU_OP_INVALID },
    /* 0x3D */ { X64CPU_OP_INVALID },
    /* 0x3E */ { X64CPU_OP_INVALID },
    /* 0x3F */ { X64CPU_OP_INVALID },

    /* 0x4_ */
    /* 0x40 */ { X64CPU_OP_CMOV, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_vqp } } },
    /* 0x41 */ { X64CPU_OP_CMOV, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_vqp } } },
    /* 0x42 */ { X64CPU_OP_CMOV, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_vqp } } },
    /* 0x43 */ { X64CPU_OP_CMOV, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_vqp } } },
    /* 0x44 */ { X64CPU_OP_CMOV, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_vqp } } },
    /* 0x45 */ { X64CPU_OP_CMOV, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_vqp } } },
    /* 0x46 */ { X64CPU_OP_CMOV, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_vqp } } },
    /* 0x47 */ { X64CPU_OP_CMOV, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_vqp } } },
    /* 0x4_ */
    /* 0x48 */ { X64CPU_OP_CMOV, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_vqp } } },
    /* 0x49 */ { X64CPU_OP_CMOV, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_vqp } } },
    /* 0x4A */ { X64CPU_OP_CMOV, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_vqp } } },
    /* 0x4B */ { X64CPU_OP_CMOV, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_vqp } } },
    /* 0x4C */ { X64CPU_OP_CMOV, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_vqp } } },
    /* 0x4D */ { X64CPU_OP_CMOV, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_vqp } } },
    /* 0x4E */ { X64CPU_OP_CMOV, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_vqp } } },
    /* 0x4F */ { X64CPU_OP_CMOV, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_vqp } } },

    /* 0x5_ */
    /* 0x50 */ { X64CPU_OP_TODO }, /* sse1 group */
    /* 0x51 */ { X64CPU_OP_TODO }, /* sse1 group */
    /* 0x52 */ { X64CPU_OP_TODO }, /* sse1 group */
    /* 0x53 */ { X64CPU_OP_TODO }, /* sse1 group */
    /* 0x54 */ { X64CPU_OP_TODO }, /* sse1 group */
    /* 0x55 */ { X64CPU_OP_TODO }, /* sse1 group */
    /* 0x56 */ { X64CPU_OP_TODO }, /* sse1 group */
    /* 0x57 */ { X64CPU_OP_TODO }, /* sse1 group */
    /* 0x5_ */
    /* 0x58 */ { X64CPU_OP_TODO }, /* sse1 group */
    /* 0x59 */ { X64CPU_OP_TODO }, /* sse1 group */
    /* 0x5A */ { X64CPU_OP_TODO }, /* sse1 group */
    /* 0x5B */ { X64CPU_OP_TODO }, /* sse1 group */
    /* 0x5C */ { X64CPU_OP_TODO }, /* sse1 group */
    /* 0x5D */ { X64CPU_OP_TODO }, /* sse1 group */
    /* 0x5E */ { X64CPU_OP_TODO }, /* sse1 group */
    /* 0x5F */ { X64CPU_OP_TODO }, /* sse1 group */

    /* 0x6_ */
    /* 0x60 */ { X64CPU_OP_SSE, 1, .sse_group = (struct x64cpu_opcode_definition[])
                {
                    { 0 },
            /* F3 */{ 0 },
            /* 66 */{ X64CPU_OP_SSE_PUNPCKLBW, 1, { { X64CPU_PT_V, X64CPU_PS_dq }, { X64CPU_PT_W, X64CPU_PS_dq } } },
            /* F2 */{ 0 },
                }
               },
    /* 0x61 */ { X64CPU_OP_SSE, 1, .sse_group = (struct x64cpu_opcode_definition[])
                {
                    { 0 },
            /* F3 */{ 0 },
            /* 66 */{ X64CPU_OP_SSE_PUNPCKLWD, 1, { { X64CPU_PT_V, X64CPU_PS_dq }, { X64CPU_PT_W, X64CPU_PS_dq } } },
            /* F2 */{ 0 },
                }
               },
    /* 0x62 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0x63 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0x64 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0x65 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0x66 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0x67 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0x6_ */
    /* 0x68 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0x69 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0x6A */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0x6B */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0x6C */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0x6D */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0x6E */ { X64CPU_OP_SSE, 1, .sse_group = (struct x64cpu_opcode_definition[])
                {
                    { 0 },
            /* F3 */{ 0 },
            /* 66 */{ X64CPU_OP_SSE_MOVD, 1, { { X64CPU_PT_V, X64CPU_PS_dq }, { X64CPU_PT_E, X64CPU_PS_dqp } } },
            /* F2 */{ 0 },
                }
               },
    /* 0x6F */ { X64CPU_OP_SSE, 1, .sse_group = (struct x64cpu_opcode_definition[])
                {
                    { 0 },
            /* F3 */{ X64CPU_OP_SSE_MOVDQU, 1, { { X64CPU_PT_V, X64CPU_PS_dq }, { X64CPU_PT_W, X64CPU_PS_dq } } },
            /* 66 */{ X64CPU_OP_SSE_MOVDQA, 1, { { X64CPU_PT_V, X64CPU_PS_dq }, { X64CPU_PT_W, X64CPU_PS_dq } } },
            /* F2 */{ 0 },
                }
               },

    /* 0x7_ */
    /* 0x70 */ { X64CPU_OP_SSE, 1, .sse_group = (struct x64cpu_opcode_definition[])
                {
                    { 0 },
            /* F3 */{ 0 },
            /* 66 */{ X64CPU_OP_SSE_PSHUFD, 1, { { X64CPU_PT_V, X64CPU_PS_dq }, { X64CPU_PT_W, X64CPU_PS_dq }, { X64CPU_PT_I, X64CPU_PS_b } } },
            /* F2 */{ 0 },
                }
               },
    /* 0x71 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0x72 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0x73 */ { X64CPU_OP_SSE, 1, .sse_group = (struct x64cpu_opcode_definition[])
                {
                    { 0 },
          /* 0xF3 */{ 0 },
          /* 0x66 */{ X64CPU_OP_GROUP, 1, .group = (struct x64cpu_opcode_definition[])
                        {
                          [7] = { X64CPU_OP_SSE_PSLLDQ, 1, { { X64CPU_PT_U, X64CPU_PS_dq }, { X64CPU_PT_I, X64CPU_PS_b } } },
                        }
                    },
          /* 0xF2 */{ 0 },
                }
               },
    /* 0x74 */ { X64CPU_OP_SSE, 1, .sse_group = (struct x64cpu_opcode_definition[])
                {
                    { 0 },
            /* F3 */{ 0 },
            /* 66 */{ X64CPU_OP_SSE_PCMPEQB, 1, { { X64CPU_PT_V, X64CPU_PS_dq }, { X64CPU_PT_W, X64CPU_PS_dq } } },
            /* F2 */{ 0 },
                }
               },
    /* 0x75 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0x76 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0x77 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0x7_ */
    /* 0x78 */ { X64CPU_OP_TODO }, /* VMREAD / VMWRITE */
    /* 0x79 */ { X64CPU_OP_TODO }, /* VMREAD / VMWRITE */
    /* 0x7A */ { X64CPU_OP_INVALID },
    /* 0x7B */ { X64CPU_OP_INVALID },
    /* 0x7C */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0x7D */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0x7E */ { X64CPU_OP_SSE, 1, .sse_group = (struct x64cpu_opcode_definition[])
                {
                    { 0 },
            /* F3 */{ 0 },
            /* 66 */{ X64CPU_OP_SSE_MOVD, 1, { { X64CPU_PT_E, X64CPU_PS_d }, { X64CPU_PT_V, X64CPU_PS_dq } } },
            /* F2 */{ 0 },
                }
               },
    /* 0x7F */ { X64CPU_OP_SSE, 1, .sse_group = (struct x64cpu_opcode_definition[])
                {
                    { 0 },
            /* F3 */{ X64CPU_OP_SSE_MOVDQU, 1, { { X64CPU_PT_W, X64CPU_PS_dq }, { X64CPU_PT_V, X64CPU_PS_dq } } },
            /* 66 */{ X64CPU_OP_SSE_MOVDQA, 1, { { X64CPU_PT_W, X64CPU_PS_dq }, { X64CPU_PT_V, X64CPU_PS_dq } } },
            /* F2 */{ 0 },
                }
               },

    /* 0x8_ */
    /* 0x80 */ { X64CPU_OP_CJMP, 0, { { X64CPU_PT_J, X64CPU_PS_vds } } },
    /* 0x81 */ { X64CPU_OP_CJMP, 0, { { X64CPU_PT_J, X64CPU_PS_vds } } },
    /* 0x82 */ { X64CPU_OP_CJMP, 0, { { X64CPU_PT_J, X64CPU_PS_vds } } },
    /* 0x83 */ { X64CPU_OP_CJMP, 0, { { X64CPU_PT_J, X64CPU_PS_vds } } },
    /* 0x84 */ { X64CPU_OP_CJMP, 0, { { X64CPU_PT_J, X64CPU_PS_vds } } },
    /* 0x85 */ { X64CPU_OP_CJMP, 0, { { X64CPU_PT_J, X64CPU_PS_vds } } },
    /* 0x86 */ { X64CPU_OP_CJMP, 0, { { X64CPU_PT_J, X64CPU_PS_vds } } },
    /* 0x87 */ { X64CPU_OP_CJMP, 0, { { X64CPU_PT_J, X64CPU_PS_vds } } },
    /* 0x8_ */
    /* 0x88 */ { X64CPU_OP_CJMP, 0, { { X64CPU_PT_J, X64CPU_PS_vds } } },
    /* 0x89 */ { X64CPU_OP_CJMP, 0, { { X64CPU_PT_J, X64CPU_PS_vds } } },
    /* 0x8A */ { X64CPU_OP_CJMP, 0, { { X64CPU_PT_J, X64CPU_PS_vds } } },
    /* 0x8B */ { X64CPU_OP_CJMP, 0, { { X64CPU_PT_J, X64CPU_PS_vds } } },
    /* 0x8C */ { X64CPU_OP_CJMP, 0, { { X64CPU_PT_J, X64CPU_PS_vds } } },
    /* 0x8D */ { X64CPU_OP_CJMP, 0, { { X64CPU_PT_J, X64CPU_PS_vds } } },
    /* 0x8E */ { X64CPU_OP_CJMP, 0, { { X64CPU_PT_J, X64CPU_PS_vds } } },
    /* 0x8F */ { X64CPU_OP_CJMP, 0, { { X64CPU_PT_J, X64CPU_PS_vds } } },

    /* 0x9_ */
    /* 0x90 */ { X64CPU_OP_CSET, 1, { { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x91 */ { X64CPU_OP_CSET, 1, { { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x92 */ { X64CPU_OP_CSET, 1, { { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x93 */ { X64CPU_OP_CSET, 1, { { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x94 */ { X64CPU_OP_CSET, 1, { { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x95 */ { X64CPU_OP_CSET, 1, { { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x96 */ { X64CPU_OP_CSET, 1, { { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x97 */ { X64CPU_OP_CSET, 1, { { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x9_ */
    /* 0x98 */ { X64CPU_OP_CSET, 1, { { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x99 */ { X64CPU_OP_CSET, 1, { { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x9A */ { X64CPU_OP_CSET, 1, { { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x9B */ { X64CPU_OP_CSET, 1, { { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x9C */ { X64CPU_OP_CSET, 1, { { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x9D */ { X64CPU_OP_CSET, 1, { { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x9E */ { X64CPU_OP_CSET, 1, { { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0x9F */ { X64CPU_OP_CSET, 1, { { X64CPU_PT_E, X64CPU_PS_b } } },

    /* 0xA_ */
    /* 0xA0 */ { X64CPU_OP_PUSH, 0, { { X64CPU_PT_rFS, X64CPU_PS_w } } },
    /* 0xA1 */ { X64CPU_OP_POP, 0, { { X64CPU_PT_rFS, X64CPU_PS_w } } },
    /* 0xA2 */ { X64CPU_OP_CPUID, 0 },
    /* 0xA3 */ { X64CPU_OP_BT, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_G, X64CPU_PS_vqp } } },
    /* 0xA4 */ { X64CPU_OP_TODO }, /* SHLD Evqp, Gvqp, Ib */
    /* 0xA5 */ { X64CPU_OP_TODO }, /* SHLD Evqp, Gvqp, CL */
    /* 0xA6 */ { X64CPU_OP_INVALID },
    /* 0xA7 */ { X64CPU_OP_INVALID },
    /* 0xA_ */
    /* 0xA8 */ { X64CPU_OP_PUSH, 0, { { X64CPU_PT_rGS, X64CPU_PS_w } } },
    /* 0xA9 */ { X64CPU_OP_POP, 0, { { X64CPU_PT_rGS, X64CPU_PS_w } } },
    /* 0xAA */ { X64CPU_OP_TODO }, /* RSM */
    /* 0xAB */ { X64CPU_OP_BTS, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_G, X64CPU_PS_vqp } } },
    /* 0xAC */ { X64CPU_OP_TODO }, /* SHRD Evqp, Gvqp, Ib */
    /* 0xAD */ { X64CPU_OP_TODO }, /* SHRD Evqp, Gvqp, CL */
    /* 0xAE */ { X64CPU_OP_TODO }, /* save restore state, MXCSR, etc group */
    /* 0xAF */ { X64CPU_OP_IMUL, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_vqp } } },

    /* 0xB_ */
    /* 0xB0 */ { X64CPU_OP_CMPXCHG, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_RAX, X64CPU_PS_b }, { X64CPU_PT_G, X64CPU_PS_b } } },
    /* 0xB1 */ { X64CPU_OP_CMPXCHG, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_RAX, X64CPU_PS_vqp }, { X64CPU_PT_G, X64CPU_PS_vqp } } },
    /* 0xB2 */ { X64CPU_OP_TODO }, /* LSS SS, Gvqp, Mptp */
    /* 0xB3 */ { X64CPU_OP_BTR, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_G, X64CPU_PS_vqp } } },
    /* 0xB4 */ { X64CPU_OP_TODO }, /* LFS FS, Gvqp, Mptp */
    /* 0xB5 */ { X64CPU_OP_TODO }, /* LGS GS, Gvqp, Mptp */
    /* 0xB6 */ { /* X64CPU_OP_MOVZX */ X64CPU_OP_MOV, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0xB7 */ { /* X64CPU_OP_MOVZX */ X64CPU_OP_MOV, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_w } } },
    /* 0xB_ */
    /* 0xB8 */ { X64CPU_OP_TODO }, /* JMPE - jump to ia-64 instruction set */
    /* 0xB9 */ { X64CPU_OP_TODO }, /* UD ? */
    /* 0xBA */ { X64CPU_OP_GROUP, 1, .group = (struct x64cpu_opcode_definition[])
                {
                  [4] = { X64CPU_OP_BT, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [5] = { X64CPU_OP_BTS, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [6] = { X64CPU_OP_BTR, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_b } } },
                  [7] = { X64CPU_OP_BTC, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_I, X64CPU_PS_b } } },
                }
               },
    /* 0xBB */ { X64CPU_OP_BTC, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_G, X64CPU_PS_vqp } } },
    /* 0xBC */ { X64CPU_OP_BSF, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_vqp } } },
    /* 0xBD */ { X64CPU_OP_BSR, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_vqp } } },
    /* 0xBE */ { X64CPU_OP_MOVSX, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_b } } },
    /* 0xBF */ { X64CPU_OP_MOVSX, 1, { { X64CPU_PT_G, X64CPU_PS_vqp }, { X64CPU_PT_E, X64CPU_PS_w } } },

    /* 0xC_ */
    /* 0xC0 */ { X64CPU_OP_XADD, 1, { { X64CPU_PT_E, X64CPU_PS_b }, { X64CPU_PT_G, X64CPU_PS_b } } },
    /* 0xC1 */ { X64CPU_OP_XADD, 1, { { X64CPU_PT_E, X64CPU_PS_vqp }, { X64CPU_PT_G, X64CPU_PS_vqp } } },
    /* 0xC2 */ { X64CPU_OP_TODO }, /* SSE */
    /* 0xC3 */ { X64CPU_OP_TODO }, /* SSE */
    /* 0xC4 */ { X64CPU_OP_TODO }, /* SSE */
    /* 0xC5 */ { X64CPU_OP_TODO }, /* SSE */
    /* 0xC6 */ { X64CPU_OP_TODO }, /* SSE */
    /* 0xC7 */ { X64CPU_OP_TODO }, /* TODO: GROUP x - CMPXCHG8B ... */
    /* 0xC_ */
    /* 0xC8 */ { X64CPU_OP_BSWAP, 0, { { X64CPU_PT_RAX_R8, X64CPU_PS_b } } },
    /* 0xC9 */ { X64CPU_OP_BSWAP, 0, { { X64CPU_PT_RCX_R9, X64CPU_PS_b } } },
    /* 0xCA */ { X64CPU_OP_BSWAP, 0, { { X64CPU_PT_RDX_R10, X64CPU_PS_b } } },
    /* 0xCB */ { X64CPU_OP_BSWAP, 0, { { X64CPU_PT_RBX_R11, X64CPU_PS_b } } },
    /* 0xCC */ { X64CPU_OP_BSWAP, 0, { { X64CPU_PT_RSP_R12, X64CPU_PS_b } } },
    /* 0xCD */ { X64CPU_OP_BSWAP, 0, { { X64CPU_PT_RBP_R13, X64CPU_PS_b } } },
    /* 0xCE */ { X64CPU_OP_BSWAP, 0, { { X64CPU_PT_RSI_R14, X64CPU_PS_b } } },
    /* 0xCF */ { X64CPU_OP_BSWAP, 0, { { X64CPU_PT_RDI_R15, X64CPU_PS_b } } },

    /* 0xD_ */
    /* 0xD0 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xD1 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xD2 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xD3 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xD4 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xD5 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xD6 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xD7 */ { X64CPU_OP_SSE, 1, .sse_group = (struct x64cpu_opcode_definition[])
                {
                    { 0 },
            /* F3 */{ 0 },
            /* 66 */{ X64CPU_OP_SSE_PMOVMSKB, 1, { { X64CPU_PT_G, X64CPU_PS_dqp }, { X64CPU_PT_U, X64CPU_PS_dq } } },
            /* F2 */{ 0 },
                }
               },
    /* 0xD_ */
    /* 0xD8 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xD9 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xDA */ { X64CPU_OP_SSE, 1, .sse_group = (struct x64cpu_opcode_definition[])
                {
                    { 0 },
            /* F3 */{ 0 },
            /* 66 */{ X64CPU_OP_SSE_PMINUB, 1, { { X64CPU_PT_V, X64CPU_PS_dq }, { X64CPU_PT_W, X64CPU_PS_dq } } },
            /* F2 */{ 0 },
                }
               },
    /* 0xDB */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xDC */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xDD */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xDE */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xDF */ { X64CPU_OP_TODO }, /* sse1/mmx group */

    /* 0xE_ */
    /* 0xE0 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xE1 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xE2 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xE3 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xE4 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xE5 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xE6 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xE7 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xE_ */
    /* 0xE8 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xE9 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xEA */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xEB */ { X64CPU_OP_SSE, 1, .sse_group = (struct x64cpu_opcode_definition[])
                {
                    { 0 },
            /* F3 */{ 0 },
            /* 66 */{ X64CPU_OP_SSE_POR, 1, { { X64CPU_PT_V, X64CPU_PS_dq }, { X64CPU_PT_W, X64CPU_PS_dq } } },
            /* F2 */{ 0 },
                }
               },
    /* 0xEC */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xED */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xEE */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xEF */ { X64CPU_OP_SSE, 1, .sse_group = (struct x64cpu_opcode_definition[])
                {
                    { 0 },
            /* F3 */{ 0 },
            /* 66 */{ X64CPU_OP_SSE_PXOR, 1, { { X64CPU_PT_V, X64CPU_PS_dq }, { X64CPU_PT_W, X64CPU_PS_dq } } },
            /* F2 */{ 0 },
                }
               },

    /* 0xF_ */
    /* 0xF0 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xF1 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xF2 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xF3 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xF4 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xF5 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xF6 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xF7 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xF_ */
    /* 0xF8 */ { X64CPU_OP_SSE, 1, .sse_group = (struct x64cpu_opcode_definition[])
                {
                    { 0 },
          /* 0xF3 */{ 0 },
          /* 0x66 */{ X64CPU_OP_SSE_PSUBB,   1, { { X64CPU_PT_V, X64CPU_PS_dq }, { X64CPU_PT_W, X64CPU_PS_dq } } },
          /* 0xF2 */{ 0 },
                }
               },
    /* 0xF9 */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xFA */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xFB */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xFC */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xFD */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xFE */ { X64CPU_OP_TODO }, /* sse1/mmx group */
    /* 0xFF */ { X64CPU_OP_INVALID },
};

