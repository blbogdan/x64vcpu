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


#include "cpu.h"

#include "opcode_decoder.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define INTERNAL_ERROR()    {(*((char*)0)) = 1; }

#define ASSERT(c) {\
    if (!(c)) {\
        fprintf(stderr, "Assertion failed at %s:%d in %s. Condition: " #c "\n", __FILE__, __LINE__, __PRETTY_FUNCTION__);\
        INTERNAL_ERROR();\
    }\
}

const uint64_t X64CPU_ALU_DEFAULT_FLAGS =
            X64FLAG_CF |
            X64FLAG_PF |
            X64FLAG_AF |
            X64FLAG_ZF |
            X64FLAG_SF |
            X64FLAG_OF ;

static inline void update_flags(struct x64cpu *cpu, uint64_t values, uint64_t bit_mask) {
    cpu->regs.rflags = (cpu->regs.rflags & (~bit_mask)) | (values & bit_mask);
}

enum x64cpu_alu_ops {
    X64CPU_ALU_NOOP = 0,
    X64CPU_ALU_ADD,
    X64CPU_ALU_OR,
    X64CPU_ALU_ADC,
    X64CPU_ALU_SBB,
    X64CPU_ALU_AND,
    X64CPU_ALU_SUB,
    X64CPU_ALU_XOR,
    X64CPU_ALU_CMP,
    X64CPU_ALU_TEST,
    X64CPU_ALU_XCHG,
    X64CPU_ALU_MOV,

    X64CPU_ALU_ROL,
    X64CPU_ALU_ROR,
    X64CPU_ALU_RCL,
    X64CPU_ALU_RCR,
    X64CPU_ALU_SHL,
    X64CPU_ALU_SHR,
    X64CPU_ALU_SAR,
    X64CPU_ALU_SAL,

    X64CPU_ALU_NOT,

    X64CPU_ALU_MUL1,
    X64CPU_ALU_MUL,
    X64CPU_ALU_IMUL1,
    X64CPU_ALU_IMUL,

    X64CPU_ALU_DIV,
    X64CPU_ALU_IDIV,

    X64CPU_ALU_BT,
    X64CPU_ALU_BTS,
    X64CPU_ALU_BSF,
    X64CPU_ALU_BSR,
};

static const char *x64cpu_exception_name_list[] = {
    "#DE - Divide error",
    "#DB - Debug",
    "#NMI",
    "#BP - Breakpoint (INT 3)",
    "#OF",
    "#BR",
    "#UD - Undefined opcode",
    "#NM",
    "#DF",
    "#(Reserved)",
    "#TS",
    "#NP",
    "#SS",
    "#GP - General Protection",
    "#PF - Page Fault"
};

const char *x64cpu_exception_name(enum x64cpu_exception exception) {
    return x64cpu_exception_name_list[exception];
}


/* Generate a CPU exception */
static void x64cpu_exception(struct x64cpu *cpu, enum x64cpu_exception exception_code) {
    cpu->cpu_exception.code = exception_code;
    cpu->cpu_exception.rip = cpu->old_rip;
    cpu->execution_result = X64CPU_RES_EXCEPTION;
    cpu->is_halted = 1;
}

static void x64cpu_memory_read(struct x64cpu *cpu, uint64_t address, uint8_t *val, uint8_t size,
                                    enum x64cpu_mem_access_flags access_flags) {
    enum x64cpu_mem_access_error result;
    uint64_t fault_addr = 0;

    if (cpu->mem_read != NULL) {
        result = cpu->mem_read(cpu, cpu->user_data, address, val, size, access_flags, &fault_addr);
    }
    else {
        result = X64CPU_MEM_ACCESS_PF;
    }

    if (result == X64CPU_MEM_ACCESS_GP) {
        x64cpu_exception(cpu, X64CPU_EXCEPTION_GP);
        cpu->cpu_exception.address = fault_addr;
        cpu->cpu_exception.r_w = 0;
    }
    else if (result == X64CPU_MEM_ACCESS_PF) {
        x64cpu_exception(cpu, X64CPU_EXCEPTION_PF);
        cpu->cpu_exception.address = fault_addr;
        cpu->cpu_exception.r_w = 0;
    }
}

static void x64cpu_memory_write(struct x64cpu *cpu, uint64_t address, uint8_t *val, uint8_t size,
                                    enum x64cpu_mem_access_flags access_flags) {
    enum x64cpu_mem_access_error result;
    uint64_t fault_addr = 0;

    if (cpu->mem_write != NULL) {
        result = cpu->mem_write(cpu, cpu->user_data, address, val, size, access_flags, &fault_addr);
    }
    else {
        result = X64CPU_MEM_ACCESS_PF;
    }

    if (result == X64CPU_MEM_ACCESS_GP) {
        x64cpu_exception(cpu, X64CPU_EXCEPTION_GP);
        cpu->cpu_exception.address = fault_addr;
        cpu->cpu_exception.r_w = 1;
    }
    else if (result == X64CPU_MEM_ACCESS_PF) {
        x64cpu_exception(cpu, X64CPU_EXCEPTION_PF);
        cpu->cpu_exception.address = fault_addr;
        cpu->cpu_exception.r_w = 1;
    }
}

#define X64CPU_DEBUG 1
#define X64CPU_DBG_INSTR(buf, size) {\
    memcpy(&cpu->instruction[cpu->instr_length], (uint8_t*)(buf), (size)); \
    cpu->instr_length += size; \
}

static uint8_t x64cpu_fetch8(struct x64cpu *cpu) {
    uint8_t ret;
    x64cpu_memory_read(cpu, cpu->regs.rip, &ret, 1, X64CPU_MEM_ACCESS_EXECUTE);
    cpu->regs.rip += 1;
#ifdef X64CPU_DEBUG
    X64CPU_DBG_INSTR(&ret, 1);
#endif
    return ret;
}

static uint16_t x64cpu_fetch16(struct x64cpu *cpu) {
    uint16_t ret;
    x64cpu_memory_read(cpu, cpu->regs.rip, (uint8_t*)&ret, 2, X64CPU_MEM_ACCESS_EXECUTE);
    cpu->regs.rip += 2;
#ifdef X64CPU_DEBUG
    X64CPU_DBG_INSTR(&ret, 2);
#endif
    return ret;
}

static uint32_t x64cpu_fetch32(struct x64cpu *cpu) {
    uint32_t ret;
    x64cpu_memory_read(cpu, cpu->regs.rip, (uint8_t*)&ret, 4, X64CPU_MEM_ACCESS_EXECUTE);
    cpu->regs.rip += 4;
#ifdef X64CPU_DEBUG
    X64CPU_DBG_INSTR(&ret, 4);
#endif
    return ret;
}

static uint64_t x64cpu_fetch64(struct x64cpu *cpu) {
    uint64_t ret;
    x64cpu_memory_read(cpu, cpu->regs.rip, (uint8_t*)&ret, 8, X64CPU_MEM_ACCESS_EXECUTE);
    cpu->regs.rip += 8;
#ifdef X64CPU_DEBUG
    X64CPU_DBG_INSTR(&ret, 8);
#endif
    return ret;
}

static int x64cpu_sse_enabled(struct x64cpu *cpu) {
    /* TODO: ... */
    return 1;
}

/* CPU Operands util methods */

static void x64cpu_operand_set_imm(struct x64cpu *cpu, int ope_index, uint8_t *val, uint8_t size) {
    cpu->op[ope_index].type = X64CPU_OPT_IMMEDIATE;
    cpu->op[ope_index].immediate = 0;
    cpu->op[ope_index].size = size;
    cpu->op[ope_index].sign_extend = 0;
    memcpy(&cpu->op[ope_index].immediate, val, size);
    cpu->op[ope_index].is_sib = 0;
}

static void x64cpu_operand_set_reg(struct x64cpu *cpu, int ope_index, uint8_t *reg, uint8_t size) {
    cpu->op[ope_index].type = X64CPU_OPT_REGISTER;
    cpu->op[ope_index].reg = reg;
    cpu->op[ope_index].size = size;
    cpu->op[ope_index].sign_extend = 0;
    cpu->op[ope_index].is_sib = 0;
}

/* For RDI, RSI ; incrementable register ; behaves like address */
static void x64cpu_operand_set_reg_ptr(struct x64cpu *cpu, int ope_index, uint8_t *reg, uint8_t reg_size, uint8_t size) {
    cpu->op[ope_index].type = X64CPU_OPT_REGISTER_POINTER;
    cpu->op[ope_index].reg = reg;
    cpu->op[ope_index].size = size;
    cpu->op[ope_index].ptr_size = reg_size;
    cpu->op[ope_index].sign_extend = 0;
    cpu->op[ope_index].is_sib = 0;
}

static void x64cpu_operand_set_address_abs(struct x64cpu *cpu, int ope_index, uint64_t address, uint8_t size) {
    cpu->op[ope_index].type = X64CPU_OPT_MEMORY_ACCESS;
    cpu->op[ope_index].address = address;
    cpu->op[ope_index].size = size;
    cpu->op[ope_index].sign_extend = 0;
    cpu->op[ope_index].is_sib = 0;
}

static void x64cpu_operand_set_address_sib(struct x64cpu *cpu, int ope_index, uint8_t *base, uint8_t *scaled,
                                            uint8_t multiplier, int64_t displacement, uint8_t size) {
    cpu->op[ope_index].type = X64CPU_OPT_MEMORY_ACCESS;
    cpu->op[ope_index].address = 0;
    cpu->op[ope_index].size = size;
    cpu->op[ope_index].sign_extend = 0;
    cpu->op[ope_index].is_sib = 1;
    cpu->op[ope_index].base_reg = base;
    cpu->op[ope_index].scaled_reg = scaled;
    cpu->op[ope_index].scale = multiplier;
    cpu->op[ope_index].displacement = displacement;
}

static uint64_t x64cpu_operand_ptr_address(struct x64cpu *cpu, int index) {
    uint64_t ret = 0;
    struct x64cpu_operand *op = &cpu->op[index];

    if (op->type != X64CPU_OPT_REGISTER_POINTER) {
        INTERNAL_ERROR();
    }

    switch (op->ptr_size) {
        case 4:
            ret = *((uint32_t*)op->reg);
            break;

        case 8:
            ret = *((uint64_t*)op->reg);
            break;

        default:
            INTERNAL_ERROR();
    }

    return ret;
}

static void x64cpu_operand_ptr_increment(struct x64cpu *cpu, int ope_index, int value) {
    struct x64cpu_operand *op = &cpu->op[ope_index];

    if (op->type != X64CPU_OPT_REGISTER_POINTER) {
        return;
    }

    switch (op->ptr_size) {
        case 1: *((uint8_t*)op->reg) += value; break;
        case 2: *((uint16_t*)op->reg) += value; break;
        case 4: *((uint32_t*)op->reg) += value; break;
        case 8: *((uint64_t*)op->reg) += value; break;
        default:
            INTERNAL_ERROR();
    }
}

static void x64cpu_operand_swap(struct x64cpu *cpu, int op1_index, int op2_index) {
    struct x64cpu_operand op1 = cpu->op[op1_index];
    struct x64cpu_operand op2 = cpu->op[op2_index];

    cpu->op[op2_index] = op1;
    cpu->op[op1_index] = op2;
}

static void x64cpu_operand_address_sib_to_abs(struct x64cpu *cpu, int index) {
    struct x64cpu_operand *op = &cpu->op[index];
    uint64_t base = 0, scaled = 0;

    if (op->type != X64CPU_OPT_MEMORY_ACCESS || op->is_sib == 0) {
        return;
    }

    if (op->base_reg) {
        memcpy(&base, op->base_reg, 8);
    }
    if (op->scaled_reg) {
        memcpy(&scaled, op->scaled_reg, 8);
    }

    op->address = base + (scaled * op->scale) + op->displacement + op->segment_offset;
    op->is_sib = 0;
}

static uint64_t x64cpu_operand_get_address(struct x64cpu *cpu, int index) {
    x64cpu_operand_address_sib_to_abs(cpu, index);
    return cpu->op[index].address;
}

static void x64cpu_operand_read(struct x64cpu *cpu, int index, uint8_t *out, uint8_t size) {
    struct x64cpu_operand *op = &cpu->op[index];
    uint64_t address;
    uint64_t val = 0x00;

    switch (op->type) {
        case X64CPU_OPT_IMMEDIATE:
            memcpy((uint8_t*)&val, &op->immediate, op->size);
            break;

        case X64CPU_OPT_REGISTER:
            memcpy((uint8_t*)&val, op->reg, op->size);
            break;

        case X64CPU_OPT_REGISTER_POINTER:
            address = x64cpu_operand_ptr_address(cpu, index);
            /* Memory access ; TODO: mode 64/32 */
            x64cpu_memory_read(cpu, address, (uint8_t*)&val, size, X64CPU_MEM_ACCESS_READ);
            break;

        case X64CPU_OPT_MEMORY_ACCESS:
            /* Memory access ; TODO: mode 64/32 */
            if (op->is_sib != 0) {
                x64cpu_operand_address_sib_to_abs(cpu, index);
            }
            address = op->address;
            x64cpu_memory_read(cpu, address, (uint8_t*)&val, size, X64CPU_MEM_ACCESS_READ);
            break;

        default:
            /* Internal error */
            INTERNAL_ERROR();
            break;
    }

    memcpy(out, (uint8_t*)&val, size);
}

static void x64cpu_operand_write(struct x64cpu *cpu, int index, uint8_t *in, uint8_t size) {
    struct x64cpu_operand *op = &cpu->op[index];
    uint64_t address;

    switch (op->type) {
        case X64CPU_OPT_IMMEDIATE:
            memcpy((uint8_t*)&op->immediate, in, size);
            op->size = size;
            break;

        case X64CPU_OPT_REGISTER:
            /* All 32-bit registers are zero-extended to 64 ??? */
            if (op->size == 4) {
                uint64_t val = 0;
                memcpy((uint8_t*)&val, in, size);
                memcpy(op->reg, (uint8_t*)&val, 8);
            }
            else {
                memcpy(op->reg, in, op->size);
            }
            break;

        case X64CPU_OPT_REGISTER_POINTER:
            address = x64cpu_operand_ptr_address(cpu, index);
            /* Memory access ; TODO: mode 64/32 */
            x64cpu_memory_write(cpu, address, in, size, X64CPU_MEM_ACCESS_WRITE);
            break;

        case X64CPU_OPT_MEMORY_ACCESS:
            /* Memory access ; TODO: mode 64/32 */
            if (op->is_sib != 0) {
                x64cpu_operand_address_sib_to_abs(cpu, index);
            }
            address = op->address;
            x64cpu_memory_write(cpu, address, in, size, X64CPU_MEM_ACCESS_WRITE);
            break;

        default:
            /* Internal error */
            INTERNAL_ERROR();
            break;
    }
}

/* Extend the size of an operand ; transforms it into an immediate value */
static void x64cpu_operand_extend(struct x64cpu *cpu, int ope_index, uint8_t new_size, int sign_extend) {
    struct x64cpu_operand *op = &cpu->op[ope_index];
    uint64_t tmp = 0;

    if (new_size <= op->size) {
        INTERNAL_ERROR();
        return;
    }

    /* Only register, immediate and memory supported; but memory turns to immediate */
    if (op->type == X64CPU_OPT_REGISTER_POINTER) {
        INTERNAL_ERROR();
        return;
    }

    if (sign_extend == 0) {
        uint64_t tmp = 0x00;
        x64cpu_operand_read(cpu, ope_index, (uint8_t*)&tmp, op->size);
        x64cpu_operand_set_imm(cpu, ope_index, (uint8_t*)&tmp, new_size);
        return;
    }

    /* Sign extend */

    switch (op->size) {
        case 1: {
                int8_t v1;
                x64cpu_operand_read(cpu, ope_index, (uint8_t*)&v1, 1);
                tmp = (int8_t)v1;
            }
            break;
        case 2: {
                int16_t v1;
                x64cpu_operand_read(cpu, ope_index, (uint8_t*)&v1, 2);
                tmp = (int16_t)v1;
            }
            break;

        case 4: {
                int32_t v1;
                x64cpu_operand_read(cpu, ope_index, (uint8_t*)&v1, 4);
                tmp = (int32_t)v1;
            }
            break;
    }

    x64cpu_operand_set_imm(cpu, ope_index, (uint8_t*)&tmp, new_size);
}

static void x64cpu_register_grab(struct x64cpu *cpu, enum x64cpu_register_set register_set, enum x64cpu_prefix_flags rex_flag, uint8_t reg, uint8_t size, uint8_t **ret, uint8_t *ret_size) {
    uint8_t *op = NULL;
    uint8_t op_size = 8;
    int can_use_rh = 1;
    int use_rex = 0;

    ASSERT(reg >= 0 && reg <= 7);
    ASSERT(size == 1 || size == 2 || size == 4 || size == 8 || size == 10 || size == 16);

    if (((cpu->prefix_flags & X64CPU_PREFIX_REX) != 0) || (size > 1)) {
        can_use_rh = 0;
    }

    if ((cpu->prefix_flags & rex_flag) != 0) {
        use_rex = 1;
    }

    switch (register_set) {
        case X64CPU_REG_GP:
        case X64CPU_REG_GP_H:
            if (register_set == X64CPU_REG_GP_H && can_use_rh == 1) {
                switch (reg) {
                    case 0x00: op = (uint8_t*)&cpu->regs.rax; break;
                    case 0x01: op = (uint8_t*)&cpu->regs.rcx; break;
                    case 0x02: op = (uint8_t*)&cpu->regs.rdx; break;
                    case 0x03: op = (uint8_t*)&cpu->regs.rbx; break;
                    /* Upper part of registers: AH, CH, DH, BH */
                    case 0x04: op = ((uint8_t*)&cpu->regs.rax + 1); break;
                    case 0x05: op = ((uint8_t*)&cpu->regs.rcx + 1); break;
                    case 0x06: op = ((uint8_t*)&cpu->regs.rdx + 1); break;
                    case 0x07: op = ((uint8_t*)&cpu->regs.rbx + 1); break;
                }

                /* Only byte size */
                op_size = 1;
            }
            else if (use_rex != 0) {
                switch (reg) {
                    case 0x00: op = (uint8_t*)&cpu->regs.r8; break;
                    case 0x01: op = (uint8_t*)&cpu->regs.r9; break;
                    case 0x02: op = (uint8_t*)&cpu->regs.r10; break;
                    case 0x03: op = (uint8_t*)&cpu->regs.r11; break;
                    case 0x04: op = (uint8_t*)&cpu->regs.r12; break;
                    case 0x05: op = (uint8_t*)&cpu->regs.r13; break;
                    case 0x06: op = (uint8_t*)&cpu->regs.r14; break;
                    case 0x07: op = (uint8_t*)&cpu->regs.r15; break;
                }
            }
            else {
                switch (reg) {
                    case 0x00: op = (uint8_t*)&cpu->regs.rax; break;
                    case 0x01: op = (uint8_t*)&cpu->regs.rcx; break;
                    case 0x02: op = (uint8_t*)&cpu->regs.rdx; break;
                    case 0x03: op = (uint8_t*)&cpu->regs.rbx; break;
                    case 0x04: op = (uint8_t*)&cpu->regs.rsp; break;
                    case 0x05: op = (uint8_t*)&cpu->regs.rbp; break;
                    case 0x06: op = (uint8_t*)&cpu->regs.rsi; break;
                    case 0x07: op = (uint8_t*)&cpu->regs.rdi; break;
                }
            }
            break;

        case X64CPU_REG_F:
            /* Flags register; ignore reg byte */
            op = (uint8_t*)&cpu->regs.rflags;
            break;

        case X64CPU_REG_S:
            /* Only word access */
            op_size = 2;

            switch (reg) {
                case 0x00: op = (uint8_t*)&cpu->regs.es; break;
                case 0x01: op = (uint8_t*)&cpu->regs.cs; break;
                case 0x02: op = (uint8_t*)&cpu->regs.ss; break;
                case 0x03: op = (uint8_t*)&cpu->regs.ds; break;
                case 0x04: op = (uint8_t*)&cpu->regs.fs; break;
                case 0x05: op = (uint8_t*)&cpu->regs.gs; break;
                default:
                    /* 0x06, 0x07 .res ??? */
                    // TODO: Not implemented
                    // INTERNAL_ERROR();
                    x64cpu_exception(cpu, X64CPU_EXCEPTION_UD);
                    break;
            }
            break;

        case X64CPU_REG_FPU:
            op = (uint8_t*)&cpu->regs.st[reg];
            op_size = 10;
            break;

        case X64CPU_REG_XMM:
            if (use_rex) {
                op = (uint8_t*)&cpu->regs.xmm[reg + 8];
            }
            else {
                op = (uint8_t*)&cpu->regs.xmm[reg];
            }
            op_size = 16;
            break;

        default:
            // TODO: not implemented
            INTERNAL_ERROR();
            break;
    }

    ASSERT(size <= op_size);

    op_size = size;

    (*ret) = op;
    (*ret_size) = op_size;
}

static void x64cpu_select_operand_reg(struct x64cpu *cpu, int index, enum x64cpu_register_set register_set,
                                        enum x64cpu_prefix_flags rex_flag, uint8_t reg, uint8_t size) {
    uint8_t *op = NULL, opsize = 0;
    x64cpu_register_grab(cpu, register_set, rex_flag, reg, size, &op, &opsize);
    x64cpu_operand_set_reg(cpu, index, op, opsize);
}

/* Determine operand-size based on definition and modrmbyte */
static void x64cpu_decode_operand_size(struct x64cpu *cpu, enum x64cpu_parameter_type type, enum x64cpu_parameter_size size,
                                        uint8_t *ret_size, uint8_t *ret_sign_extended) {
    int ret = 0;
    int sign_extended = 0;
    int prefix = cpu->prefix_flags;

    switch (type) {
        case X64CPU_PT_ST:
        case X64CPU_PT_EST:
            ret = 10; /* 80-bits */
            break;

        case X64CPU_PT_1:
        case X64CPU_PT_3:
            ret = 1;
            break;

        case X64CPU_PT_S:
            ret = 2;
            break;

        default:
            switch (size) {
                case X64CPU_PS_b: ret = 1; break;
                case X64CPU_PS_bs: ret = 1; sign_extended = 1; break;

                /* Extended to 64 in decode_operand_type */
                case X64CPU_PS_bss: ret = 1; sign_extended = 1; break;

                case X64CPU_PS_w: ret = 2; break;
                case X64CPU_PS_d: ret = 4; break;
                case X64CPU_PS_q: ret = 8; break;

                case X64CPU_PS_dqp:
                    if ((prefix & X64CPU_PREFIX_REX_W) != 0) {
                        ret = 8;
                    }
                    else {
                        ret = 4;
                    }
                    break;

                case X64CPU_PS_v:
                    if ((prefix & X64CPU_PREFIX_OP_SIZE) != 0) {
                        ret = 2;
                    }
                    else {
                        ret = 4;
                    }
                    break;

                case X64CPU_PS_vs:
                case X64CPU_PS_vds:
                    if ((prefix & X64CPU_PREFIX_OP_SIZE) != 0) {
                        ret = 2;
                    }
                    else {
                        ret = 4;
                    }
                    sign_extended = 1;
                    break;

                case X64CPU_PS_vq:
                    if ((prefix & X64CPU_PREFIX_OP_SIZE) != 0) {
                        ret = 2;
                    }
                    else {
                        ret = 8;
                    }
                    break;

                case X64CPU_PS_vqpMw: // TODO: somehow else ?
                case X64CPU_PS_vqp:
                    if ((prefix & X64CPU_PREFIX_REX_W) != 0) {
                        ret = 8;
                    }
                    else if ((prefix & X64CPU_PREFIX_OP_SIZE) != 0) {
                        ret = 2;
                    }
                    else {
                        ret = 4;
                    }
                    break;

                case X64CPU_PS_wi:
                    ret = 2;
                    break;

                case X64CPU_PS_di:
                    ret = 4;
                    break;

                case X64CPU_PS_qi:
                    ret = 8;
                    break;

                case X64CPU_PS_dq:
                    ret = 16;
                    break;

                case X64CPU_PS_bcd:
                    ret = 10; /* 80bit ? */
                    break;

                case X64CPU_PS_sr:
                    ret = 4;
                    break;

                case X64CPU_PS_dr:
                    ret = 8;
                    break;

                case X64CPU_PS_er:
                    ret = 10;
                    break;

                case X64CPU_PS_sd:
                    ret = 16;
                    break;

                case X64CPU_PS_pd:
                    ret = 16;
                    break;

                case X64CPU_PS_ss:
                    ret = 16;
                    break;

                case X64CPU_PS_ps:
                    ret = 16;
                    break;


                default:
                    /* Not implemented */
                    INTERNAL_ERROR();
                    break;
            }
            break;
    }

    (*ret_size) = ret;
    (*ret_sign_extended) = sign_extended;
}

static uint8_t x64cpu_decode_address_size(struct x64cpu *cpu) {
    uint8_t ret = 8; /* Default on 64-bit */

    if ((cpu->prefix_flags & X64CPU_PREFIX_ADDR_SIZE) == 1) {
        ret = 4;
    }

    return ret;
}

static void x64cpu_decode_sib(struct x64cpu *cpu, uint8_t **p_base, uint8_t **p_scaled, uint8_t *p_multiplier) {
    uint8_t multiplier = 1;
    uint8_t *scaled = NULL, *base = NULL;

    switch (cpu->sibbyte.ss) {
        case 0x01: multiplier = 2; break;
        case 0x02: multiplier = 4; break;
        case 0x03: multiplier = 8; break;
    }

    if ((cpu->prefix_flags & X64CPU_PREFIX_REX_X) == 0) {
        switch (cpu->sibbyte.index) {
            case 0x00: scaled = (uint8_t*) &cpu->regs.rax; break;
            case 0x01: scaled = (uint8_t*) &cpu->regs.rcx; break;
            case 0x02: scaled = (uint8_t*) &cpu->regs.rdx; break;
            case 0x03: scaled = (uint8_t*) &cpu->regs.rbx; break;
            case 0x04: scaled = (uint8_t*) NULL; break;
            case 0x05: scaled = (uint8_t*) &cpu->regs.rbp; break;
            case 0x06: scaled = (uint8_t*) &cpu->regs.rsi; break;
            case 0x07: scaled = (uint8_t*) &cpu->regs.rdi; break;
        }
    }
    else {
        switch (cpu->sibbyte.index) {
            case 0x00: scaled = (uint8_t*) &cpu->regs.r8; break;
            case 0x01: scaled = (uint8_t*) &cpu->regs.r9; break;
            case 0x02: scaled = (uint8_t*) &cpu->regs.r10; break;
            case 0x03: scaled = (uint8_t*) &cpu->regs.r11; break;
            case 0x04: scaled = (uint8_t*) &cpu->regs.r12; break;
            case 0x05: scaled = (uint8_t*) &cpu->regs.r13; break;
            case 0x06: scaled = (uint8_t*) &cpu->regs.r14; break;
            case 0x07: scaled = (uint8_t*) &cpu->regs.r15; break;
        }
    }

    if ((cpu->prefix_flags & X64CPU_PREFIX_REX_B) == 0) {
        switch (cpu->sibbyte.reg) {
            case 0x00: base = (uint8_t*) &cpu->regs.rax; break;
            case 0x01: base = (uint8_t*) &cpu->regs.rcx; break;
            case 0x02: base = (uint8_t*) &cpu->regs.rdx; break;
            case 0x03: base = (uint8_t*) &cpu->regs.rbx; break;
            case 0x04: base = (uint8_t*) &cpu->regs.rsp; break;
            case 0x05:
                switch (cpu->modrmbyte.mod) {
                    case 0x00: break;
                    case 0x01: base = (uint8_t*) &cpu->regs.rbp; break;
                    case 0x02: base = (uint8_t*) &cpu->regs.rbp; break;
                }
                break;
            case 0x06: base = (uint8_t*) &cpu->regs.rsi; break;
            case 0x07: base = (uint8_t*) &cpu->regs.rdi; break;
        }
    }
    else {
        switch (cpu->sibbyte.reg) {
            case 0x00: base = (uint8_t*) &cpu->regs.r8; break;
            case 0x01: base = (uint8_t*) &cpu->regs.r9; break;
            case 0x02: base = (uint8_t*) &cpu->regs.r10; break;
            case 0x03: base = (uint8_t*) &cpu->regs.r11; break;
            case 0x04: base = (uint8_t*) &cpu->regs.r12; break;
            case 0x05:
                switch (cpu->modrmbyte.mod) {
                    case 0x00: break;
                    case 0x01: base = (uint8_t*) &cpu->regs.r13; break;
                    case 0x10: base = (uint8_t*) &cpu->regs.r13; break;
                }
                break;
            case 0x06: base = (uint8_t*) &cpu->regs.r14; break;
            case 0x07: base = (uint8_t*) &cpu->regs.r15; break;
        }
    }

    (*p_base) = base;
    (*p_scaled) = scaled;
    (*p_multiplier) = multiplier;
}

static void x64cpu_decode_operand_EffA(struct x64cpu *cpu, int index, enum x64cpu_register_set register_set, uint8_t size) {
    uint8_t *op = NULL;
    uint8_t op_size = 0;
    int is_mem_access = 0;
    uint8_t *base = NULL, *scaled = NULL;
    uint8_t multiplier = 1;


    switch (cpu->modrmbyte.mod) {
        /* Effective address */
        case 0x00:
        case 0x01:
        case 0x02:
            is_mem_access = 1;

            op_size = size;

            if ((cpu->prefix_flags & X64CPU_PREFIX_REX_B) == 0) {
                switch (cpu->modrmbyte.rm) {
                    case 0x00: base = (uint8_t*) &cpu->regs.rax; break;
                    case 0x01: base = (uint8_t*) &cpu->regs.rcx; break;
                    case 0x02: base = (uint8_t*) &cpu->regs.rdx; break;
                    case 0x03: base = (uint8_t*) &cpu->regs.rbx; break;
                    case 0x04: x64cpu_decode_sib(cpu, &base, &scaled, &multiplier); break;
                    case 0x05:
                        if (cpu->modrmbyte.mod == 0x00) {
                            base = (uint8_t*) &cpu->regs.rip;
                        }
                        else {
                            base = (uint8_t*) &cpu->regs.rbp;
                        }
                        break;
                    case 0x06: base = (uint8_t*) &cpu->regs.rsi; break;
                    case 0x07: base = (uint8_t*) &cpu->regs.rdi; break;
                }
            }
            else {
                switch (cpu->modrmbyte.rm) {
                    case 0x00: base = (uint8_t*) &cpu->regs.r8; break;
                    case 0x01: base = (uint8_t*) &cpu->regs.r9; break;
                    case 0x02: base = (uint8_t*) &cpu->regs.r10; break;
                    case 0x03: base = (uint8_t*) &cpu->regs.r11; break;
                    case 0x04: x64cpu_decode_sib(cpu, &base, &scaled, &multiplier); break;
                    case 0x05:
                        if (cpu->modrmbyte.mod == 0x00) {
                            base = (uint8_t*) &cpu->regs.rip;
                        }
                        else {
                            base = (uint8_t*) &cpu->regs.r13;
                        }
                        break;
                    case 0x06: base = (uint8_t*) &cpu->regs.r14; break;
                    case 0x07: base = (uint8_t*) &cpu->regs.r15; break;
                }
            }
            break;

        case 0x03:
            x64cpu_register_grab(cpu, register_set, X64CPU_PREFIX_REX_B, cpu->modrmbyte.rm, size, &op, &op_size);
            break;
    }

    if (op_size == 0) {
        x64cpu_exception(cpu, X64CPU_EXCEPTION_UD);
    }
    else if (is_mem_access) {
        cpu->op[index].segment_offset = 0;
        x64cpu_operand_set_address_sib(cpu, index, base, scaled, multiplier, cpu->displacement, op_size);
        if ((cpu->prefix_flags & X64CPU_PREFIX_FS)) {
            cpu->op[index].segment_offset = cpu->regs.fs_ptr;
        }
        else if ((cpu->prefix_flags & X64CPU_PREFIX_GS)) {
            cpu->op[index].segment_offset = cpu->regs.gs_ptr;
        }
        else {
            cpu->op[index].segment_offset = 0;
        }
    }
    else {
        x64cpu_operand_set_reg(cpu, index, op, op_size);
    }
}

static void x64cpu_decode_operand_E(struct x64cpu *cpu, int index, uint8_t size) {
    x64cpu_decode_operand_EffA(cpu, index, X64CPU_REG_GP_H, size);
}

static void x64cpu_decode_operand_G(struct x64cpu *cpu, int index, uint8_t size) {
    uint8_t *op = NULL, opsize = 0;
    x64cpu_register_grab(cpu, X64CPU_REG_GP_H, X64CPU_PREFIX_REX_R, cpu->modrmbyte.reg, size, &op, &opsize);
    x64cpu_operand_set_reg(cpu, index, op, opsize);
}

static void x64cpu_decode_operand_S(struct x64cpu *cpu, int index, uint8_t size) {
    uint8_t *op = NULL, opsize = 0;
    x64cpu_register_grab(cpu, X64CPU_REG_S, 0, cpu->modrmbyte.reg, size, &op, &opsize);
    x64cpu_operand_set_reg(cpu, index, op, opsize);
}

static void x64cpu_decode_operand_F(struct x64cpu *cpu, int index, uint8_t size) {
    x64cpu_operand_set_reg(cpu, index, (uint8_t*)&cpu->regs.rflags, size);
}

static void x64cpu_decode_operand_I(struct x64cpu *cpu, int index, uint8_t size) {
    uint64_t tmp = 0;

    switch (size) {
        case 1: tmp = x64cpu_fetch8(cpu); break;
        case 2: tmp = x64cpu_fetch16(cpu); break;
        case 4: tmp = x64cpu_fetch32(cpu); break;
        case 8: tmp = x64cpu_fetch64(cpu); break;
        default:
            /* Internal error */
            INTERNAL_ERROR();
            break;
    }
    
    x64cpu_operand_set_imm(cpu, index, (uint8_t*)&tmp, size);
}

static void x64cpu_decode_operand_O(struct x64cpu *cpu, int index, uint8_t size) {
    uint64_t tmp = 0;

    switch (x64cpu_decode_address_size(cpu)) {
        case 4: tmp = x64cpu_fetch32(cpu); break;
        case 8: tmp = x64cpu_fetch64(cpu); break;
        default:
            /* Internal error */
            INTERNAL_ERROR();
            break;
    }
    
    x64cpu_operand_set_address_abs(cpu, index, tmp, size);
}

static void x64cpu_decode_operand_XY(struct x64cpu *cpu, int index, uint8_t is_y, uint8_t size) {
    uint8_t *ptr_reg = NULL;
    uint8_t ptr_reg_size = 0;
    uint8_t address_size;

    address_size = x64cpu_decode_address_size(cpu);

    if (is_y) {
        x64cpu_register_grab(cpu, X64CPU_REG_GP, 0, X64CPU_REGISTER_RDI, address_size, &ptr_reg, &ptr_reg_size);
    }
    else {
        x64cpu_register_grab(cpu, X64CPU_REG_GP, 0, X64CPU_REGISTER_RSI, address_size, &ptr_reg, &ptr_reg_size);
    }

    x64cpu_operand_set_reg_ptr(cpu, index, ptr_reg, ptr_reg_size, size);
}

static void x64cpu_decode_operand_U(struct x64cpu *cpu, int index, uint8_t size) {
    uint8_t *op = NULL, opsize = 0;

    ASSERT(size == 16);

    /* SSE2 XMM Register */
    x64cpu_register_grab(cpu, X64CPU_REG_XMM, X64CPU_PREFIX_REX_B, cpu->modrmbyte.rm, size, &op, &opsize);
    x64cpu_operand_set_reg(cpu, index, op, opsize);
}

static void x64cpu_decode_operand_V(struct x64cpu *cpu, int index, uint8_t size) {
    uint8_t *op = NULL, opsize = 0;

    ASSERT(size == 16);

    /* SSE2 XMM Register */
    x64cpu_register_grab(cpu, X64CPU_REG_XMM, X64CPU_PREFIX_REX_R, cpu->modrmbyte.reg, size, &op, &opsize);
    x64cpu_operand_set_reg(cpu, index, op, opsize);
}

static void x64cpu_decode_operand_W(struct x64cpu *cpu, int index, uint8_t size) {
    ASSERT(size == 16);

    /* SSE2 XMM Register */
    x64cpu_decode_operand_EffA(cpu, index, X64CPU_REG_XMM, size);
}

static void x64cpu_decode_operand_ES(struct x64cpu *cpu, int index, uint8_t size) {
    x64cpu_decode_operand_EffA(cpu, index, X64CPU_REG_FPU, size);
}

static void x64cpu_decode_operand_type(struct x64cpu *cpu, int index, enum x64cpu_parameter_type type,
                                        enum x64cpu_parameter_size def_size) {
    uint64_t tmp = 0;
    uint8_t size = 0;
    uint8_t sign_extended = 0;

    x64cpu_decode_operand_size(cpu, type, def_size, &size, &sign_extended);

    switch (type) {
        case X64CPU_PT_1: tmp = 1; x64cpu_operand_set_imm(cpu, index, (uint8_t*)&tmp, 1); break;
        case X64CPU_PT_3: tmp = 3; x64cpu_operand_set_imm(cpu, index, (uint8_t*)&tmp, 1); break;

        case X64CPU_PT_E: x64cpu_decode_operand_E(cpu, index, size); break;
        case X64CPU_PT_G: x64cpu_decode_operand_G(cpu, index, size); break;
        case X64CPU_PT_S: x64cpu_decode_operand_S(cpu, index, size); break;
        case X64CPU_PT_F: x64cpu_decode_operand_F(cpu, index, size); break;

        case X64CPU_PT_M:
            x64cpu_decode_operand_E(cpu, index, size);
            if (cpu->op[index].type != X64CPU_OPT_MEMORY_ACCESS) {
                cpu->op[index].type = X64CPU_OPT_NONE;
                x64cpu_exception(cpu, X64CPU_EXCEPTION_UD);
            }
            break;

        case X64CPU_PT_I: x64cpu_decode_operand_I(cpu, index, size); break;

        case X64CPU_PT_J:
            x64cpu_decode_operand_I(cpu, index, size);
            /* Always sign extend to address size (64bit) */
            x64cpu_operand_extend(cpu, index, 8, 1);
            break;

        case X64CPU_PT_O: x64cpu_decode_operand_O(cpu, index, size); break;

        case X64CPU_PT_X: x64cpu_decode_operand_XY(cpu, index, 0, size); break;
        case X64CPU_PT_Y: x64cpu_decode_operand_XY(cpu, index, 1, size); break;

        case X64CPU_PT_RAX:
        case X64CPU_PT_RCX:
        case X64CPU_PT_RDX:
        case X64CPU_PT_RBX:
        case X64CPU_PT_RSP:
        case X64CPU_PT_RBP:
        case X64CPU_PT_RSI:
        case X64CPU_PT_RDI:
            x64cpu_select_operand_reg(cpu, index, X64CPU_REG_GP, 0, (type & 0x07), size);
            break;

        case X64CPU_PT_RAX_R8:
        case X64CPU_PT_RCX_R9:
        case X64CPU_PT_RDX_R10:
        case X64CPU_PT_RBX_R11:
        case X64CPU_PT_RSP_R12:
        case X64CPU_PT_RBP_R13:
        case X64CPU_PT_RSI_R14:
        case X64CPU_PT_RDI_R15:
            x64cpu_select_operand_reg(cpu, index, X64CPU_REG_GP, X64CPU_PREFIX_REX_B, (type & 0x07), size);
            break;

        case X64CPU_PT_RAH_R12:
        case X64CPU_PT_RCH_R13:
        case X64CPU_PT_RDH_R14:
        case X64CPU_PT_RBH_R15:
            x64cpu_select_operand_reg(cpu, index, X64CPU_REG_GP_H, X64CPU_PREFIX_REX_B, (type & 0x07), size);
            break;

        case X64CPU_PT_RAH:
            x64cpu_select_operand_reg(cpu, index, X64CPU_REG_GP_H, 0, (type & 0x07), size);
            break;

        case X64CPU_PT_ST:
            x64cpu_select_operand_reg(cpu, index, X64CPU_REG_FPU, 0, (0 /* ST(0) */), 10 /* always full */);
            break;

        case X64CPU_PT_ES:
            x64cpu_decode_operand_ES(cpu, index, size);
            break;

        case X64CPU_PT_EST:
            x64cpu_decode_operand_ES(cpu, index, size);
            if (cpu->op[index].type == X64CPU_OPT_MEMORY_ACCESS) {
                cpu->op[index].type = X64CPU_OPT_NONE;
                x64cpu_exception(cpu, X64CPU_EXCEPTION_UD);
            }
            break;

        case X64CPU_PT_U:
            x64cpu_decode_operand_U(cpu, index, size);
            break;

        case X64CPU_PT_V:
            x64cpu_decode_operand_V(cpu, index, size);
            break;

        case X64CPU_PT_W:
            x64cpu_decode_operand_W(cpu, index, size);
            break;

        default:
            /* Not implemented */
            INTERNAL_ERROR();
            break;
    }

    if (sign_extended) {
        cpu->op[index].sign_extend = sign_extended;

        switch ((int)def_size) {
            case X64CPU_PS_bss:
            case X64CPU_PS_vs:
                /* Sign-extended to stack size (64bit) */
                x64cpu_operand_extend(cpu, index, 8, 1);
                cpu->op[index].sign_extend = 0;
                break;
        }
    }
}

/**
 * Decodes prefix instructions
 *
 * @return 0 - if opcode is not a prefix; non-0 - otherwise
 */
static int x64cpu_decode_prefix(struct x64cpu *cpu, uint8_t opcode) {
    enum x64cpu_prefix_flags flags = 0x00;

    /* REX Flags */
    if (((opcode & 0xF0) == 0x40) && !(cpu->prefix_flags & X64CPU_PREFIX_REX)) {
        flags |= X64CPU_PREFIX_REX;

        if (opcode & 0x01) { flags |= X64CPU_PREFIX_REX_B; }
        if (opcode & 0x02) { flags |= X64CPU_PREFIX_REX_X; }
        if (opcode & 0x04) { flags |= X64CPU_PREFIX_REX_R; }
        if (opcode & 0x08) { flags |= X64CPU_PREFIX_REX_W; }
    }
    /* Operand size prefix */
    else if (opcode == 0x66) { // && !(cpu->prefix_flags & X64CPU_PREFIX_OP_SIZE)) {
        flags |= X64CPU_PREFIX_OP_SIZE;
    }
    /* Address size prefix */
    else if (opcode == 0x67 && !(cpu->prefix_flags & X64CPU_PREFIX_ADDR_SIZE)) {
        flags |= X64CPU_PREFIX_ADDR_SIZE;
    }
    /* Repeat prefix */
    else if (((opcode & 0xFE) == 0xF2) && (cpu->repeat_prefix == 0)) {
        cpu->repeat_prefix = (opcode & 0x01) ? X64CPU_PREFIX_REPEAT_REPZ : X64CPU_PREFIX_REPEAT_REPNZ;
        cpu->repeat_rip = cpu->regs.rip;
        flags |= cpu->repeat_prefix;
    }
    /* FS Segment */
    else if (opcode == 0x64 && ((flags & X64CPU_PREFIX_FS) == 0 || ((flags & X64CPU_PREFIX_GS) == 0))) {
        flags |= X64CPU_PREFIX_FS;
    }
    /* GS Segment */
    else if (opcode == 0x65 && ((flags & X64CPU_PREFIX_FS) == 0 || ((flags & X64CPU_PREFIX_GS) == 0))) {
        flags |= X64CPU_PREFIX_GS;
    }
    /* LOCK prefix */
    else if (opcode == 0xF0 && ((flags & X64CPU_PREFIX_LOCK) == 0)) {
        flags |= X64CPU_PREFIX_LOCK;
    }
    /* FWAIT prefix */
    else if (opcode == 0x9B && ((flags & X64CPU_PREFIX_FWAIT) == 0)) {
        flags |= X64CPU_PREFIX_FWAIT;
    }
    /* Null-prefixes on 64bit */
    else {
        switch (opcode) {
            case 0x26: /* ES: */
            case 0x2E: /* CS: */
            case 0x36: /* SS: */
            case 0x3E: /* DS: */
                flags |= X64CPU_PREFIX_NULL;
                break;
        }
    }

    cpu->prefix_flags |= flags;

    return flags;
}

/**
 * Decode modrm and sib bytes
 */
static void x64cpu_decode_modrm_sib(struct x64cpu *cpu, uint8_t opcode) {
    uint8_t modrmbyte;

    /* Read modrmbyte */
    modrmbyte = x64cpu_fetch8(cpu);

    cpu->modrmbyte.full = modrmbyte;
    cpu->modrmbyte.mod = (modrmbyte & 0xC0) >> 6;
    cpu->modrmbyte.rm  = (modrmbyte & 0x07);
    cpu->modrmbyte.reg = (modrmbyte & 0x38) >> 3;

    /* Do we need SIB byte ? */
    if (cpu->modrmbyte.mod != 0x03 && cpu->modrmbyte.rm == 0x04) {
        uint8_t sib;

        /* Read sib byte */
        sib = x64cpu_fetch8(cpu);

        cpu->sibbyte.full = sib;
        cpu->sibbyte.ss    = (sib & 0xC0) >> 6;
        cpu->sibbyte.index = (sib & 0x38) >> 3;
        cpu->sibbyte.reg   = (sib & 0x07);
    }

    /* Do we need a displacement offset ? */
    cpu->displacement = 0x00;

    if (cpu->modrmbyte.mod == 0x02) {
        cpu->displacement = (int32_t)x64cpu_fetch32(cpu);
    }
    else if (cpu->modrmbyte.mod == 0x01) {
        cpu->displacement = (int8_t)x64cpu_fetch8(cpu);
    }
    else if (cpu->modrmbyte.mod == 0x00) {
        if (cpu->modrmbyte.rm == 0x05 || (cpu->modrmbyte.rm == 0x04 && cpu->sibbyte.reg == 0x05)) {
            cpu->displacement = (int32_t)x64cpu_fetch32(cpu);
        }
    }
}

/**
 * Decode instruction; return the operation to be executed, if any
 */
static enum x64cpu_operation x64cpu_decode_opcode(struct x64cpu *cpu, uint8_t opcode,
                                                    const struct x64cpu_opcode_definition *opdef) {
    int i;

    /* Need modrm/sib/displacement bytes ? */
    if (opdef->need_modrmbyte) {
        x64cpu_decode_modrm_sib(cpu, opcode);
    }

    /* Operation instruction set */
    cpu->operation_instruction_set = X64CPU_INSTR_SET_GENERAL;

    while (1) {
        /* Check for groups - operation given by the modrmbyte */
        if (opdef->operation == X64CPU_OP_GROUP) {
            opdef = &(opdef->group[cpu->modrmbyte.reg]);
        }
        else if (opdef->operation == X64CPU_OP_SSE) {
            /* SSE must be enabled */
            if (!x64cpu_sse_enabled(cpu)) {
                x64cpu_exception(cpu, X64CPU_EXCEPTION_UD);
                return X64CPU_OP_INVALID;
            }

            /* 0xF3 */
            if ((cpu->prefix_flags & X64CPU_PREFIX_REPEAT_REPZ) != 0) {
                opdef = &(opdef->sse_group[1]);
            }
            /* 0x66 */
            else if ((cpu->prefix_flags & X64CPU_PREFIX_OP_SIZE) != 0) {
                opdef = &(opdef->sse_group[2]);
            }
            /* 0xF2 */
            else if ((cpu->prefix_flags & X64CPU_PREFIX_REPEAT_REPNZ) != 0) {
                opdef = &(opdef->sse_group[3]);
            }
            else {
                opdef = &(opdef->sse_group[0]);
            }

            cpu->prefix_flags &= ~(X64CPU_PREFIX_REPEAT_REPZ | X64CPU_PREFIX_REPEAT_REPNZ);

            cpu->operation_instruction_set = X64CPU_INSTR_SET_SSE;
        }
        else if (opdef->operation == X64CPU_OP_FPU) {
            /* Memory or register access */
            int st_register = (cpu->modrmbyte.mod == 3);

            /* Last 3 bits select group */
            switch ((opcode & 0x07)) {
                case 0: opdef = &(x64cpu_opcode_def_fpu_0[cpu->modrmbyte.reg].op[st_register]); break;
                case 1: opdef = &(x64cpu_opcode_def_fpu_1[cpu->modrmbyte.reg].op[st_register]); break;
                case 2: opdef = &(x64cpu_opcode_def_fpu_2[cpu->modrmbyte.reg].op[st_register]); break;
                case 3: opdef = &(x64cpu_opcode_def_fpu_3[cpu->modrmbyte.reg].op[st_register]); break;
                case 4: opdef = &(x64cpu_opcode_def_fpu_4[cpu->modrmbyte.reg].op[st_register]); break;
                case 5: opdef = &(x64cpu_opcode_def_fpu_5[cpu->modrmbyte.reg].op[st_register]); break;
                case 6: opdef = &(x64cpu_opcode_def_fpu_6[cpu->modrmbyte.reg].op[st_register]); break;
                case 7: opdef = &(x64cpu_opcode_def_fpu_7[cpu->modrmbyte.reg].op[st_register]); break;

                default:
                    return X64CPU_OP_INVALID;
                    break;
            }

            /* Operation instruction set */
            cpu->operation_instruction_set = X64CPU_INSTR_SET_FPU;
        }
        else {
            break;
        }
    }

    /* Decode parameters */
    for (i = 0; i < 4; i++) {
        if (opdef->parameters[i].type == X64CPU_PT_NONE) {
            break;
        }

        enum x64cpu_parameter_type optype = opdef->parameters[i].type;
        enum x64cpu_parameter_size opsize = opdef->parameters[i].size;

        x64cpu_decode_operand_type(cpu, i, optype, opsize);

        /* Was there a decode error ? */
        if (cpu->cpu_exception.code != X64CPU_EXCEPTION_NONE) {
            return X64CPU_OP_INVALID;
        }

        if (opdef->parameters[i].hide != 0) {
            cpu->op[i].hidden = 1;
        }
        else {
            cpu->op[i].hidden = 0;
        }
    }

#if 0
    for (i = 0; i < 4; i++) {
        x64cpu_operand_address_sib_to_abs(cpu, i);
    }
#endif

    cpu->current_op_def = opdef;

    /* Return operation code */
    return opdef->operation;
}

static enum x64cpu_operation x64cpu_decode_opcode_1byte(struct x64cpu *cpu, uint8_t opcode) {
    const struct x64cpu_opcode_definition opdef = x64cpu_opcode_def_1byte[opcode];
    return x64cpu_decode_opcode(cpu, opcode, &opdef);
}

static enum x64cpu_operation x64cpu_decode_opcode_0F_2byte(struct x64cpu *cpu, uint8_t opcode) {
    const struct x64cpu_opcode_definition opdef = x64cpu_opcode_def_0F_2byte[opcode];
    return x64cpu_decode_opcode(cpu, opcode, &opdef);
}

/*---------------------------------------------------------------------------*/
/* Instruction decoding finished. Execution begins                           */
/*---------------------------------------------------------------------------*/

#define ALU_ASM_OP_F(op, op1, op2, size) {\
    x64cpu_operand_read(cpu, 0, (uint8_t*)&(op1), size); \
    x64cpu_operand_read(cpu, 1, (uint8_t*)&(op2), size); \
    __asm__ __volatile__( \
        "pushfq\n" \
        "mov %1, %%rax\n" \
        "pushq %%rax\n" \
        "popfq\n" \
        op " %[in], %[out]\n" \
        "pushfq\n" \
        "popq %%rax\n" \
        "mov %%rax, %1\n" \
        "popfq\n" \
        : [out] "+r" (op1), [flags] "+r" (flags) \
        : [in] "r" (op2) \
        : "cc", "rax" \
    ); \
    update_flags(cpu, flags, X64CPU_ALU_DEFAULT_FLAGS); \
    x64cpu_operand_write(cpu, 0, (uint8_t*)&(op1), size); \
}

#define ALU_ASM_OP_F_NORES(op, op1, op2, size) {\
    x64cpu_operand_read(cpu, 0, (uint8_t*)&(op1), size); \
    x64cpu_operand_read(cpu, 1, (uint8_t*)&(op2), size); \
    __asm__ __volatile__( \
        "pushfq\n" \
        "mov %1, %%rax\n" \
        "pushq %%rax\n" \
        "popfq\n" \
        op " %[in], %[out]\n" \
        "pushfq\n" \
        "popq %%rax\n" \
        "mov %%rax, %1\n" \
        "popfq\n" \
        : [out] "+r" (op1), [flags] "+r" (flags) \
        : [in] "r" (op2) \
        : "cc", "rax" \
    ); \
    update_flags(cpu, flags, X64CPU_ALU_DEFAULT_FLAGS); \
}

#define ALU_ASM_OP_F_OP2B(op, op1, size) {\
    x64cpu_operand_read(cpu, 0, (uint8_t*)&(op1), size); \
    x64cpu_operand_read(cpu, 1, (uint8_t*)&(b_op[1]), 1); \
    __asm__ __volatile__( \
        "mov %1, %%rax\n" \
        "pushq %%rax\n" \
        "popfq\n" \
        "mov %2, %%cl\n" \
        op " %%cl, %[out] \n" \
        "pushfq\n" \
        "popq %%rax\n" \
        "mov %%rax, %1\n" \
        : [out] "+r" (op1), [flags] "+r" (flags) \
        : [in] "r" (b_op[1]) \
        : "cc", "rax", "rcx" \
    ); \
    update_flags(cpu, flags, X64CPU_ALU_DEFAULT_FLAGS); \
    x64cpu_operand_write(cpu, 0, (uint8_t*)&(op1), size); \
}

#define ALU_ASM_MULT(oper, rax, rdx, imm) {\
    __asm__ __volatile__ (\
        "mov %0, %%rax\n" \
        oper " %2\n" \
        "mov %%rax, %0\n" \
        "mov %%rdx, %1\n" \
        : [op1] "+r" (rax), [op2] "+r" (rdx) \
        : [op3] "r" (imm) \
        : "cc", "rax", "rdx" \
    ); \
}

#define ALU_ASM_DIV(oper, rax, rdx, imm) {\
    __asm__ __volatile__ (\
        "mov %0, %%rax\n" \
        "mov %1, %%rdx\n" \
        oper " %2\n" \
        "mov %%rax, %0\n" \
        "mov %%rdx, %1\n" \
        : "+r" (rax), "+r" (rdx) \
        : "r" (imm) \
        : "cc", "rax", "rdx" \
    ); \
}

static void x64cpu_alu(struct x64cpu *cpu, enum x64cpu_alu_ops op) {
    uint8_t b_op[4] = {0, 0, 0, 0};
    uint16_t w_op[4] = {0, 0, 0, 0};
    uint32_t d_op[4] = {0, 0, 0, 0};
    uint64_t q_op[4] = {0, 0, 0, 0};
    uint64_t flags = cpu->regs.rflags;
    uint8_t size = 0;

    /* Fix operands size when mismatch */
    if (cpu->op[1].type != X64CPU_OPT_NONE) {
        if (cpu->op[0].size != cpu->op[1].size) {
            /* TODO: extend operand 2 to size of operand 1, right ? */
            x64cpu_operand_extend(cpu, 1, cpu->op[0].size, cpu->op[1].sign_extend);

            /* Now it should work... */
            if (cpu->op[0].size != cpu->op[1].size) {
                INTERNAL_ERROR();
            }
        }
    }

    size = cpu->op[0].size;

    switch (op) {
        case X64CPU_ALU_ADD:
            switch (size) {
                case 1: ALU_ASM_OP_F("add", b_op[0], b_op[1], 1); break;
                case 2: ALU_ASM_OP_F("add", w_op[0], w_op[1], 2); break;
                case 4: ALU_ASM_OP_F("add", d_op[0], d_op[1], 4); break;
                case 8: ALU_ASM_OP_F("add", q_op[0], q_op[1], 8); break;
            }
            break;

        case X64CPU_ALU_OR:
            switch (size) {
                case 1: ALU_ASM_OP_F("or", b_op[0], b_op[1], 1); break;
                case 2: ALU_ASM_OP_F("or", w_op[0], w_op[1], 2); break;
                case 4: ALU_ASM_OP_F("or", d_op[0], d_op[1], 4); break;
                case 8: ALU_ASM_OP_F("or", q_op[0], q_op[1], 8); break;
            }
            break;

        case X64CPU_ALU_ADC:
            switch (size) {
                case 1: ALU_ASM_OP_F("adc", b_op[0], b_op[1], 1); break;
                case 2: ALU_ASM_OP_F("adc", w_op[0], w_op[1], 2); break;
                case 4: ALU_ASM_OP_F("adc", d_op[0], d_op[1], 4); break;
                case 8: ALU_ASM_OP_F("adc", q_op[0], q_op[1], 8); break;
            }
            break;

        case X64CPU_ALU_SBB:
            switch (size) {
                case 1: ALU_ASM_OP_F("sbb", b_op[0], b_op[1], 1); break;
                case 2: ALU_ASM_OP_F("sbb", w_op[0], w_op[1], 2); break;
                case 4: ALU_ASM_OP_F("sbb", d_op[0], d_op[1], 4); break;
                case 8: ALU_ASM_OP_F("sbb", q_op[0], q_op[1], 8); break;
            }
            break;

        case X64CPU_ALU_AND:
            switch (size) {
                case 1: ALU_ASM_OP_F("and", b_op[0], b_op[1], 1); break;
                case 2: ALU_ASM_OP_F("and", w_op[0], w_op[1], 2); break;
                case 4: ALU_ASM_OP_F("and", d_op[0], d_op[1], 4); break;
                case 8: ALU_ASM_OP_F("and", q_op[0], q_op[1], 8); break;
            }
            break;

        case X64CPU_ALU_SUB:
            switch (size) {
                case 1: ALU_ASM_OP_F("sub", b_op[0], b_op[1], 1); break;
                case 2: ALU_ASM_OP_F("sub", w_op[0], w_op[1], 2); break;
                case 4: ALU_ASM_OP_F("sub", d_op[0], d_op[1], 4); break;
                case 8: ALU_ASM_OP_F("sub", q_op[0], q_op[1], 8); break;
            }
            break;

        case X64CPU_ALU_XOR:
            switch (size) {
                case 1: ALU_ASM_OP_F("xor", b_op[0], b_op[1], 1); break;
                case 2: ALU_ASM_OP_F("xor", w_op[0], w_op[1], 2); break;
                case 4: ALU_ASM_OP_F("xor", d_op[0], d_op[1], 4); break;
                case 8: ALU_ASM_OP_F("xor", q_op[0], q_op[1], 8); break;
            }
            break;

        case X64CPU_ALU_CMP:
            switch (size) {
                case 1: ALU_ASM_OP_F_NORES("cmp", b_op[0], b_op[1], 1); break;
                case 2: ALU_ASM_OP_F_NORES("cmp", w_op[0], w_op[1], 2); break;
                case 4: ALU_ASM_OP_F_NORES("cmp", d_op[0], d_op[1], 4); break;
                case 8: ALU_ASM_OP_F_NORES("cmp", q_op[0], q_op[1], 8); break;
            }
            break;

        case X64CPU_ALU_TEST:
            switch (size) {
                case 1: ALU_ASM_OP_F_NORES("test", b_op[0], b_op[1], 1); break;
                case 2: ALU_ASM_OP_F_NORES("test", w_op[0], w_op[1], 2); break;
                case 4: ALU_ASM_OP_F_NORES("test", d_op[0], d_op[1], 4); break;
                case 8: ALU_ASM_OP_F_NORES("test", q_op[0], q_op[1], 8); break;
            }
            break;

        case X64CPU_ALU_XCHG: {
                uint64_t val1 = 0, val2 = 0;
                x64cpu_operand_read(cpu, 0, (uint8_t*)&val1, size);
                x64cpu_operand_read(cpu, 1, (uint8_t*)&val2, size);

                x64cpu_operand_write(cpu, 1, (uint8_t*)&val1, size);
                x64cpu_operand_write(cpu, 0, (uint8_t*)&val2, size);
            }
            break;

        case X64CPU_ALU_MOV: {
                uint64_t val = 0;
                x64cpu_operand_read(cpu, 1, (uint8_t*)&val, size);
                x64cpu_operand_write(cpu, 0, (uint8_t*)&val, size);
            }
            break;

        case X64CPU_ALU_ROL:
            switch (size) {
                case 1: ALU_ASM_OP_F_OP2B("rolb", b_op[0], 1); break;
                case 2: ALU_ASM_OP_F_OP2B("rolw", w_op[0], 2); break;
                case 4: ALU_ASM_OP_F_OP2B("rol", d_op[0], 4); break;
                case 8: ALU_ASM_OP_F_OP2B("rolq", q_op[0], 8); break;
            }
            break;

        case X64CPU_ALU_ROR:
            switch (size) {
                case 1: ALU_ASM_OP_F_OP2B("ror", b_op[0], 1); break;
                case 2: ALU_ASM_OP_F_OP2B("ror", w_op[0], 2); break;
                case 4: ALU_ASM_OP_F_OP2B("ror", d_op[0], 4); break;
                case 8: ALU_ASM_OP_F_OP2B("ror", q_op[0], 8); break;
            }
            break;

        case X64CPU_ALU_RCL:
            switch (size) {
                case 1: ALU_ASM_OP_F_OP2B("rcl", b_op[0], 1); break;
                case 2: ALU_ASM_OP_F_OP2B("rcl", w_op[0], 2); break;
                case 4: ALU_ASM_OP_F_OP2B("rcl", d_op[0], 4); break;
                case 8: ALU_ASM_OP_F_OP2B("rcl", q_op[0], 8); break;
            }
            break;

        case X64CPU_ALU_RCR:
            switch (size) {
                case 1: ALU_ASM_OP_F_OP2B("rcr", b_op[0], 1); break;
                case 2: ALU_ASM_OP_F_OP2B("rcr", w_op[0], 2); break;
                case 4: ALU_ASM_OP_F_OP2B("rcr", d_op[0], 4); break;
                case 8: ALU_ASM_OP_F_OP2B("rcr", q_op[0], 8); break;
            }
            break;

        case X64CPU_ALU_SHL:
            switch (size) {
                case 1: ALU_ASM_OP_F_OP2B("shl", b_op[0], 1); break;
                case 2: ALU_ASM_OP_F_OP2B("shl", w_op[0], 2); break;
                case 4: ALU_ASM_OP_F_OP2B("shl", d_op[0], 4); break;
                case 8: ALU_ASM_OP_F_OP2B("shl", q_op[0], 8); break;
            }
            break;

        case X64CPU_ALU_SHR:
            switch (size) {
                case 1: ALU_ASM_OP_F_OP2B("shr", b_op[0], 1); break;
                case 2: ALU_ASM_OP_F_OP2B("shr", w_op[0], 2); break;
                case 4: ALU_ASM_OP_F_OP2B("shr", d_op[0], 4); break;
                case 8: ALU_ASM_OP_F_OP2B("shr", q_op[0], 8); break;
            }
            break;

        case X64CPU_ALU_SAL:
            switch (size) {
                case 1: ALU_ASM_OP_F_OP2B("sal", b_op[0], 1); break;
                case 2: ALU_ASM_OP_F_OP2B("sal", w_op[0], 2); break;
                case 4: ALU_ASM_OP_F_OP2B("sal", d_op[0], 4); break;
                case 8: ALU_ASM_OP_F_OP2B("sal", q_op[0], 8); break;
            }
            break;

        case X64CPU_ALU_SAR:
            switch (size) {
                case 1: ALU_ASM_OP_F_OP2B("sar", b_op[0], 1); break;
                case 2: ALU_ASM_OP_F_OP2B("sar", w_op[0], 2); break;
                case 4: ALU_ASM_OP_F_OP2B("sar", d_op[0], 4); break;
                case 8: ALU_ASM_OP_F_OP2B("sar", q_op[0], 8); break;
            }
            break;

        case X64CPU_ALU_NOT: {
                uint64_t value;
                x64cpu_operand_read(cpu, 0, (uint8_t*)&value, size);
                value = ~value;
                x64cpu_operand_write(cpu, 0, (uint8_t*)&value, size);
            }
            break;

        case X64CPU_ALU_MUL1:
        case X64CPU_ALU_IMUL1:
        case X64CPU_ALU_MUL:
        case X64CPU_ALU_IMUL:
            {
                uint64_t rax = 0, rdx = 0, imm = 0;
                int flags_set = 0;

                x64cpu_operand_read(cpu, 0, (uint8_t*)&rax, size);
                x64cpu_operand_read(cpu, 2, (uint8_t*)&imm, size);

                if (op == X64CPU_ALU_MUL1 || op == X64CPU_ALU_MUL) {
                    ALU_ASM_MULT("mul", rax, rdx, imm);
                }
                else {
                    ALU_ASM_MULT("imul", rax, rdx, imm);
                }

                switch (size) {
                    case 1:
                        if ((rax & 0xff00) != 0) { flags_set = 1; }
                        break;
                    case 2:
                        rdx = (rax & 0xffff0000) >> 16;
                        rax = (rax & 0x0000ffff);
                        if (rdx) { flags_set = 1; }
                        break;
                    case 4:
                        rdx = (rax & 0xffffffff00000000) >> 32;
                        rax = (rax & 0x00000000ffffffff);
                        if (rdx) { flags_set = 1; }
                        break;
                    case 8:
                        if (rdx) { flags_set = 1; }
                        break;
                }

                if (flags_set) {
                    cpu->regs.rflags |= (X64FLAG_CF | X64FLAG_OF);
                }
                else {
                    cpu->regs.rflags &= ~(X64FLAG_CF | X64FLAG_OF);
                }

                if (size == 1) {
                    x64cpu_operand_write(cpu, 0, (uint8_t*)&rax, 2);
                }
                else {
                    x64cpu_operand_write(cpu, 0, (uint8_t*)&rax, size);
                    if (op == X64CPU_ALU_MUL1 || op == X64CPU_ALU_IMUL1) {
                        x64cpu_operand_write(cpu, 1, (uint8_t*)&rdx, size);
                    }
                }
            }
            break;

        case X64CPU_ALU_DIV:
        case X64CPU_ALU_IDIV:
            {
                uint64_t rax = 0, rdx = 0, imm = 0;

                if (size > 1) {
                    x64cpu_operand_read(cpu, 1, (uint8_t*)&rdx, size);
                }
                x64cpu_operand_read(cpu, 2, (uint8_t*)&rax, size);
                x64cpu_operand_read(cpu, 3, (uint8_t*)&imm, size);

                if (imm == 0) {
                    x64cpu_exception(cpu, X64CPU_EXCEPTION_DE);
                    break;
                }

                if (op == X64CPU_ALU_DIV) {
                    ALU_ASM_DIV("div", rax, rdx, imm);
                }
                else {
                    ALU_ASM_DIV("idiv", rax, rdx, imm);
                }

                x64cpu_operand_write(cpu, 0, (uint8_t*)&rax, size);
                x64cpu_operand_write(cpu, 1, (uint8_t*)&rdx, size);
            }
            break;

        case X64CPU_ALU_BT:
            switch (size) {
                case 1: /* Not available in CPU */ INTERNAL_ERROR(); break;
                case 2: ALU_ASM_OP_F("bt", w_op[0], w_op[1], 2); break;
                case 4: ALU_ASM_OP_F("bt", d_op[0], d_op[1], 4); break;
                case 8: ALU_ASM_OP_F("bt", q_op[0], q_op[1], 8); break;
            }
            break;

        case X64CPU_ALU_BTS:
            switch (size) {
                case 1: /* Not available in CPU */ INTERNAL_ERROR(); break;
                case 2: ALU_ASM_OP_F("bts", w_op[0], w_op[1], 2); break;
                case 4: ALU_ASM_OP_F("bts", d_op[0], d_op[1], 4); break;
                case 8: ALU_ASM_OP_F("bts", q_op[0], q_op[1], 8); break;
            }
            break;

        case X64CPU_ALU_BSF:
            switch (size) {
                case 1: /* Not available in CPU */ INTERNAL_ERROR(); break;
                case 2: ALU_ASM_OP_F("bsf", w_op[0], w_op[1], 2); break;
                case 4: ALU_ASM_OP_F("bsf", d_op[0], d_op[1], 4); break;
                case 8: ALU_ASM_OP_F("bsf", q_op[0], q_op[1], 8); break;
            }
            break;

        case X64CPU_ALU_BSR:
            switch (size) {
                case 1: /* Not available in CPU */ INTERNAL_ERROR(); break;
                case 2: ALU_ASM_OP_F("bsr", w_op[0], w_op[1], 2); break;
                case 4: ALU_ASM_OP_F("bsr", d_op[0], d_op[1], 4); break;
                case 8: ALU_ASM_OP_F("bsr", q_op[0], q_op[1], 8); break;
            }
            break;

        default:
            /* TODO: ALU operation not implemented */
            x64cpu_exception(cpu, X64CPU_EXCEPTION_UD);
            break;
    }
}

/** Push to stack, decreasing RSP */
static void x64cpu_push(struct x64cpu *cpu, int ope_index) {
    uint64_t value = 0x00;

    /* On 64bit stack always operates on 64bit mode */
    x64cpu_operand_read(cpu, ope_index, (uint8_t*)&value, cpu->op[ope_index].size);
    cpu->regs.rsp -= 8;
    x64cpu_memory_write(cpu, cpu->regs.rsp, (uint8_t*)&value, 8, X64CPU_MEM_ACCESS_WRITE);
}

/** Pop from stack, increasing RSP */
static void x64cpu_pop(struct x64cpu *cpu, int ope_index) {
    uint64_t value = 0x00;

    /* On 64bit stack always operates on 64bit mode */
    x64cpu_memory_read(cpu, cpu->regs.rsp, (uint8_t*)&value, 8, X64CPU_MEM_ACCESS_READ);
    cpu->regs.rsp += 8;
    x64cpu_operand_write(cpu, ope_index, (uint8_t*)&value, cpu->op[ope_index].size);
}

#define FLAG_ISSET(flags, flag)     ((flags & flag) ? 1 : 0)

/** Check if the condition specified by the condition jump is true or false */
static int x64cpu_condition(struct x64cpu *cpu, uint8_t opcode) {
    int cond = 0;

    switch (opcode & 0x0F) {
        /* JO */
        case 0x00: cond = ((cpu->regs.rflags & X64FLAG_OF) != 0); break;
        /* JNO */
        case 0x01: cond = ((cpu->regs.rflags & X64FLAG_OF) == 0); break;
        /* JB / JNAE / JC */
        case 0x02: cond = ((cpu->regs.rflags & X64FLAG_CF) != 0); break;
        /* JNB / JAE / JNC */
        case 0x03: cond = ((cpu->regs.rflags & X64FLAG_CF) == 0); break;
        /* JZ / JE */
        case 0x04: cond = ((cpu->regs.rflags & X64FLAG_ZF) != 0); break;
        /* JNZ / JNE */
        case 0x05: cond = ((cpu->regs.rflags & X64FLAG_ZF) == 0); break;
        /* JBE / JNA */
        case 0x06: cond = ((cpu->regs.rflags & X64FLAG_CF) != 0 || (cpu->regs.rflags & X64FLAG_ZF) != 0); break;
        /* JNBE / JA */
        case 0x07: cond = ((cpu->regs.rflags & X64FLAG_CF) == 0 && (cpu->regs.rflags & X64FLAG_ZF) == 0); break;
        /* JS */
        case 0x08: cond = ((cpu->regs.rflags & X64FLAG_SF) != 0); break;
        /* JNS */
        case 0x09: cond = ((cpu->regs.rflags & X64FLAG_SF) == 0); break;
        /* JP / JPE */
        case 0x0A: cond = ((cpu->regs.rflags & X64FLAG_PF) != 0); break;
        /* JNP / JPO */
        case 0x0B: cond = ((cpu->regs.rflags & X64FLAG_PF) == 0); break;
        /* JL / JNGE */
        case 0x0C: cond = (FLAG_ISSET(cpu->regs.rflags, X64FLAG_SF) != FLAG_ISSET(cpu->regs.rflags, X64FLAG_OF)); break;
        /* JNL / JGE */
        case 0x0D: cond = (FLAG_ISSET(cpu->regs.rflags, X64FLAG_SF) == FLAG_ISSET(cpu->regs.rflags, X64FLAG_OF)); break;
        /* JLE / JNG */
        case 0x0E: cond = (FLAG_ISSET(cpu->regs.rflags, X64FLAG_ZF) == 1) || (FLAG_ISSET(cpu->regs.rflags, X64FLAG_SF) != FLAG_ISSET(cpu->regs.rflags, X64FLAG_OF)); break;
        /* JNLE / JG */
        case 0x0F: cond = (FLAG_ISSET(cpu->regs.rflags, X64FLAG_ZF) == 0) && (FLAG_ISSET(cpu->regs.rflags, X64FLAG_SF) == FLAG_ISSET(cpu->regs.rflags, X64FLAG_OF)); break;
    }

    return cond;
}

/** Helper function for LOOPs and REPs ;
 *  @return 1 - if condition is good, 0 - if false
 */
static int x64cpu_loop(struct x64cpu *cpu, int test_zf, int neg_test_zf) {
    int ret = 1;

    /* Decrement CX */
    cpu->regs.rcx -= 1;

    /* Check if CX != 0 */
    if (cpu->regs.rcx == 0) {
        ret = 0;
    }

    /* Check flags */
    if (test_zf) {
        if (neg_test_zf) {
            if ((cpu->regs.rflags & X64FLAG_ZF) != 0) {
                ret = 0;
            }
        }
        else {
            if ((cpu->regs.rflags & X64FLAG_ZF) == 0) {
                ret = 0;
            }
        }
    }

    return ret;
}

/* Add the offset from the specified operand to the current RIP position;
 * the operand is sign extended to 64bit
 */
static void x64cpu_jump_offset(struct x64cpu *cpu, int ope_index) {
    int64_t offset = 0;

    x64cpu_operand_read(cpu, ope_index, (uint8_t*)&offset, cpu->op[ope_index].size);

    switch (cpu->op[ope_index].size) {
        case 1: {
                int8_t tmp;
                x64cpu_operand_read(cpu, ope_index, (uint8_t*)&tmp, 1);
                offset = (int64_t)tmp;
            }
            break;

        case 2: {
                int16_t tmp;
                x64cpu_operand_read(cpu, ope_index, (uint8_t*)&tmp, 2);
                offset = (int64_t)tmp;
            }
            break;

        case 4: {
                int32_t tmp;
                x64cpu_operand_read(cpu, ope_index, (uint8_t*)&tmp, 4);
                offset = (int64_t)tmp;
            }
            break;

        case 8: {
                int64_t tmp;
                x64cpu_operand_read(cpu, ope_index, (uint8_t*)&tmp, 8);
                offset = (int64_t)tmp;
            }
            break;

        default:
            INTERNAL_ERROR();
            break;
    }

    cpu->regs.rip += (int64_t)offset;
}

static void x64cpu_operation_execute_string(struct x64cpu *cpu, enum x64cpu_operation operation, uint8_t opcode) {
    int ptr_increment = 1;

    switch (cpu->op[0].size) {
        case 1: ptr_increment = 1; break;
        case 2: ptr_increment = 2; break;
        case 4: ptr_increment = 4; break;
        case 8: ptr_increment = 8; break;
    }

    if (cpu->regs.rflags & X64FLAG_DF) {
        ptr_increment = -ptr_increment;
    }

    switch (operation) {
        case X64CPU_OP_MOVS: x64cpu_alu(cpu, X64CPU_ALU_MOV); break;
        case X64CPU_OP_CMPS: x64cpu_alu(cpu, X64CPU_ALU_CMP); break;
        case X64CPU_OP_SCAS: x64cpu_alu(cpu, X64CPU_ALU_CMP); break;
        case X64CPU_OP_STOS: x64cpu_alu(cpu, X64CPU_ALU_MOV); break;
        case X64CPU_OP_LODS: x64cpu_alu(cpu, X64CPU_ALU_MOV); break;
        default: break;
    }

    /* Increment pointers (RSI, RDI) ; only if pointer; doesn't increment AX for STOS */
    x64cpu_operand_ptr_increment(cpu, 0, ptr_increment);
    x64cpu_operand_ptr_increment(cpu, 1, ptr_increment);
}

/**
 * Execute the instruction.
 * Must allow recursive call without consequences (see GRP3 calling IMUL, IDIV, ...)
 */
static void x64cpu_operation_execute(struct x64cpu *cpu, enum x64cpu_operation operation, uint8_t opcode) {
    /* Don't allow repeat flags with non-string instructions ; allow with ret because AMD is weird */
    if (cpu->repeat_prefix != 0) {
        switch (operation) {
            case X64CPU_OP_MOVS:
            case X64CPU_OP_STOS:
            case X64CPU_OP_LODS:
                break;

            case X64CPU_OP_CMPS:
            case X64CPU_OP_SCAS:
                /* The repeat prefix for this instruction will also use ZF */
                cpu->repeat_use_zf = 1;
                break;

            case X64CPU_OP_IRET:
            case X64CPU_OP_RETN:
            case X64CPU_OP_RETF:
            case X64CPU_OP_CJMP:
                /* HACK: AMD64 uses repz ret ... should ignore repz here */
                /* HACK: seen for jumps also */
                cpu->repeat_prefix = 0;
                break;

            default:
                x64cpu_exception(cpu, X64CPU_EXCEPTION_UD);
                return;
                break;
        }
    }

    switch (operation) {
        case X64CPU_OP_NOOP:
            /* Noop */
            break;

        case X64CPU_OP_ADD: x64cpu_alu(cpu, X64CPU_ALU_ADD); break;
        case X64CPU_OP_ADC: x64cpu_alu(cpu, X64CPU_ALU_ADC); break;
        case X64CPU_OP_AND: x64cpu_alu(cpu, X64CPU_ALU_AND); break;
        case X64CPU_OP_XOR: x64cpu_alu(cpu, X64CPU_ALU_XOR); break;
        case X64CPU_OP_OR:  x64cpu_alu(cpu, X64CPU_ALU_OR); break;
        case X64CPU_OP_SBB: x64cpu_alu(cpu, X64CPU_ALU_SBB); break;
        case X64CPU_OP_SUB: x64cpu_alu(cpu, X64CPU_ALU_SUB); break;
        case X64CPU_OP_CMP: x64cpu_alu(cpu, X64CPU_ALU_CMP); break;
        case X64CPU_OP_TEST: x64cpu_alu(cpu, X64CPU_ALU_TEST); break;
        case X64CPU_OP_XCHG: x64cpu_alu(cpu, X64CPU_ALU_XCHG); break;

        case X64CPU_OP_NOT: x64cpu_alu(cpu, X64CPU_ALU_NOT); break;
        case X64CPU_OP_NEG: {
                uint64_t tmp = 0;
                x64cpu_operand_read(cpu, 0, (uint8_t*)&tmp, cpu->op[0].size);
                tmp = (0 - tmp);
                x64cpu_operand_write(cpu, 0, (uint8_t*)&tmp, cpu->op[0].size);
            }
            break;

        case X64CPU_OP_MOV: x64cpu_alu(cpu, X64CPU_ALU_MOV); break;

        case X64CPU_OP_LEA: {
                uint64_t addr = x64cpu_operand_get_address(cpu, 1);
                x64cpu_operand_write(cpu, 0, (uint8_t*)&addr, cpu->op[0].size);
            }
            break;

        case X64CPU_OP_MOVSX:
        case X64CPU_OP_MOVSXD:
            x64cpu_operand_extend(cpu, 1, cpu->op[0].size, 1);
            x64cpu_alu(cpu, X64CPU_ALU_MOV);
            break;

        case X64CPU_OP_MOVS:
        case X64CPU_OP_CMPS:
        case X64CPU_OP_SCAS:
        case X64CPU_OP_STOS:
        case X64CPU_OP_LODS:
            x64cpu_operation_execute_string(cpu, operation, opcode);
            break;

        case X64CPU_OP_CMOV:
            if (x64cpu_condition(cpu, opcode)) {
                x64cpu_alu(cpu, X64CPU_ALU_MOV);
            }
            break;

        case X64CPU_OP_PUSH: x64cpu_push(cpu, 0); break;
        case X64CPU_OP_POP: x64cpu_pop(cpu, 0); break;

        case X64CPU_OP_JMP: x64cpu_jump_offset(cpu, 0); break;

        case X64CPU_OP_CJMP:
            if (x64cpu_condition(cpu, opcode)) {
                x64cpu_jump_offset(cpu, 0);
            }
            break;

        case X64CPU_OP_LOOP:
        case X64CPU_OP_LOOPE:
        case X64CPU_OP_LOOPNE: {
                int test_zf = 0, neg_test_zf = 0;

                /* Check flags */
                switch ((int)operation) {
                    case X64CPU_OP_LOOPE: test_zf = 1; break;
                    case X64CPU_OP_LOOPNE: test_zf = 1; neg_test_zf = 1; break;
                }

                /* Jump to offset */
                if (x64cpu_loop(cpu, test_zf, neg_test_zf) == 1) {
                    x64cpu_jump_offset(cpu, 0);
                }
            }
            break;

        case X64CPU_OP_JRCX: {
                uint64_t dummy = 0;

                /* Jump if RCX is 0 ; use an operand because it depends on operand size */
                x64cpu_operand_read(cpu, 1, (uint8_t*)&dummy, 8);

                if (dummy == 0) {
                    x64cpu_jump_offset(cpu, 0);
                }
            }
            break;

        case X64CPU_OP_MUL: x64cpu_alu(cpu, X64CPU_ALU_MUL); break;
        case X64CPU_OP_MUL1: x64cpu_alu(cpu, X64CPU_ALU_MUL1); break;

        case X64CPU_OP_IMUL: x64cpu_alu(cpu, X64CPU_ALU_IMUL); break;
        case X64CPU_OP_IMUL1: x64cpu_alu(cpu, X64CPU_ALU_IMUL1); break;

        case X64CPU_OP_MUL3: {
                uint64_t val = 0;
                x64cpu_operand_read(cpu, 1, (uint8_t*)&val, cpu->op[1].size);
                x64cpu_operand_write(cpu, 0, (uint8_t*)&val, cpu->op[0].size);
                x64cpu_alu(cpu, X64CPU_ALU_MUL);
            }
            break;

        case X64CPU_OP_IMUL3: {
                uint64_t val = 0;
                x64cpu_operand_read(cpu, 1, (uint8_t*)&val, cpu->op[1].size);
                x64cpu_operand_write(cpu, 0, (uint8_t*)&val, cpu->op[0].size);
                x64cpu_alu(cpu, X64CPU_ALU_IMUL);
            }
            break;

        case X64CPU_OP_DIV: x64cpu_alu(cpu, X64CPU_ALU_DIV); break;
        case X64CPU_OP_IDIV: x64cpu_alu(cpu, X64CPU_ALU_IDIV); break;

        case X64CPU_OP_INC:
        case X64CPU_OP_DEC: {
                uint64_t val = 1;
                x64cpu_operand_set_imm(cpu, 1, (uint8_t*)&val, 1);
                if (operation == X64CPU_OP_INC) {
                    x64cpu_alu(cpu, X64CPU_ALU_ADD);
                }
                else {
                    x64cpu_alu(cpu, X64CPU_ALU_SUB);
                }
            }
            break;

        /* Call */
        case X64CPU_OP_CALL: {
                /* Push RIP */
                x64cpu_operand_set_imm(cpu, 3, (uint8_t*)&cpu->regs.rip, 8);
                x64cpu_push(cpu, 3);

                /* Jump to address */
                x64cpu_jump_offset(cpu, 0);
            }
            break;

        /* Call indirect */
        case X64CPU_OP_CALL_I: {
                uint64_t address = 0;

                /* Get address */
                x64cpu_operand_read(cpu, 0, (uint8_t*)&address, cpu->op[0].size);

                /* Push RIP */
                x64cpu_operand_set_imm(cpu, 3, (uint8_t*)&cpu->regs.rip, 8);
                x64cpu_push(cpu, 3);

                /* Jump to address */
                cpu->regs.rip = address;
            }
            break;

        /* Jump indirect */
        case X64CPU_OP_JMP_I: {
                uint64_t address = 0;

                /* Get address */
                x64cpu_operand_read(cpu, 0, (uint8_t*)&address, cpu->op[0].size);

                /* Jump to address */
                cpu->regs.rip = address;
            }
            break;

        /* Return */
        case X64CPU_OP_RETN:
        case X64CPU_OP_RETF: {
                uint64_t return_address = 0;

                /* Pop return address ; 64 bits on 64 */
                x64cpu_operand_set_imm(cpu, 3, (uint8_t*)&return_address, 8);
                x64cpu_pop(cpu, 3);
                x64cpu_operand_read(cpu, 3, (uint8_t*)&return_address, 8);

                // TODO: Return FAR on 64 bit .... POP CS ??? */

                /* Do we have a parameter ? */
                if (cpu->op[0].type > 0) {
                    /* Remove bytes from stack */
                    uint16_t bytes = 0;
                    x64cpu_operand_read(cpu, 0, (uint8_t*)&bytes, 2);

                    cpu->regs.rsp += bytes;
                }

                /* Return */
                cpu->regs.rip = return_address;
            }
            break;

        /* Enter */
        case X64CPU_OP_ENTER: {
                /* Push RBP */
                x64cpu_select_operand_reg(cpu, 3, X64CPU_REG_GP, 0, X64CPU_REGISTER_RBP, 8);
                x64cpu_push(cpu, 3);

                /* Mov RSP, RBP */
                cpu->regs.rbp = cpu->regs.rsp;

                /* Allocate num variables */
                uint16_t num_vars = 0;
                x64cpu_operand_read(cpu, 0, (uint8_t*)&num_vars, 2);

                cpu->regs.rsp -= num_vars;

                // TODO: nested level ??
            }
            break;

        /* Leave */
        case X64CPU_OP_LEAVE: {
                /* Mov RBP, RSP */
                cpu->regs.rsp = cpu->regs.rbp;

                /* Pop RBP */
                x64cpu_select_operand_reg(cpu, 3, X64CPU_REG_GP, 0, X64CPU_REGISTER_RBP, 8);
                x64cpu_pop(cpu, 3);
            }
            break;

        /* INT - Call to interrupt procedure */
        case X64CPU_OP_INT: {
                uint8_t interrupt_number = 0;
                x64cpu_operand_read(cpu, 0, (uint8_t*)&interrupt_number, 1);

#if 0
                /* Push flags */
                x64cpu_select_operand_reg(cpu, 3, X64CPU_REG_F, 0, 0, 8);
                x64cpu_push(cpu, 3);

                /* Clear IF and TF */
                cpu->regs.rflags &= ~(X64FLAG_TF | X64FLAG_IF);
#endif

                /* Interrupts must be intercepted by the client code */
                cpu->interrupt_number = interrupt_number;
                cpu->execution_result = X64CPU_RES_SOFTINT;
                cpu->is_halted = 1; /* Client must resume */
            }
            break;

        /* IRET - Return from interrupt procedure */
#if 0
        case X64CPU_OP_IRET: {
                uint64_t return_address = 0;

                /* Pop flags */
                x64cpu_select_operand_reg(cpu, 3, X64CPU_REG_F, 0, 0, 8);
                x64cpu_pop(cpu, 3);

                /* Pop return address ; 64 bits on 64 */
                x64cpu_operand_set_imm(cpu, 3, (uint8_t*)&return_address, 8);
                x64cpu_pop(cpu, 3);
                x64cpu_operand_read(cpu, 3, (uint8_t*)&return_address, 8);

                // TODO: Return FAR on 64 bit .... POP CS ??? */

                /* Return */
                cpu->regs.rip = return_address;
            }
            break;
#endif

        /* SYSCALL */
        case X64CPU_OP_SYSCALL: {
                /* syscalls must be intercepted by the client code */
                cpu->execution_result = X64CPU_RES_SYSCALL;
            }
            break;

        /* XLAT AL, (DS:rBX + AL) */
        case X64CPU_OP_XLAT: {
                uint64_t address = 0;
                uint8_t al = 0;
                uint8_t addr_size = x64cpu_decode_address_size(cpu);

                x64cpu_select_operand_reg(cpu, 3, X64CPU_REG_GP, 0, X64CPU_REGISTER_RBX, addr_size);
                x64cpu_select_operand_reg(cpu, 4, X64CPU_REG_GP, 0, X64CPU_REGISTER_RAX, 1);

                x64cpu_operand_read(cpu, 4, (uint8_t*)&al, 1);
                x64cpu_operand_read(cpu, 3, (uint8_t*)&address, addr_size);
                // TODO: DS segment on 64 ?? */
                address += al;

                x64cpu_memory_read(cpu, address, (uint8_t*)&al, 1, X64CPU_MEM_ACCESS_READ);
                x64cpu_operand_write(cpu, 4, (uint8_t*)&al, 1);
            }
            break;

        case X64CPU_OP_ROL: x64cpu_alu(cpu, X64CPU_ALU_ROL); break;
        case X64CPU_OP_ROR: x64cpu_alu(cpu, X64CPU_ALU_ROR); break;
        case X64CPU_OP_RCL: x64cpu_alu(cpu, X64CPU_ALU_RCL); break;
        case X64CPU_OP_RCR: x64cpu_alu(cpu, X64CPU_ALU_RCR); break;
        case X64CPU_OP_SHL: x64cpu_alu(cpu, X64CPU_ALU_SHL); break;
        case X64CPU_OP_SHR: x64cpu_alu(cpu, X64CPU_ALU_SHR); break;
        case X64CPU_OP_SAR: x64cpu_alu(cpu, X64CPU_ALU_SAR); break;

        /* CMC - complement carry flag */
        case X64CPU_OP_CMC:
            cpu->regs.rflags ^= X64FLAG_CF;
            break;

        case X64CPU_OP_CLC:
        case X64CPU_OP_STC:
            if (operation == X64CPU_OP_CLC) {
                cpu->regs.rflags &= ~X64FLAG_CF;
            }
            else {
                cpu->regs.rflags |= X64FLAG_CF;
            }
            break;

        case X64CPU_OP_CLI:
        case X64CPU_OP_STI:
            if (operation == X64CPU_OP_CLI) {
                cpu->regs.rflags &= ~X64FLAG_IF;
            }
            else {
                cpu->regs.rflags |= X64FLAG_IF;
            }
            break;

        case X64CPU_OP_CLD:
        case X64CPU_OP_STD:
            if (operation == X64CPU_OP_CLD) {
                cpu->regs.rflags &= ~X64FLAG_DF;
            }
            else {
                cpu->regs.rflags |= X64FLAG_DF;
            }
            break;

        /* cwtl / cltq / cbtw */
        case X64CPU_OP_CONV:
        case X64CPU_OP_CONV2: {
                int reg_size = 0, new_size = 0;

                /* REX.W ; convert dw to qw */
                if (cpu->prefix_flags & X64CPU_PREFIX_REX_W) {
                    reg_size = 4;
                    new_size = 8;
                }
                /* Operand-size prefix; convert b to w */
                else if (cpu->prefix_flags & X64CPU_PREFIX_OP_SIZE) {
                    reg_size = 1;
                    new_size = 2;
                }
                else {
                    reg_size = 2;
                    new_size = 4;
                }

                /* Convert rAX to rAX */
                if (operation == X64CPU_OP_CONV) {
                    x64cpu_select_operand_reg(cpu, 0, X64CPU_REG_GP, 0, X64CPU_REGISTER_RAX, reg_size);
                    x64cpu_operand_extend(cpu, 0, new_size, 1);
                }
                /* Convert to composite RAX.RDX ; aka move sign to RDX */
                else {
                    uint64_t v1 = 0, v2 = 0;

                    x64cpu_select_operand_reg(cpu, 0, X64CPU_REG_GP, 0, X64CPU_REGISTER_RAX, reg_size);
                    x64cpu_select_operand_reg(cpu, 1, X64CPU_REG_GP, 0, X64CPU_REGISTER_RDX, reg_size);

                    x64cpu_operand_read(cpu, 0, (uint8_t*)&v1, new_size);

                    if (new_size == 2) {
                        v2 = (v1 & 0x8000) ? -1 : 0;
                    }
                    else if (new_size == 4) {
                        v2 = (v1 & 0x80000000) ? -1 : 0;
                    }
                    else if (new_size == 8) {
                        v2 = (v1 & 0x8000000000000000) ? -1 : 0;
                    }

                    x64cpu_operand_write(cpu, 1, (uint8_t*)&v2, new_size);
                }
            }
            break;

        case X64CPU_OP_CSET: {
                uint8_t val = x64cpu_condition(cpu, opcode);
                x64cpu_operand_write(cpu, 0, (uint8_t*)&val, 1);
            }
            break;

        case X64CPU_OP_BT: x64cpu_alu(cpu, X64CPU_ALU_BT); break;
        case X64CPU_OP_BTS: x64cpu_alu(cpu, X64CPU_ALU_BTS); break;
        case X64CPU_OP_BSF: x64cpu_alu(cpu, X64CPU_ALU_BSF); break;
        case X64CPU_OP_BSR: x64cpu_alu(cpu, X64CPU_ALU_BSR); break;

        case X64CPU_OP_CMPXCHG: {
                uint64_t src = 0, dst = 0;

                x64cpu_operand_read(cpu, 0, (uint8_t*)&dst, cpu->op[0].size);
                x64cpu_operand_read(cpu, 2, (uint8_t*)&src, cpu->op[2].size);

                x64cpu_alu(cpu, X64CPU_ALU_CMP);

                if ((cpu->regs.rflags & X64FLAG_ZF) != 0) {
                    x64cpu_operand_write(cpu, 0, (uint8_t*)&src, cpu->op[0].size);
                }
                else {
                    x64cpu_operand_write(cpu, 1, (uint8_t*)&dst, cpu->op[1].size);
                }
            }
            break;

        case X64CPU_OP_XADD: {
                uint64_t old_val = 0;

                x64cpu_operand_read(cpu, 0, (uint8_t*)&old_val, cpu->op[0].size);

                x64cpu_alu(cpu, X64CPU_ALU_ADD);

                x64cpu_operand_write(cpu, 1, (uint8_t*)&old_val, cpu->op[1].size);
            }
            break;

        case X64CPU_OP_HLT:
            cpu->is_halted = 1;
            break;

        case X64CPU_OP_RDTSC:
            cpu->regs.rax = (cpu->tsc & 0xffffffff);
            cpu->regs.rdx = (cpu->tsc >> 32);
            break;

        case X64CPU_OP_CPUID:
            switch (cpu->regs.rax) {
                case X64CPU_CPUID_GETVENDORID:
                    cpu->regs.rax = X64CPU_CPUID_INTELBRANDSTRINGEND;
                    cpu->regs.rbx = 0;
                    cpu->regs.rcx = 0;
                    cpu->regs.rdx = 0;
                    memcpy(&cpu->regs.rbx, &cpu->cpuid.vendor_id[0], 4);
                    memcpy(&cpu->regs.rbx, &cpu->cpuid.vendor_id[4], 4);
                    memcpy(&cpu->regs.rbx, &cpu->cpuid.vendor_id[8], 4);
                    break;

                case X64CPU_CPUID_GETFEATURES:
                    cpu->regs.rax = cpu->cpuid.signature;
                    cpu->regs.rdx = cpu->cpuid.features_edx;
                    cpu->regs.rcx = cpu->cpuid.features_ecx;
                    break;

                // TODO: ...

                default:
                    x64cpu_exception(cpu, X64CPU_EXCEPTION_UD);
                    break;
            }
            break;

        case X64CPU_OP_INVALID:
            x64cpu_exception(cpu, X64CPU_EXCEPTION_UD);
            break;

        default:
            fprintf(stderr, "[-] CPU: opcode %02x not implemented\n", opcode);
            x64cpu_exception(cpu, X64CPU_EXCEPTION_UD);
            break;
    }
}

struct x64cpu_fxsave {
    uint16_t    fpu_control;
    uint16_t    fpu_status;
    uint8_t     fpu_tag;
    uint8_t     reserved1;
    uint16_t    fpu_opcode;
    uint64_t    fpu_rip;

    uint64_t    fpu_dip;
    uint32_t    mxcsr;
    uint32_t    mxcsr_mask;

    long double st[8];

    long double xmm[16];

    uint8_t reserved2[96];
};

static int x64cpu_operation_fpu_load_state(struct x64cpu *cpu, struct x64cpu_fxsave *state) {
    int i;

    memset(state, 0, sizeof(*state));

    state->fpu_control = cpu->regs.fpu.control;
    state->fpu_status = cpu->regs.fpu.status;
    state->fpu_tag = 0;
    for (i = 0; i < 8; i++) {
        if (X64CPU_FPU_TAG_GET(cpu, i) != X64CPU_FPU_TAG_EMPTY) {
            state->fpu_tag |= (1 << i);
        }
    }

    memcpy(state->st, cpu->regs.st, sizeof(state->st));

    /* Remove pending exceptions */
    state->fpu_status &= ~(X64CPU_FPU_STATUS_B | X64CPU_FPU_STATUS_ES);

    /* Mask exceptions */
    state->fpu_control |= ((1 << 6) - 1);

    /* Load FPU state */
    asm __volatile__("fxrstor64 (%0)" : : "r" (state) : "memory");

    return 0;
}

static int x64cpu_operation_fpu_save_state(struct x64cpu *cpu, struct x64cpu_fxsave *state) {
    int i;

    /* Save FPU state */
    asm __volatile__("fxsave64 (%0)" : : "r" (state) : "memory");

    /* FPU Control doesn't need to be saved back to CPU */

    /* Save FPU Status */
    cpu->regs.fpu.status = state->fpu_status;

    /* Save tag - TODO: better method ? */
    cpu->regs.fpu.tag = 0;
    for (i = 0; i < 8; i++) {
        if ((state->fpu_tag >> i) == 0) {
            X64CPU_FPU_TAG_SET(cpu, i, X64CPU_FPU_TAG_EMPTY);
        }
    }

    /* Save float registers */
    memcpy(cpu->regs.st, state->st, sizeof(cpu->regs.st));

    // TODO: set back to CPU state

    return 0;
}

#define FPU_ASM_OP(op, op1, type1, size1) {\
    type1 tmp; \
    x64cpu_operand_read(cpu, op1, (uint8_t*)&tmp, size1); \
    __asm__ __volatile__( \
        op " %[in] \n" \
        : \
        : [in] "m" (tmp) \
        : \
    ); \
}

#define FPU_ASM_OP_OUT(op, op1, type1, size1) {\
    type1 tmp; \
    __asm__ __volatile__( \
        op " %0 \n" \
        : \
        : "m" (tmp) \
        : \
    ); \
    x64cpu_operand_write(cpu, op1, (uint8_t*)&tmp, size1); \
}

static void x64cpu_operation_fpu_execute(struct x64cpu *cpu, enum x64cpu_operation operation, uint8_t opcode) {
    struct x64cpu_fxsave fpu_state;

    /* TODO: generate #NM is EM or TS in CR0 is set ; todo later */

    /* Prepare FPU state */
    x64cpu_operation_fpu_load_state(cpu, &fpu_state);

    switch (operation) {
        case X64CPU_OP_FPU_FINIT: // TODO: handle pending non-masked fpu exceptions ???
        case X64CPU_OP_FPU_FNINIT:
            x64cpu_fpu_init(cpu);
            break;

        case X64CPU_OP_FPU_FLD:
            switch (cpu->op[0].size) {
                case 4: FPU_ASM_OP("fld", 0, float, 4); break;
                case 8: FPU_ASM_OP("fld", 0, double, 8); break;
                case 10: FPU_ASM_OP("fld", 0, __float80, 10); break;
            }
            break;

        case X64CPU_OP_FPU_FDIV:
            switch (cpu->op[0].size) {
                case 4: FPU_ASM_OP("fdiv", 0, float, 4); break;
                case 8: FPU_ASM_OP("fdiv", 0, double, 8); break;
                case 10: FPU_ASM_OP("fdiv", 0, __float80, 10); break;
            }
            break;

        case X64CPU_OP_FPU_FSTP:
            switch (cpu->op[0].size) {
                case 4: FPU_ASM_OP_OUT("fstp", 0, float, 4); break;
                case 8: FPU_ASM_OP_OUT("fstp", 0, double, 8); break;
                case 10: FPU_ASM_OP_OUT("fstp", 0, __float80, 10); break;
            }
            break;

        case X64CPU_OP_INVALID:
            x64cpu_exception(cpu, X64CPU_EXCEPTION_UD);
            break;

        default:
            fprintf(stderr, "[-] CPU: opcode %02x not implemented\n", opcode);
            x64cpu_exception(cpu, X64CPU_EXCEPTION_UD);
            break;
    }

    /* Save FPU state */
    x64cpu_operation_fpu_save_state(cpu, &fpu_state);

    /* TODO: check for non-masked fpu exceptions */

    /* TODO: non-control FPU instructions only */
    cpu->regs.fpu.rip = cpu->old_rip;
    cpu->regs.fpu.dip = 0; // ????
    cpu->regs.fpu.opcode = ((opcode & 0x03) << 8) | ((cpu->modrmbyte.full & 0x07));

    return;
}

#define OP_SSE2_B_128(operation) {\
    char out __attribute__((vector_size(16))); \
    char in __attribute__((vector_size(16))); \
    x64cpu_operand_read(cpu, 0, (uint8_t*)&out, 16); \
    x64cpu_operand_read(cpu, 1, (uint8_t*)&in, 16); \
    out = __builtin_ia32_ ## operation ## 128(out, in); \
    x64cpu_operand_write(cpu, 0, (uint8_t*)&out, 16); \
}

#define OP_SSE2_W_128(operation) {\
    short out __attribute__((vector_size(16))); \
    short in __attribute__((vector_size(16))); \
    x64cpu_operand_read(cpu, 0, (uint8_t*)&out, 16); \
    x64cpu_operand_read(cpu, 1, (uint8_t*)&in, 16); \
    out = __builtin_ia32_ ## operation ## 128(out, in); \
    x64cpu_operand_write(cpu, 0, (uint8_t*)&out, 16); \
}

#define OP_SSE2_D_128(operation) {\
    int out __attribute__((vector_size(16))); \
    int in __attribute__((vector_size(16))); \
    x64cpu_operand_read(cpu, 0, (uint8_t*)&out, 16); \
    x64cpu_operand_read(cpu, 1, (uint8_t*)&in, 16); \
    out = __builtin_ia32_ ## operation ## 128(out, in); \
    x64cpu_operand_write(cpu, 0, (uint8_t*)&out, 16); \
}

#define OP_SSE2_Q_128(operation) {\
    long long int out __attribute__((vector_size(16))); \
    long long int in __attribute__((vector_size(16))); \
    x64cpu_operand_read(cpu, 0, (uint8_t*)&out, 16); \
    x64cpu_operand_read(cpu, 1, (uint8_t*)&in, 16); \
    out = __builtin_ia32_ ## operation ## 128(out, in); \
    x64cpu_operand_write(cpu, 0, (uint8_t*)&out, 16); \
}

#define OP_SSE2_TO_REG_128(operation) {\
    char in __attribute__((vector_size(16))); \
    uint64_t reg = 0; \
    x64cpu_operand_read(cpu, 1, (uint8_t*)&in, 16); \
    reg = __builtin_ia32_ ## operation ## 128(in); \
    x64cpu_operand_write(cpu, 0, (uint8_t*)&reg, cpu->op[0].size); \
}

static void x64cpu_operation_sse_execute(struct x64cpu *cpu, enum x64cpu_operation operation, uint8_t opcode) {
    if (!x64cpu_sse_enabled(cpu)) {
        x64cpu_exception(cpu, X64CPU_EXCEPTION_UD);
        return;
    }

    switch (operation) {
        case X64CPU_OP_SSE_MOVD: {
                uint64_t tmp[2] = { 0, 0 };
                x64cpu_operand_read(cpu, 1, (uint8_t*)tmp, cpu->op[1].size);
                tmp[0] &= 0xffffffff;
                tmp[1] = 0x00;
                x64cpu_operand_write(cpu, 0, (uint8_t*)tmp, cpu->op[0].size);
            }
            break;

        case X64CPU_OP_SSE_MOVLPD: {
                uint64_t tmp[2] = { 0, 0 };
                x64cpu_operand_read(cpu, 1, (uint8_t*)tmp, cpu->op[1].size);
                tmp[1] = 0x00;
                x64cpu_operand_write(cpu, 0, (uint8_t*)tmp, cpu->op[0].size);
            }
            break;

        case X64CPU_OP_SSE_MOVHPD: {
                uint64_t tmp[2] = { 0, 0 };

                if (cpu->op[0].type == X64CPU_OPT_MEMORY_ACCESS) {
                    x64cpu_operand_read(cpu, 0, (uint8_t*)&tmp[1], 8);
                    x64cpu_operand_read(cpu, 1, (uint8_t*)&tmp[0], 8);
                    x64cpu_operand_write(cpu, 1, (uint8_t*)&tmp[0], 16);
                }
                else {
                    x64cpu_operand_read(cpu, 0, (uint8_t*)&tmp[0], 16);
                    x64cpu_operand_write(cpu, 1, (uint8_t*)&tmp[1], 8);
                }
            }
            break;

        case X64CPU_OP_SSE_MOVDQA:
        case X64CPU_OP_SSE_MOVDQU: {
                /* Aligned ? */
                if (operation == X64CPU_OP_SSE_MOVDQA) {
                    /* MOVDQA - requires alignment */
                    uint64_t addr = 0;

                    if (cpu->op[0].type == X64CPU_OPT_MEMORY_ACCESS) {
                        addr = x64cpu_operand_get_address(cpu, 0);
                    }
                    else if (cpu->op[1].type == X64CPU_OPT_MEMORY_ACCESS) {
                        addr = x64cpu_operand_get_address(cpu, 1);
                    }

                    if ((addr & 0xF) != 0) {
                        /* Not aligned - GP fault */
                        x64cpu_exception(cpu, X64CPU_EXCEPTION_GP);
                        break;
                    }
                }

                /* MOVDQU */
                uint64_t tmp[2] = { 0, 0 };
                x64cpu_operand_read(cpu, 1, (uint8_t*)tmp, cpu->op[1].size);
                x64cpu_operand_write(cpu, 0, (uint8_t*)tmp, cpu->op[0].size);
            }
            break;

        case X64CPU_OP_SSE_MOVSS:
        case X64CPU_OP_SSE_MOVSD: {
                uint64_t tmp[2] = { 0, 0 };
                int size = 4;
                if (operation == X64CPU_OP_SSE_MOVSD) {
                    size = 8;
                }

                if (cpu->op[1].type == X64CPU_OPT_MEMORY_ACCESS) {
                    x64cpu_operand_read(cpu, 1, (uint8_t*)tmp, size);
                    x64cpu_operand_read(cpu, 0, (uint8_t*)tmp, cpu->op[0].size);
                }
                else {
                    x64cpu_operand_read(cpu, 1, (uint8_t*)tmp, size);
                    x64cpu_operand_read(cpu, 0, (uint8_t*)tmp, size);
                }
            }
            break;

        case X64CPU_OP_SSE_MOVAPS:
        case X64CPU_OP_SSE_MOVAPD: {
                /* requires alignment */
                uint64_t addr = 0;

                if (cpu->op[0].type == X64CPU_OPT_MEMORY_ACCESS) {
                    addr = x64cpu_operand_get_address(cpu, 0);
                }
                else if (cpu->op[1].type == X64CPU_OPT_MEMORY_ACCESS) {
                    addr = x64cpu_operand_get_address(cpu, 1);
                }

                if ((addr & 0xF) != 0) {
                    /* Not aligned - GP fault */
                    x64cpu_exception(cpu, X64CPU_EXCEPTION_GP);
                    break;
                }

                uint64_t tmp[2] = { 0, 0 };
                x64cpu_operand_read(cpu, 1, (uint8_t*)tmp, cpu->op[1].size);
                x64cpu_operand_write(cpu, 0, (uint8_t*)tmp, cpu->op[0].size);
            }
            break;

        case X64CPU_OP_SSE_PUNPCKLBW: OP_SSE2_B_128(punpcklbw); break;

        case X64CPU_OP_SSE_PUNPCKLWD: OP_SSE2_W_128(punpcklwd); break;

        case X64CPU_OP_SSE_PSHUFD: {
                uint32_t out[4], in[4];
                uint8_t order;

                x64cpu_operand_read(cpu, 1, (uint8_t*)in, 16);
                x64cpu_operand_read(cpu, 2, (uint8_t*)&order, 1);

                out[0] = in[((order >> 0) & 0x3)];
                out[1] = in[((order >> 2) & 0x3)];
                out[2] = in[((order >> 4) & 0x3)];
                out[3] = in[((order >> 6) & 0x3)];

                x64cpu_operand_write(cpu, 0, (uint8_t*)out, 16);
            }
            break;

        case X64CPU_OP_SSE_POR: OP_SSE2_Q_128(por); break;

        case X64CPU_OP_SSE_PXOR: OP_SSE2_Q_128(pxor); break;

        case X64CPU_OP_SSE_PSUBB: OP_SSE2_B_128(psubb); break;

        case X64CPU_OP_SSE_PSLLDQ: OP_SSE2_Q_128(psllq); break;

        case X64CPU_OP_SSE_PMOVMSKB: OP_SSE2_TO_REG_128(pmovmskb); break;

        case X64CPU_OP_SSE_PMINUB: OP_SSE2_B_128(pminub); break;

        case X64CPU_OP_SSE_PCMPEQB: OP_SSE2_B_128(pcmpeqb); break;

        default:
            fprintf(stderr, "[-] CPU: opcode %02x not implemented\n", opcode);
            x64cpu_exception(cpu, X64CPU_EXCEPTION_UD);
            break;
    }

    /* Clear any repeat prefix ; it's used for mmx */
    cpu->repeat_prefix = 0;
}

/* Reset instruction decoding state before decoding a new instruction */
static void x64cpu_execution_state_reset(struct x64cpu *cpu) {
    cpu->old_rip = cpu->regs.rip;

    cpu->cpu_exception.code = X64CPU_EXCEPTION_NONE;
    cpu->interrupt_number = -1;

    cpu->prefix_flags = 0;
    memset(&cpu->modrmbyte, 0, sizeof(cpu->modrmbyte));
    memset(&cpu->sibbyte, 0, sizeof(cpu->sibbyte));
    cpu->displacement = 0;
    cpu->op[0].type = X64CPU_OPT_NONE;
    cpu->op[1].type = X64CPU_OPT_NONE;
    cpu->op[2].type = X64CPU_OPT_NONE;
    cpu->op[3].type = X64CPU_OPT_NONE;
    cpu->instr_length = 0;

    /* If instruction is comparative (rep(n)e: CMPS / SCAS) it will set this */
    cpu->repeat_use_zf = 0;
}

/* Decode current instruction */
static int x64cpu_decode(struct x64cpu *cpu) {
    int ret = -1;
    uint8_t opcode;
    enum x64cpu_operation operation = 0x00;

    /* Fetch opcode */
    opcode = x64cpu_fetch8(cpu);
    if (cpu->cpu_exception.code != X64CPU_EXCEPTION_NONE) {
        goto _end;
    }

    /* Check prefixes */ // TODO: prefixes must have an order, blah blah
    while (x64cpu_decode_prefix(cpu, opcode)) {
        opcode = x64cpu_fetch8(cpu);
        if (cpu->cpu_exception.code != X64CPU_EXCEPTION_NONE) {
            goto _end;
        }
    }

    /* Check for extended instructions prefixes */
    if (opcode == 0x0F) {
        /* Read another opcode */
        opcode = x64cpu_fetch8(cpu);
        if (cpu->cpu_exception.code != X64CPU_EXCEPTION_NONE) {
            goto _end;
        }

        operation = x64cpu_decode_opcode_0F_2byte(cpu, opcode);
    }
    else {
        /* 1-byte opcodes */
        operation = x64cpu_decode_opcode_1byte(cpu, opcode);
    }


    cpu->current_operation = operation;
    cpu->current_opcode = opcode;

    /* Success */
    ret = 0;

_end:
    return ret;
}

int x64cpu_execute(struct x64cpu *cpu) {
    if (cpu->is_halted) {
        return 0;
    }

    cpu->execution_result = X64CPU_RES_SUCCESS;

    x64cpu_execution_state_reset(cpu);

    x64cpu_decode(cpu);

    if (cpu->cpu_exception.code != X64CPU_EXCEPTION_NONE) {
        goto _end;
    }

    /* Determine instruction set */
    if (cpu->operation_instruction_set == X64CPU_INSTR_SET_GENERAL) {
        /* Execute operation */
        x64cpu_operation_execute(cpu, cpu->current_operation, cpu->current_opcode);
    }
    else {
        switch (cpu->operation_instruction_set) {
            case X64CPU_INSTR_SET_FPU:
                x64cpu_operation_fpu_execute(cpu, cpu->current_operation, cpu->current_opcode);
                break;

            case X64CPU_INSTR_SET_SSE:
                x64cpu_operation_sse_execute(cpu, cpu->current_operation, cpu->current_opcode);
                break;

            default:
                x64cpu_exception(cpu, X64CPU_EXCEPTION_UD);
                break;
        }
    }

_end:
    cpu->instruction_counter += 1;

    /* Halt on error */
    if (cpu->execution_result != X64CPU_RES_SUCCESS) {
        cpu->is_halted = 1;
        cpu->repeat_prefix = 0; /* Interrupts stop repeating prefix loops */
    }

    /* Check for repeat prefix */
    if (cpu->repeat_prefix != 0x00) {
        int neg_test_zf = (cpu->repeat_prefix == X64CPU_PREFIX_REPEAT_REPNZ) ? 1 : 0;

        if (x64cpu_loop(cpu, cpu->repeat_use_zf, neg_test_zf) != 0) {
            /* Repeat instruction */
            cpu->regs.rip = cpu->repeat_rip;
        }
        else {
            /* When done; clear prefix */
            cpu->repeat_prefix = 0;
        }
    }

    /* Increment TSC by constant value */
    cpu->tsc += 26;

    return cpu->execution_result;
}

int x64cpu_debug_decode_instruction(const struct x64cpu *cpu, int rip_offset, struct x64cpu *state_out, int *length) {
    int i;
    struct x64cpu dummy;
    struct x64cpu *state = &dummy;

    if (state_out != NULL) {
        state = state_out;
    }

    /* Copy current CPU state to the output state */
    memcpy(state, cpu, sizeof(*state));

    state->regs.rip += rip_offset;

    state->execution_result = X64CPU_RES_SUCCESS;

    x64cpu_execution_state_reset(state);

    x64cpu_decode(state);

    /* Compute absolute address for sib operands */
    for (i = 0; i < 4; i++) {
        if (state->op[i].type != X64CPU_OPT_MEMORY_ACCESS) {
            continue;
        }

        if (state->op[i].is_sib != 0) {
            x64cpu_operand_address_sib_to_abs(state, i);
            state->op[i].is_sib = 1;
        }
    }

    if (length != NULL) {
        (*length) = state->regs.rip - state->old_rip;
    }

    return (state->execution_result != X64CPU_RES_EXCEPTION) ? 0 : -1;
}

void x64cpu_reset(struct x64cpu *cpu) {
    /* Reset RIP */
    cpu->regs.rip = 0x00;

    /* Reset flags; exceptions, interrupts */
    cpu->regs.rflags = 0x00;
    cpu->cpu_exception.code = X64CPU_EXCEPTION_NONE;
    cpu->interrupt_number = -1;

    /* Reset internal control flags */
    cpu->repeat_prefix = 0;

    cpu->is_halted = 0;

    /* Reset TSC */
    cpu->tsc = 0;

    /* Reset registers ? */
}

void x64cpu_fpu_init(struct x64cpu *cpu) {
    cpu->regs.fpu.control = X64CPU_FPU_CONTROL_INIT;
    cpu->regs.fpu.status  = 0;
    cpu->regs.fpu.tag     = 0xffff;
    cpu->regs.fpu.dip     = 0;
    cpu->regs.fpu.rip     = 0;
    cpu->regs.fpu.opcode  = 0;
}

struct x64cpu *x64cpu_create(void) {
    struct x64cpu *ret = NULL;

    ret = malloc(sizeof(struct x64cpu));
    memset(ret, 0, sizeof(struct x64cpu));

    x64cpu_init(ret);

    return ret;
}

void x64cpu_init(struct x64cpu *cpu) {
    /* Set default identification */
    strncpy(cpu->cpuid.vendor_id, "GenuineIntel", sizeof(cpu->cpuid.vendor_id));
    cpu->cpuid.signature = 0;
    cpu->cpuid.features_ecx = 0;
    cpu->cpuid.features_edx =
            X64CPU_CPUID_FEAT_EDX_FPU |
            X64CPU_CPUID_FEAT_EDX_TSC |
            X64CPU_CPUID_FEAT_EDX_MSR |
            X64CPU_CPUID_FEAT_EDX_CX8 |
            X64CPU_CPUID_FEAT_EDX_APIC |
            X64CPU_CPUID_FEAT_EDX_CMOV |
            X64CPU_CPUID_FEAT_EDX_ACPI;

    x64cpu_reset(cpu);

    /* Init FPU */
    x64cpu_fpu_init(cpu);
}

void x64cpu_copy(struct x64cpu *dest, struct x64cpu *src) {
    int i;

    memcpy(dest, src, sizeof(struct x64cpu));

    for (i = 0; i < 4; i++) {
        if (dest->op[i].type == X64CPU_OPT_NONE) {
            continue;
        }

        if (dest->op[i].reg != NULL) {
            dest->op[i].reg = ((uint8_t*)dest) + (((uint8_t*)src->op[i].reg) - ((uint8_t*)src));
        }
        if (dest->op[i].base_reg != NULL) {
            dest->op[i].base_reg = ((uint8_t*)dest) + (((uint8_t*)src->op[i].base_reg) - ((uint8_t*)src));
        }
        if (dest->op[i].scaled_reg != NULL) {
            dest->op[i].scaled_reg = ((uint8_t*)dest) + (((uint8_t*)src->op[i].scaled_reg) - ((uint8_t*)src));
        }
    }
}

void x64cpu_destroy(struct x64cpu *cpu) {
    if (!cpu) {
        return;
    }

    free(cpu);
}

#define append(str, ...) (k += snprintf(&ret[k], (ret_len - k - 1), str, ##__VA_ARGS__))
#define appreg(reg) (append("0x%016lx [%9ld]", reg, reg))
#define apprflag(flag, str) { if (cpu->regs.rflags & flag) { k += sprintf(&ret[k], " %s", str); } }

void x64cpu_dump(struct x64cpu *cpu, char *ret, int ret_len) {
    size_t k = 0;

    append("RIP: "); appreg(cpu->regs.rip); append("\n");

    append("RAX: "); appreg(cpu->regs.rax);
    append(" RBX: "); appreg(cpu->regs.rbx);
    append(" RCX: "); appreg(cpu->regs.rcx);
    append(" RDX: "); appreg(cpu->regs.rdx);
    append("\n");

    append("RSP: "); appreg(cpu->regs.rsp);
    append(" RBP: "); appreg(cpu->regs.rbp);
    append(" RSI: "); appreg(cpu->regs.rsi);
    append(" RDI: "); appreg(cpu->regs.rdi);
    append("\n");

    append("RFLAGS: 0x%016lx", cpu->regs.rflags);
    apprflag(X64FLAG_CF, "CF");
    apprflag(X64FLAG_PF, "PF");
    apprflag(X64FLAG_AF, "AF");
    apprflag(X64FLAG_ZF, "ZF");
    apprflag(X64FLAG_SF, "SF");
    apprflag(X64FLAG_SF, "TF");
    apprflag(X64FLAG_SF, "IF");
    apprflag(X64FLAG_DF, "DF");
    apprflag(X64FLAG_OF, "OF");
    apprflag(X64FLAG_ID, "ID");
    append("\n");
}

#define appflag(in, flag, str) { if ((in & flag) == flag) { append("%s ", str); } }

void x64cpu_fpu_dump(struct x64cpu *cpu, char *ret, int ret_len) {
    size_t k = 0;
    int i;
    char *tmp = "";
    int t;
    uint16_t a;
    uint64_t b;
    __float80 c;

    for (i = 7; i >= 0; i--) {
        if (X64CPU_FPU_STACK_TOP_GET(cpu) == i) {
            append("=>");
        }
        else {
            append("  ");
        }

        t = X64CPU_FPU_TAG_GET(cpu, i);
        switch (t) {
            case X64CPU_FPU_TAG_VALID: tmp = "Valid"; break;
            case X64CPU_FPU_TAG_ZERO:  tmp = "Zero"; break;
            case X64CPU_FPU_TAG_SPECIAL: tmp = "Special"; break;
            case X64CPU_FPU_TAG_EMPTY: tmp = "Empty"; break;
        }

        c = cpu->regs.st[i];

        a = *((uint16_t*)(((char*)&c) + 8));
        b = *((uint64_t*)(((char*)&c) + 0));

        append("R%d: %-8s 0x%04x%016lx    %Lf", i, tmp, a, b, c);

        append("\n");
    }

    append("%-21s 0x%04x   ", "Status Word:", cpu->regs.fpu.status);
    appflag(cpu->regs.fpu.status, X64CPU_FPU_STATUS_IE, "IE");
    appflag(cpu->regs.fpu.status, X64CPU_FPU_STATUS_DE, "DE");
    appflag(cpu->regs.fpu.status, X64CPU_FPU_STATUS_ZE, "ZE");
    appflag(cpu->regs.fpu.status, X64CPU_FPU_STATUS_OE, "OE");
    appflag(cpu->regs.fpu.status, X64CPU_FPU_STATUS_UE, "UE");
    appflag(cpu->regs.fpu.status, X64CPU_FPU_STATUS_PE, "PE");
    appflag(cpu->regs.fpu.status, X64CPU_FPU_STATUS_SF, "SF");
    appflag(cpu->regs.fpu.status, X64CPU_FPU_STATUS_ES, "ES");
    appflag(cpu->regs.fpu.status, X64CPU_FPU_STATUS_C0, "C0");
    appflag(cpu->regs.fpu.status, X64CPU_FPU_STATUS_C1, "C1");
    appflag(cpu->regs.fpu.status, X64CPU_FPU_STATUS_C2, "C2");
    appflag(cpu->regs.fpu.status, X64CPU_FPU_STATUS_C3, "C3");
    appflag(cpu->regs.fpu.status, X64CPU_FPU_STATUS_B,  "B");
    append("\n");
    append("%-21s   Top: %d", "", X64CPU_FPU_STACK_TOP_GET(cpu));
    append("\n");

    append("%-21s 0x%04x   ", "Control Word:", cpu->regs.fpu.control);
    appflag(cpu->regs.fpu.control, X64CPU_FPU_CONTROL_IM, "IM");
    appflag(cpu->regs.fpu.control, X64CPU_FPU_CONTROL_DM, "DM");
    appflag(cpu->regs.fpu.control, X64CPU_FPU_CONTROL_ZM, "ZM");
    appflag(cpu->regs.fpu.control, X64CPU_FPU_CONTROL_OM, "OM");
    appflag(cpu->regs.fpu.control, X64CPU_FPU_CONTROL_UM, "UM");
    appflag(cpu->regs.fpu.control, X64CPU_FPU_CONTROL_PM, "PM");
    appflag(cpu->regs.fpu.control, X64CPU_FPU_CONTROL_Y,  "Y");
    append("\n");
    append("%-21s   PC: ", "");
    switch (X64CPU_FPU_PC_GET(cpu)) {
        case X64CPU_FPU_CONTROL_PC_SP: append("Single precision (32-bits)"); break;
        case X64CPU_FPU_CONTROL_PC_RSVD: append("Reserved"); break;
        case X64CPU_FPU_CONTROL_PC_DP: append("Double precision ( ? -bits)"); break;
        case X64CPU_FPU_CONTROL_PC_DE: append("Extended precision (64-bits)"); break;
    }
    append("\n");
    append("%-21s   RC: ", "");
    switch (X64CPU_FPU_RC_GET(cpu)) {
        case X64CPU_FPU_CONTROL_RC_RN: append("Round to nearest"); break;
        case X64CPU_FPU_CONTROL_RC_RD: append("Round down"); break;
        case X64CPU_FPU_CONTROL_RC_RU: append("Round up"); break;
        case X64CPU_FPU_CONTROL_RC_RZ: append("Round toward zero"); break;
    }
    append("\n");

    append("%-21s 0x%04x\n", "Tag Word:", cpu->regs.fpu.tag);
    append("%-21s 0x%016lx\n", "Instruction Pointer:", cpu->regs.fpu.rip);
    append("%-21s 0x%016lx\n", "Operand Pointer:", cpu->regs.fpu.dip);
    append("%-21s 0x%04x\n", "Opcode:", cpu->regs.fpu.opcode);
}

