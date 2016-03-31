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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define INTERNAL_ERROR()    {(*((char*)0)) = 1; }

#define ASSERT(c) {\
    if (!(c)) {\
        fprintf(stderr, "Assertion failed at %s:%d in %s. Condition: " #c "\n", __FILE__, __LINE__, __PRETTY_FUNCTION__);\
        INTERNAL_ERROR();\
    }\
}


struct string {
    char        buffer[1024];
    int         length;
};

static void string_append(struct string *str, const char *fmt, ...) {
    va_list vargs;
    char *buf;
    int max_len;

    buf = &(str->buffer[str->length]);
    max_len = (sizeof(str->buffer) - str->length) - 1;

    va_start(vargs, fmt);
    str->length += vsnprintf(buf, max_len, fmt, vargs);
    va_end(vargs);
}

static const char *reg_name_rip[] = { "%eip8??", "%eip16??", "%eip", "%rip" };
static const char *reg_name_rflags[] = { "%flags8??", "%flags16??", "%eflags", "%rflags" };
static const char *reg_name_rax[] = { "%al", "%ax", "%eax", "%rax" };
static const char *reg_name_ah[] =  { "%ah", "%ah16?", "%ah32?", "%ah64?" };
static const char *reg_name_rbx[] = { "%bl", "%bx", "%ebx", "%rbx" };
static const char *reg_name_bh[] =  { "%bh", "%bh16?", "%bh32?", "%bh64?" };
static const char *reg_name_rcx[] = { "%cl", "%cx", "%ecx", "%rcx" };
static const char *reg_name_ch[] =  { "%ch", "%ch16?", "%ch32?", "%ch64?" };
static const char *reg_name_rdx[] = { "%dl", "%dx", "%edx", "%rdx" };
static const char *reg_name_dh[] =  { "%dh", "%dh16?", "%dh32?", "%dh64?" };
static const char *reg_name_rsp[] = { "%spl", "%sp", "%esp", "%rsp" };
static const char *reg_name_rbp[] = { "%bpl", "%bp", "%ebp", "%rbp" };
static const char *reg_name_rsi[] = { "%sil", "%si", "%esi", "%rsi" };
static const char *reg_name_rdi[] = { "%dil", "%di", "%edi", "%rdi" };
static const char *reg_name_r8[]  = { "%r8b", "%r8w", "%r8d", "%r8" };
static const char *reg_name_r9[]  = { "%r9b", "%r9w", "%r9d", "%r9" };
static const char *reg_name_r10[] = { "%r10b", "%r10w", "%r10d", "%r10" };
static const char *reg_name_r11[] = { "%r11b", "%r11w", "%r11d", "%r11" };
static const char *reg_name_r12[] = { "%r12b", "%r12w", "%r12d", "%r12" };
static const char *reg_name_r13[] = { "%r13b", "%r13w", "%r13d", "%r13" };
static const char *reg_name_r14[] = { "%r14b", "%r14w", "%r14d", "%r14" };
static const char *reg_name_r15[] = { "%r15b", "%r15w", "%r15d", "%r15" };
static const char *reg_name_st0[] = { "%st0b", "%st0w", "%st0d", "%st0" };
static const char *reg_name_st1[] = { "%st1b", "%st1w", "%st1d", "%st1" };
static const char *reg_name_st2[] = { "%st2b", "%st2w", "%st2d", "%st2" };
static const char *reg_name_st3[] = { "%st3b", "%st3w", "%st3d", "%st3" };
static const char *reg_name_st4[] = { "%st4b", "%st4w", "%st4d", "%st4" };
static const char *reg_name_st5[] = { "%st5b", "%st5w", "%st5d", "%st5" };
static const char *reg_name_st6[] = { "%st6b", "%st6w", "%st6d", "%st6" };
static const char *reg_name_st7[] = { "%st7b", "%st7w", "%st7d", "%st7" };
static const char *reg_name_xmm0[] = { "%xmm0b", "%xmm0w", "%xmm0d", "%xmm0" };
static const char *reg_name_xmm1[] = { "%xmm1b", "%xmm1w", "%xmm1d", "%xmm1" };
static const char *reg_name_xmm2[] = { "%xmm2b", "%xmm2w", "%xmm2d", "%xmm2" };
static const char *reg_name_xmm3[] = { "%xmm3b", "%xmm3w", "%xmm3d", "%xmm3" };
static const char *reg_name_xmm4[] = { "%xmm4b", "%xmm4w", "%xmm4d", "%xmm4" };
static const char *reg_name_xmm5[] = { "%xmm5b", "%xmm5w", "%xmm5d", "%xmm5" };
static const char *reg_name_xmm6[] = { "%xmm6b", "%xmm6w", "%xmm6d", "%xmm6" };
static const char *reg_name_xmm7[] = { "%xmm7b", "%xmm7w", "%xmm7d", "%xmm7" };
static const char *reg_name_xmm8[] = { "%xmm8b", "%xmm8w", "%xmm8d", "%xmm8" };
static const char *reg_name_xmm9[] = { "%xmm9b", "%xmm9w", "%xmm9d", "%xmm9" };
static const char *reg_name_xmm10[] = { "%xmm10b", "%xmm10w", "%xmm10d", "%xmm10" };
static const char *reg_name_xmm11[] = { "%xmm11b", "%xmm11w", "%xmm11d", "%xmm11" };
static const char *reg_name_xmm12[] = { "%xmm12b", "%xmm12w", "%xmm12d", "%xmm12" };
static const char *reg_name_xmm13[] = { "%xmm13b", "%xmm13w", "%xmm13d", "%xmm13" };
static const char *reg_name_xmm14[] = { "%xmm14b", "%xmm14w", "%xmm14d", "%xmm14" };
static const char *reg_name_xmm15[] = { "%xmm15b", "%xmm15w", "%xmm15d", "%xmm15" };

const char *x64cpu_disasm_register_name(struct x64cpu *cpu, uint8_t *reg_ptr, uint8_t size) {
    const char **ret = NULL;

    if (reg_ptr == (uint8_t*)&cpu->regs.rip) { ret = reg_name_rip; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.rflags) { ret = reg_name_rflags; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.rax) { ret = reg_name_rax; }
    else if ((reg_ptr + 2) == (uint8_t*)&cpu->regs.rax) { ret = reg_name_ah; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.rbx) { ret = reg_name_rbx; }
    else if ((reg_ptr + 2) == (uint8_t*)&cpu->regs.rbx) { ret = reg_name_bh; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.rcx) { ret = reg_name_rcx; }
    else if ((reg_ptr + 2) == (uint8_t*)&cpu->regs.rcx) { ret = reg_name_ch; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.rdx) { ret = reg_name_rdx; }
    else if ((reg_ptr + 2) == (uint8_t*)&cpu->regs.rdx) { ret = reg_name_dh; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.rsp) { ret = reg_name_rsp; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.rbp) { ret = reg_name_rbp; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.rsi) { ret = reg_name_rsi; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.rdi) { ret = reg_name_rdi; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.r8)  { ret = reg_name_r8; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.r9)  { ret = reg_name_r9; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.r10) { ret = reg_name_r10; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.r11) { ret = reg_name_r11; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.r12) { ret = reg_name_r12; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.r13) { ret = reg_name_r13; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.r14) { ret = reg_name_r14; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.r15) { ret = reg_name_r15; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.st[0]) { ret = reg_name_st0; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.st[1]) { ret = reg_name_st1; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.st[2]) { ret = reg_name_st2; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.st[3]) { ret = reg_name_st3; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.st[4]) { ret = reg_name_st4; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.st[5]) { ret = reg_name_st5; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.st[6]) { ret = reg_name_st6; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.st[7]) { ret = reg_name_st7; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.xmm[0]) { ret = reg_name_xmm0; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.xmm[1]) { ret = reg_name_xmm1; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.xmm[2]) { ret = reg_name_xmm2; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.xmm[3]) { ret = reg_name_xmm3; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.xmm[4]) { ret = reg_name_xmm4; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.xmm[5]) { ret = reg_name_xmm5; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.xmm[6]) { ret = reg_name_xmm6; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.xmm[7]) { ret = reg_name_xmm7; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.xmm[8]) { ret = reg_name_xmm8; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.xmm[9]) { ret = reg_name_xmm9; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.xmm[10]) { ret = reg_name_xmm10; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.xmm[11]) { ret = reg_name_xmm11; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.xmm[12]) { ret = reg_name_xmm12; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.xmm[13]) { ret = reg_name_xmm13; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.xmm[14]) { ret = reg_name_xmm14; }
    else if (reg_ptr == (uint8_t*)&cpu->regs.xmm[15]) { ret = reg_name_xmm15; }

    if (ret == NULL) {
        return "%???";
    }

    switch (size) {
        case 1: return ret[0]; break;
        case 2: return ret[1]; break;
        case 4: return ret[2]; break;
        case 8: return ret[3]; break;
        case 10: return ret[3]; break;
        case 16: return ret[3]; break;
    }

    return "%???";
}

static const char *disasm_operation(struct x64cpu *cpu, enum x64cpu_operation operation) {
    uint8_t opcode = cpu->current_opcode;

    switch (operation) {
        case X64CPU_OP_INVALID:
            return "(bad)";
            break;

        case X64CPU_OP_GROUP:
        case X64CPU_OP_SSE:
        case X64CPU_OP_FPU:
            return "(internal decoder error)";
            break;

        case X64CPU_OP_NOOP: return "noop"; break;

        case X64CPU_OP_ADD: return "add"; break;
        case X64CPU_OP_ADC: return "adc"; break;
        case X64CPU_OP_AND: return "and"; break;
        case X64CPU_OP_XOR: return "xor"; break;
        case X64CPU_OP_OR: return "or"; break;
        case X64CPU_OP_SBB: return "sbb"; break;
        case X64CPU_OP_SUB: return "sub"; break;
        case X64CPU_OP_CMP: return "cmp"; break;
        case X64CPU_OP_TEST: return "test"; break;
        case X64CPU_OP_XCHG: return "xchg"; break;
        case X64CPU_OP_NOT: return "not"; break;
        case X64CPU_OP_NEG: return "neg"; break;

        case X64CPU_OP_MOV: return "mov"; break;
        case X64CPU_OP_LEA: return "lea"; break;

        case X64CPU_OP_CMOV:
            switch ((opcode & 0x0F)) {
                case 0x00: return "cmovo"; break;
                case 0x01: return "cmovno"; break;
                case 0x02: return "cmovb"; break;
                case 0x03: return "cmovnb"; break;
                case 0x04: return "cmovz"; break;
                case 0x05: return "cmovnz"; break;
                case 0x06: return "cmovbe"; break;
                case 0x07: return "cmovnbe"; break;
                case 0x08: return "cmovs"; break;
                case 0x09: return "cmovns"; break;
                case 0x0A: return "cmovp"; break;
                case 0x0B: return "cmovnp"; break;
                case 0x0C: return "cmovl"; break;
                case 0x0D: return "cmovnl"; break;
                case 0x0E: return "cmovng"; break;
                case 0x0F: return "cmovg"; break;
            }
            break;

        case X64CPU_OP_MOVZX: return "movzx"; break;
        case X64CPU_OP_MOVSX: return "movsx"; break;
        case X64CPU_OP_MOVSXD: return "movsxd"; break;

        case X64CPU_OP_PUSH: return "push"; break;
        case X64CPU_OP_POP: return "pop"; break;

        case X64CPU_OP_INC: return "inc"; break;
        case X64CPU_OP_DEC: return "dec"; break;

        case X64CPU_OP_IMUL: return "imul"; break;
        case X64CPU_OP_MUL: return "mul"; break;
        case X64CPU_OP_IDIV: return "idiv"; break;
        case X64CPU_OP_DIV: return "div"; break;

        case X64CPU_OP_MOVS: return "movs"; break;
        case X64CPU_OP_CMPS: return "cmps"; break;
        case X64CPU_OP_STOS: return "stos"; break;
        case X64CPU_OP_LODS: return "lods"; break;
        case X64CPU_OP_SCAS: return "scas"; break;

        case X64CPU_OP_JMP: return "jmp"; break;
        case X64CPU_OP_JMP_I: return "jmp *"; break;
        case X64CPU_OP_JMPF: return "jmpf"; break;
        case X64CPU_OP_JMPF_I: return "jmpf *"; break;
        case X64CPU_OP_CJMP:
            switch ((opcode & 0x0F)) {
                case 0x00: return "jo"; break;
                case 0x01: return "jno"; break;
                case 0x02: return "jb"; break;
                case 0x03: return "jnb"; break;
                case 0x04: return "jz"; break;
                case 0x05: return "jnz"; break;
                case 0x06: return "jbe"; break;
                case 0x07: return "jnbe"; break;
                case 0x08: return "js"; break;
                case 0x09: return "jns"; break;
                case 0x0A: return "jp"; break;
                case 0x0B: return "jnp"; break;
                case 0x0C: return "jl"; break;
                case 0x0D: return "jnl"; break;
                case 0x0E: return "jng"; break;
                case 0x0F: return "jg"; break;
            }
            break;

        case X64CPU_OP_CALL: return "call"; break;
        case X64CPU_OP_CALL_I: return "call *"; break;
        case X64CPU_OP_CALLF_I: return "callf *"; break;
        case X64CPU_OP_IRET: return "iret"; break;
        case X64CPU_OP_RETN: return "retn"; break;
        case X64CPU_OP_RETF: return "retf"; break;

        case X64CPU_OP_ENTER: return "enter"; break;
        case X64CPU_OP_LEAVE: return "leave"; break;

        case X64CPU_OP_INT: return "int"; break;

        case X64CPU_OP_SYSCALL: return "syscall"; break;

        case X64CPU_OP_LOOP: return "loop"; break;
        case X64CPU_OP_LOOPE: return "loope"; break;
        case X64CPU_OP_LOOPNE: return "loopne"; break;
        case X64CPU_OP_JRCX: return "jrcx"; break;

        case X64CPU_OP_IN: return "in"; break;
        case X64CPU_OP_OUT: return "out"; break;
        case X64CPU_OP_INS: return "ins"; break;
        case X64CPU_OP_OUTS: return "outs"; break;

        case X64CPU_OP_CONV:
            if (cpu->prefix_flags & X64CPU_PREFIX_REX_W) {
                return "cltq";
            }
            else if (cpu->prefix_flags & X64CPU_PREFIX_OP_SIZE) {
                return "cbtw";
            }
            else {
                return "cwtl";
            }
            break;
        case X64CPU_OP_CONV2: return "(conv2-todo)"; break;

        case X64CPU_OP_HLT: return "hlt"; break;

        case X64CPU_OP_CMC: return "cmc"; break;

        case X64CPU_OP_CLC: return "clc"; break;
        case X64CPU_OP_STC: return "stc"; break;
        case X64CPU_OP_CLI: return "cli"; break;
        case X64CPU_OP_STI: return "sti"; break;
        case X64CPU_OP_CLD: return "cld"; break;
        case X64CPU_OP_STD: return "std"; break;

        case X64CPU_OP_SAHF: return "sahf"; break;
        case X64CPU_OP_LAHF: return "lahf"; break;

        case X64CPU_OP_XLAT: return "xlat"; break;

        case X64CPU_OP_ROL: return "rol"; break;
        case X64CPU_OP_ROR: return "ror"; break;
        case X64CPU_OP_RCL: return "rcl"; break;
        case X64CPU_OP_RCR: return "rcr"; break;
        case X64CPU_OP_SHL: return "shl"; break;
        case X64CPU_OP_SHR: return "shr"; break;
        case X64CPU_OP_SAR: return "sar"; break;

        case X64CPU_OP_BT: return "bt"; break;
        case X64CPU_OP_BTR: return "btr"; break;
        case X64CPU_OP_BTC: return "btc"; break;
        case X64CPU_OP_BTS: return "bts"; break;
        case X64CPU_OP_BSWAP: return "bswap"; break;
        case X64CPU_OP_BSF: return "bsf"; break;
        case X64CPU_OP_BSR: return "bsr"; break;

        case X64CPU_OP_CSET: return "cset"; break;

        case X64CPU_OP_IMUL3: return "imul"; break;
        case X64CPU_OP_MUL3: return "mul"; break;

        case X64CPU_OP_CMPXCHG: return "cmpxchg"; break;
        case X64CPU_OP_XADD: return "xadd"; break;

        case X64CPU_OP_RDTSC: return "rdtsc"; break;
        case X64CPU_OP_CPUID: return "cpuid"; break;

        case X64CPU_OP_FPU_FADD: return "fadd"; break;
        case X64CPU_OP_FPU_FIADD: return "fiadd"; break;
        case X64CPU_OP_FPU_FMUL: return "fmul"; break;
        case X64CPU_OP_FPU_FIMUL: return "fimul"; break;
        case X64CPU_OP_FPU_FCOM: return "fcom"; break;
        case X64CPU_OP_FPU_FICOM: return "ficom"; break;
        case X64CPU_OP_FPU_FCOMP: return "fcomp"; break;
        case X64CPU_OP_FPU_FICOMP: return "ficomp"; break;
        case X64CPU_OP_FPU_FSUB: return "fsub"; break;
        case X64CPU_OP_FPU_FISUB: return "fisub"; break;
        case X64CPU_OP_FPU_FSUBR: return "fsubr"; break;
        case X64CPU_OP_FPU_FISUBR: return "fisubr"; break;
        case X64CPU_OP_FPU_FDIV: return "fdiv"; break;
        case X64CPU_OP_FPU_FIDIV: return "fidiv"; break;
        case X64CPU_OP_FPU_FDIVR: return "fdivr"; break;
        case X64CPU_OP_FPU_FIDIVR: return "fidivr"; break;
        case X64CPU_OP_FPU_FLD: return "fld"; break;
        case X64CPU_OP_FPU_FILD: return "fild"; break;
        case X64CPU_OP_FPU_FXCH: return "fxch"; break;
        case X64CPU_OP_FPU_FST: return "fst"; break;
        case X64CPU_OP_FPU_FSTP: return "fstp"; break;
        case X64CPU_OP_FPU_FLDENV: return "fldenv"; break;
        case X64CPU_OP_FPU_FSTENV: return "fstenv"; break;
        case X64CPU_OP_FPU_FLDCW: return "fldcw"; break;
        case X64CPU_OP_FPU_FSTCW: return "fstcw"; break;
        case X64CPU_OP_FPU_FIST: return "fist"; break;
        case X64CPU_OP_FPU_FISTP: return "fistp"; break;
        case X64CPU_OP_FPU_FISTTP: return "fisttp"; break;
        case X64CPU_OP_FPU_FCMOVB: return "fcmovb"; break;
        case X64CPU_OP_FPU_FCMOVE: return "fcmove"; break;
        case X64CPU_OP_FPU_FCMOVBE: return "fcmovbe"; break;
        case X64CPU_OP_FPU_FCMOVU: return "fcmovu"; break;
        case X64CPU_OP_FPU_FCMOVNB: return "fcmovnb"; break;
        case X64CPU_OP_FPU_FCMOVNE: return "fcmovne"; break;
        case X64CPU_OP_FPU_FCMOVNBE: return "fcmovnbe"; break;
        case X64CPU_OP_FPU_FCMOVNU: return "fcmovnu"; break;
        case X64CPU_OP_FPU_FUCOMI: return "fucomi"; break;
        case X64CPU_OP_FPU_FCOMI: return "fcomi"; break;
        case X64CPU_OP_FPU_FUCOMPP: return "fucompp"; break;

        case X64CPU_OP_SSE_MOVD: return "movd"; break;
        case X64CPU_OP_SSE_MOVDQA: return "movdqa"; break;
        case X64CPU_OP_SSE_MOVDQU: return "movdqu"; break;
        case X64CPU_OP_SSE_MOVSS: return "movss"; break;
        case X64CPU_OP_SSE_MOVSD: return "movsd"; break;
        case X64CPU_OP_SSE_MOVAPS: return "movaps"; break;
        case X64CPU_OP_SSE_MOVAPD: return "movapd"; break;
        case X64CPU_OP_SSE_MOVLPD: return "movlpd"; break;
        case X64CPU_OP_SSE_MOVHPD: return "movhpd"; break;
        case X64CPU_OP_SSE_PUNPCKLBW: return "punpcklbw"; break;
        case X64CPU_OP_SSE_PUNPCKLWD: return "punpcklwd"; break;
        case X64CPU_OP_SSE_PSHUFD: return "pshufd"; break;
        case X64CPU_OP_SSE_POR: return "por"; break;
        case X64CPU_OP_SSE_PXOR: return "pxor"; break;
        case X64CPU_OP_SSE_PSUBB: return "psubb"; break;
        case X64CPU_OP_SSE_PSLLDQ: return "pslldq"; break;
        case X64CPU_OP_SSE_PMOVMSKB: return "pmovmskb"; break;
        case X64CPU_OP_SSE_PCMPEQB: return "pcmpeqb"; break;
    }

    return "(bad or todo?)";
}

int x64cpu_disasm_operand_is_static_ptr(struct x64cpu *cpu, int index, uint64_t *out_address) {
    int ret = 0;
    struct x64cpu_operand *op = &cpu->op[index];
    uint64_t rip = cpu->regs.rip;
    uint64_t address = 0;

    ASSERT(index >= 0 && index <= 3);

    switch (cpu->current_operation) {
        case X64CPU_OP_JMP:
        case X64CPU_OP_CALL:
        case X64CPU_OP_CJMP:
            if (op->type == X64CPU_OPT_IMMEDIATE) {
                int64_t offset = 0;

                switch (op->size) {
                    case 1: offset = (int8_t)*((uint8_t*)&op->immediate); break;
                    case 2: offset = (int16_t)*((uint16_t*)&op->immediate); break;
                    case 4: offset = (int32_t)*((uint32_t*)&op->immediate); break;
                    case 8: offset = (int64_t)*((uint64_t*)&op->immediate); break;
                }

                address = rip + offset;
                ret = 1;
                goto _end;
            }
            break;
    }

    if (op->type == X64CPU_OPT_MEMORY_ACCESS) {
        if (op->is_sib == 1 && (op->base_reg == (uint8_t*)&cpu->regs.rip)) {
            address = op->address;
            ret = 1;
            goto _end;
        }
    }

_end:
    if (ret == 1) {
        if (out_address) {
            (*out_address) = address;
        }
    }
    return ret;
}

uint64_t x64cpu_disasm_current(struct x64cpu *orig_cpu, int64_t rip_offset, char *output, int output_max_len,
                                struct x64cpu *out_state) {
    struct x64cpu decoded_state;
    int instr_length = 0;
    int rc;
    int i, k;
    int first = 1;
    struct string s_out = { .length = 0 };
    int rel_jump_instr = 0;

    rc = x64cpu_debug_decode_instruction(orig_cpu, rip_offset, &decoded_state, &instr_length);
    if (rc != 0) {
        strncpy(output, "(bad)", output_max_len);
        instr_length = 1;
        goto _end;
    }

    if (decoded_state.prefix_flags & X64CPU_PREFIX_REPEAT_REPZ) {
        string_append(&s_out, "repz: ");
    }
    else if (decoded_state.prefix_flags & X64CPU_PREFIX_REPEAT_REPNZ) {
        string_append(&s_out, "repnz: ");
    }

    if (decoded_state.prefix_flags & X64CPU_PREFIX_LOCK) {
        string_append(&s_out, "lock: ");
    }

    string_append(&s_out, "%-7s ", disasm_operation(&decoded_state, decoded_state.current_operation));

    switch (decoded_state.current_operation) {
        case X64CPU_OP_JMP:
        case X64CPU_OP_CJMP:
        case X64CPU_OP_CALL:
            rel_jump_instr = 1;
            break;
    }

    for (k = 1; k < 5; k++) {
        i = (k % 4);
        struct x64cpu_operand *op = &decoded_state.op[i];

        if (op->type == X64CPU_OPT_NONE) {
            continue;
        }

        if (op->hidden != 0) {
            continue;
        }

        if (first == 0) {
            string_append(&s_out, ",");
        }
        first = 0;

        switch (op->type) {
            case X64CPU_OPT_IMMEDIATE:
                if (rel_jump_instr) {
                    int64_t offset = 0;
                    uint64_t address = 0;

                    switch (op->size) {
                        case 1: offset = (int8_t)*((uint8_t*)&op->immediate); break;
                        case 2: offset = (int16_t)*((uint16_t*)&op->immediate); break;
                        case 4: offset = (int32_t)*((uint32_t*)&op->immediate); break;
                        case 8: offset = (int64_t)*((uint64_t*)&op->immediate); break;
                    }

                    address = decoded_state.regs.rip + offset;
                    string_append(&s_out, "0x%016lx", address);

                    if (offset < 0) {
                        string_append(&s_out, " (-0x%lx)", (0 - offset));
                    }
                    else {
                        string_append(&s_out, " (0x%lx)", offset);
                    }
                }
                else {
                    string_append(&s_out, "$0x%lx", op->immediate);
                }
                break;

            case X64CPU_OPT_REGISTER:
                string_append(&s_out, "%s", x64cpu_disasm_register_name(&decoded_state, op->reg, op->size));
                break;

            case X64CPU_OPT_REGISTER_POINTER:
                string_append(&s_out, "(%s)", x64cpu_disasm_register_name(&decoded_state, op->reg, op->size));
                break;

            case X64CPU_OPT_MEMORY_ACCESS:
                if (decoded_state.prefix_flags & X64CPU_PREFIX_FS) {
                    string_append(&s_out, "fs:");
                }
                else if (decoded_state.prefix_flags & X64CPU_PREFIX_GS) {
                    string_append(&s_out, "gs:");
                }

                if (op->is_sib == 1) {
                    if (op->displacement > 0) {
                        string_append(&s_out, "0x%lx", op->displacement);
                    }
                    else if (op->displacement < 0) {
                        string_append(&s_out, "-0x%lx", (0 - op->displacement));
                    }

                    if (op->base_reg || op->scaled_reg) {
                        string_append(&s_out, "(");
                        if (op->scaled_reg == NULL) {
                            string_append(&s_out, "%s", x64cpu_disasm_register_name(&decoded_state, op->base_reg, 8));
                        }
                        else {
                            if (op->base_reg) {
                                string_append(&s_out, "%s,", x64cpu_disasm_register_name(&decoded_state, op->base_reg, 8));
                            }
                            string_append(&s_out, "%s", x64cpu_disasm_register_name(&decoded_state, op->scaled_reg, 8));
                            if (op->scale > 1) {
                                string_append(&s_out, ",%d", (int)op->scale);
                            }
                        }
                        string_append(&s_out, ")");
                    }
                }
                else {
                    string_append(&s_out, "0x%lx", op->address);
                }
                break;
        }
    }

    string_append(&s_out, "\0");
    strncpy(output, s_out.buffer, output_max_len);

_end:
    if (out_state != NULL) {
        x64cpu_copy(out_state, &decoded_state);
    }
    return instr_length;
}


struct disasm_buffer {
    uint8_t *buffer;
    size_t buffer_len;
    uint64_t virtual_rip;
};

static int buffer_read(struct x64cpu *cpu, void *user_data, uint64_t address, uint8_t *data, uint8_t size,
                            enum x64cpu_mem_access_flags access_flags, uint64_t *fault_addr) {
    struct disasm_buffer *buf = (struct disasm_buffer*)user_data;

    address -= buf->virtual_rip;

    if ((address + size) >= buf->buffer_len) {
        if (fault_addr != 0) {
            (*fault_addr) = address;
        }
        return X64CPU_MEM_ACCESS_PF;
    }

    memcpy(data, &buf->buffer[address], size);

    return X64CPU_MEM_ACCESS_SUCCESS;
}

uint64_t x64cpu_disasm(uint8_t* buffer, size_t buffer_len, uint64_t virtual_rip,
                          int64_t offset, char *output, size_t output_max_len,
                          struct x64cpu *output_state) {
    uint64_t ret = 0;
    struct disasm_buffer buf = { .buffer = buffer, .buffer_len = buffer_len, .virtual_rip = virtual_rip };
    struct x64cpu cpu;

    x64cpu_init(&cpu);

    cpu.user_data = &buf;
    cpu.mem_read = buffer_read;
    cpu.regs.rip = virtual_rip;

    ret = x64cpu_disasm_current(&cpu, offset, output, output_max_len, output_state);

    return ret;
}

