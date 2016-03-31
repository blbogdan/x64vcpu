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


#ifndef __X64CPU_OPCODE_DECODER_H__
#define __X64CPU_OPCODE_DECODER_H__

enum x64cpu_register_set {
    X64CPU_REG_NONE = 0,
    X64CPU_REG_GP,
    X64CPU_REG_GP_H,
    X64CPU_REG_F,
    X64CPU_REG_FPU,
    X64CPU_REG_MM,
    X64CPU_REG_XMM,
    X64CPU_REG_S,
    X64CPU_REG_EEE1,
    X64CPU_REG_EEE2
};

enum x64cpu_registers {
    X64CPU_REGISTER_RAX     = 0x00,
    X64CPU_REGISTER_RCX     = 0x01,
    X64CPU_REGISTER_RDX     = 0x02,
    X64CPU_REGISTER_RBX     = 0x03,
    X64CPU_REGISTER_RSP     = 0x04,
    X64CPU_REGISTER_RBP     = 0x05,
    X64CPU_REGISTER_RSI     = 0x06,
    X64CPU_REGISTER_RDI     = 0x07,

    X64CPU_REGISTER_AH     = 0x04,
    X64CPU_REGISTER_CH     = 0x05,
    X64CPU_REGISTER_DH     = 0x06,
    X64CPU_REGISTER_BH     = 0x07,

    X64CPU_REGISTER_R8     = 0x00,
    X64CPU_REGISTER_R9     = 0x01,
    X64CPU_REGISTER_R10     = 0x02,
    X64CPU_REGISTER_R11     = 0x03,
    X64CPU_REGISTER_R12     = 0x04,
    X64CPU_REGISTER_R13     = 0x05,
    X64CPU_REGISTER_R14     = 0x06,
    X64CPU_REGISTER_R15     = 0x07,
};

enum x64cpu_operation {
    X64CPU_OP_NONE = 0,
    X64CPU_OP_INVALID = 0,
    X64CPU_OP_PREFIX = 0,
    X64CPU_OP_TODO = 0,

    X64CPU_OP_GROUP,
    X64CPU_OP_EGROUP,

    X64CPU_OP_NOOP,

    X64CPU_OP_ADD,
    X64CPU_OP_ADC,
    X64CPU_OP_AND,
    X64CPU_OP_XOR,
    X64CPU_OP_OR,
    X64CPU_OP_SBB,
    X64CPU_OP_SUB,
    X64CPU_OP_CMP,
    X64CPU_OP_TEST,
    X64CPU_OP_XCHG,
    X64CPU_OP_NOT,
    X64CPU_OP_NEG,

    X64CPU_OP_MOV,
    X64CPU_OP_LEA,

    X64CPU_OP_MOVZX,
    X64CPU_OP_MOVSX,
    X64CPU_OP_MOVSXD,

    X64CPU_OP_INC,
    X64CPU_OP_DEC,

    X64CPU_OP_PUSH,
    X64CPU_OP_POP,

    X64CPU_OP_IMUL,
    X64CPU_OP_IMUL1,
    X64CPU_OP_IMUL3,
    X64CPU_OP_MUL,
    X64CPU_OP_MUL1,
    X64CPU_OP_MUL3,
    X64CPU_OP_DIV,
    X64CPU_OP_IDIV,

    X64CPU_OP_MOVS,
    X64CPU_OP_CMPS,
    X64CPU_OP_STOS,
    X64CPU_OP_LODS,
    X64CPU_OP_SCAS,

    X64CPU_OP_JMP,
    X64CPU_OP_JMP_I,
    X64CPU_OP_JMPF,
    X64CPU_OP_JMPF_I,
    X64CPU_OP_CJMP,

    X64CPU_OP_CALL,
    X64CPU_OP_CALL_I,
    X64CPU_OP_CALLF_I,
    X64CPU_OP_IRET,
    X64CPU_OP_RETN,
    X64CPU_OP_RETF,

    X64CPU_OP_ENTER,
    X64CPU_OP_LEAVE,

    X64CPU_OP_INT,

    X64CPU_OP_SYSCALL,

    X64CPU_OP_LOOP,
    X64CPU_OP_LOOPE,
    X64CPU_OP_LOOPNE,
    X64CPU_OP_JRCX,

    X64CPU_OP_IN,
    X64CPU_OP_OUT,
    X64CPU_OP_INS,
    X64CPU_OP_OUTS,

    X64CPU_OP_CONV,
    X64CPU_OP_CONV2,

    X64CPU_OP_HLT,

    X64CPU_OP_CMC,

    X64CPU_OP_CLC,
    X64CPU_OP_STC,
    X64CPU_OP_CLI,
    X64CPU_OP_STI,
    X64CPU_OP_CLD,
    X64CPU_OP_STD,

    X64CPU_OP_SAHF,
    X64CPU_OP_LAHF,

    X64CPU_OP_XLAT,

    X64CPU_OP_ROL,
    X64CPU_OP_ROR,
    X64CPU_OP_RCL,
    X64CPU_OP_RCR,
    X64CPU_OP_SHL,
    X64CPU_OP_SHR,
    X64CPU_OP_SAR,

    X64CPU_OP_CMOV,
    X64CPU_OP_CSET,

    X64CPU_OP_CMPXCHG,
    X64CPU_OP_XADD,

    X64CPU_OP_BT,
    X64CPU_OP_BTS,
    X64CPU_OP_BTR,
    X64CPU_OP_BTC,
    X64CPU_OP_BSWAP,

    X64CPU_OP_BSF,
    X64CPU_OP_BSR,

    X64CPU_OP_CPUID,
    X64CPU_OP_RDTSC,

    /* FPU Instructions Groups */
    X64CPU_OP_FPU,

    /* FPU Instructions */
    X64CPU_OP_FPU_FADD,
    X64CPU_OP_FPU_FIADD,
    X64CPU_OP_FPU_FADDP,
    X64CPU_OP_FPU_FMUL,
    X64CPU_OP_FPU_FMULP,
    X64CPU_OP_FPU_FIMUL,
    X64CPU_OP_FPU_FCOM,
    X64CPU_OP_FPU_FICOM,
    X64CPU_OP_FPU_FCOMP,
    X64CPU_OP_FPU_FCOMPP,
    X64CPU_OP_FPU_FICOMP,
    X64CPU_OP_FPU_FSUB,
    X64CPU_OP_FPU_FSUBP,
    X64CPU_OP_FPU_FSUBR,
    X64CPU_OP_FPU_FSUBRP,
    X64CPU_OP_FPU_FISUB,
    X64CPU_OP_FPU_FISUBR,
    X64CPU_OP_FPU_FDIV,
    X64CPU_OP_FPU_FDIVP,
    X64CPU_OP_FPU_FDIVR,
    X64CPU_OP_FPU_FDIVRP,
    X64CPU_OP_FPU_FIDIV,
    X64CPU_OP_FPU_FIDIVP,
    X64CPU_OP_FPU_FIDIVR,
    X64CPU_OP_FPU_FIDIVRP,
    X64CPU_OP_FPU_FLD,
    X64CPU_OP_FPU_FILD,
    X64CPU_OP_FPU_FXCH,
    X64CPU_OP_FPU_FST,
    X64CPU_OP_FPU_FSTP,

    X64CPU_OP_FPU_FCHS,
    X64CPU_OP_FPU_FABS,
    X64CPU_OP_FPU_FTST,
    X64CPU_OP_FPU_FXAM,

    X64CPU_OP_FPU_FLD1,
    X64CPU_OP_FPU_FLDL2T,
    X64CPU_OP_FPU_FLDL2E,
    X64CPU_OP_FPU_FLDPI,
    X64CPU_OP_FPU_FLDLG2,
    X64CPU_OP_FPU_FLDLN2,
    X64CPU_OP_FPU_FLDZ,

    X64CPU_OP_FPU_F2XM1,
    X64CPU_OP_FPU_FYL2X,
    X64CPU_OP_FPU_FPTAN,
    X64CPU_OP_FPU_FPATAN,
    X64CPU_OP_FPU_FXTRACT,
    X64CPU_OP_FPU_FPREM1,
    X64CPU_OP_FPU_FDECSTP,
    X64CPU_OP_FPU_FINCSTP,

    X64CPU_OP_FPU_FPREM,
    X64CPU_OP_FPU_FYL2XP1,
    X64CPU_OP_FPU_FSQRT,
    X64CPU_OP_FPU_FSINCOS,
    X64CPU_OP_FPU_FRNDINT,
    X64CPU_OP_FPU_FSCALE,
    X64CPU_OP_FPU_FSIN,
    X64CPU_OP_FPU_FCOS,

    X64CPU_OP_FPU_FENI,
    X64CPU_OP_FPU_FDISI,
    X64CPU_OP_FPU_FCLEX,
    X64CPU_OP_FPU_FSETPM,

    X64CPU_OP_FPU_FLDENV,
    X64CPU_OP_FPU_FSTENV,

    X64CPU_OP_FPU_FLDCW,
    X64CPU_OP_FPU_FSTCW,

    X64CPU_OP_FPU_FFREE,
    X64CPU_OP_FPU_FFREEP,

    X64CPU_OP_FPU_FIST,
    X64CPU_OP_FPU_FISTP,
    X64CPU_OP_FPU_FISTTP,

    X64CPU_OP_FPU_FCMOVB,
    X64CPU_OP_FPU_FCMOVE,
    X64CPU_OP_FPU_FCMOVBE,
    X64CPU_OP_FPU_FCMOVU,
    X64CPU_OP_FPU_FCMOVNB,
    X64CPU_OP_FPU_FCMOVNE,
    X64CPU_OP_FPU_FCMOVNBE,
    X64CPU_OP_FPU_FCMOVNU,

    X64CPU_OP_FPU_FUCOM,
    X64CPU_OP_FPU_FUCOMI,
    X64CPU_OP_FPU_FUCOMIP,
    X64CPU_OP_FPU_FCOMI,
    X64CPU_OP_FPU_FCOMIP,
    X64CPU_OP_FPU_FUCOMP,
    X64CPU_OP_FPU_FUCOMPP,

    X64CPU_OP_FPU_FINIT,
    X64CPU_OP_FPU_FNINIT,

    X64CPU_OP_FPU_FRSTOR,
    X64CPU_OP_FPU_FSAVE,
    X64CPU_OP_FPU_FSTSW,

    X64CPU_OP_FPU_FBLD,
    X64CPU_OP_FPU_FBSTP,

    /* SSE Instructions */
    X64CPU_OP_SSE, /* Redirect to mmx and sse instructions definition */

    /* SSE Instructions */
    X64CPU_OP_SSE_MOV,
    X64CPU_OP_SSE_MOVSS,
    X64CPU_OP_SSE_MOVSD,
    X64CPU_OP_SSE_MOVUP,
    X64CPU_OP_SSE_MOVAPS,
    X64CPU_OP_SSE_MOVAPD,
    X64CPU_OP_SSE_MOVLPD,
    X64CPU_OP_SSE_MOVHPD,
    X64CPU_OP_SSE_MOVD,

    X64CPU_OP_SSE_MOVDQA,
    X64CPU_OP_SSE_MOVDQU,

    X64CPU_OP_SSE_PUNPCKLBW,
    X64CPU_OP_SSE_PUNPCKLWD,
    X64CPU_OP_SSE_PSHUFD,
    X64CPU_OP_SSE_POR,
    X64CPU_OP_SSE_PXOR,
    X64CPU_OP_SSE_PSUBB,
    X64CPU_OP_SSE_PSLLDQ,
    X64CPU_OP_SSE_PMOVMSKB,
    X64CPU_OP_SSE_PCMPEQB,
    X64CPU_OP_SSE_PMINUB,

    X64CPU_OP_SSE_GROUP1,

    /* 32-bit only instructions */
    X64CPU_OP_DAA,
    X64CPU_OP_DAS,
    X64CPU_OP_AAA,
    X64CPU_OP_AAM,
    X64CPU_OP_AAD,
    X64CPU_OP_PUSHA,
    X64CPU_OP_POPA,
    X64CPU_OP_BOUND,
    X64CPU_OP_ARPL,
    X64CPU_OP_SETALC,
    X64CPU_OP_LDS,
    X64CPU_OP_LES,
    X64CPU_OP_INTO,
    X64CPU_OP_CALL_FAR,
    X64CPU_OP_JMP_FAR,
    X64CPU_OP_CALL_I_FAR,
    X64CPU_OP_JMP_I_FAR,

};

enum x64cpu_parameter_type {
    X64CPU_PT_NONE = 0,

    X64CPU_PT_1,
    X64CPU_PT_3,

    X64CPU_PT_E,
    X64CPU_PT_G,
    X64CPU_PT_S,
    X64CPU_PT_F,
    X64CPU_PT_M,

    X64CPU_PT_I,
    X64CPU_PT_J,

    X64CPU_PT_O,
    X64CPU_PT_X,
    X64CPU_PT_Y,

    X64CPU_PT_RAX       = 0xA00,
    X64CPU_PT_RCX       = 0xA01,
    X64CPU_PT_RDX       = 0xA02,
    X64CPU_PT_RBX       = 0xA03,
    X64CPU_PT_RSP       = 0xA04,
    X64CPU_PT_RBP       = 0xA05,
    X64CPU_PT_RSI       = 0xA06,
    X64CPU_PT_RDI       = 0xA07,

    X64CPU_PT_RAX_R8    = 0xB00,
    X64CPU_PT_RCX_R9    = 0xB01,
    X64CPU_PT_RDX_R10   = 0xB02,
    X64CPU_PT_RBX_R11   = 0xB03,
    X64CPU_PT_RSP_R12   = 0xB04,
    X64CPU_PT_RBP_R13   = 0xB05,
    X64CPU_PT_RSI_R14   = 0xB06,
    X64CPU_PT_RDI_R15   = 0xB07,

    X64CPU_PT_RAH_R12   = 0xC04,
    X64CPU_PT_RCH_R13   = 0xC05,
    X64CPU_PT_RDH_R14   = 0xC06,
    X64CPU_PT_RBH_R15   = 0xC07,

    X64CPU_PT_RAH       = 0xD04,
    X64CPU_PT_RCH       = 0xD05,
    X64CPU_PT_RDH       = 0xD06,
    X64CPU_PT_RBH       = 0xD07,

    X64CPU_PT_rES        = 0xF00,
    X64CPU_PT_rCS        = 0xF01,
    X64CPU_PT_rSS        = 0xF02,
    X64CPU_PT_rDS        = 0xF03,
    X64CPU_PT_rFS       = 0xF04,
    X64CPU_PT_rGS       = 0xF05,

    X64CPU_PT_ES,   /* FPU */
    X64CPU_PT_EST,  /* FPU */
    X64CPU_PT_ST,   /* FPU */

    X64CPU_PT_U,    /* MMX or XMM ; depends on prefix */
    X64CPU_PT_V,    /* MMX or XMM ; depends on prefix */
    X64CPU_PT_W,    /* MMX or XMM ; depends on prefix */

    X64CPU_PT_A,
};

enum x64cpu_parameter_size {
    X64CPU_PS_NONE = 0,

    X64CPU_PS_b,
    X64CPU_PS_bs,
    X64CPU_PS_bss,

    X64CPU_PS_w,
    X64CPU_PS_d,
    X64CPU_PS_q,

    X64CPU_PS_dqp,

    X64CPU_PS_v,
    X64CPU_PS_vds,
    X64CPU_PS_vs,
    X64CPU_PS_vq,
    X64CPU_PS_vqp,
    X64CPU_PS_vqpMw,
    X64CPU_PS_vMw,

    X64CPU_PS_e, /* FPU - x87 FPU env (14/28 bit) */
    X64CPU_PS_sr, /* FPU - single real (32bit) */
    X64CPU_PS_er, /* FPU - extended real (80bit) */
    X64CPU_PS_dr, /* FPU - double real (64bit) */
    X64CPU_PS_wi, /* FPU - word int (16bit) */
    X64CPU_PS_di, /* FPU - double int (32bit) */
    X64CPU_PS_qi, /* FPU - quad int (64bit) */
    X64CPU_PS_bcd, /* FPU - bcd format (80bit?) */

    X64CPU_PS_dq, /* Double-quad word / 128bit */

    X64CPU_PS_ps, /* SSE - Packed single-precision */
    X64CPU_PS_pd, /* SSE - Packed double-precision */
    X64CPU_PS_ss, /* SSE - Scalar single-precision */
    X64CPU_PS_sd, /* SSE - Scalar double-precision */

    X64CPU_PS_a,
    X64CPU_PS_p,
};

enum x64cpu_prefix_flags {
    X64CPU_PREFIX_NONE               = 0,
    X64CPU_PREFIX_REX_W              = 0x01,
    X64CPU_PREFIX_REX_R              = 0x02,
    X64CPU_PREFIX_REX_X              = 0x04,
    X64CPU_PREFIX_REX_B              = 0x08,
    X64CPU_PREFIX_REX                = 0x10,

    X64CPU_PREFIX_OP_SIZE            = 0x20,
    X64CPU_PREFIX_ADDR_SIZE          = 0x40,

    X64CPU_PREFIX_FS                 = 0x100,
    X64CPU_PREFIX_GS                 = 0x200,

    X64CPU_PREFIX_REPEAT_REPZ        = 0x1000,
    X64CPU_PREFIX_REPEAT_REPNZ       = 0x2000,

    X64CPU_PREFIX_LOCK               = 0x10000,
    X64CPU_PREFIX_FWAIT              = 0x20000,

    X64CPU_PREFIX_NULL               = 0x8000000
};

enum x64cpu_instruction_set {
    X64CPU_INSTR_SET_GENERAL        = 0,
    X64CPU_INSTR_SET_FPU,
    X64CPU_INSTR_SET_SSE,

    X64CPU_INSTR_SET_SSE2 /* TODO: remove this */
};

struct x64cpu_opcode_definition {
    enum x64cpu_operation operation;

    int need_modrmbyte;

    struct {
        enum x64cpu_parameter_type type;
        enum x64cpu_parameter_size size;
        int hide;
    } parameters[4];

    /* If the operation is given by the register bits from the modrmbyte */
    struct x64cpu_opcode_definition *group;

    /* For some FPU operations, they are selected by the r/m byte when mod = 0x11 */
    struct x64cpu_opcode_definition *egroup;

    /* For SSE opcodes, the instruction depends on the 0xF3, 0x66, 0xF2 prefixes */
    /* 0 - no prefix, 1 - 0xF3, 2 - 0x66, 3 - 0xF2 */
    struct x64cpu_opcode_definition *sse_group;
};

struct x64cpu_opcode_definition_fpu {
    /* 0 - modrm specifies memory location ; 1 - ST(i) register */
    struct x64cpu_opcode_definition op[2];
};

extern const struct x64cpu_opcode_definition x64cpu_opcode_def_1byte[256];

extern const struct x64cpu_opcode_definition_fpu x64cpu_opcode_def_fpu_0[8];
extern const struct x64cpu_opcode_definition_fpu x64cpu_opcode_def_fpu_1[8];
extern const struct x64cpu_opcode_definition_fpu x64cpu_opcode_def_fpu_2[8];
extern const struct x64cpu_opcode_definition_fpu x64cpu_opcode_def_fpu_3[8];
extern const struct x64cpu_opcode_definition_fpu x64cpu_opcode_def_fpu_4[8];
extern const struct x64cpu_opcode_definition_fpu x64cpu_opcode_def_fpu_5[8];
extern const struct x64cpu_opcode_definition_fpu x64cpu_opcode_def_fpu_6[8];
extern const struct x64cpu_opcode_definition_fpu x64cpu_opcode_def_fpu_7[8];

extern const struct x64cpu_opcode_definition x64cpu_opcode_def_0F_2byte[256];


/* 32-bit instructions */
extern const struct x64cpu_opcode_definition x64cpu_opcode_32_def_1byte[256];

#endif /* __X64CPU_OPCODE_DECODER_H__ */

