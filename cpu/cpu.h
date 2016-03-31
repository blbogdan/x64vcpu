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


#ifndef __X64CPU_H__
#define __X64CPU_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/* Execution error / status */
enum x64cpu_execution_status {
    X64CPU_RES_SUCCESS = 0,
    X64CPU_RES_SYSCALL,         /*!< syscall instruction was executed */
    X64CPU_RES_SOFTINT,         /*!< soft interrupt */
    X64CPU_RES_EXCEPTION,
};

/* FLAGS */
enum x64cpu_flags {
    X64FLAG_CF      = (1 << 0),
    X64FLAG_PF      = (1 << 2),
    X64FLAG_AF      = (1 << 4),
    X64FLAG_ZF      = (1 << 6),
    X64FLAG_SF      = (1 << 7),
    X64FLAG_OF      = (1 << 11),

    X64FLAG_TF      = (1 << 8),
    X64FLAG_IF      = (1 << 9),

    X64FLAG_DF      = (1 << 10),

    X64FLAG_ID      = (1 << 21),
};

/* CPU Exceptions */
enum x64cpu_exception {
    X64CPU_EXCEPTION_NONE       = -1,

    X64CPU_EXCEPTION_DE         = 0,    /*!< Divide error */
    X64CPU_EXCEPTION_DB         = 1,    /*!< Debug */
    X64CPU_EXCEPTION_BP         = 3,    /*!< INT3 instruction */
    X64CPU_EXCEPTION_UD         = 6,    /*!< Invalid opcode */
    X64CPU_EXCEPTION_GP         = 13,   /*!< General Protection */
    X64CPU_EXCEPTION_PF         = 14,   /*!< Page-Fault */

    X64CPU_EXCEPTION_MF         = 16,   /*!< Floating-Point Error */

    X64CPU_EXCEPTION_LAST
};

/* x87 FPU Status */
enum x64cpu_fpu_status {
    X64CPU_FPU_STATUS_IE        = (1 << 0),    /*!< Invalid operation exception */
    X64CPU_FPU_STATUS_DE        = (1 << 1),    /*!< Denormalized-operand exception */
    X64CPU_FPU_STATUS_ZE        = (1 << 2),    /*!< Zero-divide exception */
    X64CPU_FPU_STATUS_OE        = (1 << 3),    /*!< Overflow exception */
    X64CPU_FPU_STATUS_UE        = (1 << 4),    /*!< Underflow exception */
    X64CPU_FPU_STATUS_PE        = (1 << 5),    /*!< Precision exception */

    X64CPU_FPU_STATUS_SF        = (1 << 6),    /*!< Stack fault */
    X64CPU_FPU_STATUS_ES        = (1 << 7),    /*!< Exception status */
    X64CPU_FPU_STATUS_C0        = (1 << 8),    /*!< Condition code */
    X64CPU_FPU_STATUS_C1        = (1 << 9),    /*!< Condition code */
    X64CPU_FPU_STATUS_C2        = (1 << 10),   /*!< Condition code */

    X64CPU_FPU_STATUS_TOP_MASK  = (7 << 11),   /*!< Top of stack pointer mask */

    X64CPU_FPU_STATUS_C3        = (1 << 14),   /*!< Condition code */
    X64CPU_FPU_STATUS_B         = (1 << 15),   /*!< Floating point unit busy */
};

#define X64CPU_FPU_STACK_TOP_GET(cpu)       (((cpu)->regs.fpu.status & X64CPU_FPU_STATUS_TOP_MASK) >> 11)
#define X64CPU_FPU_STACK_TOP_SET(cpu, x)    \
    { (cpu)->regs.fpu.status = ((cpu)->regs.fpu.status & (~X64CPU_FPU_STATUS_TOP_MASK)) | (((x) & 0x07) << 11); }

/* x87 FPU Control */
enum x64cpu_fpu_control {
    X64CPU_FPU_CONTROL_IM       = (1 << 0),    /*!< Invalid operation exception mask */
    X64CPU_FPU_CONTROL_DM       = (1 << 1),    /*!< Denormalized-operand exception mask */
    X64CPU_FPU_CONTROL_ZM       = (1 << 2),    /*!< Zero-divide exception mask */
    X64CPU_FPU_CONTROL_OM       = (1 << 3),    /*!< Overflow exception mask */
    X64CPU_FPU_CONTROL_UM       = (1 << 4),    /*!< Underflow exception mask */
    X64CPU_FPU_CONTROL_PM       = (1 << 5),    /*!< Precision exception mask */

    X64CPU_FPU_CONTROL_PC_MASK  = (3 << 8),    /*!< Precision control mask */
    X64CPU_FPU_CONTROL_PC_SP    = (0),         /*!< Precision control: single precision */
    X64CPU_FPU_CONTROL_PC_RSVD  = (1),         /*!< Precision control: reserved */
    X64CPU_FPU_CONTROL_PC_DP    = (2),         /*!< Precision control: double precision */
    X64CPU_FPU_CONTROL_PC_DE    = (3),         /*!< Precision control: double extended (default) */

    X64CPU_FPU_CONTROL_RC_MASK  = (3 << 10),   /*!< Rounding control mask */
    X64CPU_FPU_CONTROL_RC_RN    = (0),         /*!< Roudning control: to nearest (default) */
    X64CPU_FPU_CONTROL_RC_RD    = (1),         /*!< Roudning control: down */
    X64CPU_FPU_CONTROL_RC_RU    = (2),         /*!< Roudning control: up */
    X64CPU_FPU_CONTROL_RC_RZ    = (3),         /*!< Roudning control: toward zero */

    X64CPU_FPU_CONTROL_Y        = (1 << 12),   /*!< Infinity bit (obsolete) */
};

#define X64CPU_FPU_PC_GET(cpu)      (((cpu)->regs.fpu.control & X64CPU_FPU_CONTROL_PC_MASK) >> 8)
#define X64CPU_FPU_PC_SET(cpu, x)   \
    { (cpu)->regs.fpu.control = ((cpu)->regs.fpu.control & (~X64CPU_FPU_CONTROL_PC_MASK)) | (((x) & 0x07) << 8); }

#define X64CPU_FPU_RC_GET(cpu)      (((cpu)->regs.fpu.control & X64CPU_FPU_CONTROL_RC_MASK) >> 8)
#define X64CPU_FPU_RC_SET(cpu, x)   \
    { (cpu)->regs.fpu.control = ((cpu)->regs.fpu.control & (~X64CPU_FPU_CONTROL_RC_MASK)) | (((x) & 0x07) << 8); }

#define X64CPU_FPU_CONTROL_INIT     (0x37F)

/* x87 FPU tag word values */
enum x64cpu_fpu_tag {
    X64CPU_FPU_TAG_VALID        = 0,
    X64CPU_FPU_TAG_ZERO         = 1,
    X64CPU_FPU_TAG_SPECIAL      = 2,
    X64CPU_FPU_TAG_EMPTY        = 3
};

#define X64CPU_FPU_TAG_GET(cpu, index)      (((cpu)->regs.fpu.tag & (3 << (index * 2))) >> (index * 2))
#define X64CPU_FPU_TAG_SET(cpu, index, x)   \
    { (cpu)->regs.fpu.tag = ((cpu)->regs.fpu.tag & (~(3 << (index * 2)))) | (((x) & 0x03) << (index * 2)); }

/* CPU ID Functions */
enum x64cpu_cpuid_function {
    X64CPU_CPUID_GETVENDORID = 0,
    X64CPU_CPUID_GETFEATURES,
    X64CPU_CPUID_GETTLB,
    X64CPU_CPUID_GETSERIAL,

    X64CPU_CPUID_INTELEXTENDED      = 0x80000000,
    X64CPU_CPUID_INTELFEATURES,
    X64CPU_CPUID_INTELBRANDSTRING,
    X64CPU_CPUID_INTELBRANDSTRINGMORE,
    X64CPU_CPUID_INTELBRANDSTRINGEND,
};

enum x64cpu_cpuid_features {
    X64CPU_CPUID_FEAT_ECX_SSE3         = 1 << 0, 
    X64CPU_CPUID_FEAT_ECX_PCLMUL       = 1 << 1,
    X64CPU_CPUID_FEAT_ECX_DTES64       = 1 << 2,
    X64CPU_CPUID_FEAT_ECX_MONITOR      = 1 << 3,  
    X64CPU_CPUID_FEAT_ECX_DS_CPL       = 1 << 4,  
    X64CPU_CPUID_FEAT_ECX_VMX          = 1 << 5,  
    X64CPU_CPUID_FEAT_ECX_SMX          = 1 << 6,  
    X64CPU_CPUID_FEAT_ECX_EST          = 1 << 7,  
    X64CPU_CPUID_FEAT_ECX_TM2          = 1 << 8,  
    X64CPU_CPUID_FEAT_ECX_SSSE3        = 1 << 9,  
    X64CPU_CPUID_FEAT_ECX_CID          = 1 << 10,
    X64CPU_CPUID_FEAT_ECX_FMA          = 1 << 12,
    X64CPU_CPUID_FEAT_ECX_CX16         = 1 << 13, 
    X64CPU_CPUID_FEAT_ECX_ETPRD        = 1 << 14, 
    X64CPU_CPUID_FEAT_ECX_PDCM         = 1 << 15, 
    X64CPU_CPUID_FEAT_ECX_DCA          = 1 << 18, 
    X64CPU_CPUID_FEAT_ECX_SSE4_1       = 1 << 19, 
    X64CPU_CPUID_FEAT_ECX_SSE4_2       = 1 << 20, 
    X64CPU_CPUID_FEAT_ECX_x2APIC       = 1 << 21, 
    X64CPU_CPUID_FEAT_ECX_MOVBE        = 1 << 22, 
    X64CPU_CPUID_FEAT_ECX_POPCNT       = 1 << 23, 
    X64CPU_CPUID_FEAT_ECX_AES          = 1 << 25, 
    X64CPU_CPUID_FEAT_ECX_XSAVE        = 1 << 26, 
    X64CPU_CPUID_FEAT_ECX_OSXSAVE      = 1 << 27, 
    X64CPU_CPUID_FEAT_ECX_AVX          = 1 << 28,
 
    X64CPU_CPUID_FEAT_EDX_FPU          = 1 << 0,  
    X64CPU_CPUID_FEAT_EDX_VME          = 1 << 1,  
    X64CPU_CPUID_FEAT_EDX_DE           = 1 << 2,  
    X64CPU_CPUID_FEAT_EDX_PSE          = 1 << 3,  
    X64CPU_CPUID_FEAT_EDX_TSC          = 1 << 4,  
    X64CPU_CPUID_FEAT_EDX_MSR          = 1 << 5,  
    X64CPU_CPUID_FEAT_EDX_PAE          = 1 << 6,  
    X64CPU_CPUID_FEAT_EDX_MCE          = 1 << 7,  
    X64CPU_CPUID_FEAT_EDX_CX8          = 1 << 8,  
    X64CPU_CPUID_FEAT_EDX_APIC         = 1 << 9,  
    X64CPU_CPUID_FEAT_EDX_SEP          = 1 << 11, 
    X64CPU_CPUID_FEAT_EDX_MTRR         = 1 << 12, 
    X64CPU_CPUID_FEAT_EDX_PGE          = 1 << 13, 
    X64CPU_CPUID_FEAT_EDX_MCA          = 1 << 14, 
    X64CPU_CPUID_FEAT_EDX_CMOV         = 1 << 15, 
    X64CPU_CPUID_FEAT_EDX_PAT          = 1 << 16, 
    X64CPU_CPUID_FEAT_EDX_PSE36        = 1 << 17, 
    X64CPU_CPUID_FEAT_EDX_PSN          = 1 << 18, 
    X64CPU_CPUID_FEAT_EDX_CLF          = 1 << 19, 
    X64CPU_CPUID_FEAT_EDX_DTES         = 1 << 21, 
    X64CPU_CPUID_FEAT_EDX_ACPI         = 1 << 22, 
    X64CPU_CPUID_FEAT_EDX_MMX          = 1 << 23, 
    X64CPU_CPUID_FEAT_EDX_FXSR         = 1 << 24, 
    X64CPU_CPUID_FEAT_EDX_SSE          = 1 << 25, 
    X64CPU_CPUID_FEAT_EDX_SSE2         = 1 << 26, 
    X64CPU_CPUID_FEAT_EDX_SS           = 1 << 27, 
    X64CPU_CPUID_FEAT_EDX_HTT          = 1 << 28, 
    X64CPU_CPUID_FEAT_EDX_TM1          = 1 << 29, 
    X64CPU_CPUID_FEAT_EDX_IA64         = 1 << 30,
    X64CPU_CPUID_FEAT_EDX_PBE          = 1 << 31
};

enum x64cpu_mem_access_flags {
    X64CPU_MEM_ACCESS_NONE      = 0,
    X64CPU_MEM_ACCESS_READ,
    X64CPU_MEM_ACCESS_WRITE,
    X64CPU_MEM_ACCESS_EXECUTE
};

enum x64cpu_mem_access_error {
    X64CPU_MEM_ACCESS_SUCCESS   = 0,
    X64CPU_MEM_ACCESS_GP,               /*!< Protection Fault */
    X64CPU_MEM_ACCESS_PF,               /*!< Page Fault - page not in memory */
};

struct x64cpu_regs {
    /* Instruction pointer */
    uint64_t rip;

    /* Flags */
    uint64_t rflags;

    /* General purpose registers */
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rsp, rbp, rsi, rdi;

    /* New registers */
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;

    /* 64-bit media registers / 80-bit floating point registers */
    union {
        double mmx[8];
        __float80 st[8];
    };

    /* x87 FPU environment */
    struct {
        uint16_t control;
        uint16_t status;
        uint16_t tag;
        uint16_t opcode;
        uint64_t rip;
        uint64_t dip;
    } fpu;

    /* 128-bit media registers */
    long double xmm[16];

    /* Segment registers */
    uint16_t cs, ds, es, fs, gs, ss;

    /* FS / GS Segment Table pointers */
    uint64_t fs_ptr;
    uint64_t gs_ptr;
};

struct x64cpu_control_regs {
    /* GDTR is 80 bits long on x64 */
    struct {
        uint16_t s;
        uint64_t o;
    } gdtr;
    
    uint16_t ldtr, idtr, tr;

    /* Control registers */
    uint64_t cr[16];

    /* Debug registers */
    uint64_t dr[16];
};

enum x64cpu_operand_type {
    X64CPU_OPT_NONE = 0,
    X64CPU_OPT_IMMEDIATE,
    X64CPU_OPT_REGISTER,
    X64CPU_OPT_REGISTER_POINTER,
    X64CPU_OPT_MEMORY_ACCESS
};

struct x64cpu;
typedef int (*x64cpu_mem_cb)(struct x64cpu *cpu, void *user_data, uint64_t address, uint8_t* data, uint8_t size,
                        enum x64cpu_mem_access_flags access_flags, uint64_t *fault_addr);

struct x64cpu {
    struct x64cpu_regs regs;
    struct x64cpu_control_regs control_regs;

    struct {
        char        vendor_id[12];
        uint64_t    signature;
        uint64_t    features_edx;
        uint64_t    features_ecx;
    } cpuid;

    uint64_t tsc;

    int is_halted;

    /* Memory I/O */
    void *user_data;
    x64cpu_mem_cb mem_read;
    x64cpu_mem_cb mem_write;


    int execution_result;
    int interrupt_number;       /*!< The number of the software interrupt */
    struct {
        enum x64cpu_exception   code;       /*!< -1 = none */
        uint32_t                error_code; /*!< Error code pushed by exception */
        uint64_t                rip;        /*!< Instruction Pointer */
        uint64_t                address;    /*!< Set if memory access caused exception (CR2 register?) */
        uint8_t                 r_w;
    } cpu_exception;

    uint64_t instruction_counter;

    /* Temporary emulator variables */
    uint64_t old_rip;

    /* Stores the decoded instruction to be executed */
    int prefix_flags;   /* see enum x64cpu_prefix_flags in opcode_decoder.h */
    int current_operation; /* see enum x64cpu_operation in opcode_decoder.h */
    int operation_instruction_set; /* 0 - general purpose, x - SSE2, etc. */
    uint8_t current_opcode;

    const struct x64cpu_opcode_definition *current_op_def;

    struct {
        uint8_t full;
        uint8_t mod;
        uint8_t rm;
        uint8_t reg;
    } modrmbyte;

    struct {
        uint8_t full;
        uint8_t ss;
        uint8_t index;
        uint8_t reg;
    } sibbyte;

    int32_t displacement;   /* temporary */

    struct x64cpu_operand {
        uint8_t type;       /* see enum x64cpu_operand_type */
        union {
            uint64_t immediate;
            uint8_t *reg;
            uint64_t address;
        };
        uint8_t size;
        uint8_t ptr_size;
        uint8_t sign_extend;

        uint8_t is_sib;
        uint8_t *base_reg;
        uint8_t *scaled_reg;
        uint8_t scale;
        int64_t displacement;
        uint64_t segment_offset;

        int hidden;
    } op[4];

    int repeat_prefix;
    int repeat_use_zf;
    uint64_t repeat_rip;

    uint8_t instruction[32]; // for debugging
    uint8_t instr_length;
};

/**
 * Get a human readable name of the exception.
 */
const char *x64cpu_exception_name(enum x64cpu_exception exception);

/**
 * Decodes the instruction pointed by the RIP register, setting the 
 * execution state fields in the struct x64cpu structure, but does not
 * execute the instruction.
 * Use it to inspect the current instruction (operands, pointed address,
 * used registers, etc ...).
 *
 * @param [in] cpu The initial CPU state from which to perform decoding
 * @param [in] rip_offset Add the specified offset to the RIP register
 *                          before decoding
 * @param [out] state_out The output CPU state after decoding.
 * @param [out] length The length in bytes of the decoded instruction
 *                      (amount of bytes consumed reading the opcodes).
 *
 * Example:
 *      struct x64cpu dummy_cpu;
 *      for (i = 0; i < 100; i++) {
 *          rc = x64cpu_debug_decode_instruction(cpu, i, &dummy_cpu, &length);
 *          if (rc == 0) {
 *              // Analyze instruction
 *          }
 *          else {
 *              // Decode error
 *              // Exceptions: GP/PF reading opcodes, UD invalid opcode
 *          }
 *      }
 *
 * @return 0 on success; non-0 if instruction is invalid
 */
int x64cpu_debug_decode_instruction(const struct x64cpu *cpu, int rip_offset,
                                      struct x64cpu *state_out, int *length);

/**
 * Execute ONE instruction pointed by the RIP register and advance the
 * RIP to the next instruction.
 */
int x64cpu_execute(struct x64cpu *cpu);

/**
 * Reset the CPU.
 */
void x64cpu_reset(struct x64cpu *cpu);

/**
 * Echivalent to executing the FNINIT FPU instruction.
 * Use this to prepare the FPU for a userspace program.
 */
void x64cpu_fpu_init(struct x64cpu *cpu);

/**
 * Create a new CPU structure.
 */
struct x64cpu *x64cpu_create(void);

/**
 * Initialize a CPU structure.
 */
void x64cpu_init(struct x64cpu *cpu);

/**
 * Return a duplicate of the specified CPU structure.
 */
void x64cpu_copy(struct x64cpu *dest, struct x64cpu *src);

/**
 * Destroy a CPU structure.
 */
void x64cpu_destroy(struct x64cpu *cpu);


void x64cpu_dump(struct x64cpu *cpu, char *ret, int ret_len);

void x64cpu_fpu_dump(struct x64cpu *cpu, char *ret, int ret_len);

#ifdef __cplusplus
}
#endif

#endif /* __X64CPU_H__ */

