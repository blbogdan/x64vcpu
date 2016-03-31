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


#ifndef __X64CPU_DISASM_H__
#define __X64CPU_DISASM_H__

#include <stdint.h>

#include "cpu.h"


const char *x64cpu_disasm_register_name(struct x64cpu *cpu, uint8_t *reg_ptr, uint8_t size);

/**
 * Disassemble the specified buffer, printing the output of the first instruction
 * found in the output string buffer. Returns the amount of bytes to advance to the
 * next instruction.
 *
 * @param [in] buffer Pointer to the buffer to disassemble.
 * @param [in] buffer_len The maximum length of the input buffer.
 * @param [in] virtual_rip Used to aid the disassembler, if the "logical"
 *                          address of the opcodes is different than it's
 *                          offset in the buffer.
 *                          ALWAYS USE IT RELATIVE TO THE BEGINNING OF THE
 *                          BUFFER, REGARDLESS OF "offset" PARAMETER.
 * @param [in] offset The offset in the buffer from where to start.
 * @param [out] output Pointer to a buffer where to write the output.
 * @param [in]  output_max_len The maximum length of the output buffer.
 * @param [out] output_state Optional. Write the decoded state of the CPU
 *
 * @return Number of bytes consumed / Number of bytes to the next instruction
 */
uint64_t x64cpu_disasm(uint8_t* buffer, size_t buffer_len, uint64_t virtual_rip,
                          int64_t offset, char *output, size_t output_max_len,
                          struct x64cpu *output_state);

/**
 * Disassemble current CPU instruction.
 *
 * @param [in] cpu The CPU structure.
 * @param [in] rip_offset Offset relative to RIP from where to disassemble.
 * @param [out] output Pointer to a buffer where to write the output.
 * @param [in]  output_max_len The maximum length of the output buffer.
 *
 * @return Number of bytes consumed / Number of bytes to the next instruction
 */
uint64_t x64cpu_disasm_current(struct x64cpu *cpu, int64_t rip_offset,
                                char *output, int output_max_len,
                                struct x64cpu *out_state);

/**
 * Returns whether the specified operand is a static memory pointer
 * (e.g.: immediate memory address, jump/call offset, Effective address based
 * on displacement + %rip).
 *
 * @param [in] cpu The CPU state.
 * @param [in] index The operand index (0-3).
 * @param [out] out_address The address specified by the operand, if any, otherwise
 *                      unset.
 *
 * @return 1 if the operand is a static address pointer, 0 otherwise
 */
int x64cpu_disasm_operand_is_static_ptr(struct x64cpu *cpu, int index, uint64_t *out_address);

#endif /* __X64CPU_DISASM_H__ */

