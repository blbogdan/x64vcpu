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

#include "../environment/win/PEFile.h"

extern "C" {
#include "../cpu/cpu.h"
#include "../cpu/opcode_decoder.h"
#include "../cpu/disasm.h"
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include <queue>
#include <map>
#include <set>


struct io_user_data {
    FILE *fd;
};

int io_adapter(PEFile::io_callback_op op, void *user_data, void *buffer, int n) {
    int rc = -1;
    struct io_user_data *ctx = (struct io_user_data*)user_data;
    FILE *fd = ctx->fd;

    if (op == PEFile::IO_CB_OP_READ) {
        rc = fread(buffer, n, 1, fd);
    }
    else if (op == PEFile::IO_CB_OP_SEEK) {
        rc = fseek(fd, n, SEEK_SET);
    }
    else {
        return -1;
    }

    if (rc < 0) {
        rc = -errno;
    }

    return rc;
}

struct disasm_buffer {
    uint8_t *buffer;
    size_t buffer_len;
    uint64_t virtual_rip;
};

static int buffer_read(struct x64cpu *cpu, void *user_data, uint64_t address,
                        uint8_t *data, uint8_t size, 
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

struct disasm_ctx {
    std::map<uint64_t, std::string> lines;
    std::map<uint64_t, std::string> function_names;
    std::queue<uint64_t> starts;
    PEFile *pe;
    struct disasm_buffer code_buf;
};

static bool valid_rip(struct disasm_ctx *ctx, uint64_t rip) {
    if (rip >= ctx->code_buf.virtual_rip) {
        if (rip < (ctx->code_buf.virtual_rip + ctx->code_buf.buffer_len)) {
            return true;
        }
    }
    return false;
}

int disasm(struct disasm_ctx *ctx) {
    std::queue<uint64_t> queue;
    uint64_t start_rip;
    uint64_t len;
    char out[128], tmp[512], extra[128];
    struct x64cpu state;
    int rc;

    memset(&state, 0, sizeof(state));
    state.user_data = &ctx->code_buf;
    state.mem_read = buffer_read;

    start_rip = ctx->starts.front();
    queue.push(start_rip);
    ctx->starts.pop();

    if (ctx->function_names.find(start_rip) == ctx->function_names.end()) {
        snprintf(out, sizeof(out), "_anonymous@%016lx", start_rip);
        ctx->function_names[start_rip] = out;
    }

    while (!queue.empty()) {
        uint64_t rip = queue.front();
        queue.pop();

        if (ctx->lines.find(rip) != ctx->lines.end()) {
            continue;
        }

        if (!valid_rip(ctx, rip)) {
            continue;
        }

        uint64_t branch_address = 0;
        bool is_branch = false;
        extra[0] = '\0';

        state.is_halted = 0;
        state.regs.rip = rip;
        len = x64cpu_disasm_current(&state, 0, out, sizeof(out), NULL);

        rc = x64cpu_debug_decode_instruction(&state, 0, &state, (int*)&len);
        if (rc != 0) {
            snprintf(tmp, sizeof(tmp), "0x%016lx: %s", rip, "(bad)");
            ctx->lines[rip] = tmp;
            continue;
        }

        switch (state.current_operation) {
            case X64CPU_OP_JMP:
            case X64CPU_OP_CALL:
            case X64CPU_OP_CJMP:
                if (state.op[0].type == X64CPU_OPT_IMMEDIATE) {
                    int64_t offset = 0;

                    switch (state.op[0].size) {
                        case 1: offset = (int8_t)*((uint8_t*)&state.op[0].immediate); break;
                        case 2: offset = (int16_t)*((uint16_t*)&state.op[0].immediate); break;
                        case 4: offset = (int32_t)*((uint32_t*)&state.op[0].immediate); break;
                        case 8: offset = (int64_t)*((uint64_t*)&state.op[0].immediate); break;
                    }

                    branch_address = rip + len + offset;
                    if (valid_rip(ctx, branch_address)) {
                        is_branch = true;
                    }

                    std::map<uint64_t, std::string>::iterator itr;
                    itr = ctx->function_names.find(branch_address);
                    if (itr != ctx->function_names.end()) {
                        snprintf(extra, sizeof(extra), "; 0x%016lx <%s>", branch_address, itr->second.c_str());
                    }
                    else {
                        snprintf(extra, sizeof(extra), "; 0x%016lx", branch_address);
                    }
                }
                break;

            case X64CPU_OP_JMP_I:
            case X64CPU_OP_CALL_I:
                if (state.op[0].type == X64CPU_OPT_MEMORY_ACCESS &&
                        state.op[0].is_sib == 1 && (state.op[0].base_reg == (uint8_t*)&state.regs.rip)) {
                    branch_address = (state.op[0].address);// + len;

                    if (valid_rip(ctx, branch_address)) {
                        is_branch = true;
                    }

                    std::map<uint64_t, std::string>::iterator itr;
                    itr = ctx->function_names.find(branch_address);
                    if (itr != ctx->function_names.end()) {
                        snprintf(extra, sizeof(extra), "; 0x%016lx <%s>", branch_address, itr->second.c_str());
                    }
                    else {
                        snprintf(extra, sizeof(extra), "; 0x%016lx", branch_address);
                    }
                }
                break;
        }

        snprintf(tmp, sizeof(tmp), "0x%016lx: %s    %s", rip, out, extra);
        ctx->lines[rip] = tmp;

        switch (state.current_operation) {
            case X64CPU_OP_RETN:
            case X64CPU_OP_RETF:
                break;

            case X64CPU_OP_CALL:
            case X64CPU_OP_CALL_I:
                if (is_branch) {
                    ctx->starts.push(branch_address);
                }
                queue.push(rip + len);
                break;

            case X64CPU_OP_CJMP:
                queue.push(rip + len);
            case X64CPU_OP_JMP:
            case X64CPU_OP_JMP_I:
                if (is_branch) {
                    ctx->starts.push(branch_address);
                }
                break;

            default:
                queue.push(rip + len);
                break;
        }
    }

    return 0;
}

int disasm_output(struct disasm_ctx *ctx) {
    uint64_t next_address = ctx->code_buf.virtual_rip;
    uint64_t len;
    std::map<uint64_t, std::string>::iterator itr;
    std::map<uint64_t, std::string>::iterator itr2;
    char output[64];

    itr = ctx->lines.begin();
    for ( ; itr != ctx->lines.end(); itr++) {
        if (itr->first > next_address) {
            uint64_t start = next_address;
            uint64_t end = itr->first;
            uint64_t i;

            fprintf(stdout, "\tdb \\");
            for (i = start; i < end; i++) {
                if ((i - start) % 16 == 0) {
                    fprintf(stdout, "\n\t\t");
                }
                fprintf(stdout, "%02x ", (int)ctx->code_buf.buffer[i - ctx->code_buf.virtual_rip]);
            }
            fprintf(stdout, "\n");
        }

        len = x64cpu_disasm(&ctx->code_buf.buffer[(itr->first) - ctx->code_buf.virtual_rip], 20,  (itr->first), 0, output, sizeof(output), NULL);

        next_address = (itr->first) + len;

        itr2 = ctx->function_names.find(itr->first);
        if (itr2 != ctx->function_names.end()) {
            fprintf(stdout, "\nFunction %s\n", itr2->second.c_str());
        }

        fprintf(stdout, "\t%s\n", itr->second.c_str());
    }

    return 0;
}

int disassemblePE(PEFile *pe) {
    struct disasm_ctx ctx;
    PESection *text_section = NULL;
    uint8_t *section_data = NULL;
    size_t max_size;
    int i;

    for (i = 0; i < pe->coff_header.number_of_sections; i++) {
        if (strncmp(".text", pe->sections[i].name, sizeof(".text")) == 0) {
            text_section = &pe->sections[i];
            break;
        }
    }

    if (text_section == NULL) {
        fprintf(stderr, "No .text section found.\n");
        return 0;
    }

    max_size = text_section->virtual_size;
    if (text_section->size_of_raw_data > text_section->virtual_size) {
        max_size = text_section->size_of_raw_data;
    }
    section_data = (uint8_t*)calloc(1, max_size);
    memcpy(&section_data[0], text_section->data, text_section->size_of_raw_data);

    ctx.code_buf = (struct disasm_buffer) {
        .buffer = text_section->data,
        .buffer_len = max_size,
        .virtual_rip = text_section->virtual_address
    };

    /* Disassemble entry point */
    if (pe->coff_optional_header.address_of_entry_point != 0) {
        ctx.starts.push(pe->coff_optional_header.address_of_entry_point);
    }

    /* Disassemble exports */
    for (i = 0; i < pe->exports.exports.size(); i++) {
        struct PEFile::PEExportedSymbol exported = pe->exports.exports[i];

        if (!exported.is_forwarder) {
            ctx.starts.push(exported.address);

            PEFile::AddressToName::iterator itr;
            itr = pe->exports.address_to_name.find(exported.address);
            if (itr != pe->exports.address_to_name.end()) {
                ctx.function_names[exported.address] = itr->second;
            }
        }
    }

    ctx.pe = pe;

    while (ctx.starts.size() > 0) {
        disasm(&ctx);
    }

    disasm_output(&ctx);

#if 0
    if (section_data != NULL) {
        free(section_data);
    }
#endif
    return 0;
}

void dumpPE(const char* filename, int disassemble) {
    PEFile *pe = NULL;
    struct io_user_data udata;
    std::string out;

    udata.fd = fopen(filename, "rb");
    if (udata.fd == NULL) {
        fprintf(stderr, "Cannot open %s: %s.\n", filename, strerror(errno));
        return;
    }

    pe = PEFile::loadPE(filename, io_adapter, &udata);

    out = pe->dump();

    fprintf(stdout, "%s\n", out.c_str());

    if (disassemble) {
        disassemblePE(pe);
    }

    if (pe) {
        delete pe;
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage:\n\t%s <filename>\n", argv[0]);
        return 1;
    }

    dumpPE(argv[1], (argc > 2));

    return 0;
}

