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


#include <ncurses.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

extern "C" {
#include "../cpu/disasm.h"
#include "../cpu/opcode_decoder.h"
}
#include "../environment/linux/EnvLinux.h"
#include "../environment/linux/ElfLoader.h"


struct gui_window_pos {
    int x, y;
    int width, height;
};

struct gui_context {
    WINDOW *code;
    struct gui_window_pos code_pos;

    WINDOW *code_log;
    WINDOW *code_log_sub;
    struct gui_window_pos code_log_pos;

    WINDOW *cpu;
    struct gui_window_pos cpu_pos;

    WINDOW *stack;
    struct gui_window_pos stack_pos;

    WINDOW *cmd;
    struct gui_window_pos cmd_pos;

    /* Gui states */
    int memview_memory;
    uint64_t memview_address;

    uint64_t disasm_address;
};

struct debugger {
    struct gui_context gui;

    Environment *env;
    Process *proc;
};


WINDOW* gui_create_window(struct gui_window_pos *pos) {
    WINDOW *ret = NULL;

    ret = newwin(pos->height, pos->width, pos->y, pos->x);
    box(ret, 0, 0);
    wrefresh(ret);

    return ret;
}

int gui_init(struct gui_context *ctx) {
    initscr();

    noecho();
    cbreak();
    keypad(stdscr, TRUE);

    // start_color();

    printw("Test");
    refresh();

    /* Create windows */

    /* Stack window - 20% width */
    {
        ctx->stack_pos.height = LINES;
        ctx->stack_pos.width = 53 + 4;
        ctx->stack_pos.x = (COLS - ctx->stack_pos.width);
        ctx->stack_pos.y = 0;

        ctx->stack = gui_create_window(&ctx->stack_pos);
    }

    /* Cmd window - 20 lines */
    {
        ctx->cmd_pos.height = 20;
        ctx->cmd_pos.width = COLS - ctx->stack_pos.width;
        ctx->cmd_pos.x = 0;
        ctx->cmd_pos.y = LINES - ctx->cmd_pos.height;

        ctx->cmd = gui_create_window(&ctx->cmd_pos);

        wmove(ctx->cmd, 1, 2);

        scrollok(ctx->cmd, TRUE);
    }

    /* CPU window - 5 lines */
    {
        ctx->cpu_pos.height = 7;
        ctx->cpu_pos.width = COLS - ctx->stack_pos.width;
        ctx->cpu_pos.x = 0;
        ctx->cpu_pos.y = (ctx->cmd_pos.y - ctx->cpu_pos.height);

        ctx->cpu = gui_create_window(&ctx->cpu_pos);
    }

    /* Code window */
    {
        ctx->code_pos.height = (LINES - (ctx->cpu_pos.height + ctx->cmd_pos.height));
        ctx->code_pos.width = 118; // COLS - ctx->stack_pos.width;
        ctx->code_pos.x = 0;
        ctx->code_pos.y = 0;

        ctx->code = gui_create_window(&ctx->code_pos);
    }

    /* Code log window */
    {
        ctx->code_log_pos.height = (LINES - (ctx->cpu_pos.height + ctx->cmd_pos.height));
        ctx->code_log_pos.width = COLS - ctx->stack_pos.width - ctx->code_pos.width;
        ctx->code_log_pos.x = 119;
        ctx->code_log_pos.y = 0;

        ctx->code_log = gui_create_window(&ctx->code_log_pos);

        // wmove(ctx->code_log, 1, 2);
        // scrollok(ctx->code_log, TRUE);

        ctx->code_log_sub = derwin(ctx->code_log, ctx->code_log_pos.height - 2, ctx->code_log_pos.width - 2, 1, 1);
        scrollok(ctx->code_log_sub, TRUE);

    }

#if 0
    init_pair(1, COLOR_GREEN, COLOR_BLACK);
    attron(COLOR_PAIR(1));
    wattron(ctx->cmd, COLOR_PAIR(1));
    wattron(ctx->stack, COLOR_PAIR(1));
    wattron(ctx->cpu, COLOR_PAIR(1));
    wattron(ctx->code, COLOR_PAIR(1));
#endif

    return 0;
}

void gui_destroy() {
    endwin();
}

void gui_update_view(struct debugger *dbg) {
    struct gui_context *ctx = &dbg->gui;
    struct x64cpu *cpu = dbg->env->cpu;
    Process *proc = dbg->proc;

    /* Update CPU view */
    {
        char flags_buffer[64] = { 0, };
        size_t flags_k = 0;

        mvwprintw(ctx->cpu, 0, 3, " CPU ");

#define printreg(line, reg_col, name, var) {\
    /* One register print length is 46 */ \
    mvwprintw(ctx->cpu, line, 2 + (46 * reg_col), name ": 0x%016lx [%17ld]  ", (var), (var));\
}

#define appflag(flag, name) { \
    if (((cpu->regs.rflags) & (flag)) != 0) { \
        flags_k += snprintf(&flags_buffer[flags_k], sizeof(flags_buffer) - flags_k, " %s", (name)); \
    } \
}

        printreg(1, 0, "RIP", cpu->regs.rip);

        appflag(X64FLAG_CF, "CF");
        appflag(X64FLAG_PF, "PF");
        appflag(X64FLAG_AF, "AF");
        appflag(X64FLAG_ZF, "ZF");
        appflag(X64FLAG_SF, "SF");
        appflag(X64FLAG_SF, "TF");
        appflag(X64FLAG_SF, "IF");
        appflag(X64FLAG_DF, "DF");
        appflag(X64FLAG_OF, "OF");
        appflag(X64FLAG_ID, "ID");
        mvwprintw(ctx->cpu, 1, 2 + (46 * 1), "RFLAGS: 0x%016lx %-32s  ", cpu->regs.rflags, flags_buffer);

        mvwprintw(ctx->cpu, 1, 2 + (46 * 3), "Instructions executed: %-9ld    ", cpu->instruction_counter);

        printreg(2, 0, "RAX", cpu->regs.rax);
        printreg(2, 1, "RBX", cpu->regs.rbx);
        printreg(2, 2, "RCX", cpu->regs.rcx);
        printreg(2, 3, "RDX", cpu->regs.rdx);

        printreg(3, 0, "RSP", cpu->regs.rsp);
        printreg(3, 1, "RBP", cpu->regs.rbp);
        printreg(3, 2, "RSI", cpu->regs.rsi);
        printreg(3, 3, "RDI", cpu->regs.rdi);

        printreg(4, 0, "R8 ", cpu->regs.r8);
        printreg(4, 1, "R9 ", cpu->regs.r9);
        printreg(4, 2, "R10", cpu->regs.r10);
        printreg(4, 3, "R11", cpu->regs.r11);

        printreg(5, 0, "R12", cpu->regs.r12);
        printreg(5, 1, "R13", cpu->regs.r13);
        printreg(5, 2, "R14", cpu->regs.r14);
        printreg(5, 3, "R15", cpu->regs.r15);

        wrefresh(ctx->cpu);

#undef printreg
#undef appflag
    }

    /* Update code view */
    {
        mvwprintw(ctx->code, 0, 3, " Code ");
        wmove(ctx->code, 1, 2);

        uint8_t membuf[512];
        uint64_t start_addr = cpu->regs.rip, addr, len, i, k;
        int line = 1;
        char output[64], tmp[80], extra[64] = { 0 };

        if (cpu->regs.rip < ctx->disasm_address || cpu->regs.rip > (ctx->disasm_address + 100)) {
            ctx->disasm_address = cpu->regs.rip;
        }

        start_addr = ctx->disasm_address;

        if (x64cpu_vmem_copyfrom(&proc->memory, start_addr, membuf, sizeof(membuf)) < 0) {
            wprintw(ctx->code, "0x%016lx:        <page fault>        \n", start_addr);
        }
        else {
            wattroff(ctx->code, A_BOLD);
            addr = start_addr;
            for (k = 0; k < 512; ) {
                addr = start_addr + k;

                len = x64cpu_disasm((uint8_t*)&membuf[k], 512, addr, 0, output, sizeof(output) - 1, NULL);
                for (i = 0; i < len; i++) {
                    snprintf(&tmp[i * 3], 4, " %02x", (int)membuf[i + k]);
                }

                if (addr == cpu->regs.rip) {
                    wattron(ctx->code, A_BOLD);
                }

                if (cpu->op[0].type == 4) {
                    snprintf(extra, sizeof(extra) - 1, "; 0x%016lx    ", cpu->op[0].address);
                }
                else if (cpu->op[1].type == 4) {
                    snprintf(extra, sizeof(extra) - 1, "; 0x%016lx    ", cpu->op[1].address);
                }
                else {
                    extra[0] = '\0';
                }

                mvwprintw(ctx->code, line, 2, "0x%016lx:  %-36s  %-36s%-40s\n", addr, tmp, output, extra);

                wattroff(ctx->code, A_BOLD);

                k += len;
                line += 1;
                if (line >= (ctx->code_pos.height - 1)) {
                    break;
                }
            }
        }

        wrefresh(ctx->code);
    }

    /* Update stack view */
    {
        mvwprintw(ctx->stack, 0, 3, " Stack / Memory ");
        wmove(ctx->stack, 1, 2);

        int is_stack = 1;
        uint64_t stack_bottom = cpu->regs.rsp + (8 * 100);
        uint64_t stack_top = cpu->regs.rsp;
        uint64_t address, tmp;
        uint64_t highlighted = cpu->regs.rsp;
        uint8_t buffer[8];
        char output[128];
        size_t i, k;
        int rc;
        int line = 1;
        int same = 0, add_delim = 0;

        for (i = 0; i < 100; i++) {
            mvwprintw(ctx->stack, (1 + i), 2, "%54s", " ");
        }
        wmove(ctx->stack, 1, 2);

        if (ctx->memview_memory == 1) {
            is_stack = 0;
            stack_top = ((ctx->memview_address - (8 * 49)) & (~0x07));
            stack_bottom = ((ctx->memview_address + (8 * 49)) & (~0x07));
            highlighted = (ctx->memview_address & (~0x07));
        }
        else if (ctx->memview_memory == 2) {
            uint64_t addr = 0x00;

            if (cpu->op[0].type == 4) {
                addr = cpu->op[0].address;
            }
            else if (cpu->op[1].type == 4) {
                addr = cpu->op[1].address;
            }

            is_stack = 0;
            stack_top = ((addr - (8 * 49)) & (~0x07));
            stack_bottom = ((addr + (8 * 49)) & (~0x07));
            highlighted = (addr & (~0x07));
        }

        {
            for (address = stack_top; address <= stack_bottom; address += 8) {
                rc = x64cpu_vmem_read(&proc->memory, address, buffer, sizeof(buffer),
                                    (enum x64cpu_mem_access_flags)0, NULL);
                if (rc != 0) {
                    if (same == 2) {
                        add_delim = 1;
                        continue;
                    }
                    strncpy(output, "  <page fault>", sizeof(output) - 1);
                    same = 2;
                }
                else {
                    memcpy(&tmp, buffer, sizeof(tmp));
                    if (tmp == 0 && same == 1) {
                        add_delim = 1;
                        continue;
                    }
                    k = 0;
                    for (i = 0; i < 8; i++) {
                        k += snprintf(&output[k], sizeof(output) - k, " %02x", buffer[i]);
                    }
                    k += snprintf(&output[k], sizeof(output) - k, "  ");
                    for (i = 0; i < 8; i++) {
                        if (buffer[i] >= 32 && buffer[i] <= 127) {
                            k += snprintf(&output[k], sizeof(output) - k, "%c", buffer[i]);
                        }
                        else {
                            k += snprintf(&output[k], sizeof(output) - k, ".");
                        }
                    }
                    if (tmp == 0) {
                        same = 1;
                    }
                    else {
                        same = 0;
                    }
                }
                if (add_delim) {
                    mvwprintw(ctx->stack, line, 2, "    ....                           ");
                    line += 1;
                    add_delim = 0;
                }
                if (highlighted == address) {
                    wattron(ctx->stack, A_BOLD);
                }
                mvwprintw(ctx->stack, line, 2, "%016lx: %s", address, output);
                wattroff(ctx->stack, A_BOLD);
                line += 1;
                if (line >= (ctx->stack_pos.height - 1)) {
                    break;
                }
            }
        }

        wrefresh(ctx->stack);
    }
}

int gui_log(void *log_user_data, const char *fmt, ...) {
    struct gui_context *ctx = (struct gui_context*)log_user_data;
    int rc, i;
    int x, y;
    char buffer[8192];

    va_list va_args;
    va_start(va_args, fmt);
    rc = vsnprintf(buffer, sizeof(buffer) - 1, fmt, va_args);
    va_end(va_args);

    for (i = 0; i < rc; i++) {
        waddch(ctx->cmd, buffer[i]);
        if (buffer[i] == '\n') {
            getyx(ctx->cmd, y, x);
            wmove(ctx->cmd, y, 2);
        }
    }

    wrefresh(ctx->cmd);

    return rc;
}

#define append(str, ...) (k += snprintf(&buffer[k], (size_of_buffer - k), str, ##__VA_ARGS__))

static int disasm_current(struct debugger *dbg, char *buffer, int size_of_buffer) {
    int k = 0;

    struct gui_context *ctx = &dbg->gui;
    struct x64cpu dummy_cpu;
    struct x64cpu *cpu = &dummy_cpu;
    Process *proc = dbg->proc;

    char output[64];
    uint64_t len, ret;
    int i;
    uint64_t rip = cpu->regs.rip;

    len = x64cpu_disasm_current(dbg->env->cpu, 0, output, sizeof(output) - 1, cpu);

    append("0x%016lx: %-36s\n", rip, output);

    append("%-16s", "");

    if (cpu->execution_result == X64CPU_RES_SUCCESS) {
    for (i = 0; i < 4; i++) {
        if (cpu->op[i].type == 2) {
            append("%d:[%016lx]  ", i, *((uint64_t*)cpu->op[i].reg));
        }
        else if (cpu->op[i].type == 3) {
            uint64_t addr = *((uint64_t*)cpu->op[i].reg);
            uint64_t tmp = 0;
            ret = x64cpu_vmem_read(&proc->memory, addr, (uint8_t*)&tmp, 8,
                                    (enum x64cpu_mem_access_flags)0, NULL);
            if (ret == 0) {
                append("%d:[%016lx] <%016lx>  ", i, addr, tmp);
            }
            else {
                append("%d:[%016lx] <pfault>  ", i, addr);
            }
        }
        else if (cpu->op[i].type == 4) {
            uint64_t base = (cpu->op[i].base_reg) ? (*((uint64_t*)cpu->op[i].base_reg)) : 0;
            uint64_t scaled = (cpu->op[i].scaled_reg) ? (*((uint64_t*)cpu->op[i].scaled_reg)) : 0;
            uint8_t scale = cpu->op[i].scale;
            int64_t displacement = cpu->op[i].displacement;
            uint64_t segment_offset = cpu->op[i].segment_offset;
            uint64_t addr = cpu->op[i].address;
            uint64_t tmp = 0;

            if (displacement < 0) {
                append("%d: [-%lx +", i, (0 - displacement));
            }
            else {
                append("%d: [%lx +", i, displacement);
            }
            append("%lx + %lx * %d : %lx][0x%016lx] ", base, scaled, (int)scale, segment_offset, addr);

            if (x64cpu_vmem_read(&proc->memory, addr, (uint8_t*)&tmp, 8, 
                                    (enum x64cpu_mem_access_flags)0, NULL) == 0) {
                append(" <%lx>", tmp);
            }
            else {
                append(" <pfault>");
            }
            append("  ");
        }
    }
    }
    append("\n");

    return k;
}

int gui_code_log(struct debugger *dbg, int flush) {
    struct gui_context *ctx = &dbg->gui;
    WINDOW *win = ctx->code_log_sub;
    static char buffer[32768];
    static int k = 0;

    if (flush != 2) {
        k += disasm_current(dbg, &buffer[k], sizeof(buffer) - k - 1);
    }

    if ((flush && k > 0) || (k > 8192)) {
        wprintw(win, "%s\n", buffer);
        k = 0;
        wrefresh(win);
    }

    return 0;
}

int load_file(const char* filename, Environment *env, int argc, char **argv, char **envp,
                    Process **out_proc) {
    int ret = -1;
    int fd = -1;
    int _argc = 1;
    const char *_argv[] = {
        filename,
        NULL
    };
    Process *proc = NULL;
    Thread *th = NULL;
    struct elf_file *elf = NULL;
    int i;

    ret = ElfLoader::loadElfFromFile(filename, &elf);
    if (ret < 0) {
        fprintf(stderr, "Could not load ELF file: %s: %d: %s\n", filename, -ret, strerror(-ret));
        goto _end;
    }

    proc = env->createProcess();
    for (i = 0; i < _argc; i++) {
        proc->arguments.push_back(_argv[i]);
    }
    {
        char **env = envp;
        char *e = NULL;

        while ((e = (*env++)) != NULL) {
            char *r = strchr(e, '=');
            char *n;
            if (!r) {
                continue;
            }

            n = strndupa(e, (r - e));
            r++;

            if (strcmp(n, "_") == 0) {
                proc->environment_variables["_"] = filename;
            }
            else {
                proc->environment_variables[n] = r;
            }
        }
    }

    ret = ElfLoader::loadProcess(proc, elf, filename, &th);
    if (ret < 0) {
        fprintf(stderr, "[*] Error creating process: %d.\n", ret);
        goto _end;
    }

    env->setCurrentThread(th);

    proc->state = Process::RUNNING;

    /* Success */
    ret = 0;
    (*out_proc) = proc;

_end:
    if (elf) {
        // elf_destroy(elf);
    }
    return ret;
}

void debugger_main(struct debugger *dbg) {
    Environment *env = dbg->env;
    struct gui_context *ctx = &dbg->gui;
    int running = 1;
    int stepping = 1;
    int rc;
    int cmd;
    uint64_t breakpoint_rip = 0;
    uint64_t next_rip = 0;
    int instr_length;
	int start_logging = 1;
    struct x64cpu *cpu = env->cpu;
    struct x64cpu dummy_cpu;

    while (running) {
        x64cpu_debug_decode_instruction(cpu, 0, &dummy_cpu, &instr_length);
        next_rip = cpu->regs.rip + instr_length;

        /* Breakpoints */
        if (dbg->proc->state != Process::RUNNING) { stepping = 1; }
        if (cpu->regs.rip == breakpoint_rip) { stepping = 1; breakpoint_rip = 0; }

        {
            // if (cpu->regs.rip == 0x00007ffff7a93cc1) { stepping = 1; }
            // if (cpu->instruction_counter == 1050) { stepping = 1; }
            // if (cpu->current_operation == X64CPU_OP_SYSCALL) { stepping = 1; }

            // if (cpu->regs.rip == 0x00007ffff7a9a0c4) { stepping = 1; }
            // if (cpu->regs.rip == 0x00007ffff7a9a6f0) { stepping = 1; }
            // if (cpu->regs.rip == 0x00007ffff7a8e55d) { stepping = 1; }
            // if (cpu->regs.rip == 0x00007ffff7a9f85e) { stepping = 1; }
            if (cpu->regs.rip == 0x7ffff7ddfbaf) { stepping = 1; }
#if 0
            if (cpu->op[0].type == 4) {
                uint64_t addr = (cpu->op[0].address) & (~0x07);
                if (addr == 0x00007ffff5ff76c8) { stepping = 1; }
            }
            if (cpu->op[1].type == 4) {
                uint64_t addr = (cpu->op[1].address) & (~0x07);
                if (addr == 0x00007ffff7ddcffe) { stepping = 1; }
            }
#endif
        }

        /* Auto-break to main progress entry point */
#if 0
        if (cpu->regs.rip == dbg->proc->main_entry_addr) {
            stepping = 1;
            gui_log(&dbg->gui, "[*] Reached main process entry address.\n");
        }
#endif

        if (stepping) {
            gui_update_view(dbg);
            gui_code_log(dbg, 2);
            cmd = getch();

            switch (cmd) {
                case 'q':
                    running = 0;
                    break;

                case KEY_UP:
                    wscrl(ctx->code_log_sub, -10);
                    break;

                case KEY_DOWN:
                    wscrl(ctx->code_log_sub, 10);
                    break;

                case 'r':
                    stepping = 0;
                case 'n':
                    if (cmd == 'n' && cpu->current_operation == X64CPU_OP_CALL) {
                        breakpoint_rip = next_rip;
                        stepping = 0;
                    }
                case 's':
                    if (!cpu->is_halted) {
                        gui_code_log(dbg, 1);
                        rc = env->step();
                        if (rc != 0) {
                            gui_log(&dbg->gui, "[*] CPU Exception (%d): [%d] %s at RIP 0x%016lx.\n",
                                        cpu->execution_result,
                                        cpu->cpu_exception.code, x64cpu_exception_name(cpu->cpu_exception.code),
                                        cpu->cpu_exception.rip
                            );
                            cpu->regs.rip = cpu->cpu_exception.rip;
                        }
                    }
                    if (cpu->is_halted) {
                        gui_log(&dbg->gui, "[*] CPU Halted. Program stopped.\n");
                    }
                    break;

                case 'i': {
                        char cmd;
                        gui_log(&dbg->gui, "> Info: (f)loat, ... : ");
                        cmd = getch();
                        if (cmd == 'f') {
                            char output[8192];
                            x64cpu_fpu_dump(cpu, output, sizeof(output) - 1);
                            gui_log(&dbg->gui, "\n%s", output);
                        }
                    }
                    break;

                case 'o': {
                        dbg->gui.memview_memory = 1;
                        dbg->gui.memview_address = 0x00;

                        if (cpu->op[0].type == 4) {
                            dbg->gui.memview_address = cpu->op[0].address;
                        }
                        else if (cpu->op[1].type == 4) {
                            dbg->gui.memview_address = cpu->op[1].address;
                        }
                    }
                    break;

                case 'm': {
                        std::string out;

                        out = dbg->proc->dumpSegments();

                        gui_log(&dbg->gui, "[*] Process memory segments:\n");
                        gui_log(&dbg->gui, "%s\n", out.c_str());
                    }
                    break;

                case 'p': {
                        char cmd;
                        wprintw(ctx->cmd, "Move memory viewer to (s)tack / (a)dress / (o)perand >");
                        wrefresh(ctx->cmd);
                        cmd = getch();
                        if (cmd == 's') {
                            dbg->gui.memview_memory = 0;
                            wprintw(ctx->cmd, "Pointing to stack.");
                            wrefresh(ctx->cmd);
                        }
                        else if (cmd == 'a') {
                            wprintw(ctx->cmd, "\nEnter address (in hex): 0x");
                            echo();
                            wscanw(ctx->cmd, "%lx", &dbg->gui.memview_address);
                            noecho();
                            wrefresh(ctx->cmd);
                            dbg->gui.memview_memory = 1;
                        }
                        else if (cmd == 'o') {
                            dbg->gui.memview_memory = 2;
                            wprintw(ctx->cmd, "Pointing to operand.");
                            wrefresh(ctx->cmd);
                        }
                        wprintw(ctx->cmd, "\n");
                        wrefresh(ctx->cmd);
                    }
                    break;
            }
        }
        else {
            if (cpu->is_halted) {
                stepping = 1;
            }

			if (start_logging) {
	            gui_code_log(dbg, 0);
			}
            rc = env->step();
            if (rc != 0) {
                gui_log(&dbg->gui, "[*] CPU Exception (%d): [%d] %s at RIP 0x%016lx.\n",
                            cpu->execution_result,
                            cpu->cpu_exception.code, x64cpu_exception_name(cpu->cpu_exception.code),
                            cpu->cpu_exception.rip
                );
                cpu->regs.rip = cpu->cpu_exception.rip;
                stepping = 1;
            }
            if (cpu->is_halted) {
                gui_log(&dbg->gui, "[*] CPU Halted. Program stopped.\n");
                stepping = 1;
            }
        }
    }
}

class LogInterface : public Environment::LogInterface {
public:
    LogInterface(struct debugger *dbg) { this->dbg = dbg; }

    int log(const char *msg) {
        gui_log(dbg, "[*] %s\n", msg);
        return strlen(msg);
    }

public:
    struct debugger *dbg;
};

int main(int argc, char **argv, char *envp[]) {
    struct debugger dbg;
    int i;

    memset(&dbg, 0, sizeof(dbg));

    if (argc < 2) {
        fprintf(stderr, "Usage:\n\t%s <filename>\n", argv[0]);
        return 1;
    }

#if 0
    {
        size_t i = 0;
        for (i = 0; envp[i] != NULL; i++) {
            fprintf(stderr, "%s\n", envp[i]);
        }
        return 0;
    }
#endif

    int _argc = 1;
    char *_argv[] = {
        argv[0],
        ""
    };

    char **_envp = envp;

    gui_init(&dbg.gui);

    dbg.env = new EnvLinux();
    dbg.env->log_interface = new LogInterface(&dbg);

    if (load_file(argv[1], dbg.env, _argc, _argv, _envp, &dbg.proc) < 0) {
        fprintf(stderr, "Cannot load executable image: %s.\n", argv[1]);
        return 1;
    }

    gui_update_view(&dbg);

    debugger_main(&dbg);

    gui_destroy();

    return 0;
}

