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

#include "Debugger.h"

#include "modules/Modules.h"

#include "../environment/linux/ElfLoader.h"

#include <map>
#include <string.h>

/* ------------------------------------------------------------------------- */
int Debugger::Module::init() {
    return 0;
}
/* ------------------------------------------------------------------------- */
int Debugger::Module::update() {
    return 0;
}
/* ------------------------------------------------------------------------- */
int Debugger::Module::key(int ch) {
    return 0;
}
/* ------------------------------------------------------------------------- */
int Debugger::Module::prestep() {
    return 0;
}
int Debugger::Module::poststep() {
    return 0;
}
/* ------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------- */
class LogInterface : public Environment::LogInterface {
public:
    LogInterface(Debugger *dbg) { this->dbg = dbg; }

    int log(const char *msg) {
        return dbg->log("[*] %s\n", msg);
    }

private:
    Debugger *dbg;
};
/* ------------------------------------------------------------------------- */
Debugger::Debugger() {
    memset(&this->gui, 0, sizeof(this->gui));

#ifdef _WINENV
    env = new WinEnv();
    env->log_user_data = this;
    env->_logger = Debugger::_log;
    env->system_directory = "/mnt/c_drive/Windows/System32";
#else
    env = new EnvLinux();
    env->log_interface = new LogInterface(this);
#endif
}
/* ------------------------------------------------------------------------- */
Debugger::~Debugger() {
    delete env;

    endwin();
}
/* ------------------------------------------------------------------------- */
int Debugger::log(const char *fmt, ...) {
    int rc;
    char buffer[8192];

    va_list va_args;
    va_start(va_args, fmt);
    rc = vsnprintf(buffer, sizeof(buffer) - 1, fmt, va_args);
    va_end(va_args);

    return Debugger::_log(this, "%s", buffer);
}
/* ------------------------------------------------------------------------- */
int Debugger::_log(void *user_data, const char *fmt, ...) {
    Debugger *dbg = (Debugger*)user_data;
    int rc, i;
    char buffer[8192];
    char *ptr;

    va_list va_args;
    va_start(va_args, fmt);
    rc = vsnprintf(buffer, sizeof(buffer) - 1, fmt, va_args);
    va_end(va_args);

    dbg->console->printf("%s", buffer);
    dbg->console->flush();

    return rc;
}
/* ------------------------------------------------------------------------- */
int Debugger::initialize() {
    if (this->initGUI() != 0) {
        return -1;
    }

    if (this->loadModules() != 0) {
        return -1;
    }

    this->redrawGUI(1);

    log("x64cpu debugger <version>\n");
    log("Copyright(c) 2016 Bogdan Blagaila\n");
    log("License LGPLv3+: GNU Lesser GPL version 3 or later <http://gnu.org/licenses/lgpl.html>\n"
        "This is free software: you are free to change and redistribute it.\n"
        "There is NO WARRANTY, to the extent permitted by law.\n"
    );

    return 0;
}
/* ------------------------------------------------------------------------- */
int Debugger::loadElfFile(const char *filename, int argc, const char **argv, const char **envp) {
#if _WINENV
    if (env->createProcess(filename, &proc) != 0) {
        return 1;
    }
#else
    int ret;
    struct elf_file *elf = NULL;
    Thread *th = NULL;

    ret = ElfLoader::loadElfFromFile(filename, &elf);
    if (ret < 0) {
        log("Error opening file <%s>: %d: %s.\n", filename, (-ret), strerror(-ret));
        return 1;
    }

    proc = env->createProcess();

    ret = ElfLoader::loadProcess(proc, elf, filename, &th);
    if (ret < 0) {
        log("Error creating process: %d.\n", ret);
        return 1;
    }

    env->setCurrentThread(th);

#endif
    return 0;
}
/* ------------------------------------------------------------------------- */
int Debugger::mainLoop() {
    int cmd;
    int running;

    running = 1;
    while (running) {
        this->redrawGUI(0);

        cmd = getch();

// log("Key pressed: %s - %d\n", keyname(cmd), cmd);

        switch (cmd) {
            case 'q':
                running = 0;
                break;

            case /* Ctrl+L */12:
                this->redrawGUI(1);
                break;

            case 's':
                this->step();
                break;

            case 'r':
                this->run();
                break;

            case 'n': this->next(); break;

            case KEY_PPAGE:
                if (this->gui.focused) {
                    this->gui.focused->scrollUp(10);
                }
                break;

            case KEY_NPAGE:
                if (this->gui.focused) {
                    this->gui.focused->scrollDown(10);
                }
                break;

            case '`':
                this->changeFocus(this->gui.console);
                break;

            default:
                if (cmd >= '1' && cmd <= '9') {
                    this->setMain(cmd - '1');
                    this->changeFocus(this->gui.main);
                }
                else {
                    if (this->gui.focused == this->gui.console) {
                        this->handleCommand(cmd);
                    }
                    else if (this->gui.focused == this->gui.main) {
                        this->current_module->key(cmd);
                    }
                }
                break;

        }
    }

    return 0;
}
/* ------------------------------------------------------------------------- */
int Debugger::handleCommand(int cmd) {
    switch (cmd) {
        case 'b': {
                uint64_t address = 0;
                std::string name = "";

                log("Breakpoint address > 0x");
                echo();
                this->gui.console->scanw("%lx", &address);
                noecho();

                breakpoints[address] = true;

                log("Added breakpoint to %lx", address);
#if 0
                if (proc && proc->findSymbolAtAddress(address, name) == 0) {
                    log("  <%s>", name.c_str());
                }
#endif
                log("\n");
            }
            break;
    }

    return 0;
}
/* ------------------------------------------------------------------------- */
int Debugger::run(bool run_to, uint64_t address) {
    int ret = 0;
    int rc;

    while (1) {
        rc = this->step();

        this->redrawGUI(0);

        if (rc != 0) {
            break;
        }

        if (run_to) {
            if (env->cpu->regs.rip == address) {
                break;
            }
        }
        if (breakpoints.find(env->cpu->regs.rip) != breakpoints.end()) {
            break;
        }
    }

    return ret;
}
/* ------------------------------------------------------------------------- */
int Debugger::step() {
    int ret = 0;
    int rc;
    Thread *th;
    ModuleList::iterator itr;

#if 0
    for (itr = loaded_list.begin(); itr != loaded_list.end(); itr++) {
        (*itr)->prestep();
    }
#endif

    th = proc->threads.begin()->second;
    env->setCurrentThread(th);

    rc = env->step(th);

    for (itr = loaded_list.begin(); itr != loaded_list.end(); itr++) {
        (*itr)->poststep();
    }

    if (rc == 1) {
        log("[*] Program stopped.\n");
        ret = 1;
    }
    else if (rc != 0) {
        log("[*] CPU Exception (%d): [%d] %s at RIP 0x%016lx.\n",
                    env->cpu->execution_result,
                    env->cpu->cpu_exception.code, x64cpu_exception_name(env->cpu->cpu_exception.code),
                    env->cpu->cpu_exception.rip
        );
        env->cpu->regs.rip = env->cpu->cpu_exception.rip;
        ret = 1;
    }
    if (env->cpu->is_halted) {
        log("[*] CPU Halted. Program stopped.\n");
        ret = 1;
    }

    return ret;
}
/* ------------------------------------------------------------------------- */
uint64_t Debugger::getNextRip() {
    struct x64cpu *cpu = this->getCPU();
    struct x64cpu dummy;
    uint64_t ret = cpu->regs.rip;
    int len;

    if (x64cpu_debug_decode_instruction(cpu, 0, &dummy, &len) == 0) {
        ret += len;
    }
    else {
        /* Invalid instruction; maybe 1 byte ? */
        ret += 1;
    }

    return ret;
}
/* ------------------------------------------------------------------------- */
int Debugger::next() {
    uint64_t runto = this->getNextRip();
log("Running until 0x%016lx.\n", runto);
    return this->run(true, runto);
}
/* ------------------------------------------------------------------------- */
int Debugger::loadModules() {
    /* Load special modules */

    /* Load CPU viewer */
    Module *cpu_viewer = ::getCPUViewer();
    cpu_viewer->dbg = this;
    cpu_viewer->console = new Buffer(gui.cpu->getRows() - 2, gui.cpu->getCols() - 2, 0);
    gui.cpu->attachBuffer(cpu_viewer->console);
    loaded_list.push_back(cpu_viewer);

    /* Load Stack View */
    Module *stack_view = ::getStackView();
    stack_view->dbg = this;
    stack_view->console = new Buffer(gui.right->getRows() - 2, gui.right->getCols() - 2, 0);
    gui.right->attachBuffer(stack_view->console);
    loaded_list.push_back(stack_view);

    /* TODO: flexible main windows */
    {
        int i = 0;
        Module **list = ::getModules();
        while (list[i] != NULL) {
            Module *module = list[i++];

            module->dbg = this;
            module->console = new Buffer(gui.geom.main_height - 2, gui.geom.main_width - 2, 5000);
            
            module_list.push_back(module);
            loaded_list.push_back(module);
        }

        this->setMain(0);
    }

    return 0;
}
/* ------------------------------------------------------------------------- */
int Debugger::setMain(int index) {
    Module *tmp;
    if (index > module_list.size()) {
        return -1;
    }

    tmp = module_list[index];
    if (tmp == NULL) {
        return -1;
    }

    this->current_module = tmp;
    gui.main->attachBuffer(this->current_module->console);

    return 0;
}
/* ------------------------------------------------------------------------- */
void Debugger::redrawGUI(int full) {
    if (full) {
        gui.main->update();
        gui.right->update();
        gui.console->update();
        gui.cpu->update();
    }

#if 1
    ModuleList::iterator itr;
    for (itr = loaded_list.begin(); itr != loaded_list.end(); itr++) {
        (*itr)->update();
    }
#endif
}
/* ------------------------------------------------------------------------- */
void Debugger::changeFocus(Window *focus) {
    if (this->gui.focused) {
        this->gui.focused->focus(false);
    }
    this->gui.focused = focus;
    if (this->gui.focused) {
        this->gui.focused->focus(true);
    }
}
/* ------------------------------------------------------------------------- */
int Debugger::initGUI() {
    initscr();

    noecho();
    cbreak();
    keypad(stdscr, TRUE);

    printw("Test");
    refresh();

    gui.focused = NULL;
    gui.geom.main_width = (COLS - 54);
    gui.geom.main_height = (LINES - 7 - 20);

    gui.console = new Window("Buffer", 20, gui.geom.main_width, 0, LINES - 20);
    gui.cpu = new Window("CPU", 7, gui.geom.main_width, 0, LINES - 20 - 7);
    gui.right = new Window("Stack/Memory", LINES, 54, gui.geom.main_width, 0);

    gui.main = new Window("Main", gui.geom.main_height, gui.geom.main_width, 0, 0);

    this->console = new Buffer(20, gui.geom.main_width, 5000);
    gui.console->attachBuffer(this->console);

    this->changeFocus(gui.console);

    return 0;
}
/* ------------------------------------------------------------------------- */

