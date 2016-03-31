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

#ifndef __DEBUGGER_H__
#define __DEBUGGER_H__

#include "Buffer.h"
#include "Window.h"

#ifdef _WINENV
#include "../env/win/WinEnv.h"
#else
#include "../environment/Environment.h"
#include "../environment/linux/EnvLinux.h"
#endif

#include <vector>


class Debugger {
public:
    class Module {
    public:
        virtual int init();
        virtual int update();
        virtual int key(int ch);
        virtual int prestep();
        virtual int poststep();

    public:
        Debugger *dbg;
        Buffer *console;
        int width, height;

    };
public:
    Debugger();

    virtual ~Debugger();

public:
    int log(const char *fmt, ...);
    static int _log(void *user_data, const char *fmt, ...);

    int initialize();

    int loadElfFile(const char *filename, int argc, const char **argv, const char **envp);

    int mainLoop();

    inline Window* getConsole() {
        return this->gui.console;
    }

    inline struct x64cpu* getCPU() {
        return env->cpu;
    }
    inline struct x64cpu_vmem* getMemory() {
        if (proc) {
            return &proc->memory;
        }
        return NULL;
    }
#ifdef _WINENV
    inline WinProcess* getProcess() {
        return proc;
    }
#else
    inline Process* getProcess() {
        return proc;
    }
#endif

    int run(bool run_to = false, uint64_t address = 0);
    int step();
    uint64_t getNextRip();
    int next();

private:
    int handleCommand(int cmd);

    int loadModules();
    int setMain(int index);
    int initGUI();
    void redrawGUI(int full);
    void changeFocus(Window *focus);

private:
#ifdef _WINENV
    WinEnv *env;
    WinProcess *proc;
#else
    Environment *env;
    Process *proc;
#endif

    std::map<uint64_t, bool> breakpoints;

    typedef std::vector<Module*> ModuleList;
    ModuleList module_list;
    Module *current_module;
    ModuleList loaded_list;

    struct {
        Window *main;
        Window *right;
        Window *console;
        Window *cpu;

        struct {
            int main_width;
            int main_height;
        } geom;

        Window *focused;
    } gui;
    Buffer *console;

};

#endif /* __DEBUGGER_H__ */

