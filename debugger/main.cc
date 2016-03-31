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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include "debugger.h"

int main(int argc, char **argv, char **envp) {
    int ret = 0;
    Debugger *dbg = NULL;
    int _argc;
    const char *_argv[] = {
        argv[1],
        NULL
    };
    const char **_envp;

    if (argc < 2) {
        fprintf(stderr, "Usage:\n\t%s <filename>\n", argv[0]);
        ret = 1;
        goto _end;
    }

    dbg = new Debugger();
    if (dbg->initialize() != 0) {
        fprintf(stderr, "Cannot initialize debugger\n");
        ret = 1;
        goto _end;
    }

    _argc = 1;
    _envp = (const char**)envp;

    dbg->loadElfFile(argv[1], _argc, _argv, _envp);

    ret = dbg->mainLoop();

_end:
    if (dbg) {
        delete dbg;
    }
    return ret;
}

