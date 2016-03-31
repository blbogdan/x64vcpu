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
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "../environment/linux/EnvLinux.h"
#include "../environment/linux/ElfLoader.h"

extern "C" {
#include "../cpu/disasm.h"
}

#include <list>
#include <string>

enum Verbosity {
    VERB_NONE = 0,
    VERB_QUIET,
    VERB_ASM,
    VERB_ASM_CPU
};

struct settings_t {
    enum Verbosity verbose;
    const char *filename;
    std::list<std::string> args;
};

struct settings_t settings = {
    .verbose = VERB_NONE,
    .filename = NULL
};

int parseargs(int argc, char **argv) {
    int ret = -1;
    char buf[256];
    char *s;
    int i;
    int state = 0;

    for (i = 1; i < argc; i++) {
        s = argv[i];

        if (state == 0 && s[0] == '-') {
            if (strcmp(s, "-q") == 0) {
                settings.verbose = VERB_QUIET;
            }
            else if (strcmp(s, "-v") == 0) {
                settings.verbose = VERB_ASM;
            }
            else if (strcmp(s, "-vv") == 0) {
                settings.verbose = VERB_ASM_CPU;
            }
            else if (strcmp(s, "-h") == 0 || strcmp(s, "--help") == 0) {
                goto _end;
            }
            else {
                goto _end;
            }
        }
        else {
            /* Filename */
            if (settings.filename == NULL) {
                settings.filename = s;
                ret = 0;
                state = 1;
                continue;
            }
            else {
                settings.args.push_back(s);
            }
        }
    }

_end:
    if (ret != 0) {
        fprintf(stderr, "Usage:  %s [options] <filename>\n", argv[0]);
        fprintf(stderr, "Options:\n");
        fprintf(stderr, "\t%-12s\t%s\n", "-q", "Quiet (no debug output)");
        fprintf(stderr, "\t%-12s\t%s\n", "-v", "Verbose (dumps executed instructions)");
        fprintf(stderr, "\t%-12s\t%s\n", "-vv", "Verbose (dumps executed instructions and cpu state)");
        fprintf(stderr, "\n");
    }
    return ret;
}

class LogInterface : public Environment::LogInterface {
public:
    int log(const char *msg) {
        return fprintf(stderr, "[*] %s\n", msg);
    }
};

int main(int argc, char **argv, char **envp) {
    int ret = 1;
    EnvLinux *env = NULL;
    Process *proc = NULL;
    Thread *th = NULL;
    struct elf_file *elf = NULL;
    char buf[8192], buf2[256];

    fprintf(stderr, "x64cpu debugger <version>\n");
    fprintf(stderr, "Copyright(c) 2016 Bogdan Blagaila\n");
    fprintf(stderr, "License LGPLv3+: GNU Lesser GPL version 3 or later <http://gnu.org/licenses/lgpl.html>\n"
        "This is free software: you are free to change and redistribute it.\n"
        "There is NO WARRANTY, to the extent permitted by law.\n"
    );
    fprintf(stderr, "\n");

    if (parseargs(argc, argv) != 0) {
        return 1;
    }

    ret = ElfLoader::loadElfFromFile(settings.filename, &elf);
    if (ret < 0) {
        fprintf(stderr, "Error opening file <%s>: %d: %s.\n", settings.filename, (-ret), strerror(-ret));
        return 1;
    }

    env = new EnvLinux();
    env->log_interface = new LogInterface();

    if (settings.verbose == VERB_QUIET) {
        env->log_syscalls = 0;
    }

    proc = env->createProcess();

    proc->arguments.push_back(settings.filename);
    proc->arguments.insert(proc->arguments.end(), settings.args.begin(), settings.args.end());
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
                proc->environment_variables["_"] = settings.filename;
            }
            else {
                proc->environment_variables[n] = r;
            }
        }
    }

    ret = ElfLoader::loadProcess(proc, elf, settings.filename, &th);
    if (ret < 0) {
        fprintf(stderr, "[*] Error creating process: %d.\n", ret);
        return 1;
    }

    {
        std::string tmp = proc->dumpSegments();
        fprintf(stdout, "%s\n", tmp.c_str());
    }

    fprintf(stdout, "[*] Running ...\n");

    th = proc->threads.begin()->second;
    env->setCurrentThread(th);

    while (1) {
        if (settings.verbose >= VERB_ASM) {
            int i;
            struct x64cpu out;
            x64cpu_disasm_current(env->cpu, 0, buf, sizeof(buf) - 1, &out);
            for (i = 0; i < out.instr_length; i++) {
                snprintf(&buf2[i * 3], 4, "%02x ", (int)out.instruction[i]);
            }
            fprintf(stdout, "0x%016lx:  %-32s  %s\n", env->cpu->regs.rip, buf2, buf);
        }
        if (settings.verbose >= VERB_ASM_CPU) {
            x64cpu_dump(env->cpu, buf, sizeof(buf));
            fprintf(stdout, "%s\n", buf);
        }

        ret = env->step(th);

        if (ret == 1) {
            fprintf(stdout, "[*] Program stopped.\n");
            break;
        }

        if (ret < 0) {
            fprintf(stdout, "[*] Unhandled exception.\n");
            break;
        }
    }

    {
        std::string tmp = proc->dumpSegments();
        fprintf(stdout, "%s\n", tmp.c_str());
    }

    return ret;
}

