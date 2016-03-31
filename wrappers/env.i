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

/* env.i */

%module env

%include "cstring.i"
%include "carrays.i"
%include <std_string.i>
%include <std_map.i>


%typemap(in)    uint8_t,uint16_t,uint32_t,uint64_t    { $1 = ($type) SvIV($input); }
%typemap(out)   uint8_t,uint16_t,uint32_t,uint64_t    { $result = sv_newmortal(); sv_setiv($result, (IV)$1); argvi++; }

%{
#include "../environment/Environment.h"

#include "../environment/linux/elf-file.h"
#include "../environment/linux/ElfLoader.h"
#include "../environment/linux/EnvLinux.h"

#include "../environment/win/PEFile.h"

struct _env_io_callback_user_data {
    SV *pl_callback;
    SV* pl_userdata;
};

int _env_wrapped_call_perl_io_callback(enum PEFile::io_callback_op op, void *p_user_data, void *buffer, int n) {
    struct _env_io_callback_user_data *tmp = (struct _env_io_callback_user_data*)p_user_data;
    int ret = -1;
    int rc;

    dSP;
    I32 ax;
    int count;

    ENTER;
    SAVETMPS;

    PUSHMARK(SP);
    mXPUSHi(op);
    PUSHs(tmp->pl_userdata);
    mXPUSHi(n);
    PUTBACK;

    count = call_sv(tmp->pl_callback, G_ARRAY);

    SPAGAIN;
    SP -= count;
    ax = (SP - PL_stack_base) + 1;

    /* Get return values */
    ret = -1;
    if (count != 2) {
        croak("env io_callback Perl callback should return 2 values ($result, $buffer)");
        goto _end;
    }

    rc = (int)SvIV(ST(0));

    if (buffer != NULL && rc > 0) {
        SV *sv;
        int i;
        STRLEN len;
        char *str;

        sv = ST(1);
        if (op == PEFile::IO_CB_OP_READ) {
            if (!SvOK(sv)) {
                croak("env io_callback Perl callback: READ op must return buffer");
                goto _end;
            }
        }

        str = SvPV(sv, len);
        if (str == NULL) {
            croak("env io_callback Perl callback: second returned value not a string");
            goto _end;
        }

        if (len != n) {
            croak("env io_callback Perl callback: returned buffer size not matching requested size");
            goto _end;
        }

        for (i = 0; i < len; i++) {
            ((char*)buffer)[i] = str[i];
        }
    }

    ret = rc;

_end:
    PUTBACK;
    FREETMPS;
    LEAVE;

    return ret;
}

%}
%typemap(in)    (PEFile::io_callback io_fn, void *io_user_data) {
    struct _env_io_callback_user_data *tmp = (struct _env_io_callback_user_data*)malloc(sizeof(struct _env_io_callback_user_data));

    tmp->pl_callback = $input;
    SvREFCNT_inc($input);
    tmp->pl_userdata = &PL_sv_undef;

    $1 = _env_wrapped_call_perl_io_callback;
    $2 = tmp;
}
%typemap(freearg)    (PEFile::io_callback io_fn, void *io_user_data) {
    SvREFCNT_dec($input);
    free($2);
}


%include "../environment/Environment.h"

%include "../environment/linux/elf-file.h"
%include "../environment/linux/ElfLoader.h"
%include "../environment/linux/EnvLinux.h"

%include "../environment/win/PEFile.h"

