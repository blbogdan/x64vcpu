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

/* cpu.i */

%module cpu

%include "cstring.i"
%include "carrays.i"


%typemap(in)    uint8_t,uint16_t,uint32_t,uint64_t    { $1 = ($type) SvIV($input); }
%typemap(out)   uint8_t,uint16_t,uint32_t,uint64_t    { $result = sv_newmortal(); sv_setiv($result, (IV)$1); argvi++; }

%typemap(in)    (uint8_t* buffer, size_t buffer_len) {
    int i;
    size_t len;
    AV *tempav;
    SV **tv;

    if (!SvROK($input)) {
        SWIG_croak("Argument $argnum is not a reference.");
    }
    if (SvTYPE(SvRV($input)) != SVt_PVAV) {
        SWIG_croak("Argument $argnum is not an array.");
    }

    tempav = (AV*)SvRV($input);
    len = av_len(tempav);
    $1 = (uint8_t*)malloc(len * sizeof(uint8_t));
    for (i = 0; i < len; i++) {
        tv = av_fetch(tempav, i, 0);
        $1[i] = (uint8_t)SvIV(*tv);
    }

    $2 = len;
}
%typemap(freearg)   (uint8_t* buffer, size_t bufferlen) {
    free($1);
}

%rename ("%(regex:/^(X64CPU_|x64cpu_)(.*)/\\2/)s") "";
%rename ("%(regex:/^(32_opcode)/b32_opcode/)s") "";


%cstring_output_maxsize(char *ret, int ret_len);
%cstring_output_maxsize(char *output, size_t output_max_len);
%cstring_output_maxsize(char *output, int output_max_len);

%{
#include "../cpu/cpu.h"
#include "../cpu/disasm.h"
#include "../cpu/opcode_decoder.h"
#include "../cpu/virtual_memory.h"



struct wrapped_x64cpu {
    struct x64cpu cpu;

    SV *pl_user_data;
    SV *pl_mem_read;
    SV *pl_mem_write;
};

int wrapped_call_perl_mem_read_cb(SV *sub, struct wrapped_x64cpu *cpu, SV *user_data,
                                uint64_t address, uint8_t *data, uint8_t size,
                                enum x64cpu_mem_access_flags access_flags,
                                uint64_t *fault_address) {
    int ret = -1;

    if (user_data == NULL) {
        user_data = &PL_sv_undef;
    }

    dSP;
    I32 ax;
    int count;

    ENTER;
    SAVETMPS;

    PUSHMARK(SP);
    XPUSHs(SWIG_NewPointerObj(SWIG_as_voidptr(cpu), SWIGTYPE_p_x64cpu, 0));
    XPUSHs(user_data);
    mXPUSHi(address);
    mXPUSHi(size);
    mXPUSHi(access_flags);
    PUTBACK;

    count = call_sv(sub, G_ARRAY);

    SPAGAIN;
    SP -= count;
    ax = (SP - PL_stack_base) + 1;

    /* Get return values */
    ret = -1;
    uint8_t returned_value[16];

    memset(returned_value, 0, sizeof(returned_value));

    if (count != 3) {
        croak("x64cpu mem_read Perl callback should return 3 values ($result, @value, $fault_address/undef)!");
        goto _end;
    }

    if (count >= 3) {
        if (fault_address) {
            SV *sv = ST(2);
            if (SvOK(sv)) {
                (*fault_address) = (uint64_t)SvIV(ST(2));
            }
        }
    }
    if (count >= 2) {
        SV *sv;
        AV *av;
        SV **tv;
        int i, len;

        sv = ST(1);
        if (SvTYPE(SvRV(sv)) != SVt_PVAV) {
            croak("x64cpu mem_read Perl callback: second returned value not an array!");
            goto _end;
        }

        av = (AV*)SvRV(sv);
        len = av_len(av);

        if (len != size) {
            croak("x64cpu mem_read Perl callback: second returned value: size not matching requested size!");
            goto _end;
        }

        for (i = 0; i < len; i++) {
            tv = av_fetch(av, i, 0);
            if (tv) {
                returned_value[i] = (uint8_t)SvIV(*tv);
            }
            else {
                croak("x64cpu mem_read Perl callback: returned array must contain only integers!");
                goto _end;
            }
        }

        memcpy(data, returned_value, size);
    }
    if (count >= 1) {
        ret = (int)SvIV(ST(0));
    }

_end:
    PUTBACK;
    FREETMPS;
    LEAVE;

    return ret;    
}

int wrapped_call_perl_mem_write_cb(SV *sub, struct wrapped_x64cpu *cpu, SV *user_data,
                                uint64_t address, uint8_t *data, uint8_t size,
                                enum x64cpu_mem_access_flags access_flags,
                                uint64_t *fault_address) {
    int ret = -1;
    int i;
    AV* data_a;

    if (user_data == NULL) {
        user_data = &PL_sv_undef;
    }

    data_a = newAV();
    for (i = 0; i < size; i++) {
        av_push(data_a, newSViv(data[i]));
    }

    dSP;
    I32 ax;
    int count;

    ENTER;
    SAVETMPS;

    PUSHMARK(SP);
    XPUSHs(SWIG_NewPointerObj(SWIG_as_voidptr(cpu), SWIGTYPE_p_x64cpu, 0));
    XPUSHs(user_data);
    mXPUSHi(address);
    mXPUSHs(data_a);
    mXPUSHi(size);
    mXPUSHi(access_flags);
    PUTBACK;

    count = call_sv(sub, G_ARRAY);

    SPAGAIN;
    SP -= count;
    ax = (SP - PL_stack_base) + 1;

    /* Get return values */
    ret = -1;

    if (count != 2) {
        croak("x64cpu mem_write Perl callback should return 2 values ($result, $fault_address/undef)!");
        goto _end;
    }

    if (count >= 2) {
        if (fault_address) {
            SV *sv = ST(2);
            if (SvOK(sv)) {
                (*fault_address) = (uint64_t)SvIV(ST(2));
            }
        }
    }
    if (count >= 1) {
        ret = (int)SvIV(ST(0));
    }

_end:
    PUTBACK;
    FREETMPS;
    LEAVE;

    return ret;    
}

int wrapped_mem_read_cb(struct x64cpu *t_cpu, void *memory, uint64_t address, uint8_t *data, uint8_t size,
                                enum x64cpu_mem_access_flags access_flags, uint64_t *fault_address) {
    struct wrapped_x64cpu* cpu = (struct wrapped_x64cpu*)t_cpu;

    if (cpu->pl_mem_read != &PL_sv_undef) {
        return wrapped_call_perl_mem_read_cb(cpu->pl_mem_read, cpu, cpu->pl_user_data,
                                        address, data, size, access_flags, fault_address);
    }

    if (cpu->cpu.mem_read != wrapped_mem_read_cb) {
        return cpu->cpu.mem_read(t_cpu, memory, address, data, size, access_flags, fault_address);
    }

    if (fault_address) {
        (*fault_address) = address;
    }
    croak("x64cpu mem_read Perl callback: null callback");
    return -1;
}

int wrapped_mem_write_cb(struct x64cpu *t_cpu, void *memory, uint64_t address, uint8_t *data, uint8_t size,
                                enum x64cpu_mem_access_flags access_flags, uint64_t *fault_address) {
    struct wrapped_x64cpu* cpu = (struct wrapped_x64cpu*)t_cpu;

    if (cpu->pl_mem_write != &PL_sv_undef) {
        return wrapped_call_perl_mem_write_cb(cpu->pl_mem_write, cpu, cpu->pl_user_data,
                                        address, data, size, access_flags, fault_address);
    }

    if (cpu->cpu.mem_write != wrapped_mem_write_cb) {
        return cpu->cpu.mem_write(t_cpu, memory, address, data, size, access_flags, fault_address);
    }

    if (fault_address) {
        (*fault_address) = address;
    }
    croak("x64cpu mem_write Perl callback: null callback");
    return -1;
}



%}

%ignore x64cpu::mem_read;
%ignore x64cpu::mem_write;

%include "../cpu/cpu.h"
%include "../cpu/disasm.h"
%include "../cpu/opcode_decoder.h"
%include "../cpu/virtual_memory.h"

%callback("%s_cb");
int x64cpu_vmem_read_cpu_glue(struct x64cpu *ignored, void *memory, uint64_t address, uint8_t *data, uint8_t size,
                                enum x64cpu_mem_access_flags access_flags, uint64_t *fault_address);
int x64cpu_vmem_write_cpu_glue(struct x64cpu *ignored, void *memory, uint64_t address, uint8_t *data, uint8_t size,
                                enum x64cpu_mem_access_flags access_flags, uint64_t *fault_address);
%nocallback;

%extend x64cpu {
    SV *pl_user_data;
    SV *pl_mem_read;
    SV *pl_mem_write;

    x64cpu() {
        struct wrapped_x64cpu *cpu = calloc(1, sizeof(struct wrapped_x64cpu));
        x64cpu_init((struct x64cpu*)cpu);

        cpu->cpu.mem_read = wrapped_mem_read_cb;
        cpu->cpu.mem_write = wrapped_mem_write_cb;

        cpu->pl_user_data = &PL_sv_undef;
        cpu->pl_mem_read = &PL_sv_undef;
        cpu->pl_mem_write = &PL_sv_undef;

        return (struct x64cpu*)cpu;
    }
    ~x64cpu() {
        free($self);
    }
}

%{
SV *x64cpu_pl_user_data_get(struct x64cpu *t_cpu) {
    struct wrapped_x64cpu* cpu = (struct wrapped_x64cpu*)t_cpu;
   
    return cpu->pl_user_data ;
}
void x64cpu_pl_user_data_set(struct x64cpu *t_cpu, SV* data) {
    struct wrapped_x64cpu* cpu = (struct wrapped_x64cpu*)t_cpu;
   
    if (cpu->pl_user_data != &PL_sv_undef) {
        SvREFCNT_dec(cpu->pl_user_data );
        cpu->pl_user_data = &PL_sv_undef;
    }
    if (data != &PL_sv_undef) {
        cpu->pl_user_data = data;
        SvREFCNT_inc(cpu->pl_user_data );
    }
}
%}

%define MEMCBHELPER(name)
%inline %{

SV *x64cpu_pl_ ## name ## _get(struct x64cpu *t_cpu) {
    struct wrapped_x64cpu* cpu = (struct wrapped_x64cpu*)t_cpu;
   
    return cpu->pl_ ## name ;
}

void x64cpu_pl_ ## name ## _set(struct x64cpu *t_cpu, SV *cb) {
    struct wrapped_x64cpu* cpu = (struct wrapped_x64cpu*)t_cpu;
    int res;
    x64cpu_mem_cb arg2 = (x64cpu_mem_cb) 0;

    /* Remove old reference */
    if (cpu->pl_ ## name != &PL_sv_undef) {
        SvREFCNT_dec(cpu->pl_ ## name);
        cpu->pl_ ## name = &PL_sv_undef;
    }

    /* Is it a native callback function ? */
    res = SWIG_ConvertFunctionPtr(cb, (void**)(&arg2), SWIGTYPE_p_f_p_struct_x64cpu_p_void_uint64_t_p_uint8_t_uint8_t_enum_x64cpu_mem_access_flags_p_uint64_t__int);
    if (SWIG_IsOK(res)) {
        cpu->cpu.## name = arg2;
        return;
    }

    /* Not a native callback; set the native function pointer to the wrapper */
    cpu->cpu.## name = wrapped_ ## name ## _cb;

    if (cb != &PL_sv_undef) {
        cpu->pl_ ## name = cb;
        SvREFCNT_inc(cpu->pl_ ## name);
    }
}

%}
%enddef

MEMCBHELPER(mem_read)
MEMCBHELPER(mem_write)

