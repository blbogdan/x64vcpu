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

#include "EnvLinuxSyscall.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/mman.h>
// #include <sys/prctl.h>
#include <asm/prctl.h>
#include <linux/limits.h>

#define LOG(str, ...)       { if (env->log_syscalls) { env->log(str, ##__VA_ARGS__); } }

#define DECL_PDATA(source) \
    struct EnvLinux::ProcessData *pdata = (struct EnvLinux::ProcessData*)((source)->user_data);

/* ------------------------------------------------------------------------- */
int _get_string(Process *proc, uint64_t address, std::string& output, size_t max_len) {
    uint64_t ret = 0;
    int rc;
    uint64_t i, len;
    enum x64cpu_mem_access_flags flags = X64CPU_MEM_ACCESS_READ;

    for (i = address, len = 0; ; i++, len++) {
        char c;

        if (max_len != -1 && len > max_len) {
            break;
        }

        rc = x64cpu_vmem_read(&proc->memory, i, (uint8_t*)&c, sizeof(c), flags, NULL);
        if (rc == X64CPU_MEM_ACCESS_GP) {
            return -EFAULT;
        }
        else if (rc == X64CPU_MEM_ACCESS_PF) {
            return -EFAULT;
        }

        if (c == '\0') {
            break;
        }

        output += c;
    }

    return ret;
}

#define STR_PARAM(index, name, max_len, error_if_long) \
    std::string name ; \
    { \
        int rc = _get_string(proc, params[(index)], name, (max_len));\
        if (rc != 0) { return rc; } \
        if ((error_if_long) && (name.size() > (max_len))) { return -ENAMETOOLONG; } \
    }

int _get_buffer(Process *proc, uint64_t address, size_t length, uint8_t **output) {
    int ret = 0;
    int rc;
    uint64_t i;
    enum x64cpu_mem_access_flags flags = X64CPU_MEM_ACCESS_READ;
    uint8_t *buffer = NULL;

    buffer = (uint8_t*)malloc(length);

    for (i = 0; i < length; i++) {
        rc = x64cpu_vmem_read(&proc->memory, (address + i), (uint8_t*)(&buffer[i]),
                                sizeof(uint8_t), flags, NULL);
        if (rc == X64CPU_MEM_ACCESS_GP) {
            ret = -EFAULT;
            goto _err;
        }
        else if (rc == X64CPU_MEM_ACCESS_PF) {
            ret = -EFAULT;
            goto _err;
        }
    }

_err:
    if (ret != 0) {
        free(buffer);
    }
    else {
        (*output) = buffer;
    }

    return ret;
}

#define STRUCT_PARAM(index, type, name) \
    type name ; \
    { \
        int rc = x64cpu_vmem_copyfrom(&proc->memory, params[(index)], \
                                        (uint8_t*)&(name), sizeof(type)); \
        if (rc != sizeof(type)) { \
            return -EFAULT; \
        } \
    }

#define SET_STRUCT(address, value) \
    { \
        int rc = x64cpu_vmem_copyto(&proc->memory, (address), (uint8_t*)&(value), \
                    sizeof((value))); \
        if (rc != sizeof((value))) { ret = -EFAULT; goto _end; } \
    }

#define BUFFER_PARAM_OUT(name, size) \
    uint8_t * name = (uint8_t*)calloc(1, (size)); \
    if ((name) == NULL) { ret = -ENOMEM; goto _end; }

#define BUFFER_PARAM_IN(name, size, address) \
    uint8_t * name = (uint8_t*)calloc(1, (size)); \
    if ((name) == NULL) { ret = -ENOMEM; goto _end; } \
    { \
        int rc = x64cpu_vmem_copyfrom(&proc->memory, (address), (name), (size)); \
        if (rc != (size)) { ret = -EFAULT; goto _end; } \
    }

#define SET_BUFFER_PARAM(name, size, address) \
    { \
        int rc = x64cpu_vmem_copyto(&proc->memory, (address), (uint8_t*)(name), \
                                        (size)); \
        if (rc != (size)) { ret = -EFAULT; goto _end; } \
    }

#define GET_FILE(name, fileno) \
    {\
        EnvLinux::ProcessData::FileDescriptorMap::iterator itr; \
        itr = pdata->file_descriptors.find((fileno)); \
        if (itr == pdata->file_descriptors.end()) { \
            ret = -EBADF; \
            goto _end; \
        } \
        (name) = itr->second; \
    }

/* ------------------------------------------------------------------------- */
uint64_t linux_syscall_read(uint64_t number, EnvLinux *env,
                    Process* proc, Thread *thread, uint64_t params[6]) {
    uint64_t ret = -1;
    uint64_t fileno = params[0];
    uint64_t buf_ptr = params[1];
    uint64_t count = params[2];
    DECL_PDATA(proc);
    EnvLinuxIOFile *file = NULL;
    BUFFER_PARAM_OUT(buf, count);

    LOG("Program called read(%d, %p, %d)", fileno, buf_ptr, count);

    GET_FILE(file, fileno);

    ret = file->read(buf, count);

    if (ret > 0) {
        SET_BUFFER_PARAM(buf, ret, buf_ptr);
    }

_end:
    if (buf) { free(buf); }
    return ret;
}
/* ------------------------------------------------------------------------- */
uint64_t linux_syscall_write(uint64_t number, EnvLinux *env,
                    Process* proc, Thread *thread, uint64_t params[6]) {
    uint64_t ret = -1;
    uint64_t fileno = params[0];
    uint64_t buf_ptr = params[1];
    uint64_t count = params[2];
    DECL_PDATA(proc);
    EnvLinuxIOFile *file = NULL;
    BUFFER_PARAM_IN(buf, count, buf_ptr);

    LOG("Program called write(%d, %p, %d)", fileno, buf_ptr, count);

#if 0
    if (fileno == 1 || fileno == 2) {
        if (fileno == 1) {
            LOG("1> %.*s <1", count, buf);
        }
        else {
            LOG("2> %.*s <2", count, buf);
        }

        ret = count;
        goto _end;
    }
#endif

    GET_FILE(file, fileno);

    ret = file->write(buf, count);

_end:
    if (buf) { free(buf); }
    return ret;
}
/* ------------------------------------------------------------------------- */
uint64_t linux_syscall_open(uint64_t number, EnvLinux *env,
                    Process* proc, Thread *thread, uint64_t params[6]) {
    uint64_t ret = -1;
    STR_PARAM(0, filename, PATH_MAX, 1);
    uint64_t flags = params[1];
    uint64_t mode = params[2];
    DECL_PDATA(proc);
    EnvLinuxIOFile *file = NULL;

    LOG("Program called open(\"%s\", %d, %d.)", filename.c_str(), flags, mode);

    ret = pdata->io_manager->open(filename.c_str(), flags, mode, &file);
    if (ret != 0) {
        return ret;
    }

    ret = pdata->next_fd++;
    pdata->file_descriptors[ret] = file;

    return ret;
}
/* ------------------------------------------------------------------------- */
uint64_t linux_syscall_close(uint64_t number, EnvLinux *env,
                    Process* proc, Thread *thread, uint64_t params[6]) {
    uint64_t ret = -1;
    uint64_t fileno = params[0];
    DECL_PDATA(proc);
    EnvLinuxIOFile *file = NULL;

    LOG("Program called closed(%d)", fileno);

    GET_FILE(file, fileno);

    file->close();
    delete file;
    pdata->file_descriptors.erase(fileno);

    /* Success */
    ret = 0;

_end:
    return ret;
}
/* ------------------------------------------------------------------------- */
uint64_t linux_syscall_stat(uint64_t number, EnvLinux *env,
                    Process* proc, Thread *thread, uint64_t params[6]) {
    uint64_t ret = -1;
    STR_PARAM(0, filename, PATH_MAX, 1);
    uint64_t statbuf_addr = params[1];
    DECL_PDATA(proc);

    struct stat statbuf;

    LOG("Program called stat(\"%s\", %p)", filename.c_str(), statbuf_addr);

    ret = pdata->io_manager->stat(filename.c_str(), &statbuf);
    if (ret < 0) {
        return ret;
    }

    SET_STRUCT(statbuf_addr, statbuf);

_end:
    return ret;
}
/* ------------------------------------------------------------------------- */
uint64_t linux_syscall_fstat(uint64_t number, EnvLinux *env,
                    Process* proc, Thread *thread, uint64_t params[6]) {
    uint64_t ret = -1;
    uint64_t fd = params[0];
    uint64_t statbuf_addr = params[1];
    DECL_PDATA(proc);
    EnvLinuxIOFile *file = NULL;

    struct stat statbuf;

    LOG("Program called fstat(%d, %p)", fd, statbuf_addr);

    GET_FILE(file, fd);

    ret = file->fstat(&statbuf);
    if (ret < 0) {
        return ret;
    }

_end:
    SET_STRUCT(statbuf_addr, statbuf);
    return ret;
}
/* ------------------------------------------------------------------------- */
uint64_t linux_syscall_mmap(uint64_t number, EnvLinux *env,
                    Process* proc, Thread *thread, uint64_t params[6]) {
    uint64_t ret = -1;
    uint64_t addr = params[0];
    uint64_t len = params[1];
    uint64_t prot = params[2];
    uint64_t flags = params[3];
    int64_t fd = (signed)params[4];
    uint64_t off = params[5];

    uint64_t base_addr;
#if 0
    int protection = Process::PROT_READ | Process::PROT_WRITE | Process::PROT_EXEC;
#else
    int protection = 7;
#endif
    int rc;
    DECL_PDATA(proc);

    LOG("Program called mmap(%p, %ld, 0x%lx, 0x%lx, %ld, %ld).", addr, len, prot, flags, fd, off);

    if ((flags & MAP_ANONYMOUS) && fd != -1) {
        return -EINVAL;
    }

    if ((len & X64CPU_VMEM_PAGE_OFFSET_MASK) != 0) {
        len += X64CPU_VMEM_PAGE_SIZE;
        len &= X64CPU_VMEM_PAGE_ADDR_MASK;
    }

    if ((flags & MAP_FIXED) == 0) {
        rc = proc->findAddrForSegment(pdata->maps_arena, len,
                                                1, 0x1000, &base_addr);
        if (rc != 0) {
            return -ENOMEM;
        }
    }
    else {
        if ((addr & X64CPU_VMEM_PAGE_OFFSET_MASK) != 0) {
            return -EINVAL;
        }

        base_addr = addr;
    }

    if (fd != -1) {
        EnvLinuxIOFile *file = NULL;
        ssize_t old_offset, rc;
        struct Process::Segment *segment = NULL;
        uint8_t *buffer = NULL;
        GET_FILE(file, fd);

        old_offset = file->seek(0, SEEK_CUR);
        if (old_offset < 0 || (file->seek(off, SEEK_SET) < 0)) {
            // TODO: dellocate segments from memory ?
            return -EBADF;
        }

        buffer = (uint8_t*)calloc(1, len);

        rc = file->read(buffer, len);
        if (rc < 0) {
            return rc;
        }

        /* Allocate segment */
        /* Remove previous */
        proc->removeSegment(base_addr, (base_addr + len));
        segment = proc->addSegment(base_addr, (base_addr + len), protection, file->name.c_str(), NULL);
        if (segment == NULL) {
            /* Overlap ? */
            return -ENOMEM;
        }

        rc = x64cpu_vmem_copyto(&proc->memory, base_addr, buffer, len);
        if (rc != len) {
            // what ?
        }

_end:
        if (buffer != NULL) {
            free(buffer);
        }
        file->seek(old_offset, SEEK_SET);
    }
    else {
        /* Allocate segment */
        /* Remove previous */
        proc->removeSegment(base_addr, (base_addr + len));
        struct Process::Segment *segment = proc->addSegment(base_addr, (base_addr + len),
                                                protection, "", NULL);
        if (segment == NULL) {
            return -ENOMEM;
        }
    }

    /* Success */
    ret = base_addr;

    return ret;
}
/* ------------------------------------------------------------------------- */
uint64_t linux_syscall_mprotect(uint64_t number, EnvLinux *env,
                    Process* proc, Thread *thread, uint64_t params[6]) {
    uint64_t ret = -1;
    uint64_t addr = params[0];
    uint64_t len = params[1];
    uint64_t prot = params[2];

    LOG("Program called mprotect(%p, %d, %d)", addr, len, prot);

    // TODO : ...
    ret = 0;

    return ret;
}
/* ------------------------------------------------------------------------- */
uint64_t linux_syscall_munmap(uint64_t number, EnvLinux *env,
                    Process* proc, Thread *thread, uint64_t params[6]) {
    uint64_t ret = -1;
    uint64_t addr = params[0];
    uint64_t len = params[1];

    LOG("Program called unmap(%p, %d)", addr, len);

    if (len == 0) {
        return -EINVAL;
    }

    if ((addr & X64CPU_VMEM_PAGE_SIZE) != 0) {
        return -EINVAL;
    }

    proc->removeSegment(addr, (addr + len));
    ret = 0;

    return ret;
}
/* ------------------------------------------------------------------------- */
uint64_t linux_syscall_brk(uint64_t number, EnvLinux *env,
                    Process* proc, Thread *thread, uint64_t params[6]) {
    uint64_t ret = -1;
    uint64_t end_data_segment = params[0];
    DECL_PDATA(proc);

    LOG("Program called brk(%p).", end_data_segment);

    if (end_data_segment == 0) {
        ret = pdata->heap_top;
    }
    else {
        // TODO: ...
    }

    return ret;
}
/* ------------------------------------------------------------------------- */
uint64_t linux_syscall_ioctl(uint64_t number, EnvLinux *env,
                    Process* proc, Thread *thread, uint64_t params[6]) {
    uint64_t ret = -1;
    uint64_t fd = params[0];
    uint64_t cmd = params[1];
    uint64_t args = params[2];

    EnvLinuxIOFile *file = NULL;
    DECL_PDATA(proc);

    LOG("Program called ioctl(%d, 0x%x, %p).", fd, cmd, args);

    GET_FILE(file, fd);

_end:
    return ret;
}
/* ------------------------------------------------------------------------- */
struct x64env_linux_iovec {
    void *iov_base;
    size_t iov_len;
};
uint64_t linux_syscall_writev(uint64_t number, EnvLinux *env,
                    Process* proc, Thread *thread, uint64_t params[6]) {
    uint64_t ret = 0, rc;
    uint64_t fd = params[0];
    uint64_t iovec_ptr = params[1];
    uint64_t vlen = params[2];

    uint64_t i, j, size;
    struct x64env_linux_iovec io;
    EnvLinuxIOFile *file = NULL;
    DECL_PDATA(proc);

    LOG("Program called writev(%d, %p, %d).", fd, iovec_ptr, vlen);

    GET_FILE(file, fd);

    for (i = 0; i < vlen; i++) {
        uint8_t *buffer = NULL;

        rc = x64cpu_vmem_copyfrom(&proc->memory, iovec_ptr, (uint8_t*)&io, sizeof(io));
        if (rc != sizeof(io)) {
            return -EFAULT;
        }

        iovec_ptr += sizeof(io);

        rc = _get_buffer(proc, (uint64_t)io.iov_base, io.iov_len, (uint8_t**)&buffer);
        if (rc != 0) {
            return -EFAULT;
        }

        rc = file->write(buffer, io.iov_len);
        ret += rc;

        free(buffer);
        buffer = NULL;
    }

_end:
    return ret;
}
/* ------------------------------------------------------------------------- */
uint64_t linux_syscall_access(uint64_t number, EnvLinux *env,
                    Process* proc, Thread *thread, uint64_t params[6]) {
    uint64_t ret = -1;
    STR_PARAM(0, pathname, PATH_MAX, 1);
    uint64_t mode = params[1];
    DECL_PDATA(proc);

    LOG("Program called access(\"%s\", %d).", pathname.c_str(), mode);

    ret = pdata->io_manager->access(pathname.c_str(), mode);

    return ret;
}
/* ------------------------------------------------------------------------- */
uint64_t linux_syscall_uname(uint64_t number, EnvLinux *env,
                    Process* proc, Thread *thread, uint64_t params[6]) {
    uint64_t ret = -1;
    uint64_t struct_addr = params[0];
    struct utsname buf;

    memset(&buf, 0, sizeof(buf));
    strncpy(buf.sysname, "Linux", sizeof(buf.sysname));
    strncpy(buf.nodename, "debian", sizeof(buf.nodename));
    strncpy(buf.release, "3.16.0-4-amd64", sizeof(buf.release));
    strncpy(buf.version, "#1 SMP Debian 3.16.7-ckt20-1+deb8u3 (2016-01-17)", sizeof(buf.version));
    strncpy(buf.machine, "x86_64", sizeof(buf.machine));
    // strncpy(buf.__domainname, "(none)", sizeof(buf.__domainname));

    LOG("Program called uname(%p).", struct_addr);

    ret = x64cpu_vmem_copyto(&proc->memory, struct_addr, (uint8_t*)&buf, sizeof(buf));
    if (ret != sizeof(buf)) {
        ret = -EFAULT;
    }

    ret = 0;

    return ret;
}
/* ------------------------------------------------------------------------- */
uint64_t linux_syscall_arch_prctl(uint64_t number, EnvLinux *env,
                    Process* proc, Thread *thread, uint64_t params[6]) {
    uint64_t code = params[0];
    uint64_t addr = params[1];

    uint64_t tmp = 0;
    uint8_t rc;

    LOG("Program called arch_prctl(%d, %p)", code, addr);

    switch (code) {
        case ARCH_SET_FS:
            rc = x64cpu_vmem_read(&proc->memory, addr, (uint8_t*)&tmp, 8, X64CPU_MEM_ACCESS_READ, NULL);
            if (rc != 0) {
                return -EFAULT;
            }
            env->cpu->regs.fs_ptr = tmp;
            break;

        case ARCH_GET_FS:
            tmp = env->cpu->regs.fs_ptr;
            rc = x64cpu_vmem_write(&proc->memory, addr, (uint8_t*)&tmp, 8, X64CPU_MEM_ACCESS_WRITE, NULL);
            if (rc != 0) {
                return -EFAULT;
            }
            break;

        default:
            return -EINVAL;
    }

    return 0;

}
/* ------------------------------------------------------------------------- */
uint64_t linux_syscall_exit_group(uint64_t number, EnvLinux *env,
                    Process* proc, Thread *thread, uint64_t params[6]) {
    uint64_t ret = 0;
    uint64_t exit_code = params[0];
    DECL_PDATA(proc);

    LOG("Program called exit_group(%ld)", exit_code);

    proc->state = Process::ZOMBIE;
    pdata->exit_code = (uint32_t)exit_code;

    LOG("Process %d exited with code %d.", proc->getId(), pdata->exit_code);

    return ret;
}
/* ------------------------------------------------------------------------- */
void EnvLinuxSyscall::installSyscalls(EnvLinux::syscall_handler_t handlers[256]) {
    /*  0 - read() */
    handlers[0x00] = linux_syscall_read;

    /*  1 - write() */
    handlers[0x01] = linux_syscall_write;

    /*  2 - open() */
    handlers[0x02] = linux_syscall_open;

    /*  3 - close() */
    handlers[0x03] = linux_syscall_close;

    /*  4 - stat() */
    handlers[0x04] = linux_syscall_stat;

    /*  5 - fstat() */
    handlers[0x05] = linux_syscall_fstat;

    /*  9 - mmap() */
    handlers[0x09] = linux_syscall_mmap;

    /* 10 - mprotect() */
    handlers[0x0a] = linux_syscall_mprotect;

    /* 11 - munmap() */
    handlers[0x0b] = linux_syscall_munmap;

    /* 12 - brk */
    handlers[0x0c] = linux_syscall_brk;

    /* 16 - ioctl() */
    handlers[0x10] = linux_syscall_ioctl;

    /* 20 - writev() */
    handlers[0x14] = linux_syscall_writev;

    /* 21 - access() */
    handlers[0x15] = linux_syscall_access;

    /* 63 - uname() */
    handlers[0x3f] = linux_syscall_uname;

    /* 158 - arch_prctl() */
    handlers[0x9e] = linux_syscall_arch_prctl;

    /* 231 - exit_group() */
    handlers[0xe7] = linux_syscall_exit_group;
}
/* ------------------------------------------------------------------------- */

