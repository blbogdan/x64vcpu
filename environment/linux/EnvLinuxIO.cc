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

#include "EnvLinuxIO.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>


/* ------------------------------------------------------------------------- */
EnvLinuxIOFile::~EnvLinuxIOFile() {
}
/* ------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------- */
class NativeIOFile : public EnvLinuxIOFile {
public:
    NativeIOFile(int fd) { this->fd = fd; }

    virtual ~NativeIOFile() { close(); }

public:
    void close() {
        if (this->fd != -1) {
            ::close(this->fd);
            this->fd = -1;
        }
    }

    ssize_t read(void *buf, size_t count) {
        return ::read(this->fd, buf, count);
    }

    ssize_t write(void *buf, size_t count) {
        return -EPERM;
    }

    int fstat(struct stat *statbuf) {
        return ::fstat(this->fd, statbuf);
    }

    ssize_t seek(off_t offset, int whence) {
        return ::lseek(this->fd, offset, whence);
    }

    int ioctl(unsigned long request, void *argp) {
        return -ENOTTY;
    }

private:
    int fd;

};
/* ------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------- */
EnvLinuxIO::EnvLinuxIO() {
}
/* ------------------------------------------------------------------------- */
EnvLinuxIO::~EnvLinuxIO() {
}
/* ------------------------------------------------------------------------- */
int EnvLinuxIO::access(const char *pathname, int mode) {
    return ::access(pathname, mode);
}
/* ------------------------------------------------------------------------- */
int EnvLinuxIO::stat(const char *path, struct stat *statbuf) {
    return ::stat(path, statbuf);
}
/* ------------------------------------------------------------------------- */
int EnvLinuxIO::open(const char *pathname, int flags, mode_t mode, EnvLinuxIOFile **file) {
    int ret = -1;
    const char *allowed[] = {
        "/etc/ld.so.nohwcap",
        "/etc/ld.so.preload",
        "/etc/ld.so.cache",
        "/lib/",
        "/lib64/",
        "/lib/x86_64-linux-gnu/",
        "/usr/lib/",
        "/usr/lib/x86_64-linux-gnu/",
        NULL
    };
    const char **p;
    int allow = 0;

    p = allowed;
    while (*p) {
        if (strncmp(*p, pathname, strlen(*p)) == 0) {
            allow = 1;
            break;
        }
        p++;
    }

    if (!allow) {
        return -ENOENT;
    }

    flags &= ~(O_WRONLY | O_RDWR);
    flags |= O_RDONLY;

    ret = ::open(pathname, flags, mode);
    if (ret == -1) {
        return -errno;
    }

    (*file) = new NativeIOFile(ret);
    {
#if 0
        char *tmp = strdupa(pathname);
        (*file)->name = basename(tmp);
#else
        (*file)->name = pathname;
#endif
    }
    ret = 0;

    return ret;
}
/* ------------------------------------------------------------------------- */
int EnvLinuxIO::mapHostPath(const char *dest, const char *src, int flags) {
    return -1;
}
/* ------------------------------------------------------------------------- */

