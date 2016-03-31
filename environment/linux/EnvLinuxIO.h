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

#ifndef __ENVIRONMENT_LINUX_IO_H__
#define __ENVIRONMENT_LINUX_IO_H__

#include <unistd.h>
#include <sys/types.h>

#include <string>

class EnvLinuxIO;

class EnvLinuxIOFile {
public:
    virtual ~EnvLinuxIOFile();

    virtual void close() = 0;
    virtual ssize_t read(void *buf, size_t count) = 0;
    virtual ssize_t write(void *buf, size_t count) = 0;
    virtual int fstat(struct stat *statbuf) = 0;
    virtual ssize_t seek(off_t offset, int whence) = 0;
    virtual int ioctl(unsigned long request, void *argp) = 0;

public:
    std::string name;
};

class EnvLinuxIO {
public:
    enum Flags {
        FLAG_NONE = 0,
    };

public:
    EnvLinuxIO();

    virtual ~EnvLinuxIO();

public:
    int access(const char *pathname, int mode);

    int stat(const char *path, struct stat *statbuf);

    int open(const char *pathname, int flags, mode_t mode, EnvLinuxIOFile **file);

public:
    int mapHostPath(const char *dest, const char *src, int flags);

private:

};

#endif /* __ENVIRONMENT_LINUX_IO_H__ */

