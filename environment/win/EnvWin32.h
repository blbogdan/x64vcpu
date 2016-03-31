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

#ifndef __ENVIRONMENT_WIN32_H__
#define __ENVIRONMENT_WIN32_H__

#include "../Environment.h"


class EnvWin32 : public Environment {
public:
    EnvWin32();

    virtual ~EnvWin32();

public:
    virtual void handleProcessNew(Process *process);
    virtual void handleProcessDestroy(Process *process);
    virtual void handleThreadNew(Thread *thread);
    virtual void handleThreadDestroy(Thread *thread);

    virtual void handleProcessMemoryFault(Thread *thread, int code, uint64_t address);

};

#endif /* __ENVIRONMENT_WIN32_H__ */

