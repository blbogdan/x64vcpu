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

#ifndef __WINDOW_H__
#define __WINDOW_H__

#include "Buffer.h"

#include <ncurses.h>

class Window {
public:
    Window(const char *title, int cols, int rows, int x, int y);

    ~Window();

public:
    int scanw(const char *fmt, ...);

    void update();

    void attachBuffer(Buffer* console);

    void focus(bool focused);

    inline int getRows() const { return rows; }
    inline int getCols() const { return cols; }

    inline void scrollUp(int amount) {
        if (this->console) {
            this->console->scrollUp(amount);
        }
    }
    inline void scrollDown(int amount) {
        if (this->console) {
            this->console->scrollDown(amount);
        }
    }
    inline void scrollReset() {
        if (this->console) {
            this->console->scrollReset();
        }
    }

private:
    void _redrawFrame();

    std::string title;
    int x, y;
    int rows, cols;
    bool focused;

    WINDOW* frame;
    WINDOW* content;
    Buffer *console;

};

#endif /* __WINDOW_H__ */

