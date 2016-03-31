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

#ifndef __BUFFER_H__
#define __BUFFER_H__

#include <list>
#include <string>


class Buffer {
public:
    Buffer(int rows, int cols, int max_scrollback);

    virtual ~Buffer();

public:
    void setWindow(void *ncurses_window);

    void nl();
    int printf(const char *fmt, ...);

    void flush();

    void clear();
    void reset_pos();
    void refresh();

    void scrollUp(int amount);
    void scrollDown(int amount);
    void scrollReset();

    inline int getHeight() const { return rows; }
    inline int getWidth() const { return cols; }

private:
    int rows, cols;

    int max_scrollback;
    typedef std::list<std::string> LinesBuffer;
    LinesBuffer lines;
    std::string current_line;

    int scroll_amount;

    /* ncurses window */
    void *ncurses_window;
    std::string buffer;

    size_t flush_level;

};

#endif /* __BUFFER_H__ */

