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

#include "Buffer.h"

#include <ncurses.h>
#include <stdarg.h>


/* ------------------------------------------------------------------------- */
Buffer::Buffer(int rows, int cols, int max_scrollback) {
    this->rows = rows;
    this->cols = cols;
    this->max_scrollback = max_scrollback;
    this->current_line = "";
    this->scroll_amount = 0;

    this->ncurses_window = NULL;
    this->buffer = "";
    this->buffer.reserve(8192);
    this->flush_level = 8192;
}
/* ------------------------------------------------------------------------- */
Buffer::~Buffer() {
}
/* ------------------------------------------------------------------------- */
void Buffer::setWindow(void *ncurses_window) {
    this->ncurses_window = ncurses_window;
    this->refresh();
}
/* ------------------------------------------------------------------------- */
void Buffer::nl() {
    int limit;

    lines.push_back(this->current_line);
    this->current_line = "";

    limit = this->max_scrollback + this->rows;
    while (lines.size() > limit) {
        lines.pop_front();
    }
}
/* ------------------------------------------------------------------------- */
int Buffer::printf(const char *fmt, ...) {
    int rc;
    va_list args;
    char *buffer = NULL;
    int i;
    char c;

    va_start(args, fmt);
    rc = vasprintf(&buffer, fmt, args);
    va_end(args);

    if (this->max_scrollback == 0) {
        if (this->ncurses_window != NULL) {
            this->buffer.append(buffer);
            if (this->buffer.size() >= this->flush_level) {
                this->flush();
            }
        }

        return rc;
    }

    for (i = 0; i < rc; i++) {
        c = buffer[i];

        if (c == '\n' || (this->current_line.size() >= this->cols)) {
            this->nl();
        }

        if (c != '\n') {
            this->current_line.push_back(c);
        }

        if (this->ncurses_window != NULL && this->scroll_amount == 0) {
            this->buffer.push_back(c);
        }
    }

    if (this->buffer.size() >= this->flush_level) {
        this->flush();
    }

    return rc;
}
/* ------------------------------------------------------------------------- */
void Buffer::flush() {
    if (this->buffer.size() < 1 || this->ncurses_window == NULL) {
        return;
    }

    wprintw((WINDOW*)this->ncurses_window, "%s", this->buffer.c_str());
    this->buffer = "";
    wrefresh((WINDOW*)this->ncurses_window);
}
/* ------------------------------------------------------------------------- */
void Buffer::clear() {
    this->lines.clear();
    this->current_line = "";
    this->scrollReset();

    if (this->ncurses_window != NULL) {
        werase((WINDOW*)this->ncurses_window);
        wmove((WINDOW*)this->ncurses_window, 0, 0);
        wrefresh((WINDOW*)this->ncurses_window);
        this->buffer = "";
    }
}
/* ------------------------------------------------------------------------- */
void Buffer::reset_pos() {
    if (this->ncurses_window != NULL) {
        this->flush();
        wmove((WINDOW*)this->ncurses_window, 0, 0);
    }
}
/* ------------------------------------------------------------------------- */
void Buffer::refresh() {
    WINDOW *wnd;
    int i, go_back;
    LinesBuffer::reverse_iterator itr;

    if (this->ncurses_window == NULL) {
        return;
    }

    /* Nothing to refresh */
    if (this->max_scrollback == 0) {
        this->flush();
        return;
    }

    wnd = (WINDOW*)this->ncurses_window;

    this->buffer = "";
    werase(wnd);
    wmove(wnd, 0, 0);

    go_back = (this->rows + this->scroll_amount);
    for (itr = lines.rbegin(), i = 0; itr != lines.rend() && i < go_back; ++itr,i++);

    for (i = 0; i < this->rows && itr != lines.rbegin(); --itr, i++) {
        wprintw(wnd, "%s\n", (*itr).c_str());
    }
    if (itr != lines.rend()) {
        wprintw(wnd, "%s\n", (*itr).c_str());
    }

    if (this->scroll_amount == 0) {
        wprintw(wnd, "%s\n", this->current_line.c_str());
    }

    wrefresh(wnd);
}
/* ------------------------------------------------------------------------- */
void Buffer::scrollUp(int amount) {
    int limit;

    if (this->lines.size() < this->rows) {
        return;
    }

    limit = (this->lines.size() - this->rows) + 1;

    this->scroll_amount += amount;

    if (this->scroll_amount > limit) {
        this->scroll_amount = limit;
    }

    this->refresh();
}
/* ------------------------------------------------------------------------- */
void Buffer::scrollDown(int amount) {
    this->scroll_amount -= amount;
    if (this->scroll_amount < 0) {
        this->scroll_amount = 0;
    }

    this->refresh();
}
/* ------------------------------------------------------------------------- */
void Buffer::scrollReset() {
    this->scroll_amount = 0;
    this->refresh();
}
/* ------------------------------------------------------------------------- */

