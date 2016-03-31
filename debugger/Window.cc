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

#include "Window.h"

#include <ncurses.h>


/* ------------------------------------------------------------------------- */
Window::Window(const char *title, int rows, int cols, int x, int y) {
    this->title = title;
    this->rows = rows;
    this->cols = cols;
    this->x = x;
    this->y = y;
    this->focused = false;

    this->frame = newwin(this->rows, this->cols, this->y, this->x);
    box(this->frame, 0, 0);
    wrefresh(this->frame);

    this->content = derwin(this->frame, this->rows - 2, this->cols - 2, 1, 1);
    scrollok(this->content, TRUE);
    wmove(this->content, 0, 0);

    this->console = NULL;
}
/* ------------------------------------------------------------------------- */
Window::~Window() {
    // TODO: destroy ncurses windows
}
/* ------------------------------------------------------------------------- */
int Window::scanw(const char *fmt, ...) {
    int ret = -1;
    va_list vargs;

    va_start(vargs, fmt);
    ret = vwscanw(this->content, fmt, vargs);
    va_end(vargs);

    return ret;
}
/* ------------------------------------------------------------------------- */
void Window::attachBuffer(Buffer* console) {
    if (this->console != NULL) {
        this->console->setWindow(NULL);
        this->console = NULL;
    }

    this->console = console;
    if (this->console != NULL) {
        this->console->setWindow(this->content);
    }
}
/* ------------------------------------------------------------------------- */
void Window::focus(bool focused) {
    this->focused = focused;
    this->_redrawFrame();
}
/* ------------------------------------------------------------------------- */
void Window::_redrawFrame() {
    box(this->frame, 0, 0);

    if (this->title.size() > 0) {
        if (this->focused) {
            wattron(this->frame, A_BOLD);
        }
        mvwprintw(this->frame, 0, 3, " %s ", this->title.c_str());
        if (this->focused) {
            wattroff(this->frame, A_BOLD);
        }
    }

    wrefresh(this->frame);
}
/* ------------------------------------------------------------------------- */
void Window::update() {
    werase(this->frame);

    this->_redrawFrame();

    if (this->console != NULL) {
        this->console->refresh();
    }
}
/* ------------------------------------------------------------------------- */

