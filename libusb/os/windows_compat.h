/*
 * Windows compat: POSIX compatibility wrapper
 *
 * pipe implementation from mlton (http://www.mlton.org - runtime/platform/mingw.h):
 * -----------------------------------------------------------------------------
 * This is the license for MLton, a whole-program optimizing compiler for
 * the Standard ML programming language.  Send comments and questions to
 * MLton@mlton.org.
 *
 * MLton COPYRIGHT NOTICE, LICENSE AND DISCLAIMER.
 *
 * Copyright (C) 1999-2009 Henry Cejtin, Matthew Fluet, Suresh
 *    Jagannathan, and Stephen Weeks.
 * Copyright (C) 1997-2000 by the NEC Research Institute
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted,
 * provided that the above copyright notice appear in all copies and that
 * both the copyright notice and this permission notice and warranty
 * disclaimer appear in supporting documentation, and that the name of
 * the above copyright holders, or their entities, not be used in
 * advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission.

 * The above copyright holders disclaim all warranties with regard to
 * this software, including all implied warranties of merchantability and
 * fitness. In no event shall the above copyright holders be liable for
 * any special, indirect or consequential damages or any damages
 * whatsoever resulting from loss of use, data or profits, whether in an
 * action of contract, negligence or other tortious action, arising out
 * of or in connection with the use or performance of this software.
 * -----------------------------------------------------------------------------
 *
 *
 * poll implementation from polipo (http://www.pps.jussieu.fr/~jch/software/polipo/):
 * -----------------------------------------------------------------------------
 * Copyright (c) 2006 by Dan Kennedy.
 * Copyright (c) 2006 by Juliusz Chroboczek.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 * -----------------------------------------------------------------------------
 */
#pragma once

/* winsock doesn't feature poll(), so there is a version implemented
 * in terms of select() in mingw.c. The following definitions
 * are copied from linux man pages. A poll() macro is defined to
 * call the version in mingw.c.
 */
#define POLLIN      0x0001    /* There is data to read */
#define POLLPRI     0x0002    /* There is urgent data to read */
#define POLLOUT     0x0004    /* Writing now will not block */
#define POLLERR     0x0008    /* Error condition */
#define POLLHUP     0x0010    /* Hung up */
#define POLLNVAL    0x0020    /* Invalid request: fd not open */

struct pollfd {
    unsigned int fd;  /* file descriptor */
    short events;     /* requested events */
    short revents;    /* returned events */
};
#define poll(x, y, z)        mingw_poll(x, y, z)

typedef unsigned int nfds_t;
int pipe(int pipefd[2]);
int mingw_poll(struct pollfd *fds, unsigned int nfds, int timo);

#ifndef TIMESPEC_TO_TIMEVAL
#define TIMESPEC_TO_TIMEVAL(tv, ts) { \
(tv)->tv_sec = (ts)->tv_sec; \
(tv)->tv_usec = (ts)->tv_nsec / 1000; \
}
#endif
