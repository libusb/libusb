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
 * parts of poll implementation from libusb-win32 v1, by Stephan Meyer et al.
 *
 */
#pragma once

/* 
 * Copied from linux man pages.
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
#define poll(x, y, z) windows_poll(x, y, z)

typedef unsigned int nfds_t;
int pipe(int pipefd[2]);
int windows_poll(struct pollfd *fds, unsigned int nfds, int timeout);

#ifndef TIMESPEC_TO_TIMEVAL
#define TIMESPEC_TO_TIMEVAL(tv, ts) { \
(tv)->tv_sec = (ts)->tv_sec; \
(tv)->tv_usec = (ts)->tv_nsec / 1000; \
}
#endif
