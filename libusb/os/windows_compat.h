/*
 * Windows compat: POSIX compatibility wrapper
 * Copyright (C) 2009 Pete Batard <pbatard@gmail.com>
 *
 * Parts of poll implementation from libusb-win32, by Stephan Meyer et al.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */
#pragma once

#define MAX_FDS 256

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
typedef unsigned int nfds_t;

#define poll(x, y, z) libusb_poll(x, y, z)
#define pipe(x) libusb_pipe(x)

int libusb_pipe(int pipefd[2]);
int libusb_poll(struct pollfd *fds, unsigned int nfds, int timeout);
int create_overlapped(void* pollfds_lock);
void free_overlapped(int fd);
void *fd_to_overlapped(int fd);
int overlapped_to_fd(void* overlapped);
void init_overlapped(void);

#ifndef TIMESPEC_TO_TIMEVAL
#define TIMESPEC_TO_TIMEVAL(tv, ts) { \
(tv)->tv_sec = (ts)->tv_sec; \
(tv)->tv_usec = (ts)->tv_nsec / 1000; \
}
#endif
