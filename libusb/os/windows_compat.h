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

/* 
 * Prevent compilation problems on Windows platforms
 *
 * This is placed in the .h to limit changes required to the core files
 */
#ifdef interface
#undef interface
#endif

#define MAX_FDS     256

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

// access modes
enum rw_type {
	RW_NONE,
	RW_READ,
	RW_WRITE,
};

// fd struct that can be used for polling on Windows
struct winfd {
	int fd;                  // what's exposed to libusb core
	HANDLE handle;           // what we need to attach overlapped to the I/O op, so we can poll it
	OVERLAPPED* overlapped;  // what will report our I/O status
	enum rw_type rw;         // I/O transfer direction: read *XOR* write (NOT BOTH)
};
extern const struct winfd INVALID_WINFD;

int pipe_for_poll(int pipefd[2]);
int poll(struct pollfd *fds, unsigned int nfds, int timeout);
ssize_t write_for_poll(int fd, const void *buf, size_t count);
ssize_t read_for_poll(int fd, void *buf, size_t count);
int close_for_poll(int fd);

void init_polling(void);
void exit_polling(void);
struct winfd create_fd_for_poll(HANDLE handle, int access_mode);
void free_fd_for_poll(int fd);
void free_overlapped_for_poll(int fd);
struct winfd fd_to_winfd(int fd);
struct winfd handle_to_winfd(HANDLE handle);
struct winfd overlapped_to_winfd(OVERLAPPED* overlapped);

#ifndef TIMESPEC_TO_TIMEVAL
#define TIMESPEC_TO_TIMEVAL(tv, ts) { \
(tv)->tv_sec = (ts)->tv_sec; \
(tv)->tv_usec = (ts)->tv_nsec / 1000; \
}
#endif
