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

#if defined(_MSC_VER)
// disable /W4 MSVC warnings that are benign
#pragma warning(disable:4127) // conditional expression is constant
#endif

#if !defined(ssize_t)
#if defined (_WIN64)
#define ssize_t __int64
#else
#define ssize_t long
#endif
#endif

enum windows_version {
	WINDOWS_UNSUPPORTED,
	WINDOWS_XP,
	WINDOWS_VISTA_AND_LATER,
};
extern enum windows_version windows_version;

#define MAX_FDS     256

#define POLLIN      0x0001    /* There is data to read */
#define POLLPRI     0x0002    /* There is urgent data to read */
#define POLLOUT     0x0004    /* Writing now will not block */
#define POLLERR     0x0008    /* Error condition */
#define POLLHUP     0x0010    /* Hung up */
#define POLLNVAL    0x0020    /* Invalid request: fd not open */

struct pollfd {
    int fd;           /* file descriptor */
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
	int fd;				            // what's exposed to libusb core
	HANDLE handle;                  // what we need to attach overlapped to the I/O op, so we can poll it
	OVERLAPPED* overlapped;         // what will report our I/O status
	enum rw_type rw;                // I/O transfer direction: read *XOR* write (NOT BOTH)
	BOOLEAN completed_synchronously;// flag for async transfers that completed during request
};
extern const struct winfd INVALID_WINFD;

int _libusb_pipe(int pipefd[2]);
int _libusb_poll(struct pollfd *fds, unsigned int nfds, int timeout);
ssize_t _libusb_write(int fd, const void *buf, size_t count);
ssize_t _libusb_read(int fd, void *buf, size_t count);
int _libusb_close(int fd);

void init_polling(void);
void exit_polling(void);
struct winfd _libusb_create_fd(HANDLE handle, int access_mode);
void _libusb_free_fd(int fd);
struct winfd fd_to_winfd(int fd);
struct winfd handle_to_winfd(HANDLE handle);
struct winfd overlapped_to_winfd(OVERLAPPED* overlapped);

// When building using the MSDDK and sources
#if defined(DDKBUILD)
#if !defined(timeval)
struct timeval {
        long    tv_sec;         /* seconds */
        long    tv_usec;        /* and microseconds */
};
#endif

#if !defined(timerisset)
#define timerisset(tvp)         ((tvp)->tv_sec || (tvp)->tv_usec)
#endif

#if !defined(timercmp)
#define timercmp(tvp, uvp, cmp) \
        ((tvp)->tv_sec cmp (uvp)->tv_sec || \
         (tvp)->tv_sec == (uvp)->tv_sec && (tvp)->tv_usec cmp (uvp)->tv_usec)
#endif

#if !defined(timerclr)
#define timerclear(tvp)         (tvp)->tv_sec = (tvp)->tv_usec = 0
#endif
#endif

#if !defined(TIMESPEC_TO_TIMEVAL)
#define TIMESPEC_TO_TIMEVAL(tv, ts) {                   \
	(tv)->tv_sec = (long)(ts)->tv_sec;                  \
	(tv)->tv_usec = (long)(ts)->tv_nsec / 1000;         \
}
#endif
#if !defined(timersub)
#define timersub(a, b, result)                          \
do {                                                    \
	(result)->tv_sec = (a)->tv_sec - (b)->tv_sec;       \
	(result)->tv_usec = (a)->tv_usec - (b)->tv_usec;    \
	if ((result)->tv_usec < 0) {                        \
		--(result)->tv_sec;                             \
		(result)->tv_usec += 1000000;                   \
	}                                                   \
} while (0)
#endif
