/*
 * signalfd header
 * Copyright (C) 2007 Daniel Drake <dsd@gentoo.org>
 *
 * Based on glibc header
 * Copyright (C) 2007 Free Software Foundation, Inc.
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
 */

#ifndef __FPUSB_SIGNALFD_H__
#define __FPUSB_SIGNALFD_H__

/* FIXME: in future, remove this and unconditionally use glibc directly when
 * glibc-2.8 is widespread */

#include <signal.h>
#include <stdint.h>

#ifdef __i386__
#define __NR_signalfd 321
#elif defined(__x86_64__)
#define __NR_signalfd 282
#else
#error "signalfd unsupported on this architecture"
#endif

/* signalfd() implementation was added as of glibc-2.7 */
#if __GLIBC_PREREQ(2, 7)
int signalfd(int fd, const sigset_t *mask, int flags);
#else
#include <sys/syscall.h>

#define SIZEOF_SIG (_NSIG / 8)
#define SIZEOF_SIGSET (SIZEOF_SIG > sizeof(sigset_t) ? sizeof(sigset_t): SIZEOF_SIG)

static inline int signalfd(int fd, const sigset_t *mask, int flags)
{
	return syscall(__NR_signalfd, fd, mask, SIZEOF_SIGSET);
}
#endif

struct signalfd_siginfo {
	uint32_t ssi_signo;
	int32_t ssi_errno;
	int32_t ssi_code;
	uint32_t ssi_pid;
	uint32_t ssi_uid;
	int32_t ssi_fd;
	uint32_t ssi_tid;
	uint32_t ssi_band;
	uint32_t ssi_overrun;
	uint32_t ssi_trapno;
	int32_t ssi_status;
	int32_t ssi_int;
	uint64_t ssi_ptr;
	uint64_t ssi_utime;
	uint64_t ssi_stime;
	uint64_t ssi_addr;
	uint8_t __pad[48];
};

#endif

