/* -*- Mode: C; c-basic-offset:8 ; indent-tabs-mode:t -*- */
/*
 * Linux usbfs backend for libusb
 * Copyright (C) 2007-2009 Daniel Drake <dsd@gentoo.org>
 * Copyright (c) 2001 Johannes Erdfelt <johannes@erdfelt.com>
 * Copyright (c) 2013 Nathan Hjelm <hjelmn@mac.com>
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

#include <config.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#ifdef HAVE_ASM_TYPES_H
#include <asm/types.h>
#endif

#include <sys/socket.h>
#include <linux/netlink.h>

#include "libusbi.h"
#include "linux_usbfs.h"

#define KERNEL 1

static int linux_netlink_socket = -1;
static int netlink_control_pipe[2] = { -1, -1 };
static pthread_t libusb_linux_event_thread;

static void *linux_netlink_event_thread_main(void *arg);

static struct sockaddr_nl snl = { .nl_family = AF_NETLINK, .nl_groups = KERNEL };

static int set_fd_cloexec_nb(int fd)
{
	int flags;

#if defined(FD_CLOEXEC)
	flags = fcntl(fd, F_GETFD);
	if (flags == -1) {
		usbi_err(NULL, "failed to get netlink fd flags (%d)", errno);
		return -1;
	}

	if (!(flags & FD_CLOEXEC)) {
		if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1) {
			usbi_err(NULL, "failed to set netlink fd flags (%d)", errno);
			return -1;
		}
	}
#endif

	flags = fcntl(fd, F_GETFL);
	if (flags == -1) {
		usbi_err(NULL, "failed to get netlink fd status flags (%d)", errno);
		return -1;
	}

	if (!(flags & O_NONBLOCK)) {
		if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
			usbi_err(NULL, "failed to set netlink fd status flags (%d)", errno);
			return -1;
		}
	}

	return 0;
}

int linux_netlink_start_event_monitor(void)
{
	int socktype = SOCK_RAW;
	int ret;

#if defined(SOCK_CLOEXEC)
	socktype |= SOCK_CLOEXEC;
#endif
#if defined(SOCK_NONBLOCK)
	socktype |= SOCK_NONBLOCK;
#endif

	linux_netlink_socket = socket(PF_NETLINK, socktype, NETLINK_KOBJECT_UEVENT);
	if (linux_netlink_socket == -1 && errno == EINVAL) {
		usbi_dbg("failed to create netlink socket of type %d, attempting SOCK_RAW", socktype);
		linux_netlink_socket = socket(PF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);
	}

	if (linux_netlink_socket == -1) {
		usbi_err(NULL, "failed to create netlink socket (%d)", errno);
		goto err;
	}

	ret = set_fd_cloexec_nb(linux_netlink_socket);
	if (ret == -1)
		goto err_close_socket;

	ret = bind(linux_netlink_socket, (struct sockaddr *)&snl, sizeof(snl));
	if (ret == -1) {
		usbi_err(NULL, "failed to bind netlink socket (%d)", errno);
		goto err_close_socket;
	}

	/* TODO -- add authentication */
	/* setsockopt(linux_netlink_socket, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one)); */

	ret = usbi_pipe(netlink_control_pipe);
	if (ret) {
		usbi_err(NULL, "failed to create netlink control pipe");
		goto err_close_socket;
	}

	ret = pthread_create(&libusb_linux_event_thread, NULL, linux_netlink_event_thread_main, NULL);
	if (ret != 0) {
		usbi_err(NULL, "failed to create netlink event thread (%d)", ret);
		goto err_close_pipe;
	}

	return LIBUSB_SUCCESS;

err_close_pipe:
	close(netlink_control_pipe[0]);
	close(netlink_control_pipe[1]);
	netlink_control_pipe[0] = -1;
	netlink_control_pipe[1] = -1;
err_close_socket:
	close(linux_netlink_socket);
	linux_netlink_socket = -1;
err:
	return LIBUSB_ERROR_OTHER;
}

int linux_netlink_stop_event_monitor(void)
{
	char dummy = 1;
	ssize_t r;

	assert(linux_netlink_socket != -1);

	/* Write some dummy data to the control pipe and
	 * wait for the thread to exit */
	r = usbi_write(netlink_control_pipe[1], &dummy, sizeof(dummy));
	if (r <= 0)
		usbi_warn(NULL, "netlink control pipe signal failed");

	pthread_join(libusb_linux_event_thread, NULL);

	close(linux_netlink_socket);
	linux_netlink_socket = -1;

	/* close and reset control pipe */
	close(netlink_control_pipe[0]);
	close(netlink_control_pipe[1]);
	netlink_control_pipe[0] = -1;
	netlink_control_pipe[1] = -1;

	return LIBUSB_SUCCESS;
}

static const char *netlink_message_parse(const char *buffer, size_t len, const char *key)
{
	size_t keylen = strlen(key);
	size_t offset;

	for (offset = 0; offset < len && buffer[offset] != '\0'; offset += strlen(buffer + offset) + 1) {
		if (strncmp(buffer + offset, key, keylen) == 0 &&
			buffer[offset + keylen] == '=') {
			return buffer + offset + keylen + 1;
		}
	}

	return NULL;
}

/* parse parts of netlink message common to both libudev and the kernel */
static int linux_netlink_parse(const char *buffer, size_t len, int *detached,
	const char **sys_name, uint8_t *busnum, uint8_t *devaddr)
{
	const char *tmp;
	int i;

	errno = 0;

	*sys_name = NULL;
	*detached = 0;
	*busnum   = 0;
	*devaddr  = 0;

	tmp = netlink_message_parse(buffer, len, "ACTION");
	if (!tmp) {
		return -1;
	} else if (strcmp(tmp, "remove") == 0) {
		*detached = 1;
	} else if (strcmp(tmp, "add") != 0) {
		usbi_dbg("unknown device action %s", tmp);
		return -1;
	}

	/* check that this is a usb message */
	tmp = netlink_message_parse(buffer, len, "SUBSYSTEM");
	if (!tmp || strcmp(tmp, "usb") != 0) {
		/* not usb. ignore */
		return -1;
	}

	/* check that this is an actual usb device */
	tmp = netlink_message_parse(buffer, len, "DEVTYPE");
	if (!tmp || strcmp(tmp, "usb_device") != 0) {
		/* not usb. ignore */
		return -1;
	}

	tmp = netlink_message_parse(buffer, len, "BUSNUM");
	if (!tmp) {
		/* no bus number. try "DEVICE" */
		tmp = netlink_message_parse(buffer, len, "DEVICE");
		if (!tmp) {
			/* not usb. ignore */
			return -1;
		}

		/* Parse a device path such as /dev/bus/usb/003/004 */
		const char *pLastSlash = strrchr(tmp, '/');
		if (!pLastSlash)
			return -1;

		*busnum = (uint8_t)(strtoul(pLastSlash - 3, NULL, 10) & 0xff);
		if (errno) {
			errno = 0;
			return -1;
		}

		*devaddr = (uint8_t)(strtoul(pLastSlash + 1, NULL, 10) & 0xff);
		if (errno) {
			errno = 0;
			return -1;
		}

		return 0;
	}

	*busnum = (uint8_t)(strtoul(tmp, NULL, 10) & 0xff);
	if (errno) {
		errno = 0;
		return -1;
	}

	tmp = netlink_message_parse(buffer, len, "DEVNUM");
	if (!tmp)
		return -1;

	*devaddr = (uint8_t)(strtoul(tmp, NULL, 10) & 0xff);
	if (errno) {
		errno = 0;
		return -1;
	}

	tmp = netlink_message_parse(buffer, len, "DEVPATH");
	if (!tmp)
		return -1;

	for (i = strlen(tmp) - 1; i; --i) {
		if (tmp[i] == '/') {
			*sys_name = tmp + i + 1;
			break;
		}
	}

	/* found a usb device */
	return 0;
}

static int linux_netlink_read_message(void)
{
	char buffer[1024];
	const char *sys_name = NULL;
	uint8_t busnum, devaddr;
	int detached, r;
	ssize_t len;
	struct iovec iov = { .iov_base = buffer, .iov_len = sizeof(buffer) };
	struct msghdr meh = {
		.msg_iov = &iov, .msg_iovlen = 1,
		.msg_name = &snl, .msg_namelen = sizeof(snl)
	};

	/* read netlink message */
	memset(buffer, 0, sizeof(buffer));
	len = recvmsg(linux_netlink_socket, &meh, 0);
	if (len < 32) {
		if (errno != EAGAIN)
			usbi_dbg("error receiving message from netlink");
		return -1;
	}

	/* TODO -- authenticate this message is from the kernel or udevd */

	r = linux_netlink_parse(buffer, (size_t)len, &detached, &sys_name, &busnum, &devaddr);
	if (r)
		return r;

	usbi_dbg("netlink hotplug found device busnum: %hhu, devaddr: %hhu, sys_name: %s, removed: %s",
		 busnum, devaddr, sys_name, detached ? "yes" : "no");

	/* signal device is available (or not) to all contexts */
	if (detached)
		linux_device_disconnected(busnum, devaddr);
	else
		linux_hotplug_enumerate(busnum, devaddr, sys_name);

	return 0;
}

static void *linux_netlink_event_thread_main(void *arg)
{
	char dummy;
	ssize_t r;
	struct pollfd fds[] = {
		{ .fd = netlink_control_pipe[0],
		  .events = POLLIN },
		{ .fd = linux_netlink_socket,
		  .events = POLLIN },
	};

	UNUSED(arg);

	usbi_dbg("netlink event thread entering");

	while (poll(fds, 2, -1) >= 0) {
		if (fds[0].revents & POLLIN) {
			/* activity on control pipe, read the byte and exit */
			r = usbi_read(netlink_control_pipe[0], &dummy, sizeof(dummy));
			if (r <= 0)
				usbi_warn(NULL, "netlink control pipe read failed");
			break;
		}
		if (fds[1].revents & POLLIN) {
			usbi_mutex_static_lock(&linux_hotplug_lock);
			linux_netlink_read_message();
			usbi_mutex_static_unlock(&linux_hotplug_lock);
		}
	}

	usbi_dbg("netlink event thread exiting");

	return NULL;
}

void linux_netlink_hotplug_poll(void)
{
	int r;

	usbi_mutex_static_lock(&linux_hotplug_lock);
	do {
		r = linux_netlink_read_message();
	} while (r == 0);
	usbi_mutex_static_unlock(&linux_hotplug_lock);
}
