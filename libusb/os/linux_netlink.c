/* -*- Mode: C; c-basic-offset:8 ; indent-tabs-mode:t -*- */
/*
 * Linux usbfs backend for libusb
 * Copyright (C) 2007-2009 Daniel Drake <dsd@gentoo.org>
 * Copyright (c) 2001 Johannes Erdfelt <johannes@erdfelt.com>
 * Copyright (c) 2013 Nathan Hjelm <hjelmn@mac.com>
 * Copyright (c) 2016 Chris Dickens <christopher.a.dickens@gmail.com>
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

#include "libusbi.h"
#include "linux_usbfs.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_ASM_TYPES_H
#include <asm/types.h>
#endif
#include <sys/socket.h>
#include <linux/netlink.h>

#define NL_GROUP_KERNEL 1

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC	0
#endif

#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK	0
#endif

static int linux_netlink_socket = -1;
static usbi_event_t netlink_control_event = USBI_INVALID_EVENT;
static pthread_t libusb_linux_event_thread;

static void *linux_netlink_event_thread_main(void *arg);

static int set_fd_cloexec_nb(int fd, int socktype)
{
	int flags;

#if defined(FD_CLOEXEC)
	/* Make sure the netlink socket file descriptor is marked as CLOEXEC */
	if (!(socktype & SOCK_CLOEXEC)) {
		flags = fcntl(fd, F_GETFD);
		if (flags == -1) {
			usbi_err(NULL, "failed to get netlink fd flags, errno=%d", errno);
			return -1;
		}

		if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1) {
			usbi_err(NULL, "failed to set netlink fd flags, errno=%d", errno);
			return -1;
		}
	}
#endif

	/* Make sure the netlink socket is non-blocking */
	if (!(socktype & SOCK_NONBLOCK)) {
		flags = fcntl(fd, F_GETFL);
		if (flags == -1) {
			usbi_err(NULL, "failed to get netlink fd status flags, errno=%d", errno);
			return -1;
		}

		if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
			usbi_err(NULL, "failed to set netlink fd status flags, errno=%d", errno);
			return -1;
		}
	}

	return 0;
}

int linux_netlink_start_event_monitor(void)
{
	struct sockaddr_nl sa_nl = { .nl_family = AF_NETLINK, .nl_groups = NL_GROUP_KERNEL };
	int socktype = SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC;
	int opt = 1;
	int ret;

	linux_netlink_socket = socket(PF_NETLINK, socktype, NETLINK_KOBJECT_UEVENT);
	if (linux_netlink_socket == -1 && errno == EINVAL) {
		usbi_dbg(NULL, "failed to create netlink socket of type %d, attempting SOCK_RAW", socktype);
		socktype = SOCK_RAW;
		linux_netlink_socket = socket(PF_NETLINK, socktype, NETLINK_KOBJECT_UEVENT);
	}

	if (linux_netlink_socket == -1) {
		usbi_err(NULL, "failed to create netlink socket, errno=%d", errno);
		goto err;
	}

	ret = set_fd_cloexec_nb(linux_netlink_socket, socktype);
	if (ret == -1)
		goto err_close_socket;

	ret = bind(linux_netlink_socket, (struct sockaddr *)&sa_nl, sizeof(sa_nl));
	if (ret == -1) {
		usbi_err(NULL, "failed to bind netlink socket, errno=%d", errno);
		goto err_close_socket;
	}

	ret = setsockopt(linux_netlink_socket, SOL_SOCKET, SO_PASSCRED, &opt, sizeof(opt));
	if (ret == -1) {
		usbi_err(NULL, "failed to set netlink socket SO_PASSCRED option, errno=%d", errno);
		goto err_close_socket;
	}

	ret = usbi_create_event(&netlink_control_event);
	if (ret) {
		usbi_err(NULL, "failed to create netlink control event");
		goto err_close_socket;
	}

	ret = pthread_create(&libusb_linux_event_thread, NULL, linux_netlink_event_thread_main, NULL);
	if (ret != 0) {
		usbi_err(NULL, "failed to create netlink event thread (%d)", ret);
		goto err_destroy_event;
	}

	return LIBUSB_SUCCESS;

err_destroy_event:
	usbi_destroy_event(&netlink_control_event);
	netlink_control_event = (usbi_event_t)USBI_INVALID_EVENT;
err_close_socket:
	close(linux_netlink_socket);
	linux_netlink_socket = -1;
err:
	return LIBUSB_ERROR_OTHER;
}

int linux_netlink_stop_event_monitor(void)
{
	int ret;

	assert(linux_netlink_socket != -1);

	/* Signal the control event and wait for the thread to exit */
	usbi_signal_event(&netlink_control_event);

	ret = pthread_join(libusb_linux_event_thread, NULL);
	if (ret)
		usbi_warn(NULL, "failed to join netlink event thread (%d)", ret);

	usbi_destroy_event(&netlink_control_event);
	netlink_control_event = (usbi_event_t)USBI_INVALID_EVENT;

	close(linux_netlink_socket);
	linux_netlink_socket = -1;

	return LIBUSB_SUCCESS;
}

static const char *netlink_message_parse(const char *buffer, size_t len, const char *key)
{
	const char *end = buffer + len;
	size_t keylen = strlen(key);

	while (buffer < end && *buffer) {
		if (strncmp(buffer, key, keylen) == 0 && buffer[keylen] == '=')
			return buffer + keylen + 1;
		buffer += strlen(buffer) + 1;
	}

	return NULL;
}

/* parse parts of netlink message common to both libudev and the kernel */
static int linux_netlink_parse(const char *buffer, size_t len, int *detached,
	const char **sys_name, uint8_t *busnum, uint8_t *devaddr)
{
	const char *tmp, *slash;

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
		usbi_dbg(NULL, "unknown device action %s", tmp);
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
	if (tmp) {
		*busnum = (uint8_t)(strtoul(tmp, NULL, 10) & 0xff);
		if (errno) {
			errno = 0;
			return -1;
		}

		tmp = netlink_message_parse(buffer, len, "DEVNUM");
		if (NULL == tmp)
			return -1;

		*devaddr = (uint8_t)(strtoul(tmp, NULL, 10) & 0xff);
		if (errno) {
			errno = 0;
			return -1;
		}
	} else {
		/* no bus number. try "DEVICE" */
		tmp = netlink_message_parse(buffer, len, "DEVICE");
		if (!tmp) {
			/* not usb. ignore */
			return -1;
		}

		/* Parse a device path such as /dev/bus/usb/003/004 */
		slash = strrchr(tmp, '/');
		if (!slash)
			return -1;

		*busnum = (uint8_t)(strtoul(slash - 3, NULL, 10) & 0xff);
		if (errno) {
			errno = 0;
			return -1;
		}

		*devaddr = (uint8_t)(strtoul(slash + 1, NULL, 10) & 0xff);
		if (errno) {
			errno = 0;
			return -1;
		}

		return 0;
	}

	tmp = netlink_message_parse(buffer, len, "DEVPATH");
	if (!tmp)
		return -1;

	slash = strrchr(tmp, '/');
	if (slash)
		*sys_name = slash + 1;

	/* found a usb device */
	return 0;
}

static int linux_netlink_read_message(void)
{
	char cred_buffer[CMSG_SPACE(sizeof(struct ucred))];
	char msg_buffer[2048];
	const char *sys_name = NULL;
	uint8_t busnum, devaddr;
	int detached, r;
	ssize_t len;
	struct cmsghdr *cmsg;
	struct ucred *cred;
	struct sockaddr_nl sa_nl;
	struct iovec iov = { .iov_base = msg_buffer, .iov_len = sizeof(msg_buffer) };
	struct msghdr msg = {
		.msg_iov = &iov, .msg_iovlen = 1,
		.msg_control = cred_buffer, .msg_controllen = sizeof(cred_buffer),
		.msg_name = &sa_nl, .msg_namelen = sizeof(sa_nl)
	};

	/* read netlink message */
	len = recvmsg(linux_netlink_socket, &msg, 0);
	if (len == -1) {
		if (errno != EAGAIN && errno != EINTR)
			usbi_err(NULL, "error receiving message from netlink, errno=%d", errno);
		return -1;
	}

	if (len < 32 || (msg.msg_flags & MSG_TRUNC)) {
		usbi_err(NULL, "invalid netlink message length");
		return -1;
	}

	if (sa_nl.nl_groups != NL_GROUP_KERNEL || sa_nl.nl_pid != 0) {
		usbi_dbg(NULL, "ignoring netlink message from unknown group/PID (%u/%u)",
			 (unsigned int)sa_nl.nl_groups, (unsigned int)sa_nl.nl_pid);
		return -1;
	}

	cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg || cmsg->cmsg_type != SCM_CREDENTIALS) {
		usbi_dbg(NULL, "ignoring netlink message with no sender credentials");
		return -1;
	}

	cred = (struct ucred *)CMSG_DATA(cmsg);
	if (cred->uid != 0) {
		usbi_dbg(NULL, "ignoring netlink message with non-zero sender UID %u", (unsigned int)cred->uid);
		return -1;
	}

	r = linux_netlink_parse(msg_buffer, (size_t)len, &detached, &sys_name, &busnum, &devaddr);
	if (r)
		return r;

	usbi_dbg(NULL, "netlink hotplug found device busnum: %hhu, devaddr: %hhu, sys_name: %s, removed: %s",
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
	struct pollfd fds[] = {
		{ .fd = USBI_EVENT_OS_HANDLE(&netlink_control_event),
		  .events = USBI_EVENT_POLL_EVENTS },
		{ .fd = linux_netlink_socket,
		  .events = POLLIN },
	};
	int r;

	UNUSED(arg);

#if defined(HAVE_PTHREAD_SETNAME_NP)
	r = pthread_setname_np(pthread_self(), "libusb_event");
	if (r)
		usbi_warn(NULL, "failed to set hotplug event thread name, error=%d", r);
#endif

	usbi_dbg(NULL, "netlink event thread entering");

	while (1) {
		r = poll(fds, 2, -1);
		if (r == -1) {
			/* check for temporary failure */
			if (errno == EINTR)
				continue;
			usbi_err(NULL, "poll() failed, errno=%d", errno);
			break;
		}
		if (fds[0].revents) {
			/* activity on control event, exit */
			break;
		}
		if (fds[1].revents) {
			usbi_mutex_static_lock(&linux_hotplug_lock);
			linux_netlink_read_message();
			usbi_mutex_static_unlock(&linux_hotplug_lock);
		}
	}

	usbi_dbg(NULL, "netlink event thread exiting");

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
