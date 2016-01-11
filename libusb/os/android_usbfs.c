/*
 * Android usbfs backend for libusb
 *
 * Copyright  ©  2016 Eugene Hutorny <eugene@hutorny.in.ua>
 * Copyright (C) 2007-2009 Daniel Drake <dsd@gentoo.org>
 * Copyright (c) 2001 Johannes Erdfelt <johannes@erdfelt.com>
 * Copyright (c) 2014 Shachar Gritzman <gritzman@outlook.com>
 *
 * Refactored as a separate source file for Android OS
 *
 * Modified *find_usbfs_path function to support android SElinux policy and Lollipop,
 * no root is needed.
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

#include "config.h"
#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>
#include "libusbi.h"
#include "android_usbfs.h"

#include "linux_usbfs.c"

// *** PrimeSense patch for Android ***
/* Returns the file descriptor of 'file_name', if it has been opened by the process, or -1 otherwise. */
static int find_fd_by_name(char *file_name)
{
	struct dirent *fd_dirent;
	DIR *proc_fd = opendir("/proc/self/fd");
	int ret = -1;

	while (fd_dirent = readdir(proc_fd))
	{
		char link_file_name[PATH_MAX];
		char fd_file_name[PATH_MAX];

		if (fd_dirent->d_type != DT_LNK)
		{
			continue;
		}

		snprintf(link_file_name, PATH_MAX, "/proc/self/fd/%s", fd_dirent->d_name);

		memset(fd_file_name, 0, sizeof(fd_file_name));
		readlink(link_file_name, fd_file_name, sizeof(fd_file_name) - 1);

		if (!strcmp(fd_file_name, file_name))
		{
			ret = atoi(fd_dirent->d_name);
			usbi_dbg("found %s -> %s", link_file_name, fd_file_name);
			break;
		}
	}

	closedir(proc_fd);

	return ret;
}
// *** PrimeSense patch for Android ***

static void _get_usbfs_path(struct libusb_device *dev, char *path) {
	snprintf(path, PATH_MAX, "%s/%03d/%03d",
			usbfs_path, dev->bus_number, dev->device_address);
}

static int android_open_existing(struct libusb_device_handle *handle) {
	char filename[PATH_MAX];

	_get_usbfs_path(handle->dev, filename);
	usbi_dbg("opening %s", filename);
	return find_fd_by_name(filename);
}

static int android_open(struct libusb_device_handle *handle) {
	struct linux_device_handle_priv *hpriv = _device_handle_priv(handle);
	if( (hpriv->fd = android_open_existing(handle)) > 0 ) {
		return usbi_add_pollfd(HANDLE_CTX(handle), hpriv->fd, POLLOUT);
		// close(hpriv->fd) is not called because it was open not here
	} else {
		return op_open(handle);
	}
}

static int android_init(struct libusb_context *ctx)
{
	struct stat statbuf;
	int r;
	usbfs_path = "/dev/bus/usb";

//	usbfs_path = find_usbfs_path();
//	if (!usbfs_path) {
//		usbi_err(ctx, "could not find usbfs");
//		return LIBUSB_ERROR_OTHER;
//	}

	if (monotonic_clkid == -1)
		monotonic_clkid = find_monotonic_clock();

	if (supports_flag_bulk_continuation == -1) {
		/* bulk continuation URB flag available from Linux 2.6.32 */
		supports_flag_bulk_continuation = kernel_version_ge(2,6,32);
		if (supports_flag_bulk_continuation == -1) {
			usbi_err(ctx, "error checking for bulk continuation support");
			return LIBUSB_ERROR_OTHER;
		}
	}

	if (supports_flag_bulk_continuation)
		usbi_dbg("bulk continuation flag supported");

	if (-1 == supports_flag_zero_packet) {
		/* zero length packet URB flag fixed since Linux 2.6.31 */
		supports_flag_zero_packet = kernel_version_ge(2,6,31);
		if (-1 == supports_flag_zero_packet) {
			usbi_err(ctx, "error checking for zero length packet support");
			return LIBUSB_ERROR_OTHER;
		}
	}

	if (supports_flag_zero_packet)
		usbi_dbg("zero length packet flag supported");

	if (-1 == sysfs_has_descriptors) {
		/* sysfs descriptors has all descriptors since Linux 2.6.26 */
		sysfs_has_descriptors = kernel_version_ge(2,6,26);
		if (-1 == sysfs_has_descriptors) {
			usbi_err(ctx, "error checking for sysfs descriptors");
			return LIBUSB_ERROR_OTHER;
		}
	}

	if (-1 == sysfs_can_relate_devices) {
		/* sysfs has busnum since Linux 2.6.22 */
		sysfs_can_relate_devices = kernel_version_ge(2,6,22);
		if (-1 == sysfs_can_relate_devices) {
			usbi_err(ctx, "error checking for sysfs busnum");
			return LIBUSB_ERROR_OTHER;
		}
	}

	if (sysfs_can_relate_devices || sysfs_has_descriptors) {
		r = stat(SYSFS_DEVICE_PATH, &statbuf);
		if (r != 0 || !S_ISDIR(statbuf.st_mode)) {
			usbi_warn(ctx, "sysfs not mounted");
			sysfs_can_relate_devices = 0;
			sysfs_has_descriptors = 0;
		}
	}

	if (sysfs_can_relate_devices)
		usbi_dbg("sysfs can relate devices");

	if (sysfs_has_descriptors)
		usbi_dbg("sysfs has complete descriptors");

	usbi_mutex_static_lock(&linux_hotplug_startstop_lock);
	r = LIBUSB_SUCCESS;
	if (init_count == 0) {
		/* start up hotplug event handler */
		//r =
		linux_start_event_monitor(); /* since Lollipop,
		netlink_socket closed by SElinux neverallow appdomain
		therefore, result of linux_start_event_monitor is ignored here
		*/
	}
	if (r == LIBUSB_SUCCESS) {
		r = linux_scan_devices(ctx);
		if (r == LIBUSB_SUCCESS)
			init_count++;
		else if (init_count == 0)
			linux_stop_event_monitor();
	} else
		usbi_err(ctx, "error starting hotplug event monitor");
	usbi_mutex_static_unlock(&linux_hotplug_startstop_lock);

	return r;
}

const struct usbi_os_backend android_usbfs_backend = {
	.name = "Android usbfs",
	.caps = USBI_CAP_HAS_HID_ACCESS,
	.init = android_init,
	.exit = op_exit,
	.get_device_list = NULL,
	.hotplug_poll = op_hotplug_poll,
	.get_device_descriptor = op_get_device_descriptor,
	.get_active_config_descriptor = op_get_active_config_descriptor,
	.get_config_descriptor = op_get_config_descriptor,
	.get_config_descriptor_by_value = op_get_config_descriptor_by_value,

	.open = android_open,
	.close = op_close,
	.get_configuration = op_get_configuration,
	.set_configuration = op_set_configuration,
	.claim_interface = op_claim_interface,
	.release_interface = op_release_interface,

	.set_interface_altsetting = op_set_interface,
	.clear_halt = op_clear_halt,
	.reset_device = op_reset_device,

	.alloc_streams = op_alloc_streams,
	.free_streams = op_free_streams,

	.kernel_driver_active = op_kernel_driver_active,
	.detach_kernel_driver = op_detach_kernel_driver,
	.attach_kernel_driver = op_attach_kernel_driver,

	.destroy_device = op_destroy_device,

	.submit_transfer = op_submit_transfer,
	.cancel_transfer = op_cancel_transfer,
	.clear_transfer_priv = op_clear_transfer_priv,

	.handle_events = op_handle_events,

	.clock_gettime = op_clock_gettime,

#ifdef USBI_TIMERFD_AVAILABLE
	.get_timerfd_clockid = op_get_timerfd_clockid,
#endif

	.device_priv_size = sizeof(struct linux_device_priv),
	.device_handle_priv_size = sizeof(struct linux_device_handle_priv),
	.transfer_priv_size = sizeof(struct linux_transfer_priv),
};
