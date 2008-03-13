/*
 * Linux usbfs backend for libusb
 * Copyright (C) 2007-2008 Daniel Drake <dsd@gentoo.org>
 * Copyright (c) 2001 Johannes Erdfelt <johannes@erdfelt.com>
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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "libusb.h"
#include "libusbi.h"
#include "linux_usbfs.h"

static const char *usbfs_path = NULL;

struct linux_device_priv {
	char *nodepath;	
};

struct linux_device_handle_priv {
	int fd;
};

struct linux_transfer_priv {
	struct usbfs_urb urb;
};

static struct linux_device_priv *__device_priv(struct libusb_device *dev)
{
	return (struct linux_device_priv *) dev->os_priv;
}

static struct linux_device_handle_priv *__device_handle_priv(
	struct libusb_device_handle *handle)
{
	return (struct linux_device_handle_priv *) handle->os_priv;
}

static struct linux_transfer_priv *__transfer_priv(
	struct usbi_transfer *transfer)
{
	return (struct linux_transfer_priv *) transfer->os_priv;
}

#define TRANSFER_PRIV_GET_ITRANSFER(tpriv) \
	((struct usbi_transfer *) \
		container_of((tpriv), struct usbi_transfer, os_priv))

static int check_usb_vfs(const char *dirname)
{
	DIR *dir;
	struct dirent *entry;
	int found = 0;

	dir = opendir(dirname);
	if (!dir)
		return 0;

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] == '.')
			continue;

		/* We assume if we find any files that it must be the right place */
		found = 1;
		break;
	}

	closedir(dir);
	return found;
}

static const char *find_usbfs_path(void)
{
	const char *path = "/dev/bus/usb";
	const char *ret = NULL;

	if (check_usb_vfs(path)) {
		ret = path;
	} else {
		path = "/proc/bus/usb";
		if (check_usb_vfs(path))
			ret = path;
	}

	usbi_dbg("found usbfs at %s", ret);
	return ret;
}

static int op_init(void)
{
	usbfs_path = find_usbfs_path();
	if (!usbfs_path) {
		usbi_err("could not find usbfs");
		return -ENODEV;
	}
	return 0;
}

static int initialize_device(struct libusb_device *dev, uint8_t busnum,
	uint8_t devaddr)
{
	struct linux_device_priv *priv = __device_priv(dev);
	char path[PATH_MAX + 1];
	unsigned char raw_desc[DEVICE_DESC_LENGTH];
	int fd = 0;
	int i;
	int r;
	int tmp;

	priv->nodepath = NULL;
	dev->config = NULL;

	snprintf(path, PATH_MAX, "%s/%03d/%03d", usbfs_path, busnum, devaddr);
	usbi_dbg("%s", path);
	fd = open(path, O_RDWR);
	if (!fd) {
		usbi_dbg("open '%s' failed, ret=%d errno=%d", path, fd, errno);
		/* FIXME this might not be an error if the file has gone away due
		 * to unplugging */
		r = -EIO;
		goto err;
	}

	/* FIXME: move config parsing into main lib */
	r = read(fd, raw_desc, DEVICE_DESC_LENGTH);
	if (r < 0) {
		usbi_err("read failed ret=%d errno=%d", r, errno);
		goto err;
	}
	/* FIXME: short read handling? */

	usbi_parse_descriptor(raw_desc, "bbWbbbbWWWbbbb", &dev->desc);

	/* Now try to fetch the rest of the descriptors */
	if (dev->desc.bNumConfigurations > USB_MAXCONFIG) {
		usbi_err("too many configurations");
		r = -EINVAL;
		goto err;
	}

	if (dev->desc.bNumConfigurations < 1) {
		usbi_dbg("no configurations?");
		r = -EINVAL;
		goto err;
	}

	tmp = dev->desc.bNumConfigurations * sizeof(struct libusb_config_descriptor);
	dev->config = malloc(tmp);
	if (!dev->config) {
		r = -ENOMEM;
		goto err;
	}

	memset(dev->config, 0, tmp);
	for (i = 0; i < dev->desc.bNumConfigurations; i++) {
		unsigned char buffer[8], *bigbuffer;
		struct libusb_config_descriptor config;

		/* Get the first 8 bytes to figure out what the total length is */
		r = read(fd, buffer, sizeof(buffer));
		if (r < sizeof(buffer)) {
			usbi_err("short descriptor read (%d/%d)", r, sizeof(buffer));
			r = -EIO;
			goto err;
		}

		usbi_parse_descriptor(buffer, "bbw", &config);

		bigbuffer = malloc(config.wTotalLength);
		if (!bigbuffer) {
			r = -ENOMEM;
			goto err;
		}

		/* Read the rest of the config descriptor */
		memcpy(bigbuffer, buffer, sizeof(buffer));

		tmp = config.wTotalLength - 8;
		r = read(fd, bigbuffer + 8, tmp);
		if (r < tmp) {
			usbi_err("short descriptor read (%d/%d)", r, tmp);
			free(bigbuffer);
			r = -EIO;
			goto err;
		}

		r = usbi_parse_configuration(&dev->config[i], bigbuffer);
		if (r > 0)
			usbi_warn("descriptor data still left\n");
		free(bigbuffer);
	}

	priv->nodepath = strdup(path);
	if (!priv->nodepath) {
		r = -ENOMEM;
		goto err;
	}

	close(fd);
	return 0;

err:
	if (fd)
		close(fd);
	if (dev->config) {
		free(dev->config);
		dev->config = NULL;
	}
	if (priv->nodepath) {
		free(priv->nodepath);
		priv->nodepath = NULL;
	}
	return r;
}

/* open a device file, set up the libusb_device structure for it, and add it to
 * discdevs. on failure (non-zero return) the pre-existing discdevs should
 * be destroyed (and devices freed). on success, the new discdevs pointer
 * should be used it may have been moved. */
static int scan_device(struct discovered_devs **_discdevs, uint8_t busnum,
	uint8_t devaddr)
{
	struct discovered_devs *discdevs;
	unsigned long session_id;
	struct libusb_device *dev;
	int need_unref = 0;
	int r = 0;

	/* FIXME: session ID is not guaranteed unique as addresses can wrap and
	 * will be reused. instead we should add a simple sysfs attribute with
	 * a session ID. */
	session_id = busnum << 8 | devaddr;
	usbi_dbg("busnum %d devaddr %d session_id %ld", busnum, devaddr,
		session_id);

	dev = usbi_get_device_by_session_id(session_id);
	if (dev) {
		usbi_dbg("using existing device for %d/%d (session %ld)",
			busnum, devaddr, session_id);
	} else {
		usbi_dbg("allocating new device for %d/%d (session %ld)",
			busnum, devaddr, session_id);
		dev = usbi_alloc_device(session_id);
		if (!dev) {
			r = -ENOMEM;
			goto out;
		}
		need_unref = 1;
		r = initialize_device(dev, busnum, devaddr);
		if (r < 0)
			goto out;
	}

	discdevs = discovered_devs_append(*_discdevs, dev);
	if (!discdevs)
		r = -ENOMEM;
	else
		*_discdevs = discdevs;

out:
	if (need_unref)
		libusb_device_unref(dev);
	return r;
}

/* open a bus directory and adds all discovered devices to discdevs. on
 * failure (non-zero return) the pre-existing discdevs should be destroyed
 * (and devices freed). on success, the new discdevs pointer should be used
 * as it may have been moved. */
static int scan_busdir(struct discovered_devs **_discdevs, uint8_t busnum)
{
	DIR *dir;
	char dirpath[PATH_MAX + 1];
	struct dirent *entry;
	struct discovered_devs *discdevs = *_discdevs;
	int r = 0;

	snprintf(dirpath, PATH_MAX, "%s/%03d", usbfs_path, busnum);
	usbi_dbg("%s", dirpath);
	dir = opendir(dirpath);
	if (!dir) {
		usbi_err("opendir '%s' failed, errno=%d", dirpath, errno);
		/* FIXME: should handle valid race conditions like hub unplugged
		 * during directory iteration - this is not an error */
		return -1;
	}

	while ((entry = readdir(dir))) {
		int devaddr;

		if (entry->d_name[0] == '.')
			continue;

		devaddr = atoi(entry->d_name);
		if (devaddr == 0) {
			usbi_dbg("unknown dir entry %s", entry->d_name);
			continue;
		}

		r = scan_device(&discdevs, busnum, (uint8_t) devaddr);
		if (r < 0)
			goto out;
	}

	*_discdevs = discdevs;
out:
	closedir(dir);
	return r;
}

static int op_get_device_list(struct discovered_devs *discdevs)
{
	struct dirent *entry;
	int r = 0;
	DIR *buses = opendir(usbfs_path);
	if (!buses) {
		usbi_err("opendir buses failed errno=%d", errno);
		return -1;
	}

	while ((entry = readdir(buses))) {
		struct discovered_devs *discdevs_new = discdevs;
		int busnum;

		if (entry->d_name[0] == '.')
			continue;

		busnum = atoi(entry->d_name);
		if (busnum == 0) {
			usbi_dbg("unknown dir entry %s", entry->d_name);
			continue;
		}

		r = scan_busdir(&discdevs_new, busnum);
		if (r < 0)
			goto out;
		discdevs = discdevs_new;
	}

out:
	closedir(buses);
	return r;
}

static int op_open(struct libusb_device_handle *handle)
{
	struct linux_device_priv *dpriv = __device_priv(handle->dev);
	struct linux_device_handle_priv *hpriv = __device_handle_priv(handle);

	hpriv->fd = open(dpriv->nodepath, O_RDWR);
	if (hpriv->fd < 0) {
		usbi_err("open failed, code %d errno %d", hpriv->fd, errno);
		return -EIO;
	}

	return usbi_add_pollfd(hpriv->fd, POLLOUT);
}

static void op_close(struct libusb_device_handle *dev_handle)
{
	int fd = __device_handle_priv(dev_handle)->fd;
	usbi_remove_pollfd(fd);
	close(fd);
}

static int op_claim_interface(struct libusb_device_handle *handle, int iface)
{
	int fd = __device_handle_priv(handle)->fd;
	int r = ioctl(fd, IOCTL_USBFS_CLAIMINTF, &iface);
	if (r < 0)
		usbi_err("claim interface failed, error %d", r);
	return r;
}

static int op_release_interface(struct libusb_device_handle *handle, int iface)
{
	int fd = __device_handle_priv(handle)->fd;
	int r = ioctl(fd, IOCTL_USBFS_RELEASEINTF, &iface);
	if (r < 0)
		usbi_err("release interface failed, error %d", r);
	return r;
}

static void op_destroy_device(struct libusb_device *dev)
{
	unsigned char *nodepath = __device_priv(dev)->nodepath;
	if (nodepath)
		free(nodepath);
}

static int submit_transfer(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = &itransfer->pub;
	struct usbfs_urb *urb = &__transfer_priv(itransfer)->urb;
	struct linux_device_handle_priv *dpriv =
		__device_handle_priv(transfer->dev_handle);
	int to_be_transferred = transfer->length - itransfer->transferred;
	int r;

	urb->buffer = transfer->buffer + itransfer->transferred;
	urb->buffer_length = MIN(to_be_transferred, MAX_URB_BUFFER_LENGTH);

	/* FIXME: for requests that we have to split into multiple URBs, we should
	 * submit all the URBs instantly: submit, submit, submit, reap, reap, reap
	 * rather than: submit, reap, submit, reap, submit, reap
	 * this will improve performance and fix bugs concerning behaviour when
	 * the user submits two similar multiple-urb requests */
	usbi_dbg("transferring %d from %d bytes", urb->buffer_length,
		to_be_transferred);

	r = ioctl(dpriv->fd, IOCTL_USBFS_SUBMITURB, urb);
	if (r < 0)
		usbi_err("submiturb failed error %d errno=%d", r, errno);

	return r;
}

static int op_submit_transfer(struct usbi_transfer *itransfer)
{
	struct usbfs_urb *urb = &__transfer_priv(itransfer)->urb;
	struct libusb_transfer *transfer = &itransfer->pub;

	memset(urb, 0, sizeof(*urb));
	switch (transfer->endpoint_type) {
	case LIBUSB_ENDPOINT_TYPE_CONTROL:
		urb->type = USBFS_URB_TYPE_CONTROL;
		break;
	case LIBUSB_ENDPOINT_TYPE_BULK:
		urb->type = USBFS_URB_TYPE_BULK;
		break;
	case LIBUSB_ENDPOINT_TYPE_INTERRUPT:
		urb->type = USBFS_URB_TYPE_INTERRUPT;
		break;
	default:
		usbi_err("unknown endpoint type %d", transfer->endpoint_type);
		return -EINVAL;
	}

	urb->endpoint = transfer->endpoint;
	return submit_transfer(itransfer);
}

static int op_cancel_transfer(struct usbi_transfer *itransfer)
{
	struct usbfs_urb *urb = &__transfer_priv(itransfer)->urb;
	struct libusb_transfer *transfer = &itransfer->pub;
	struct linux_device_handle_priv *dpriv =
		__device_handle_priv(transfer->dev_handle);

	return ioctl(dpriv->fd, IOCTL_USBFS_DISCARDURB, urb);
}

static int reap_for_handle(struct libusb_device_handle *handle)
{
	struct linux_device_handle_priv *hpriv = __device_handle_priv(handle);
	int r;
	struct usbfs_urb *urb;
	struct linux_transfer_priv *tpriv;
	struct usbi_transfer *itransfer;
	struct libusb_transfer *transfer;
	int trf_requested;
	int length;

	r = ioctl(hpriv->fd, IOCTL_USBFS_REAPURBNDELAY, &urb);
	if (r == -1 && errno == EAGAIN)
		return r;
	if (r < 0) {
		usbi_err("reap failed error %d errno=%d", r, errno);
		return r;
	}

	tpriv = container_of(urb, struct linux_transfer_priv, urb);
	itransfer = TRANSFER_PRIV_GET_ITRANSFER(tpriv);
	transfer = &itransfer->pub;

	usbi_dbg("urb type=%d status=%d transferred=%d", urb->type, urb->status,
		urb->actual_length);
	list_del(&itransfer->list);

	if (urb->status == -2) {
		usbi_handle_transfer_cancellation(itransfer);
		return 0;
	}

	/* FIXME: research what other status codes may exist */
	if (urb->status != 0)
		usbi_warn("unrecognised urb status %d", urb->status);

	/* determine how much data was asked for */
	length = transfer->length;
	if (transfer->endpoint_type == LIBUSB_ENDPOINT_TYPE_CONTROL)
		length -= LIBUSB_CONTROL_SETUP_SIZE;
	trf_requested = MIN(length - itransfer->transferred,
		MAX_URB_BUFFER_LENGTH);

	itransfer->transferred += urb->actual_length;

	/* if we were provided less data than requested, then our transfer is
	 * done */
	if (urb->actual_length < trf_requested) {
		usbi_dbg("less data than requested (%d/%d) --> all done",
			urb->actual_length, trf_requested);
		usbi_handle_transfer_completion(itransfer, LIBUSB_TRANSFER_COMPLETED);
		return 0;
	}

	/* if we've transferred all data, we're done */
	if (itransfer->transferred == length) {
		usbi_dbg("transfer complete --> all done");
		usbi_handle_transfer_completion(itransfer, LIBUSB_TRANSFER_COMPLETED);
		return 0;
	}

	/* otherwise, we have more data to transfer */
	usbi_dbg("more data to transfer...");
	return submit_transfer(itransfer);
}

static int op_handle_events(fd_set *readfds, fd_set *writefds)
{
	struct libusb_device_handle *handle;
	int r;

	list_for_each_entry(handle, &usbi_open_devs, list) {
		struct linux_device_handle_priv *hpriv = __device_handle_priv(handle);
		if (!FD_ISSET(hpriv->fd, writefds))
			continue;
		r = reap_for_handle(handle);
		if (r == -1 && errno == EAGAIN)
			continue;
		if (r < 0)
			return r;
	}

	return 0;
}

const struct usbi_os_backend linux_usbfs_backend = {
	.name = "Linux usbfs",
	.init = op_init,
	.exit = NULL,
	.get_device_list = op_get_device_list,
	.open = op_open,
	.close = op_close,
	.claim_interface = op_claim_interface,
	.release_interface = op_release_interface,

	.destroy_device = op_destroy_device,

	.submit_transfer = op_submit_transfer,
	.cancel_transfer = op_cancel_transfer,

	.handle_events = op_handle_events,

	.device_priv_size = sizeof(struct linux_device_priv),
	.device_handle_priv_size = sizeof(struct linux_device_handle_priv),
	.transfer_priv_size = sizeof(struct linux_transfer_priv),
};

