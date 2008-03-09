/*
 * Core functions for libusb
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
#include <features.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "libusb.h"
#include "libusbi.h"

struct list_head usb_devs;
struct list_head open_devs;
static const char *usbfs_path = NULL;

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

/* we traverse usbfs without knowing how many devices we are going to find.
 * so we create this discovered_devs model which is similar to a linked-list
 * which grows when required. it can be freed once discovery has completed,
 * eliminating the need for a list node in the libusb_device structure
 * itself. */
#define DISCOVERED_DEVICES_SIZE_STEP 8
struct discovered_devs {
	size_t len;
	size_t capacity;
	struct libusb_device *devices[0];
};

static struct discovered_devs *discovered_devs_alloc(void)
{
	struct discovered_devs *ret =
		malloc(sizeof(*ret) + (sizeof(void *) * DISCOVERED_DEVICES_SIZE_STEP));

	if (ret) {
		ret->len = 0;
		ret->capacity = DISCOVERED_DEVICES_SIZE_STEP;
	}
	return ret;
}

/* append a device to the discovered devices collection. may realloc itself,
 * returning new discdevs. returns NULL on realloc failure. */
static struct discovered_devs *discovered_devs_append(
	struct discovered_devs *discdevs, struct libusb_device *dev)
{
	size_t len = discdevs->len;
	size_t capacity;

	/* if there is space, just append the device */
	if (len < discdevs->capacity) {
		discdevs->devices[len] = libusb_device_ref(dev);
		discdevs->len++;
		return discdevs;
	}

	/* exceeded capacity, need to grow */
	usbi_dbg("need to increase capacity");
	capacity = discdevs->capacity + DISCOVERED_DEVICES_SIZE_STEP;
	discdevs = realloc(discdevs,
		sizeof(*discdevs) + (sizeof(void *) * capacity));
	if (discdevs) {
		discdevs->capacity = capacity;
		discdevs->devices[len] = libusb_device_ref(dev);
		discdevs->len++;
	}

	return discdevs;
}

static void discovered_devs_free(struct discovered_devs *discdevs)
{
	size_t i;

	for (i = 0; i < discdevs->len; i++)
		libusb_device_unref(discdevs->devices[i]);

	free(discdevs);
}

static struct libusb_device *device_new(uint8_t busnum, uint8_t devaddr)
{
	char path[PATH_MAX + 1];
	unsigned char raw_desc[DEVICE_DESC_LENGTH];
	struct libusb_device *dev = malloc(sizeof(*dev));
	int fd = 0;
	int i;
	int r;
	int tmp;

	if (!dev)
		return NULL;

	dev->refcnt = 1;
	dev->nodepath = NULL;
	dev->config = NULL;

	snprintf(path, PATH_MAX, "%s/%03d/%03d", usbfs_path, busnum, devaddr);
	usbi_dbg("%s", path);
	fd = open(path, O_RDWR);
	if (!fd) {
		usbi_dbg("open '%s' failed, ret=%d errno=%d", path, fd, errno);
		/* FIXME this might not be an error if the file has gone away due
		 * to unplugging */
		goto err;
	}

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
		goto err;
	}

	if (dev->desc.bNumConfigurations < 1) {
		usbi_dbg("no configurations?");
		goto err;
	}

	tmp = dev->desc.bNumConfigurations * sizeof(struct libusb_config_descriptor);
	dev->config = malloc(tmp);
	if (!dev->config)
		goto err;

	memset(dev->config, 0, tmp);
	for (i = 0; i < dev->desc.bNumConfigurations; i++) {
		unsigned char buffer[8], *bigbuffer;
		struct libusb_config_descriptor config;

		/* Get the first 8 bytes to figure out what the total length is */
		r = read(fd, buffer, sizeof(buffer));
		if (r < sizeof(buffer)) {
			usbi_err("short descriptor read (%d/%d)", r, sizeof(buffer));
			goto err;
		}

		usbi_parse_descriptor(buffer, "bbw", &config);

		bigbuffer = malloc(config.wTotalLength);
		if (!bigbuffer)
			goto err;

		/* Read the rest of the config descriptor */
		memcpy(bigbuffer, buffer, sizeof(buffer));

		tmp = config.wTotalLength - 8;
		r = read(fd, bigbuffer + 8, tmp);
		if (r < tmp) {
			usbi_err("short descriptor read (%d/%d)", r, tmp);
			free(bigbuffer);
			goto err;
		}

		r = usbi_parse_configuration(&dev->config[i], bigbuffer);
		if (r > 0)
			usbi_warn("descriptor data still left\n");
		free(bigbuffer);
	}

	dev->nodepath = strdup(path);
	if (!dev->nodepath)
		goto err;

	dev->session_data = busnum << 8 | devaddr;
	list_add(&dev->list, &usb_devs);
	close(fd);
	return dev;

err:
	if (fd)
		close(fd);
	if (dev->config)
		free(dev->config);
	if (dev->nodepath)
		free(dev->nodepath);
	if (dev)
		free(dev);
	return NULL;
}

static struct libusb_device *get_device_by_session_id(unsigned long session_id)
{
	struct libusb_device *dev;

	list_for_each_entry(dev, &usb_devs, list)
		if (dev->session_data == session_id)
			return dev;

	return NULL;
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

	dev = get_device_by_session_id(session_id);
	if (dev) {
		usbi_dbg("using existing device for %d/%d (session %ld)",
			busnum, devaddr, session_id);
	} else {
		usbi_dbg("allocating new device for %d/%d (session %ld)",
			busnum, devaddr, session_id);
		dev = device_new(busnum, devaddr);
		if (!dev) {
			r = -EIO;
			goto out;
		}
		need_unref = 1;
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

API_EXPORTED int libusb_get_device_list(struct libusb_device ***list)
{
	DIR *buses;
	struct discovered_devs *discdevs = discovered_devs_alloc();
	struct dirent *entry;
	struct libusb_device **ret;
	int r = 0;
	size_t i;
	size_t len;
	usbi_dbg("");

	if (!discdevs)
		return -ENOMEM;

	buses = opendir(usbfs_path);
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

	/* convert discovered_devs into a list */
	len = discdevs->len;
	ret = malloc(sizeof(void *) * (len + 1));
	if (!ret) {
		r = -ENOMEM;
		goto out;
	}

	ret[len] = NULL;
	for (i = 0; i < len; i++) {
		struct libusb_device *dev = discdevs->devices[i];
		ret[i] = libusb_device_ref(dev);
	}
	*list = ret;

out:
	discovered_devs_free(discdevs);
	closedir(buses);
	return r;
}

API_EXPORTED void libusb_free_device_list(struct libusb_device **list,
	int unref_devices)
{
	if (!list)
		return;

	if (unref_devices) {
		int i = 0;
		struct libusb_device *dev;

		while ((dev = list[i++]) != NULL)
			libusb_device_unref(dev);
	}
	free(list);
}

API_EXPORTED struct libusb_device *libusb_device_ref(struct libusb_device *dev)
{
	dev->refcnt++;
	return dev;
}

API_EXPORTED void libusb_device_unref(struct libusb_device *dev)
{
	if (!dev)
		return;

	if (--dev->refcnt == 0) {
		usbi_dbg("destroy device %04x:%04x", dev->desc.idVendor,
			dev->desc.idProduct);
		list_del(&dev->list);
		free(dev->config);
		free(dev->nodepath);
		free(dev);
	}
}

API_EXPORTED struct libusb_dev_descriptor *libusb_device_get_descriptor(
	struct libusb_device *dev)
{
	return &dev->desc;
}

API_EXPORTED struct libusb_config_descriptor *libusb_device_get_config(
	struct libusb_device *dev)
{
	return dev->config;
}

API_EXPORTED struct libusb_device_handle *libusb_open(struct libusb_device *dev)
{
	struct libusb_device_handle *devh;
	int fd;
	usbi_dbg("open %04x:%04x", dev->desc.idVendor, dev->desc.idProduct);

	fd = open(dev->nodepath, O_RDWR);
	if (!fd) {
		usbi_err("open failed, code %d errno %d", fd, errno);
		return NULL;
	}

	devh = malloc(sizeof(*devh));
	if (!devh) {
		close(fd);
		return NULL;
	}

	devh->fd = fd;
	devh->dev = libusb_device_ref(dev);
	list_add(&devh->list, &open_devs);
	usbi_add_pollfd(fd, POLLOUT);
	return devh;
}

/* convenience function for finding a device with a particular vendor/product
 * combination. has limitations and is hence not intended for use in "real
 * applications": if multiple devices have the same VID+PID it'll only
 * give you the first one, etc. */
API_EXPORTED struct libusb_device_handle *libusb_open_device_with_vid_pid(
	uint16_t vendor_id, uint16_t product_id)
{
	struct libusb_device **devs;
	struct libusb_device *found = NULL;
	struct libusb_device *dev;
	struct libusb_device_handle *devh;
	size_t i = 0;

	if (libusb_get_device_list(&devs) < 0)
		return NULL;

	while ((dev = devs[i++]) != NULL) {
		struct libusb_dev_descriptor *desc = libusb_device_get_descriptor(dev);
		if (desc->idVendor == vendor_id && desc->idProduct == product_id) {
			found = dev;
			break;
		}
	}

	if (found)
		devh = libusb_open(found);

	libusb_free_device_list(devs, 1);
	return devh;
}

static void do_close(struct libusb_device_handle *devh)
{
	usbi_remove_pollfd(devh->fd);
	close(devh->fd);
	libusb_device_unref(devh->dev);
}

API_EXPORTED void libusb_close(struct libusb_device_handle *devh)
{
	if (!devh)
		return;
	usbi_dbg("");

	list_del(&devh->list);
	do_close(devh);
	free(devh);
}

API_EXPORTED struct libusb_device *libusb_devh_get_dev(
	struct libusb_device_handle *devh)
{
	return devh->dev;
}

API_EXPORTED int libusb_claim_interface(struct libusb_device_handle *dev,
	int iface)
{
	int r;
	usbi_dbg("interface %d", iface);
	
	r = ioctl(dev->fd, IOCTL_USB_CLAIMINTF, &iface);
	if (r < 0)
		usbi_err("claim interface failed, error %d", r);
	return r;
}

API_EXPORTED int libusb_release_interface(struct libusb_device_handle *dev,
	int iface)
{
	int r;
	usbi_dbg("interface %d", iface);

	r = ioctl(dev->fd, IOCTL_USB_RELEASEINTF, &iface);
	if (r < 0)
		usbi_err("release interface failed, error %d", r);
	return r;
}

API_EXPORTED int libusb_init(void)
{
	usbi_dbg("");
	usbfs_path = find_usbfs_path();
	if (!usbfs_path) {
		usbi_err("could not find usbfs");
		return -ENODEV;
	}

	list_init(&usb_devs);
	list_init(&open_devs);
	usbi_io_init();
	return 0;
}

API_EXPORTED void libusb_exit(void)
{
	struct libusb_device_handle *devh;
	usbi_dbg("");
	if (!list_empty(&open_devs)) {
		usbi_dbg("naughty app left some devices open!\n");
		list_for_each_entry(devh, &open_devs, list)
			do_close(devh);
	}
}

API_EXPORTED size_t libusb_get_pollfds(struct libusb_pollfd **pollfds)
{
	struct libusb_device_handle *devh;
	struct libusb_pollfd *ret;
	size_t cnt = 0;
	size_t i = 0;

	/* count number of open devices */
	list_for_each_entry(devh, &open_devs, list)
		cnt++;

	/* create array */
	ret = calloc(cnt, sizeof(struct libusb_pollfd));
	if (!ret)
		return -ENOMEM;

	/* add fds */
	list_for_each_entry(devh, &open_devs, list) {
		ret[i++].fd = devh->fd;
		ret[i].events = POLLOUT;
	}
	
	*pollfds = ret;
	return cnt;
}

void usbi_log(enum usbi_log_level level, const char *function,
	const char *format, ...)
{
	va_list args;
	FILE *stream = stdout;
	const char *prefix;

	switch (level) {
	case LOG_LEVEL_INFO:
		prefix = "info";
		break;
	case LOG_LEVEL_WARNING:
		stream = stderr;
		prefix = "warning";
		break;
	case LOG_LEVEL_ERROR:
		stream = stderr;
		prefix = "error";
		break;
	case LOG_LEVEL_DEBUG:
		stream = stderr;
		prefix = "debug";
		break;
	default:
		stream = stderr;
		prefix = "unknown";
		break;
	}

	fprintf(stream, "libusb:%s [%s] ", prefix, function);

	va_start (args, format);
	vfprintf(stream, format, args);
	va_end (args);

	fprintf(stream, "\n");
}

