/*
 * Core functions for libfpusb
 * Copyright (C) 2007 Daniel Drake <dsd@gentoo.org>
 *
 * Portions based on libusb-0.1
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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fpusb.h"
#include "fpusbi.h"

static struct list_head usb_devs;
struct list_head open_devs;

static int parse_descriptor(unsigned char *source, char *descriptor, void *dest)
{
	unsigned char *sp = source, *dp = dest;
	uint16_t w;
	uint32_t d;
	char *cp;

	for (cp = descriptor; *cp; cp++) {
		switch (*cp) {
			case 'b':	/* 8-bit byte */
				*dp++ = *sp++;
				break;
			case 'w':	/* 16-bit word, convert from little endian to CPU */
				w = (sp[1] << 8) | sp[0]; sp += 2;
				dp += ((unsigned long)dp & 1);	/* Align to word boundary */
				*((uint16_t *)dp) = w; dp += 2;
				break;
			case 'd':	/* 32-bit dword, convert from little endian to CPU */
				d = (sp[3] << 24) | (sp[2] << 16) | (sp[1] << 8) | sp[0]; sp += 4;
				dp += ((unsigned long)dp & 2);	/* Align to dword boundary */
				*((uint32_t *)dp) = d; dp += 4;
				break;
			case 'W':	/* 16-bit word, keep CPU endianess */
				dp += ((unsigned long)dp & 1);	/* Align to word boundary */
				memcpy(dp, sp, 2); sp += 2; dp += 2;
				break;
			case 'D':	/* 32-bit dword, keep CPU endianess */
				dp += ((unsigned long)dp & 2);	/* Align to dword boundary */
				memcpy(dp, sp, 4); sp += 4; dp += 4;
				break;
		}
	}

	return sp - source;
}

static int scan_device(char *busdir, const char *devnum)
{
	char path[PATH_MAX + 1];
    unsigned char raw_desc[DEVICE_DESC_LENGTH];
	struct fpusb_dev *dev = malloc(sizeof(*dev));
	int fd;
	int r;

	snprintf(path, PATH_MAX, "%s/%s", busdir, devnum);
	fp_dbg("%s", path);
	fd = open(path, O_RDWR);
	if (!fd) {
		fp_dbg("open '%s' failed, ret=%d errno=%d", path, fd, errno);
		return -1;
	}

    r = read(fd, raw_desc, DEVICE_DESC_LENGTH);
	if (r < 0) {
		fp_err("read failed ret=%d errno=%d", r, errno);
		return r;
	}
	/* FIXME: short read handling? */

    parse_descriptor(raw_desc, "bbWbbbbWWWbbbb", &dev->desc);
	fp_dbg("found device %04x:%04x", dev->desc.idVendor, dev->desc.idProduct);
	dev->nodepath = strdup(path);
	list_add(&dev->list, &usb_devs);

	close(fd);
	return 0;
}

static int scan_busdir(const char *busnum)
{
	DIR *dir;
	char dirpath[PATH_MAX + 1];
	struct dirent *entry;

	snprintf(dirpath, PATH_MAX, "%s/%s", USBFS_PATH, busnum);
	fp_dbg("%s", dirpath);
	dir = opendir(dirpath);
	if (!dir) {
		fp_err("opendir '%s' failed, errno=%d", dirpath, errno);
		return -1;
	}

	while (entry = readdir(dir)) {
		if (entry->d_name[0] == '.')
			continue;
		/* deliberately ignoring errors due to valid unplug race conditions */
		scan_device(dirpath, entry->d_name);
	}

	return 0;
}

API_EXPORTED int fpusb_find_devices(void)
{
	DIR *busses;
	struct dirent *entry;
	fp_dbg("");

	busses = opendir(USBFS_PATH);
	if (!busses) {
		fp_err("opendir busses failed errno=%d", errno);
		return -1;
	}

	while (entry = readdir(busses)) {
		if (entry->d_name[0] == '.')
			continue;
		/* deliberately ignoring errors, valid race conditions exist
		 * e.g. unplugging of hubs in the middle of this loop*/
		scan_busdir(entry->d_name);
	}

	return 0;
}

API_EXPORTED struct fpusb_dev *fpusb_get_devices(void)
{
	if (list_empty(&usb_devs))
		return NULL;
	return list_entry(usb_devs.next, struct fpusb_dev, list);
}

API_EXPORTED struct fpusb_dev *fpusb_dev_next(struct fpusb_dev *dev)
{
	struct list_head *head = &dev->list;
	if (!head || head->next == &usb_devs)
		return NULL;
	return list_entry(head->next, struct fpusb_dev, list);
}

API_EXPORTED struct usb_dev_descriptor *fpusb_dev_get_descriptor(
	struct fpusb_dev *dev)
{
	return &dev->desc;
}

API_EXPORTED struct fpusb_dev_handle *fpusb_devh_open(struct fpusb_dev *dev)
{
	struct fpusb_dev_handle *devh;
	int fd;
	fp_dbg("open %04x:%04x", dev->desc.idVendor, dev->desc.idProduct);

	fd = open(dev->nodepath, O_RDWR);
	if (!fd) {
		fp_err("open failed, code %d errno %d", fd, errno);
		return NULL;
	}

	devh = malloc(sizeof(*devh));
	if (!devh) {
		close(fd);
		return NULL;
	}

	devh->fd = fd;
	devh->dev = dev;
	list_add(&devh->list, &open_devs);
	return devh;
}

static void do_close(struct fpusb_dev_handle *devh)
{
	close(devh->fd);	
}

API_EXPORTED void fpusb_devh_close(struct fpusb_dev_handle *devh)
{
	if (!devh)
		return;
	fp_dbg("");

	list_del(&devh->list);
	do_close(devh);
	free(devh);
}

API_EXPORTED int fpusb_devh_claim_intf(struct fpusb_dev_handle *dev,
	int iface)
{
	int r;
	fp_dbg("interface %d", iface);
	
	r = ioctl(dev->fd, IOCTL_USB_CLAIMINTF, &iface);
	if (r < 0)
		fp_err("claim interface failed, error %d", r);
	return r;
}

API_EXPORTED int fpusb_devh_release_intf(struct fpusb_dev_handle *dev,
	int iface)
{
	int r;
	fp_dbg("interface %d", iface);

	r = ioctl(dev->fd, IOCTL_USB_RELEASEINTF, &iface);
	if (r < 0)
		fp_err("release interface failed, error %d", r);
	return r;
}

API_EXPORTED int fpusb_init(int signum)
{
	/* FIXME: find correct usb node path */
	fp_dbg("");
	list_init(&usb_devs);
	list_init(&open_devs);
	return fpi_io_init(signum);
}

API_EXPORTED void fpusb_exit(void)
{
	struct fpusb_dev_handle *devh;
	fp_dbg("");
	if (!list_empty(&open_devs)) {
		fp_dbg("naughty app left some devices open!\n");
		list_for_each_entry(devh, &open_devs, list)
			do_close(devh);
	}
	fpi_io_exit();
}

void fpi_log(enum fpi_log_level level, const char *function,
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

	fprintf(stream, "fpusb:%s [%s] ", prefix, function);

	va_start (args, format);
	vfprintf(stream, format, args);
	va_end (args);

	fprintf(stream, "\n");
}

