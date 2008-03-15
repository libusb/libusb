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

#include <errno.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libusb.h"
#include "libusbi.h"

#ifdef OS_LINUX
const struct usbi_os_backend * const usbi_backend = &linux_usbfs_backend;
#else
#error "Unsupported OS"
#endif

static struct list_head usb_devs;
struct list_head usbi_open_devs;

/* we traverse usbfs without knowing how many devices we are going to find.
 * so we create this discovered_devs model which is similar to a linked-list
 * which grows when required. it can be freed once discovery has completed,
 * eliminating the need for a list node in the libusb_device structure
 * itself. */
#define DISCOVERED_DEVICES_SIZE_STEP 8

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
struct discovered_devs *discovered_devs_append(
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

struct libusb_device *usbi_alloc_device(unsigned long session_id)
{
	size_t priv_size = usbi_backend->device_priv_size;
	struct libusb_device *dev = malloc(sizeof(*dev) + priv_size);
	if (!dev)
		return NULL;

	dev->refcnt = 1;
	dev->session_data = session_id;
	list_add(&dev->list, &usb_devs);
	memset(&dev->os_priv, 0, priv_size);
	return dev;
}

struct libusb_device *usbi_get_device_by_session_id(unsigned long session_id)
{
	struct libusb_device *dev;

	list_for_each_entry(dev, &usb_devs, list)
		if (dev->session_data == session_id)
			return dev;

	return NULL;
}

API_EXPORTED int libusb_get_device_list(struct libusb_device ***list)
{
	struct discovered_devs *discdevs = discovered_devs_alloc();
	struct libusb_device **ret;
	int r = 0;
	size_t i;
	size_t len;
	usbi_dbg("");

	if (!discdevs)
		return -ENOMEM;

	r = usbi_backend->get_device_list(&discdevs);
	if (r < 0)
		goto out;

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

		if (usbi_backend->destroy_device)
			usbi_backend->destroy_device(dev);

		list_del(&dev->list);
		if (dev->config)
			free(dev->config);
		free(dev);
	}
}

API_EXPORTED struct libusb_device_descriptor *libusb_get_device_descriptor(
	struct libusb_device *dev)
{
	return &dev->desc;
}

API_EXPORTED struct libusb_config_descriptor *libusb_get_config_descriptor(
	struct libusb_device *dev)
{
	return dev->config;
}

API_EXPORTED struct libusb_device_handle *libusb_open(struct libusb_device *dev)
{
	struct libusb_device_handle *handle;
	size_t priv_size = usbi_backend->device_handle_priv_size;
	int r;
	usbi_dbg("open %04x:%04x", dev->desc.idVendor, dev->desc.idProduct);

	handle = malloc(sizeof(*handle) + priv_size);
	if (!handle)
		return NULL;

	handle->dev = libusb_device_ref(dev);
	memset(&handle->os_priv, 0, priv_size);
	r = usbi_backend->open(handle);
	if (r < 0) {
		libusb_device_unref(dev);
		free(handle);
		return NULL;
	}

	list_add(&handle->list, &usbi_open_devs);
	return handle;
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
	struct libusb_device_handle *handle = NULL;
	size_t i = 0;

	if (libusb_get_device_list(&devs) < 0)
		return NULL;

	while ((dev = devs[i++]) != NULL) {
		struct libusb_device_descriptor *desc =
			libusb_get_device_descriptor(dev);
		if (desc->idVendor == vendor_id && desc->idProduct == product_id) {
			found = dev;
			break;
		}
	}

	if (found)
		handle = libusb_open(found);

	libusb_free_device_list(devs, 1);
	return handle;
}

static void do_close(struct libusb_device_handle *dev_handle)
{
	usbi_backend->close(dev_handle);
	libusb_device_unref(dev_handle->dev);
}

API_EXPORTED void libusb_close(struct libusb_device_handle *dev_handle)
{
	if (!dev_handle)
		return;
	usbi_dbg("");

	list_del(&dev_handle->list);
	do_close(dev_handle);
	free(dev_handle);
}

API_EXPORTED struct libusb_device *libusb_get_device(
	struct libusb_device_handle *dev_handle)
{
	return dev_handle->dev;
}

API_EXPORTED int libusb_claim_interface(struct libusb_device_handle *dev,
	int iface)
{
	usbi_dbg("interface %d", iface);
	return usbi_backend->claim_interface(dev, iface);
}

API_EXPORTED int libusb_release_interface(struct libusb_device_handle *dev,
	int iface)
{
	usbi_dbg("interface %d", iface);
	return usbi_backend->release_interface(dev, iface);
}

API_EXPORTED int libusb_init(void)
{
	usbi_dbg("");

	if (usbi_backend->init) {
		int r = usbi_backend->init();
		if (r < 0)
			return r;
	}

	list_init(&usb_devs);
	list_init(&usbi_open_devs);
	usbi_io_init();
	return 0;
}

API_EXPORTED void libusb_exit(void)
{
	struct libusb_device_handle *devh;
	usbi_dbg("");
	if (!list_empty(&usbi_open_devs)) {
		usbi_dbg("naughty app left some devices open!\n");
		list_for_each_entry(devh, &usbi_open_devs, list)
			do_close(devh);
		/* FIXME where do the open handles get freed? */
	}
	if (usbi_backend->exit)
		usbi_backend->exit();
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

