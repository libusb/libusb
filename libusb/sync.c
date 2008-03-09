/*
 * Synchronous I/O functions for libusb
 * Copyright (C) 2007-2008 Daniel Drake <dsd@gentoo.org>
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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "libusbi.h"

static void ctrl_transfer_cb(struct libusb_transfer *transfer)
{
	int *completed = transfer->user_data;
	*completed = 1;
	usbi_dbg("actual_length=%d", transfer->actual_length);
	/* caller interprets result and frees transfer */
}

API_EXPORTED int libusb_control_transfer(libusb_device_handle *dev_handle,
	uint8_t bRequestType, uint8_t bRequest, uint16_t wValue, uint16_t wIndex,
	unsigned char *data, uint16_t wLength, unsigned int timeout)
{
	struct libusb_transfer *transfer = libusb_alloc_transfer();
	unsigned char *buffer;
	int length = wLength + LIBUSB_CONTROL_SETUP_SIZE;
	int completed = 0;
	int r;

	if (!transfer)
		return -ENOMEM;
	
	buffer = malloc(length);
	if (!buffer) {
		libusb_free_transfer(transfer);
		return -ENOMEM;
	}

	libusb_fill_control_setup(buffer, bRequestType, bRequest, wValue, wIndex,
		wLength);
	if ((bRequestType & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_OUT)
		memcpy(buffer + LIBUSB_CONTROL_SETUP_SIZE, data, wLength);

	libusb_fill_control_transfer(transfer, dev_handle, buffer, length,
		ctrl_transfer_cb, &completed, timeout);
	r = libusb_submit_transfer(transfer);
	if (r < 0) {
		libusb_free_transfer(transfer);
		return r;
	}

	while (!completed) {
		r = libusb_poll();
		if (r < 0) {
			libusb_cancel_transfer_sync(dev_handle, transfer);
			libusb_free_transfer(transfer);
			return r;
		}
	}

	if ((bRequestType & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_IN)
		memcpy(data, libusb_control_transfer_get_data(transfer),
			transfer->actual_length);

	switch (transfer->status) {
	case LIBUSB_TRANSFER_COMPLETED:
		r = transfer->actual_length;
		break;
	case LIBUSB_TRANSFER_TIMED_OUT:
		r = -ETIMEDOUT;
		break;
	default:
		usbi_warn("unrecognised status code %d", transfer->status);
		r = -1;
	}

	libusb_free_transfer(transfer);
	return r;
}

static void bulk_transfer_cb(struct libusb_transfer *transfer)
{
	int *completed = transfer->user_data;
	*completed = 1;
	usbi_dbg("actual_length=%d", transfer->actual_length);
	/* caller interprets results and frees transfer */
}

static int do_sync_bulk_transfer(struct libusb_device_handle *dev_handle,
	unsigned char endpoint, unsigned char *buffer, int length,
	int *transferred, unsigned int timeout, unsigned char endpoint_type)
{
	struct libusb_transfer *transfer = libusb_alloc_transfer();
	int completed = 0;
	int r;

	if (!transfer)
		return -ENOMEM;

	libusb_fill_bulk_transfer(transfer, dev_handle, endpoint, buffer, length,
		bulk_transfer_cb, &completed, timeout);
	transfer->endpoint_type = endpoint_type;

	r = libusb_submit_transfer(transfer);
	if (r < 0) {
		libusb_free_transfer(transfer);
		return r;
	}

	while (!completed) {
		r = libusb_poll();
		if (r < 0) {
			libusb_cancel_transfer_sync(dev_handle, transfer);
			libusb_free_transfer(transfer);
			return r;
		}
	}

	*transferred = transfer->actual_length;
	switch (transfer->status) {
	case LIBUSB_TRANSFER_COMPLETED:
		r = 0;
		break;
	case LIBUSB_TRANSFER_TIMED_OUT:
		r = -ETIMEDOUT;
		break;
	default:
		usbi_warn("unrecognised status code %d", transfer->status);
		r = -1;
	}

	libusb_free_transfer(transfer);
	return r;
}

/* FIXME: should transferred be the return value? */
API_EXPORTED int libusb_bulk_transfer(struct libusb_device_handle *dev_handle,
	unsigned char endpoint, unsigned char *data, int length, int *transferred,
	unsigned int timeout)
{
	return do_sync_bulk_transfer(dev_handle, endpoint, data, length,
		transferred, timeout, LIBUSB_ENDPOINT_TYPE_BULK);
}

/* FIXME: do we need an interval param here? usbfs doesn't expose it? */
API_EXPORTED int libusb_interrupt_transfer(
	struct libusb_device_handle *dev_handle, unsigned char endpoint,
	unsigned char *data, int length, int *transferred, unsigned int timeout)
{
	return do_sync_bulk_transfer(dev_handle, endpoint, data, length,
		transferred, timeout, LIBUSB_ENDPOINT_TYPE_INTERRUPT);
}

