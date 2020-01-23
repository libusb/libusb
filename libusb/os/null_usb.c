/*
 * Copyright © 2019 Pino Toscano <toscano.pino@tiscali.it>
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

static int
null_get_device_list(struct libusb_context * ctx,
	struct discovered_devs **discdevs)
{
	return LIBUSB_SUCCESS;
}

static int
null_open(struct libusb_device_handle *handle)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static void
null_close(struct libusb_device_handle *handle)
{
}

static int
null_get_device_descriptor(struct libusb_device *dev, unsigned char *buf,
    int *host_endian)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int
null_get_active_config_descriptor(struct libusb_device *dev,
    unsigned char *buf, size_t len, int *host_endian)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int
null_get_config_descriptor(struct libusb_device *dev, uint8_t idx,
    unsigned char *buf, size_t len, int *host_endian)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int
null_set_configuration(struct libusb_device_handle *handle, int config)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int
null_claim_interface(struct libusb_device_handle *handle, int iface)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int
null_release_interface(struct libusb_device_handle *handle, int iface)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int
null_set_interface_altsetting(struct libusb_device_handle *handle, int iface,
    int altsetting)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int
null_clear_halt(struct libusb_device_handle *handle, unsigned char endpoint)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int
null_reset_device(struct libusb_device_handle *handle)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int
null_submit_transfer(struct usbi_transfer *itransfer)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int
null_cancel_transfer(struct usbi_transfer *itransfer)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int
null_clock_gettime(int clkid, struct timespec *tp)
{
	switch (clkid) {
	case USBI_CLOCK_MONOTONIC:
		return clock_gettime(CLOCK_REALTIME, tp);
	case USBI_CLOCK_REALTIME:
		return clock_gettime(CLOCK_REALTIME, tp);
	default:
		return LIBUSB_ERROR_INVALID_PARAM;
	}
}

const struct usbi_os_backend usbi_backend = {
	.name = "Null backend",
	.caps = 0,
	.get_device_list = null_get_device_list,
	.open = null_open,
	.close = null_close,
	.get_device_descriptor = null_get_device_descriptor,
	.get_active_config_descriptor = null_get_active_config_descriptor,
	.get_config_descriptor = null_get_config_descriptor,
	.set_configuration = null_set_configuration,
	.claim_interface = null_claim_interface,
	.release_interface = null_release_interface,
	.set_interface_altsetting = null_set_interface_altsetting,
	.clear_halt = null_clear_halt,
	.reset_device = null_reset_device,
	.submit_transfer = null_submit_transfer,
	.cancel_transfer = null_cancel_transfer,
	.clock_gettime = null_clock_gettime,
};
