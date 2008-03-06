/*
 * libusb example program to list devices on the bus
 * Copyright (C) 2007 Daniel Drake <dsd@gentoo.org>
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

#include <stdio.h>

#include <libusb/libusb.h>

void print_devs(libusb_device **devs)
{
	libusb_device *dev;
	int i;

	while ((dev = devs[i++]) != NULL) {
		struct libusb_dev_descriptor *desc = libusb_device_get_descriptor(dev);
		printf("%04x:%04x\n", desc->idVendor, desc->idProduct);
	}
}

int main(void)
{
	libusb_device **devs;
	int r;

	r = libusb_init();
	if (r < 0)
		return r;

	r = libusb_get_device_list(&devs);
	if (r < 0)
		return r;

	print_devs(devs);
	libusb_free_device_list(devs, 1);

	libusb_exit();
	return 0;
}

