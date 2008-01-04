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

void print_devs(libusb_dev *devs)
{
	libusb_dev *dev;

	for (dev = devs; dev; dev = libusb_dev_next(dev)) {
		struct usb_dev_descriptor *desc = libusb_dev_get_descriptor(dev);
		printf("%04x:%04x\n", desc->idVendor, desc->idProduct);
	}
}

int main(void)
{
	libusb_dev *devs;
	libusb_init(0);
	libusb_find_devices();
	devs = libusb_get_devices();

	print_devs(devs);

	libusb_exit();
	return 0;
}

