/*
 * fpusb example program to list devices on the bus
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

#include <libfpusb/fpusb.h>

void print_devs(fpusb_dev *devs)
{
	fpusb_dev *dev;

	for (dev = devs; dev; dev = fpusb_dev_next(dev)) {
		struct usb_dev_descriptor *desc = fpusb_dev_get_descriptor(dev);
		printf("%04x:%04x\n", desc->idVendor, desc->idProduct);
	}
}

int main(void)
{
	fpusb_dev *devs;
	fpusb_init(0);
	fpusb_find_devices();
	devs = fpusb_get_devices();

	print_devs(devs);

	fpusb_exit();
	return 0;
}

