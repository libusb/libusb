/*
 * libusb example program to list devices on the bus
 * Copyright © 2007 Daniel Drake <dsd@gentoo.org>
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
#include <string.h>

#include "libusb.h"

static void print_devs(libusb_device **devs, int verbose)
{
	libusb_device *dev;
	int i = 0, j = 0;
	uint8_t path[8]; 
	char string_buffer[LIBUSB_DEVICE_STRING_BYTES_MAX];

	while ((dev = devs[i++]) != NULL) {
		struct libusb_device_descriptor desc;
		int r = libusb_get_device_descriptor(dev, &desc);
		if (r < 0) {
			fprintf(stderr, "failed to get device descriptor");
			return;
		}

		printf("%04x:%04x (bus %d, device %d)",
			desc.idVendor, desc.idProduct,
			libusb_get_bus_number(dev), libusb_get_device_address(dev));

		r = libusb_get_port_numbers(dev, path, sizeof(path));
		if (r > 0) {
			printf(" path: %d", path[0]);
			for (j = 1; j < r; j++)
				printf(".%d", path[j]);
		}

		if (verbose) {
			r = libusb_get_device_string(dev, LIBUSB_DEVICE_STRING_MANUFACTURER,
				string_buffer, sizeof(string_buffer));
			if (r >= 0) {
				printf("\n    manufacturer = %s", string_buffer);
			}

			r = libusb_get_device_string(dev, LIBUSB_DEVICE_STRING_PRODUCT,
				string_buffer, sizeof(string_buffer));
			if (r >= 0) {
				printf("\n    product = %s", string_buffer);
			}

			r = libusb_get_device_string(dev, LIBUSB_DEVICE_STRING_SERIAL_NUMBER,
				string_buffer, sizeof(string_buffer));
			if (r >= 0) {
				printf("\n    serial_number = %s", string_buffer);
			}
		}
		printf("\n");
	}
}

static int usage(void) {
	printf("usage: listdevs [--verbose]\n");
	return 1;
}

int main(int argc, char *argv[])
{
	int verbose = 0;
	libusb_device **devs;
	int r;
	ssize_t cnt;

	--argc; ++argv;  /* consume argument */
	while (argc) {
		if ((0 == strcmp("-v", argv[0])) || (0 == strcmp("--verbose", argv[0]))) {
			++verbose;
			--argc; ++argv;  /* consume argument */
		} else {
			return usage();
		}
	}

	r = libusb_init_context(/*ctx=*/NULL, /*options=*/NULL, /*num_options=*/0);
	if (r < 0)
		return r;

	cnt = libusb_get_device_list(NULL, &devs);
	if (cnt < 0){
		libusb_exit(NULL);
		return (int) cnt;
	}

	print_devs(devs, verbose);
	libusb_free_device_list(devs, 1);

	libusb_exit(NULL);
	return 0;
}
