/*
 * xusb: winusb specific test program
 * based on lsusb, copyright (C) 2007 Daniel Drake <dsd@gentoo.org>
 *
 * Currently, this test program will try to access an XBox USB
 * Gamepad through WinUSB. To access your device, change VID/PID.
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
#include <sys/types.h>

#include <libusb/libusb.h>

//#define USE_MOUSE
#define USE_XBOX

#ifdef USE_MOUSE
// Logitech optical mouse
#define VID 0x046D
#define PID 0xC03E
#endif

#ifdef USE_XBOX
// Microsoft XBox Controller
#define VID 0x045E
#define PID 0x0289
#endif

#ifdef USE_KEY
// 2 GB Usb key
#define VID 0x0204
#define PID 0x6025
#endif



static void print_devs(libusb_device **devs)
{
	libusb_device *dev;
	libusb_device_handle *handle;
	int i = 0;

	while ((dev = devs[i++]) != NULL) {
		struct libusb_device_descriptor desc;
		int r = libusb_get_device_descriptor(dev, &desc);
		if (r < 0) {
			fprintf(stderr, "failed to get device descriptor");
			return;
		}

		printf("%04x:%04x (bus %d, device %d)\n",
			desc.idVendor, desc.idProduct,
			libusb_get_bus_number(dev), libusb_get_device_address(dev));

		// DEBUG: Access an XBox gamepad through WinUSB
//		if ((desc.idVendor == 0x045e) && (desc.idProduct == 0x0289)) {
		if ((desc.idVendor == VID) && (desc.idProduct == PID)) {
			printf("Opening device:\n");
			r = libusb_open(dev, &handle);
			if (r != LIBUSB_SUCCESS) {
				printf("libusb error: %d\n", r);
				continue;
			}
			
			printf("Claiming interface:\n");
			r = libusb_claim_interface(handle, 0);
			if (r != LIBUSB_SUCCESS) {
				printf("libusb error: %d\n", r);
				continue;
			}

			printf("Releasing interface:\n");
			r = libusb_release_interface(handle, 0);
			if (r != LIBUSB_SUCCESS) {
				printf("libusb error: %d\n", r);
				continue;
			}

			printf("Closing device:\n");
			libusb_close(handle);
		}
	}
}

int main(void)
{
	libusb_device **devs;
	int r;
	ssize_t cnt;

	r = libusb_init(NULL);
	if (r < 0)
		return r;

	cnt = libusb_get_device_list(NULL, &devs);
	if (cnt < 0)
		return (int) cnt;

	print_devs(devs);
	libusb_free_device_list(devs, 1);

	libusb_exit(NULL);
	return 0;
}

