/*
 * xusb: libusb-winusb specific test program, (c) 2009 Pete Batard
 * based on lsusb, copyright (C) 2007 Daniel Drake <dsd@gentoo.org>
 *
 * This test program tries to access an USB device through WinUSB. 
 * To access your device, change VID/PID.
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
#include <inttypes.h>

#include <libusb/libusb.h>

#define perr(...) fprintf(stderr, __VA_ARGS__)
#define ERR_EXIT(errcode) do { perr("  libusb error: %d\n", errcode); return -1; } while (0)
#define CALL_CHECK(fcall) do { r=fcall; if (r < 0) ERR_EXIT(r); } while (0);

//#define USE_MOUSE
//#define USE_XBOX
#define USE_JTAG

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

#ifdef USE_JTAG
// OLIMEX ARM-USB-TINY, 2 channel composite device
#define VID 0x15BA
#define PID 0x0004
#endif

static void print_devs(libusb_device **devs)
{
	libusb_device *dev;
	int i = 0;

	while ((dev = devs[i++]) != NULL) {
		struct libusb_device_descriptor desc;
		int r = libusb_get_device_descriptor(dev, &desc);
		if (r < 0) {
			perr("failed to get device descriptor\n");
			return;
		}

		printf("%04x:%04x (bus %d, device %d)\n",
			desc.idVendor, desc.idProduct,
			libusb_get_bus_number(dev), libusb_get_device_address(dev));
	}
}

int test_device(uint16_t vid, uint16_t pid)
{
	libusb_device_handle *handle;
	int r;
	int iface = 1;
	
	printf("Opening device...\n");
	handle = libusb_open_device_with_vid_pid(NULL, vid, pid);

	if (handle == NULL) {
		perr("  failed.\n");
		return -1;
	}

	printf("Claiming interface %d...\n", iface);
	r = libusb_claim_interface(handle, iface);
	if (r != LIBUSB_SUCCESS) {
		// Maybe we need to detach the driver
		perr("failed. Trying to detach driver...\n");
		CALL_CHECK(libusb_detach_kernel_driver(handle, iface));
		printf("Claiming interface again...\n");
		CALL_CHECK(libusb_claim_interface(handle, iface));
	}

	char string[128];
	printf("Retieving string descriptor...\n");
	CALL_CHECK(libusb_get_string_descriptor_ascii(handle, 3, string, 128));
	printf("Got string: \"%s\"\n", string);

	printf("Releasing interface...\n");
	CALL_CHECK(libusb_release_interface(handle, iface));

	printf("Closing device...\n");
	libusb_close(handle);

	return 0;
}

int main(void)
{
	libusb_device **devs;
	int r;
	ssize_t cnt;

	r = libusb_init(NULL);
	if (r < 0)
		return r;
/*
	cnt = libusb_get_device_list(NULL, &devs);
	if (cnt < 0)
		return (int) cnt;
*/
//	print_devs(devs);

	test_device(VID, PID);

//	libusb_free_device_list(devs, 1);

	libusb_exit(NULL);
	return 0;
}

