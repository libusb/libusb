/*
 * xusb: libusb-winusb specific test program, (c) 2009 Pete Batard
 * based on lsusb, copyright (C) 2007 Daniel Drake <dsd@gentoo.org>
 *
 * This test program tries to access an USB device through WinUSB. 
 * To access your device, modify this source and add your VID/PID.
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
#include <string.h>
#include "../config.h"

#include <libusb/libusb.h>

#ifdef OS_WINDOWS
#include <windows.h>
#define msleep(msecs) Sleep(msecs)
#ifdef interface
#undef interface
#endif
#else
#include <unistd.h>
#define	msleep(msecs) usleep(1000*msecs)
#endif

#define perr(...) fprintf(stderr, __VA_ARGS__)
#define ERR_EXIT(errcode) do { perr("  libusb error: %d\n", errcode); return -1; } while (0)
#define CALL_CHECK(fcall) do { r=fcall; if (r < 0) ERR_EXIT(r); } while (0);
#define B(x) (((x)!=0)?1:0)

// HID Class-Specific Requests values. See section 7.2 of the HID specifications
#define HID_GET_REPORT                0x01
#define HID_GET_IDLE                  0x02
#define HID_GET_PROTOCOL              0x03
#define HID_SET_REPORT                0x09
#define HID_SET_IDLE                  0x0A
#define HID_SET_PROTOCOL              0x0B
#define HID_REPORT_TYPE_INPUT         0x01
#define HID_REPORT_TYPE_OUTPUT        0x02
#define HID_REPORT_TYPE_FEATURE       0x03

// Mass Storage Requests values. See section 3 of the Bulk-Only Mass Storage Class specifications
#define BOMS_RESET                    0xFF
#define BOMS_GET_MAX_LUN              0xFE

enum test_type {
	USE_XBOX,
	USE_KEY,
	USE_JTAG,
} test_mode;
uint16_t VID, PID;

// The XBOX Controller is really a HID device that got its  HID Report Descriptors 
// removed by Microsoft.
// Input/Output reports described at http://euc.jp/periphs/xbox-controller.ja.html
int display_xbox_status(libusb_device_handle *handle)
{
	int r;
	uint8_t input_report[20];
	printf("Retrieving XBox Input Report...\n");
	CALL_CHECK(libusb_control_transfer(handle, LIBUSB_ENDPOINT_IN|LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_RECIPIENT_INTERFACE, 
		HID_GET_REPORT, (HID_REPORT_TYPE_INPUT<<8)|0x00, 0, input_report, 20, 1000));
	printf("D-pad: %02X\n", input_report[2]&0x0F);
	printf("Start:%d, Back:%d, Left Stick Press:%d, Right Stick Press:%d\n", B(input_report[2]&0x10), B(input_report[2]&0x20),
		B(input_report[2]&0x40), B(input_report[2]&0x80));
	// A, B, X, Y, Black, White are pressure sensitive
	printf("A:%d, B:%d, X:%d, Y:%d, White:%d, Black:%d\n", input_report[4], input_report[5], 
		input_report[6], input_report[7], input_report[9], input_report[8]);
	printf("Left Trigger: %d, Right Trigger: %d\n", input_report[10], input_report[11]);
	printf("Left Analog (X,Y): (%d,%d)\n", (int16_t)((input_report[13]<<8)|input_report[12]), 
		(int16_t)((input_report[15]<<8)|input_report[14]));
	printf("Right Analog (X,Y): (%d,%d)\n", (int16_t)((input_report[17]<<8)|input_report[16]), 
		(int16_t)((input_report[19]<<8)|input_report[18]));
	return 0;
}

int set_xbox_actuators(libusb_device_handle *handle, uint8_t left, uint8_t right)
{
	int r;
	uint8_t output_report[6];

	printf("Writing XBox Controller Output Report...\n");

	memset(output_report, 0, 6);
	output_report[1] = 6;
	output_report[3] = left;
	output_report[5] = right;

	CALL_CHECK(libusb_control_transfer(handle, LIBUSB_ENDPOINT_OUT|LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_RECIPIENT_INTERFACE, 
		HID_SET_REPORT, (HID_REPORT_TYPE_OUTPUT<<8)|0x00, 0, output_report, 6, 1000));
	return 0;
}

// Mass Storage device to test bulk transfers (/!\ destructive test /!\)
int test_mass_storage(libusb_device_handle *handle)
{
	int r;
	unsigned char lun;
	printf("Sending Mass Storage Reset...\n");
	CALL_CHECK(libusb_control_transfer(handle, LIBUSB_ENDPOINT_OUT|LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_RECIPIENT_INTERFACE, 
		BOMS_RESET, 0, 0, NULL, 0, 1000));
	printf("Getting Max LUN...\n");
	CALL_CHECK(libusb_control_transfer(handle, LIBUSB_ENDPOINT_IN|LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_RECIPIENT_INTERFACE, 
		BOMS_GET_MAX_LUN, 0, 0, &lun, 1, 1000));
	printf("  Max LUN = %d\n", lun);
	return 0;
}

int test_device(uint16_t vid, uint16_t pid)
{
	libusb_device_handle *handle;
	libusb_device *dev;
	int i, j, r;
	int iface = 0;
	
	printf("Opening device...\n");
	handle = libusb_open_device_with_vid_pid(NULL, vid, pid);

	if (handle == NULL) {
		perr("  failed.\n");
		return -1;
	}

	dev = libusb_get_device(handle);

	printf("Claiming interface %d...\n", iface);
	r = libusb_claim_interface(handle, iface);
	if (r != LIBUSB_SUCCESS) {
		// Maybe we need to detach the driver
		perr("failed. Trying to detach driver...\n");
		CALL_CHECK(libusb_detach_kernel_driver(handle, iface));
		printf("Claiming interface again...\n");
		CALL_CHECK(libusb_claim_interface(handle, iface));
	}

	struct libusb_device_descriptor dev_desc;
	printf("reading device descriptor...\n");
	CALL_CHECK(libusb_get_device_descriptor(dev, &dev_desc));
	printf("length = %d\n", dev_desc.bLength);
	printf("device class = %d\n", dev_desc.bDeviceClass);
	printf("ser num = %d\n", dev_desc.iSerialNumber);
	printf("VID:PID %04X:%04X\n", dev_desc.idVendor, dev_desc.idProduct);
	printf("bcdDevice = %04X\n", dev_desc.bcdDevice);
	printf("iMan:iProd:iSer %d:%d:%d\n", dev_desc.iManufacturer, dev_desc.iProduct, dev_desc.iSerialNumber);
	printf("num confs = %d\n", dev_desc.bNumConfigurations);

	struct libusb_config_descriptor *conf_desc;
	printf("reading configuration descriptor...\n");
	CALL_CHECK(libusb_get_config_descriptor(dev, 0, &conf_desc));
	printf("num interfaces = %d\n", conf_desc->bNumInterfaces);
	for (i=0; i<conf_desc->bNumInterfaces; i++) {
		for (j=0; j<conf_desc->interface[i].num_altsetting; j++) {
			printf("interface[%d].altsetting[%d]: num endpoints = %d\n", 
				i, j, conf_desc->interface[i].altsetting[j].bNumEndpoints);
			printf("   Class.SubClass.Protocol: %02X.%02X.%02X\n", 
				conf_desc->interface[i].altsetting[j].bInterfaceClass,
				conf_desc->interface[i].altsetting[j].bInterfaceSubClass,
				conf_desc->interface[i].altsetting[j].bInterfaceProtocol);
		}
	}
	libusb_free_config_descriptor(conf_desc);

	if (test_mode == USE_XBOX) {
		CALL_CHECK(display_xbox_status(handle));
		CALL_CHECK(set_xbox_actuators(handle, 128, 222));
		msleep(2000);
		CALL_CHECK(set_xbox_actuators(handle, 0, 0));
	} else {
		char string[128];
		printf("Retieving string descriptor...\n");
		CALL_CHECK(libusb_get_string_descriptor_ascii(handle, 2, string, 128));
		printf("Got string: \"%s\"\n", string);
	}

	if (test_mode = USE_KEY) {
		CALL_CHECK(test_mass_storage(handle));
	}

	printf("Releasing interface...\n");
	CALL_CHECK(libusb_release_interface(handle, iface));

	printf("Closing device...\n");
	libusb_close(handle);

	return 0;
}

int main(int argc, char** argv)
{
	int r;

	// Default test = Microsoft XBox Controller Type S
	VID = 0x045E;
	PID = 0x0289;
	test_mode = USE_XBOX;

	if (argc == 2) {
		if ((argv[1][0] != '-') || (argv[1][1] == 'h')) {
			printf("usage: %s [-h] [-j] [-k] [-x]\n", argv[0]);
			printf("   -h: display usage\n");
			printf("   -j: test OLIMEX ARM-USB-TINY JTAG, 2 channel composite device\n");
			printf("   -k: test Generic 2 GB USB Key\n");
			printf("   -x: test Microsoft XBox Controller Type S\n");
			return 0;
		}
		switch(argv[1][1]) {
		case 'j':
			// OLIMEX ARM-USB-TINY JTAG, 2 channel composite device
			VID = 0x15BA;
			PID = 0x0004;
			test_mode = USE_JTAG;
			break;
		case 'k':
			// Generic 2 GB USB Key (SCSI Transparent/Bulk Only)
			VID = 0x0204;
			PID = 0x6025;
			test_mode = USE_KEY;
			break;
		default:
			break;
		}
	}

	r = libusb_init(NULL);
	if (r < 0)
		return r;

	test_device(VID, PID);

	libusb_exit(NULL);
	return 0;
}

