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

#ifdef _MSC_VER
#include <config_msvc.h>
#else
#include <config.h>
#endif
#include <stdio.h>
#include <sys/types.h>
#include <inttypes.h>
#include <string.h>
#include <stdarg.h>

#include <libusb/libusb.h>

#ifdef OS_WINDOWS
#include <windows.h>
#define msleep(msecs) Sleep(msecs)
#else
#include <unistd.h>
#define	msleep(msecs) usleep(1000*msecs)
#endif

inline static int perr(char const *format, ...)
{
	va_list args;
	int r;

	va_start (args, format);
	r = vfprintf(stderr, format, args);
	va_end(args);

	return r;
}

#define ERR_EXIT(errcode) do { perr("  %s\n", libusb_strerror(errcode)); return -1; } while (0)
#define CALL_CHECK(fcall) do { r=fcall; if (r < 0) ERR_EXIT(r); } while (0);
#define B(x) (((x)!=0)?1:0)
#define be_to_int32(buf) (((buf)[0]<<24)|((buf)[1]<<16)|((buf)[2]<<8)|(buf)[3])

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

// Section 5.1: Command Block Wrapper (CBW)
struct command_block_wrapper {
	uint8_t dCBWSignature[4];
	uint32_t dCBWTag;
	uint32_t dCBWDataTransferLength;
	uint8_t bmCBWFlags;
	uint8_t bCBWLUN;
	uint8_t bCBWCBLength;
	uint8_t CBWCB[16];
};

// Section 5.2: Command Status Wrapper (CSW)
struct command_status_wrapper {
	uint8_t dCSWSignature[4];
	uint32_t dCSWTag;
	uint32_t dCSWDataResidue;
	uint8_t bCSWStatus;
};

static uint8_t cdb_length[256] = {
//	 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
	06,06,06,06,06,06,06,06,06,06,06,06,06,06,06,06,  //  0
	06,06,06,06,06,06,06,06,06,06,06,06,06,06,06,06,  //  1
	10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,  //  2
	10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,  //  3
	10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,  //  4
	10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,  //  5
	00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,  //  6
	00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,  //  7
	16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,  //  8
	16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,  //  9
	12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,  //  A
	12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,  //  B
	00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,  //  C
	00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,  //  D
	00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,  //  E
	00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,  //  F
};

enum test_type {
	USE_XBOX,
	USE_KEY,
	USE_JTAG,
	USE_HID,
	USE_SIDEWINDER,
} test_mode;
uint16_t VID, PID;

// The XBOX Controller is really a HID device that got its  HID Report Descriptors 
// removed by Microsoft.
// Input/Output reports described at http://euc.jp/periphs/xbox-controller.ja.html
int display_xbox_status(libusb_device_handle *handle)
{
	int r;
	uint8_t input_report[20];
	printf("\nReading XBox Input Report...\n");
	CALL_CHECK(libusb_control_transfer(handle, LIBUSB_ENDPOINT_IN|LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_RECIPIENT_INTERFACE, 
		HID_GET_REPORT, (HID_REPORT_TYPE_INPUT<<8)|0x00, 0, input_report, 20, 1000));
	printf("   D-pad: %02X\n", input_report[2]&0x0F);
	printf("   Start:%d, Back:%d, Left Stick Press:%d, Right Stick Press:%d\n", B(input_report[2]&0x10), B(input_report[2]&0x20),
		B(input_report[2]&0x40), B(input_report[2]&0x80));
	// A, B, X, Y, Black, White are pressure sensitive
	printf("   A:%d, B:%d, X:%d, Y:%d, White:%d, Black:%d\n", input_report[4], input_report[5], 
		input_report[6], input_report[7], input_report[9], input_report[8]);
	printf("   Left Trigger: %d, Right Trigger: %d\n", input_report[10], input_report[11]);
	printf("   Left Analog (X,Y): (%d,%d)\n", (int16_t)((input_report[13]<<8)|input_report[12]), 
		(int16_t)((input_report[15]<<8)|input_report[14]));
	printf("   Right Analog (X,Y): (%d,%d)\n", (int16_t)((input_report[17]<<8)|input_report[16]), 
		(int16_t)((input_report[19]<<8)|input_report[18]));
	return 0;
}

int set_xbox_actuators(libusb_device_handle *handle, uint8_t left, uint8_t right)
{
	int r;
	uint8_t output_report[6];

	printf("\nWriting XBox Controller Output Report...\n");

	memset(output_report, 0, sizeof(output_report));
	output_report[1] = sizeof(output_report);
	output_report[3] = left;
	output_report[5] = right;

	CALL_CHECK(libusb_control_transfer(handle, LIBUSB_ENDPOINT_OUT|LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_RECIPIENT_INTERFACE, 
		HID_SET_REPORT, (HID_REPORT_TYPE_OUTPUT<<8)|0x00, 0, output_report,06, 1000));
	return 0;
}

int send_mass_storage_command(libusb_device_handle *handle, uint8_t endpoint, uint8_t lun, 
	uint8_t *cdb, uint8_t direction, int data_length, uint32_t *ret_tag)
{
	static uint32_t tag = 1;
	uint8_t cdb_len;
	int r, size;
	struct command_block_wrapper cbw;

	if (cdb == NULL) {
		return -1;
	}

	if (endpoint & LIBUSB_ENDPOINT_IN) {
		perr("send_mass_storage_command: cannot send command on IN endpoint\n");
		return -1;
	}

	cdb_len = cdb_length[cdb[0]];
	if ((cdb_len == 0) || (cdb_len > sizeof(cbw.CBWCB))) {
		perr("send_mass_storage_command: don't know how to handle this command (%02X, length %d)\n",
			cdb[0], cdb_len);
		return -1;
	}

	memset(&cbw, 0, sizeof(cbw));
	cbw.dCBWSignature[0] = 'U';
	cbw.dCBWSignature[1] = 'S';
	cbw.dCBWSignature[2] = 'B';
	cbw.dCBWSignature[3] = 'C';
	*ret_tag = tag;
	cbw.dCBWTag = tag++;
	cbw.dCBWDataTransferLength = data_length;
	cbw.bmCBWFlags = direction;
	cbw.bCBWLUN = lun;
	cbw.bCBWCBLength = cdb_len;
	memcpy(cbw.CBWCB, cdb, cdb_len);

	CALL_CHECK(libusb_bulk_transfer(handle, endpoint, (unsigned char*)&cbw, 15+cdb_len, &size, 1000));
	printf("   sent %d bytes (confirmed %d)\n", 15+cdb_len, size);
	return 0;
}

int get_mass_storage_status(libusb_device_handle *handle, uint8_t endpoint, uint32_t expected_tag)
{
	int r, size;
	struct command_status_wrapper csw;

	CALL_CHECK(libusb_bulk_transfer(handle, endpoint, (unsigned char*)&csw, 13, &size, 1000));
	if (size != 13) {
		perr("   get_mass_storage_status: received %d bytes (expected 13)\n", size);
		return -1;
	}
	if (csw.dCSWTag != expected_tag) {
		perr("   get_mass_storage_status: mismatched tags (expected %08X, received %08X)\n",
			expected_tag, csw.dCSWTag);
		return -1;
	}
	printf("   Mass Storage Status: %02X (%s)\n", csw.bCSWStatus, csw.bCSWStatus?"FAILED":"Success");
	if (csw.dCSWTag != expected_tag)
		return -1;
	if (csw.bCSWStatus)
		return -2;	// request Get Sense

	return 0;
}

void get_sense(libusb_device_handle *handle, uint8_t endpoint_in, uint8_t endpoint_out)
{
	uint8_t cdb[16];	// SCSI Command Descriptor Block
	uint8_t sense[18];
	uint32_t expected_tag;
	int size;

	// Request Sense
	printf("Request Sense:\n");
	memset(sense, 0, sizeof(sense));
	memset(cdb, 0, sizeof(cdb));
	cdb[0] = 0x03;	// Request Sense
	cdb[4] = 0x12;

	send_mass_storage_command(handle, endpoint_out, 0, cdb, LIBUSB_ENDPOINT_IN, 0x12, &expected_tag);
	libusb_bulk_transfer(handle, endpoint_in, (unsigned char*)&sense, 0x12, &size, 1000);
	printf("   received %d bytes\n", size);

	if ((sense[0] != 0x70) && (sense[0] != 0x71)) {
		perr("   ERROR No sense data\n");
	} else {
		perr("   ERROR Sense: %02X %02X %02X\n", sense[2]&0x0F, sense[12], sense[13]);
	}
	get_mass_storage_status(handle, endpoint_in, expected_tag);
}

// Mass Storage device to test bulk transfers (non destructive test)
int test_mass_storage(libusb_device_handle *handle, uint8_t endpoint_in, uint8_t endpoint_out)
{
	int r, i, size;
	uint8_t lun;
	uint32_t expected_tag;
	uint32_t max_lba, block_size;
	double device_size;
	uint8_t cdb[16];	// SCSI Command Descriptor Block
	uint8_t buffer[512];
	if (buffer == NULL) {
		perr("failed to allocate mass storage test buffer\n");
		return -1;
	}

	printf("Sending Mass Storage Reset...\n");
	CALL_CHECK(libusb_control_transfer(handle, LIBUSB_ENDPOINT_OUT|LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_RECIPIENT_INTERFACE, 
		BOMS_RESET, 0, 0, NULL, 0, 1000));
	printf("Reading Max LUN:\n");
	CALL_CHECK(libusb_control_transfer(handle, LIBUSB_ENDPOINT_IN|LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_RECIPIENT_INTERFACE, 
		BOMS_GET_MAX_LUN, 0, 0, &lun, 1, 1000));
	printf("   Max LUN = %d\n", lun);

	// Send Inquiry
	printf("Sending Inquiry:\n");
	memset(buffer, 0, sizeof(buffer));
	memset(cdb, 0, sizeof(cdb));
	cdb[0] = 0x12;	// Inquiry
	cdb[4] = 0x60;	// Inquiry data size

	send_mass_storage_command(handle, endpoint_out, 0, cdb, LIBUSB_ENDPOINT_IN, 0x60, &expected_tag);
	CALL_CHECK(libusb_bulk_transfer(handle, endpoint_in, (unsigned char*)&buffer, 0x60, &size, 1000));
	printf("   received %d bytes\n", size);
	printf("   VID:PID:REV:SPE %s:%s:%s:%s\n", &buffer[8], &buffer[16], &buffer[32], &buffer[38]);
	if (get_mass_storage_status(handle, endpoint_in, expected_tag) == -2) {
		get_sense(handle, endpoint_in, 0x01);
	}

	// Read capacity
	printf("Reading Capacity:\n");
	memset(buffer, 0, sizeof(buffer));
	memset(cdb, 0, sizeof(cdb));
	cdb[0] = 0x25;	// Read Capacity

	send_mass_storage_command(handle, endpoint_out, 0, cdb, LIBUSB_ENDPOINT_IN, 0x08, &expected_tag);
	CALL_CHECK(libusb_bulk_transfer(handle, endpoint_in, (unsigned char*)&buffer, 0x08, &size, 1000));
	printf("   received %d bytes\n", size);
	max_lba = be_to_int32(&buffer[0]);
	block_size = be_to_int32(&buffer[4]);
	device_size = ((double)(max_lba+1))*block_size/(1024*1024*1024);
	printf("   Max LBA: %08X, Block Size: %08X (%.2f GB)\n", max_lba, block_size, device_size);
	if (get_mass_storage_status(handle, endpoint_in, expected_tag) == -2) {
		get_sense(handle, endpoint_in, 0x01);
	}

	size = (block_size > sizeof(buffer))?sizeof(buffer):block_size;

	// Send Read
	printf("Attempting to read %d bytes:\n", size);
	memset(buffer, 0, size);
	memset(cdb, 0, sizeof(cdb));

//	cdb[0] = 0x28;	// Read(10)
//	cdb[7] = 0x02;	// 0x200 bytes

	cdb[0] = 0xA8;	// Read(12)
	cdb[8] = 0x02;	// 0x200 bytes

	send_mass_storage_command(handle, endpoint_out, 0, cdb, LIBUSB_ENDPOINT_IN, size, &expected_tag);
	libusb_bulk_transfer(handle, endpoint_in, (unsigned char*)&buffer, size, &size, 5000);
	printf("   READ: received %d bytes\n", size);
	if (get_mass_storage_status(handle, endpoint_in, expected_tag) == -2) {
		get_sense(handle, endpoint_in, 0x01);
	} else {
		for(i=0; i<0x10; i++) {
			printf(" %02X", buffer[i]);
		}
		printf("\n");
	}

	return 0;
}

// Plantronics (HID)
int display_plantronics_status(libusb_device_handle *handle)
{
	int r;
	uint8_t input_report[2];
	printf("\nReading Plantronics Input Report...\n");
	r = libusb_control_transfer(handle, LIBUSB_ENDPOINT_IN|LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_RECIPIENT_INTERFACE, 
		HID_GET_REPORT, (HID_REPORT_TYPE_INPUT<<8)|0x00, 0, input_report, 2, 5000);
	if (r >= 0) {
		printf("  OK\n");
	} else {
		switch(r) {
		case LIBUSB_ERROR_TIMEOUT:
			printf("  Timeout! Please make sure you press the mute button within the 5 seconds allocated...\n");
			break;
		default:
			printf("  Error: %d\n", r);
			break;
		}
	}
	return 0;
}

// SideWinder (HID)
int display_sidewinder_status(libusb_device_handle *handle)
{
	int r;
	uint8_t input_report[6];
	printf("\nReading SideWinder Input Report.\n");
	r = libusb_control_transfer(handle, LIBUSB_ENDPOINT_IN|LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_RECIPIENT_INTERFACE, 
		HID_GET_REPORT, (HID_REPORT_TYPE_INPUT<<8)|0x00, 0, input_report, 6, 5000);
	if (r >= 0) {
		printf("  OK\n");
	} else {
		switch(r) {
		case LIBUSB_ERROR_TIMEOUT:
			printf("  Timeout! Please make sure you use the joystick within the 5 seconds allocated...\n\n");
			break;
		default:
			printf("  Error: %d\n", r);
			break;
		}
	}
	return 0;
}

int test_device(uint16_t vid, uint16_t pid)
{
	libusb_device_handle *handle;
	libusb_device *dev;
	struct libusb_config_descriptor *conf_desc;
	const struct libusb_endpoint_descriptor *endpoint;
	int i, j, k, r;
	int iface, nb_ifaces, nb_strings;
	int test_scsi = 0;
	struct libusb_device_descriptor dev_desc;
	char string[128];
	uint8_t endpoint_in = 0, endpoint_out = 0;	// default IN and OUT endpoints

	printf("Opening device...\n");
	handle = libusb_open_device_with_vid_pid(NULL, vid, pid);

	if (handle == NULL) {
		perr("  failed.\n");
		return -1;
	}

	dev = libusb_get_device(handle);

	printf("\nReading device descriptor:\n");
	CALL_CHECK(libusb_get_device_descriptor(dev, &dev_desc));
	printf("            length: %d\n", dev_desc.bLength);
	printf("      device class: %d\n", dev_desc.bDeviceClass);
	printf("               S/N: %d\n", dev_desc.iSerialNumber);
	printf("           VID:PID: %04X:%04X\n", dev_desc.idVendor, dev_desc.idProduct);
	printf("         bcdDevice: %04X\n", dev_desc.bcdDevice);
	printf("   iMan:iProd:iSer: %d:%d:%d\n", dev_desc.iManufacturer, dev_desc.iProduct, dev_desc.iSerialNumber);
	printf("          nb confs: %d\n", dev_desc.bNumConfigurations);

	printf("\nReading configuration descriptors:\n");
	CALL_CHECK(libusb_get_config_descriptor(dev, 0, &conf_desc));
	nb_ifaces = conf_desc->bNumInterfaces;
	printf("   nb interfaces = %d\n", nb_ifaces);
	for (i=0; i<conf_desc->bNumInterfaces; i++) {
		for (j=0; j<conf_desc->usb_interface[i].num_altsetting; j++) {
			printf("interface[%d].altsetting[%d]: num endpoints = %d\n", 
				i, j, conf_desc->usb_interface[i].altsetting[j].bNumEndpoints);
			printf("   Class.SubClass.Protocol: %02X.%02X.%02X\n", 
				conf_desc->usb_interface[i].altsetting[j].bInterfaceClass,
				conf_desc->usb_interface[i].altsetting[j].bInterfaceSubClass,
				conf_desc->usb_interface[i].altsetting[j].bInterfaceProtocol);
			if ( (conf_desc->usb_interface[i].altsetting[j].bInterfaceClass == LIBUSB_CLASS_MASS_STORAGE) 
			  && ( (conf_desc->usb_interface[i].altsetting[j].bInterfaceSubClass == 0x01)
			  || (conf_desc->usb_interface[i].altsetting[j].bInterfaceSubClass == 0x06) ) ) {
				// Mass storage devices that can use basic SCSI commands
				test_scsi = -1;
			}
			for (k=0; k<conf_desc->usb_interface[i].altsetting[j].bNumEndpoints; k++) {
				endpoint = &conf_desc->usb_interface[i].altsetting[j].endpoint[k];
				printf("       endpoint[%d].address: %02X\n", k, endpoint->bEndpointAddress);
				// Set the first IN/OUT endpoints found as default for testing
				if (endpoint->bEndpointAddress & LIBUSB_ENDPOINT_IN) {
					if (!endpoint_in) {
						endpoint_in = endpoint->bEndpointAddress;
					}
				} else {
					if (!endpoint_out) {
						endpoint_out = endpoint->bEndpointAddress;
					}
				}
				printf("           max packet size: %04X\n", endpoint->wMaxPacketSize);
				printf("          polling interval: %02X\n", endpoint->bInterval);
			}
		}
	}
	libusb_free_config_descriptor(conf_desc);

	// On Windows, autoclaim will sort things out
#ifndef OS_WINDOWS
	for (iface = 0; iface < nb_ifaces; iface++)
	{
		printf("\nClaiming interface %d...\n", iface);
		r = libusb_claim_interface(handle, iface);
		if (r != LIBUSB_SUCCESS) {
			if (iface == 0) {
				// Maybe we need to detach the driver
				perr("failed. Trying to detach driver...\n");
				libusb_detach_kernel_driver(handle, iface);
				printf("Claiming interface again...\n");
				libusb_claim_interface(handle, iface);
			} else {
				printf("failed.\n");
			}
		}
	}
#endif

	r = libusb_get_string_descriptor(handle, 0, 0, string, 128);
	if (r > 0) {
		nb_strings = string[0];
		printf("\nReading string descriptors:\n");
		for (i=1; i<nb_strings; i++) {
			if (libusb_get_string_descriptor_ascii(handle, (uint8_t)i, string, 128) >= 0) {
				printf("   String (%d/%d): \"%s\"\n", i, nb_strings-1, string);
			}
		}
	}
	
	switch(test_mode) {
	case USE_XBOX:
		CALL_CHECK(display_xbox_status(handle));
		CALL_CHECK(set_xbox_actuators(handle, 128, 222));
		msleep(2000);
		CALL_CHECK(set_xbox_actuators(handle, 0, 0));
		break;
	case USE_SIDEWINDER:
		display_sidewinder_status(handle);
		break;
	case USE_HID:
		display_plantronics_status(handle);
		break;
	default:
		break;
	}

	if (test_scsi) {
		CALL_CHECK(test_mass_storage(handle, endpoint_in, endpoint_out));
	}

	printf("\n");
	for (iface = 0; iface<nb_ifaces; iface++) {
		printf("Releasing interface %d...\n", iface);
		libusb_release_interface(handle, iface);
	}

	printf("Closing device...\n");
	libusb_close(handle);

	return 0;
}

int
#ifdef _MSC_VER
__cdecl
#endif
main(int argc, char** argv)
{
	int r;

	// Default test = Microsoft XBox Controller Type S - 1 interface
	VID = 0x045E;
	PID = 0x0289;
	test_mode = USE_XBOX;

	if (argc == 2) {
		if ((argv[1][0] != '-') || (argv[1][1] == 'h')) {
			printf("usage: %s [-h] [-i] [-j] [-k] [-l] [-s] [-x]\n", argv[0]);
			printf("   -h: display usage\n");
			printf("   -i: test IBM HID Optical Mouse\n");
			printf("   -j: test OLIMEX ARM-USB-TINY JTAG, 2 channel composite device\n");
			printf("   -k: test Generic 2 GB USB Key\n");
			printf("   -s: test Microsoft Sidwinder Precision Pro\n");
			printf("   -x: test Microsoft XBox Controller Type S (default)\n");
			return 0;
		}
		switch(argv[1][1]) {
		case 'i':
			// IBM HID Optical mouse - 1 interface
			VID = 0x04B3;
			PID = 0x3108;
			test_mode = USE_HID;
			break;
		case 'j':
			// OLIMEX ARM-USB-TINY JTAG, 2 channel composite device - 2 interfaces
			VID = 0x15BA;
			PID = 0x0004;
			test_mode = USE_JTAG;
			break;
		case 'k':
			// Generic 2 GB USB Key (SCSI Transparent/Bulk Only) - 1 interface
			VID = 0x0204;
			PID = 0x6025;
			test_mode = USE_KEY;
			break;
		case 'l':
			// Plantronics DSP 400, 2 channel HID composite device - 1 HID interface
			VID = 0x047F;
			PID = 0x0CA1;
			test_mode = USE_HID;
			break;
		case 's':
			// Microsoft Sidewinder Precision Pro Joystick - 1 HID interface
			VID = 0x045E;
			PID = 0x0008;
			test_mode = USE_SIDEWINDER;
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

