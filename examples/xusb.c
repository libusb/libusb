/*
 * xusb: libusb-winusb specific test program
 * Copyright (c) 2009-2010 Pete Batard <pbatard@gmail.com>
 * Based on lsusb, copyright (c) 2007 Daniel Drake <dsd@gentoo.org>
 * With contributions to Mass Storage test by Alan Stern.
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

#include <config.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <libusb/libusb.h>

#ifdef OS_WINDOWS
#define msleep(msecs) Sleep(msecs)
#else
#include <unistd.h>
#define	msleep(msecs) usleep(1000*msecs)
#endif

#if !defined(_MSC_VER) || _MSC_VER<=1200
#define sscanf_s sscanf
#endif

#if !defined(bool)
#define bool int
#endif
#if !defined(true)
#define true (1 == 1)
#endif
#if !defined(false)
#define false (!true)
#endif


// Future versions of libusb will use usb_interface instead of interface
// in libusb_config_descriptor => catter for that
#define usb_interface interface

inline static int perr(char const *format, ...)
{
	va_list args;
	int r;

	va_start (args, format);
	r = vfprintf(stderr, format, args);
	va_end(args);

	return r;
}

#define ERR_EXIT(errcode) do { perr("   %s\n", libusb_strerror(errcode)); return -1; } while (0)
#define CALL_CHECK(fcall) do { r=fcall; if (r < 0) ERR_EXIT(r); } while (0);
#define B(x) (((x)!=0)?1:0)
#define be_to_int32(buf) (((buf)[0]<<24)|((buf)[1]<<16)|((buf)[2]<<8)|(buf)[3])

#define RETRY_MAX                     5
#define REQUEST_SENSE_LENGTH          0x12
#define INQUIRY_LENGTH                0x24
#define READ_CAPACITY_LENGTH          0x08

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
} test_mode;
uint16_t VID, PID;

void display_buffer_hex(unsigned char *buffer, unsigned size) 
{
	unsigned i;

	for (i=0; i<size; i++) {
		if (!(i%0x10))
			printf("\n  ");
		printf(" %02X", buffer[i]);
	}
	printf("\n");
}


// The XBOX Controller is really a HID device that got its HID Report Descriptors 
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
		HID_SET_REPORT, (HID_REPORT_TYPE_OUTPUT<<8)|0x00, 0, output_report, 06, 1000));
	return 0;
}

int send_mass_storage_command(libusb_device_handle *handle, uint8_t endpoint, uint8_t lun, 
	uint8_t *cdb, uint8_t direction, int data_length, uint32_t *ret_tag)
{
	static uint32_t tag = 1;
	uint8_t cdb_len;
	int i, r, size;
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
	// Subclass is 1 or 6 => cdb_len
	cbw.bCBWCBLength = cdb_len;
	memcpy(cbw.CBWCB, cdb, cdb_len);

	i = 0;
	do {
		// The transfer length must always be exactly 31 bytes.
		r = libusb_bulk_transfer(handle, endpoint, (unsigned char*)&cbw, 31, &size, 1000);
		if (r == LIBUSB_ERROR_PIPE) {
			libusb_clear_halt(handle, endpoint);
		}
		i++;
	} while ((r == LIBUSB_ERROR_PIPE) && (i<RETRY_MAX));
	if (r != LIBUSB_SUCCESS) {
		perr("   send_mass_storage_command: %s\n", libusb_strerror(r));
		return -1;
	}	
	
	printf("   sent %d CDB bytes\n", cdb_len);
	return 0;
}

int get_mass_storage_status(libusb_device_handle *handle, uint8_t endpoint, uint32_t expected_tag)
{
	int i, r, size;
	struct command_status_wrapper csw;

	// The device is allowed to STALL this transfer. If it does, you have to
	// clear the stall and try again.
	i = 0;
	do {
		r = libusb_bulk_transfer(handle, endpoint, (unsigned char*)&csw, 13, &size, 1000);
		if (r == LIBUSB_ERROR_PIPE) {
			libusb_clear_halt(handle, endpoint);
		}
		i++;
	} while ((r == LIBUSB_ERROR_PIPE) && (i<RETRY_MAX));
	if (r != LIBUSB_SUCCESS) {
		perr("   get_mass_storage_status: %s\n", libusb_strerror(r));
		return -1;
	}
	if (size != 13) {
		perr("   get_mass_storage_status: received %d bytes (expected 13)\n", size);
		return -1;
	}
	if (csw.dCSWTag != expected_tag) {
		perr("   get_mass_storage_status: mismatched tags (expected %08X, received %08X)\n",
			expected_tag, csw.dCSWTag);
		return -1;
	}
	// For this test, we ignore the dCSWSignature check for validity...
	printf("   Mass Storage Status: %02X (%s)\n", csw.bCSWStatus, csw.bCSWStatus?"FAILED":"Success");
	if (csw.dCSWTag != expected_tag)
		return -1;
	if (csw.bCSWStatus) {
		// REQUEST SENSE is appropriate only if bCSWStatus is 1, meaning that the
		// command failed somehow.  Larger values (2 in particular) mean that
		// the command couldn't be understood.
		if (csw.bCSWStatus == 1)
			return -2;	// request Get Sense
		else
			return -1;
	}

	// In theory we also should check dCSWDataResidue.  But lots of devices
	// set it wrongly.
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
	cdb[4] = REQUEST_SENSE_LENGTH;

	send_mass_storage_command(handle, endpoint_out, 0, cdb, LIBUSB_ENDPOINT_IN, REQUEST_SENSE_LENGTH, &expected_tag);
	libusb_bulk_transfer(handle, endpoint_in, (unsigned char*)&sense, REQUEST_SENSE_LENGTH, &size, 1000);
	printf("   received %d bytes\n", size);

	if ((sense[0] != 0x70) && (sense[0] != 0x71)) {
		perr("   ERROR No sense data\n");
	} else {
		perr("   ERROR Sense: %02X %02X %02X\n", sense[2]&0x0F, sense[12], sense[13]);
	}
	// Strictly speaking, the get_mass_storage_status() call should come
	// before these perr() lines.  If the status is nonzero then we must
	// assume there's no data in the buffer.  For xusb it doesn't matter.
	get_mass_storage_status(handle, endpoint_in, expected_tag);
}

// Mass Storage device to test bulk transfers (non destructive test)
int test_mass_storage(libusb_device_handle *handle, uint8_t endpoint_in, uint8_t endpoint_out)
{
	int r;
	uint8_t lun;
	uint32_t expected_tag;
	uint32_t i, size, max_lba, block_size;
	double device_size;
	uint8_t cdb[16];	// SCSI Command Descriptor Block
	uint8_t buffer[64];
	char vid[9], pid[9], rev[5];
	unsigned char *data;

	printf("Reading Max LUN:\n");
	r = libusb_control_transfer(handle, LIBUSB_ENDPOINT_IN|LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_RECIPIENT_INTERFACE, 
		BOMS_GET_MAX_LUN, 0, 0, &lun, 1, 1000);
	// Some devices send a STALL instead of the actual value. 
	// In such cases we should set lun to 0.
	if (r == 0) {
		lun = 0;
	} else if (r < 0) {
		perr("   Failed: %s", libusb_strerror(r));
	}
	printf("   Max LUN = %d\n", lun);

	// Send Inquiry
	printf("Sending Inquiry:\n");
	memset(buffer, 0, sizeof(buffer));
	memset(cdb, 0, sizeof(cdb));
	cdb[0] = 0x12;	// Inquiry
	cdb[4] = INQUIRY_LENGTH;

	send_mass_storage_command(handle, endpoint_out, lun, cdb, LIBUSB_ENDPOINT_IN, INQUIRY_LENGTH, &expected_tag);
	CALL_CHECK(libusb_bulk_transfer(handle, endpoint_in, (unsigned char*)&buffer, INQUIRY_LENGTH, &size, 1000));
	printf("   received %d bytes\n", size);
	// The following strings are not zero terminated
	for (i=0; i<8; i++) {
		vid[i] = buffer[8+i];
		pid[i] = buffer[16+i];
		rev[i/2] = buffer[32+i/2];	// instead of another loop
	}
	vid[8] = 0;
	pid[8] = 0;
	rev[4] = 0;
	printf("   VID:PID:REV \"%8s\":\"%8s\":\"%4s\"\n", vid, pid, rev);
	if (get_mass_storage_status(handle, endpoint_in, expected_tag) == -2) {
		get_sense(handle, endpoint_in, endpoint_out);
	}

	// Read capacity
	printf("Reading Capacity:\n");
	memset(buffer, 0, sizeof(buffer));
	memset(cdb, 0, sizeof(cdb));
	cdb[0] = 0x25;	// Read Capacity

	send_mass_storage_command(handle, endpoint_out, lun, cdb, LIBUSB_ENDPOINT_IN, READ_CAPACITY_LENGTH, &expected_tag);
	CALL_CHECK(libusb_bulk_transfer(handle, endpoint_in, (unsigned char*)&buffer, READ_CAPACITY_LENGTH, &size, 1000));
	printf("   received %d bytes\n", size);
	max_lba = be_to_int32(&buffer[0]);
	block_size = be_to_int32(&buffer[4]);
	device_size = ((double)(max_lba+1))*block_size/(1024*1024*1024);
	printf("   Max LBA: %08X, Block Size: %08X (%.2f GB)\n", max_lba, block_size, device_size);
	if (get_mass_storage_status(handle, endpoint_in, expected_tag) == -2) {
		get_sense(handle, endpoint_in, endpoint_out);
	}

	data = malloc(block_size);
	if (data == NULL) {
		perr("   unable to allocate data buffer\n");
		return -1;
	}

	// Send Read
	printf("Attempting to read %d bytes:\n", block_size);
	memset(data, 0, block_size);
	memset(cdb, 0, sizeof(cdb));

	cdb[0] = 0x28;	// Read(10)
	cdb[8] = 0x01;	// 1 block

	send_mass_storage_command(handle, endpoint_out, lun, cdb, LIBUSB_ENDPOINT_IN, block_size, &expected_tag);
	libusb_bulk_transfer(handle, endpoint_in, data, block_size, &size, 5000);
	printf("   READ: received %d bytes\n", size);
	if (get_mass_storage_status(handle, endpoint_in, expected_tag) == -2) {
		get_sense(handle, endpoint_in, endpoint_out);
	} else {
		display_buffer_hex(data, size);
	}

	return 0;
}

// HID
int get_hid_input_record_size(uint8_t *hid_report_descriptor, int size)
{
	uint8_t i, j = 0;
	uint8_t offset;
	int record_size[2] = {0, 0};
	int nb_bits = 0, nb_items = 0;
	bool found_bits, found_items, found_direction;

	found_bits = false;
	found_items = false;
	found_direction = false;
	for (i = hid_report_descriptor[0]+1; i < size; i += offset) {
		offset = (hid_report_descriptor[i]&0x03) + 1;
		if (offset == 4)
			offset = 5;
		switch (hid_report_descriptor[i]) {
		case 0x75:	// bitsize
			nb_bits = hid_report_descriptor[i+1];
			found_bits = true;
			break;
		case 0x95:	// count
			nb_items  = hid_report_descriptor[i+1];
			found_items = true;
			break;
		case 0x81:	// input
			found_direction = true;
			j = 0;
			break;
		case 0x91:	// output
			found_direction = true;
			j = 1;
			break;
		case 0xC0:	// end of collection
			nb_items = 0;
			nb_bits = 0;
			break;
		default:
			continue;
		}
		if (found_direction) {
			found_bits = false;
			found_items = false;
			found_direction = false;
			record_size[j] += nb_items*nb_bits;
		}
	}
	return (record_size[0]+7)/8;
}

int test_hid(libusb_device_handle *handle, uint8_t endpoint_in)
{
	int r, size;
	uint8_t hid_report_descriptor[256];
	uint8_t *input_report;

	printf("\nReading HID Report Descriptors:\n");
	r = libusb_control_transfer(handle, LIBUSB_ENDPOINT_IN|LIBUSB_REQUEST_TYPE_STANDARD|LIBUSB_RECIPIENT_INTERFACE, 
		LIBUSB_REQUEST_GET_DESCRIPTOR, LIBUSB_DT_REPORT<<8, 0, hid_report_descriptor, 256, 1000);
	if (r < 0) {
		printf("failed\n");
		return -1;
	} else {
		display_buffer_hex(hid_report_descriptor, r);
		size = get_hid_input_record_size(hid_report_descriptor, r);
		printf("\n   Input Report Length: %d\n", size);
	}

	input_report = calloc(size, 1);
	if (input_report == NULL) {
		return -1;
	}

	printf("\nReading Feature Report...\n");
	r = libusb_control_transfer(handle, LIBUSB_ENDPOINT_IN|LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_RECIPIENT_INTERFACE, 
		HID_GET_REPORT, (HID_REPORT_TYPE_FEATURE<<8)|0, 0, input_report, (uint16_t)size, 5000);
	if (r >= 0) {
		display_buffer_hex(input_report, size);
	} else {
		switch(r) {		
		case LIBUSB_ERROR_NOT_FOUND:
			printf("   No Feature Report available for this device\n");
			break;
		case LIBUSB_ERROR_PIPE:
			printf("   Detected stall - resetting pipe...\n");
			libusb_clear_halt(handle, 0);
			break;
		default:
			printf("   Error: %s\n", libusb_strerror(r));
			break;
		}
	}

	printf("\nReading Input Report...\n");
	r = libusb_control_transfer(handle, LIBUSB_ENDPOINT_IN|LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_RECIPIENT_INTERFACE, 
		HID_GET_REPORT, (HID_REPORT_TYPE_INPUT<<8)|0x00, 0, input_report, (uint16_t)size, 5000);
	if (r >= 0) {
		display_buffer_hex(input_report, size);
	} else {
		switch(r) {
		case LIBUSB_ERROR_TIMEOUT:
			printf("   Timeout! Please make sure you act on the device within the 5 seconds allocated...\n");
			break;
		case LIBUSB_ERROR_PIPE:
			printf("   Detected stall - resetting pipe...\n");
			libusb_clear_halt(handle, 0);
			break;
		default:
			printf("   Error: %s\n", libusb_strerror(r));
			break;
		}
	}

	// Attempt a bulk read from endpoint 0 (this should just return a raw input report)
	printf("\nTesting interrupt read using endpoint %02X...\n", endpoint_in);
	r = libusb_interrupt_transfer(handle, endpoint_in, input_report, size, &size, 5000);
	if (r >= 0) {
		display_buffer_hex(input_report, size);
	} else {
		printf("   %s\n", libusb_strerror(r));
	}

	free(input_report);
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
#ifndef OS_WINDOWS
	int iface_detached = -1;
#endif
	int test_scsi = 0;
	struct libusb_device_descriptor dev_desc;
	char string[128];
	uint8_t endpoint_in = 0, endpoint_out = 0;	// default IN and OUT endpoints

	printf("Opening device...\n");
	handle = libusb_open_device_with_vid_pid(NULL, vid, pid);

	if (handle == NULL) {
		perr("  Failed.\n");
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
	printf("             nb interfaces: %d\n", nb_ifaces);
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
			  || (conf_desc->usb_interface[i].altsetting[j].bInterfaceSubClass == 0x06) ) 
			  && (conf_desc->usb_interface[i].altsetting[j].bInterfaceProtocol == 0x50) ) {
				// Mass storage devices that can use basic SCSI commands
				test_scsi = -1;
			}
			for (k=0; k<conf_desc->usb_interface[i].altsetting[j].bNumEndpoints; k++) {
				endpoint = &conf_desc->usb_interface[i].altsetting[j].endpoint[k];
				printf("       endpoint[%d].address: %02X\n", k, endpoint->bEndpointAddress);
				// Use the last IN/OUT endpoints found as default for testing
				if (endpoint->bEndpointAddress & LIBUSB_ENDPOINT_IN) {
					endpoint_in = endpoint->bEndpointAddress;
				} else {
					endpoint_out = endpoint->bEndpointAddress;
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
				perr("   Failed. Trying to detach driver...\n");
				libusb_detach_kernel_driver(handle, iface);
				iface_detached = iface;
				printf("   Claiming interface again...\n");
				libusb_claim_interface(handle, iface);
			} else {
				printf("failed.\n");
			}
		}
	}
#endif

	printf("\nReading string descriptors:\n");
	r = libusb_get_string_descriptor(handle, 0, 0, string, 128);
	if (r > 0) {
		nb_strings = string[0];
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
	case USE_HID:
		test_hid(handle, endpoint_in);
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

#ifndef OS_WINDOWS
	if (iface_detached >= 0) {
		printf("Re-attaching kernel driver...\n");
		libusb_attach_kernel_driver(handle, iface_detached);
	}
#endif

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
	int show_help = 0;
	int got_vidpid = 0;
	int r;
	size_t i, arglen1, arglen2;
	unsigned tmp_vid, tmp_pid;
	uint16_t endian_test = 0xBE00;

	// Default test = Microsoft XBox Controller Type S - 1 interface
	VID = 0x045E;
	PID = 0x0289;
	test_mode = USE_XBOX;

	if (((uint8_t*)&endian_test)[0] == 0xBE) {
		printf("Despite their natural superiority for end users, big endian\n"
			"CPUs are not supported with this program, sorry.\n");
		return 0;
	}

	if (argc >= 2) {
		arglen1 = strlen(argv[1]);
		if ( ((argv[1][0] == '-') || (argv[1][0] == '/'))
		  && (arglen1 >= 2) ) {
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
				test_mode = USE_HID;
				break;
			default:
				show_help = -1;
				break;
			}
		} else {
			for (i=0; i<arglen1; i++) {
				if (argv[1][i] == ':')
					break;
			}
			if (i != arglen1) {
				if (sscanf_s(argv[1], "%x:%x" , &tmp_vid, &tmp_pid) != 2) {
					printf("   Please specify VID & PID as \"vid:pid\" in hexadecimal format\n");
					return 1;
				}
				VID = (uint16_t)tmp_vid;
				PID = (uint16_t)tmp_pid;
				test_mode = USE_KEY;
				got_vidpid = -1;
			} else {
				show_help = -1;
			}
		}
	}

	if ((argc == 3) && (!got_vidpid)) {
		arglen2 = strlen(argv[2]);
		for (i=0; i<arglen2; i++) {
			if (argv[2][i] == ':')
				break;
		}
		if (i != arglen2) {
			if (sscanf_s(argv[2], "%x:%x" , &tmp_vid, &tmp_pid) != 2) {
				printf("   Please specify VID & PID as \"vid:pid\" in hexadecimal format\n");
				return 1;
			}
			VID = (uint16_t)tmp_vid;
			PID = (uint16_t)tmp_pid;
		} else {
			show_help = -1;
		}
	}

	if ((show_help) || (argc == 1) || (argc >= 4)) {
		printf("usage: %s [-h] [-i] [-j] [-k] [-l] [-s] [-x] [vid:pid]\n", argv[0]);
		printf("   -h: display usage\n");
		printf("   -i: test HID device\n");
		printf("   -j: test OLIMEX ARM-USB-TINY JTAG, 2 channel composite device\n");
		printf("   -k: test Mass Storage USB device\n");
		printf("   -l: test Plantronics Headset (HID)\n");
		printf("   -s: test Microsoft Sidewinder Precision Pro (HID)\n");
		printf("   -x: test Microsoft XBox Controller Type S (default)\n");
		return 0;
	}

	r = libusb_init(NULL);
	if (r < 0)
		return r;

	test_device(VID, PID);

	libusb_exit(NULL);

	return 0;
}

