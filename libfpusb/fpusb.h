/*
 * Public libfpusb header file
 * Copyright (C) 2007 Daniel Drake <dsd@gentoo.org>
 *
 * Portions based on libusb-0.1
 * Copyright (c) 2001 Johannes Erdfelt <johannes@erdfelt.com>
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

#ifndef __FPUSB_H__
#define __FPUSB_H__

#include <stdint.h>
#include <sys/time.h>

/* standard USB stuff */

/* Device and/or Interface Class codes */
#define USB_CLASS_PER_INTERFACE		0	/* for DeviceClass */
#define USB_CLASS_AUDIO				1
#define USB_CLASS_COMM				2
#define USB_CLASS_HID				3
#define USB_CLASS_PRINTER			7
#define USB_CLASS_PTP				6
#define USB_CLASS_MASS_STORAGE		8
#define USB_CLASS_HUB				9
#define USB_CLASS_DATA				10
#define USB_CLASS_VENDOR_SPEC		0xff

/* Descriptor types */
#define USB_DT_DEVICE			0x01
#define USB_DT_CONFIG			0x02
#define USB_DT_STRING			0x03
#define USB_DT_INTERFACE		0x04
#define USB_DT_ENDPOINT			0x05
#define USB_DT_HID				0x21
#define USB_DT_REPORT			0x22
#define USB_DT_PHYSICAL			0x23
#define USB_DT_HUB				0x29

/* Descriptor sizes per descriptor type */
#define USB_DT_DEVICE_SIZE			18
#define USB_DT_CONFIG_SIZE			9
#define USB_DT_INTERFACE_SIZE		9
#define USB_DT_ENDPOINT_SIZE		7
#define USB_DT_ENDPOINT_AUDIO_SIZE	9	/* Audio extension */
#define USB_DT_HUB_NONVAR_SIZE		7

#define USB_ENDPOINT_ADDRESS_MASK	0x0f    /* in bEndpointAddress */
#define USB_ENDPOINT_DIR_MASK		0x80

#define USB_ENDPOINT_IN			0x80
#define USB_ENDPOINT_OUT		0x00

#define USB_ENDPOINT_TYPE_MASK			0x03    /* in bmAttributes */
#define USB_ENDPOINT_TYPE_CONTROL		0
#define USB_ENDPOINT_TYPE_ISOCHRONOUS	1
#define USB_ENDPOINT_TYPE_BULK			2
#define USB_ENDPOINT_TYPE_INTERRUPT		3

/* Standard requests */
#define USB_REQ_GET_STATUS			0x00
#define USB_REQ_CLEAR_FEATURE		0x01
/* 0x02 is reserved */
#define USB_REQ_SET_FEATURE			0x03
/* 0x04 is reserved */
#define USB_REQ_SET_ADDRESS			0x05
#define USB_REQ_GET_DESCRIPTOR		0x06
#define USB_REQ_SET_DESCRIPTOR		0x07
#define USB_REQ_GET_CONFIGURATION	0x08
#define USB_REQ_SET_CONFIGURATION	0x09
#define USB_REQ_GET_INTERFACE		0x0A
#define USB_REQ_SET_INTERFACE		0x0B
#define USB_REQ_SYNCH_FRAME			0x0C

#define USB_TYPE_STANDARD		(0x00 << 5)
#define USB_TYPE_CLASS			(0x01 << 5)
#define USB_TYPE_VENDOR			(0x02 << 5)
#define USB_TYPE_RESERVED		(0x03 << 5)

#define USB_RECIP_DEVICE		0x00
#define USB_RECIP_INTERFACE		0x01
#define USB_RECIP_ENDPOINT		0x02
#define USB_RECIP_OTHER			0x03

struct usb_dev_descriptor {
	uint8_t  bLength;
	uint8_t  bDescriptorType;
	uint16_t bcdUSB;
	uint8_t  bDeviceClass;
	uint8_t  bDeviceSubClass;
	uint8_t  bDeviceProtocol;
	uint8_t  bMaxPacketSize0;
	uint16_t idVendor;
	uint16_t idProduct;
	uint16_t bcdDevice;
	uint8_t  iManufacturer;
	uint8_t  iProduct;
	uint8_t  iSerialNumber;
	uint8_t  bNumConfigurations;
};

/* fpusb */

struct fpusb_dev;
typedef struct fpusb_dev fpusb_dev;

struct fpusb_dev_handle;
typedef struct fpusb_dev_handle fpusb_dev_handle;

struct fpusb_urb_handle;
typedef struct fpusb_urb_handle fpusb_urb_handle;

enum fp_urb_cb_status {
	FP_URB_SILENT_COMPLETION = 0,
	FP_URB_COMPLETED,
	FP_URB_TIMEOUT,
	FP_URB_CANCELLED,
};

struct fpusb_ctrl_msg {
	uint8_t requesttype;
	uint8_t request;
	uint16_t value;
	uint16_t index;
	uint16_t length;
	unsigned char *data;
};

typedef void (*fpusb_ctrl_cb_fn)(fpusb_dev_handle *devh, fpusb_urb_handle *urbh,
	struct fpusb_ctrl_msg *msg, enum fp_urb_cb_status status,
	unsigned char *data, int actual_length, void *user_data);

struct fpusb_bulk_msg {
	unsigned char endpoint;
	unsigned char *data;
	int length;
};

typedef void (*fpusb_bulk_cb_fn)(fpusb_dev_handle *devh, fpusb_urb_handle *urbh,
	struct fpusb_bulk_msg *msg, enum fp_urb_cb_status status,
	int actual_length, void *user_data);

int fpusb_init(int signum);
void fpusb_exit(void);

int fpusb_find_devices(void);
fpusb_dev *fpusb_get_devices(void);
struct usb_dev_descriptor *fpusb_dev_get_descriptor(fpusb_dev *dev);
fpusb_dev *fpusb_dev_next(fpusb_dev *dev);

fpusb_dev_handle *fpusb_dev_open(fpusb_dev *dev);
void fpusb_dev_close(fpusb_dev_handle *devh);
int fpusb_dev_claim_intf(fpusb_dev_handle *dev, int iface);
int fpusb_dev_release_intf(fpusb_dev_handle *dev, int iface);

/* async I/O */

fpusb_urb_handle *fpusb_submit_ctrl_msg(fpusb_dev_handle *devh,
	struct fpusb_ctrl_msg *msg, fpusb_ctrl_cb_fn callback, void *user_data,
	unsigned int timeout);
fpusb_urb_handle *fpusb_submit_bulk_msg(fpusb_dev_handle *devh,
	struct fpusb_bulk_msg *msg, fpusb_bulk_cb_fn callback, void *user_data,
	unsigned int timeout);
fpusb_urb_handle *fpusb_submit_intr_msg(fpusb_dev_handle *devh,
	struct fpusb_bulk_msg *msg, fpusb_bulk_cb_fn callback, void *user_data,
	unsigned int timeout);

int fpusb_urb_handle_cancel(fpusb_dev_handle *devh, fpusb_urb_handle *urbh);
int fpusb_urb_handle_cancel_sync(fpusb_dev_handle *devh,
	fpusb_urb_handle *urbh);
void fpusb_urb_handle_free(fpusb_urb_handle *urbh);

int fpusb_poll_timeout(struct timeval *tv);
int fpusb_poll(void);

/* sync I/O */

int fpusb_ctrl_msg(fpusb_dev_handle *devh, struct fpusb_ctrl_msg *msg,
	unsigned int timeout);
int fpusb_bulk_msg(fpusb_dev_handle *devh, struct fpusb_bulk_msg *msg,
	int *transferred, unsigned int timeout);
int fpusb_intr_msg(fpusb_dev_handle *devh, struct fpusb_bulk_msg *msg,
	int *transferred, unsigned int timeout);

#endif
