/*
 * Public libusb header file
 * Copyright (C) 2007 Daniel Drake <dsd@gentoo.org>
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

#ifndef __LIBUSB_H__
#define __LIBUSB_H__

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

struct usb_endpoint_descriptor {
	uint8_t  bLength;
	uint8_t  bDescriptorType;
	uint8_t  bEndpointAddress;
	uint8_t  bmAttributes;
	uint16_t wMaxPacketSize;
	uint8_t  bInterval;
	uint8_t  bRefresh;
	uint8_t  bSynchAddress;

	unsigned char *extra;	/* Extra descriptors */
	int extralen;
};

struct usb_interface_descriptor {
	uint8_t  bLength;
	uint8_t  bDescriptorType;
	uint8_t  bInterfaceNumber;
	uint8_t  bAlternateSetting;
	uint8_t  bNumEndpoints;
	uint8_t  bInterfaceClass;
	uint8_t  bInterfaceSubClass;
	uint8_t  bInterfaceProtocol;
	uint8_t  iInterface;

	struct usb_endpoint_descriptor *endpoint;

	unsigned char *extra;	/* Extra descriptors */
	int extralen;
};

struct usb_interface {
	struct usb_interface_descriptor *altsetting;
	int num_altsetting;
};

struct usb_config_descriptor {
	uint8_t  bLength;
	uint8_t  bDescriptorType;
	uint16_t wTotalLength;
	uint8_t  bNumInterfaces;
	uint8_t  bConfigurationValue;
	uint8_t  iConfiguration;
	uint8_t  bmAttributes;
	uint8_t  MaxPower;

	struct usb_interface *interface;

	unsigned char *extra;	/* Extra descriptors */
	int extralen;
};

/* off-the-wire structures */

struct usb_ctrl_setup {
	uint8_t  bRequestType;
	uint8_t  bRequest;
	uint16_t wValue;
	uint16_t wIndex;
	uint16_t wLength;
} __attribute__((packed));

/* libusb */

struct libusb_dev;
typedef struct libusb_dev libusb_dev;

struct libusb_dev_handle;
typedef struct libusb_dev_handle libusb_dev_handle;

struct libusb_urb_handle;
typedef struct libusb_urb_handle libusb_urb_handle;

enum fp_urb_cb_status {
	FP_URB_SILENT_COMPLETION = 0,
	FP_URB_COMPLETED,
	FP_URB_TIMEOUT,
	FP_URB_CANCELLED,
};

struct libusb_ctrl_msg {
	uint8_t requesttype;
	uint8_t request;
	uint16_t value;
	uint16_t index;
	uint16_t length;
	unsigned char *data;
};

typedef void (*libusb_ctrl_cb_fn)(libusb_dev_handle *devh, libusb_urb_handle *urbh,
	enum fp_urb_cb_status status, struct usb_ctrl_setup *setup,
	unsigned char *data, int actual_length, void *user_data);

struct libusb_bulk_msg {
	unsigned char endpoint;
	unsigned char *data;
	int length;
};

typedef void (*libusb_bulk_cb_fn)(libusb_dev_handle *devh, libusb_urb_handle *urbh,
	enum fp_urb_cb_status status, unsigned char endpoint,
	int rqlength, unsigned char *data, int actual_length, void *user_data);

int libusb_init(int signum);
void libusb_exit(void);

int libusb_find_devices(void);
libusb_dev *libusb_get_devices(void);
struct usb_dev_descriptor *libusb_dev_get_descriptor(libusb_dev *dev);
struct usb_config_descriptor *libusb_dev_get_config(libusb_dev *dev);
libusb_dev *libusb_dev_next(libusb_dev *dev);

libusb_dev_handle *libusb_devh_open(libusb_dev *dev);
void libusb_devh_close(libusb_dev_handle *devh);
struct libusb_dev *libusb_devh_get_dev(libusb_dev_handle *devh);
int libusb_devh_claim_intf(libusb_dev_handle *dev, int iface);
int libusb_devh_release_intf(libusb_dev_handle *dev, int iface);

/* async I/O */

libusb_urb_handle *libusb_submit_ctrl_msg(libusb_dev_handle *devh,
	struct libusb_ctrl_msg *msg, libusb_ctrl_cb_fn callback, void *user_data,
	unsigned int timeout);
libusb_urb_handle *libusb_submit_bulk_msg(libusb_dev_handle *devh,
	struct libusb_bulk_msg *msg, libusb_bulk_cb_fn callback, void *user_data,
	unsigned int timeout);
libusb_urb_handle *libusb_submit_intr_msg(libusb_dev_handle *devh,
	struct libusb_bulk_msg *msg, libusb_bulk_cb_fn callback, void *user_data,
	unsigned int timeout);

int libusb_urb_handle_cancel(libusb_dev_handle *devh, libusb_urb_handle *urbh);
int libusb_urb_handle_cancel_sync(libusb_dev_handle *devh,
	libusb_urb_handle *urbh);
void libusb_urb_handle_free(libusb_urb_handle *urbh);

int libusb_poll_timeout(struct timeval *tv);
int libusb_poll(void);
int libusb_get_pollfd(void);

/* sync I/O */

int libusb_ctrl_msg(libusb_dev_handle *devh, struct libusb_ctrl_msg *msg,
	unsigned int timeout);
int libusb_bulk_msg(libusb_dev_handle *devh, struct libusb_bulk_msg *msg,
	int *transferred, unsigned int timeout);
int libusb_intr_msg(libusb_dev_handle *devh, struct libusb_bulk_msg *msg,
	int *transferred, unsigned int timeout);

#endif
