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
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* standard USB stuff */

/* Device and/or Interface Class codes */
#define LIBUSB_CLASS_PER_INTERFACE		0	/* for DeviceClass */
#define LIBUSB_CLASS_AUDIO				1
#define LIBUSB_CLASS_COMM				2
#define LIBUSB_CLASS_HID				3
#define LIBUSB_CLASS_PRINTER			7
#define LIBUSB_CLASS_PTP				6
#define LIBUSB_CLASS_MASS_STORAGE		8
#define LIBUSB_CLASS_HUB				9
#define LIBUSB_CLASS_DATA				10
#define LIBUSB_CLASS_VENDOR_SPEC		0xff

/* Descriptor types */
#define LIBUSB_DT_DEVICE			0x01
#define LIBUSB_DT_CONFIG			0x02
#define LIBUSB_DT_STRING			0x03
#define LIBUSB_DT_INTERFACE		0x04
#define LIBUSB_DT_ENDPOINT			0x05
#define LIBUSB_DT_HID				0x21
#define LIBUSB_DT_REPORT			0x22
#define LIBUSB_DT_PHYSICAL			0x23
#define LIBUSB_DT_HUB				0x29

/* Descriptor sizes per descriptor type */
#define LIBUSB_DT_DEVICE_SIZE			18
#define LIBUSB_DT_CONFIG_SIZE			9
#define LIBUSB_DT_INTERFACE_SIZE		9
#define LIBUSB_DT_ENDPOINT_SIZE		7
#define LIBUSB_DT_ENDPOINT_AUDIO_SIZE	9	/* Audio extension */
#define LIBUSB_DT_HUB_NONVAR_SIZE		7

#define LIBUSB_ENDPOINT_ADDRESS_MASK	0x0f    /* in bEndpointAddress */
#define LIBUSB_ENDPOINT_DIR_MASK		0x80

#define LIBUSB_ENDPOINT_IN			0x80
#define LIBUSB_ENDPOINT_OUT		0x00

#define LIBUSB_ENDPOINT_TYPE_MASK			0x03    /* in bmAttributes */
#define LIBUSB_ENDPOINT_TYPE_CONTROL		0
#define LIBUSB_ENDPOINT_TYPE_ISOCHRONOUS	1
#define LIBUSB_ENDPOINT_TYPE_BULK			2
#define LIBUSB_ENDPOINT_TYPE_INTERRUPT		3

/* Standard requests */
#define LIBUSB_REQ_GET_STATUS			0x00
#define LIBUSB_REQ_CLEAR_FEATURE		0x01
/* 0x02 is reserved */
#define LIBUSB_REQ_SET_FEATURE			0x03
/* 0x04 is reserved */
#define LIBUSB_REQ_SET_ADDRESS			0x05
#define LIBUSB_REQ_GET_DESCRIPTOR		0x06
#define LIBUSB_REQ_SET_DESCRIPTOR		0x07
#define LIBUSB_REQ_GET_CONFIGURATION	0x08
#define LIBUSB_REQ_SET_CONFIGURATION	0x09
#define LIBUSB_REQ_GET_INTERFACE		0x0A
#define LIBUSB_REQ_SET_INTERFACE		0x0B
#define LIBUSB_REQ_SYNCH_FRAME			0x0C

#define LIBUSB_TYPE_STANDARD		(0x00 << 5)
#define LIBUSB_TYPE_CLASS			(0x01 << 5)
#define LIBUSB_TYPE_VENDOR			(0x02 << 5)
#define LIBUSB_TYPE_RESERVED		(0x03 << 5)

#define LIBUSB_RECIP_DEVICE		0x00
#define LIBUSB_RECIP_INTERFACE		0x01
#define LIBUSB_RECIP_ENDPOINT		0x02
#define LIBUSB_RECIP_OTHER			0x03

struct libusb_dev_descriptor {
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

struct libusb_endpoint_descriptor {
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

struct libusb_interface_descriptor {
	uint8_t  bLength;
	uint8_t  bDescriptorType;
	uint8_t  bInterfaceNumber;
	uint8_t  bAlternateSetting;
	uint8_t  bNumEndpoints;
	uint8_t  bInterfaceClass;
	uint8_t  bInterfaceSubClass;
	uint8_t  bInterfaceProtocol;
	uint8_t  iInterface;

	struct libusb_endpoint_descriptor *endpoint;

	unsigned char *extra;	/* Extra descriptors */
	int extralen;
};

struct libusb_interface {
	struct libusb_interface_descriptor *altsetting;
	int num_altsetting;
};

struct libusb_config_descriptor {
	uint8_t  bLength;
	uint8_t  bDescriptorType;
	uint16_t wTotalLength;
	uint8_t  bNumInterfaces;
	uint8_t  bConfigurationValue;
	uint8_t  iConfiguration;
	uint8_t  bmAttributes;
	uint8_t  MaxPower;

	struct libusb_interface *interface;

	unsigned char *extra;	/* Extra descriptors */
	int extralen;
};

/* off-the-wire structures */

struct libusb_ctrl_setup {
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

enum libusb_urb_cb_status {
	FP_URB_SILENT_COMPLETION = 0,
	FP_URB_COMPLETED,
	FP_URB_TIMEOUT,
	FP_URB_CANCELLED,
};

struct libusb_control_transfer {
	uint8_t requesttype;
	uint8_t request;
	uint16_t value;
	uint16_t index;
	uint16_t length;
	unsigned char *data;
};

typedef void (*libusb_ctrl_cb_fn)(libusb_dev_handle *devh, libusb_urb_handle *urbh,
	enum libusb_urb_cb_status status, struct libusb_ctrl_setup *setup,
	unsigned char *data, int actual_length, void *user_data);

struct libusb_bulk_transfer {
	unsigned char endpoint;
	unsigned char *data;
	int length;
};

typedef void (*libusb_bulk_cb_fn)(libusb_dev_handle *devh, libusb_urb_handle *urbh,
	enum libusb_urb_cb_status status, unsigned char endpoint,
	int rqlength, unsigned char *data, int actual_length, void *user_data);

int libusb_init(void);
void libusb_exit(void);

int libusb_find_devices(void);
libusb_dev *libusb_get_devices(void);
struct libusb_dev_descriptor *libusb_dev_get_descriptor(libusb_dev *dev);
struct libusb_config_descriptor *libusb_dev_get_config(libusb_dev *dev);
libusb_dev *libusb_dev_next(libusb_dev *dev);

libusb_dev_handle *libusb_open(libusb_dev *dev);
void libusb_close(libusb_dev_handle *devh);
struct libusb_dev *libusb_devh_get_dev(libusb_dev_handle *devh);
int libusb_claim_interface(libusb_dev_handle *dev, int iface);
int libusb_release_interface(libusb_dev_handle *dev, int iface);

/* async I/O */

libusb_urb_handle *libusb_async_control_transfer(libusb_dev_handle *devh,
	struct libusb_control_transfer *transfer, libusb_ctrl_cb_fn callback,
	void *user_data, unsigned int timeout);
libusb_urb_handle *libusb_async_bulk_transfer(libusb_dev_handle *devh,
	struct libusb_bulk_transfer *transfer, libusb_bulk_cb_fn callback,
	void *user_data, unsigned int timeout);
libusb_urb_handle *libusb_async_interrupt_transfer(libusb_dev_handle *devh,
	struct libusb_bulk_transfer *transfer, libusb_bulk_cb_fn callback,
	void *user_data, unsigned int timeout);

int libusb_urb_handle_cancel(libusb_dev_handle *devh, libusb_urb_handle *urbh);
int libusb_urb_handle_cancel_sync(libusb_dev_handle *devh,
	libusb_urb_handle *urbh);
void libusb_urb_handle_free(libusb_urb_handle *urbh);

/* sync I/O */

int libusb_control_transfer(libusb_dev_handle *devh,
	struct libusb_control_transfer *transfer, unsigned int timeout);
int libusb_bulk_transfer(libusb_dev_handle *devh,
	struct libusb_bulk_transfer *transfer, int *transferred,
	unsigned int timeout);
int libusb_interrupt_transfer(libusb_dev_handle *devh,
	struct libusb_bulk_transfer *transfer, int *transferred,
	unsigned int timeout);

/* polling and timeouts */
struct libusb_pollfd {
	int fd;
	short events;
};

int libusb_poll_timeout(struct timeval *tv);
int libusb_poll(void);
int libusb_get_next_timeout(struct timeval *tv);
size_t libusb_get_pollfds(struct libusb_pollfd **pollfds);

typedef void (*libusb_pollfd_added_cb)(int fd, short events);
typedef void (*libusb_pollfd_removed_cb)(int fd);
void libusb_set_pollfd_notifiers(libusb_pollfd_added_cb added_cb,
	libusb_pollfd_removed_cb removed_cb);

#ifdef __cplusplus
}
#endif

#endif
