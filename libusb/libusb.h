/*
 * Public libusb header file
 * Copyright (C) 2007-2008 Daniel Drake <dsd@gentoo.org>
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

struct libusb_control_setup {
	uint8_t  bRequestType;
	uint8_t  bRequest;
	uint16_t wValue;
	uint16_t wIndex;
	uint16_t wLength;
} __attribute__((packed));

#define LIBUSB_CONTROL_SETUP_SIZE (sizeof(struct libusb_control_setup))

/* libusb */

struct libusb_device;
typedef struct libusb_device libusb_device;

struct libusb_device_handle;
typedef struct libusb_device_handle libusb_device_handle;

enum libusb_transfer_status {
	LIBUSB_TRANSFER_SILENT_COMPLETION = 0,
	LIBUSB_TRANSFER_COMPLETED,
	LIBUSB_TRANSFER_TIMED_OUT,
	LIBUSB_TRANSFER_CANCELLED,
};

struct libusb_transfer;

typedef void (*libusb_transfer_cb_fn)(struct libusb_transfer *transfer);

struct libusb_transfer {
	libusb_device_handle *dev_handle;
	unsigned char endpoint;
	unsigned char endpoint_type;
	unsigned int timeout;
	enum libusb_transfer_status status;

	int length;
	int actual_length;
	libusb_transfer_cb_fn callback;
	void *user_data;

	unsigned char *buffer;
};

int libusb_init(void);
void libusb_exit(void);

int libusb_get_device_list(libusb_device ***list);
void libusb_free_device_list(libusb_device **list, int unref_devices);
struct libusb_dev_descriptor *libusb_device_get_descriptor(libusb_device *dev);
struct libusb_config_descriptor *libusb_device_get_config(libusb_device *dev);
libusb_device *libusb_device_ref(libusb_device *dev);
void libusb_device_unref(libusb_device *dev);

libusb_device_handle *libusb_open(libusb_device *dev);
void libusb_close(libusb_device_handle *devh);
libusb_device *libusb_devh_get_device(libusb_device_handle *devh);
int libusb_claim_interface(libusb_device_handle *dev, int iface);
int libusb_release_interface(libusb_device_handle *dev, int iface);

libusb_device_handle *libusb_open_device_with_vid_pid(uint16_t vendor_id,
	uint16_t product_id);

/* async I/O */

static inline unsigned char *libusb_control_transfer_get_data(
	struct libusb_transfer *transfer)
{
	return transfer->buffer + LIBUSB_CONTROL_SETUP_SIZE;
}

static inline struct libusb_control_setup *libusb_control_transfer_get_setup(
	struct libusb_transfer *transfer)
{
	return (struct libusb_control_setup *) transfer->buffer;
}

static inline void libusb_fill_control_setup(unsigned char *buffer,
	uint8_t bRequestType, uint8_t bRequest, uint16_t wValue, uint16_t wIndex,
	uint16_t wLength)
{
	struct libusb_control_setup *setup = (struct libusb_control_setup *) buffer;
	setup->bRequestType = bRequestType;
	setup->bRequest = bRequest;
	setup->wValue = wValue;
	setup->wIndex = wIndex;
	setup->wLength = wLength;
}

size_t libusb_get_transfer_alloc_size(void);
void libusb_init_transfer(struct libusb_transfer *transfer);

struct libusb_transfer *libusb_alloc_transfer(void);
int libusb_submit_transfer(struct libusb_transfer *transfer);
int libusb_cancel_transfer(libusb_device_handle *devh,
	struct libusb_transfer *transfer);
int libusb_cancel_transfer_sync(libusb_device_handle *devh,
	struct libusb_transfer *transfer);
void libusb_free_transfer(struct libusb_transfer *transfer);

static inline void libusb_fill_control_transfer(
	struct libusb_transfer *transfer, libusb_device_handle *dev_handle,
	unsigned char *buffer, int length, libusb_transfer_cb_fn callback,
	void *user_data, unsigned int timeout)
{
	transfer->dev_handle = dev_handle;
	transfer->endpoint = 0;
	transfer->endpoint_type = LIBUSB_ENDPOINT_TYPE_CONTROL;
	transfer->timeout = timeout;
	transfer->buffer = buffer;
	transfer->length = length;
	transfer->user_data = user_data;
	transfer->callback = callback;
}

static inline void libusb_fill_bulk_transfer(struct libusb_transfer *transfer,
	libusb_device_handle *dev_handle, unsigned char endpoint,
	unsigned char *buffer, int length, libusb_transfer_cb_fn callback,
	void *user_data, unsigned int timeout)
{
	transfer->dev_handle = dev_handle;
	transfer->endpoint = endpoint;
	transfer->endpoint_type = LIBUSB_ENDPOINT_TYPE_BULK;
	transfer->timeout = timeout;
	transfer->buffer = buffer;
	transfer->length = length;
	transfer->user_data = user_data;
	transfer->callback = callback;
}

static inline void libusb_fill_interrupt_transfer(
	struct libusb_transfer *transfer, libusb_device_handle *dev_handle,
	unsigned char endpoint, unsigned char *buffer, int length,
	libusb_transfer_cb_fn callback, void *user_data, unsigned int timeout)
{
	transfer->dev_handle = dev_handle;
	transfer->endpoint = endpoint;
	transfer->endpoint_type = LIBUSB_ENDPOINT_TYPE_INTERRUPT;
	transfer->timeout = timeout;
	transfer->buffer = buffer;
	transfer->length = length;
	transfer->user_data = user_data;
	transfer->callback = callback;
}

/* sync I/O */

int libusb_control_transfer(libusb_device_handle *dev_handle,
	uint8_t request_type, uint8_t request, uint16_t value, uint16_t index,
	unsigned char *data, uint16_t length, unsigned int timeout);

int libusb_bulk_transfer(libusb_device_handle *dev_handle,
	unsigned char endpoint, unsigned char *data, int length,
	int *actual_length, unsigned int timeout);

int libusb_interrupt_transfer(libusb_device_handle *dev_handle,
	unsigned char endpoint, unsigned char *data, int length,
	int *actual_length, unsigned int timeout);

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
