/*
 * usbfs header structures
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

#ifndef __FPUSB_USBFS_H__
#define __FPUSB_USBFS_H__

struct usb_ctrltransfer {
	/* keep in sync with usbdevice_fs.h:usbdevfs_ctrltransfer */
	uint8_t  bRequestType;
	uint8_t  bRequest;
	uint16_t wValue;
	uint16_t wIndex;
	uint16_t wLength;

	uint32_t timeout;	/* in milliseconds */

	/* pointer to data */
	void *data;
};

struct usb_bulktransfer {
	/* keep in sync with usbdevice_fs.h:usbdevfs_bulktransfer */
	unsigned int ep;
	unsigned int len;
	unsigned int timeout;	/* in milliseconds */

	/* pointer to data */
	void *data;
};

struct usb_setinterface {
	/* keep in sync with usbdevice_fs.h:usbdevfs_setinterface */
	unsigned int interface;
	unsigned int altsetting;
};

#define USB_MAXDRIVERNAME 255

struct usb_getdriver {
	unsigned int interface;
	char driver[USB_MAXDRIVERNAME + 1];
};

#define USB_URB_DISABLE_SPD	1
#define USB_URB_ISO_ASAP	2
#define USB_URB_QUEUE_BULK	0x10

enum usb_urb_type {
	USB_URB_TYPE_ISO = 0,
	USB_URB_TYPE_INTERRUPT = 1,
	USB_URB_TYPE_CONTROL = 2,
	USB_URB_TYPE_BULK = 3,
};

struct usb_iso_packet_desc {
	unsigned int length;
	unsigned int actual_length;
	unsigned int status;
};

#define MAX_URB_BUFFER_LENGTH		16384

struct usb_urb {
	unsigned char type;
	unsigned char endpoint;
	int status;
	unsigned int flags;
	void *buffer;
	int buffer_length;
	int actual_length;
	int start_frame;
	int number_of_packets;
	int error_count;
	unsigned int signr;
	void *usercontext;
	struct usb_iso_packet_desc iso_frame_desc[0];
};

struct usb_connectinfo {
	unsigned int devnum;
	unsigned char slow;
};

struct usb_ioctl {
	int ifno;	/* interface 0..N ; negative numbers reserved */
	int ioctl_code;	/* MUST encode size + direction of data so the
			 * macros in <asm/ioctl.h> give correct values */
	void *data;	/* param buffer (in, or out) */
};

struct usb_hub_portinfo {
	unsigned char numports;
	unsigned char port[127];	/* port to device num mapping */
};

#define IOCTL_USB_CONTROL	_IOWR('U', 0, struct usb_ctrltransfer)
#define IOCTL_USB_BULK		_IOWR('U', 2, struct usb_bulktransfer)
#define IOCTL_USB_RESETEP	_IOR('U', 3, unsigned int)
#define IOCTL_USB_SETINTF	_IOR('U', 4, struct usb_setinterface)
#define IOCTL_USB_SETCONFIG	_IOR('U', 5, unsigned int)
#define IOCTL_USB_GETDRIVER	_IOW('U', 8, struct usb_getdriver)
#define IOCTL_USB_SUBMITURB	_IOR('U', 10, struct usb_urb)
#define IOCTL_USB_DISCARDURB	_IO('U', 11)
#define IOCTL_USB_REAPURB	_IOW('U', 12, void *)
#define IOCTL_USB_REAPURBNDELAY	_IOW('U', 13, void *)
#define IOCTL_USB_CLAIMINTF	_IOR('U', 15, unsigned int)
#define IOCTL_USB_RELEASEINTF	_IOR('U', 16, unsigned int)
#define IOCTL_USB_CONNECTINFO	_IOW('U', 17, struct usb_connectinfo)
#define IOCTL_USB_IOCTL         _IOWR('U', 18, struct usb_ioctl)
#define IOCTL_USB_HUB_PORTINFO	_IOR('U', 19, struct usb_hub_portinfo)
#define IOCTL_USB_RESET		_IO('U', 20)
#define IOCTL_USB_CLEAR_HALT	_IOR('U', 21, unsigned int)
#define IOCTL_USB_DISCONNECT	_IO('U', 22)
#define IOCTL_USB_CONNECT	_IO('U', 23)

#endif
