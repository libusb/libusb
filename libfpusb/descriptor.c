/*
 * USB descriptor handling functions for libfpusb
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

#include <stdlib.h>
#include <string.h>

#include "fpusbi.h"

#define DESC_HEADER_LENGTH		2
#define DEVICE_DESC_LENGTH		18
#define CONFIG_DESC_LENGTH		9
#define INTERFACE_DESC_LENGTH		9
#define ENDPOINT_DESC_LENGTH		7
#define ENDPOINT_AUDIO_DESC_LENGTH	9

int fpi_parse_descriptor(unsigned char *source, char *descriptor, void *dest)
{
	unsigned char *sp = source, *dp = dest;
	uint16_t w;
	uint32_t d;
	char *cp;

	for (cp = descriptor; *cp; cp++) {
		switch (*cp) {
			case 'b':	/* 8-bit byte */
				*dp++ = *sp++;
				break;
			case 'w':	/* 16-bit word, convert from little endian to CPU */
				w = (sp[1] << 8) | sp[0]; sp += 2;
				dp += ((unsigned long)dp & 1);	/* Align to word boundary */
				*((uint16_t *)dp) = w; dp += 2;
				break;
			case 'd':	/* 32-bit dword, convert from little endian to CPU */
				d = (sp[3] << 24) | (sp[2] << 16) | (sp[1] << 8) | sp[0]; sp += 4;
				dp += ((unsigned long)dp & 2);	/* Align to dword boundary */
				*((uint32_t *)dp) = d; dp += 4;
				break;
			case 'W':	/* 16-bit word, keep CPU endianess */
				dp += ((unsigned long)dp & 1);	/* Align to word boundary */
				memcpy(dp, sp, 2); sp += 2; dp += 2;
				break;
			case 'D':	/* 32-bit dword, keep CPU endianess */
				dp += ((unsigned long)dp & 2);	/* Align to dword boundary */
				memcpy(dp, sp, 4); sp += 4; dp += 4;
				break;
		}
	}

	return sp - source;
}

static int parse_endpoint(struct usb_endpoint_descriptor *endpoint,
	unsigned char *buffer, int size)
{
	struct usb_descriptor_header header;
	unsigned char *begin;
	int parsed = 0;
	int len;

	fpi_parse_descriptor(buffer, "bb", &header);

	/* Everything should be fine being passed into here, but we sanity */
	/*  check JIC */
	if (header.bLength > size) {
		fp_err("ran out of descriptors parsing");
		return -1;
	}

	if (header.bDescriptorType != USB_DT_ENDPOINT) {
		fp_err("unexpected descriptor %x (expected %x)",
			header.bDescriptorType, USB_DT_ENDPOINT);
		return parsed;
	}

	if (header.bLength >= ENDPOINT_AUDIO_DESC_LENGTH)
		fpi_parse_descriptor(buffer, "bbbbwbbb", endpoint);
	else if (header.bLength >= ENDPOINT_DESC_LENGTH)
		fpi_parse_descriptor(buffer, "bbbbwb", endpoint);

	buffer += header.bLength;
	size -= header.bLength;
	parsed += header.bLength;

	/* Skip over the rest of the Class Specific or Vendor Specific */
	/*  descriptors */
	begin = buffer;
	while (size >= DESC_HEADER_LENGTH) {
		fpi_parse_descriptor(buffer, "bb", &header);

		if (header.bLength < 2) {
			fp_err("invalid descriptor length %d", header.bLength);
			return -1;
		}

		/* If we find another "proper" descriptor then we're done  */
		if ((header.bDescriptorType == USB_DT_ENDPOINT) ||
				(header.bDescriptorType == USB_DT_INTERFACE) ||
				(header.bDescriptorType == USB_DT_CONFIG) ||
				(header.bDescriptorType == USB_DT_DEVICE))
			break;

		fp_dbg("skipping descriptor %x", header.bDescriptorType);
		buffer += header.bLength;
		size -= header.bLength;
		parsed += header.bLength;
	}

	/* Copy any unknown descriptors into a storage area for drivers */
	/*  to later parse */
	len = (int)(buffer - begin);
	if (!len) {
		endpoint->extra = NULL;
		endpoint->extralen = 0;
		return parsed;
	}

	endpoint->extra = malloc(len);
	if (!endpoint->extra) {
		endpoint->extralen = 0;
		return parsed;
	}

	memcpy(endpoint->extra, begin, len);
	endpoint->extralen = len;

	return parsed;
}

static int parse_interface(struct usb_interface *interface,
	unsigned char *buffer, int size)
{
	int i;
	int len;
	int r;
	int parsed = 0;
	int tmp;
	struct usb_descriptor_header header;
	struct usb_interface_descriptor *ifp;
	unsigned char *begin;

	interface->num_altsetting = 0;

	while (size >= INTERFACE_DESC_LENGTH) {
		interface->altsetting = realloc(interface->altsetting,
			sizeof(struct usb_interface_descriptor) *
			(interface->num_altsetting + 1));
		if (!interface->altsetting)
			return -1;

		ifp = interface->altsetting + interface->num_altsetting;
		interface->num_altsetting++;
		fpi_parse_descriptor(buffer, "bbbbbbbbb", ifp);

		/* Skip over the interface */
		buffer += ifp->bLength;
		parsed += ifp->bLength;
		size -= ifp->bLength;

		begin = buffer;

		/* Skip over any interface, class or vendor descriptors */
		while (size >= DESC_HEADER_LENGTH) {
			fpi_parse_descriptor(buffer, "bb", &header);
			if (header.bLength < 2) {
				fp_err("invalid descriptor of length %d", header.bLength);
				return -1;
			}

			/* If we find another "proper" descriptor then we're done */
			if ((header.bDescriptorType == USB_DT_INTERFACE) ||
					(header.bDescriptorType == USB_DT_ENDPOINT) ||
					(header.bDescriptorType == USB_DT_CONFIG) ||
					(header.bDescriptorType == USB_DT_DEVICE))
				break;

			buffer += header.bLength;
			parsed += header.bLength;
			size -= header.bLength;
		}

		/* Copy any unknown descriptors into a storage area for */
		/*  drivers to later parse */
		len = (int)(buffer - begin);
		if (!len) {
			ifp->extra = NULL;
			ifp->extralen = 0;
		} else {
			ifp->extra = malloc(len);
			if (!ifp->extra) {
				ifp->extralen = 0;
				/* FIXME will leak memory */
				return -1;
			}
			memcpy(ifp->extra, begin, len);
			ifp->extralen = len;
		}

		/* Did we hit an unexpected descriptor? */
		fpi_parse_descriptor(buffer, "bb", &header);
		if ((size >= DESC_HEADER_LENGTH) &&
				((header.bDescriptorType == USB_DT_CONFIG) ||
				 (header.bDescriptorType == USB_DT_DEVICE)))
			return parsed;

		if (ifp->bNumEndpoints > USB_MAXENDPOINTS) {
			fp_err("too many endpoints (%d)", ifp->bNumEndpoints);
			/* FIXME will leak memory */
			return -1;
		}

		if (ifp->bNumEndpoints > 0) {
			tmp = ifp->bNumEndpoints * sizeof(struct usb_endpoint_descriptor);
			ifp->endpoint = malloc(tmp);
			if (!ifp->endpoint)
				/* FIXME will leak memory? */
				return -1;      

			memset(ifp->endpoint, 0, tmp);
			for (i = 0; i < ifp->bNumEndpoints; i++) {
				fpi_parse_descriptor(buffer, "bb", &header);

				if (header.bLength > size) {
					fp_err("ran out of descriptors parsing");
					/* FIXME will leak memory */
					return -1;
				}

				r = parse_endpoint(ifp->endpoint + i, buffer, size);
				if (r < 0)
					/* FIXME will leak memory */
					return r;

				buffer += r;
				parsed += r;
				size -= r;
			}
		} else
			ifp->endpoint = NULL;

		/* We check to see if it's an alternate to this one */
		ifp = (struct usb_interface_descriptor *) buffer;
		if (size < USB_DT_INTERFACE_SIZE ||
				ifp->bDescriptorType != USB_DT_INTERFACE ||
				!ifp->bAlternateSetting)
			return parsed;
	}

	return parsed;
}

int fpi_parse_configuration(struct usb_config_descriptor *config,
	unsigned char *buffer)
{
	int i;
	int r;
	int size;
	int tmp;
	struct usb_descriptor_header header;

	fpi_parse_descriptor(buffer, "bbwbbbbb", config);
	size = config->wTotalLength;

	if (config->bNumInterfaces > USB_MAXINTERFACES) {
		fp_err("too many interfaces (%d)", config->bNumInterfaces);
		return -1;
	}

	tmp = config->bNumInterfaces * sizeof(struct usb_interface);
	config->interface = malloc(tmp);
	if (!config->interface)
		return -1;      

	memset(config->interface, 0, tmp);
	buffer += config->bLength;
	size -= config->bLength;

	config->extra = NULL;
	config->extralen = 0;

	for (i = 0; i < config->bNumInterfaces; i++) {
		int len;
		unsigned char *begin;

		/* Skip over the rest of the Class Specific or Vendor */
		/*  Specific descriptors */
		begin = buffer;
		while (size >= DESC_HEADER_LENGTH) {
			fpi_parse_descriptor(buffer, "bb", &header);

			if ((header.bLength > size) ||
					(header.bLength < DESC_HEADER_LENGTH)) {
				fp_err("invalid descriptor length of %d", header.bLength);
				return -1;
			}

			/* If we find another "proper" descriptor then we're done */
			if ((header.bDescriptorType == USB_DT_ENDPOINT) ||
					(header.bDescriptorType == USB_DT_INTERFACE) ||
					(header.bDescriptorType == USB_DT_CONFIG) ||
					(header.bDescriptorType == USB_DT_DEVICE))
				break;

			fp_dbg("skipping descriptor 0x%x\n", header.bDescriptorType);
			buffer += header.bLength;
			size -= header.bLength;
		}

		/* Copy any unknown descriptors into a storage area for */
		/*  drivers to later parse */
		len = (int)(buffer - begin);
		if (len) {
			/* FIXME: We should realloc and append here */
			if (!config->extralen) {
				config->extra = malloc(len);
				if (!config->extra) {
					config->extralen = 0;
					/* FIXME will leak memory */
					return -1;
				}

				memcpy(config->extra, begin, len);
				config->extralen = len;
			}
		}

		r = parse_interface(config->interface + i, buffer, size);
		if (r < 0)
			return r;

		buffer += r;
		size -= r;
	}

	return size;
}

