/*
 * Internal header for libfpusb
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

#ifndef __FPUSBI_H__
#define __FPUSBI_H__

#include <config.h>

#include <endian.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <time.h>

#include <fpusb.h>
#include <usbfs.h>

#define USBFS_PATH "/dev/bus/usb"
#define DEVICE_DESC_LENGTH		18

#define USB_MAXENDPOINTS	32
#define USB_MAXINTERFACES	32
#define USB_MAXCONFIG		8

struct list_head {
	struct list_head *prev, *next;
};

/* Get an entry from the list 
 * 	ptr - the address of this list_head element in "type" 
 * 	type - the data type that contains "member"
 * 	member - the list_head element in "type" 
 */
#define list_entry(ptr, type, member) \
	((type *)((char *)(ptr) - (unsigned long)(&((type *)0L)->member)))

/* Get each entry from a list
 *	pos - A structure pointer has a "member" element
 *	head - list head
 *	member - the list_head element in "pos"
 */
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member);	\
	     &pos->member != (head);					\
	     pos = list_entry(pos->member.next, typeof(*pos), member))

#define list_for_each_entry_safe(pos, n, head, member)			\
        for (pos = list_entry((head)->next, typeof(*pos), member),	\
		n = list_entry(pos->member.next, typeof(*pos), member);	\
	     &pos->member != (head);					\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))

#define list_empty(entry) ((entry)->next == (entry))

static inline void list_init(struct list_head *entry)
{
	entry->prev = entry->next = entry;
}

static inline void list_add(struct list_head *entry, struct list_head *head)
{
	entry->next = head->next;
	entry->prev = head;

	head->next->prev = entry;
	head->next = entry;
}

static inline void list_add_tail(struct list_head *entry,
	struct list_head *head)
{
	entry->next = head;
	entry->prev = head->prev;

	head->prev->next = entry;
	head->prev = entry;
}

static inline void list_del(struct list_head *entry)
{
	entry->next->prev = entry->prev;
	entry->prev->next = entry->next;
}

#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})

#define bswap16(x) (((x & 0xff) << 8) | (x >> 8))
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define cpu_to_le16(x) (x)
#define le16_to_cpu(x) (x)
#elif __BYTE_ORDER == __BIG_ENDIAN
#define le16_to_cpu(x) bswap16(x)
#define cpu_to_le16(x) bswap16(x)
#else
#error "Unrecognized endianness"
#endif

#define MIN(a, b)	((a) < (b) ? (a) : (b))
#define MAX(a, b)	((a) > (b) ? (a) : (b))

#define TIMESPEC_IS_SET(ts) ((ts)->tv_sec != 0 || (ts)->tv_nsec != 0)

enum fpi_log_level {
	LOG_LEVEL_DEBUG,
	LOG_LEVEL_INFO,
	LOG_LEVEL_WARNING,
	LOG_LEVEL_ERROR,
};

void fpi_log(enum fpi_log_level, const char *function, const char *format, ...);

#ifdef ENABLE_LOGGING
#define _fpi_log(level, fmt...) fpi_log(level, __FUNCTION__, fmt)
#else
#define _fpi_log(level, fmt...)
#endif

#ifdef ENABLE_DEBUG_LOGGING
#define fp_dbg(fmt...) _fpi_log(LOG_LEVEL_DEBUG, fmt)
#else
#define fp_dbg(fmt...)
#endif

#define fp_info(fmt...) _fpi_log(LOG_LEVEL_INFO, fmt)
#define fp_warn(fmt...) _fpi_log(LOG_LEVEL_WARNING, fmt)
#define fp_err(fmt...) _fpi_log(LOG_LEVEL_ERROR, fmt)

struct fpusb_dev {
	struct list_head list;
	char *nodepath;
	struct usb_dev_descriptor desc;
	struct usb_config_descriptor *config;
};

struct fpusb_dev_handle {
	struct list_head list;
	struct fpusb_dev *dev;
	int fd;
};

enum fpusb_urb_type {
	FPUSB_URB_CONTROL,
	FPUSB_URB_BULK,
};

#define FPUSB_URBH_DATA_BELONGS_TO_USER		(1<<0)
#define FPUSB_URBH_SYNC_CANCELLED 			(1<<1)
#define FPUSB_URBH_TIMED_OUT	 			(1<<2)

struct fpusb_urb_handle {
	struct fpusb_dev_handle *devh;
	struct usb_urb urb;
	struct list_head list;
	struct timespec timeout;
	timer_t timer;
	unsigned char urb_type;
	unsigned char endpoint;
	void *msg;
	int transfer_len;
	int transferred;
	unsigned char *buffer;
	void *callback;
	void *user_data;
	uint8_t flags;
};

/* bus structures */

struct usb_ctrl_setup {
	uint8_t  bRequestType;
	uint8_t  bRequest;
	uint16_t wValue;
	uint16_t wIndex;
	uint16_t wLength;
} __attribute__((packed));

/* All standard descriptors have these 2 fields in common */
struct usb_descriptor_header {
	uint8_t  bLength;
	uint8_t  bDescriptorType;
};

/* shared data and functions */

extern struct list_head open_devs;

int fpi_io_init(int _signum);
void fpi_io_exit(void);

int fpi_parse_descriptor(unsigned char *source, char *descriptor, void *dest);
int fpi_parse_configuration(struct usb_config_descriptor *config,
		unsigned char *buffer);

#endif

