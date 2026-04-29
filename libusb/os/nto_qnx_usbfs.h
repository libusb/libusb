/*
 * QNX Neutrino backend for libusb
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

#ifndef __LIBUSB_USBFS_H__
#define __LIBUSB_USBFS_H__

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/usbdi.h>
#include <fcntl.h>
#include <sys/queue.h>
#include <time.h>

/* message passing */
#include <sys/iofunc.h>
#include <sys/neutrino.h>
#include <sys/dispatch.h>

#include "libusb.h"
#include "libusbi.h"

#define NTO_QNX_MAX_ENDPOINT_COUNT 16

struct claimed_interfaces_list {
    TAILQ_ENTRY(claimed_interfaces_list) chain;
    int claimed_interface;
    struct usbd_device * usbd_device; /**< Claimed USB device. */
    int alt_setting;
};

struct nto_qnx_device_priv
{
    unsigned char * dev_descriptor;
    unsigned char * config_descriptor;
    struct usbd_device * usbd_device; /**< pointer to QNX USB device structure */
    int selected_configuration;
    /* Maps in endpoints to their owning interfaces */
    int in_ep_to_iface[NTO_QNX_MAX_ENDPOINT_COUNT];
    /* Maps out endpoints to their owning interfaces*/
    int out_ep_to_iface[NTO_QNX_MAX_ENDPOINT_COUNT];
    TAILQ_HEAD(, claimed_interfaces_list) claimed_interfaces;
};

struct nto_qnx_device_handle_priv
{
    struct usbd_pipe * control_pipe; /**< device control pipe */
    int fds[2];                  /* file descriptors returned from pipe() */
    char msg_buf[sizeof(uint32_t) + sizeof(void*)];
    int msg_buf_offset;
};

struct nto_qnx_transfer_priv
{
    unsigned char * internal_buffer;
    struct usbd_urb * urb;
    struct usbd_pipe * transfer_pipe;
};

enum {
    MESSAGE_DEVICE_GONE,
    MESSAGE_ASYNC_IO_COMPLETE
};

enum nto_qnx_urb_type {
	NTO_QNX_URB_TYPE_ISO = 0,
	NTO_QNX_URB_TYPE_INTERRUPT = 1,
	NTO_QNX_URB_TYPE_CONTROL = 2,
	NTO_QNX_URB_TYPE_BULK = 3,
};

/* Function declarations */


#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: https://f27svn.qnx.com/svn/repos/osr/trunk/libusb/dist/libusb/os/nto_qnx_usbfs.h $ $Rev: 1771 $")
#endif
