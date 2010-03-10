/* LIBUSB-WIN32, Generic Windows USB Library
 * Copyright (c) 2002-2005 Stephan Meyer <ste_meyer@web.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#ifndef __DRIVER_API_H__
#define __DRIVER_API_H__

enum {
  LIBUSB0_DEBUG_OFF,
  LIBUSB0_DEBUG_ERR,
  LIBUSB0_DEBUG_MSG,
};


/* 64k */
#define LIBUSB0_MAX_READ_WRITE 0x10000

#define LIBUSB0_MAX_NUMBER_OF_DEVICES 256
#define LIBUSB0_MAX_NUMBER_OF_CHILDREN 32

#define LIBUSB0_IOCTL_SET_CONFIGURATION CTL_CODE(FILE_DEVICE_UNKNOWN,\
0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define LIBUSB0_IOCTL_GET_CONFIGURATION CTL_CODE(FILE_DEVICE_UNKNOWN,\
0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define LIBUSB0_IOCTL_SET_INTERFACE CTL_CODE(FILE_DEVICE_UNKNOWN,\
0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define LIBUSB0_IOCTL_GET_INTERFACE CTL_CODE(FILE_DEVICE_UNKNOWN,\
0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define LIBUSB0_IOCTL_SET_FEATURE CTL_CODE(FILE_DEVICE_UNKNOWN,\
0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define LIBUSB0_IOCTL_CLEAR_FEATURE CTL_CODE(FILE_DEVICE_UNKNOWN,\
0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define LIBUSB0_IOCTL_GET_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN,\
0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define LIBUSB0_IOCTL_SET_DESCRIPTOR CTL_CODE(FILE_DEVICE_UNKNOWN,\
0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define LIBUSB0_IOCTL_GET_DESCRIPTOR CTL_CODE(FILE_DEVICE_UNKNOWN,\
0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define LIBUSB0_IOCTL_INTERRUPT_OR_BULK_WRITE CTL_CODE(FILE_DEVICE_UNKNOWN,\
0x80A, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

#define LIBUSB0_IOCTL_INTERRUPT_OR_BULK_READ CTL_CODE(FILE_DEVICE_UNKNOWN,\
0x80B, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

#define LIBUSB0_IOCTL_VENDOR_WRITE CTL_CODE(FILE_DEVICE_UNKNOWN,\
0x80C, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define LIBUSB0_IOCTL_VENDOR_READ CTL_CODE(FILE_DEVICE_UNKNOWN,\
0x80D, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define LIBUSB0_IOCTL_RESET_ENDPOINT CTL_CODE(FILE_DEVICE_UNKNOWN,\
0x80E, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define LIBUSB0_IOCTL_ABORT_ENDPOINT CTL_CODE(FILE_DEVICE_UNKNOWN,\
0x80F, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define LIBUSB0_IOCTL_RESET_DEVICE CTL_CODE(FILE_DEVICE_UNKNOWN,\
0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define LIBUSB0_IOCTL_SET_DEBUG_LEVEL CTL_CODE(FILE_DEVICE_UNKNOWN,\
0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define LIBUSB0_IOCTL_GET_VERSION CTL_CODE(FILE_DEVICE_UNKNOWN,\
0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define LIBUSB0_IOCTL_ISOCHRONOUS_WRITE CTL_CODE(FILE_DEVICE_UNKNOWN,\
0x813, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

#define LIBUSB0_IOCTL_ISOCHRONOUS_READ CTL_CODE(FILE_DEVICE_UNKNOWN,\
0x814, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

#define LIBUSB0_IOCTL_CLAIM_INTERFACE CTL_CODE(FILE_DEVICE_UNKNOWN,\
0x815, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define LIBUSB0_IOCTL_RELEASE_INTERFACE CTL_CODE(FILE_DEVICE_UNKNOWN,\
0x816, METHOD_BUFFERED, FILE_ANY_ACCESS)

#include <pshpack1.h> 


typedef struct {
  unsigned int timeout;
  union {
    struct
    {
      unsigned int configuration;
    } configuration;
    struct
    {
      unsigned int interface;
      unsigned int altsetting;
    } interface;
    struct
    {
      unsigned int endpoint;
      unsigned int packet_size;
    } endpoint;    
    struct
    {
      unsigned int type;
      unsigned int recipient;
      unsigned int request;
      unsigned int value;
      unsigned int index;
    } vendor;
    struct
    {
      unsigned int recipient;
      unsigned int feature;
      unsigned int index;
    } feature;
    struct
    {
      unsigned int recipient;
      unsigned int index;
      unsigned int status;
    } status;
    struct
    {
      unsigned int type;
      unsigned int index;
      unsigned int language_id;
      unsigned int recipient;
    } descriptor;    
    struct
    {
      unsigned int level;
    } debug;
    struct
    {
      unsigned int major;
      unsigned int minor;
      unsigned int micro;
      unsigned int nano;
    } version;
  };
} libusb0_request;
    
#include <poppack.h>

#endif
