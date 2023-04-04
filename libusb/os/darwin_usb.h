/*
 * darwin backend for libusb 1.0
 * Copyright © 2008-2023 Nathan Hjelm <hjelmn@users.sourceforge.net>
 * Copyright © 2019-2023 Google LLC. All rights reserved.
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

#if !defined(LIBUSB_DARWIN_H)
#define LIBUSB_DARWIN_H

#include <stdbool.h>

#include "libusbi.h"

#include <IOKit/IOTypes.h>
#include <IOKit/IOCFBundle.h>
#include <IOKit/usb/IOUSBLib.h>
#include <IOKit/IOCFPlugIn.h>

#if defined(HAVE_IOKIT_USB_IOUSBHOSTFAMILYDEFINITIONS_H)
#include <IOKit/usb/IOUSBHostFamilyDefinitions.h>
#endif

/* IOUSBInterfaceInferface */

#if defined(kIOUSBInterfaceInterfaceID800)
#define MAX_INTERFACE_VERSION 800
#elif defined(kIOUSBInterfaceInterfaceID700)
#define	MAX_INTERFACE_VERSION 700
#elif defined(kIOUSBInterfaceInterfaceID650)
#define MAX_INTERFACE_VERSION 650
#elif defined(kIOUSBInterfaceInterfaceID550)
#define MAX_INTERFACE_VERSION 550
#elif defined(kIOUSBInterfaceInterfaceID245)
#define MAX_INTERFACE_VERSION 245
#else
#define	MAX_INTERFACE_VERSION 220
#endif

/* set to the minimum version and casted up as needed. */
typedef IOUSBInterfaceInterface220 **usb_interface_t;

#define IOINTERFACE0(darwin_interface, version) ((IOUSBInterfaceInterface ## version **) (darwin_interface)->interface)
#define IOINTERFACE_V(darwin_interface, version) IOINTERFACE0(darwin_interface, version)
#define IOINTERFACE(darwin_interface) ((darwin_interface)->interface)

/* IOUSBDeviceInterface */

#if defined(kIOUSBDeviceInterfaceID650)
#define MAX_DEVICE_VERSION 650
#elif defined(kIOUSBDeviceInterfaceID500)
#define	MAX_DEVICE_VERSION 500
#elif defined(kIOUSBDeviceInterfaceID320)
#define MAX_DEVICE_VERSION 320
#elif defined(kIOUSBDeviceInterfaceID300)
#define MAX_DEVICE_VERSION 300
#elif defined(kIOUSBDeviceInterfaceID245)
#define MAX_DEVICE_VERSION 245
#else
#define	MAX_DEVICE_VERSION 197
#endif

/* set to the minimum version and casted up as needed */
typedef IOUSBDeviceInterface197 **usb_device_t;

#define IODEVICE0(darwin_device, version) ((IOUSBDeviceInterface ## version **)(darwin_device))
#define IODEVICE_V(darwin_device, version) IODEVICE0(darwin_device, version)

#if !defined(kIOUSBHostInterfaceClassName)
#define kIOUSBHostInterfaceClassName "IOUSBHostInterface"
#endif

#if !defined(kUSBHostMatchingPropertyInterfaceNumber)
#define kUSBHostMatchingPropertyInterfaceNumber "bInterfaceNumber"
#endif

#if !defined(IO_OBJECT_NULL)
#define IO_OBJECT_NULL ((io_object_t) 0)
#endif

/* returns the current macOS version in a format similar to the
 * MAC_OS_X_VERSION_MIN_REQUIRED macro.
 * Examples:
 *   10.1.5 -> 100105
 *   13.3.0 -> 130300
 */
uint32_t get_running_version(void);

typedef IOCFPlugInInterface *io_cf_plugin_ref_t;
typedef IONotificationPortRef io_notification_port_t;

/* private structures */
struct darwin_cached_device {
  struct list_head      list;
  IOUSBDeviceDescriptor dev_descriptor;
  UInt32                location;
  UInt64                parent_session;
  UInt64                session;
  USBDeviceAddress      address;
  char                  sys_path[21];
  usb_device_t          device;
  io_service_t          service;
  int                   open_count;
  UInt8                 first_config, active_config, port;
  int                   can_enumerate;
  int                   refcount;
  bool                  in_reenumerate;
  int                   capture_count;
};

struct darwin_device_priv {
  struct darwin_cached_device *dev;
};

struct darwin_device_handle_priv {
  bool                 is_open;
  CFRunLoopSourceRef   cfSource;

  struct darwin_interface {
    usb_interface_t      interface;
    uint8_t              num_endpoints;
    CFRunLoopSourceRef   cfSource;
    uint64_t             frames[256];
    uint8_t              endpoint_addrs[USB_MAXENDPOINTS];
  } interfaces[USB_MAXINTERFACES];
};

struct darwin_transfer_priv {
  /* Isoc */
  IOUSBIsocFrame *isoc_framelist;
  int num_iso_packets;

  /* Control */
  IOUSBDevRequestTO req;

  /* Bulk */

  /* Completion status */
  IOReturn result;
  UInt32 size;
};

#endif
