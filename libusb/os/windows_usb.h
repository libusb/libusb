/*
 * Windows backend for libusb 1.0
 * Copyright (C) 2009 Pete Batard <pbatard@gmail.com>
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

#pragma once

// Windows API default is uppercase - ugh!
#if !defined(bool)
#define bool BOOLEAN
#endif
#if !defined(true)
#define true TRUE
#endif
#if !defined(false)
#define false FALSE
#endif

// Make sure you keep these in check with what libusb uses for its device declaration
#if !defined(libusb_bus_t)
#define libusb_bus_t uint8_t
#define LIBUSB_BUS_MAX UINT8_MAX
#endif
#if !defined(libusb_devaddr_t)
#define libusb_devaddr_t uint8_t
#define LIBUSB_DEVADDR_MAX UINT8_MAX
#endif

// Better safe than sorry...
#define safe_free(p) do {if (p != NULL) {free(p); p = NULL;}} while(0)
#define safe_closehandle(h) do {if (h != INVALID_HANDLE_VALUE) {CloseHandle(h); h = INVALID_HANDLE_VALUE;}} while(0)
#define safe_strncpy(dst, dst_max, src, count) strncpy(dst, src, min(count, dst_max - 1))
#define safe_strncat(dst, dst_max, src, count) strncat(dst, src, min(count, dst_max - strlen(dst) - 1))
#define safe_strcmp(str1, str2) strcmp(((str1==NULL)?"<NULL>":str1), ((str2==NULL)?"<NULL>":str2))
#define safe_strdup _strdup
#define safe_sprintf _snprintf
#define safe_unref_device(dev) do {if (dev != NULL) {libusb_unref_device(dev); dev = NULL;}} while(0)

#define ROOT_PREFIX "\\\\.\\"

#define wchar_to_utf8_ms(wstr, str, strlen) WideCharToMultiByte(CP_UTF8, 0, wstr, -1, str, strlen, NULL, NULL)
#define ERRNO GetLastError()


/*
 * private structures definition
 * with inline pseudo constructors/destructors
 */

// HCDs
struct windows_hcd_priv {
	HANDLE handle;
	char *name;
	char *path;
	struct windows_hcd_priv *next;
};

static inline void windows_hcd_priv_init(struct windows_hcd_priv* p) {
	p->handle = INVALID_HANDLE_VALUE;
	p->name = NULL;
	p->path = NULL;
	p->next = NULL;
}

static inline void windows_hcd_priv_release(struct windows_hcd_priv* p) {
	safe_closehandle(p->handle);
	safe_free(p->name);
	safe_free(p->path);
}

// Nodes (Hubs & devices)
struct windows_device_priv {
	HANDLE handle;	// connection handle
	struct libusb_device *parent_dev;	// access to parent is required for usermode ops
	ULONG connection_index;	// also required for some usermode ops
	char *path;	// path used by Windows to reference the USB node
	USB_DEVICE_DESCRIPTOR dev_descriptor;
	unsigned char *config_descriptor;
};

static inline void windows_device_priv_init(struct windows_device_priv* p) {
	p->handle = INVALID_HANDLE_VALUE;
	p->parent_dev = NULL;
	p->connection_index = 0;
	p->path = NULL;
	p->config_descriptor = NULL;
	memset(&(p->dev_descriptor), 0, sizeof(USB_DEVICE_DESCRIPTOR));
}

static inline void windows_device_priv_release(struct windows_device_priv* p) {
	safe_closehandle(p->handle);
	safe_free(p->path);
	safe_free(p->config_descriptor);
}

static inline struct windows_device_priv *__device_priv(struct libusb_device *dev) {
	return (struct windows_device_priv *)dev->os_priv;
}

struct windows_device_handle_priv {
	HANDLE fd;
};


struct windows_transfer_priv {
	int NOT_IMPLEMENTED;
};


/*
 * Windows API structures (redefined for convenience)
 */
#define USB_HCD_DRIVERKEY_NAME_FIXED_MAX 64
typedef struct _USB_HCD_DRIVERKEY_NAME_FIXED {
	ULONG ActualLength;
	WCHAR DriverKeyName[USB_HCD_DRIVERKEY_NAME_FIXED_MAX];
} USB_HCD_DRIVERKEY_NAME_FIXED;

// Fixed length version of USB_ROOT_HUB_NAME & USB_NODE_CONNECTION_NAME
#define USB_HUB_NAME_FIXED_MAX 128
typedef struct _USB_ROOT_HUB_NAME_FIXED {
	ULONG ActualLength;
	WCHAR RootHubName[USB_HUB_NAME_FIXED_MAX];
} USB_ROOT_HUB_NAME_FIXED;

typedef struct _USB_NODE_CONNECTION_NAME_FIXED {
	ULONG ConnectionIndex;
	ULONG ActualLength;
	WCHAR NodeName[USB_HUB_NAME_FIXED_MAX];
} USB_NODE_CONNECTION_NAME_FIXED;

typedef struct _USB_HUB_NAME_FIXED {
	union {
		USB_ROOT_HUB_NAME_FIXED root;
		USB_NODE_CONNECTION_NAME_FIXED node;
	} u;
} USB_HUB_NAME_FIXED;

// The following structures need to be packed
#pragma pack(1)
typedef struct _USB_CONFIGURATION_DESCRIPTOR_SHORT {
	USB_DESCRIPTOR_REQUEST req;
	USB_CONFIGURATION_DESCRIPTOR data;
} USB_CONFIGURATION_DESCRIPTOR_SHORT;

typedef struct _USB_DEVICE_DESCRIPTOR_BUFFER {
	USB_DESCRIPTOR_REQUEST req;
	USB_DEVICE_DESCRIPTOR data;
} USB_DEVICE_DESCRIPTOR_BUFFER;
#pragma pack()


/*
 * Some of the EX stuff is not yet in MinGW => define it
 */
#ifndef USB_GET_NODE_CONNECTION_INFORMATION_EX
#define USB_GET_NODE_CONNECTION_INFORMATION_EX 274
#endif

#ifndef IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX
#define IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX \
	CTL_CODE(FILE_DEVICE_USB, USB_GET_NODE_CONNECTION_INFORMATION_EX, \
	METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

#ifndef USB_NODE_CONNECTION_INFORMATION_EX
typedef struct _USB_NODE_CONNECTION_INFORMATION_EX {
	ULONG ConnectionIndex;
	USB_DEVICE_DESCRIPTOR DeviceDescriptor;
	UCHAR CurrentConfigurationValue;
	UCHAR Speed;
	BOOLEAN DeviceIsHub;
	USHORT DeviceAddress;
	ULONG NumberOfOpenPipes;
	USB_CONNECTION_STATUS ConnectionStatus;
	USB_PIPE_INFO PipeList[0];
} USB_NODE_CONNECTION_INFORMATION_EX, *PUSB_NODE_CONNECTION_INFORMATION_EX;
#endif

#ifndef USB_HUB_CAP_FLAGS
typedef union _USB_HUB_CAP_FLAGS {
	ULONG ul;
	struct {
		ULONG HubIsHighSpeedCapable:1;
		ULONG HubIsHighSpeed:1;
		ULONG HubIsMultiTtCapable:1;
		ULONG HubIsMultiTt:1;
		ULONG HubIsRoot:1;
		ULONG HubIsArmedWakeOnConnect:1;
		ULONG ReservedMBZ:26;
	};
} USB_HUB_CAP_FLAGS, *PUSB_HUB_CAP_FLAGS;
#endif

#ifndef USB_HUB_CAPABILITIES_EX
typedef struct _USB_HUB_CAPABILITIES_EX {
	USB_HUB_CAP_FLAGS CapabilityFlags;
} USB_HUB_CAPABILITIES_EX, *PUSB_HUB_CAPABILITIES_EX;
#endif

#ifndef USB_GET_HUB_CAPABILITIES_EX
#define USB_GET_HUB_CAPABILITIES_EX 276
#endif

#ifndef IOCTL_USB_GET_HUB_CAPABILITIES_EX
#define IOCTL_USB_GET_HUB_CAPABILITIES_EX \
	CTL_CODE( FILE_DEVICE_USB, USB_GET_HUB_CAPABILITIES_EX, \
	METHOD_BUFFERED, FILE_ANY_ACCESS )
#endif

