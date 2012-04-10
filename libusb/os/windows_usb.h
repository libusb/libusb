/*
 * Windows backend for libusb 1.0
 * Copyright (C) 2009-2010 Pete Batard <pbatard@gmail.com>
 * With contributions from Michael Plante, Orin Eman et al.
 * Parts of this code adapted from libusb-win32-v1 by Stephan Meyer
 * Major code testing contribution by Xiaofan Chen
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

#if defined(_MSC_VER)
// disable /W4 MSVC warnings that are benign
#pragma warning(disable:4127) // conditional expression is constant
#pragma warning(disable:4100) // unreferenced formal parameter
#pragma warning(disable:4214) // bit field types other than int
#pragma warning(disable:4201) // nameless struct/union
#endif

// Windows API default is uppercase - ugh!
#if !defined(bool)
#define bool BOOL
#endif
#if !defined(true)
#define true TRUE
#endif
#if !defined(false)
#define false FALSE
#endif

// Missing from MSVC6 setupapi.h
#if !defined(SPDRP_ADDRESS)
#define SPDRP_ADDRESS	28
#endif
#if !defined(SPDRP_INSTALL_STATE)
#define SPDRP_INSTALL_STATE	34
#endif

#if defined(__CYGWIN__ )
// cygwin produces a warning unless these prototypes are defined
extern int _snprintf(char *buffer, size_t count, const char *format, ...);
extern char *_strdup(const char *strSource);
// _beginthreadex is MSVCRT => unavailable for cygwin. Fallback to using CreateThread
#define _beginthreadex(a, b, c, d, e, f) CreateThread(a, b, (LPTHREAD_START_ROUTINE)c, d, e, f)
#endif
#define safe_free(p) do {if (p != NULL) {free((void*)p); p = NULL;}} while(0)
#define safe_closehandle(h) do {if (h != INVALID_HANDLE_VALUE) {CloseHandle(h); h = INVALID_HANDLE_VALUE;}} while(0)
#define safe_min(a, b) min((size_t)(a), (size_t)(b))
#define safe_strcp(dst, dst_max, src, count) do {memcpy(dst, src, safe_min(count, dst_max)); \
	((char*)dst)[safe_min(count, dst_max)-1] = 0;} while(0)
#define safe_strcpy(dst, dst_max, src) safe_strcp(dst, dst_max, src, safe_strlen(src)+1)
#define safe_strncat(dst, dst_max, src, count) strncat(dst, src, safe_min(count, dst_max - safe_strlen(dst) - 1))
#define safe_strcat(dst, dst_max, src) safe_strncat(dst, dst_max, src, safe_strlen(src)+1)
#define safe_strcmp(str1, str2) strcmp(((str1==NULL)?"<NULL>":str1), ((str2==NULL)?"<NULL>":str2))
#define safe_strncmp(str1, str2, count) strncmp(((str1==NULL)?"<NULL>":str1), ((str2==NULL)?"<NULL>":str2), count)
#define safe_strlen(str) ((str==NULL)?0:strlen(str))
#define safe_sprintf _snprintf
#define safe_unref_device(dev) do {if (dev != NULL) {libusb_unref_device(dev); dev = NULL;}} while(0)
#define wchar_to_utf8_ms(wstr, str, strlen) WideCharToMultiByte(CP_UTF8, 0, wstr, -1, str, strlen, NULL, NULL)
static inline void upperize(char* str) {
	size_t i;
	if (str == NULL) return;
	for (i=0; i<safe_strlen(str); i++)
		str[i] = (char)toupper((int)str[i]);
}

#define MAX_CTRL_BUFFER_LENGTH      4096
#define MAX_USB_DEVICES             256
#define MAX_USB_STRING_LENGTH       128
#define MAX_GUID_STRING_LENGTH      40
#define MAX_PATH_LENGTH             128
#define MAX_KEY_LENGTH              256
#define MAX_TIMER_SEMAPHORES        128
#define TIMER_REQUEST_RETRY_MS      100
#define ERR_BUFFER_SIZE             256
#define LIST_SEPARATOR              ';'
#define HTAB_SIZE                   1021

// http://msdn.microsoft.com/en-us/library/ff545978.aspx
// http://msdn.microsoft.com/en-us/library/ff545972.aspx
// http://msdn.microsoft.com/en-us/library/ff545982.aspx
#if !defined(GUID_DEVINTERFACE_USB_HOST_CONTROLLER)
const GUID GUID_DEVINTERFACE_USB_HOST_CONTROLLER = { 0x3ABF6F2D, 0x71C4, 0x462A, {0x8A, 0x92, 0x1E, 0x68, 0x61, 0xE6, 0xAF, 0x27} };
#endif
#if !defined(GUID_DEVINTERFACE_USB_DEVICE)
const GUID GUID_DEVINTERFACE_USB_DEVICE = { 0xA5DCBF10, 0x6530, 0x11D2, {0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED} };
#endif
#if !defined(GUID_DEVINTERFACE_USB_HUB)
const GUID GUID_DEVINTERFACE_USB_HUB = { 0xF18A0E88, 0xC30C, 0x11D0, {0x88, 0x15, 0x00, 0xA0, 0xC9, 0x06, 0xBE, 0xD8} };
#endif
const GUID GUID_NULL = { 0x00000000, 0x0000, 0x0000, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} };


/*
 * Multiple USB API backend support
 */
#define USB_API_UNSUPPORTED 0
#define USB_API_HUB         1
#define USB_API_COMPOSITE   2
#define USB_API_WINUSB      3
#define USB_API_MAX         4

#define CLASS_GUID_UNSUPPORTED      GUID_NULL
const GUID CLASS_GUID_LIBUSB_WINUSB = { 0x78A1C341, 0x4539, 0x11D3, {0xB8, 0x8D, 0x00, 0xC0, 0x4F, 0xAD, 0x51, 0x71} };
const GUID CLASS_GUID_COMPOSITE     = { 0x36FC9E60, 0xC465, 0x11cF, {0x80, 0x56, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00} };

struct windows_usb_api_backend {
	const uint8_t id;
	const char* designation;
	const GUID *class_guid;  // The Class GUID (for fallback in case the driver name cannot be read)
	const char **driver_name_list; // Driver name, without .sys, e.g. "usbccgp"
	const uint8_t nb_driver_names;
	int (*init)(struct libusb_context *ctx);
	int (*exit)(void);
	int (*open)(struct libusb_device_handle *dev_handle);
	void (*close)(struct libusb_device_handle *dev_handle);
	int (*claim_interface)(struct libusb_device_handle *dev_handle, int iface);
	int (*set_interface_altsetting)(struct libusb_device_handle *dev_handle, int iface, int altsetting);
	int (*release_interface)(struct libusb_device_handle *dev_handle, int iface);
	int (*clear_halt)(struct libusb_device_handle *dev_handle, unsigned char endpoint);
	int (*reset_device)(struct libusb_device_handle *dev_handle);
	int (*submit_bulk_transfer)(struct usbi_transfer *itransfer);
	int (*submit_iso_transfer)(struct usbi_transfer *itransfer);
	int (*submit_control_transfer)(struct usbi_transfer *itransfer);
	int (*abort_control)(struct usbi_transfer *itransfer);
	int (*abort_transfers)(struct usbi_transfer *itransfer);
	int (*copy_transfer_data)(struct usbi_transfer *itransfer, uint32_t io_size);
};

extern const struct windows_usb_api_backend usb_api_backend[USB_API_MAX];

#define PRINT_UNSUPPORTED_API(fname)              \
	usbi_dbg("unsupported API call for '"         \
		#fname "' (unrecognized device driver)"); \
	return LIBUSB_ERROR_NOT_SUPPORTED;

/*
 * private structures definition
 * with inline pseudo constructors/destructors
 */
typedef struct libusb_device_descriptor USB_DEVICE_DESCRIPTOR, *PUSB_DEVICE_DESCRIPTOR;
struct windows_device_priv {
	uint8_t depth;						// distance to HCD
	uint8_t port;						// port number on the hub
	struct libusb_device *parent_dev;	// access to parent is required for usermode ops
	char *path;							// device interface path
	struct windows_usb_api_backend const *apib;
	struct {
		char *path;						// each interface needs a device interface path,
		struct windows_usb_api_backend const *apib; // an API backend (multiple drivers support),
		int8_t nb_endpoints;			// and a set of endpoint addresses (USB_MAXENDPOINTS)
		uint8_t *endpoint;
	} usb_interface[USB_MAXINTERFACES];
	uint8_t composite_api_flags;		// composite devices require additional data
	uint8_t active_config;
	USB_DEVICE_DESCRIPTOR dev_descriptor;
	unsigned char **config_descriptor;	// list of pointers to the cached config descriptors
};

static inline struct windows_device_priv *_device_priv(struct libusb_device *dev) {
	return (struct windows_device_priv *)dev->os_priv;
}

static inline void windows_device_priv_init(libusb_device* dev) {
	struct windows_device_priv* p = _device_priv(dev);
	int i;
	p->depth = 0;
	p->port = 0;
	p->parent_dev = NULL;
	p->path = NULL;
	p->apib = &usb_api_backend[USB_API_UNSUPPORTED];
	p->composite_api_flags = 0;
	p->active_config = 0;
	p->config_descriptor = NULL;
	memset(&(p->dev_descriptor), 0, sizeof(USB_DEVICE_DESCRIPTOR));
	for (i=0; i<USB_MAXINTERFACES; i++) {
		p->usb_interface[i].path = NULL;
		p->usb_interface[i].apib = &usb_api_backend[USB_API_UNSUPPORTED];
		p->usb_interface[i].nb_endpoints = 0;
		p->usb_interface[i].endpoint = NULL;
	}
}

static inline void windows_device_priv_release(libusb_device* dev) {
	struct windows_device_priv* p = _device_priv(dev);
	int i;
	safe_free(p->path);
	if ((dev->num_configurations > 0) && (p->config_descriptor != NULL)) {
		for (i=0; i < dev->num_configurations; i++)
			safe_free(p->config_descriptor[i]);
	}
	safe_free(p->config_descriptor);
	for (i=0; i<USB_MAXINTERFACES; i++) {
		safe_free(p->usb_interface[i].path);
		safe_free(p->usb_interface[i].endpoint);
	}
}

struct interface_handle_t {
	HANDLE dev_handle; // WinUSB needs an extra handle for the file
	HANDLE api_handle; // used by the API to communicate with the device
};

struct windows_device_handle_priv {
	int active_interface;
	struct interface_handle_t interface_handle[USB_MAXINTERFACES];
	int autoclaim_count[USB_MAXINTERFACES]; // For auto-release
};

static inline struct windows_device_handle_priv *_device_handle_priv(
	struct libusb_device_handle *handle)
{
	return (struct windows_device_handle_priv *) handle->os_priv;
}

// used for async polling functions
struct windows_transfer_priv {
	struct winfd pollable_fd;
	uint8_t interface_number;
};

// used to match a device driver (including filter drivers) against a supported API
struct driver_lookup {
	char list[MAX_KEY_LENGTH+1];// REG_MULTI_SZ list of services (driver) names
	const DWORD reg_prop;		// SPDRP registry key to use to retreive list
	const char* designation;	// internal designation (for debug output)
};

/*
 * API macros - from libusb-win32 1.x
 */
#define DLL_DECLARE_PREFIXNAME(api, ret, prefixname, name, args)    \
	typedef ret (api * __dll_##name##_t)args;                 \
	static __dll_##name##_t prefixname = NULL

#define DLL_LOAD_PREFIXNAME(dll, prefixname, name, ret_on_failure) \
	do {                                                      \
		HMODULE h = GetModuleHandleA(#dll);                   \
	if (!h)                                                   \
		h = LoadLibraryA(#dll);                               \
	if (!h) {                                                 \
		if (ret_on_failure) { return LIBUSB_ERROR_NOT_FOUND; }\
		else { break; }                                       \
	}                                                         \
	prefixname = (__dll_##name##_t)GetProcAddress(h, #name);       \
	if (prefixname) break;                                         \
	prefixname = (__dll_##name##_t)GetProcAddress(h, #name "A");   \
	if (prefixname) break;                                         \
	prefixname = (__dll_##name##_t)GetProcAddress(h, #name "W");   \
	if (prefixname) break;                                         \
	if(ret_on_failure)                                        \
		return LIBUSB_ERROR_NOT_FOUND;                        \
	} while(0)

#define DLL_DECLARE(api, ret, name, args)   DLL_DECLARE_PREFIXNAME(api, ret, name, name, args)
#define DLL_LOAD(dll, name, ret_on_failure) DLL_LOAD_PREFIXNAME(dll, name, name, ret_on_failure)
#define DLL_DECLARE_PREFIXED(api, ret, prefix, name, args)   DLL_DECLARE_PREFIXNAME(api, ret, prefix##name, name, args)
#define DLL_LOAD_PREFIXED(dll, prefix, name, ret_on_failure) DLL_LOAD_PREFIXNAME(dll, prefix##name, name, ret_on_failure)

/* OLE32 dependency */
DLL_DECLARE_PREFIXED(WINAPI, HRESULT, p, CLSIDFromString, (LPCOLESTR, LPCLSID));

/* SetupAPI dependencies */
DLL_DECLARE_PREFIXED(WINAPI, HDEVINFO, p, SetupDiGetClassDevsA, (const GUID*, PCSTR, HWND, DWORD));
DLL_DECLARE_PREFIXED(WINAPI, BOOL, p, SetupDiEnumDeviceInfo, (HDEVINFO, DWORD, PSP_DEVINFO_DATA));
DLL_DECLARE_PREFIXED(WINAPI, BOOL, p, SetupDiEnumDeviceInterfaces, (HDEVINFO, PSP_DEVINFO_DATA,
			const GUID*, DWORD, PSP_DEVICE_INTERFACE_DATA));
DLL_DECLARE_PREFIXED(WINAPI, BOOL, p, SetupDiGetDeviceInterfaceDetailA, (HDEVINFO, PSP_DEVICE_INTERFACE_DATA,
			PSP_DEVICE_INTERFACE_DETAIL_DATA_A, DWORD, PDWORD, PSP_DEVINFO_DATA));
DLL_DECLARE_PREFIXED(WINAPI, BOOL, p, SetupDiDestroyDeviceInfoList, (HDEVINFO));
DLL_DECLARE_PREFIXED(WINAPI, HKEY, p, SetupDiOpenDevRegKey, (HDEVINFO, PSP_DEVINFO_DATA, DWORD, DWORD, DWORD, REGSAM));
DLL_DECLARE_PREFIXED(WINAPI, BOOL, p, SetupDiGetDeviceRegistryPropertyA, (HDEVINFO,
			PSP_DEVINFO_DATA, DWORD, PDWORD, PBYTE, DWORD, PDWORD));
DLL_DECLARE_PREFIXED(WINAPI, LONG, p, RegQueryValueExW, (HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD));
DLL_DECLARE_PREFIXED(WINAPI, LONG, p, RegCloseKey, (HKEY));

/*
 * Windows DDK API definitions. Most of it copied from MinGW's includes
 */
typedef DWORD DEVNODE, DEVINST;
typedef DEVNODE *PDEVNODE, *PDEVINST;
typedef DWORD RETURN_TYPE;
typedef RETURN_TYPE CONFIGRET;

#define CR_SUCCESS                              0x00000000
#define CR_NO_SUCH_DEVNODE                      0x0000000D

#define USB_DEVICE_DESCRIPTOR_TYPE              LIBUSB_DT_DEVICE
#define USB_CONFIGURATION_DESCRIPTOR_TYPE       LIBUSB_DT_CONFIG
#define USB_STRING_DESCRIPTOR_TYPE              LIBUSB_DT_STRING
#define USB_INTERFACE_DESCRIPTOR_TYPE           LIBUSB_DT_INTERFACE
#define USB_ENDPOINT_DESCRIPTOR_TYPE            LIBUSB_DT_ENDPOINT

#define USB_REQUEST_GET_STATUS                  LIBUSB_REQUEST_GET_STATUS
#define USB_REQUEST_CLEAR_FEATURE               LIBUSB_REQUEST_CLEAR_FEATURE
#define USB_REQUEST_SET_FEATURE                 LIBUSB_REQUEST_SET_FEATURE
#define USB_REQUEST_SET_ADDRESS                 LIBUSB_REQUEST_SET_ADDRESS
#define USB_REQUEST_GET_DESCRIPTOR              LIBUSB_REQUEST_GET_DESCRIPTOR
#define USB_REQUEST_SET_DESCRIPTOR              LIBUSB_REQUEST_SET_DESCRIPTOR
#define USB_REQUEST_GET_CONFIGURATION           LIBUSB_REQUEST_GET_CONFIGURATION
#define USB_REQUEST_SET_CONFIGURATION           LIBUSB_REQUEST_SET_CONFIGURATION
#define USB_REQUEST_GET_INTERFACE               LIBUSB_REQUEST_GET_INTERFACE
#define USB_REQUEST_SET_INTERFACE               LIBUSB_REQUEST_SET_INTERFACE
#define USB_REQUEST_SYNC_FRAME                  LIBUSB_REQUEST_SYNCH_FRAME

#define USB_GET_NODE_INFORMATION                258
#define USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION 260
#define USB_GET_NODE_CONNECTION_NAME            261
#define USB_GET_HUB_CAPABILITIES                271
#if !defined(USB_GET_NODE_CONNECTION_INFORMATION_EX)
#define USB_GET_NODE_CONNECTION_INFORMATION_EX  274
#endif
#if !defined(USB_GET_HUB_CAPABILITIES_EX)
#define USB_GET_HUB_CAPABILITIES_EX             276
#endif

#ifndef METHOD_BUFFERED
#define METHOD_BUFFERED                         0
#endif
#ifndef FILE_ANY_ACCESS
#define FILE_ANY_ACCESS                         0x00000000
#endif
#ifndef FILE_DEVICE_UNKNOWN
#define FILE_DEVICE_UNKNOWN                     0x00000022
#endif
#ifndef FILE_DEVICE_USB
#define FILE_DEVICE_USB                         FILE_DEVICE_UNKNOWN
#endif

#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access)( \
  ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif

typedef enum USB_CONNECTION_STATUS {
	NoDeviceConnected,
	DeviceConnected,
	DeviceFailedEnumeration,
	DeviceGeneralFailure,
	DeviceCausedOvercurrent,
	DeviceNotEnoughPower,
	DeviceNotEnoughBandwidth,
	DeviceHubNestedTooDeeply,
	DeviceInLegacyHub
} USB_CONNECTION_STATUS, *PUSB_CONNECTION_STATUS;

typedef enum USB_HUB_NODE {
	UsbHub,
	UsbMIParent
} USB_HUB_NODE;

/* Cfgmgr32.dll interface */
DLL_DECLARE(WINAPI, CONFIGRET, CM_Get_Parent, (PDEVINST, DEVINST, ULONG));
DLL_DECLARE(WINAPI, CONFIGRET, CM_Get_Child, (PDEVINST, DEVINST, ULONG));
DLL_DECLARE(WINAPI, CONFIGRET, CM_Get_Sibling, (PDEVINST, DEVINST, ULONG));
DLL_DECLARE(WINAPI, CONFIGRET, CM_Get_Device_IDA, (DEVINST, PCHAR, ULONG, ULONG));

#define IOCTL_USB_GET_HUB_CAPABILITIES_EX \
  CTL_CODE( FILE_DEVICE_USB, USB_GET_HUB_CAPABILITIES_EX, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_USB_GET_HUB_CAPABILITIES \
  CTL_CODE(FILE_DEVICE_USB, USB_GET_HUB_CAPABILITIES, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION \
  CTL_CODE(FILE_DEVICE_USB, USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_USB_GET_ROOT_HUB_NAME \
  CTL_CODE(FILE_DEVICE_USB, HCD_GET_ROOT_HUB_NAME, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_USB_GET_NODE_INFORMATION \
  CTL_CODE(FILE_DEVICE_USB, USB_GET_NODE_INFORMATION, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX \
  CTL_CODE(FILE_DEVICE_USB, USB_GET_NODE_CONNECTION_INFORMATION_EX, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_USB_GET_NODE_CONNECTION_ATTRIBUTES \
  CTL_CODE(FILE_DEVICE_USB, USB_GET_NODE_CONNECTION_ATTRIBUTES, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_USB_GET_NODE_CONNECTION_NAME \
  CTL_CODE(FILE_DEVICE_USB, USB_GET_NODE_CONNECTION_NAME, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Most of the structures below need to be packed
#pragma pack(push, 1)

typedef struct USB_INTERFACE_DESCRIPTOR {
  UCHAR  bLength;
  UCHAR  bDescriptorType;
  UCHAR  bInterfaceNumber;
  UCHAR  bAlternateSetting;
  UCHAR  bNumEndpoints;
  UCHAR  bInterfaceClass;
  UCHAR  bInterfaceSubClass;
  UCHAR  bInterfaceProtocol;
  UCHAR  iInterface;
} USB_INTERFACE_DESCRIPTOR, *PUSB_INTERFACE_DESCRIPTOR;

typedef struct USB_CONFIGURATION_DESCRIPTOR {
  UCHAR  bLength;
  UCHAR  bDescriptorType;
  USHORT wTotalLength;
  UCHAR  bNumInterfaces;
  UCHAR  bConfigurationValue;
  UCHAR  iConfiguration;
  UCHAR  bmAttributes;
  UCHAR  MaxPower;
} USB_CONFIGURATION_DESCRIPTOR, *PUSB_CONFIGURATION_DESCRIPTOR;

typedef struct USB_CONFIGURATION_DESCRIPTOR_SHORT {
	struct {
		ULONG ConnectionIndex;
		struct {
			UCHAR bmRequest;
			UCHAR bRequest;
			USHORT wValue;
			USHORT wIndex;
			USHORT wLength;
		} SetupPacket;
	} req;
	USB_CONFIGURATION_DESCRIPTOR data;
} USB_CONFIGURATION_DESCRIPTOR_SHORT;

typedef struct USB_ENDPOINT_DESCRIPTOR {
  UCHAR  bLength;
  UCHAR  bDescriptorType;
  UCHAR  bEndpointAddress;
  UCHAR  bmAttributes;
  USHORT  wMaxPacketSize;
  UCHAR  bInterval;
} USB_ENDPOINT_DESCRIPTOR, *PUSB_ENDPOINT_DESCRIPTOR;

typedef struct USB_DESCRIPTOR_REQUEST {
	ULONG  ConnectionIndex;
	struct {
		UCHAR  bmRequest;
		UCHAR  bRequest;
		USHORT  wValue;
		USHORT  wIndex;
		USHORT  wLength;
	} SetupPacket;
//	UCHAR  Data[0];
} USB_DESCRIPTOR_REQUEST, *PUSB_DESCRIPTOR_REQUEST;

typedef struct USB_HUB_DESCRIPTOR {
	UCHAR  bDescriptorLength;
	UCHAR  bDescriptorType;
	UCHAR  bNumberOfPorts;
	USHORT  wHubCharacteristics;
	UCHAR  bPowerOnToPowerGood;
	UCHAR  bHubControlCurrent;
	UCHAR  bRemoveAndPowerMask[64];
} USB_HUB_DESCRIPTOR, *PUSB_HUB_DESCRIPTOR;

typedef struct USB_ROOT_HUB_NAME {
	ULONG  ActualLength;
	WCHAR  RootHubName[1];
} USB_ROOT_HUB_NAME, *PUSB_ROOT_HUB_NAME;

typedef struct USB_ROOT_HUB_NAME_FIXED {
	ULONG ActualLength;
	WCHAR RootHubName[MAX_PATH_LENGTH];
} USB_ROOT_HUB_NAME_FIXED;

typedef struct USB_NODE_CONNECTION_NAME {
	ULONG  ConnectionIndex;
	ULONG  ActualLength;
	WCHAR  NodeName[1];
} USB_NODE_CONNECTION_NAME, *PUSB_NODE_CONNECTION_NAME;

typedef struct USB_NODE_CONNECTION_NAME_FIXED {
	ULONG ConnectionIndex;
	ULONG ActualLength;
	WCHAR NodeName[MAX_PATH_LENGTH];
} USB_NODE_CONNECTION_NAME_FIXED;

typedef struct USB_HUB_NAME_FIXED {
	union {
		USB_ROOT_HUB_NAME_FIXED root;
		USB_NODE_CONNECTION_NAME_FIXED node;
	} u;
} USB_HUB_NAME_FIXED;

typedef struct USB_HUB_INFORMATION {
	USB_HUB_DESCRIPTOR  HubDescriptor;
	BOOLEAN  HubIsBusPowered;
} USB_HUB_INFORMATION, *PUSB_HUB_INFORMATION;

typedef struct USB_MI_PARENT_INFORMATION {
  ULONG  NumberOfInterfaces;
} USB_MI_PARENT_INFORMATION, *PUSB_MI_PARENT_INFORMATION;

typedef struct USB_NODE_INFORMATION {
	USB_HUB_NODE  NodeType;
	union {
		USB_HUB_INFORMATION  HubInformation;
		USB_MI_PARENT_INFORMATION  MiParentInformation;
	} u;
} USB_NODE_INFORMATION, *PUSB_NODE_INFORMATION;

typedef struct USB_PIPE_INFO {
	USB_ENDPOINT_DESCRIPTOR  EndpointDescriptor;
	ULONG  ScheduleOffset;
} USB_PIPE_INFO, *PUSB_PIPE_INFO;

typedef struct USB_NODE_CONNECTION_INFORMATION_EX {
	ULONG  ConnectionIndex;
	USB_DEVICE_DESCRIPTOR  DeviceDescriptor;
	UCHAR  CurrentConfigurationValue;
	UCHAR  Speed;
	BOOLEAN  DeviceIsHub;
	USHORT  DeviceAddress;
	ULONG  NumberOfOpenPipes;
	USB_CONNECTION_STATUS  ConnectionStatus;
//	USB_PIPE_INFO  PipeList[0];
} USB_NODE_CONNECTION_INFORMATION_EX, *PUSB_NODE_CONNECTION_INFORMATION_EX;

typedef struct USB_HUB_CAP_FLAGS {
	ULONG HubIsHighSpeedCapable:1;
	ULONG HubIsHighSpeed:1;
	ULONG HubIsMultiTtCapable:1;
	ULONG HubIsMultiTt:1;
	ULONG HubIsRoot:1;
	ULONG HubIsArmedWakeOnConnect:1;
	ULONG ReservedMBZ:26;
} USB_HUB_CAP_FLAGS, *PUSB_HUB_CAP_FLAGS;

typedef struct USB_HUB_CAPABILITIES {
  ULONG  HubIs2xCapable : 1;
} USB_HUB_CAPABILITIES, *PUSB_HUB_CAPABILITIES;

typedef struct USB_HUB_CAPABILITIES_EX {
	USB_HUB_CAP_FLAGS CapabilityFlags;
} USB_HUB_CAPABILITIES_EX, *PUSB_HUB_CAPABILITIES_EX;

#pragma pack(pop)

/* winusb.dll interface */

#define SHORT_PACKET_TERMINATE  0x01
#define AUTO_CLEAR_STALL        0x02
#define PIPE_TRANSFER_TIMEOUT   0x03
#define IGNORE_SHORT_PACKETS    0x04
#define ALLOW_PARTIAL_READS     0x05
#define AUTO_FLUSH              0x06
#define RAW_IO                  0x07
#define MAXIMUM_TRANSFER_SIZE   0x08
#define AUTO_SUSPEND            0x81
#define SUSPEND_DELAY           0x83
#define DEVICE_SPEED            0x01
#define LowSpeed                0x01
#define FullSpeed               0x02
#define HighSpeed               0x03

typedef enum USBD_PIPE_TYPE {
	UsbdPipeTypeControl,
	UsbdPipeTypeIsochronous,
	UsbdPipeTypeBulk,
	UsbdPipeTypeInterrupt
} USBD_PIPE_TYPE;

typedef struct {
  USBD_PIPE_TYPE PipeType;
  UCHAR          PipeId;
  USHORT         MaximumPacketSize;
  UCHAR          Interval;
} WINUSB_PIPE_INFORMATION, *PWINUSB_PIPE_INFORMATION;

#pragma pack(1)
typedef struct {
  UCHAR  request_type;
  UCHAR  request;
  USHORT value;
  USHORT index;
  USHORT length;
} WINUSB_SETUP_PACKET, *PWINUSB_SETUP_PACKET;
#pragma pack()

typedef void *WINUSB_INTERFACE_HANDLE, *PWINUSB_INTERFACE_HANDLE;

DLL_DECLARE(WINAPI, BOOL, WinUsb_Initialize, (HANDLE, PWINUSB_INTERFACE_HANDLE));
DLL_DECLARE(WINAPI, BOOL, WinUsb_Free, (WINUSB_INTERFACE_HANDLE));
DLL_DECLARE(WINAPI, BOOL, WinUsb_GetAssociatedInterface, (WINUSB_INTERFACE_HANDLE, UCHAR, PWINUSB_INTERFACE_HANDLE));
DLL_DECLARE(WINAPI, BOOL, WinUsb_GetDescriptor, (WINUSB_INTERFACE_HANDLE, UCHAR, UCHAR, USHORT, PUCHAR, ULONG, PULONG));
DLL_DECLARE(WINAPI, BOOL, WinUsb_QueryInterfaceSettings, (WINUSB_INTERFACE_HANDLE, UCHAR, PUSB_INTERFACE_DESCRIPTOR));
DLL_DECLARE(WINAPI, BOOL, WinUsb_QueryDeviceInformation, (WINUSB_INTERFACE_HANDLE, ULONG, PULONG, PVOID));
DLL_DECLARE(WINAPI, BOOL, WinUsb_SetCurrentAlternateSetting, (WINUSB_INTERFACE_HANDLE, UCHAR));
DLL_DECLARE(WINAPI, BOOL, WinUsb_GetCurrentAlternateSetting, (WINUSB_INTERFACE_HANDLE, PUCHAR));
DLL_DECLARE(WINAPI, BOOL, WinUsb_QueryPipe, (WINUSB_INTERFACE_HANDLE, UCHAR, UCHAR, PWINUSB_PIPE_INFORMATION));
DLL_DECLARE(WINAPI, BOOL, WinUsb_SetPipePolicy, (WINUSB_INTERFACE_HANDLE, UCHAR, ULONG, ULONG, PVOID));
DLL_DECLARE(WINAPI, BOOL, WinUsb_GetPipePolicy, (WINUSB_INTERFACE_HANDLE, UCHAR, ULONG, PULONG, PVOID));
DLL_DECLARE(WINAPI, BOOL, WinUsb_ReadPipe, (WINUSB_INTERFACE_HANDLE, UCHAR, PUCHAR, ULONG, PULONG, LPOVERLAPPED));
DLL_DECLARE(WINAPI, BOOL, WinUsb_WritePipe, (WINUSB_INTERFACE_HANDLE, UCHAR, PUCHAR, ULONG, PULONG, LPOVERLAPPED));
DLL_DECLARE(WINAPI, BOOL, WinUsb_ControlTransfer, (WINUSB_INTERFACE_HANDLE, WINUSB_SETUP_PACKET, PUCHAR, ULONG, PULONG, LPOVERLAPPED));
DLL_DECLARE(WINAPI, BOOL, WinUsb_ResetPipe, (WINUSB_INTERFACE_HANDLE, UCHAR));
DLL_DECLARE(WINAPI, BOOL, WinUsb_AbortPipe, (WINUSB_INTERFACE_HANDLE, UCHAR));
DLL_DECLARE(WINAPI, BOOL, WinUsb_FlushPipe, (WINUSB_INTERFACE_HANDLE, UCHAR));
