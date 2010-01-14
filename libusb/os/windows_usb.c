/*
 * windows backend for libusb 1.0
 * Copyright (c) 2009 Pete Batard <pbatard@gmail.com>
 * Parts of this code adapted from libusb-win32-v1 by Stephan Meyer
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
#include <config.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <pthread.h>
#include <stdio.h>
#include <windows.h>
#include <tchar.h>
#include <setupapi.h>
#include <ddk/usbiodef.h>
#include <ddk/usbioctl.h>
#include <ddk/cfgmgr32.h>
#include <largeint.h>
#include <inttypes.h>
#include <objbase.h>  // for string to GUID conv. requires libole32.a

/* Prevent compilation problems on Windows platforms */
#ifdef interface
#undef interface
#endif

#include "libusbi.h"
#include "windows_compat.h"
#include "windows_usb.h"

// These GUIDs appear undefined on MinGW32
#ifndef GUID_DEVINTERFACE_USB_HOST_CONTROLLER
	// http://msdn.microsoft.com/en-us/library/bb663109.aspx
	const GUID GUID_DEVINTERFACE_USB_HOST_CONTROLLER = {  0x3ABF6F2D, 0x71C4, 0x462A, {0x8A, 0x92, 0x1E, 0x68, 0x61, 0xE6, 0xAF, 0x27} };
#endif

#ifndef GUID_DEVINTERFACE_USB_DEVICE
	// http://msdn.microsoft.com/en-us/library/bb663093.aspx
	const GUID GUID_DEVINTERFACE_USB_DEVICE = {  0xA5DCBF10, 0x6530, 0x11D2, {0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED} };
#endif

// The 3 macros below are used in conjunction with safe loops.
#define LOOP_CHECK(fcall) { r=fcall; if (r != LIBUSB_SUCCESS) continue; }
#define LOOP_CONTINUE(...) { usbi_warn(ctx, __VA_ARGS__); continue; }
#define LOOP_BREAK(err) { r=err; continue; } 

// Helper prototypes
static int windows_get_active_config_descriptor(struct libusb_device *dev, unsigned char *buffer, size_t len, int *host_endian);
static int windows_clock_gettime(int clk_id, struct timespec *tp);
// WinUSB API prototypes
static int winusb_api_init(struct libusb_context *ctx);
static int winusb_api_exit(void);
static int winusb_open(struct libusb_device_handle *dev_handle);
static void winusb_close(struct libusb_device_handle *dev_handle);
static int winusb_claim_interface(struct libusb_device_handle *dev_handle, int iface);
static int winusb_release_interface(struct libusb_device_handle *dev_handle, int iface);
static int winusb_submit_control_transfer(struct usbi_transfer *itransfer);
static int winusb_set_interface_altsetting(struct libusb_device_handle *dev_handle, int iface, int altsetting);
static int winusb_submit_bulk_transfer(struct usbi_transfer *itransfer);
static int winusb_submit_iso_transfer(struct usbi_transfer *itransfer);
static int winusb_clear_halt(struct libusb_device_handle *dev_handle, unsigned char endpoint);
static int winusb_abort_transfers(struct usbi_transfer *itransfer);
static int winusb_abort_control(struct usbi_transfer *itransfer);
static int winusb_reset_device(struct libusb_device_handle *dev_handle);

// Global variables
struct windows_hcd_priv* hcd_root = NULL;
uint64_t hires_frequency, hires_ticks_to_ps;
const uint64_t epoch_time = 116444736000000000;	// 1970.01.01 00:00:000 in MS Filetime
DWORD_PTR old_affinity_mask;
enum windows_version windows_version = WINDOWS_UNSUPPORTED;
// WinUSB globals
bool api_winusb_available = false;
#define CHECK_WINUSB_AVAILABLE do { if (!api_winusb_available) return LIBUSB_ERROR_ACCESS; } while (0)

/*
 * Converts a WCHAR string to UTF8 (allocate returned string)
 * Returns NULL on error
 */
char* wchar_to_utf8(LPCWSTR wstr)
{
	size_t size;
	char* str;

	// Find out the size we need to allocate for our converted string
	size = wchar_to_utf8_ms(wstr, NULL, 0);
	if (size <= 1)	// An empty string would be size 1
		return NULL;

	if ((str = malloc(size)) == NULL)
		return NULL;

	if (wchar_to_utf8_ms(wstr, str, size) != size) {
		safe_free(str);
		return NULL;
	}

	return str;
}

/*
 * Converts a windows error to human readable string
 * uses retval as errorcode, or, if 0, use GetLastError()
 */
static char *windows_error_str(uint32_t retval)
{
static char err_string[ERR_BUFFER_SIZE];

	DWORD size;
	uint32_t errcode, format_errcode;

	errcode = retval?retval:GetLastError();

	safe_sprintf(err_string, ERR_BUFFER_SIZE, "[%d] ", errcode);

	size = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, errcode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR) &err_string[strlen(err_string)],
		ERR_BUFFER_SIZE, NULL);
	if (size == 0)
	{
		format_errcode = GetLastError();
		if (format_errcode)
			safe_sprintf(err_string, ERR_BUFFER_SIZE,
				"Windows error code %u (FormatMessage error code %u)", errcode, format_errcode);
		else
			safe_sprintf(err_string, ERR_BUFFER_SIZE, "Unknown error code %u", errcode);
	}
	return err_string;
}

/*
 * Sanitize Microsoft's paths: convert to uppercase, add prefix and fix backslashes.
 * Return an allocated sanitized string or NULL on error.
 */
static char* sanitize_path(const char* path)
{
	const char root_prefix[] = "\\\\.\\";
	int j;
	size_t size, root_size;
	char* ret_path = NULL;
	int add_root = 0;

	if (path == NULL)
		return NULL;

	size = strlen(path)+1;
	root_size = sizeof(root_prefix)-1;

	// Microsoft indiscriminatly uses '\\?\', '\\.\', '##?#" or "##.#" for root prefixes.
	if (!((size > 3) && (((path[0] == '\\') && (path[1] == '\\') && (path[3] == '\\')) || 
		((path[0] == '#') && (path[1] == '#') && (path[3] == '#'))))) {
		add_root = root_size;
		size += add_root;
	}

	if ((ret_path = (char*)calloc(size, 1)) == NULL) 
		return NULL;

	safe_strncpy(&ret_path[add_root], size-add_root, path, strlen(path));

	// Ensure consistancy with root prefix
	for (j=0; j<root_size; j++)
		ret_path[j] = root_prefix[j];

	// Same goes for '\' and '#' after the root prefix. Ensure '#' is used
	for(j=root_size; j<size; j++) {
		ret_path[j] = toupper(ret_path[j]);	// Fix case too
		if (ret_path[j] == '\\')
			ret_path[j] = '#';
	}

	return ret_path;
}

/*
 * enumerate interfaces for a specific GUID
 *
 * Parameters:
 * dev_info: a pointer to a dev_info list
 * guid: the GUID for which to retrieve interface details
 * index: zero based index of the interface in the device info list
 *
 * Note: it is the responsibility of the caller to free the DEVICE_INTERFACE_DETAIL_DATA
 * structure returned and call this function repeatedly using the same guid (with an 
 * incremented index starting at zero) until all interfaces have been returned.
 */
SP_DEVICE_INTERFACE_DETAIL_DATA *get_interface_details(struct libusb_context *ctx, HDEVINFO* dev_info, GUID guid, unsigned index)
{
	SP_DEVICE_INTERFACE_DATA dev_interface_data;
	SP_DEVICE_INTERFACE_DETAIL_DATA *dev_interface_details = NULL;
	DWORD size;

	if (index <= 0) {
		*dev_info = SetupDiGetClassDevs(&guid, NULL, NULL, DIGCF_PRESENT|DIGCF_DEVICEINTERFACE);
	}

	if (*dev_info == INVALID_HANDLE_VALUE) {
		return NULL;
	}

	dev_interface_data.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

	if (!SetupDiEnumDeviceInterfaces(*dev_info, NULL, &guid, index, &dev_interface_data)) {
		SetupDiDestroyDeviceInfoList(*dev_info);
		*dev_info = INVALID_HANDLE_VALUE;
		return NULL;
	}

	// Read interface data (dummy + actual) to access the device path
	if (!SetupDiGetDeviceInterfaceDetail(*dev_info, &dev_interface_data, NULL, 0, &size, NULL)) {
		// The dummy call should fail with ERROR_INSUFFICIENT_BUFFER
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			usbi_err(ctx, "could not access interface data (dummy) for index %u: %s", 
				index, windows_error_str(0));
			goto err_exit;
		}
	} 
	else {
		usbi_err(ctx, "program assertion failed - http://msdn.microsoft.com/en-us/library/ms792901.aspx is wrong.");
		goto err_exit;
	}

	if ((dev_interface_details = malloc(size)) == NULL) {
		usbi_err(ctx, "could not allocate interface data for index %u.", index);
		goto err_exit;
	}

	dev_interface_details->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA); 
	if (!SetupDiGetDeviceInterfaceDetail(*dev_info, &dev_interface_data, 
		dev_interface_details, size, &size, NULL)) {
		usbi_err(ctx, "could not access interface data (actual) for index %u: %s", 
			index, windows_error_str(0));
	}

	return dev_interface_details;

err_exit:
	SetupDiDestroyDeviceInfoList(*dev_info);
	*dev_info = INVALID_HANDLE_VALUE;
	return NULL;
}

/*
 * Populate the endpoints addresses of the device_priv interface helper structs
 */
static void windows_assign_endpoints(struct libusb_device *dev, int iface, int altsetting)
{
	int i;
	struct windows_device_priv *priv = __device_priv(dev);
	struct libusb_config_descriptor *conf_desc;
	const struct libusb_interface_descriptor *if_desc;

	if (libusb_get_config_descriptor(dev, 0, &conf_desc) == LIBUSB_SUCCESS) {
		if_desc = &conf_desc->interface[iface].altsetting[altsetting];
		safe_free(priv->interface[iface].endpoint);
		priv->interface[iface].endpoint = malloc(if_desc->bNumEndpoints);
		if (priv->interface[iface].endpoint != NULL) {
			priv->interface[iface].nb_endpoints = if_desc->bNumEndpoints;
			for (i=0; i<if_desc->bNumEndpoints; i++) {
				priv->interface[iface].endpoint[i] = if_desc->endpoint[i].bEndpointAddress;
				usbi_dbg("(re)assigned endpoint %02X to interface %d", priv->interface[iface].endpoint[i], iface);
			}
		}
		libusb_free_config_descriptor(conf_desc);		
	}
}

/*
 * init: libusb backend init function
 *
 * This function enumerates the HCDs (Host Controller Drivers) and populates our private HCD list
 * In our implementation, we equate Windows' "HCD" to LibUSB's "bus". Note that bus is zero indexed.
 * HCDs are not expected to change after init (might not hold true for hot pluggable USB PCI card?)
 */
static int windows_init(struct libusb_context *ctx)
{
	HDEVINFO dev_info;
	SP_DEVICE_INTERFACE_DETAIL_DATA *dev_interface_details = NULL;
	GUID guid;
	libusb_bus_t bus;
	int r = LIBUSB_SUCCESS;
	LARGE_INTEGER li_frequency;
	OSVERSIONINFO os_version;

	// If our HCD list is populated, we don't need to re-init
	if (hcd_root != NULL) {
		usbi_dbg("init already occured.");
		return LIBUSB_SUCCESS;
	}

	// Detect OS version
	memset(&os_version, 0, sizeof(OSVERSIONINFO));
	os_version.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	windows_version = WINDOWS_UNSUPPORTED;
	if ((GetVersionEx(&os_version) != 0) && (os_version.dwPlatformId == VER_PLATFORM_WIN32_NT)) {
		if ((os_version.dwMajorVersion == 5) && (os_version.dwMinorVersion == 1)) {
			windows_version = WINDOWS_XP;
		} else if (os_version.dwMajorVersion >= 6) {
			windows_version = WINDOWS_VISTA_AND_LATER;
		}
	}
	if (windows_version ==  WINDOWS_UNSUPPORTED) {
		usbi_err(ctx, "This version of Windows is NOT supported");
		return LIBUSB_ERROR_NOT_SUPPORTED;
	}

	// Initialize pollable file descriptors
	init_polling();

	// Initialize the low level APIs
	r = winusb_api_init(ctx);
	if (r != LIBUSB_SUCCESS) {
		return r;
	}

	// Because QueryPerformanceCounter might report different values when 
	// running on different cores, we glue the libusb main thread to the
	// first core to prevent timing discrepancies.
	// TODO? create a seperate thread for timer and detect single core
	old_affinity_mask = SetThreadAffinityMask(GetCurrentThread(), 0);

	// Find out if we have access to a monotonic (hires) timer
	if (!QueryPerformanceFrequency(&li_frequency)) {
		usbi_dbg("no hires timer available on this platform");
		hires_frequency = 0;
		hires_ticks_to_ps = 0;	
	} else {
		hires_frequency = li_frequency.QuadPart;
		// The hires frequency can go as high as 4 GHz, so we'll use a conversion
		// to picoseconds to compute the tv_nsecs part in clock_gettime
		hires_ticks_to_ps =  1000000000000 / hires_frequency; 
		usbi_dbg("hires timer available (Frequency: %"PRIu64" Hz)", hires_frequency);
	}

	// We maintain a chained list of the Host Controllers found
	struct windows_hcd_priv** _hcd_cur = &hcd_root;

	guid = GUID_DEVINTERFACE_USB_HOST_CONTROLLER;

	for (bus = 0; ; bus++)
	{
		// safe loop: free up any (unprotected) dynamic resource
		// NB: this is always executed before breaking the loop
		safe_free(dev_interface_details);
		safe_free(*_hcd_cur);

		dev_interface_details = get_interface_details(ctx, &dev_info, guid, bus);
		// safe loop: end of loop condition
		if ((dev_interface_details == NULL) || (r != LIBUSB_SUCCESS))
			break;

		// Will need to change storage and size of libusb_bus_t if this ever occurs
		if (bus == LIBUSB_BUS_MAX) {
			LOOP_CONTINUE("program assertion failed - found more than %d buses, skipping the rest.", LIBUSB_BUS_MAX);
		}

		// Allocate and init a new priv structure to hold our data
		if ((*_hcd_cur = malloc(sizeof(struct windows_hcd_priv))) == NULL) {
			usbi_err(ctx, "could not allocate private structure for bus %u. aborting.", bus);
			LOOP_BREAK(LIBUSB_ERROR_NO_MEM);
		}
		windows_hcd_priv_init(*_hcd_cur);
		(*_hcd_cur)->path = sanitize_path(dev_interface_details->DevicePath);

		_hcd_cur = &((*_hcd_cur)->next);
	}

	// TODO: event thread for hotplug (see darwin source)

	if (hcd_root == NULL)
		return LIBUSB_ERROR_NO_DEVICE;
	else 
		return LIBUSB_SUCCESS;
}

/*
 * Initialize device structure, including active config
 */ 
static int initialize_device(struct libusb_device *dev, libusb_bus_t busnum,
	libusb_devaddr_t devaddr, char *path, int connection_index, uint8_t active_config,
	struct libusb_device *parent_dev)
{
	struct windows_device_priv *priv = __device_priv(dev);

	windows_device_priv_init(priv);

	dev->bus_number = busnum;
	dev->device_address = devaddr;
	priv->path = path;
	priv->connection_index = connection_index;
	priv->parent_dev = parent_dev;

	priv->active_config = active_config;

	if (priv->active_config != 0) {
		usbi_dbg("active config: %d", priv->active_config);
	} else {
		// USB devices that don't have a config value are usually missing
		// a driver issue => report this
		// TODO: use this for automated driver installation
		// TODO: can we get an error code to confirm from SetupDiWhatever?
		priv->driver = safe_strdup("no_driver");
		usbi_dbg("* DRIVERLESS DEVICE *");
	}

	return LIBUSB_SUCCESS;
}

/*
 * HCD (root) hubs need to have their device descriptor manually populated
 *
 * Note that we follow the Linux convention and use the "Linux Foundation root hub"
 * vendor ID as well as the product ID to indicate the hub speed
 */
static int force_hcd_device_descriptor(struct libusb_device *dev, HANDLE handle) 
{
	DWORD size;
	USB_HUB_CAPABILITIES hub_caps;
	USB_HUB_CAPABILITIES_EX hub_caps_ex;
	struct windows_device_priv *priv = __device_priv(dev);
	struct libusb_context *ctx = DEVICE_CTX(dev);

	priv->dev_descriptor.bLength = sizeof(USB_DEVICE_DESCRIPTOR);
	priv->dev_descriptor.bDescriptorType = USB_DEVICE_DESCRIPTOR_TYPE;
	dev->num_configurations = priv->dev_descriptor.bNumConfigurations = 1;
	priv->dev_descriptor.idVendor = 0x1d6b;		// Linux Foundation root hub

	if (windows_version >= WINDOWS_VISTA_AND_LATER) {
		size = sizeof(USB_HUB_CAPABILITIES_EX);
		if (DeviceIoControl(handle, IOCTL_USB_GET_HUB_CAPABILITIES_EX, &hub_caps_ex, 
			size, &hub_caps_ex, size, &size, NULL)) {
			// Sanity check. HCD hub should always be root
			if (!hub_caps_ex.CapabilityFlags.HubIsRoot) {
				usbi_warn(ctx, "program assertion failed - HCD hub is not reported as root hub.");
			}
			priv->dev_descriptor.idProduct = hub_caps_ex.CapabilityFlags.HubIsHighSpeedCapable?2:1;
		}
	} else {
		size = sizeof(USB_HUB_CAPABILITIES);
		if (!DeviceIoControl(handle, IOCTL_USB_GET_HUB_CAPABILITIES, &hub_caps, 
			size, &hub_caps, size, &size, NULL)) {
			usbi_warn(ctx, "could not read hub capabilities (std) for hub %s: %s", 
				priv->path, windows_error_str(0));
			return LIBUSB_ERROR_IO;
		}
		priv->dev_descriptor.idProduct = hub_caps.HubIs2xCapable?2:1;
	}

	return LIBUSB_SUCCESS;
}

/*
 * fetch and cache all the config descriptors through I/O
 */
static int cache_config_descriptors(struct libusb_device *dev, HANDLE hub_handle) 
{
	DWORD size, ret_size;
	struct libusb_context *ctx = DEVICE_CTX(dev);
	struct windows_device_priv *priv = __device_priv(dev);
	int r;
	uint8_t i;

	USB_CONFIGURATION_DESCRIPTOR_SHORT cd_buf_short;    // dummy request
	PUSB_DESCRIPTOR_REQUEST cd_buf_actual = NULL;       // actual request
	PUSB_CONFIGURATION_DESCRIPTOR cd_data = NULL;

	if (dev->num_configurations == 0)
		return LIBUSB_ERROR_INVALID_PARAM;

	priv->config_descriptor = malloc(dev->num_configurations * sizeof(PUSB_CONFIGURATION_DESCRIPTOR));
	if (priv->config_descriptor == NULL)
		return LIBUSB_ERROR_NO_MEM;
	for (i=0; i<dev->num_configurations; i++)
		priv->config_descriptor[i] = NULL;

	for (i=0, r=LIBUSB_SUCCESS; ; i++) 
	{
		// safe loop: release all dynamic resources
		safe_free(cd_buf_actual);

		// safe loop: end of loop condition 
		if ((i >= dev->num_configurations) || (r != LIBUSB_SUCCESS))
			break;

		size = sizeof(USB_CONFIGURATION_DESCRIPTOR_SHORT);
		memset(&cd_buf_short, 0, size);

		cd_buf_short.req.ConnectionIndex = priv->connection_index;
		cd_buf_short.req.SetupPacket.bmRequest = LIBUSB_ENDPOINT_IN;
		cd_buf_short.req.SetupPacket.bRequest = USB_REQUEST_GET_DESCRIPTOR;
		cd_buf_short.req.SetupPacket.wValue = (USB_CONFIGURATION_DESCRIPTOR_TYPE << 8) | i;
		cd_buf_short.req.SetupPacket.wIndex = i;
		cd_buf_short.req.SetupPacket.wLength = (USHORT)(size - sizeof(USB_DESCRIPTOR_REQUEST));

		// Dummy call to get the required data size
		if (!DeviceIoControl(hub_handle, IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION, &cd_buf_short, size,
			&cd_buf_short, size, &ret_size, NULL)) {
			usbi_err(ctx, "could not access configuration descriptor (dummy): %s", windows_error_str(0));
			LOOP_BREAK(LIBUSB_ERROR_IO);
		}

		if ((ret_size != size) || (cd_buf_short.data.wTotalLength < sizeof(USB_CONFIGURATION_DESCRIPTOR))) {
			usbi_err(ctx, "unexpected configuration descriptor size (dummy).");
			LOOP_BREAK(LIBUSB_ERROR_IO);
		}

		size = sizeof(USB_DESCRIPTOR_REQUEST) + cd_buf_short.data.wTotalLength;
		if ((cd_buf_actual = (PUSB_DESCRIPTOR_REQUEST)malloc(size)) == NULL) {
			usbi_err(ctx, "could not allocate configuration descriptor buffer. aborting.");
			LOOP_BREAK(LIBUSB_ERROR_NO_MEM);
		}
		memset(cd_buf_actual, 0, size);

		// Actual call
		cd_buf_actual->ConnectionIndex = priv->connection_index;
		cd_buf_actual->SetupPacket.bmRequest = LIBUSB_ENDPOINT_IN;
		cd_buf_actual->SetupPacket.bRequest = USB_REQUEST_GET_DESCRIPTOR;
		cd_buf_actual->SetupPacket.wValue = (USB_CONFIGURATION_DESCRIPTOR_TYPE << 8) | i;
		cd_buf_actual->SetupPacket.wIndex = i;
		cd_buf_actual->SetupPacket.wLength = (USHORT)(size - sizeof(USB_DESCRIPTOR_REQUEST));

		if (!DeviceIoControl(hub_handle, IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION, cd_buf_actual, size,
			cd_buf_actual, size, &ret_size, NULL)) {
			usbi_err(ctx, "could not access configuration descriptor (actual): %s", windows_error_str(0));
			LOOP_BREAK(LIBUSB_ERROR_IO);
		}

		cd_data = (PUSB_CONFIGURATION_DESCRIPTOR)cd_buf_actual->Data;

		if ((size != ret_size) || (cd_data->wTotalLength != cd_buf_short.data.wTotalLength)) {
			usbi_err(ctx, "unexpected configuration descriptor size (actual).");
			LOOP_BREAK(LIBUSB_ERROR_IO);
		}

		if (cd_data->bDescriptorType != USB_CONFIGURATION_DESCRIPTOR_TYPE) {
			usbi_err(ctx, "not a configuration descriptor");
			LOOP_BREAK(LIBUSB_ERROR_IO);
		}

		usbi_dbg("cached config descriptor #%d (%d bytes)", i+1, cd_data->wTotalLength);
	
		// Sanity check. Ensures that indexes for our list of config desc is in the right order
		if (i != (cd_data->bConfigurationValue-1)) {
			LOOP_CONTINUE("program assertion failed: config descriptors are being read out of order");
		}

		// Cache the descriptor
		priv->config_descriptor[i] = malloc(cd_data->wTotalLength);
		if (priv->config_descriptor[i] == NULL)
			return LIBUSB_ERROR_NO_MEM;

		memcpy(priv->config_descriptor[i], cd_data, cd_data->wTotalLength);
	}
	return LIBUSB_SUCCESS;
}

/*
 * Recursively enumerates and finds all hubs & devices
 */
static int usb_enumerate_hub(struct libusb_context *ctx, struct discovered_devs **_discdevs, 
	HANDLE hub_handle, libusb_bus_t busnum, struct libusb_device *parent_dev, uint8_t nb_ports) 
{
	struct discovered_devs *discdevs = *_discdevs;
	struct libusb_device *dev = NULL;
	DWORD size, size_initial, size_fixed, getname_ioctl;
	HANDLE handle = INVALID_HANDLE_VALUE;
	USB_HUB_NAME_FIXED s_hubname;
	USB_NODE_CONNECTION_INFORMATION conn_info;
	USB_NODE_INFORMATION hub_node;
	bool is_hcd;	
	int i, r;
	LPCWSTR wstr;
	char *tmp_str = NULL, *path_str = NULL;
	unsigned long session_id;
	libusb_devaddr_t devaddr = 0;
	struct windows_device_priv *priv, *parent_priv; 

	// obviously, root (HCD) hubs have no parent
	is_hcd = (parent_dev == NULL);
	if (is_hcd)
	{
		if (nb_ports != 1) {
			usbi_warn(ctx, "program assertion failed - invalid number of ports for HCD.");
			return LIBUSB_ERROR_INVALID_PARAM;
		}
		parent_priv = NULL;
		size_initial = sizeof(USB_ROOT_HUB_NAME);
		size_fixed = sizeof(USB_ROOT_HUB_NAME_FIXED);
		getname_ioctl = IOCTL_USB_GET_ROOT_HUB_NAME;
	}
	else
	{
		parent_priv = __device_priv(parent_dev);
		size_initial = sizeof(USB_NODE_CONNECTION_NAME);
		size_fixed = sizeof(USB_NODE_CONNECTION_NAME_FIXED);
		getname_ioctl = IOCTL_USB_GET_NODE_CONNECTION_NAME;
	}

	// Loop through all the ports on this hub
	for (i = 1, r = LIBUSB_SUCCESS; ; i++)
	{
		// safe loop: release all dynamic resources 
		safe_unref_device(dev);
		safe_free(tmp_str);
		safe_free(path_str);
		safe_closehandle(handle);

		// safe loop: end of loop condition 
		if ((i > nb_ports) || (r != LIBUSB_SUCCESS))
			break;

		// For non HCDs, check if the node on this port is a hub or a regular device
		if (!is_hcd) {
			size = sizeof(USB_NODE_CONNECTION_INFORMATION);
			conn_info.ConnectionIndex = i;
			if (!DeviceIoControl(hub_handle, IOCTL_USB_GET_NODE_CONNECTION_INFORMATION, &conn_info, size,
				&conn_info, size, &size, NULL)) {
				LOOP_CONTINUE("could not get node connection information: %s", windows_error_str(0));
			}

			if (conn_info.ConnectionStatus == NoDeviceConnected) {
				continue;
			} 

			if (conn_info.DeviceAddress == 0) {
				LOOP_CONTINUE("program assertion failed - device address is zero " 
					"(conflicts with root hub), ignoring device");
			}

			s_hubname.u.node.ConnectionIndex = i;	// Only used for non HCDs (s_hubname is an union)
		} 
		else 
		{
			// HCDs have only 1 node, and it's always a hub
			conn_info.DeviceAddress = 0;
			conn_info.DeviceIsHub = true;
			conn_info.CurrentConfigurationValue = 1;
		}

		// If this node is a hub (HCD or not), open it
		if (conn_info.DeviceIsHub) {	
			size = size_initial;
			if (!DeviceIoControl(hub_handle, getname_ioctl, &s_hubname, size, 
				&s_hubname, size, &size, NULL)) {
				LOOP_CONTINUE("could not get hub path (dummy): %s", windows_error_str(0));
			}

			size = is_hcd?s_hubname.u.root.ActualLength:s_hubname.u.node.ActualLength;
			if (size > size_fixed) {
				LOOP_CONTINUE("program assertion failed - hub path is too long");
			}

			if (!is_hcd) {
				// previous call trashes some of the data
				s_hubname.u.node.ConnectionIndex = i;
			}
			if (!DeviceIoControl(hub_handle, getname_ioctl, &s_hubname, size,
				&s_hubname, size, &size, NULL)) {
				LOOP_CONTINUE("could not get hub path (actual): %s", windows_error_str(0));
			}

			// Add prefix
			wstr = is_hcd?s_hubname.u.root.RootHubName:s_hubname.u.node.NodeName;
			tmp_str = wchar_to_utf8(wstr);
			if (tmp_str == NULL) {
				usbi_err(ctx, "could not convert hub path string.");
				LOOP_BREAK(LIBUSB_ERROR_NO_MEM);
			}

			path_str = sanitize_path(tmp_str);
			if (path_str == NULL) {
				usbi_err(ctx, "could not sanitize hub path string.");
				LOOP_BREAK(LIBUSB_ERROR_NO_MEM);
			}

			// Open Hub
			handle = CreateFileA(path_str, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 
				FILE_FLAG_POSIX_SEMANTICS|FILE_FLAG_OVERLAPPED, NULL);
			if(handle == INVALID_HANDLE_VALUE) {
				LOOP_CONTINUE("could not open hub %s: %s", path_str, windows_error_str(0));
			}
		}

		// Generate a session ID
		// Will need to change the session_id computation if this assertion fails
		if (conn_info.DeviceAddress > LIBUSB_DEVADDR_MAX) {
			LOOP_CONTINUE("program assertion failed - device address is greater than 255, ignoring device");
		} else {
			devaddr = conn_info.DeviceAddress;
		}
		// Same trick as linux for session_id, with same caveat
		session_id = busnum << (sizeof(libusb_devaddr_t)*8) | devaddr;
		usbi_dbg("busnum %d devaddr %d session_id %ld", busnum, devaddr, session_id);

		// Allocate device if needed
		dev = usbi_get_device_by_session_id(ctx, session_id);
		if (dev) {
			usbi_dbg("using existing device for session %ld", session_id);
			priv = __device_priv(dev);
		} else {
			usbi_dbg("allocating new device for session %ld", session_id);
			if ((dev = usbi_alloc_device(ctx, session_id)) == NULL) { 
				LOOP_BREAK(LIBUSB_ERROR_NO_MEM);
			}

			LOOP_CHECK(initialize_device(dev, busnum, devaddr, path_str, i, 
				conn_info.CurrentConfigurationValue, parent_dev));
			priv = __device_priv(dev);

			path_str = NULL;	// protect our path from being freed

			// Setup the cached descriptors. Note that only non HCDs can fetch descriptors
			if (!is_hcd) { 
				// The device descriptor has been read with conn_info
				memcpy(&priv->dev_descriptor, &(conn_info.DeviceDescriptor), sizeof(USB_DEVICE_DESCRIPTOR));
				dev->num_configurations = priv->dev_descriptor.bNumConfigurations;
				// If we can't read the config descriptors, just set the number of confs to zero
				if (cache_config_descriptors(dev, hub_handle) != LIBUSB_SUCCESS) {
					dev->num_configurations = 0;
					priv->dev_descriptor.bNumConfigurations = 0;
				}
			} else {
				LOOP_CHECK(force_hcd_device_descriptor(dev, handle));
			}
			LOOP_CHECK(usbi_sanitize_device(dev));
		}

		discdevs = discovered_devs_append(*_discdevs, dev);
		if (!discdevs) { 
			LOOP_BREAK(LIBUSB_ERROR_NO_MEM);
		}

		*_discdevs = discdevs;

		// Finally, if device is a hub, recurse
		if (conn_info.DeviceIsHub) {
			// Force the driver name
			priv->driver = safe_strdup("usbhub");
			// Find number of ports for this hub
			size =  sizeof(USB_NODE_INFORMATION);
			if (!DeviceIoControl(handle, IOCTL_USB_GET_NODE_INFORMATION, &hub_node, size,
				&hub_node, size, &size, NULL)) {
				LOOP_CONTINUE("could not retreive information for hub %s: %s", 
					priv->path, windows_error_str(0));
			}

			if (hub_node.NodeType != UsbHub) {
				LOOP_CONTINUE("unexpected hub type (%d) for hub %s", hub_node.NodeType, priv->path);
			}

			usbi_dbg("%d ports Hub: %s", hub_node.u.HubInformation.HubDescriptor.bNumberOfPorts, priv->path);

			usb_enumerate_hub(ctx, _discdevs, handle, busnum, dev, 
				hub_node.u.HubInformation.HubDescriptor.bNumberOfPorts);
		}
	}

	return r;
}

/*
 * Composite device interfaces are not enumerated using GUID_DEVINTERFACE_USB_DEVICE,
 * but instead require a different lookup mechanism
 */
static int set_composite_device(struct libusb_context *ctx, DEVINST devinst, struct windows_device_priv *priv)
{
	DEVINST child_devinst;
	int i, j, max_guids, nb_paths, interface_number;
	bool found;
	DWORD type, size;
	CONFIGRET r;
	HDEVINFO dev_info;
	SP_DEVINFO_DATA dev_info_data;
	SP_DEVICE_INTERFACE_DETAIL_DATA *dev_interface_details = NULL;
	HKEY key;
	WCHAR guid_string_w[40];
	GUID guid;
	GUID guid_table[MAX_USB_DEVICES];
	char* sanitized_path[MAX_USB_DEVICES];
	char* sanitized_short = NULL;
	char path[MAX_PATH_LENGTH];
	char driver[MAX_KEY_LENGTH];

	dev_info = SetupDiGetClassDevs(NULL, "USB", NULL, DIGCF_PRESENT|DIGCF_ALLCLASSES);
	if (dev_info == INVALID_HANDLE_VALUE) {
		return LIBUSB_ERROR_NOT_FOUND;
	}

	// First, retrieve all the device interface GUIDs
	max_guids = 0;
	for (i = 0; ; i++)
	{
		dev_info_data.cbSize = sizeof(dev_info_data);
		if (!SetupDiEnumDeviceInfo(dev_info, i, &dev_info_data)) {
			break;
		}

		key = SetupDiOpenDevRegKey(dev_info, &dev_info_data, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_READ);
		if (key == INVALID_HANDLE_VALUE) {
			usbi_dbg("invalid handle");
			continue;
		}

		if (RegQueryValueExW(key, L"DeviceInterfaceGUIDs", NULL, &type, (BYTE*)guid_string_w, &size) != ERROR_SUCCESS) {
			RegCloseKey(key);
			continue;
		}
		RegCloseKey(key);
		CLSIDFromString(guid_string_w, &guid);

		// identical device interface GUIDs are not supposed to happen, but are a real possibility
		// => check and ignore duplicates
		found = false;
		for (j=0; j<max_guids; j++) {
			if (memcmp(&guid_table[j], &guid, sizeof(GUID)) == 0) {
				found = true;
				break;
			}
		}
		if (!found) {
			guid_table[max_guids++] = guid;
			if (max_guids > MAX_USB_DEVICES) {
				usbi_warn(ctx, "more than %d devices - ignoring the rest", MAX_USB_DEVICES);
				break;
			}
		}
	}
	SetupDiDestroyDeviceInfoList(dev_info);

	// Now let's find the device interface paths for all these devices
	nb_paths = 0;
	for (j=0; j<max_guids; j++)
	{
		guid = guid_table[j];
		for (i = 0; ; i++)	
		{
			safe_free(dev_interface_details);
			dev_interface_details = get_interface_details(ctx, &dev_info, guid, i);
			if (dev_interface_details == NULL)
				break;

			// For now, we weed out all non WinUSB interfaces (which can happen
			// with a mix of WinUSB and proprietary drivers on composite devices)
			// If other APIs are supported, other drivers need to be added
			dev_info_data.cbSize = sizeof(dev_info_data);
			if (!SetupDiEnumDeviceInfo(dev_info, i, &dev_info_data)) {
				LOOP_CONTINUE("could not retrieve info data: %s", windows_error_str(0));
			}

			if(!SetupDiGetDeviceRegistryProperty(dev_info, &dev_info_data, SPDRP_SERVICE, 
				NULL, (BYTE*)driver, MAX_KEY_LENGTH, &size)) {
				LOOP_CONTINUE("could not read driver: %s", windows_error_str(0));
			}

			if (safe_strcmp(driver, "WinUSB") == 0) {
				sanitized_path[nb_paths++] = sanitize_path(dev_interface_details->DevicePath);
				if (nb_paths > MAX_USB_DEVICES) {
					usbi_warn(ctx, "more than %d devices - ignoring the rest", MAX_USB_DEVICES);
					break;
				}
			}
		}
	}

	// Finally, match the interface paths with the interfaces. We do that 
	// by looking at the children of the composite device
	// NB: if the interfaces are not found in their expected position,
	// claim_interface will issue a warning
	found = false;
	for (interface_number = 0; interface_number<USB_MAXINTERFACES; interface_number++)
	{
		if (interface_number == 0) {
			r = CM_Get_Child(&child_devinst, devinst, 0);
		} else {
			r = CM_Get_Sibling(&child_devinst, child_devinst, 0);
		}
		if (r == CR_NO_SUCH_DEVNODE) {	// end of the siblings
			break;
		} else if (r != CR_SUCCESS) {
			usbi_dbg("interface_nr = %d, error = %X", interface_number, r);
			break;
		}

		r = CM_Get_Device_ID(child_devinst, path, MAX_PATH_LENGTH, 0);
		if (r != CR_SUCCESS) {
			usbi_err(ctx, "could not retrieve simple path for interface %d: CR error %d", 
				interface_number, r);
		}
		sanitized_short = sanitize_path(path);

		for (j=0; j<nb_paths; j++) {
			if (safe_strncmp(sanitized_path[j], sanitized_short, strlen(sanitized_short)) == 0) {
				priv->interface[interface_number].path = sanitized_path[j];
				sanitized_path[j] = NULL;
			}
		}
		safe_free(sanitized_short);

		if (priv->interface[interface_number].path == NULL) {
			usbi_warn(ctx, "could not retrieve full path for interface %d", 
				interface_number);
			continue;
		}
		usbi_dbg("interface_path[%d]: %s", interface_number, priv->interface[interface_number].path);
		found = true;
	}

	for (j=0; j<nb_paths; j++) {
		safe_free(sanitized_path[j]);
	}

	if (found == 0) {
		usbi_warn(ctx, "composite device: no interfaces were found");
		return LIBUSB_ERROR_NOT_FOUND;
	}

	return LIBUSB_SUCCESS;
}

/*
 * This function retrieves and sets the paths of all non-hub devices
 * NB: No I/O with device is required during this call
 */
static int set_device_paths(struct libusb_context *ctx, struct discovered_devs *discdevs) 
{
	struct windows_device_priv *priv;
	struct windows_device_priv *parent_priv;
	char path[MAX_PATH_LENGTH];
	char reg_key[MAX_KEY_LENGTH];
	char *sanitized_path = NULL;
	HDEVINFO dev_info;
	SP_DEVICE_INTERFACE_DETAIL_DATA *dev_interface_details = NULL;
	SP_DEVINFO_DATA dev_info_data;
	DEVINST parent_devinst;
	GUID guid;
	DWORD size, reg_type;
	int	r = LIBUSB_SUCCESS;
	unsigned i, j, port_nr, hub_nr;
	bool found;

	// TODO: MI_## automated driver installation:
	guid = GUID_DEVINTERFACE_USB_DEVICE; 
	for (i = 0; ; i++)	
	{
		// safe loop: free up any (unprotected) dynamic resource
		safe_free(dev_interface_details);
		safe_free(sanitized_path);

		dev_interface_details = get_interface_details(ctx, &dev_info, guid, i);
		// safe loop: end of loop condition
		if ( (dev_interface_details == NULL)
		  || (r != LIBUSB_SUCCESS) )
			break;

		dev_info_data.cbSize = sizeof(dev_info_data);
		if (!SetupDiEnumDeviceInfo(dev_info, i, &dev_info_data)) {
			LOOP_CONTINUE("could not retrieve info data for device #%u, skipping: %s", 
				i, windows_error_str(0));
		}

		if (windows_version >= WINDOWS_VISTA_AND_LATER) {
			// Retrieve location information (port#) through the Location Information registry data
			if(!SetupDiGetDeviceRegistryProperty(dev_info, &dev_info_data, SPDRP_LOCATION_INFORMATION, 
				&reg_type, (BYTE*)reg_key, MAX_KEY_LENGTH, &size)) {
				LOOP_CONTINUE("could not retrieve location information for device #%u, skipping: %s", 
					i, windows_error_str(0));
			}

			if (size != sizeof("Port_#1234.Hub_#1234")) {
				LOOP_CONTINUE("unexpected registry key size for device #%u, skipping", i);
			}
			if (sscanf(reg_key, "Port_#%04d.Hub_#%04d", &port_nr, &hub_nr) != 2) {
				LOOP_CONTINUE("failure to read port and hub number for device #%u, skipping", i);
			}
		} else {
			// We're out of luck for Location Information on XP, since SPDRP_LOCATION_INFORMATION
			// returns anything but an actual location. However, it looks like the port number is 
			// the last digit before '#{' in the path string, so let's try that.
			// TODO: device enum that doesn't require this workaround
			found = false;
			for (j=0; j<safe_strlen(dev_interface_details->DevicePath); j++) {
				if ( (dev_interface_details->DevicePath[j] == '{') 
				  && (dev_interface_details->DevicePath[j-1] == '#') ) {
					// Matched '#{'. Now go back to last delimiter
					for (; j>=0; j--) {
						if (dev_interface_details->DevicePath[j] == '&') {
							found = true;
							break;
						}
					}
					if (found) {
						sscanf(&dev_interface_details->DevicePath[j+1], "%d#{%*s", &port_nr);
					}
					break;
				}
			}
			if (!found) {
				LOOP_CONTINUE("failure to \"guess\" port number for device #%u, skipping", i);
			}
		}

		// Retrieve parent's path using PnP Configuration Manager (CM)
		if (CM_Get_Parent(&parent_devinst, dev_info_data.DevInst, 0) != CR_SUCCESS) {
			LOOP_CONTINUE("could not retrieve parent info data for device #%u, skipping: %s", 
				i, windows_error_str(0));
		}
		
		if (CM_Get_Device_ID(parent_devinst, path, MAX_PATH_LENGTH, 0) != CR_SUCCESS) {
			LOOP_CONTINUE("could not retrieve parent's path for device #%u, skipping: %s", 
				i, windows_error_str(0));
		}

		// Fix parent's path inconsistancies before attempting to compare
		sanitized_path = sanitize_path(path);
		if (sanitized_path == NULL) {
			LOOP_CONTINUE("could not sanitize parent's path for device #%u, skipping.", i);
		}

		// With the parent path and port number, we should be able to locate our device 
		// by comparing these values to the ones we got when enumerating hubs
		found = false;
		for (j=0; j<discdevs->len; j++) {
			priv = __device_priv(discdevs->devices[j]);

			if (priv->parent_dev == NULL) {
				continue;	// ignore HCDs
			}

			parent_priv = __device_priv(priv->parent_dev);

			// NB: we compare strings of different lengths below => strncmp
			if ( (safe_strncmp(parent_priv->path, sanitized_path, strlen(sanitized_path)) == 0) 
			  && (port_nr == priv->connection_index) ) {

				priv->path = sanitize_path(dev_interface_details->DevicePath);

				usbi_dbg("path (%d:%d): %s", discdevs->devices[j]->bus_number, 
					discdevs->devices[j]->device_address, priv->path);

				// Check the service name to know what kind of device we have.
				// The service name is really the driver name without ".sys" ("WinUSB", "HidUsb", ...)
				// It tells us if we can use WinUSB, if we have a composite device, and the API to use
				if(!SetupDiGetDeviceRegistryProperty(dev_info, &dev_info_data, SPDRP_SERVICE, 
					&reg_type, (BYTE*)reg_key, MAX_KEY_LENGTH, &size)) {
					usbi_err(ctx, "could not retrieve driver information for device #%u, skipping: %s", 
						i, windows_error_str(0));
					break;
				}

				priv->driver = safe_strdup(reg_key);
				usbi_dbg("driver: %s", priv->driver);
				found = true;

				if (safe_strcmp(priv->driver, "WinUSB") == 0) {
					priv->api = API_WINUSB;
					// For non composite, the first interface is the same as the device
					priv->interface[0].path = safe_strdup(priv->path);	// needs strdup
				} else if (safe_strcmp(reg_key, "usbccgp") == 0) {
					// Composite (multi-interface) devices are identified by their use of 
					// the USB Common Class Generic Parent driver
					if (set_composite_device(ctx, dev_info_data.DevInst, priv) == LIBUSB_SUCCESS) {
						priv->api = API_WINUSB;
					} else {
						priv->api = API_NONE;
					}
				} else {
					// All other USB access drivers (HID, Mass Storage) are ignored for now
				}
				break;
			}
		}
		if (!found) {
			LOOP_CONTINUE("could not match %s with a libusb device.", dev_interface_details->DevicePath);
		}
	}

	return LIBUSB_SUCCESS;
}

/*
 * get_device_list: libusb backend device enumeration function
 */
static int windows_get_device_list(struct libusb_context *ctx, struct discovered_devs **_discdevs)
{
	struct windows_hcd_priv* hcd;	
	HANDLE handle = INVALID_HANDLE_VALUE;
	int r = LIBUSB_SUCCESS;
	libusb_bus_t bus;

	// Use the index of the HCD in the chained list as bus #
	for (hcd = hcd_root, bus = 0; ; hcd = hcd->next, bus++)
	{
		safe_closehandle(handle);

		if ( (hcd == NULL) || (r != LIBUSB_SUCCESS) )
			break;

		if (bus == LIBUSB_BUS_MAX) {
			LOOP_CONTINUE("program assertion failed - got more than %d buses, skipping the rest.", LIBUSB_BUS_MAX);
		}

		handle = CreateFileA(hcd->path, GENERIC_WRITE, FILE_SHARE_WRITE,
			NULL, OPEN_EXISTING, FILE_FLAG_POSIX_SEMANTICS|FILE_FLAG_OVERLAPPED, NULL);
		if (handle == INVALID_HANDLE_VALUE) {
			LOOP_CONTINUE("could not open bus %u, skipping: %s", bus, windows_error_str(0));
		}

		LOOP_CHECK(usb_enumerate_hub(ctx, _discdevs, handle, bus, NULL, 1));
	}

	// Set the interface path for non-hubs
	r = set_device_paths(ctx, *_discdevs);

	return r;
}

/*
 * exit: libusb backend deinitialization function
 */
static void windows_exit(void)
{
	struct windows_hcd_priv* hcd_tmp;	

	while (hcd_root != NULL)
	{
		hcd_tmp = hcd_root;	// Keep a copy for free
		hcd_root = hcd_root->next;
		windows_hcd_priv_release(hcd_tmp);
		safe_free(hcd_tmp);
	}

	winusb_api_exit();
	exit_polling();

	SetThreadAffinityMask(GetCurrentThread(), old_affinity_mask);

	// TODO: delete event thread for hotplug (see darwin source)
}

static int windows_get_device_descriptor(struct libusb_device *dev, unsigned char *buffer, int *host_endian)
{
	struct windows_device_priv *priv = __device_priv(dev);

	memcpy(buffer, &(priv->dev_descriptor), DEVICE_DESC_LENGTH);
	*host_endian = 0;

	return LIBUSB_SUCCESS;
}

static int windows_get_config_descriptor(struct libusb_device *dev, uint8_t config_index, unsigned char *buffer, size_t len, int *host_endian)
{
	struct windows_device_priv *priv = __device_priv(dev);
	PUSB_CONFIGURATION_DESCRIPTOR config_header;
	size_t size;

	// config index is zero based
	if (config_index >= dev->num_configurations)
		return LIBUSB_ERROR_INVALID_PARAM;

	if ((priv->config_descriptor == NULL) || (priv->config_descriptor[config_index] == NULL))
		return LIBUSB_ERROR_NOT_FOUND;

	config_header = (PUSB_CONFIGURATION_DESCRIPTOR)priv->config_descriptor[config_index];

	size = min(config_header->wTotalLength, len);
	memcpy(buffer, priv->config_descriptor[config_index], size);

	return LIBUSB_SUCCESS;
}

/*
 * return the cached copy of the active config descriptor
 */
static int windows_get_active_config_descriptor(struct libusb_device *dev, unsigned char *buffer, size_t len, int *host_endian)
{
	struct windows_device_priv *priv = __device_priv(dev);

	if (priv->active_config == 0)
		return LIBUSB_ERROR_NOT_FOUND;

	// config index is zero based
	return windows_get_config_descriptor(dev, priv->active_config-1, buffer, len, host_endian);
}

static int windows_open(struct libusb_device_handle *dev_handle)
{
	int r = LIBUSB_SUCCESS;
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);

	API_CALL(priv->api, open, dev_handle);

	return r;
}

static void windows_close(struct libusb_device_handle *dev_handle)
{
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);

	switch(priv->api) {
	case API_WINUSB:
		winusb_close(dev_handle);
		break;
	default:
		break;
	}
}

static int windows_get_configuration(struct libusb_device_handle *dev_handle, int *config)
{
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);

	*config = priv->active_config;
	return LIBUSB_SUCCESS;
}

/* 
 * from http://msdn.microsoft.com/en-us/library/ms793522.aspx: "The port driver 
 * does not currently expose a service that allows higher-level drivers to set 
 * the configuration."
 * TODO: See what users of devices with multiple confs report with this call
 */
static int windows_set_configuration(struct libusb_device_handle *dev_handle, int config)
{
	int r = LIBUSB_SUCCESS;

	if (config >= USB_MAXCONFIG)
		return LIBUSB_ERROR_INVALID_PARAM;

	r = libusb_control_transfer(dev_handle, LIBUSB_ENDPOINT_OUT | 
		LIBUSB_REQUEST_TYPE_STANDARD | LIBUSB_RECIPIENT_DEVICE,
		LIBUSB_REQUEST_SET_CONFIGURATION, config,
		0, NULL, 0, 1000);

	return r;
}

static int windows_claim_interface(struct libusb_device_handle *dev_handle, int iface)
{
	int r = LIBUSB_SUCCESS;
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);

	if (iface >= USB_MAXINTERFACES)
		return LIBUSB_ERROR_INVALID_PARAM;

	safe_free(priv->interface[iface].endpoint);
	priv->interface[iface].nb_endpoints= 0;

	API_CALL(priv->api, claim_interface, dev_handle, iface);

	if (r == LIBUSB_SUCCESS) {
		windows_assign_endpoints(dev_handle->dev, iface, 0);
	}

	return r;
}

static int windows_set_interface_altsetting(struct libusb_device_handle *dev_handle, int iface, int altsetting)
{
	int r = LIBUSB_SUCCESS;
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);

	safe_free(priv->interface[iface].endpoint);
	priv->interface[iface].nb_endpoints= 0;

	API_CALL(priv->api, set_interface_altsetting, dev_handle, iface, altsetting);

	if (r == LIBUSB_SUCCESS) {
		windows_assign_endpoints(dev_handle->dev, iface, altsetting);
	}

	return r;
}

static int windows_release_interface(struct libusb_device_handle *dev_handle, int iface)
{
	int r = LIBUSB_SUCCESS;
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);

	windows_set_interface_altsetting(dev_handle, iface, 0);
	API_CALL(priv->api, release_interface, dev_handle, iface);

	return r;
}

static int windows_clear_halt(struct libusb_device_handle *dev_handle, unsigned char endpoint)
{
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);
	int r;

	API_CALL(priv->api, clear_halt, dev_handle, endpoint);
	return r;
}

static int windows_reset_device(struct libusb_device_handle *dev_handle)
{
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);
	int r;

	API_CALL(priv->api, reset_device, dev_handle);
	return r;
}

// The 3 functions below are unlikely to ever get supported on Windows
static int windows_kernel_driver_active(struct libusb_device_handle *dev_handle, int iface)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int windows_attach_kernel_driver(struct libusb_device_handle *dev_handle, int iface) {
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int windows_detach_kernel_driver(struct libusb_device_handle *dev_handle, int iface) {
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static void windows_destroy_device(struct libusb_device *dev)
{
	struct windows_device_priv *priv = __device_priv(dev);
	windows_device_priv_release(priv, dev->num_configurations);
}

static void windows_clear_transfer_priv(struct usbi_transfer *itransfer)
{
	struct windows_transfer_priv *transfer_priv = usbi_transfer_get_os_priv(itransfer);

	usbi_remove_pollfd(ITRANSFER_CTX(itransfer), transfer_priv->pollable_fd.fd);
	free_fd_for_poll(transfer_priv->pollable_fd.fd);
}

static int submit_bulk_transfer(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = __USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct libusb_context *ctx = DEVICE_CTX(transfer->dev_handle->dev);
	struct windows_transfer_priv *transfer_priv = usbi_transfer_get_os_priv(itransfer);
	struct windows_device_priv *priv = __device_priv(transfer->dev_handle->dev);
	int r;

	API_CALL(priv->api, submit_bulk_transfer, itransfer);
	if (r != LIBUSB_SUCCESS) {
		return r;
	}

	usbi_add_pollfd(ctx, transfer_priv->pollable_fd.fd,
		(transfer->endpoint & LIBUSB_ENDPOINT_IN)?POLLIN:POLLOUT);

	return LIBUSB_SUCCESS;
}

static int submit_iso_transfer(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = __USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct libusb_context *ctx = DEVICE_CTX(transfer->dev_handle->dev);
	struct windows_transfer_priv *transfer_priv = usbi_transfer_get_os_priv(itransfer);
	struct windows_device_priv *priv = __device_priv(transfer->dev_handle->dev);
	int r;

	API_CALL(priv->api, submit_iso_transfer, itransfer);
	if (r != LIBUSB_SUCCESS) {
		return r;
	}

	usbi_add_pollfd(ctx, transfer_priv->pollable_fd.fd,
		(transfer->endpoint & LIBUSB_ENDPOINT_IN)?POLLIN:POLLOUT);

	return LIBUSB_SUCCESS;
}

static int submit_control_transfer(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = __USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct libusb_context *ctx = DEVICE_CTX(transfer->dev_handle->dev);
	struct windows_transfer_priv *transfer_priv = usbi_transfer_get_os_priv(itransfer);
	struct windows_device_priv *priv = __device_priv(transfer->dev_handle->dev);
	int r;

	API_CALL(priv->api, submit_control_transfer, itransfer);
	if (r != LIBUSB_SUCCESS) {
		return r;
	}

	usbi_add_pollfd(ctx, transfer_priv->pollable_fd.fd, POLLIN);

	return LIBUSB_SUCCESS;

}

static int windows_submit_transfer(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = __USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);

	switch (transfer->type) {
	case LIBUSB_TRANSFER_TYPE_CONTROL:
		return submit_control_transfer(itransfer);
	case LIBUSB_TRANSFER_TYPE_BULK:
	case LIBUSB_TRANSFER_TYPE_INTERRUPT:
		return submit_bulk_transfer(itransfer);
	case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS:
		return submit_iso_transfer(itransfer);
	default:
		usbi_err(TRANSFER_CTX(transfer), "unknown endpoint type %d", transfer->type);
		return LIBUSB_ERROR_INVALID_PARAM;
	}
}

static int windows_abort_control(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = __USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct windows_device_priv *priv = __device_priv(transfer->dev_handle->dev);
	int r;

	API_CALL(priv->api, abort_control, itransfer);
	return r;
}

static int windows_abort_transfers(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = __USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct windows_device_priv *priv = __device_priv(transfer->dev_handle->dev);
	int r;

	API_CALL(priv->api, abort_transfers, itransfer);
	return r;
}

static int windows_cancel_transfer(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = __USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);

	windows_clear_transfer_priv(itransfer);	// Cancel polling

	switch (transfer->type) {
	case LIBUSB_TRANSFER_TYPE_CONTROL:
		return windows_abort_control(itransfer);
	case LIBUSB_TRANSFER_TYPE_BULK:
	case LIBUSB_TRANSFER_TYPE_INTERRUPT:
	case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS:
		return windows_abort_transfers(itransfer);
	default:
		usbi_err(ITRANSFER_CTX(itransfer), "unknown endpoint type %d", transfer->type);
		return LIBUSB_ERROR_INVALID_PARAM;
	}
}

static void windows_transfer_callback (struct usbi_transfer *itransfer, uint32_t io_result, uint32_t io_size) 
{
	int status;

	usbi_dbg("handling I/O completion with status %d", io_result);

	switch(io_result) {
	case NO_ERROR:
		status = LIBUSB_TRANSFER_COMPLETED;
		itransfer->transferred += io_size;
		break;
	case ERROR_GEN_FAILURE:
		usbi_dbg("detected endpoint stall");
		status = LIBUSB_TRANSFER_STALL;
		break;
	default:
		usbi_err(ITRANSFER_CTX(itransfer), "I/O error: %s", windows_error_str(0));
		status = LIBUSB_TRANSFER_ERROR;
		break;
	}

	usbi_handle_transfer_completion(itransfer, status);
}

static void windows_handle_callback (struct usbi_transfer *itransfer, uint32_t io_result, uint32_t io_size) 
{
	struct libusb_transfer *transfer = __USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);

	switch (transfer->type) {
	case LIBUSB_TRANSFER_TYPE_CONTROL:
	case LIBUSB_TRANSFER_TYPE_BULK:
	case LIBUSB_TRANSFER_TYPE_INTERRUPT:
	case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS:
		windows_transfer_callback (itransfer, io_result, io_size);
		break;
	default:
		usbi_err(ITRANSFER_CTX(itransfer), "unknown endpoint type %d", transfer->type);
	}
}

static int windows_handle_events(struct libusb_context *ctx, struct pollfd *fds, nfds_t nfds, int num_ready)
{
	struct windows_transfer_priv* transfer_priv = NULL;
	int i = 0;
	bool found = false;
	struct usbi_transfer *transfer;
	DWORD io_size, io_result;

	pthread_mutex_lock(&ctx->open_devs_lock);
	for (i = 0; i < nfds && num_ready > 0; i++) {

		usbi_dbg("checking fd %d with revents = %04x", fds[i].fd, fds[i].revents);

		if (!fds[i].revents) {
			continue;
		}

		num_ready--;

		// Because a Windows OVERLAPPED is used for poll emulation, 
		// a pollable fd is created and stored with each transfer
		list_for_each_entry(transfer, &ctx->flying_transfers, list) {
			transfer_priv = usbi_transfer_get_os_priv(transfer);
			if (transfer_priv->pollable_fd.fd == fds[i].fd) {
				found = true;
				break;
			}
		}

		if (found) {
			if (GetOverlappedResult(transfer_priv->pollable_fd.handle, 
				transfer_priv->pollable_fd.overlapped, &io_size, false)) {
				io_result = NO_ERROR;
			} else {
				io_result = GetLastError();
			}
			usbi_remove_pollfd(ctx, transfer_priv->pollable_fd.fd);
			free_fd_for_poll(transfer_priv->pollable_fd.fd);
			windows_handle_callback(transfer, io_result, io_size);
		} else {
			usbi_err(ctx, "could not find a matching transfer for fd %x", fds[i]);
			return LIBUSB_ERROR_NOT_FOUND;
		}
	}

	pthread_mutex_unlock(&ctx->open_devs_lock);
	return LIBUSB_SUCCESS;
}

/*
 * Monotonic and real time functions
 */
static int windows_clock_gettime(int clk_id, struct timespec *tp)
{
	LARGE_INTEGER hires_counter;
	FILETIME ftime;
	ULARGE_INTEGER rtime;

	switch(clk_id) {
	case USBI_CLOCK_MONOTONIC:
		// If hires_frequency is set, we have an hires monotonic timer available
		if ((hires_frequency != 0) && (QueryPerformanceCounter(&hires_counter) != 0))
		{
			tp->tv_sec = hires_counter.QuadPart / hires_frequency;
			tp->tv_nsec = ((hires_counter.QuadPart % hires_frequency)/1000) * hires_ticks_to_ps;
			return LIBUSB_SUCCESS;
		}	
		// make sure we fall through to real-time if we can't get hires timer
	case USBI_CLOCK_REALTIME:
		// We follow http://msdn.microsoft.com/en-us/library/ms724928%28VS.85%29.aspx
		// with a predef epoch_time to have an epoch that starts at 1970.01.01 00:00
		// Note however that our resolution is bounded by the Windows system time 
		// functions and is at best of the order of 1 ms (or, usually, worse)
		GetSystemTimeAsFileTime(&ftime);
		rtime.LowPart = ftime.dwLowDateTime;
		rtime.HighPart = ftime.dwHighDateTime;
		rtime.QuadPart -= epoch_time;
		tp->tv_sec = rtime.QuadPart / 10000000;
		tp->tv_nsec = (rtime.QuadPart % 10000000)*100;
		return LIBUSB_SUCCESS;
	default:
		return LIBUSB_ERROR_INVALID_PARAM;
	}
	return LIBUSB_ERROR_OTHER;
}

const struct usbi_os_backend windows_backend = {
	.name = "Windows",
	.init = windows_init,
	.exit = windows_exit,
	.get_device_list = windows_get_device_list,
	.get_device_descriptor = windows_get_device_descriptor,
	.get_active_config_descriptor = windows_get_active_config_descriptor,
	.get_config_descriptor = windows_get_config_descriptor,

	.open = windows_open,
	.close = windows_close,
	.get_configuration = windows_get_configuration,
	.set_configuration = windows_set_configuration,
	.claim_interface = windows_claim_interface,
	.release_interface = windows_release_interface,

	.set_interface_altsetting = windows_set_interface_altsetting,
	.clear_halt = windows_clear_halt,
	.reset_device = windows_reset_device,

	.kernel_driver_active = windows_kernel_driver_active,
	.detach_kernel_driver = windows_detach_kernel_driver,
	.attach_kernel_driver = windows_attach_kernel_driver,

	.destroy_device = windows_destroy_device,

	.submit_transfer = windows_submit_transfer,
	.cancel_transfer = windows_cancel_transfer,
	.clear_transfer_priv = windows_clear_transfer_priv,

	.handle_events = windows_handle_events,

	.clock_gettime = windows_clock_gettime,

	.device_priv_size = sizeof(struct windows_device_priv),
	.device_handle_priv_size = sizeof(struct windows_device_handle_priv),
	.transfer_priv_size = sizeof(struct windows_transfer_priv),
	.add_iso_packet_size = 0,
};

/*
 * WinUSB API functions
 */
static int winusb_api_init(struct libusb_context *ctx)
{
	DLL_LOAD(winusb.dll, WinUsb_Initialize, TRUE);
	DLL_LOAD(winusb.dll, WinUsb_Free, TRUE);
	DLL_LOAD(winusb.dll, WinUsb_GetAssociatedInterface, TRUE);
	DLL_LOAD(winusb.dll, WinUsb_GetDescriptor, TRUE); 
	DLL_LOAD(winusb.dll, WinUsb_QueryInterfaceSettings, TRUE);
	DLL_LOAD(winusb.dll, WinUsb_QueryDeviceInformation, TRUE);
	DLL_LOAD(winusb.dll, WinUsb_SetCurrentAlternateSetting, TRUE); 
	DLL_LOAD(winusb.dll, WinUsb_GetCurrentAlternateSetting, TRUE);
	DLL_LOAD(winusb.dll, WinUsb_QueryPipe, TRUE);
	DLL_LOAD(winusb.dll, WinUsb_SetPipePolicy, TRUE);
	DLL_LOAD(winusb.dll, WinUsb_GetPipePolicy, TRUE);
	DLL_LOAD(winusb.dll, WinUsb_ReadPipe, TRUE);
	DLL_LOAD(winusb.dll, WinUsb_WritePipe, TRUE);
	DLL_LOAD(winusb.dll, WinUsb_ControlTransfer, TRUE);
	DLL_LOAD(winusb.dll, WinUsb_ResetPipe, TRUE);
	DLL_LOAD(winusb.dll, WinUsb_AbortPipe, TRUE);
	DLL_LOAD(winusb.dll, WinUsb_FlushPipe, TRUE);

	api_winusb_available = true;
	return LIBUSB_SUCCESS;
}

static int winusb_api_exit(void) 
{
	api_winusb_available = false;
	return LIBUSB_SUCCESS;
}

static int winusb_open(struct libusb_device_handle *dev_handle) 
{
	struct libusb_context *ctx = DEVICE_CTX(dev_handle->dev);
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);
	struct windows_device_handle_priv *handle_priv = (struct windows_device_handle_priv *)dev_handle->os_priv;

	HANDLE file_handle;
	int i;

	CHECK_WINUSB_AVAILABLE;

	// WinUSB requires a seperate handle for each interface
	for (i = 0; i < USB_MAXINTERFACES; i++) {
		if (priv->interface[i].path != NULL) {
			file_handle = CreateFileA(priv->interface[i].path, GENERIC_WRITE | GENERIC_READ, FILE_SHARE_WRITE | FILE_SHARE_READ, 
				NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
			if (file_handle == INVALID_HANDLE_VALUE) {
				usbi_err(ctx, "could not open device %s (interface %d): %s", priv->path, i, windows_error_str(0));
				switch(GetLastError()) {
				case ERROR_FILE_NOT_FOUND:	// The device was disconnected
					return LIBUSB_ERROR_NO_DEVICE;
				case ERROR_ACCESS_DENIED:
					return LIBUSB_ERROR_ACCESS;
				default:
					return LIBUSB_ERROR_IO;
				}
			}
			handle_priv->interface_handle[i].file = file_handle;
		}
	}

	return LIBUSB_SUCCESS;
}

static void winusb_close(struct libusb_device_handle *dev_handle)
{
	struct windows_device_handle_priv *handle_priv = (struct windows_device_handle_priv *)dev_handle->os_priv;
	HANDLE file_handle;
	int i;

	if (!api_winusb_available)
		return;

	for (i = 0; i < USB_MAXINTERFACES; i++) {
		file_handle = handle_priv->interface_handle[i].file;
		if ( (file_handle != 0) && (file_handle != INVALID_HANDLE_VALUE)) {
			CloseHandle(file_handle);
		}
	}
}

static int winusb_claim_interface(struct libusb_device_handle *dev_handle, int iface)
{
	struct libusb_context *ctx = DEVICE_CTX(dev_handle->dev);
	struct windows_device_handle_priv *handle_priv = (struct windows_device_handle_priv *)dev_handle->os_priv;
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);
	bool is_composite = (safe_strcmp(priv->driver, "usbccgp") == 0);
	HANDLE file_handle, winusb_handle;
	USB_INTERFACE_DESCRIPTOR if_desc;
	UCHAR policy;
	uint8_t endpoint_address;
	int i;

	CHECK_WINUSB_AVAILABLE;

	winusb_handle = handle_priv->interface_handle[iface].winusb;

	// interfaces for composite devices are always independent, therefore 
	// "alt" interfaces are only found on non-composite
	if ((!is_composite) && (iface != 0)) {
		// It is a requirement on Windows that to claim an interface >= 1 
		// on a non-composite device, you must first have claimed interface 0
		if ((winusb_handle == 0) || (winusb_handle == INVALID_HANDLE_VALUE)) {
			return LIBUSB_ERROR_ACCESS;
		}

		if (!WinUsb_GetAssociatedInterface(winusb_handle, iface-1, 
			&handle_priv->interface_handle[iface].winusb)) {
			handle_priv->interface_handle[iface].winusb = INVALID_HANDLE_VALUE;
			switch(GetLastError()) {
			case ERROR_NO_MORE_ITEMS:   // invalid iface
				return LIBUSB_ERROR_NOT_FOUND;
			case ERROR_BAD_COMMAND:     // The device was disconnected
				return LIBUSB_ERROR_NO_DEVICE;
			case ERROR_ALREADY_EXISTS:  // already claimed
				return LIBUSB_ERROR_BUSY;
			default:
				usbi_err(ctx, "could not claim interface %d: %s", iface, windows_error_str(0));
				return LIBUSB_ERROR_ACCESS;
			}
		}
	} else {
		// composite device (independent interfaces) or interface 0
		file_handle = handle_priv->interface_handle[iface].file;
		if ((file_handle == 0) || (file_handle == INVALID_HANDLE_VALUE)) {
			return LIBUSB_ERROR_NOT_FOUND;
		}

		if (!WinUsb_Initialize(file_handle, &winusb_handle)) {
			usbi_err(ctx, "could not access interface %d: %s", iface, windows_error_str(0));
			handle_priv->interface_handle[iface].winusb = INVALID_HANDLE_VALUE;

			switch(GetLastError()) {
			case ERROR_BAD_COMMAND:	// The device was disconnected
				return LIBUSB_ERROR_NO_DEVICE;
			default:
				usbi_err(ctx, "could not claim interface %d: %s", iface, windows_error_str(0));
				return LIBUSB_ERROR_ACCESS;
			}
		}
		handle_priv->interface_handle[iface].winusb = winusb_handle;
	}
	if (!WinUsb_QueryInterfaceSettings(winusb_handle, 0, &if_desc)) {
		usbi_err(ctx, "could not query interface settings for interface %d: %s", iface, windows_error_str(0));
	} else if (if_desc.bInterfaceNumber != iface) {
		usbi_warn(ctx, "program assertion failed: WinUSB interface %d found at position %d", 
			if_desc.bInterfaceNumber, iface);
	}

	usbi_dbg("claimed interface %d", iface);
	handle_priv->active_interface = iface;

	// With handle and enpoints set (in parent), we can setup the default 
	// pipe properties (copied from libusb-win32-v1)
	// see http://download.microsoft.com/download/D/1/D/D1DD7745-426B-4CC3-A269-ABBBE427C0EF/DVC-T705_DDC08.pptx
	for (i=0; i<priv->interface[iface].nb_endpoints; i++) {
		endpoint_address = priv->interface[iface].endpoint[i];
		policy = false;
		if (!WinUsb_SetPipePolicy(winusb_handle, endpoint_address,
			SHORT_PACKET_TERMINATE, sizeof(UCHAR), &policy)) {
			usbi_dbg("failed to disable SHORT_PACKET_TERMINATE for endpoint %02X", endpoint_address);
		}
		if (!WinUsb_SetPipePolicy(winusb_handle, endpoint_address,
			IGNORE_SHORT_PACKETS, sizeof(UCHAR), &policy)) {
			usbi_dbg("failed to disable IGNORE_SHORT_PACKETS for endpoint %02X", endpoint_address);
		}
		if (!WinUsb_SetPipePolicy(winusb_handle, endpoint_address,
			ALLOW_PARTIAL_READS, sizeof(UCHAR), &policy)) {
			usbi_dbg("failed to disable ALLOW_PARTIAL_READS for endpoint %02X", endpoint_address);
		}
		policy = true;
		if (!WinUsb_SetPipePolicy(winusb_handle, endpoint_address,
			AUTO_CLEAR_STALL, sizeof(UCHAR), &policy)) {
			usbi_dbg("failed to enable AUTO_CLEAR_STALL for endpoint %02X", endpoint_address);
		}
	}

	return LIBUSB_SUCCESS;
}

static int winusb_release_interface(struct libusb_device_handle *dev_handle, int iface)
{
	struct windows_device_handle_priv *handle_priv = (struct windows_device_handle_priv *)dev_handle->os_priv;
	HANDLE winusb_handle;

	CHECK_WINUSB_AVAILABLE;

	winusb_handle = handle_priv->interface_handle[iface].winusb;
	if ((winusb_handle == 0) || (winusb_handle == INVALID_HANDLE_VALUE)) {
		return LIBUSB_ERROR_NOT_FOUND;
	}

	WinUsb_Free(winusb_handle);

	return LIBUSB_SUCCESS;
}

/*
 * Return the first valid WinUSB handle, for control transfers
 */
static int winusb_get_valid_interface(struct windows_device_handle_priv *handle_priv)
{
	int i;

	for (i=0; i<USB_MAXINTERFACES; i++) {
		if ( (handle_priv->interface_handle[i].winusb != 0) 
		  && (handle_priv->interface_handle[i].winusb != INVALID_HANDLE_VALUE)) {
			return i;
		}
	}
	return -1;
}

/*
 * Lookup interface by endpoint address. -1 if not found
 */
static int winusb_interface_by_endpoint(struct windows_device_priv *priv, 
	struct windows_device_handle_priv *handle_priv, uint8_t endpoint_address)
{
	int i, j;
	for (i=0; i<USB_MAXINTERFACES; i++) {
		if (handle_priv->interface_handle[i].winusb == INVALID_HANDLE_VALUE)
			continue;
		if (handle_priv->interface_handle[i].winusb == 0)
			continue;
		if (priv->interface[i].endpoint == NULL)
			continue;
		for (j=0; j<priv->interface[i].nb_endpoints; j++) {
			if (priv->interface[i].endpoint[j] == endpoint_address) {
				return i;
			}
		}
	}
	return -1;
}

static int winusb_submit_control_transfer(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = __USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct libusb_context *ctx = DEVICE_CTX(transfer->dev_handle->dev);
	struct windows_transfer_priv *transfer_priv = usbi_transfer_get_os_priv(itransfer);
	struct windows_device_handle_priv *handle_priv = (struct windows_device_handle_priv *)transfer->dev_handle->os_priv;
	WINUSB_SETUP_PACKET *setup = (WINUSB_SETUP_PACKET *) transfer->buffer;
	ULONG size;
	HANDLE winusb_handle;
	int current_interface;
	struct winfd wfd;

	CHECK_WINUSB_AVAILABLE;

	transfer_priv->pollable_fd = INVALID_WINFD;
	size = transfer->length - LIBUSB_CONTROL_SETUP_SIZE;

	if (size > MAX_CTRL_BUFFER_LENGTH)
		return LIBUSB_ERROR_INVALID_PARAM;

	current_interface = winusb_get_valid_interface(handle_priv);
	// Attempt to claim an interface if none was found
	if (current_interface < 0) {
		for (current_interface=0; current_interface<USB_MAXINTERFACES; current_interface++) {
			if (libusb_claim_interface(transfer->dev_handle, current_interface) == LIBUSB_SUCCESS) {
				usbi_warn(ctx, "auto-claimed interface %d for control request", current_interface);
				break;
			}
		}
	}
	if (current_interface == USB_MAXINTERFACES) {
		usbi_err(ctx, "no active interface");
		return LIBUSB_ERROR_NOT_FOUND;
	}

	usbi_dbg("will use interface %d", current_interface);
	winusb_handle = handle_priv->interface_handle[current_interface].winusb;

	wfd = create_fd_for_poll(winusb_handle, _O_RDONLY);	
	if (wfd.fd < 0) {
		return LIBUSB_ERROR_NO_MEM;
	}

	if (!WinUsb_ControlTransfer(wfd.handle, *setup, transfer->buffer + LIBUSB_CONTROL_SETUP_SIZE, size, NULL, wfd.overlapped)) {
		if(GetLastError() != ERROR_IO_PENDING) {
			usbi_err(ctx, "WinUsb_ControlTransfer failed: %s", windows_error_str(0));
			free_fd_for_poll(wfd.fd);
			return LIBUSB_ERROR_IO;
		}
	} else {
		// TODO: find out if this ever happens through user test reports
		usbi_err(ctx, "chill out man; this is like way too fast for async I/O...");
		free_fd_for_poll(wfd.fd);
		return LIBUSB_ERROR_IO;
	}

	// Use priv_transfer to store data needed for async polling
	transfer_priv->pollable_fd = wfd;

	return LIBUSB_SUCCESS;
}

static int winusb_set_interface_altsetting(struct libusb_device_handle *dev_handle, int iface, int altsetting)
{
	struct libusb_context *ctx = DEVICE_CTX(dev_handle->dev);
	struct windows_device_handle_priv *handle_priv = (struct windows_device_handle_priv *)dev_handle->os_priv;
	HANDLE winusb_handle;

	CHECK_WINUSB_AVAILABLE;

	winusb_handle = handle_priv->interface_handle[iface].winusb;
	if ((winusb_handle == 0) || (winusb_handle == INVALID_HANDLE_VALUE)) {
		usbi_err(ctx, "interface must be claimed first");
		return LIBUSB_ERROR_NOT_FOUND;
	}

	if (!WinUsb_SetCurrentAlternateSetting(winusb_handle, altsetting)) {
		usbi_err(ctx, "WinUsb_SetCurrentAlternateSetting failed: %s", windows_error_str(0));
		return LIBUSB_ERROR_IO;
	}

	return LIBUSB_SUCCESS;
}

static int winusb_submit_bulk_transfer(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = __USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct libusb_context *ctx = DEVICE_CTX(transfer->dev_handle->dev);
	struct windows_transfer_priv *transfer_priv = usbi_transfer_get_os_priv(itransfer);
	struct windows_device_handle_priv *handle_priv = (struct windows_device_handle_priv *)transfer->dev_handle->os_priv;
	struct windows_device_priv *priv = __device_priv(transfer->dev_handle->dev);
	HANDLE winusb_handle;
	bool direction_in, ret;
	int current_interface;
	struct winfd wfd;

	CHECK_WINUSB_AVAILABLE;

	transfer_priv->pollable_fd = INVALID_WINFD;

	current_interface = winusb_interface_by_endpoint(priv, handle_priv, transfer->endpoint);
	if (current_interface < 0) {
		usbi_err(ctx, "unable to match endpoint to an open interface - cancelling transfer");
		return LIBUSB_ERROR_NOT_FOUND;
	}

	usbi_dbg("matched endpoint %02X with interface %d", transfer->endpoint, current_interface);

	winusb_handle = handle_priv->interface_handle[current_interface].winusb;
	direction_in = transfer->endpoint & LIBUSB_ENDPOINT_IN;

	wfd = create_fd_for_poll(winusb_handle, direction_in?_O_RDONLY:_O_WRONLY);	
	if (wfd.fd < 0) {
		return LIBUSB_ERROR_NO_MEM;
	}

	if (direction_in) {
		usbi_dbg("reading %d bytes", transfer->length);
		ret = WinUsb_ReadPipe(winusb_handle, transfer->endpoint, transfer->buffer, transfer->length, NULL, wfd.overlapped);
	} else {
		usbi_dbg("writing %d bytes", transfer->length);
		ret = WinUsb_WritePipe(winusb_handle, transfer->endpoint, transfer->buffer, transfer->length, NULL, wfd.overlapped);
	}
	if (!ret) {
		if(GetLastError() != ERROR_IO_PENDING) {
			usbi_err(ctx, "WinUsb_Pipe Transfer failed: %s", windows_error_str(0));
			free_fd_for_poll(wfd.fd);
			return LIBUSB_ERROR_IO;
		}
	} else {
		// TODO: find out if this ever happens through user test reports
		usbi_err(ctx, "chill out man; this is like way too fast for async I/O...");
		free_fd_for_poll(wfd.fd);
		return LIBUSB_ERROR_IO;
	}

	transfer_priv->pollable_fd = wfd;

	return LIBUSB_SUCCESS;
}

static int winusb_submit_iso_transfer(struct usbi_transfer *itransfer) {
	// WinUSB does not support isochronous transfers
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int winusb_clear_halt(struct libusb_device_handle *dev_handle, unsigned char endpoint)
{
	struct libusb_context *ctx = DEVICE_CTX(dev_handle->dev);
	struct windows_device_handle_priv *handle_priv = (struct windows_device_handle_priv *)dev_handle->os_priv;
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);
	HANDLE winusb_handle;
	int current_interface;

	CHECK_WINUSB_AVAILABLE;

	current_interface = winusb_interface_by_endpoint(priv, handle_priv, endpoint);
	if (current_interface < 0) {
		usbi_err(ctx, "unable to match endpoint to an open interface - cannot clear");
		return LIBUSB_ERROR_NOT_FOUND;
	}

	usbi_dbg("matched endpoint %02X with interface %d", endpoint, current_interface);
	winusb_handle = handle_priv->interface_handle[current_interface].winusb;

	if (!WinUsb_ResetPipe(winusb_handle, endpoint)) {
		usbi_err(ctx, "WinUsb_ResetPipe failed: %s", windows_error_str(0));
		return LIBUSB_ERROR_NO_DEVICE;
	}

	return LIBUSB_SUCCESS;
}

/*
 * from http://www.winvistatips.com/winusb-bugchecks-t335323.html (confirmed
 * through testing as well):
 * "You can not call WinUsb_AbortPipe on control pipe. You can possibly cancel
 * the control transfer using CancelIo"
 */
static int winusb_abort_control(struct usbi_transfer *itransfer)
{
	// Cancelling of the I/O is done in the parent
	return LIBUSB_SUCCESS;
}

static int winusb_abort_transfers(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = __USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct libusb_context *ctx = DEVICE_CTX(transfer->dev_handle->dev);
	struct windows_device_handle_priv *handle_priv = (struct windows_device_handle_priv *)transfer->dev_handle->os_priv;
	struct windows_device_priv *priv = __device_priv(transfer->dev_handle->dev);
	HANDLE winusb_handle;
	int current_interface;

	CHECK_WINUSB_AVAILABLE;

	current_interface = winusb_interface_by_endpoint(priv, handle_priv, transfer->endpoint);
	if (current_interface < 0) {
		usbi_err(ctx, "unable to match endpoint to an open interface - cancelling abort");
		return LIBUSB_ERROR_NOT_FOUND;
	}

	usbi_dbg("matched endpoint %02X with interface %d", transfer->endpoint, current_interface);

	winusb_handle = handle_priv->interface_handle[current_interface].winusb;

	if (!WinUsb_AbortPipe(winusb_handle, transfer->endpoint)) {
		usbi_err(ctx, "WinUsb_AbortPipe failed: %s", windows_error_str(0));
		return LIBUSB_ERROR_NO_DEVICE;
	}

	return LIBUSB_SUCCESS;
}

/* 
 * from the "How to Use WinUSB to Communicate with a USB Device" Microsoft white paper
 * (http://www.microsoft.com/whdc/connect/usb/winusb_howto.mspx):
 * "WinUSB does not support host-initiated reset port and cycle port operations" and
 * IOCTL_INTERNAL_USB_CYCLE_PORT is only available in kernel mode and the
 * IOCTL_USB_HUB_CYCLE_PORT ioctl was removed from Vista => the best we can do is 
 * cycle the pipes (and even then, the control pipe can not be reset using WinUSB)
 */
static int winusb_reset_device(struct libusb_device_handle *dev_handle)
{
	struct libusb_context *ctx = DEVICE_CTX(dev_handle->dev);
	struct windows_device_handle_priv *handle_priv = (struct windows_device_handle_priv *)dev_handle->os_priv;
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);
	struct winfd wfd;
	HANDLE winusb_handle;
	int i, j;

	CHECK_WINUSB_AVAILABLE;

	// Reset any available pipe (except control)
	for (i=0; i<USB_MAXINTERFACES; i++) {
		winusb_handle = handle_priv->interface_handle[i].winusb;
		for (wfd = handle_to_winfd(winusb_handle); wfd.fd > 0;)
		{
			// Cancel any pollable I/O
			usbi_remove_pollfd(ctx, wfd.fd);
			free_fd_for_poll(wfd.fd);
			wfd = handle_to_winfd(winusb_handle);
		} 

		if ( (winusb_handle != 0) && (winusb_handle != INVALID_HANDLE_VALUE)) {
			for (j=0; j<priv->interface[i].nb_endpoints; j++) {
				usbi_dbg("resetting ep %02X", priv->interface[i].endpoint[j]);
				// TODO: looks like whatever you try here, you can't get an actual reset of the ep
				if (!WinUsb_AbortPipe(winusb_handle, priv->interface[i].endpoint[j])) {
					usbi_err(ctx, "WinUsb_AbortPipe (pipe address %02X) failed: %s", 
						priv->interface[i].endpoint[j], windows_error_str(0));
				}
				// FlushPipe seems to fail on OUT pipes
				if ( (priv->interface[i].endpoint[j] & LIBUSB_ENDPOINT_IN) 
				  && (!WinUsb_FlushPipe(winusb_handle, priv->interface[i].endpoint[j])) ) {
					usbi_err(ctx, "WinUsb_FlushPipe (pipe address %02X) failed: %s", 
						priv->interface[i].endpoint[j], windows_error_str(0));
				}
				if (!WinUsb_ResetPipe(winusb_handle, priv->interface[i].endpoint[j])) {
					usbi_err(ctx, "WinUsb_ResetPipe (pipe address %02X) failed: %s", 
						priv->interface[i].endpoint[j], windows_error_str(0));
				}
			}
		}
	}

	return LIBUSB_SUCCESS;
}
