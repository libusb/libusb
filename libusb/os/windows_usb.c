/*
 * windows backend for libusb 1.0
 * Copyright (c) 2009 Pete Batard <pbatard@gmail.com>
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

/*
 * Design considerations:
 *
 * No matter where it happens, a failed malloc is a critical error and will
 * abort whichever section of code is running.
 *
 * Both our buses and device addresses are zero indexed rather than 1 indexed
 * for convenience reasons (post HCD devaddr start at 1 on window, and we need
 * to set a devaddr for the non enumerated HCD hub)
 *
 * While we try to work around OS errors by skipping the device/op whenever
 * possible (and produce a warning), any libusb calls returning an error is
 * treated as a potential critical bug and cause for an immediate abort of
 * the function that called it.
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

static int windows_get_active_config_descriptor(struct libusb_device *dev, unsigned char *buffer, size_t len, int *host_endian);
static int windows_get_active_config(struct libusb_device *dev);

// HCD private chained list
struct windows_hcd_priv* hcd_root = NULL;
// timers
uint64_t hires_frequency, hires_frequency_ns;
// 1970.01.01 00:00:000 in MS Filetime, as computed and confirmed with google
const uint64_t epoch_time = 116444736000000000;

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
 */
static char *windows_error_str(void)
{
static char err_string[ERR_BUFFER_SIZE];
	DWORD size;
	unsigned int errcode, format_errcode;

	errcode = GetLastError();
	size = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, errcode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR) &err_string,
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
	int j;
	size_t size;
	char* ret_path;
	bool has_root_prefix = false;

	if (path == NULL)
		return NULL;

	size = strlen(path)+1;
	if ((size > 3) && (path[0] == '\\') && (path[1] == '\\') && (path[3] == '\\')) {
		has_root_prefix = true;
	} else {
		size += sizeof(ROOT_PREFIX);
	}

	if ((ret_path = (char*)calloc(size, 1)) == NULL) 
		return NULL;

	if (!has_root_prefix) {
		safe_strncpy(ret_path, size, ROOT_PREFIX, sizeof(ROOT_PREFIX));
	}
	safe_strncat(ret_path, size, path, strlen(path));

	// Microsoft indiscriminatly uses '\\?\' or '\\.\' for root prefixes. Ensure '\\.\' is used
	ret_path[2] = '.';

	// Same goes for '\' and '#' after the root prefix. Ensure '#' is used
	for(j=sizeof(ROOT_PREFIX)-1; j<size; j++) {
		ret_path[j] = toupper(ret_path[j]);	// Fix case too
		if (ret_path[j] == '\\')
			ret_path[j] = '#';
	}

	return ret_path;
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
	SP_DEVICE_INTERFACE_DATA dev_interface_data;
	SP_DEVICE_INTERFACE_DETAIL_DATA *dev_interface_details = NULL;
	GUID guid;
	DWORD size;
	libusb_bus_t bus;
	int r = LIBUSB_SUCCESS;
	LARGE_INTEGER li_frequency;

	// If our HCD list is populated, we don't need to re-init
	if (hcd_root != NULL) {
		usbi_dbg("init already occured.");
		return LIBUSB_SUCCESS;
	}

	// Find out if we have access to a monotonic (hires) timer
	if (!QueryPerformanceFrequency(&li_frequency)) {
		usbi_dbg("no hires timer available on this platform");
		hires_frequency = 0;
		hires_frequency_ns = 0;	
	} else {
		usbi_dbg("hires timer available");
		hires_frequency = li_frequency.QuadPart;
		// We compute the ns frequency as well for speedup
		hires_frequency_ns =  hires_frequency / 1000000000; 
	}

	// We maintain a chained list of the Host Controllers found
	struct windows_hcd_priv** _hcd_cur = &hcd_root;

	guid = GUID_DEVINTERFACE_USB_HOST_CONTROLLER;
	dev_info = SetupDiGetClassDevs(&guid, NULL, NULL, (DIGCF_PRESENT | DIGCF_DEVICEINTERFACE));

	if (dev_info != INVALID_HANDLE_VALUE)
	{
		dev_interface_data.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

		for (bus = 0; ; bus++)
		{
			// safe loop: free up any (unprotected) dynamic resource
			// NB: this is always executed before breaking the loop
			safe_free(dev_interface_details);
			safe_free(*_hcd_cur);

			// safe loop: end of loop condition
			if ((SetupDiEnumDeviceInterfaces(dev_info, NULL, &guid, bus, &dev_interface_data) != TRUE) || (r != LIBUSB_SUCCESS))
				break;

			// Will need to change storage and size of libusb_bus_t if this ever occurs
			if (bus == LIBUSB_BUS_MAX) {
				LOOP_CONTINUE("program assertion failed - found more than %d buses, skipping the rest.", LIBUSB_BUS_MAX);
			}

			// Do a dummy call to get the size
			if (!SetupDiGetDeviceInterfaceDetail(dev_info, &dev_interface_data, NULL, 0, &size, NULL)) {
				// The dummy call should fail with ERROR_INSUFFICIENT_BUFFER
				if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
					LOOP_CONTINUE("could not access interface data for bus %u, skipping: %s",
						bus, windows_error_str());
				}
			}
			else {
				LOOP_CONTINUE("program assertion failed - http://msdn.microsoft.com/en-us/library/ms792901.aspx is wrong.");
			}

			if ((dev_interface_details = malloc(size)) == NULL) {
				usbi_err(ctx, "could not allocate interface data for bus %u. aborting.", bus);
				LOOP_BREAK(LIBUSB_ERROR_NO_MEM);
			}

			dev_interface_details->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
			// Actual call.
			if (!SetupDiGetDeviceInterfaceDetail(dev_info, &dev_interface_data,
				dev_interface_details, size, &size, NULL)) {
				LOOP_CONTINUE("could not access interface data for bus %u, skipping: %s",
					bus, windows_error_str());
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
		SetupDiDestroyDeviceInfoList(dev_info);
	}

	// TODO: pthread stuff

	if (hcd_root == NULL)
		return LIBUSB_ERROR_NO_DEVICE;
	else 
		return LIBUSB_SUCCESS;
}

/*
 * Initialize device structure, including active config
 */ 
static int initialize_device(struct libusb_device *dev, libusb_bus_t busnum,
	libusb_devaddr_t devaddr, char *path, int connection_index,
	struct libusb_device *parent_dev)
{
	struct windows_device_priv *priv = __device_priv(dev);
	int active_config = 0;

	// Set default values
	windows_device_priv_init(priv);

	dev->bus_number = busnum;
	dev->device_address = devaddr;
	priv->path = path;
	priv->connection_index = connection_index;
	priv->parent_dev = parent_dev;

	active_config = windows_get_active_config(dev);

	if (active_config < 0) {
		return active_config;
	} else if (active_config == 0) {
		// specs say a configuration value of 0 means unconfigured.
		usbi_dbg("assuming unconfigured device");
	}
	priv->active_config = active_config;

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

	// TODO: fill in more blanks 
	priv->dev_descriptor.bLength = sizeof(USB_DEVICE_DESCRIPTOR);
	priv->dev_descriptor.bDescriptorType = USB_DEVICE_DESCRIPTOR_TYPE;
	dev->num_configurations = priv->dev_descriptor.bNumConfigurations = 1;
	priv->dev_descriptor.idVendor = 0x1d6b;			// Linux Foundation root hub

	// The EX query was implemented in Vista, and at the moment, we have no easy way
	// of detecting the windows version in MinGW (the _WIN32_WINNT variable is fixed)
	// Thus we try the ex query regardless and fallback to regular if it fails
	size = sizeof(USB_HUB_CAPABILITIES_EX);
	if (DeviceIoControl(handle, IOCTL_USB_GET_HUB_CAPABILITIES_EX, &hub_caps_ex, 
		size, &hub_caps_ex, size, &size, NULL)) {
		// Sanity check. HCD hub should always be root
		if (!hub_caps_ex.CapabilityFlags.HubIsRoot) {
			usbi_warn(ctx, "program assertion failed - HCD hub is not reported as root hub.");
		}
		priv->dev_descriptor.idProduct = hub_caps_ex.CapabilityFlags.HubIsHighSpeedCapable?2:1;
	} else {
		// Standard query
		size = sizeof(USB_HUB_CAPABILITIES);
		if (!DeviceIoControl(handle, IOCTL_USB_GET_HUB_CAPABILITIES_EX, &hub_caps, 
			size, &hub_caps, size, &size, NULL)) {
			usbi_warn(ctx, "could not read hub capabilities (std) for hub %s: %s", 
				priv->path, windows_error_str());
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

	USB_CONFIGURATION_DESCRIPTOR_SHORT cd_buf_short;	// dummy request
	PUSB_DESCRIPTOR_REQUEST cd_buf_actual = NULL;	// actual request
	PUSB_CONFIGURATION_DESCRIPTOR cd_data = NULL;

	// Report an error if there are no configs available
	if (dev->num_configurations == 0)
		return LIBUSB_ERROR_INVALID_PARAM;

	// Allocate the list of pointers to the descriptors
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
		cd_buf_short.req.SetupPacket.bmRequest = 0x80;
		cd_buf_short.req.SetupPacket.bRequest = USB_REQUEST_GET_DESCRIPTOR;
		cd_buf_short.req.SetupPacket.wValue = (USB_CONFIGURATION_DESCRIPTOR_TYPE << 8) | i;
		cd_buf_short.req.SetupPacket.wIndex = i;
		cd_buf_short.req.SetupPacket.wLength = (USHORT)(size - sizeof(USB_DESCRIPTOR_REQUEST));

		// Dummy call to get the required data size
		if (!DeviceIoControl(hub_handle, IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION, &cd_buf_short, size,
			&cd_buf_short, size, &ret_size, NULL)) {
			usbi_err(ctx, "could not access configuration descriptor (dummy): %s", windows_error_str());
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
		cd_buf_actual->SetupPacket.bmRequest = 0x80;
		cd_buf_actual->SetupPacket.bRequest = USB_REQUEST_GET_DESCRIPTOR;
		cd_buf_actual->SetupPacket.wValue = (USB_CONFIGURATION_DESCRIPTOR_TYPE << 8) | i;
		cd_buf_actual->SetupPacket.wIndex = i;
		cd_buf_actual->SetupPacket.wLength = (USHORT)(size - sizeof(USB_DESCRIPTOR_REQUEST));

		if (!DeviceIoControl(hub_handle, IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION, cd_buf_actual, size,
			cd_buf_actual, size, &ret_size, NULL)) {
			usbi_err(ctx, "could not access configuration descriptor (actual): %s", windows_error_str());
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
	{	// HCD root hub
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
	{	// Node
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
			// TODO: add EX info
			size = sizeof(USB_NODE_CONNECTION_INFORMATION);
			conn_info.ConnectionIndex = i;	
			if (!DeviceIoControl(hub_handle, IOCTL_USB_GET_NODE_CONNECTION_INFORMATION, &conn_info, size,
				&conn_info, size, &size, NULL)) {
				LOOP_CONTINUE("could not get node connection information: %s", windows_error_str());
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
		}

		// If this node is a hub (HCD or not), open it
		if (conn_info.DeviceIsHub) {	
			size = size_initial;
			if (!DeviceIoControl(hub_handle, getname_ioctl, &s_hubname, size, 
				&s_hubname, size, &size, NULL)) {
				LOOP_CONTINUE("could not get hub path (dummy): %s", windows_error_str());
			}

			size = is_hcd?s_hubname.u.root.ActualLength:s_hubname.u.node.ActualLength;
			if (size > size_fixed) {
				LOOP_CONTINUE("program assertion failed - hub path is too long");
			}

			// ConnectionIndex needs to be written again for the actual query
			if (!is_hcd) {
				s_hubname.u.node.ConnectionIndex = i;
			}
			if (!DeviceIoControl(hub_handle, getname_ioctl, &s_hubname, size,
				&s_hubname, size, &size, NULL)) {
				LOOP_CONTINUE("could not get hub path (actual): %s", windows_error_str());
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
				LOOP_CONTINUE("could not open hub %s: %s", path_str, windows_error_str());
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

			LOOP_CHECK(initialize_device(dev, busnum, devaddr, path_str, i, parent_dev));
			priv = __device_priv(dev);
			path_str = NULL;	// protect our path from being freed

			// Setup the cached descriptors. Note that only non HCDs can fetch descriptors
			// For HCDs, we just populate it manually
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

		// Append the device to the list of discovered devices
		discdevs = discovered_devs_append(*_discdevs, dev);
		if (!discdevs) { 
			LOOP_BREAK(LIBUSB_ERROR_NO_MEM);
		}

		*_discdevs = discdevs;

		// Finally, if device is a hub, recurse
		if (conn_info.DeviceIsHub) {
			// Find number of ports for this hub
			size =  sizeof(USB_NODE_INFORMATION);
			if (!DeviceIoControl(handle, IOCTL_USB_GET_NODE_INFORMATION, &hub_node, size,
				&hub_node, size, &size, NULL)) {
				LOOP_CONTINUE("could not retreive information for hub %s: %s", 
					priv->path, windows_error_str());
			}

			if (hub_node.NodeType != UsbHub) {
				LOOP_CONTINUE("unexpected hub type (%d) for hub %s", hub_node.NodeType, priv->path);
			}

			usbi_dbg("%d ports Hub: %s", hub_node.u.HubInformation.HubDescriptor.bNumberOfPorts, priv->path);

			// More hubs (NB: we don't really care about the value returned)
			usb_enumerate_hub(ctx, _discdevs, handle, busnum, dev, 
				hub_node.u.HubInformation.HubDescriptor.bNumberOfPorts);
		}
	}

	return r;
}

/*
 * This function retrieves and sets the paths of all non-hub devices
 * NB: No I/O with device is required during this call
 */
static int set_device_paths(struct libusb_context *ctx, struct discovered_devs *discdevs) 
{
	struct windows_device_priv *priv;
	struct windows_device_priv *parent_priv;
	char parent_path[MAX_PATH_LENGTH];
	char reg_key[MAX_KEY_LENGTH];
	char *sanitized_path = NULL;
	HDEVINFO dev_info;
	SP_DEVICE_INTERFACE_DATA dev_interface_data;
	SP_DEVICE_INTERFACE_DETAIL_DATA *dev_interface_details = NULL;
	SP_DEVINFO_DATA dev_info_data;
	DEVINST parent_devinst;
	GUID guid;
	DWORD size, reg_type;
	int	r = LIBUSB_SUCCESS;
	unsigned i, j, port_nr, hub_nr;
	bool found;

	// List all connected devices that are not a hub
	guid = GUID_DEVINTERFACE_USB_DEVICE; 
	dev_info = SetupDiGetClassDevs(&guid, NULL, NULL, (DIGCF_PRESENT | DIGCF_DEVICEINTERFACE));

	if (dev_info != INVALID_HANDLE_VALUE)
	{
		dev_interface_data.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

		for (i = 0; ; i++)	
		{
			// safe loop: free up any (unprotected) dynamic resource
			safe_free(dev_interface_details);
			safe_free(sanitized_path);

			// safe loop: end of loop condition
			guid = GUID_DEVINTERFACE_USB_DEVICE;
			if ( (SetupDiEnumDeviceInterfaces(dev_info, NULL, &guid, i, &dev_interface_data) != TRUE) 
				||(r != LIBUSB_SUCCESS) )
				break;

			// Read interface data (dummy + actual) to access the device path
			if (!SetupDiGetDeviceInterfaceDetail(dev_info, &dev_interface_data, NULL, 0, &size, NULL)) {
				// The dummy call should fail with ERROR_INSUFFICIENT_BUFFER
				if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
					LOOP_CONTINUE("could not access interface data (dummy) for device #%u, skipping: %s", 
						i, windows_error_str());
				}
			} 
			else {
				LOOP_CONTINUE("program assertion failed - http://msdn.microsoft.com/en-us/library/ms792901.aspx is wrong.");
			}

			if ((dev_interface_details = malloc(size)) == NULL) {
				usbi_err(ctx, "could not allocate interface data for device #%u. aborting.", i);
				LOOP_BREAK(LIBUSB_ERROR_NO_MEM);
			}

			dev_interface_details->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA); 
			if (!SetupDiGetDeviceInterfaceDetail(dev_info, &dev_interface_data, 
				dev_interface_details, size, &size, NULL)) {
				LOOP_CONTINUE("could not access interface data (actual) for device #%u, skipping: %s", 
					i, windows_error_str());
			}

			// Retrieve location information (port#) through the Location Information registry data
			dev_info_data.cbSize = sizeof(dev_info_data);
			if (!SetupDiEnumDeviceInfo(dev_info, i, &dev_info_data)) {
				LOOP_CONTINUE("could not retrieve info data for device #%u, skipping: %s", 
					i, windows_error_str());
			}

			if(!SetupDiGetDeviceRegistryProperty(dev_info, &dev_info_data, SPDRP_LOCATION_INFORMATION, 
				&reg_type, (BYTE*)reg_key, MAX_KEY_LENGTH, &size)) {
				LOOP_CONTINUE("could not retrieve location information for device #%u, skipping: %s", 
					i, windows_error_str());
			}

			if (size != sizeof("Port_#1234.Hub_#1234")) {
				LOOP_CONTINUE("unexpected registry key size for device #%u, skipping", i);
			}
			if (sscanf(reg_key, "Port_#%04d.Hub_#%04d", &port_nr, &hub_nr) != 2) {
				LOOP_CONTINUE("failure to read port and hub number for device #%u, skipping", i);
			}

			// Retrieve parent's path using PnP Configuration Manager (CM)
			if (CM_Get_Parent(&parent_devinst, dev_info_data.DevInst, 0) != CR_SUCCESS) {
				LOOP_CONTINUE("could not retrieve parent info data for device #%u, skipping: %s", 
					i, windows_error_str());
			}
			
			if (CM_Get_Device_ID(parent_devinst, parent_path, MAX_PATH_LENGTH, 0) != CR_SUCCESS) {
				LOOP_CONTINUE("could not retrieve parent's path for device #%u, skipping: %s", 
					i, windows_error_str());
			}

			// Fix parent's path inconsistancies before attempting to compare
			sanitized_path = sanitize_path(parent_path);
			if (sanitized_path == NULL) {
				LOOP_CONTINUE("could not sanitize parent's path for device #%u, skipping.", i);
			}

			// With the parent path and port number, we should be able to locate our device 
			// by comparing these values to the ones we got when enumerating hubs
			found = false;
			for (j=0; j<discdevs->len; j++) {
				priv = __device_priv(discdevs->devices[j]);
				// ignore HCDs
				if (priv->parent_dev == NULL) {
					continue;
				}
				parent_priv = __device_priv(priv->parent_dev);
				if ( (safe_strncmp(parent_priv->path, sanitized_path, strlen(sanitized_path)) == 0) &&
					 (port_nr == priv->connection_index) ) {
					priv->path = sanitize_path(dev_interface_details->DevicePath);
					usbi_dbg("path (%d:%d): %s", discdevs->devices[j]->bus_number, 
						discdevs->devices[j]->device_address, priv->path);
					found = true;
					break;
				}
			}
			if (!found) {
				LOOP_CONTINUE("could not match %s with a libusb device.", dev_interface_details->DevicePath);
			}
		}
		SetupDiDestroyDeviceInfoList(dev_info);
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

	// We use the index of the HCD in the chained list as bus #
	for (hcd = hcd_root, bus = 0; ; hcd = hcd->next, bus++)
	{
		safe_closehandle(handle);

		if ( (hcd == NULL) || (r != LIBUSB_SUCCESS) )
			break;

		// Shouldn't be needed, but let's be safe
		if (bus == LIBUSB_BUS_MAX) {
			LOOP_CONTINUE("program assertion failed - got more than %d buses, skipping the rest.", LIBUSB_BUS_MAX);
		}

		handle = CreateFileA(hcd->path, GENERIC_WRITE, FILE_SHARE_WRITE,
			NULL, OPEN_EXISTING, FILE_FLAG_POSIX_SEMANTICS|FILE_FLAG_OVERLAPPED, NULL);
		if (handle == INVALID_HANDLE_VALUE) {
			LOOP_CONTINUE("could not open bus %u, skipping: %s", bus, windows_error_str());
		}

		LOOP_CHECK(usb_enumerate_hub(ctx, _discdevs, handle, bus, NULL, 1));
	}

	// Non hub device paths are set using a separate method
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

	//TODO: Thread stuff
}

static int windows_get_device_descriptor(struct libusb_device *dev, unsigned char *buffer, int *host_endian)
{
	struct windows_device_priv *priv = __device_priv(dev);

	// return cached copy
	memmove(buffer, &(priv->dev_descriptor), DEVICE_DESC_LENGTH);
	*host_endian = 0;

	return LIBUSB_SUCCESS;
}

/*
 * return the cached copy of the relevant config descriptor
 */
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
 * Retrieve the bConfigurationValue for the active configuration for a device.
 * This is meant to be called during init so that the value can be cached
 */
static int windows_get_active_config(struct libusb_device *dev)
{
	// TODO: As we don't have control msg I/O yet, force the value to first conf.
	return 1;
}

/*
 * return the cached copy of the active config descriptor
 */
static int windows_get_active_config_descriptor(struct libusb_device *dev, unsigned char *buffer, size_t len, int *host_endian)
{
	struct windows_device_priv *priv = __device_priv(dev);

	// Has active config been set yet
	if (priv->active_config == 0)
		return LIBUSB_ERROR_NOT_FOUND;

	// config indexes for get_config_descriptors start at zero
	return windows_get_config_descriptor(dev, priv->active_config-1, buffer, len, host_endian);
}

static int windows_open(struct libusb_device_handle *dev_handle)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static void windows_close(struct libusb_device_handle *dev_handle)
{
}

/*
 * Get the bConfigurationValue for the active configuration for a device.
 */
static int windows_get_configuration(struct libusb_device_handle *dev_handle, int *config)
{
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);

	*config = priv->active_config;
	return LIBUSB_SUCCESS;
}

static int windows_set_configuration(struct libusb_device_handle *dev_handle, int config)
{
	/* 
	 * from http://msdn.microsoft.com/en-us/library/ms793522.aspx: The port driver 
	 * does not currently expose a service that allows higher-level drivers to set 
	 * the configuration.
	 * TODO: See if this is achievable with kernel drivers
	 */
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int windows_claim_interface(struct libusb_device_handle *dev_handle, int iface)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int windows_release_interface(struct libusb_device_handle *dev_handle, int iface)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int windows_set_interface_altsetting(struct libusb_device_handle *dev_handle, int iface, int altsetting)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int windows_clear_halt(struct libusb_device_handle *dev_handle, unsigned char endpoint)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int windows_reset_device(struct libusb_device_handle *dev_handle)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int windows_kernel_driver_active(struct libusb_device_handle *dev_handle, int iface)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

/* attaching/detaching kernel drivers is not currently supported (maybe in the future?) */
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

static int submit_bulk_transfer(struct usbi_transfer *itransfer)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int submit_iso_transfer(struct usbi_transfer *itransfer)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int submit_control_transfer(struct usbi_transfer *itransfer)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
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

static int cancel_control_transfer(struct usbi_transfer *itransfer)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int windows_abort_transfers (struct usbi_transfer *itransfer)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int windows_cancel_transfer(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = __USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);

	switch (transfer->type) {
	case LIBUSB_TRANSFER_TYPE_CONTROL:
		return cancel_control_transfer(itransfer);
	case LIBUSB_TRANSFER_TYPE_BULK:
	case LIBUSB_TRANSFER_TYPE_INTERRUPT:
	case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS:
		return windows_abort_transfers(itransfer);
	default:
		usbi_err(TRANSFER_CTX(transfer), "unknown endpoint type %d", transfer->type);
		return LIBUSB_ERROR_INVALID_PARAM;
	}
}

static void windows_clear_transfer_priv(struct usbi_transfer *itransfer)
{
}

static int windows_handle_events(struct libusb_context *ctx, struct pollfd *fds, nfds_t nfds, int num_ready)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
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
		if (hires_frequency != 0) {
			if (QueryPerformanceCounter(&hires_counter) == 0)
				return LIBUSB_ERROR_IO;
			tp->tv_sec = hires_counter.QuadPart / hires_frequency;
			tp->tv_nsec = (hires_counter.QuadPart % hires_frequency) / hires_frequency_ns;
			return LIBUSB_SUCCESS;
		}	
		// make sure we fall through to real-time if no hires timer is present
	case USBI_CLOCK_REALTIME:
		// To get a 100ns resolution time value with real time, we follow 
		// http://msdn.microsoft.com/en-us/library/ms724928%28VS.85%29.aspx
		// with a predef epoch_time to have an epoch that starts at 1970.01.01 00:00
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
