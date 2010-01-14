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
// TODO: fix this. prevents an annoying warning for now
#ifdef PTW32_DLLPORT
#undef PTW32_DLLPORT
#endif
#include <pthread.h>
#include <stdio.h>
#include <windows.h>
#include <tchar.h>
#include <setupapi.h>
#include <ddk/usbiodef.h>
#include <ddk/usbioctl.h>
#include <largeint.h>

#include "libusbi.h"
#include "windows_compat.h"
#include "windows_usb.h"

// The 3 macros below are used in conjunction with safe loops.
#define LOOP_CHECK(fcall) { r=fcall; if (r != LIBUSB_SUCCESS) continue; }
#define LOOP_CONTINUE(...) { usbi_warn(ctx, __VA_ARGS__); continue; }
#define LOOP_BREAK(err) { r=err; continue; } 

/*
 * globals
 */


// async event thread
// static pthread_t libusb_windows_at;

// root and last HCD pointer
struct windows_hcd_priv* _hcd_root = NULL;

// timers
uint64_t hires_frequency, hires_frequency_ns;
// 1970.01.01 00:00:000 in MS Filetime, as computed and confirmed with google
const uint64_t epoch_time = 116444736000000000;

/*
 * Helper functions
 *
 * TODO: Move elsewhere
 */


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


#define ERR_BUFFER_SIZE	256
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
 * init: libusb backend init function
 *
 * This function enumerates the HCDs (Host Controller Drivers) and populates our private HCD list
 * In our implementation, we equate Windows' "HCD" to LibUSB's "bus". Note that bus is zero indexed.
 * HCDs are not expected to change after init (might not hold true for hot pluggable USB PCI card?)
 *
 * This function must return a LIBUSB code
 *
 */
static int windows_init(struct libusb_context *ctx)
{
	HANDLE handle = INVALID_HANDLE_VALUE;
	HDEVINFO dev_info;
	SP_DEVICE_INTERFACE_DATA dev_interface_data;
	SP_DEVICE_INTERFACE_DETAIL_DATA *_dev_interface_details = NULL;
	USB_HCD_DRIVERKEY_NAME_FIXED driverkey_name;
	GUID guid;
	DWORD size;
	libusb_bus_t bus;
	int r = LIBUSB_SUCCESS;
	LARGE_INTEGER li_frequency;

	// If our HCD list is populated, we don't need to re-init
	if (_hcd_root != NULL) {
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
	struct windows_hcd_priv** __hcd_cur = &_hcd_root;

	// For readability
	#define _hcd_cur (*__hcd_cur)

	guid = GUID_DEVINTERFACE_USB_HOST_CONTROLLER;
	dev_info = SetupDiGetClassDevs(&guid, NULL, NULL, (DIGCF_PRESENT | DIGCF_DEVICEINTERFACE));

	if (dev_info != INVALID_HANDLE_VALUE)
	{
		dev_interface_data.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

		guid = GUID_CLASS_USB_HOST_CONTROLLER;
		for (bus = 0; ; bus++)
		{
			// safe loop: free up any (unprotected) dynamic resource
			// NB: this is always executed before breaking the loop
			safe_closehandle(handle);
			safe_free(_dev_interface_details);
			safe_free(_hcd_cur);

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
			else
				LOOP_CONTINUE("program assertion failed - http://msdn.microsoft.com/en-us/library/ms792901.aspx is wrong.");

			if ((_dev_interface_details = malloc(size)) == NULL) {
				usbi_err(ctx, "could not allocate interface data for bus %u. aborting.", bus);
				LOOP_BREAK(LIBUSB_ERROR_NO_MEM);
			}

			_dev_interface_details->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
			// Actual call.
			if (!SetupDiGetDeviceInterfaceDetail(dev_info, &dev_interface_data,
				_dev_interface_details, size, &size, NULL)) {
				LOOP_CONTINUE("could not access interface data for bus %u, skipping: %s",
					bus, windows_error_str());
			}

			handle = CreateFileA(_dev_interface_details->DevicePath, GENERIC_WRITE, FILE_SHARE_WRITE,
				NULL, OPEN_EXISTING, FILE_FLAG_POSIX_SEMANTICS|FILE_FLAG_OVERLAPPED, NULL);
			if(handle == INVALID_HANDLE_VALUE) {
				LOOP_CONTINUE("could not open bus %u, skipping: %s", bus, windows_error_str());
			}

//			usbi_dbg("Found Hcd: %s", _dev_interface_details->DevicePath);

			// Allocate and init a new priv structure to hold our data
			if ((_hcd_cur = malloc(sizeof(struct windows_hcd_priv))) == NULL) {
				usbi_err(ctx, "could not allocate private structure for bus %u. aborting.", bus);
				LOOP_BREAK(LIBUSB_ERROR_NO_MEM);
			}
			windows_hcd_priv_init(_hcd_cur);
			_hcd_cur->path = safe_strdup(_dev_interface_details->DevicePath);

			// get the Driverkey name for this HDC
			if (!DeviceIoControl(handle, IOCTL_GET_HCD_DRIVERKEY_NAME, &driverkey_name, sizeof(USB_HCD_DRIVERKEY_NAME),
				&driverkey_name, sizeof(USB_HCD_DRIVERKEY_NAME), &size, NULL)) {
				LOOP_CONTINUE("could not access DriverKey name (dummy) for bus %u, skipping: %s",
					bus, windows_error_str());
			}

			if ((size = driverkey_name.ActualLength) > (USB_HCD_DRIVERKEY_NAME_FIXED_MAX*sizeof(WCHAR))) {
				LOOP_CONTINUE("DriverKey name too long for bus %d (%d), skipping.", size, bus);
			}

			if (!DeviceIoControl(handle, IOCTL_GET_HCD_DRIVERKEY_NAME, &driverkey_name, size,
				&driverkey_name, size, &size, NULL)) {
				LOOP_CONTINUE("could not access DriverKey name (actual) for bus %u, skipping: %s",
					bus, windows_error_str());
			}

			// Convert DriverKey name to something we can handle
			_hcd_cur->name = wchar_to_utf8(driverkey_name.DriverKeyName);
			if (_hcd_cur == NULL) {
				LOOP_CONTINUE("Could not convert DriverKey Name for bus %u. skipping.", bus);
			}
//			usbi_dbg("Got driverkey: %s", _hcd_cur->name);

			// Setup new chained list node as current
			_hcd_cur->handle = handle;			// Keep a copy of the HCD file handle
			handle = INVALID_HANDLE_VALUE;		// Prevents the CloseHandle() call at the beginning of loop
			__hcd_cur = &(_hcd_cur->next);
		}
	}

	// TODO: SetupDiDestroyDeviceInfoList(dev_info);
	// TODO: pthread stuff
/*
	pthread_create(&libusb_windows_at, NULL, event_thread_main, (void *)ctx);

	while (!libusb_windows_acfl)
		usleep (10);
*/
	// nonzero on error

	return (_hcd_root == NULL)?LIBUSB_ERROR_NO_DEVICE:LIBUSB_SUCCESS;
	#undef _hcd_cur
}


static int initialize_device(struct libusb_device *dev, libusb_bus_t busnum,
	libusb_devaddr_t devaddr, const char *path_or_something)
{

	struct windows_device_priv *priv = __device_priv(dev);
/*	unsigned char *dev_buf;
	char path[PATH_MAX];
	int fd;
	int active_config = 0;
	int device_configured = 1;
	ssize_t r;
*/
	// Empty struct
	windows_device_priv_init(priv);
	dev->bus_number = busnum;
	dev->device_address = devaddr;

/*
	if (sysfs_dir) {
		priv->sysfs_dir = malloc(strlen(sysfs_dir) + 1);
		if (!priv->sysfs_dir)
			return LIBUSB_ERROR_NO_MEM;
		strcpy(priv->sysfs_dir, sysfs_dir);
	}

	if (sysfs_has_descriptors)
		return 0;

	// cache device descriptor in memory so that we can retrieve it later
	// without waking the device up (op_get_device_descriptor)

	priv->dev_descriptor = NULL;
	priv->config_descriptor = NULL;

	if (sysfs_can_relate_devices) {
		int tmp = sysfs_get_active_config(dev, &active_config);
		if (tmp < 0)
			return tmp;
		if (active_config == -1)
			device_configured = 0;
	}

	__get_usbfs_path(dev, path);
	fd = open(path, O_RDWR);
	if (fd < 0 && errno == EACCES) {
		fd = open(path, O_RDONLY);
		// if we only have read-only access to the device, we cannot
		// send a control message to determine the active config. just
		// assume the first one is active.
		active_config = -1;
	}

	if (fd < 0) {
		usbi_err(DEVICE_CTX(dev), "open failed, ret=%d errno=%d", fd, errno);
		return LIBUSB_ERROR_IO;
	}

	if (!sysfs_can_relate_devices) {
		if (active_config == -1) {
			// if we only have read-only access to the device, we cannot
			// send a control message to determine the active config. just
			// assume the first one is active.
			usbi_warn(DEVICE_CTX(dev), "access to %s is read-only; cannot "
				"determine active configuration descriptor", path);
		} else {
			active_config = usbfs_get_active_config(dev, fd);
			if (active_config < 0) {
				close(fd);
				return active_config;
			} else if (active_config == 0) {
				// some buggy devices have a configuration 0, but we're
				// reaching into the corner of a corner case here, so let's
				// not support buggy devices in these circumstances.
				// stick to the specs: a configuration value of 0 means
				// unconfigured.
				usbi_dbg("assuming unconfigured device");
				device_configured = 0;
			}
		}
	}

	dev_buf = malloc(DEVICE_DESC_LENGTH);
	if (!dev_buf) {
		close(fd);
		return LIBUSB_ERROR_NO_MEM;
	}

	r = read(fd, dev_buf, DEVICE_DESC_LENGTH);
	if (r < 0) {
		usbi_err(DEVICE_CTX(dev),
			"read descriptor failed ret=%d errno=%d", fd, errno);
		free(dev_buf);
		close(fd);
		return LIBUSB_ERROR_IO;
	} else if (r < DEVICE_DESC_LENGTH) {
		usbi_err(DEVICE_CTX(dev), "short descriptor read (%d)", r);
		free(dev_buf);
		close(fd);
		return LIBUSB_ERROR_IO;
	}

	// bit of a hack: set num_configurations now because cache_active_config()
	// calls usbi_get_config_index_by_value() which uses it
	dev->num_configurations = dev_buf[DEVICE_DESC_LENGTH - 1];

	if (device_configured) {
		r = cache_active_config(dev, fd, active_config);
		if (r < 0) {
			close(fd);
			free(dev_buf);
			return r;
		}
	}

	close(fd);
	priv->dev_descriptor = dev_buf;
*/
	return LIBUSB_SUCCESS;
}

static int read_device_descriptor(struct libusb_context *ctx,
	struct libusb_device *dev, HANDLE hub_handle, ULONG connection_index,
	UCHAR descriptor_index)
{
	DWORD size, ret_size;
	struct windows_device_priv *priv = __device_priv(dev);

	USB_DEVICE_DESCRIPTOR_BUFFER dd_buf;
	size = sizeof(dd_buf);
	memset(&dd_buf, 0, size);

	dd_buf.req.ConnectionIndex = connection_index;
	dd_buf.req.SetupPacket.bmRequest = 0x80;
	dd_buf.req.SetupPacket.bRequest = USB_REQUEST_GET_DESCRIPTOR;
//	cd_buf.rew.SetupPacket.wValue = (USB_CONFIGURATION_DESCRIPTOR_TYPE << 8) | descriptor_index;
	dd_buf.req.SetupPacket.wValue = (USB_DEVICE_DESCRIPTOR_TYPE << 8) | descriptor_index;
//	cd_buf.req.SetupPacket.wIndex = descriptor_lang;	// USHORT
	dd_buf.req.SetupPacket.wLength = (USHORT)(size - sizeof(USB_DESCRIPTOR_REQUEST));

	// read the device descriptor
	if (!DeviceIoControl(hub_handle, IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION, &dd_buf, size,
		&dd_buf, size, &ret_size, NULL)) {
		usbi_warn(ctx, "could not read device descriptor: %s", windows_error_str());
		return LIBUSB_ERROR_IO;
	}

	if ((ret_size != size) ||
		(dd_buf.data.bLength < sizeof(USB_DEVICE_DESCRIPTOR)) ||
		(DEVICE_DESC_LENGTH != sizeof(USB_DEVICE_DESCRIPTOR))) {
		usbi_warn(ctx, "unexpected device descriptor size.");
		return LIBUSB_ERROR_IO;
	}

	memmove(&(priv->dev_descriptor), &(dd_buf.data), DEVICE_DESC_LENGTH);
//	usbi_dbg("ID: %04x:%04x", priv->dev_descriptor.idVendor, priv->dev_descriptor.idProduct);

	return LIBUSB_SUCCESS;
}

static int set_hcd_device_descriptor(struct libusb_context *ctx, struct libusb_device *dev)
{
 	struct windows_device_priv *priv = __device_priv(dev);

	// TODO: fill in more blanks and call IOCTL_USB_GET_HUB_CAPABILITIES from here?
	priv->dev_descriptor.bLength = sizeof(USB_DEVICE_DESCRIPTOR);
	priv->dev_descriptor.bDescriptorType = USB_DEVICE_DESCRIPTOR_TYPE;
	priv->dev_descriptor.idVendor = 0x1d6b;
	priv->dev_descriptor.idProduct = 1;
}

/*
 * Recursively enumerates and find all hubs
 *
 * hub_dev: HANDLE of the Hub to be enumerated
 * parent_privv: pointer to the parent hub priv struct, or NULL is parent is an HCD
 */
static int usb_enumerate_hub(struct libusb_context *ctx,
	struct discovered_devs **_discdevs, HANDLE hub_handle,
	libusb_bus_t busnum, struct windows_device_priv* parent_priv)
{
	struct discovered_devs *discdevs = *_discdevs;
	struct libusb_device *dev = NULL;
	DWORD size, size_initial, size_fixed, getname_ioctl;
	HANDLE handle = INVALID_HANDLE_VALUE;
	USB_HUB_NAME_FIXED s_hubname;
	USB_NODE_CONNECTION_INFORMATION conn_info;
	USB_NODE_INFORMATION hub_node;
	USB_HUB_CAPABILITIES hub_caps;
#if (_WIN32_WINNT >= 0x0600)
#error If you see this, then MinGW is great!
	USB_HUB_CAPABILITIES_EX hub_caps_ex;
#endif
	bool is_hcd, has_hub_caps_ex;	
	int i, r;
	LPCWSTR wstr;
	char *tmp_str = NULL, *tmp_str2 = NULL;
	uint8_t nb_ports;
	unsigned long session_id;
	libusb_devaddr_t devaddr = 0;
	struct windows_device_priv *priv;

	is_hcd = (parent_priv == NULL);
	if (is_hcd)
	{	// HCD root hub
		nb_ports = 1;
		size_initial = sizeof(USB_ROOT_HUB_NAME);
		size_fixed = sizeof(USB_ROOT_HUB_NAME_FIXED);
		getname_ioctl = IOCTL_USB_GET_ROOT_HUB_NAME;
	}
	else
	{	// Node Hub
		nb_ports = parent_priv->nb_ports;
		size_initial = sizeof(USB_NODE_CONNECTION_NAME);
		size_fixed = sizeof(USB_NODE_CONNECTION_NAME_FIXED);
		getname_ioctl = IOCTL_USB_GET_NODE_CONNECTION_NAME;
	}

	// Loop through all the ports
	for (i=1, r = LIBUSB_SUCCESS; ; i++)
	{
		// safe loop: release all dynamic resources
		safe_unref_device(dev);
		safe_free(tmp_str);
		safe_free(tmp_str2);
		safe_closehandle(handle);

		// safe loop: end of loop condition
		if ((i > nb_ports) || (r != LIBUSB_SUCCESS))
			break;

		// For non HCD nodes, check if we have a hub or a regular device
		if (!is_hcd)
		{
			// TODO: add EX info
			size = sizeof(USB_NODE_CONNECTION_INFORMATION);
			conn_info.ConnectionIndex = i;	
			if (!DeviceIoControl(hub_handle, IOCTL_USB_GET_NODE_CONNECTION_INFORMATION, &conn_info, size,
				&conn_info, size, &size, NULL)) {
				LOOP_CONTINUE("could not get node connection information: %s", windows_error_str());
			}

			if (conn_info.ConnectionStatus == NoDeviceConnected) {
//				usbi_dbg("No device is connected on port %d.", i);
				continue;
			}

			if (conn_info.DeviceAddress == 0) {
				LOOP_CONTINUE("program assertion failed - device address is zero "
					"(conflicts with HCD), ignoring device");
			}

			s_hubname.u.node.ConnectionIndex = i;
		}
		else
		{	// HCDs have 1 node, and it's a hub
			conn_info.DeviceAddress = 0;
			conn_info.DeviceIsHub = true;
		}

		// Allocate device

		// Will need to change the session_id computation if this assertion fails
		if (conn_info.DeviceAddress > LIBUSB_DEVADDR_MAX) {
			LOOP_CONTINUE("program assertion failed - device address is greater than 255, ignoring device");
		} else {
			devaddr = conn_info.DeviceAddress;
		}

		// Same trick as linux for session_id, with same caveat
		session_id = busnum << (sizeof(libusb_devaddr_t)*8) | devaddr;
		usbi_dbg("busnum %d devaddr %d session_id %ld", busnum, devaddr, session_id);

		dev = usbi_get_device_by_session_id(ctx, session_id);

		if (dev) {
			usbi_dbg("using existing device for session %ld", session_id);
		} else {
			usbi_dbg("allocating new device for session %ld", session_id);
			if ((dev = usbi_alloc_device(ctx, session_id)) == NULL) {
				LOOP_BREAK(LIBUSB_ERROR_NO_MEM);
			}

			LOOP_CHECK(initialize_device(dev, busnum, devaddr, "whatever"));

			if (!is_hcd) {
				// Only non HCD hubs have a configuration descriptor
				LOOP_CHECK(read_device_descriptor(ctx, dev, hub_handle, i, 0));
			} else {
				// So we manually setup HCDs as a result
				LOOP_CHECK(set_hcd_device_descriptor(ctx, dev));
			}

			// TODO: set conf so that sanitize is happy?
//			LOOP_CHECK(usbi_sanitize_device(dev));
		}

		// Append the device to the list of discovered devices
		discdevs = discovered_devs_append(*_discdevs, dev);
		if (!discdevs) {
			LOOP_BREAK(LIBUSB_ERROR_NO_MEM);
		}

		*_discdevs = discdevs;

		// Not a hub => ignore
		if (!conn_info.DeviceIsHub)	{
			usbi_dbg("device on port %d not a hub", i);
			continue;
		}

		// At this stage, we are dealing with a hub
		size = size_initial;
		if (!DeviceIoControl(hub_handle, getname_ioctl, &s_hubname, size,
			&s_hubname, size, &size, NULL)) {
			LOOP_CONTINUE("could not get hub path (dummy): %s", windows_error_str());
		}

		size = is_hcd?s_hubname.u.root.ActualLength:s_hubname.u.node.ActualLength;
		if (size > size_fixed) {
			LOOP_CONTINUE("program assertion failed - hub path is too long");
		}

		// ConnectionIndex needs to be re-initialized for nodes
		if (!is_hcd)
			s_hubname.u.node.ConnectionIndex = i;
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
		size = strlen(tmp_str) + sizeof(ROOT_PREFIX);

		if ((tmp_str2 = malloc(size)) == NULL) {
			usbi_err(ctx, "could not allocate string for hub path.");
			LOOP_BREAK(LIBUSB_ERROR_NO_MEM);
		}

		// Buffer overflows shouldn't happen on system strings, but still...
		safe_strncpy(tmp_str2, size, ROOT_PREFIX, sizeof(ROOT_PREFIX));
		safe_strncat(tmp_str2, size, tmp_str, strlen(tmp_str));

		// Populate hub private data
		priv = __device_priv(dev);
		// Session IDs are supposed to prevent the need for this
		if (priv->path != NULL)
			free(priv->path);
		priv->path = tmp_str2;
		tmp_str2 = NULL;	// protect our path from being freed

		// Open Hub
		handle = CreateFileA(priv->path, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
			FILE_FLAG_POSIX_SEMANTICS|FILE_FLAG_OVERLAPPED, NULL);
		if(handle == INVALID_HANDLE_VALUE) {
			LOOP_CONTINUE("could not open hub %s: %s", priv->path, windows_error_str());
		}
		priv->handle = handle;
		handle = INVALID_HANDLE_VALUE;	// protect our handle from closure

		// Get Hub capabilities as reported by Windows (needed to fill in the "fake" HCD
		// hub device descriptor)
		has_hub_caps_ex = false;

		// The EX query was implemented in Vista
		// TODO: drop the broken version detection and try EX regardless
#if (_WIN32_WINNT >= 0x0600)
		size = sizeof(USB_HUB_CAPABILITIES_EX);
		if (!DeviceIoControl(priv->handle, IOCTL_USB_GET_HUB_CAPABILITIES_EX, &hub_caps_ex,
			size, &hub_caps_ex, size, &size, NULL)) {
			LOOP_CONTINUE("could not read hub capabilities (ex) for hub %s: %s",
				priv->path, windows_error_str());
		}
		has_hub_caps_ex = true;
#endif
		// Standard query
		size = sizeof(USB_HUB_CAPABILITIES);
		if (!DeviceIoControl(priv->handle, IOCTL_USB_GET_HUB_CAPABILITIES_EX, &hub_caps,
			size, &hub_caps, size, &size, NULL)) {
			LOOP_CONTINUE("could not read hub capabilities (std) for hub %s: %s",
				priv->path, windows_error_str());
		}

		if (is_hcd)
			priv->dev_descriptor.idProduct = (hub_caps.HubIs2xCapable)?2:1;

		// Find number of ports for this hub
		size = sizeof(USB_NODE_INFORMATION);
		if (!DeviceIoControl(priv->handle, IOCTL_USB_GET_NODE_INFORMATION, &hub_node, size,
			&hub_node, size, &size, NULL)) {
			LOOP_CONTINUE("could not retreive information for hub %s: %s",
				priv->path, windows_error_str());
		}

		if (hub_node.NodeType != UsbHub) {
			LOOP_CONTINUE("unexpected hub type (%d) for hub %s", hub_node.NodeType, priv->path);
		}

		priv->nb_ports = hub_node.u.HubInformation.HubDescriptor.bNumberOfPorts;
		usbi_dbg("%d ports Hub: %s", priv->nb_ports, priv->path);

		// More hubs
		usb_enumerate_hub(ctx, _discdevs, priv->handle, busnum, priv);
	}

	return r;
}

/*
 * get_device_list: libusb backend device enumeration function
 *
 *
 */
static int windows_get_device_list(struct libusb_context *ctx, struct discovered_devs **_discdevs)
{
	struct windows_hcd_priv* _hcd;	
	int r = LIBUSB_SUCCESS;
	libusb_bus_t bus;

	// We use the index of the HCD in the chained list as bus #
	for (_hcd = _hcd_root, bus = 0; _hcd != NULL; _hcd = _hcd->next, bus++)
	{
		// Shouldn't be needed, but let's be safe
		if (bus == LIBUSB_BUS_MAX) {
			LOOP_CONTINUE("program assertion failed - got more than %d buses, skipping the rest.", LIBUSB_BUS_MAX);
		}

		usbi_dbg("Enumerating bus %u", bus);
		LOOP_CHECK(usb_enumerate_hub(ctx, _discdevs, _hcd->handle, bus, NULL));
	}

	return r;
}

/*
 * exit: libusb backend deinitialization function
 *
 */
static void windows_exit(void)
{
	struct windows_hcd_priv* _hcd_tmp;	

	while (_hcd_root != NULL)
	{
//		usbi_dbg("freeing HCD %s", _hcd_root->path);
		_hcd_tmp = _hcd_root;	// Keep a copy for free
		_hcd_root = _hcd_root->next;
		windows_hcd_priv_release(_hcd_tmp);
		safe_free(_hcd_tmp);
	}

	//TODO: Thread stuff
/*
	// stop the async runloop
	CFRunLoopStop(libusb_windows_acfl);
	pthread_join(libusb_windows_at, &ret);

	if (libusb_windows_mp)
		mach_port_deallocate(mach_task_self(), libusb_windows_mp);

	libusb_windows_mp = 0;
*/
}

static int windows_get_device_descriptor(struct libusb_device *dev, unsigned char *buffer, int *host_endian)
{
	struct windows_device_priv *priv = __device_priv(dev);

	// return cached copy
	memmove(buffer, &(priv->dev_descriptor), DEVICE_DESC_LENGTH);
	*host_endian = 0;

	return LIBUSB_SUCCESS;
}

static int windows_get_active_config_descriptor(struct libusb_device *dev, unsigned char *buffer, size_t len, int *host_endian)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int windows_get_config_descriptor(struct libusb_device *dev, uint8_t config_index, unsigned char *buffer, size_t len, int *host_endian)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int windows_open(struct libusb_device_handle *dev_handle)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static void windows_close(struct libusb_device_handle *dev_handle)
{
}

static int windows_get_configuration(struct libusb_device_handle *dev_handle, int *config)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int windows_set_configuration(struct libusb_device_handle *dev_handle, int config)
{
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
//	usbi_dbg("destroying dev %d", dev->session_data);
	windows_device_priv_release(priv);
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

static int op_handle_events(struct libusb_context *ctx, struct pollfd *fds, nfds_t nfds, int num_ready)
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

	.handle_events = op_handle_events,

	.clock_gettime = windows_clock_gettime,

	.device_priv_size = sizeof(struct windows_device_priv),
	.device_handle_priv_size = sizeof(struct windows_device_handle_priv),
	.transfer_priv_size = sizeof(struct windows_transfer_priv),
	.add_iso_packet_size = 0,
};
