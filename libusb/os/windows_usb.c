/*
 * windows backend for libusb 1.0
 * Copyright (c) 2009-2010 Pete Batard <pbatard@gmail.com>
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

// COMPILATION OPTIONS:
// - Should libusb automatically claim (and release) the interfaces it requires?
#define AUTO_CLAIM
// - Forces instant overlapped completion on timeouts: can prevents extensive
//   wait in poll, after a timeout, but might affect subsequent API calls.
//   ***USE AT YOUR OWN RISKS***
//#define FORCE_INSTANT_TIMEOUTS

#include <config.h>
#include <windows.h>
#include <setupapi.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <process.h>
#include <stdio.h>
#include <inttypes.h>
#include <objbase.h>
#include <winioctl.h>

#include <libusbi.h>
#include "poll_windows.h"
#include "windows_usb.h"

// The following prevents "banned API" errors when using the MS's WDK OACR/Prefast
#if defined(_PREFAST_)
#pragma warning(disable:28719)
#endif

// The 2 macros below are used in conjunction with safe loops.
#define LOOP_CHECK(fcall) { r=fcall; if (r != LIBUSB_SUCCESS) continue; }
#define LOOP_BREAK(err) { r=err; continue; }

extern void usbi_fd_notification(struct libusb_context *ctx);

// Helper prototypes
static int windows_get_active_config_descriptor(struct libusb_device *dev, unsigned char *buffer, size_t len, int *host_endian);
static int windows_clock_gettime(int clk_id, struct timespec *tp);
unsigned __stdcall windows_clock_gettime_threaded(void* param);
// WinUSB API prototypes
static int winusb_init(struct libusb_context *ctx);
static int winusb_exit(void);
static int winusb_open(struct libusb_device_handle *dev_handle);
static void winusb_close(struct libusb_device_handle *dev_handle);
static int winusb_claim_interface(struct libusb_device_handle *dev_handle, int iface);
static int winusb_release_interface(struct libusb_device_handle *dev_handle, int iface);
static int winusb_submit_control_transfer(struct usbi_transfer *itransfer);
static int winusb_set_interface_altsetting(struct libusb_device_handle *dev_handle, int iface, int altsetting);
static int winusb_submit_bulk_transfer(struct usbi_transfer *itransfer);
static int winusb_clear_halt(struct libusb_device_handle *dev_handle, unsigned char endpoint);
static int winusb_abort_transfers(struct usbi_transfer *itransfer);
static int winusb_abort_control(struct usbi_transfer *itransfer);
static int winusb_reset_device(struct libusb_device_handle *dev_handle);
static int winusb_copy_transfer_data(struct usbi_transfer *itransfer, uint32_t io_size);
// Composite API prototypes
static int composite_init(struct libusb_context *ctx);
static int composite_exit(void);
static int composite_open(struct libusb_device_handle *dev_handle);
static void composite_close(struct libusb_device_handle *dev_handle);
static int composite_claim_interface(struct libusb_device_handle *dev_handle, int iface);
static int composite_set_interface_altsetting(struct libusb_device_handle *dev_handle, int iface, int altsetting);
static int composite_release_interface(struct libusb_device_handle *dev_handle, int iface);
static int composite_submit_control_transfer(struct usbi_transfer *itransfer);
static int composite_submit_bulk_transfer(struct usbi_transfer *itransfer);
static int composite_submit_iso_transfer(struct usbi_transfer *itransfer);
static int composite_clear_halt(struct libusb_device_handle *dev_handle, unsigned char endpoint);
static int composite_abort_transfers(struct usbi_transfer *itransfer);
static int composite_abort_control(struct usbi_transfer *itransfer);
static int composite_reset_device(struct libusb_device_handle *dev_handle);
static int composite_copy_transfer_data(struct usbi_transfer *itransfer, uint32_t io_size);


// Global variables
struct windows_hcd_priv* hcd_root = NULL;
uint64_t hires_frequency, hires_ticks_to_ps;
const uint64_t epoch_time = UINT64_C(116444736000000000);	// 1970.01.01 00:00:000 in MS Filetime
enum windows_version windows_version = WINDOWS_UNSUPPORTED;
// Concurrency
static int concurrent_usage = -1;
#if defined(AUTO_CLAIM)
usbi_mutex_t autoclaim_lock;
#endif
// Timer thread
// NB: index 0 is for monotonic and 1 is for the thread exit event
HANDLE timer_thread = NULL;
HANDLE timer_mutex = NULL;
struct timespec timer_tp;
volatile LONG request_count[2] = {0, 1};	// last one must be > 0
HANDLE timer_request[2] = { NULL, NULL };
HANDLE timer_response = NULL;
// API globals
bool api_winusb_available = false;
#define CHECK_WINUSB_AVAILABLE do { if (!api_winusb_available) return LIBUSB_ERROR_ACCESS; } while (0)


/*
 * Converts a WCHAR string to UTF8 (allocate returned string)
 * Returns NULL on error
 */
static char* wchar_to_utf8(LPCWSTR wstr)
{
	int size;
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

static inline BOOLEAN guid_eq(const GUID *guid1, const GUID *guid2) {
	if ((guid1 != NULL) && (guid2 != NULL)) {
		return (memcmp(guid1, guid2, sizeof(GUID)) == 0);
	}
	return false;
}

#if 0
static char* guid_to_string(const GUID guid)
{
	static char guid_string[MAX_GUID_STRING_LENGTH];

	sprintf(guid_string, "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		(unsigned int)guid.Data1, guid.Data2, guid.Data3,
		guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
		guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
	return guid_string;
}
#endif

/*
 * Converts a windows error to human readable string
 * uses retval as errorcode, or, if 0, use GetLastError()
 */
static char *windows_error_str(uint32_t retval)
{
static char err_string[ERR_BUFFER_SIZE];

	DWORD size;
	size_t i;
	uint32_t error_code, format_error;

	error_code = retval?retval:GetLastError();

	safe_sprintf(err_string, ERR_BUFFER_SIZE, "[%d] ", error_code);

	size = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, error_code,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR) &err_string[safe_strlen(err_string)],
		ERR_BUFFER_SIZE - (DWORD)safe_strlen(err_string), NULL);
	if (size == 0) {
		format_error = GetLastError();
		if (format_error)
			safe_sprintf(err_string, ERR_BUFFER_SIZE,
				"Windows error code %u (FormatMessage error code %u)", error_code, format_error);
		else
			safe_sprintf(err_string, ERR_BUFFER_SIZE, "Unknown error code %u", error_code);
	} else {
		// Remove CR/LF terminators
		for (i=safe_strlen(err_string)-1; ((err_string[i]==0x0A) || (err_string[i]==0x0D)); i--) {
			err_string[i] = 0;
		}
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
	size_t j, size, root_size;
	char* ret_path = NULL;
	size_t add_root = 0;

	if (path == NULL)
		return NULL;

	size = safe_strlen(path)+1;
	root_size = sizeof(root_prefix)-1;

	// Microsoft indiscriminatly uses '\\?\', '\\.\', '##?#" or "##.#" for root prefixes.
	if (!((size > 3) && (((path[0] == '\\') && (path[1] == '\\') && (path[3] == '\\')) ||
		((path[0] == '#') && (path[1] == '#') && (path[3] == '#'))))) {
		add_root = root_size;
		size += add_root;
	}

	if ((ret_path = (char*)calloc(size, 1)) == NULL)
		return NULL;

	safe_strcpy(&ret_path[add_root], size-add_root, path);

	// Ensure consistancy with root prefix
	for (j=0; j<root_size; j++)
		ret_path[j] = root_prefix[j];

	// Same goes for '\' and '#' after the root prefix. Ensure '#' is used
	for(j=root_size; j<size; j++) {
		ret_path[j] = (char)toupper((int)ret_path[j]);	// Fix case too
		if (ret_path[j] == '\\')
			ret_path[j] = '#';
	}

	return ret_path;
}

/*
 * Cfgmgr32, OLE32 and SetupAPI DLL functions
 */
static int init_dlls(void)
{
	DLL_LOAD(Cfgmgr32.dll, CM_Get_Parent, TRUE);
	DLL_LOAD(Cfgmgr32.dll, CM_Get_Child, TRUE);
	DLL_LOAD(Cfgmgr32.dll, CM_Get_Sibling, TRUE);
	DLL_LOAD(Cfgmgr32.dll, CM_Get_Device_IDA, TRUE);
	DLL_LOAD(Cfgmgr32.dll, CM_Get_Device_IDW, TRUE);

	// Prefixed to avoid conflict with header files
	DLL_LOAD_PREFIXED(OLE32.dll, p, CLSIDFromString, TRUE);
	DLL_LOAD_PREFIXED(SetupAPI.dll, p, SetupDiGetClassDevs, TRUE);
	DLL_LOAD_PREFIXED(SetupAPI.dll, p, SetupDiEnumDeviceInfo, TRUE);
	DLL_LOAD_PREFIXED(SetupAPI.dll, p, SetupDiEnumDeviceInterfaces, TRUE);
	DLL_LOAD_PREFIXED(SetupAPI.dll, p, SetupDiGetDeviceInterfaceDetail, TRUE);
	DLL_LOAD_PREFIXED(SetupAPI.dll, p, SetupDiDestroyDeviceInfoList, TRUE);
	DLL_LOAD_PREFIXED(SetupAPI.dll, p, SetupDiOpenDevRegKey, TRUE);
	DLL_LOAD_PREFIXED(SetupAPI.dll, p, SetupDiGetDeviceRegistryProperty, TRUE);
	DLL_LOAD_PREFIXED(SetupAPI.dll, p, SetupDiGetDeviceRegistryPropertyW, TRUE);
	return LIBUSB_SUCCESS;
}

/*
 * enumerate interfaces for a specific GUID
 *
 * Parameters:
 * dev_info: a pointer to a dev_info list
 * dev_info_data: a pointer to an SP_DEVINFO_DATA to be filled (or NULL if not needed)
 * guid: the GUID for which to retrieve interface details
 * index: zero based index of the interface in the device info list
 *
 * Note: it is the responsibility of the caller to free the DEVICE_INTERFACE_DETAIL_DATA
 * structure returned and call this function repeatedly using the same guid (with an
 * incremented index starting at zero) until all interfaces have been returned.
 */
SP_DEVICE_INTERFACE_DETAIL_DATA *get_interface_details(struct libusb_context *ctx,
	HDEVINFO *dev_info, SP_DEVINFO_DATA *dev_info_data, GUID guid, unsigned _index)
{
	SP_DEVICE_INTERFACE_DATA dev_interface_data;
	SP_DEVICE_INTERFACE_DETAIL_DATA *dev_interface_details = NULL;
	DWORD size;

	if (_index <= 0) {
		*dev_info = pSetupDiGetClassDevs(&guid, NULL, NULL, DIGCF_PRESENT|DIGCF_DEVICEINTERFACE);
	}
	if (*dev_info == INVALID_HANDLE_VALUE) {
		return NULL;
	}

	if (dev_info_data != NULL) {
		dev_info_data->cbSize = sizeof(SP_DEVINFO_DATA);
		if (!pSetupDiEnumDeviceInfo(*dev_info, _index, dev_info_data)) {
			if (GetLastError() != ERROR_NO_MORE_ITEMS) {
				usbi_err(ctx, "Could not obtain device info data for index %u: %s",
					_index, windows_error_str(0));
			}
			pSetupDiDestroyDeviceInfoList(*dev_info);
			*dev_info = INVALID_HANDLE_VALUE;
			return NULL;
		}
	}

	dev_interface_data.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
	if (!pSetupDiEnumDeviceInterfaces(*dev_info, NULL, &guid, _index, &dev_interface_data)) {
		if (GetLastError() != ERROR_NO_MORE_ITEMS) {
			usbi_err(ctx, "Could not obtain interface data for index %u: %s",
				_index, windows_error_str(0));
		}
		pSetupDiDestroyDeviceInfoList(*dev_info);
		*dev_info = INVALID_HANDLE_VALUE;
		return NULL;
	}

	// Read interface data (dummy + actual) to access the device path
	if (!pSetupDiGetDeviceInterfaceDetail(*dev_info, &dev_interface_data, NULL, 0, &size, NULL)) {
		// The dummy call should fail with ERROR_INSUFFICIENT_BUFFER
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			usbi_err(ctx, "could not access interface data (dummy) for index %u: %s",
				_index, windows_error_str(0));
			goto err_exit;
		}
	}
	else {
		usbi_err(ctx, "program assertion failed - http://msdn.microsoft.com/en-us/library/ms792901.aspx is wrong.");
		goto err_exit;
	}

	if ((dev_interface_details = malloc(size)) == NULL) {
		usbi_err(ctx, "could not allocate interface data for index %u.", _index);
		goto err_exit;
	}

	dev_interface_details->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
	if (!pSetupDiGetDeviceInterfaceDetail(*dev_info, &dev_interface_data,
		dev_interface_details, size, &size, NULL)) {
		usbi_err(ctx, "could not access interface data (actual) for index %u: %s",
			_index, windows_error_str(0));
	}

	return dev_interface_details;

err_exit:
	pSetupDiDestroyDeviceInfoList(*dev_info);
	*dev_info = INVALID_HANDLE_VALUE;
	return NULL;
}

/*
 * Populate the endpoints addresses of the device_priv interface helper structs
 */
static int windows_assign_endpoints(struct libusb_device *dev, int iface, int altsetting)
{
	int i, r;
	struct windows_device_priv *priv = __device_priv(dev);
	struct libusb_config_descriptor *conf_desc;
	const struct libusb_interface_descriptor *if_desc;

	r = libusb_get_config_descriptor(dev, 0, &conf_desc);
	if (r != LIBUSB_SUCCESS) {
		usbi_warn(NULL, "could not read config descriptor: error %d", r);
		return r;
	}

	if_desc = &conf_desc->interface[iface].altsetting[altsetting];
	safe_free(priv->usb_interface[iface].endpoint);

	if (if_desc->bNumEndpoints == 0) {
		usbi_dbg("no endpoints found for interface %d", iface);
		return LIBUSB_SUCCESS;
	}

	priv->usb_interface[iface].endpoint = malloc(if_desc->bNumEndpoints);
	if (priv->usb_interface[iface].endpoint == NULL) {
		return LIBUSB_ERROR_NO_MEM;
	}

	priv->usb_interface[iface].nb_endpoints = if_desc->bNumEndpoints;
	for (i=0; i<if_desc->bNumEndpoints; i++) {
		priv->usb_interface[iface].endpoint[i] = if_desc->endpoint[i].bEndpointAddress;
		usbi_dbg("(re)assigned endpoint %02X to interface %d", priv->usb_interface[iface].endpoint[i], iface);
	}
	libusb_free_config_descriptor(conf_desc);

	return LIBUSB_SUCCESS;
}

// Lookup for a match in the list of API driver names
bool is_api_driver(char* driver, uint8_t api)
{
	uint8_t i;
	const char sep_str[2] = {LIST_SEPARATOR, 0};
	char *tok, *tmp_str;
	size_t len = safe_strlen(driver);

	if (len == 0) return false;
	tmp_str = calloc(len+1, 1);
	if (tmp_str == NULL) return false;
	memcpy(tmp_str, driver, len+1);
	tok = strtok(tmp_str, sep_str);
	while (tok != NULL) {
		for (i=0; i<usb_api_backend[api].nb_driver_names; i++) {
			if (safe_strcmp(tok, usb_api_backend[api].driver_name_list[i]) == 0) {
				free(tmp_str);
				return true;
			}
		}
		tok = strtok(NULL, sep_str);
	}
	free (tmp_str);
	return false;
}

/*
 * auto-claiming and auto-release helper functions
 */
#if defined(AUTO_CLAIM)
static int auto_claim(struct libusb_transfer *transfer, int *interface_number, int api_type)
{
	struct libusb_context *ctx = DEVICE_CTX(transfer->dev_handle->dev);
	struct windows_device_handle_priv *handle_priv = __device_handle_priv(
		transfer->dev_handle);
	struct windows_device_priv *priv = __device_priv(transfer->dev_handle->dev);
	int current_interface = *interface_number;
	int r = LIBUSB_SUCCESS;

	usbi_mutex_lock(&autoclaim_lock);
	if (current_interface < 0)	// No serviceable interface was found
	{
		for (current_interface=0; current_interface<USB_MAXINTERFACES; current_interface++) {
			// Must claim an interface of the same API type
			if ( (priv->usb_interface[current_interface].apib == &usb_api_backend[api_type])
			  && (libusb_claim_interface(transfer->dev_handle, current_interface) == LIBUSB_SUCCESS) ) {
				usbi_dbg("auto-claimed interface %d for control request", current_interface);
				if (handle_priv->autoclaim_count[current_interface] != 0) {
					usbi_warn(ctx, "program assertion failed - autoclaim_count was nonzero");
				}
				handle_priv->autoclaim_count[current_interface]++;
				break;
			}
		}
		if (current_interface == USB_MAXINTERFACES) {
			usbi_err(ctx, "could not auto-claim any interface");
			r = LIBUSB_ERROR_NOT_FOUND;
		}
	} else {
		// If we have a valid interface that was autoclaimed, we must increment
		// its autoclaim count so that we can prevent an early release.
		if (handle_priv->autoclaim_count[current_interface] != 0) {
			handle_priv->autoclaim_count[current_interface]++;
		}
	}
	usbi_mutex_unlock(&autoclaim_lock);

	*interface_number = current_interface;
	return r;

}

static void auto_release(struct usbi_transfer *itransfer)
{
	struct windows_transfer_priv *transfer_priv = usbi_transfer_get_os_priv(itransfer);
	struct libusb_transfer *transfer = __USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	libusb_device_handle *dev_handle = transfer->dev_handle;
	struct windows_device_handle_priv* handle_priv = __device_handle_priv(dev_handle);
	int r;

	usbi_mutex_lock(&autoclaim_lock);
	if (handle_priv->autoclaim_count[transfer_priv->interface_number] > 0) {
		handle_priv->autoclaim_count[transfer_priv->interface_number]--;
		if (handle_priv->autoclaim_count[transfer_priv->interface_number] == 0) {
			r = libusb_release_interface(dev_handle, transfer_priv->interface_number);
			if (r == LIBUSB_SUCCESS) {
				usbi_dbg("auto-released interface %d", transfer_priv->interface_number);
			} else {
				usbi_dbg("failed to auto-release interface %d (error=%d)",
					transfer_priv->interface_number, r);
			}
		}
	}
	usbi_mutex_unlock(&autoclaim_lock);
}
#endif


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
	int i, r = LIBUSB_ERROR_OTHER;
	OSVERSIONINFO os_version;
	HANDLE semaphore;
	struct windows_hcd_priv** _hcd_cur;
	TCHAR sem_name[11+1+8]; // strlen(libusb_init)+'\0'+(32-bit hex PID)

	sprintf(sem_name, "libusb_init%08X", (unsigned int)GetCurrentProcessId()&0xFFFFFFFF);
	semaphore = CreateSemaphore(NULL, 1, 1, sem_name);
	if (semaphore == NULL) {
		usbi_err(ctx, "could not create semaphore: %s", windows_error_str(0));
		return LIBUSB_ERROR_NO_MEM;
	}

	// A successful wait brings our semaphore count to 0 (unsignaled)
	// => any concurent wait stalls until the semaphore's release
	if (WaitForSingleObject(semaphore, INFINITE) != WAIT_OBJECT_0) {
		usbi_err(ctx, "failure to access semaphore: %s", windows_error_str(0));
		CloseHandle(semaphore);
		return LIBUSB_ERROR_NO_MEM;
    }

	// NB: concurrent usage supposes that init calls are equally balanced with
	// exit calls. If init is called more than exit, we will not exit properly
	if ( ++concurrent_usage == 0 ) {	// First init?
		_hcd_cur = &hcd_root;

		// Detect OS version
		memset(&os_version, 0, sizeof(OSVERSIONINFO));
		os_version.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
		windows_version = WINDOWS_UNSUPPORTED;
		if ((GetVersionEx(&os_version) != 0) && (os_version.dwPlatformId == VER_PLATFORM_WIN32_NT)) {
			if ((os_version.dwMajorVersion == 5) && (os_version.dwMinorVersion == 1)) {
				windows_version = WINDOWS_XP;
			} else if ((os_version.dwMajorVersion == 5) && (os_version.dwMinorVersion == 2)) {
				windows_version = WINDOWS_2003;	// also includes XP 64
			} else if (os_version.dwMajorVersion >= 6) {
				windows_version = WINDOWS_VISTA_AND_LATER;
			}
		}
		if (windows_version == WINDOWS_UNSUPPORTED) {
			usbi_err(ctx, "This version of Windows is NOT supported");
			r = LIBUSB_ERROR_NOT_SUPPORTED;
			goto init_exit;
		}

#if defined(AUTO_CLAIM)
		// We need a lock for proper auto-release
		usbi_mutex_init(&autoclaim_lock, NULL);
#endif

		// Initialize pollable file descriptors
		init_polling();

		// Load DLL imports
		if (init_dlls() != LIBUSB_SUCCESS) {
			usbi_err(ctx, "could not resolve DLL functions");
			return LIBUSB_ERROR_NOT_FOUND;
		}

		// Initialize the low level APIs (we don't care about errors at this stage)
		for (i=0; i<USB_API_MAX; i++) {
			usb_api_backend[i].init(ctx);
		}

		// Because QueryPerformanceCounter might report different values when
		// running on different cores, we create a separate thread for the timer
		// calls, which we glue to the first core always to prevent timing discrepancies.
		r = LIBUSB_ERROR_NO_MEM;
		for (i = 0; i < 2; i++) {
			timer_request[i] = CreateEvent(NULL, TRUE, FALSE, NULL);
			if (timer_request[i] == NULL) {
				usbi_err(ctx, "could not create timer request event %d - aborting", i);
				goto init_exit;
			}
		}
		timer_response = CreateSemaphore(NULL, 0, MAX_TIMER_SEMAPHORES, NULL);
		if (timer_response == NULL) {
			usbi_err(ctx, "could not create timer response semaphore - aborting");
			goto init_exit;
		}
		timer_mutex = CreateMutex(NULL, FALSE, NULL);
		if (timer_mutex == NULL) {
			usbi_err(ctx, "could not create timer mutex - aborting");
			goto init_exit;
		}
		timer_thread = (HANDLE)_beginthreadex(NULL, 0, windows_clock_gettime_threaded, NULL, 0, NULL);
		if (timer_thread == NULL) {
			usbi_err(ctx, "Unable to create timer thread - aborting");
			goto init_exit;
		}
		SetThreadAffinityMask(timer_thread, 0);

		guid = GUID_DEVINTERFACE_USB_HOST_CONTROLLER;

		r = LIBUSB_SUCCESS;
		for (bus = 0; ; bus++)
		{
			// safe loop: free up any (unprotected) dynamic resource
			// NB: this is always executed before breaking the loop
			safe_free(dev_interface_details);
			safe_free(*_hcd_cur);

			dev_interface_details = get_interface_details(ctx, &dev_info, NULL, guid, bus);
			// safe loop: end of loop condition
			if ((dev_interface_details == NULL) || (r != LIBUSB_SUCCESS))
				break;

			// Will need to change storage and size of libusb_bus_t if this ever occurs
			if (bus == LIBUSB_BUS_MAX) {
				usbi_warn(ctx, "program assertion failed - found more than %d buses, skipping the rest.", LIBUSB_BUS_MAX);
				continue;
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
		// TODO (2nd official release): thread for hotplug (see darwin source)
	}

	if (hcd_root == NULL)
		r = LIBUSB_ERROR_NO_DEVICE;
	else
		r = LIBUSB_SUCCESS;

init_exit: // Holds semaphore here.
	if(!concurrent_usage && r != LIBUSB_SUCCESS) { // First init failed?
		if (timer_thread) {
			SetEvent(timer_request[1]); // actually the signal to quit the thread.
			if (WAIT_OBJECT_0 != WaitForSingleObject(timer_thread, INFINITE)) {
				usbi_warn(ctx, "could not wait for timer thread to quit");
				TerminateThread(timer_thread, 1); // shouldn't happen, but we're destroying
												  // all objects it might have held anyway.
			}
			CloseHandle(timer_thread);
			timer_thread = NULL;
		}
		for (i = 0; i < 2; i++) {
			if (timer_request[i]) {
				CloseHandle(timer_request[i]);
				timer_request[i] = NULL;
			}
		}
		if (timer_response) {
			CloseHandle(timer_response);
			timer_response = NULL;
		}
		if (timer_mutex) {
			CloseHandle(timer_mutex);
			timer_mutex = NULL;
		}
	}

	if (r != LIBUSB_SUCCESS)
		--concurrent_usage; // Not expected to call libusb_exit if we failed.

	ReleaseSemaphore(semaphore, 1, NULL);	// increase count back to 1
	CloseHandle(semaphore);
	return r;
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
		// USB devices that don't have a config value are usually missing a driver
		// TODO (after first official release): use this for automated driver installation
		// NB: SetupDiGetDeviceRegistryProperty w/ SPDRP_INSTALL_STATE would tell us
		// if the driver is properly installed, but driverless devices don't seem to
		// be enumerable by SetupDi...
		usbi_dbg("* This device has no driver => libusb will not be able to access it *");
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

	// The following is used to set the VIS:PID of root HUBs similarly to what
	// Linux does: 1d6b:0001 is for 1x root hubs, 1d6b:0002 for 2x
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
			priv->dev_descriptor.idProduct = 1;	// Indicate 1x speed
		} else {
			priv->dev_descriptor.idProduct = hub_caps.HubIs2xCapable?2:1;
		}
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

		cd_data = (PUSB_CONFIGURATION_DESCRIPTOR)((UCHAR*)cd_buf_actual+sizeof(USB_DESCRIPTOR_REQUEST));

		if ((size != ret_size) || (cd_data->wTotalLength != cd_buf_short.data.wTotalLength)) {
			usbi_err(ctx, "unexpected configuration descriptor size (actual).");
			LOOP_BREAK(LIBUSB_ERROR_IO);
		}

		if (cd_data->bDescriptorType != USB_CONFIGURATION_DESCRIPTOR_TYPE) {
			usbi_err(ctx, "not a configuration descriptor");
			LOOP_BREAK(LIBUSB_ERROR_IO);
		}

		usbi_dbg("cached config descriptor %d (bConfigurationValue=%d, %d bytes)",
			i, cd_data->bConfigurationValue, cd_data->wTotalLength);

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
	bool is_hcd, need_unref = false;
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
		if (need_unref) {
			safe_unref_device(dev);
			need_unref = false;
		}
		safe_free(tmp_str);
		safe_free(path_str);
		safe_closehandle(handle);

		// safe loop: end of loop condition
		if ((i > nb_ports) || (r != LIBUSB_SUCCESS))
			break;

		memset(&conn_info, 0, sizeof(conn_info));
		// For non HCDs, check if the node on this port is a hub or a regular device
		if (!is_hcd) {
			size = sizeof(USB_NODE_CONNECTION_INFORMATION);
			conn_info.ConnectionIndex = i;
			if (!DeviceIoControl(hub_handle, IOCTL_USB_GET_NODE_CONNECTION_INFORMATION, &conn_info, size,
				&conn_info, size, &size, NULL)) {
				usbi_warn(ctx, "could not get node connection information: %s", windows_error_str(0));
				continue;
			}

			if (conn_info.ConnectionStatus == NoDeviceConnected) {
				continue;
			}

			if (conn_info.DeviceAddress == LIBUSB_DEVADDR_MAX) {
				usbi_warn(ctx, "program assertion failed - device address is %d "
					"(conflicts with root hub), ignoring device", LIBUSB_DEVADDR_MAX);
				continue;
			}

			s_hubname.u.node.ConnectionIndex = i;	// Only used for non HCDs (s_hubname is an union)
		}
		else
		{
			// HCDs have only 1 node, and it's always a hub
			conn_info.DeviceAddress = LIBUSB_DEVADDR_MAX;	// using 0 can conflict with driverless devices
			conn_info.DeviceIsHub = true;
			conn_info.CurrentConfigurationValue = 1;
		}

		// If this node is a hub (HCD or not), open it
		if (conn_info.DeviceIsHub) {
			size = size_initial;
			if (!DeviceIoControl(hub_handle, getname_ioctl, &s_hubname, size,
				&s_hubname, size, &size, NULL)) {
				usbi_warn(ctx, "could not get hub path (dummy): %s", windows_error_str(0));
				continue;
			}

			size = is_hcd?s_hubname.u.root.ActualLength:s_hubname.u.node.ActualLength;
			if (size > size_fixed) {
				usbi_warn(ctx, "program assertion failed - hub path is too long");
				continue;
			}

			if (!is_hcd) {
				// previous call trashes some of the data
				s_hubname.u.node.ConnectionIndex = i;
			}
			if (!DeviceIoControl(hub_handle, getname_ioctl, &s_hubname, size,
				&s_hubname, size, &size, NULL)) {
				usbi_warn(ctx, "could not get hub path (actual): %s", windows_error_str(0));
				continue;
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
				FILE_FLAG_OVERLAPPED, NULL);
			if(handle == INVALID_HANDLE_VALUE) {
				usbi_warn(ctx, "could not open hub %s: %s", path_str, windows_error_str(0));
				continue;
			}
		}

		// Generate a session ID
		// Will need to change the session_id computation if this assertion fails
		if (conn_info.DeviceAddress > LIBUSB_DEVADDR_MAX) {
			usbi_warn(ctx, "program assertion failed - device address is greater than %d, ignoring device",
				LIBUSB_DEVADDR_MAX);
			continue;
		} else {
			devaddr = (uint8_t)conn_info.DeviceAddress;
		}
		// Same trick as linux for session_id, with same caveat
		session_id = busnum << (sizeof(libusb_devaddr_t)*8) | devaddr;
		usbi_dbg("busnum %d devaddr %d session_id %ld", busnum, devaddr, session_id);

		// Allocate device if needed
		dev = usbi_get_device_by_session_id(ctx, session_id);
		if (dev) {
			usbi_dbg("using existing device for session %ld", session_id);
			priv = __device_priv(dev);
			// Because we are rebuilding the list, there's no guarantee
			// the parent device pointer is still the same.
			// Other device data should still be reusable
			priv->parent_dev = parent_dev;
		} else {
			usbi_dbg("allocating new device for session %ld", session_id);
			if ((dev = usbi_alloc_device(ctx, session_id)) == NULL) {
				LOOP_BREAK(LIBUSB_ERROR_NO_MEM);
			}
			need_unref = true;

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
			// Find number of ports for this hub
			size =  sizeof(USB_NODE_INFORMATION);
			if (!DeviceIoControl(handle, IOCTL_USB_GET_NODE_INFORMATION, &hub_node, size,
				&hub_node, size, &size, NULL)) {
				usbi_warn(ctx, "could not retreive information for hub %s: %s",
					priv->path, windows_error_str(0));
				continue;
			}

			if (hub_node.NodeType != UsbHub) {
				usbi_warn(ctx, "unexpected hub type (%d) for hub %s", hub_node.NodeType, priv->path);
				continue;
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
	unsigned i, j, max_guids, nb_paths, interface_number;
	uint8_t api;
	bool found;
	DWORD type, size;
	CONFIGRET r;
	HDEVINFO dev_info;
	SP_DEVINFO_DATA dev_info_data;
	SP_DEVICE_INTERFACE_DETAIL_DATA *dev_interface_details = NULL;
	HKEY key;
	WCHAR guid_string_w[MAX_GUID_STRING_LENGTH];
	GUID guid, class_guid;
	GUID guid_table[MAX_USB_DEVICES];
	char* sanitized_path[MAX_USB_DEVICES];
	uint8_t api_type[MAX_USB_DEVICES];
	char* sanitized_short = NULL;
	char path[MAX_PATH_LENGTH];
	char driver[MAX_KEY_LENGTH];

	dev_info = pSetupDiGetClassDevs(NULL, "USB", NULL, DIGCF_PRESENT|DIGCF_ALLCLASSES);
	if (dev_info == INVALID_HANDLE_VALUE) {
		return LIBUSB_ERROR_NOT_FOUND;
	}

	max_guids = 0;

	// First, retrieve all the device interface GUIDs
	for (i = 0; ; i++)
	{
		dev_info_data.cbSize = sizeof(dev_info_data);
		if (!pSetupDiEnumDeviceInfo(dev_info, i, &dev_info_data)) {
			break;
		}

		key = pSetupDiOpenDevRegKey(dev_info, &dev_info_data, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_READ);
		if (key == INVALID_HANDLE_VALUE) {
			usbi_dbg("could not open registry key");
			continue;
		}

		size = sizeof(guid_string_w);
		r = RegQueryValueExW(key, L"DeviceInterfaceGUIDs", NULL, &type,
			(BYTE*)guid_string_w, &size);
		RegCloseKey(key);
		if (r != ERROR_SUCCESS) {
			continue;
		}
		pCLSIDFromString(guid_string_w, &guid);

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
	pSetupDiDestroyDeviceInfoList(dev_info);

	// Now let's find the device interface paths for all these devices
	nb_paths = 0;
	for (j=0; j<max_guids; j++)
	{
		guid = guid_table[j];

		for (i = 0; ; i++)
		{
			safe_free(dev_interface_details);
			dev_interface_details = get_interface_details(ctx, &dev_info, &dev_info_data, guid, i);
			if (dev_interface_details == NULL)
				break;

			// In case we can't read the driver string through SPDRP_SERVICE,
			// we need the ClassGUID for comparison.
			if(!pSetupDiGetDeviceRegistryPropertyW(dev_info, &dev_info_data, SPDRP_CLASSGUID,
				NULL, (BYTE*)guid_string_w, sizeof(guid_string_w), &size)) {
				usbi_warn(ctx, "could not read class GUID for device %s, skipping: %s",
					dev_interface_details->DevicePath, windows_error_str(0));
				continue;
			}
			pCLSIDFromString(guid_string_w, &class_guid);

			// Attempt to read the driver string
			if(!pSetupDiGetDeviceRegistryProperty(dev_info, &dev_info_data, SPDRP_SERVICE,
				NULL, (BYTE*)driver, MAX_KEY_LENGTH, &size)) {
				driver[0] = 0;
			}

			for (api=USB_API_WINUSB; api<USB_API_MAX; api++) {
				if ( (is_api_driver(driver, api))
				  || (guid_eq(&class_guid, usb_api_backend[api].class_guid)) ) {
					api_type[nb_paths] = api;
					sanitized_path[nb_paths++] = sanitize_path(dev_interface_details->DevicePath);
					if (nb_paths > MAX_USB_DEVICES) {
						usbi_warn(ctx, "more than %d devices - ignoring the rest", MAX_USB_DEVICES);
						break;
					}
				}
			}
		}
	}

	// Finally, match the interface paths with the interfaces. We do that
	// by looking at the children of the composite device
	// NB: if the interfaces are not found in their expected position,
	// claim_interface will issue a warning
	found = false;
	memset(&child_devinst, 0, sizeof(DEVINST));	// prevents /W4 warning
	for (i = 0; i<USB_MAXINTERFACES; i++)
	{
		if (i == 0) {
			r = CM_Get_Child(&child_devinst, devinst, 0);
		} else {
			r = CM_Get_Sibling(&child_devinst, child_devinst, 0);
		}
		if (r == CR_NO_SUCH_DEVNODE) {	// end of the siblings
			break;
		} else if (r != CR_SUCCESS) {
			usbi_dbg("unable to find interface sibling #%d, error = %X", i, r);
			break;
		}

		r = CM_Get_Device_ID(child_devinst, path, MAX_PATH_LENGTH, 0);
		if (r != CR_SUCCESS) {
			usbi_err(ctx, "could not retrieve simple path for interface %d: CR error %d",
				i, r);
			continue;
		}
		sanitized_short = sanitize_path(path);
		if (sanitized_short == NULL) {
			usbi_err(ctx, "could not sanitize path for interface %d", i);
			continue;
		}

		// Because MI_## are not necessarily in sequential order, we
		// retrieve the actual interface number from the path's MI value
		interface_number = i;
		for (j=0; sanitized_short[j] != 0; ) {
			if ( (sanitized_short[j++] == 'M') && (sanitized_short[j++] == 'I')
			  && (sanitized_short[j++] == '_') ) {
				interface_number = (sanitized_short[j++] - '0')*10;
				interface_number += sanitized_short[j] - '0';
				break;
			}
		}
		if (sanitized_short[j] == 0) {
			usbi_warn(ctx, "failure to read interface number for %s. Using default value %d",
				sanitized_short, interface_number);
		}

		for (j=0; j<nb_paths; j++) {
			if ( (safe_strncmp(sanitized_path[j], sanitized_short, safe_strlen(sanitized_short)) == 0) ) {
				priv->usb_interface[interface_number].path = sanitized_path[j];
				priv->usb_interface[interface_number].apib = &usb_api_backend[api_type[j]];
				priv->composite_api_flags |= 1<<api_type[j];
				sanitized_path[j] = NULL;
			}
		}
		safe_free(sanitized_short);

		if (priv->usb_interface[interface_number].path == NULL) {
			usbi_warn(ctx, "interface_path[%d]: unhandled API - interface will be disabled",
				interface_number);
			continue;
		}
		usbi_dbg("interface_path[%d]: %s", interface_number, priv->usb_interface[interface_number].path);
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
	// Precedence for filter drivers vs driver is in the order of this array
	struct driver_lookup lookup[3] = {
		{"\0\0", SPDRP_SERVICE, "driver"},
		{"\0\0", SPDRP_UPPERFILTERS, "upper filter driver"},
		{"\0\0", SPDRP_LOWERFILTERS, "lower filter driver"}
	};
	struct windows_device_priv *priv;
	struct windows_device_priv *parent_priv;
	char path[MAX_PATH_LENGTH];
	char *sanitized_path = NULL;
	HDEVINFO dev_info;
	SP_DEVICE_INTERFACE_DETAIL_DATA *dev_interface_details = NULL;
	SP_DEVINFO_DATA dev_info_data;
	DEVINST parent_devinst;
	GUID guid;
	DWORD size, reg_type, install_state, port_nr;
	int r = LIBUSB_SUCCESS;
	unsigned i, j, k, l;
	uint8_t api;
	bool found;

	// TODO (after first official release): MI_## automated driver installation
	guid = GUID_DEVINTERFACE_USB_DEVICE;
	for (i = 0; ; i++)
	{
		// safe loop: free up any (unprotected) dynamic resource
		safe_free(dev_interface_details);
		safe_free(sanitized_path);

		dev_interface_details = get_interface_details(ctx, &dev_info, &dev_info_data, guid, i);
		// safe loop: end of loop condition
		if ( (dev_interface_details == NULL)
		  || (r != LIBUSB_SUCCESS) )
			break;

		// Check that the driver installation is OK
		if ( (!pSetupDiGetDeviceRegistryProperty(dev_info, &dev_info_data, SPDRP_INSTALL_STATE,
			&reg_type, (BYTE*)&install_state, 4, &size))
		  || (size != 4) ){
			usbi_warn(ctx, "could not detect installation state of driver for %s: %s",
				dev_interface_details->DevicePath, windows_error_str(0));
		} else if (install_state != 0) {
			usbi_warn(ctx, "driver for device %s is reporting an issue (code: %d) - skipping",
				dev_interface_details->DevicePath, install_state);
			continue;
		}

		// The SPDRP_ADDRESS for USB devices should be the device port number on the hub
		if ( (!pSetupDiGetDeviceRegistryProperty(dev_info, &dev_info_data, SPDRP_ADDRESS,
			&reg_type, (BYTE*)&port_nr, 4, &size))
		  || (size != 4) ){
			usbi_warn(ctx, "could not retrieve port number for device %s, skipping: %s",
				dev_interface_details->DevicePath, windows_error_str(0));
			continue;
		}

		// Retrieve parent's path using PnP Configuration Manager (CM)
		if (CM_Get_Parent(&parent_devinst, dev_info_data.DevInst, 0) != CR_SUCCESS) {
			usbi_warn(ctx, "could not retrieve parent info data for device %s, skipping: %s",
				dev_interface_details->DevicePath, windows_error_str(0));
			continue;
		}

		if (CM_Get_Device_ID(parent_devinst, path, MAX_PATH_LENGTH, 0) != CR_SUCCESS) {
			usbi_warn(ctx, "could not retrieve parent's path for device %s, skipping: %s",
				dev_interface_details->DevicePath, windows_error_str(0));
			continue;
		}

		// Fix parent's path inconsistencies before attempting to compare
		sanitized_path = sanitize_path(path);
		if (sanitized_path == NULL) {
			usbi_warn(ctx, "could not sanitize parent's path for device %s, skipping.",
				dev_interface_details->DevicePath);
			continue;
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
			if ( (safe_strncmp(parent_priv->path, sanitized_path, safe_strlen(sanitized_path)) == 0)
			  && (port_nr == priv->connection_index) ) {

				priv->path = sanitize_path(dev_interface_details->DevicePath);

				usbi_dbg("path (%d:%d): %s", discdevs->devices[j]->bus_number,
					discdevs->devices[j]->device_address, priv->path);

				// Check the service & filter names to know the API we should use
				for (k=0; k<3; k++) {
					if (pSetupDiGetDeviceRegistryProperty(dev_info, &dev_info_data, lookup[k].reg_prop,
						&reg_type, (BYTE*)lookup[k].list, MAX_KEY_LENGTH, &size)) {
						// Turn the REG_SZ SPDRP_SERVICE into REG_MULTI_SZ
						if (lookup[k].reg_prop == SPDRP_SERVICE) {
							// our buffers are MAX_KEY_LENGTH+1 so we can overflow if needed
							lookup[k].list[safe_strlen(lookup[k].list)+1] = 0;
						}
						// MULTI_SZ is a pain to work with. Turn it into something much more manageable
						// NB: none of the driver names we check against contain LIST_SEPARATOR,
						// (currently ';'), so even if an unsuported one does, it's not an issue
						for (l=0; (lookup[k].list[l] != 0) || (lookup[k].list[l+1] != 0); l++) {
							if (lookup[k].list[l] == 0) {
								lookup[k].list[l] = LIST_SEPARATOR;
							}
						}
						upperize(lookup[k].list);
						usbi_dbg("%s(s): %s", lookup[k].designation, lookup[k].list);
						found = true;
					} else {
						if (GetLastError() != ERROR_INVALID_DATA) {
							usbi_dbg("could not access %s: %s", lookup[k].designation, windows_error_str(0));
						}
						lookup[k].list[0] = 0;
					}
				}

				for (api=0; api<USB_API_MAX; api++) {
					for (k=0; k<3; k++) {
						if (is_api_driver(lookup[k].list, api)) {
							usbi_dbg("matched %s name against %s", lookup[k].designation, usb_api_backend[api].designation);
							break;
						}
					}
					if (k >= 3) continue;
					priv->apib = &usb_api_backend[api];
					switch(api) {
					case USB_API_COMPOSITE:
						set_composite_device(ctx, dev_info_data.DevInst, priv);
						break;
					default:
						// For other devices, the first interface is the same as the device
						priv->usb_interface[0].path = malloc(safe_strlen(priv->path)+1);
						if (priv->usb_interface[0].path != NULL) {
							safe_strcpy(priv->usb_interface[0].path, safe_strlen(priv->path)+1, priv->path);
						}
						// The following is needed if we want to API calls to work for both simple
						// and composite devices, as
						for(k=0; k<USB_MAXINTERFACES; k++) {
							priv->usb_interface[k].apib = &usb_api_backend[api];
						}
						break;
					}
				}
				break;
			}
		}
		if (!found) {
			usbi_warn(ctx, "could not match %s with a libusb device.", dev_interface_details->DevicePath);
			continue;
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
			usbi_warn(ctx, "program assertion failed - got more than %d buses, skipping the rest.", LIBUSB_BUS_MAX);
			continue;
		}

		handle = CreateFileA(hcd->path, GENERIC_WRITE, FILE_SHARE_WRITE,
			NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
		if (handle == INVALID_HANDLE_VALUE) {
			usbi_warn(ctx, "could not open bus %u, skipping: %s", bus, windows_error_str(0));
			continue;
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
	int i;
	HANDLE semaphore;
	TCHAR sem_name[11+1+8]; // strlen(libusb_init)+'\0'+(32-bit hex PID)

	sprintf(sem_name, "libusb_init%08X", (unsigned int)GetCurrentProcessId()&0xFFFFFFFF);
	semaphore = CreateSemaphore(NULL, 1, 1, sem_name);
	if (semaphore == NULL) {
		return;
	}

	// A successful wait brings our semaphore count to 0 (unsignaled)
	// => any concurent wait stalls until the semaphore release
	if (WaitForSingleObject(semaphore, INFINITE) != WAIT_OBJECT_0) {
		CloseHandle(semaphore);
		return;
	}

	// Only works if exits and inits are balanced exactly
	if (--concurrent_usage < 0) {	// Last exit
		while (hcd_root != NULL)
		{
			hcd_tmp = hcd_root;	// Keep a copy for free
			hcd_root = hcd_root->next;
			windows_hcd_priv_release(hcd_tmp);
			safe_free(hcd_tmp);
		}

		for (i=0; i<USB_API_MAX; i++) {
			usb_api_backend[i].exit();
		}
		exit_polling();

		if (timer_thread) {
			SetEvent(timer_request[1]); // actually the signal to quit the thread.
			if (WAIT_OBJECT_0 != WaitForSingleObject(timer_thread, INFINITE)) {
				usbi_dbg("could not wait for timer thread to quit");
				TerminateThread(timer_thread, 1);
			}
			CloseHandle(timer_thread);
			timer_thread = NULL;
		}
		for (i = 0; i < 2; i++) {
			if (timer_request[i]) {
				CloseHandle(timer_request[i]);
				timer_request[i] = NULL;
			}
		}
		if (timer_response) {
			CloseHandle(timer_response);
			timer_response = NULL;
		}
		if (timer_mutex) {
			CloseHandle(timer_mutex);
			timer_mutex = NULL;
		}
	}

	ReleaseSemaphore(semaphore, 1, NULL);	// increase count back to 1
	CloseHandle(semaphore);
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
	return windows_get_config_descriptor(dev, (uint8_t)(priv->active_config-1), buffer, len, host_endian);
}

static int windows_open(struct libusb_device_handle *dev_handle)
{
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);
	struct libusb_context *ctx = DEVICE_CTX(dev_handle->dev);

	if (priv->apib == NULL) {
		usbi_err(ctx, "program assertion failed - device is not initialized");
		return LIBUSB_ERROR_NO_DEVICE;
	}

	return priv->apib->open(dev_handle);
}

static void windows_close(struct libusb_device_handle *dev_handle)
{
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);

	priv->apib->close(dev_handle);
}

static int windows_get_configuration(struct libusb_device_handle *dev_handle, int *config)
{
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);

	if (priv->active_config == 0) {
		*config = 0;
		return LIBUSB_ERROR_NOT_FOUND;
	}

	*config = priv->active_config;
	return LIBUSB_SUCCESS;
}

/*
 * from http://msdn.microsoft.com/en-us/library/ms793522.aspx: "The port driver
 * does not currently expose a service that allows higher-level drivers to set
 * the configuration."
 */
static int windows_set_configuration(struct libusb_device_handle *dev_handle, int config)
{
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);
	int r = LIBUSB_SUCCESS;

	if (config >= USB_MAXCONFIG)
		return LIBUSB_ERROR_INVALID_PARAM;

	r = libusb_control_transfer(dev_handle, LIBUSB_ENDPOINT_OUT |
		LIBUSB_REQUEST_TYPE_STANDARD | LIBUSB_RECIPIENT_DEVICE,
		LIBUSB_REQUEST_SET_CONFIGURATION, (uint16_t)config,
		0, NULL, 0, 1000);

	if (r == LIBUSB_SUCCESS) {
		priv->active_config = (uint8_t)config;
	}
	return r;
}

static int windows_claim_interface(struct libusb_device_handle *dev_handle, int iface)
{
	int r = LIBUSB_SUCCESS;
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);

	if (iface >= USB_MAXINTERFACES)
		return LIBUSB_ERROR_INVALID_PARAM;

	safe_free(priv->usb_interface[iface].endpoint);
	priv->usb_interface[iface].nb_endpoints= 0;

	r = priv->apib->claim_interface(dev_handle, iface);

	if (r == LIBUSB_SUCCESS) {
		r = windows_assign_endpoints(dev_handle->dev, iface, 0);
	}

	return r;
}

static int windows_set_interface_altsetting(struct libusb_device_handle *dev_handle, int iface, int altsetting)
{
	int r = LIBUSB_SUCCESS;
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);

	safe_free(priv->usb_interface[iface].endpoint);
	priv->usb_interface[iface].nb_endpoints= 0;

	r = priv->apib->set_interface_altsetting(dev_handle, iface, altsetting);

	if (r == LIBUSB_SUCCESS) {
		r = windows_assign_endpoints(dev_handle->dev, iface, altsetting);
	}

	return r;
}

static int windows_release_interface(struct libusb_device_handle *dev_handle, int iface)
{
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);

	windows_set_interface_altsetting(dev_handle, iface, 0);
	return priv->apib->release_interface(dev_handle, iface);
}

static int windows_clear_halt(struct libusb_device_handle *dev_handle, unsigned char endpoint)
{
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);
	return priv->apib->clear_halt(dev_handle, endpoint);
}

static int windows_reset_device(struct libusb_device_handle *dev_handle)
{
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);
	return priv->apib->reset_device(dev_handle);
}

// The 3 functions below are unlikely to ever get supported on Windows
static int windows_kernel_driver_active(struct libusb_device_handle *dev_handle, int iface)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int windows_attach_kernel_driver(struct libusb_device_handle *dev_handle, int iface)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int windows_detach_kernel_driver(struct libusb_device_handle *dev_handle, int iface)
{
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

	usbi_free_fd(transfer_priv->pollable_fd.fd);
#if defined(AUTO_CLAIM)
	// When auto claim is in use, attempt to release the auto-claimed interface
	auto_release(itransfer);
#endif
}

static int submit_bulk_transfer(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = __USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct libusb_context *ctx = DEVICE_CTX(transfer->dev_handle->dev);
	struct windows_transfer_priv *transfer_priv = usbi_transfer_get_os_priv(itransfer);
	struct windows_device_priv *priv = __device_priv(transfer->dev_handle->dev);
	int r;

	r = priv->apib->submit_bulk_transfer(itransfer);
	if (r != LIBUSB_SUCCESS) {
		return r;
	}

	usbi_add_pollfd(ctx, transfer_priv->pollable_fd.fd,
		(short)((transfer->endpoint & LIBUSB_ENDPOINT_IN)?POLLIN:POLLOUT));
#if !defined(DYNAMIC_FDS)
	usbi_fd_notification(ctx);
#endif

	return LIBUSB_SUCCESS;
}

static int submit_iso_transfer(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = __USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct libusb_context *ctx = DEVICE_CTX(transfer->dev_handle->dev);
	struct windows_transfer_priv *transfer_priv = usbi_transfer_get_os_priv(itransfer);
	struct windows_device_priv *priv = __device_priv(transfer->dev_handle->dev);
	int r;

	r = priv->apib->submit_iso_transfer(itransfer);
	if (r != LIBUSB_SUCCESS) {
		return r;
	}

	usbi_add_pollfd(ctx, transfer_priv->pollable_fd.fd,
		(short)((transfer->endpoint & LIBUSB_ENDPOINT_IN)?POLLIN:POLLOUT));
#if !defined(DYNAMIC_FDS)
	usbi_fd_notification(ctx);
#endif

	return LIBUSB_SUCCESS;
}

static int submit_control_transfer(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = __USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct libusb_context *ctx = DEVICE_CTX(transfer->dev_handle->dev);
	struct windows_transfer_priv *transfer_priv = usbi_transfer_get_os_priv(itransfer);
	struct windows_device_priv *priv = __device_priv(transfer->dev_handle->dev);
	int r;

	r = priv->apib->submit_control_transfer(itransfer);
	if (r != LIBUSB_SUCCESS) {
		return r;
	}

	usbi_add_pollfd(ctx, transfer_priv->pollable_fd.fd, POLLIN);
#if !defined(DYNAMIC_FDS)
	usbi_fd_notification(ctx);
#endif

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

	return priv->apib->abort_control(itransfer);
}

static int windows_abort_transfers(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = __USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct windows_device_priv *priv = __device_priv(transfer->dev_handle->dev);

	return priv->apib->abort_transfers(itransfer);
}

static int windows_cancel_transfer(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = __USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
#if defined(FORCE_INSTANT_TIMEOUTS)
	struct windows_transfer_priv *transfer_priv = usbi_transfer_get_os_priv(itransfer);

	// Forces instant overlapped completion on timeouts - use at your own risks
	if (itransfer->flags & USBI_TRANSFER_TIMED_OUT) {
		transfer_priv->pollable_fd.overlapped->Internal &= ~STATUS_PENDING;
	}
#endif
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

static void windows_transfer_callback(struct usbi_transfer *itransfer, uint32_t io_result, uint32_t io_size)
{
	struct libusb_transfer *transfer = __USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct windows_device_priv *priv = __device_priv(transfer->dev_handle->dev);
	int status;

	usbi_dbg("handling I/O completion with errcode %d", io_result);

	switch(io_result) {
	case NO_ERROR:
		status = priv->apib->copy_transfer_data(itransfer, io_size);
		break;
	case ERROR_GEN_FAILURE:
		usbi_dbg("detected endpoint stall");
		status = LIBUSB_TRANSFER_STALL;
		break;
	case ERROR_SEM_TIMEOUT:
		usbi_dbg("detected semaphore timeout");
		status = LIBUSB_TRANSFER_TIMED_OUT;
		break;
	case ERROR_OPERATION_ABORTED:
		if (itransfer->flags & USBI_TRANSFER_TIMED_OUT) {
			usbi_dbg("detected timeout");
			status = LIBUSB_TRANSFER_TIMED_OUT;
		} else {
			usbi_dbg("detected operation aborted");
			status = LIBUSB_TRANSFER_CANCELLED;
		}
		break;
	default:
		usbi_err(ITRANSFER_CTX(itransfer), "detected I/O error: %s", windows_error_str(0));
		status = LIBUSB_TRANSFER_ERROR;
		break;
	}
	windows_clear_transfer_priv(itransfer);	// Cancel polling
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

static int windows_handle_events(struct libusb_context *ctx, struct pollfd *fds, POLL_NFDS_TYPE nfds, int num_ready)
{
	struct windows_transfer_priv* transfer_priv = NULL;
	POLL_NFDS_TYPE i = 0;
	bool found = false;
	struct usbi_transfer *transfer;
	DWORD io_size, io_result;

	usbi_mutex_lock(&ctx->open_devs_lock);
	for (i = 0; i < nfds && num_ready > 0; i++) {

		usbi_dbg("checking fd %d with revents = %04x", fds[i].fd, fds[i].revents);

		if (!fds[i].revents) {
			continue;
		}

		num_ready--;

		// Because a Windows OVERLAPPED is used for poll emulation,
		// a pollable fd is created and stored with each transfer
		usbi_mutex_lock(&ctx->flying_transfers_lock);
		list_for_each_entry(transfer, &ctx->flying_transfers, list, struct usbi_transfer) {
			transfer_priv = usbi_transfer_get_os_priv(transfer);
			if (transfer_priv->pollable_fd.fd == fds[i].fd) {
				found = true;
				break;
			}
		}
		usbi_mutex_unlock(&ctx->flying_transfers_lock);

		if (found) {
			// Handle async requests that completed synchronously first
			if (HasOverlappedIoCompletedSync(transfer_priv->pollable_fd.overlapped)) {
				io_result = NO_ERROR;
				io_size = (DWORD)transfer_priv->pollable_fd.overlapped->InternalHigh;
			// Regular async overlapped
			} else if (GetOverlappedResult(transfer_priv->pollable_fd.handle,
				transfer_priv->pollable_fd.overlapped, &io_size, false)) {
				io_result = NO_ERROR;
			} else {
				io_result = GetLastError();
			}
			usbi_remove_pollfd(ctx, transfer_priv->pollable_fd.fd);
			// let handle_callback free the event using the transfer wfd
			// If you don't use the transfer wfd, you run a risk of trying to free a
			// newly allocated wfd that took the place of the one from the transfer.
			windows_handle_callback(transfer, io_result, io_size);
		} else {
			usbi_err(ctx, "could not find a matching transfer for fd %x", fds[i]);
			return LIBUSB_ERROR_NOT_FOUND;
		}
	}

	usbi_mutex_unlock(&ctx->open_devs_lock);
	return LIBUSB_SUCCESS;
}

/*
 * Monotonic and real time functions
 */
unsigned __stdcall windows_clock_gettime_threaded(void* param)
{
	LARGE_INTEGER hires_counter, li_frequency;
	LONG nb_responses;
	int timer_index;

	// Init - find out if we have access to a monotonic (hires) timer
	if (!QueryPerformanceFrequency(&li_frequency)) {
		usbi_dbg("no hires timer available on this platform");
		hires_frequency = 0;
		hires_ticks_to_ps = UINT64_C(0);
	} else {
		hires_frequency = li_frequency.QuadPart;
		// The hires frequency can go as high as 4 GHz, so we'll use a conversion
		// to picoseconds to compute the tv_nsecs part in clock_gettime
		hires_ticks_to_ps = UINT64_C(1000000000000) / hires_frequency;
		usbi_dbg("hires timer available (Frequency: %"PRIu64" Hz)", hires_frequency);
	}

	// Main loop - wait for requests
	while (1) {
		timer_index = WaitForMultipleObjects(2, timer_request, FALSE, INFINITE) - WAIT_OBJECT_0;
		if ( (timer_index != 0) && (timer_index != 1) ) {
			usbi_dbg("failure to wait on requests: %s", windows_error_str(0));
			continue;
		}
		if (request_count[timer_index] == 0) {
			// Request already handled
			ResetEvent(timer_request[timer_index]);
			// There's still a possiblity that a thread sends a request between the
			// time we test request_count[] == 0 and we reset the event, in which case
			// the request would be ignored. The simple solution to that is to test
			// request_count again and process requests if non zero.
			if (request_count[timer_index] == 0)
				continue;
		}
		switch (timer_index) {
		case 0:
			WaitForSingleObject(timer_mutex, INFINITE);
			// Requests to this thread are for hires always
			if (QueryPerformanceCounter(&hires_counter) != 0) {
				timer_tp.tv_sec = (long)(hires_counter.QuadPart / hires_frequency);
				timer_tp.tv_nsec = (long)(((hires_counter.QuadPart % hires_frequency)/1000) * hires_ticks_to_ps);
			} else {
				// Fallback to real-time if we can't get monotonic value
				// Note that real-time clock does not wait on the mutex or this thread.
				windows_clock_gettime(USBI_CLOCK_REALTIME, &timer_tp);
			}
			ReleaseMutex(timer_mutex);

			nb_responses = InterlockedExchange((LONG*)&request_count[0], 0);
			if ( (nb_responses)
			  && (ReleaseSemaphore(timer_response, nb_responses, NULL) == 0) ) {
				usbi_dbg("unable to release timer semaphore %d: %s", windows_error_str(0));
			}
			continue;
		case 1: // time to quit
			usbi_dbg("timer thread quitting");
			return 0;
		}
	}
	usbi_dbg("ERROR: broken timer thread");
	return 1;
}

static int windows_clock_gettime(int clk_id, struct timespec *tp)
{
	FILETIME filetime;
	ULARGE_INTEGER rtime;
	DWORD r;
	switch(clk_id) {
	case USBI_CLOCK_MONOTONIC:
		if (hires_frequency != 0) {
			while (1) {
				InterlockedIncrement((LONG*)&request_count[0]);
				SetEvent(timer_request[0]);
				r = WaitForSingleObject(timer_response, TIMER_REQUEST_RETRY_MS);
				switch(r) {
				case WAIT_OBJECT_0:
					WaitForSingleObject(timer_mutex, INFINITE);
					*tp = timer_tp;
					ReleaseMutex(timer_mutex);
					return LIBUSB_SUCCESS;
				case WAIT_TIMEOUT:
					usbi_dbg("could not obtain a timer value within reasonable timeframe - too much load?");
					break; // Retry until successful
				default:
					usbi_dbg("WaitForSingleObject failed: %s", windows_error_str(0));
					return LIBUSB_ERROR_OTHER;
				}
			}
		}
		// Fall through and return real-time if monotonic was not detected @ timer init
	case USBI_CLOCK_REALTIME:
		// We follow http://msdn.microsoft.com/en-us/library/ms724928%28VS.85%29.aspx
		// with a predef epoch_time to have an epoch that starts at 1970.01.01 00:00
		// Note however that our resolution is bounded by the Windows system time
		// functions and is at best of the order of 1 ms (or, usually, worse)
		GetSystemTimeAsFileTime(&filetime);
		rtime.LowPart = filetime.dwLowDateTime;
		rtime.HighPart = filetime.dwHighDateTime;
		rtime.QuadPart -= epoch_time;
		tp->tv_sec = (long)(rtime.QuadPart / 10000000);
		tp->tv_nsec = (long)((rtime.QuadPart % 10000000)*100);
		return LIBUSB_SUCCESS;
	default:
		return LIBUSB_ERROR_INVALID_PARAM;
	}
}


// NB: MSVC6 does not support named initializers.
const struct usbi_os_backend windows_backend = {
	"Windows",
	windows_init,
	windows_exit,

	windows_get_device_list,
	windows_open,
	windows_close,

	windows_get_device_descriptor,
	windows_get_active_config_descriptor,
	windows_get_config_descriptor,

	windows_get_configuration,
	windows_set_configuration,
	windows_claim_interface,
	windows_release_interface,

	windows_set_interface_altsetting,
	windows_clear_halt,
	windows_reset_device,

	windows_kernel_driver_active,
	windows_detach_kernel_driver,
	windows_attach_kernel_driver,

	windows_destroy_device,

	windows_submit_transfer,
	windows_cancel_transfer,
	windows_clear_transfer_priv,

	windows_handle_events,

	windows_clock_gettime,
#if defined(USBI_TIMERFD_AVAILABLE)
	NULL,
#endif
	sizeof(struct windows_device_priv),
	sizeof(struct windows_device_handle_priv),
	sizeof(struct windows_transfer_priv),
	0,
};


/*
 * USB API backends
 */
static int unsupported_init(struct libusb_context *ctx) {
	return LIBUSB_SUCCESS;
}
static int unsupported_exit(void) {
	return LIBUSB_SUCCESS;
}
static int unsupported_open(struct libusb_device_handle *dev_handle) {
	PRINT_UNSUPPORTED_API(open);
}
static void unsupported_close(struct libusb_device_handle *dev_handle) {
	usbi_dbg("unsupported API call for 'close'");
}
static int unsupported_claim_interface(struct libusb_device_handle *dev_handle, int iface) {
	PRINT_UNSUPPORTED_API(claim_interface);
}
static int unsupported_set_interface_altsetting(struct libusb_device_handle *dev_handle, int iface, int altsetting) {
	PRINT_UNSUPPORTED_API(set_interface_altsetting);
}
static int unsupported_release_interface(struct libusb_device_handle *dev_handle, int iface) {
	PRINT_UNSUPPORTED_API(release_interface);
}
static int unsupported_clear_halt(struct libusb_device_handle *dev_handle, unsigned char endpoint) {
	PRINT_UNSUPPORTED_API(clear_halt);
}
static int unsupported_reset_device(struct libusb_device_handle *dev_handle) {
	PRINT_UNSUPPORTED_API(reset_device);
}
static int unsupported_submit_bulk_transfer(struct usbi_transfer *itransfer) {
	PRINT_UNSUPPORTED_API(submit_bulk_transfer);
}
static int unsupported_submit_iso_transfer(struct usbi_transfer *itransfer) {
	PRINT_UNSUPPORTED_API(submit_iso_transfer);
}
static int unsupported_submit_control_transfer(struct usbi_transfer *itransfer) {
	PRINT_UNSUPPORTED_API(submit_control_transfer);
}
static int unsupported_abort_control(struct usbi_transfer *itransfer) {
	PRINT_UNSUPPORTED_API(abort_control);
}
static int unsupported_abort_transfers(struct usbi_transfer *itransfer) {
	PRINT_UNSUPPORTED_API(abort_transfers);
}
static int unsupported_copy_transfer_data(struct usbi_transfer *itransfer, uint32_t io_size) {
	PRINT_UNSUPPORTED_API(copy_transfer_data);
}

// These names must be uppercase
const char* composite_driver_names[] = {"USBCCGP"};
const char* winusb_driver_names[] = {"WINUSB"};
const struct windows_usb_api_backend usb_api_backend[USB_API_MAX] = {
	{
		USB_API_UNSUPPORTED,
		"Unsupported API",
		&CLASS_GUID_UNSUPPORTED,
		NULL,
		0,
		unsupported_init,
		unsupported_exit,
		unsupported_open,
		unsupported_close,
		unsupported_claim_interface,
		unsupported_set_interface_altsetting,
		unsupported_release_interface,
		unsupported_clear_halt,
		unsupported_reset_device,
		unsupported_submit_bulk_transfer,
		unsupported_submit_iso_transfer,
		unsupported_submit_control_transfer,
		unsupported_abort_control,
		unsupported_abort_transfers,
		unsupported_copy_transfer_data,
	}, {
		USB_API_COMPOSITE,
		"Composite API",
		&CLASS_GUID_COMPOSITE,
		composite_driver_names,
		sizeof(composite_driver_names)/sizeof(composite_driver_names[0]),
		composite_init,
		composite_exit,
		composite_open,
		composite_close,
		composite_claim_interface,
		composite_set_interface_altsetting,
		composite_release_interface,
		composite_clear_halt,
		composite_reset_device,
		composite_submit_bulk_transfer,
		composite_submit_iso_transfer,
		composite_submit_control_transfer,
		composite_abort_control,
		composite_abort_transfers,
		composite_copy_transfer_data,
	}, {
		USB_API_WINUSB,
		"WinUSB API",
		&CLASS_GUID_LIBUSB_WINUSB,
		winusb_driver_names,
		sizeof(winusb_driver_names)/sizeof(winusb_driver_names[0]),
		winusb_init,
		winusb_exit,
		winusb_open,
		winusb_close,
		winusb_claim_interface,
		winusb_set_interface_altsetting,
		winusb_release_interface,
		winusb_clear_halt,
		winusb_reset_device,
		winusb_submit_bulk_transfer,
		unsupported_submit_iso_transfer,
		winusb_submit_control_transfer,
		winusb_abort_control,
		winusb_abort_transfers,
		winusb_copy_transfer_data,
	},
};


/*
 * WinUSB API functions
 */
static int winusb_init(struct libusb_context *ctx)
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

static int winusb_exit(void)
{
	return LIBUSB_SUCCESS;
}

// NB: open and close must ensure that they only handle interface of
// the right API type, as these functions can be called wholesale from
// composite_open(), with interfaces belonging to different APIs
static int winusb_open(struct libusb_device_handle *dev_handle)
{
	struct libusb_context *ctx = DEVICE_CTX(dev_handle->dev);
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);
	struct windows_device_handle_priv *handle_priv = __device_handle_priv(dev_handle);

	HANDLE file_handle;
	int i;

	CHECK_WINUSB_AVAILABLE;

	// WinUSB requires a seperate handle for each interface
	for (i = 0; i < USB_MAXINTERFACES; i++) {
		if ( (priv->usb_interface[i].path != NULL)
		  && (priv->usb_interface[i].apib->id == USB_API_WINUSB) ) {
			file_handle = CreateFileA(priv->usb_interface[i].path, GENERIC_WRITE | GENERIC_READ, FILE_SHARE_WRITE | FILE_SHARE_READ,
				NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
			if (file_handle == INVALID_HANDLE_VALUE) {
				usbi_err(ctx, "could not open device %s (interface %d): %s", priv->usb_interface[i].path, i, windows_error_str(0));
				switch(GetLastError()) {
				case ERROR_FILE_NOT_FOUND:	// The device was disconnected
					return LIBUSB_ERROR_NO_DEVICE;
				case ERROR_ACCESS_DENIED:
					return LIBUSB_ERROR_ACCESS;
				default:
					return LIBUSB_ERROR_IO;
				}
			}
			handle_priv->interface_handle[i].dev_handle = file_handle;
		}
	}

	return LIBUSB_SUCCESS;
}

static void winusb_close(struct libusb_device_handle *dev_handle)
{
	struct windows_device_handle_priv *handle_priv = __device_handle_priv(dev_handle);
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);
	HANDLE file_handle;
	int i;

	if (!api_winusb_available)
		return;

	for (i = 0; i < USB_MAXINTERFACES; i++) {
		if (priv->usb_interface[i].apib->id == USB_API_WINUSB) {
			file_handle = handle_priv->interface_handle[i].dev_handle;
			if ( (file_handle != 0) && (file_handle != INVALID_HANDLE_VALUE)) {
				CloseHandle(file_handle);
			}
		}
	}
}

static int winusb_claim_interface(struct libusb_device_handle *dev_handle, int iface)
{
	struct libusb_context *ctx = DEVICE_CTX(dev_handle->dev);
	struct windows_device_handle_priv *handle_priv = __device_handle_priv(dev_handle);
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);
	bool is_using_usbccgp = (priv->apib->id == USB_API_COMPOSITE);
	HANDLE file_handle, winusb_handle;
	UCHAR policy;
	uint8_t endpoint_address;
	int i;

	CHECK_WINUSB_AVAILABLE;

	// If the device is composite, but using the default Windows composite parent driver (usbccgp)
	// or if it's the first WinUSB interface, we get a handle through WinUsb_Initialize().
	if ((is_using_usbccgp) || (iface == 0)) {
		// composite device (independent interfaces) or interface 0
		winusb_handle = handle_priv->interface_handle[iface].api_handle;
		file_handle = handle_priv->interface_handle[iface].dev_handle;
		if ((file_handle == 0) || (file_handle == INVALID_HANDLE_VALUE)) {
			return LIBUSB_ERROR_NOT_FOUND;
		}

		if (!WinUsb_Initialize(file_handle, &winusb_handle)) {
			usbi_err(ctx, "could not access interface %d: %s", iface, windows_error_str(0));
			handle_priv->interface_handle[iface].api_handle = INVALID_HANDLE_VALUE;

			switch(GetLastError()) {
			case ERROR_BAD_COMMAND:	// The device was disconnected
				return LIBUSB_ERROR_NO_DEVICE;
			default:
				usbi_err(ctx, "could not claim interface %d: %s", iface, windows_error_str(0));
				return LIBUSB_ERROR_ACCESS;
			}
		}
		handle_priv->interface_handle[iface].api_handle = winusb_handle;
	} else {
		// For all other interfaces, use WinUsb_GetAssociatedInterface()
		winusb_handle = handle_priv->interface_handle[0].api_handle;
		// It is a requirement for multiple interface devices using WinUSB that you
		// must first claim the first interface before you claim any other
		if ((winusb_handle == 0) || (winusb_handle == INVALID_HANDLE_VALUE)) {
#if defined(AUTO_CLAIM)
			file_handle = handle_priv->interface_handle[0].dev_handle;
			if (WinUsb_Initialize(file_handle, &winusb_handle)) {
				handle_priv->interface_handle[0].api_handle = winusb_handle;
				usbi_warn(ctx, "auto-claimed interface 0 (required to claim %d with WinUSB)", iface);
			} else {
				usbi_warn(ctx, "failed to auto-claim interface 0 (required to claim %d with WinUSB)", iface);
				return LIBUSB_ERROR_ACCESS;
			}
#else
			usbi_warn(ctx, "you must claim interface 0 before you can claim %d with WinUSB", iface);
			return LIBUSB_ERROR_ACCESS;
#endif
		}
		if (!WinUsb_GetAssociatedInterface(winusb_handle, (UCHAR)(iface-1),
			&handle_priv->interface_handle[iface].api_handle)) {
			handle_priv->interface_handle[iface].api_handle = INVALID_HANDLE_VALUE;
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
	}
	usbi_dbg("claimed interface %d", iface);
	handle_priv->active_interface = iface;

	// With handle and enpoints set (in parent), we can setup the default
	// pipe properties (copied from libusb-win32-v1)
	// see http://download.microsoft.com/download/D/1/D/D1DD7745-426B-4CC3-A269-ABBBE427C0EF/DVC-T705_DDC08.pptx
	for (i=0; i<priv->usb_interface[iface].nb_endpoints; i++) {
		endpoint_address = priv->usb_interface[iface].endpoint[i];
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
	struct windows_device_handle_priv *handle_priv = __device_handle_priv(dev_handle);
	HANDLE winusb_handle;

	CHECK_WINUSB_AVAILABLE;

	winusb_handle = handle_priv->interface_handle[iface].api_handle;
	if ((winusb_handle == 0) || (winusb_handle == INVALID_HANDLE_VALUE)) {
		return LIBUSB_ERROR_NOT_FOUND;
	}

	WinUsb_Free(winusb_handle);
	handle_priv->interface_handle[iface].api_handle = INVALID_HANDLE_VALUE;

	return LIBUSB_SUCCESS;
}

/*
 * Return the first valid interface (of the same API type), for control transfers
 */
static int winusb_get_valid_interface(struct libusb_device_handle *dev_handle)
{
	struct windows_device_handle_priv *handle_priv = __device_handle_priv(dev_handle);
	int i;

	for (i=0; i<USB_MAXINTERFACES; i++) {
		if ( (handle_priv->interface_handle[i].dev_handle != 0)
		  && (handle_priv->interface_handle[i].dev_handle != INVALID_HANDLE_VALUE)
		  && (handle_priv->interface_handle[i].api_handle != 0)
		  && (handle_priv->interface_handle[i].api_handle != INVALID_HANDLE_VALUE) ) {
			return i;
		}
	}
	return -1;
}

/*
 * Lookup interface by endpoint address. -1 if not found
 */
static int interface_by_endpoint(struct windows_device_priv *priv,
	struct windows_device_handle_priv *handle_priv, uint8_t endpoint_address)
{
	int i, j;
	for (i=0; i<USB_MAXINTERFACES; i++) {
		if (handle_priv->interface_handle[i].api_handle == INVALID_HANDLE_VALUE)
			continue;
		if (handle_priv->interface_handle[i].api_handle == 0)
			continue;
		if (priv->usb_interface[i].endpoint == NULL)
			continue;
		for (j=0; j<priv->usb_interface[i].nb_endpoints; j++) {
			if (priv->usb_interface[i].endpoint[j] == endpoint_address) {
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
	struct windows_device_handle_priv *handle_priv = __device_handle_priv(
		transfer->dev_handle);
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

	current_interface = winusb_get_valid_interface(transfer->dev_handle);
	if (current_interface < 0) {
#if defined(AUTO_CLAIM)
		if (auto_claim(transfer, &current_interface, USB_API_WINUSB) != LIBUSB_SUCCESS) {
			return LIBUSB_ERROR_NOT_FOUND;
		}
#else
		usbi_warn(ctx, "no interface available for control transfer");
		return LIBUSB_ERROR_NOT_FOUND;
#endif
	}

	usbi_dbg("will use interface %d", current_interface);
	winusb_handle = handle_priv->interface_handle[current_interface].api_handle;

	wfd = usbi_create_fd(winusb_handle, _O_RDONLY);
	// Always use the handle returned from usbi_create_fd (wfd.handle)
	if (wfd.fd < 0) {
		return LIBUSB_ERROR_NO_MEM;
	}

	if (!WinUsb_ControlTransfer(wfd.handle, *setup, transfer->buffer + LIBUSB_CONTROL_SETUP_SIZE, size, NULL, wfd.overlapped)) {
		if(GetLastError() != ERROR_IO_PENDING) {
			usbi_err(ctx, "WinUsb_ControlTransfer failed: %s", windows_error_str(0));
			usbi_free_fd(wfd.fd);
			return LIBUSB_ERROR_IO;
		}
	} else {
		wfd.overlapped->Internal = STATUS_COMPLETED_SYNCHRONOUSLY;
		wfd.overlapped->InternalHigh = (DWORD)size;
	}

	// Use priv_transfer to store data needed for async polling
	transfer_priv->pollable_fd = wfd;
	transfer_priv->interface_number = (uint8_t)current_interface;

	return LIBUSB_SUCCESS;
}

static int winusb_set_interface_altsetting(struct libusb_device_handle *dev_handle, int iface, int altsetting)
{
	struct libusb_context *ctx = DEVICE_CTX(dev_handle->dev);
	struct windows_device_handle_priv *handle_priv = __device_handle_priv(dev_handle);
	HANDLE winusb_handle;

	CHECK_WINUSB_AVAILABLE;

	if (altsetting > 255) {
		return LIBUSB_ERROR_INVALID_PARAM;
	}

	winusb_handle = handle_priv->interface_handle[iface].api_handle;
	if ((winusb_handle == 0) || (winusb_handle == INVALID_HANDLE_VALUE)) {
		usbi_err(ctx, "interface must be claimed first");
		return LIBUSB_ERROR_NOT_FOUND;
	}

	if (!WinUsb_SetCurrentAlternateSetting(winusb_handle, (UCHAR)altsetting)) {
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
	struct windows_device_handle_priv *handle_priv = __device_handle_priv(transfer->dev_handle);
	struct windows_device_priv *priv = __device_priv(transfer->dev_handle->dev);
	HANDLE winusb_handle;
	bool direction_in, ret;
	int current_interface;
	struct winfd wfd;

	CHECK_WINUSB_AVAILABLE;

	transfer_priv->pollable_fd = INVALID_WINFD;

	current_interface = interface_by_endpoint(priv, handle_priv, transfer->endpoint);
	if (current_interface < 0) {
		usbi_err(ctx, "unable to match endpoint to an open interface - cancelling transfer");
		return LIBUSB_ERROR_NOT_FOUND;
	}

	usbi_dbg("matched endpoint %02X with interface %d", transfer->endpoint, current_interface);

	winusb_handle = handle_priv->interface_handle[current_interface].api_handle;
	direction_in = transfer->endpoint & LIBUSB_ENDPOINT_IN;

	wfd = usbi_create_fd(winusb_handle, direction_in?_O_RDONLY:_O_WRONLY);
	// Always use the handle returned from usbi_create_fd (wfd.handle)
	if (wfd.fd < 0) {
		return LIBUSB_ERROR_NO_MEM;
	}

	if (direction_in) {
		usbi_dbg("reading %d bytes", transfer->length);
		ret = WinUsb_ReadPipe(wfd.handle, transfer->endpoint, transfer->buffer, transfer->length, NULL, wfd.overlapped);
	} else {
		usbi_dbg("writing %d bytes", transfer->length);
		ret = WinUsb_WritePipe(wfd.handle, transfer->endpoint, transfer->buffer, transfer->length, NULL, wfd.overlapped);
	}
	if (!ret) {
		if(GetLastError() != ERROR_IO_PENDING) {
			usbi_err(ctx, "WinUsb_Pipe Transfer failed: %s", windows_error_str(0));
			usbi_free_fd(wfd.fd);
			return LIBUSB_ERROR_IO;
		}
	} else {
		wfd.overlapped->Internal = STATUS_COMPLETED_SYNCHRONOUSLY;
		wfd.overlapped->InternalHigh = (DWORD)transfer->length;
	}

	transfer_priv->pollable_fd = wfd;
	transfer_priv->interface_number = (uint8_t)current_interface;

	return LIBUSB_SUCCESS;
}

static int winusb_clear_halt(struct libusb_device_handle *dev_handle, unsigned char endpoint)
{
	struct libusb_context *ctx = DEVICE_CTX(dev_handle->dev);
	struct windows_device_handle_priv *handle_priv = __device_handle_priv(dev_handle);
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);
	HANDLE winusb_handle;
	int current_interface;

	CHECK_WINUSB_AVAILABLE;

	current_interface = interface_by_endpoint(priv, handle_priv, endpoint);
	if (current_interface < 0) {
		usbi_err(ctx, "unable to match endpoint to an open interface - cannot clear");
		return LIBUSB_ERROR_NOT_FOUND;
	}

	usbi_dbg("matched endpoint %02X with interface %d", endpoint, current_interface);
	winusb_handle = handle_priv->interface_handle[current_interface].api_handle;

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
	struct windows_device_handle_priv *handle_priv = __device_handle_priv(transfer->dev_handle);
	struct windows_transfer_priv *transfer_priv = usbi_transfer_get_os_priv(itransfer);
	HANDLE winusb_handle;
	int current_interface;

	CHECK_WINUSB_AVAILABLE;

	current_interface = transfer_priv->interface_number;
	if ((current_interface < 0) || (current_interface >= USB_MAXINTERFACES)) {
		usbi_err(ctx, "program assertion failed: invalid interface_number");
		return LIBUSB_ERROR_NOT_FOUND;
	}
	usbi_dbg("will use interface %d", current_interface);

	winusb_handle = handle_priv->interface_handle[current_interface].api_handle;

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
// TODO (2nd official release): see if we can force eject the device and redetect it (reuse hotplug?)
static int winusb_reset_device(struct libusb_device_handle *dev_handle)
{
	struct libusb_context *ctx = DEVICE_CTX(dev_handle->dev);
	struct windows_device_handle_priv *handle_priv = __device_handle_priv(dev_handle);
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);
	struct winfd wfd;
	HANDLE winusb_handle;
	int i, j;

	CHECK_WINUSB_AVAILABLE;

	// Reset any available pipe (except control)
	for (i=0; i<USB_MAXINTERFACES; i++) {
		winusb_handle = handle_priv->interface_handle[i].api_handle;
		for (wfd = handle_to_winfd(winusb_handle); wfd.fd > 0;)
		{
			// Cancel any pollable I/O
			usbi_remove_pollfd(ctx, wfd.fd);
			usbi_free_fd(wfd.fd);
			wfd = handle_to_winfd(winusb_handle);
		}

		if ( (winusb_handle != 0) && (winusb_handle != INVALID_HANDLE_VALUE)) {
			for (j=0; j<priv->usb_interface[i].nb_endpoints; j++) {
				usbi_dbg("resetting ep %02X", priv->usb_interface[i].endpoint[j]);
				if (!WinUsb_AbortPipe(winusb_handle, priv->usb_interface[i].endpoint[j])) {
					usbi_err(ctx, "WinUsb_AbortPipe (pipe address %02X) failed: %s",
						priv->usb_interface[i].endpoint[j], windows_error_str(0));
				}
				// FlushPipe seems to fail on OUT pipes
				if ( (priv->usb_interface[i].endpoint[j] & LIBUSB_ENDPOINT_IN)
				  && (!WinUsb_FlushPipe(winusb_handle, priv->usb_interface[i].endpoint[j])) ) {
					usbi_err(ctx, "WinUsb_FlushPipe (pipe address %02X) failed: %s",
						priv->usb_interface[i].endpoint[j], windows_error_str(0));
				}
				if (!WinUsb_ResetPipe(winusb_handle, priv->usb_interface[i].endpoint[j])) {
					usbi_err(ctx, "WinUsb_ResetPipe (pipe address %02X) failed: %s",
						priv->usb_interface[i].endpoint[j], windows_error_str(0));
				}
			}
		}
	}

	return LIBUSB_SUCCESS;
}

static int winusb_copy_transfer_data(struct usbi_transfer *itransfer, uint32_t io_size)
{
	itransfer->transferred += io_size;
	return LIBUSB_TRANSFER_COMPLETED;
}


/*
 * Composite API functions
 */
static int composite_init(struct libusb_context *ctx)
{
	return LIBUSB_SUCCESS;
}

static int composite_exit(void)
{
	return LIBUSB_SUCCESS;
}

static int composite_open(struct libusb_device_handle *dev_handle)
{
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);
	unsigned api;
	int r;
	uint8_t flag = 1<<USB_API_WINUSB;

	for (api=USB_API_WINUSB; api<USB_API_MAX; api++) {
		if (priv->composite_api_flags & flag) {
			r = usb_api_backend[api].open(dev_handle);
			if (r != LIBUSB_SUCCESS) {
				return r;
			}
		}
		flag <<= 1;
	}
	return LIBUSB_SUCCESS;
}

static void composite_close(struct libusb_device_handle *dev_handle)
{
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);
	unsigned api;
	uint8_t flag = 1<<USB_API_WINUSB;

	for (api=USB_API_WINUSB; api<USB_API_MAX; api++) {
		if (priv->composite_api_flags & flag) {
			usb_api_backend[api].close(dev_handle);
		}
		flag <<= 1;
	}
}

static int composite_claim_interface(struct libusb_device_handle *dev_handle, int iface)
{
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);
	return priv->usb_interface[iface].apib->claim_interface(dev_handle, iface);
}

static int composite_set_interface_altsetting(struct libusb_device_handle *dev_handle, int iface, int altsetting)
{
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);
	return priv->usb_interface[iface].apib->set_interface_altsetting(dev_handle, iface, altsetting);
}

static int composite_release_interface(struct libusb_device_handle *dev_handle, int iface)
{
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);
	return priv->usb_interface[iface].apib->release_interface(dev_handle, iface);
}

static int composite_submit_control_transfer(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = __USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct libusb_context *ctx = DEVICE_CTX(transfer->dev_handle->dev);
	struct windows_device_priv *priv = __device_priv(transfer->dev_handle->dev);
	int i;

	for (i=0; i<USB_MAXINTERFACES; i++) {
		if (priv->usb_interface[i].path != NULL) {
			usbi_dbg("using interface %d", i);
			return priv->usb_interface[i].apib->submit_control_transfer(itransfer);
		}
	}

	usbi_err(ctx, "no libusb supported interfaces to complete request");
	return LIBUSB_ERROR_NOT_FOUND;
}

static int composite_submit_bulk_transfer(struct usbi_transfer *itransfer) {
	struct libusb_transfer *transfer = __USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct libusb_context *ctx = DEVICE_CTX(transfer->dev_handle->dev);
	struct windows_device_handle_priv *handle_priv = __device_handle_priv(transfer->dev_handle);
	struct windows_device_priv *priv = __device_priv(transfer->dev_handle->dev);
	int current_interface;

	current_interface = interface_by_endpoint(priv, handle_priv, transfer->endpoint);
	if (current_interface < 0) {
		usbi_err(ctx, "unable to match endpoint to an open interface - cancelling transfer");
		return LIBUSB_ERROR_NOT_FOUND;
	}

	return priv->usb_interface[current_interface].apib->submit_bulk_transfer(itransfer);
}

static int composite_submit_iso_transfer(struct usbi_transfer *itransfer) {
	struct libusb_transfer *transfer = __USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct libusb_context *ctx = DEVICE_CTX(transfer->dev_handle->dev);
	struct windows_device_handle_priv *handle_priv = __device_handle_priv(transfer->dev_handle);
	struct windows_device_priv *priv = __device_priv(transfer->dev_handle->dev);
	int current_interface;

	current_interface = interface_by_endpoint(priv, handle_priv, transfer->endpoint);
	if (current_interface < 0) {
		usbi_err(ctx, "unable to match endpoint to an open interface - cancelling transfer");
		return LIBUSB_ERROR_NOT_FOUND;
	}

	return priv->usb_interface[current_interface].apib->submit_iso_transfer(itransfer);
}

static int composite_clear_halt(struct libusb_device_handle *dev_handle, unsigned char endpoint)
{
	struct libusb_context *ctx = DEVICE_CTX(dev_handle->dev);
	struct windows_device_handle_priv *handle_priv = __device_handle_priv(dev_handle);
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);
	int current_interface;

	current_interface = interface_by_endpoint(priv, handle_priv, endpoint);
	if (current_interface < 0) {
		usbi_err(ctx, "unable to match endpoint to an open interface - cannot clear");
		return LIBUSB_ERROR_NOT_FOUND;
	}

	return priv->usb_interface[current_interface].apib->clear_halt(dev_handle, endpoint);
}

static int composite_abort_control(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = __USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct windows_transfer_priv *transfer_priv = usbi_transfer_get_os_priv(itransfer);
	struct windows_device_priv *priv = __device_priv(transfer->dev_handle->dev);

	return priv->usb_interface[transfer_priv->interface_number].apib->abort_control(itransfer);
}

static int composite_abort_transfers(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = __USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct windows_transfer_priv *transfer_priv = usbi_transfer_get_os_priv(itransfer);
	struct windows_device_priv *priv = __device_priv(transfer->dev_handle->dev);

	return priv->usb_interface[transfer_priv->interface_number].apib->abort_transfers(itransfer);
}

static int composite_reset_device(struct libusb_device_handle *dev_handle)
{
	struct windows_device_priv *priv = __device_priv(dev_handle->dev);
	unsigned api;
	int r;
	uint8_t flag = 1<<USB_API_WINUSB;

	for (api=USB_API_WINUSB; api<USB_API_MAX; api++) {
		if (priv->composite_api_flags & flag) {
			r = usb_api_backend[api].reset_device(dev_handle);
			if (r != LIBUSB_SUCCESS) {
				return r;
			}
		}
		flag <<= 1;
	}
	return LIBUSB_SUCCESS;
}

static int composite_copy_transfer_data(struct usbi_transfer *itransfer, uint32_t io_size)
{
	struct libusb_transfer *transfer = __USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct windows_transfer_priv *transfer_priv = usbi_transfer_get_os_priv(itransfer);
	struct windows_device_priv *priv = __device_priv(transfer->dev_handle->dev);

	return priv->usb_interface[transfer_priv->interface_number].apib->copy_transfer_data(itransfer, io_size);
}
