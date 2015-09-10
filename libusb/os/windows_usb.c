/*
 * windows backend for libusb 1.0
 * Copyright © 2009-2012 Pete Batard <pete@akeo.ie>
 * With contributions from Michael Plante, Orin Eman et al.
 * Parts of this code adapted from libusb-win32-v1 by Stephan Meyer
 * HID Reports IOCTLs inspired from HIDAPI by Alan Ott, Signal 11 Software
 * Hash table functions adapted from glibc, by Ulrich Drepper et al.
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

#include "libusbi.h"
#include "poll_windows.h"
#include "windows_usb.h"

// The 2 macros below are used in conjunction with safe loops.
#define LOOP_CHECK(fcall) { r=fcall; if (r != LIBUSB_SUCCESS) continue; }
#define LOOP_BREAK(err) { r=err; continue; }

// Helper prototypes
static int windows_get_active_config_descriptor(struct libusb_device *dev, unsigned char *buffer, size_t len, int *host_endian);
static int windows_clock_gettime(int clk_id, struct timespec *tp);
unsigned __stdcall windows_clock_gettime_threaded(void* param);
// Common calls
static int common_configure_endpoints(int sub_api, struct libusb_device_handle *dev_handle, int iface);

// WinUSB-like API prototypes
static int winusbx_init(int sub_api, struct libusb_context *ctx);
static int winusbx_exit(int sub_api);
static int winusbx_open(int sub_api, struct libusb_device_handle *dev_handle);
static void winusbx_close(int sub_api, struct libusb_device_handle *dev_handle);
static int winusbx_configure_endpoints(int sub_api, struct libusb_device_handle *dev_handle, int iface);
static int winusbx_claim_interface(int sub_api, struct libusb_device_handle *dev_handle, int iface);
static int winusbx_release_interface(int sub_api, struct libusb_device_handle *dev_handle, int iface);
static int winusbx_submit_control_transfer(int sub_api, struct usbi_transfer *itransfer);
static int winusbx_set_interface_altsetting(int sub_api, struct libusb_device_handle *dev_handle, int iface, int altsetting);
static int winusbx_submit_bulk_transfer(int sub_api, struct usbi_transfer *itransfer);
static int winusbx_clear_halt(int sub_api, struct libusb_device_handle *dev_handle, unsigned char endpoint);
static int winusbx_abort_transfers(int sub_api, struct usbi_transfer *itransfer);
static int winusbx_abort_control(int sub_api, struct usbi_transfer *itransfer);
static int winusbx_reset_device(int sub_api, struct libusb_device_handle *dev_handle);
static int winusbx_copy_transfer_data(int sub_api, struct usbi_transfer *itransfer, uint32_t io_size);
// HID API prototypes
static int hid_init(int sub_api, struct libusb_context *ctx);
static int hid_exit(int sub_api);
static int hid_open(int sub_api, struct libusb_device_handle *dev_handle);
static void hid_close(int sub_api, struct libusb_device_handle *dev_handle);
static int hid_claim_interface(int sub_api, struct libusb_device_handle *dev_handle, int iface);
static int hid_release_interface(int sub_api, struct libusb_device_handle *dev_handle, int iface);
static int hid_set_interface_altsetting(int sub_api, struct libusb_device_handle *dev_handle, int iface, int altsetting);
static int hid_submit_control_transfer(int sub_api, struct usbi_transfer *itransfer);
static int hid_submit_bulk_transfer(int sub_api, struct usbi_transfer *itransfer);
static int hid_clear_halt(int sub_api, struct libusb_device_handle *dev_handle, unsigned char endpoint);
static int hid_abort_transfers(int sub_api, struct usbi_transfer *itransfer);
static int hid_reset_device(int sub_api, struct libusb_device_handle *dev_handle);
static int hid_copy_transfer_data(int sub_api, struct usbi_transfer *itransfer, uint32_t io_size);
// Composite API prototypes
static int composite_init(int sub_api, struct libusb_context *ctx);
static int composite_exit(int sub_api);
static int composite_open(int sub_api, struct libusb_device_handle *dev_handle);
static void composite_close(int sub_api, struct libusb_device_handle *dev_handle);
static int composite_claim_interface(int sub_api, struct libusb_device_handle *dev_handle, int iface);
static int composite_set_interface_altsetting(int sub_api, struct libusb_device_handle *dev_handle, int iface, int altsetting);
static int composite_release_interface(int sub_api, struct libusb_device_handle *dev_handle, int iface);
static int composite_submit_control_transfer(int sub_api, struct usbi_transfer *itransfer);
static int composite_submit_bulk_transfer(int sub_api, struct usbi_transfer *itransfer);
static int composite_submit_iso_transfer(int sub_api, struct usbi_transfer *itransfer);
static int composite_clear_halt(int sub_api, struct libusb_device_handle *dev_handle, unsigned char endpoint);
static int composite_abort_transfers(int sub_api, struct usbi_transfer *itransfer);
static int composite_abort_control(int sub_api, struct usbi_transfer *itransfer);
static int composite_reset_device(int sub_api, struct libusb_device_handle *dev_handle);
static int composite_copy_transfer_data(int sub_api, struct usbi_transfer *itransfer, uint32_t io_size);


// Global variables
uint64_t hires_frequency, hires_ticks_to_ps;
const uint64_t epoch_time = UINT64_C(116444736000000000);	// 1970.01.01 00:00:000 in MS Filetime
int windows_version = WINDOWS_UNDEFINED;
static char windows_version_str[128] = "Windows Undefined";
// Concurrency
static int concurrent_usage = -1;
usbi_mutex_t autoclaim_lock;
// Timer thread
HANDLE timer_thread = NULL;
DWORD timer_thread_id = 0;
// API globals
#define CHECK_WINUSBX_AVAILABLE(sub_api) do { if (sub_api == SUB_API_NOTSET) sub_api = priv->sub_api; \
	if (!WinUSBX[sub_api].initialized) return LIBUSB_ERROR_ACCESS; } while(0)
static struct winusb_interface WinUSBX[SUB_API_MAX];
const char* sub_api_name[SUB_API_MAX] = WINUSBX_DRV_NAMES;
bool api_hid_available = false;
#define CHECK_HID_AVAILABLE do { if (!api_hid_available) return LIBUSB_ERROR_ACCESS; } while (0)

static inline BOOLEAN guid_eq(const GUID *guid1, const GUID *guid2) {
	if ((guid1 != NULL) && (guid2 != NULL)) {
		return (memcmp(guid1, guid2, sizeof(GUID)) == 0);
	}
	return false;
}

#if defined(ENABLE_LOGGING)
static char* guid_to_string(const GUID* guid)
{
	static char guid_string[MAX_GUID_STRING_LENGTH];

	if (guid == NULL) return NULL;
	sprintf(guid_string, "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		(unsigned int)guid->Data1, guid->Data2, guid->Data3,
		guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
		guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
	return guid_string;
}
#endif

/*
 * Converts a windows error to human readable string
 * uses retval as errorcode, or, if 0, use GetLastError()
 */
#if defined(ENABLE_LOGGING)
static char *windows_error_str(uint32_t retval)
{
static char err_string[ERR_BUFFER_SIZE];

	DWORD size;
	ssize_t i;
	uint32_t error_code, format_error;

	error_code = retval?retval:GetLastError();

	safe_sprintf(err_string, ERR_BUFFER_SIZE, "[%u] ", error_code);

	// Translate codes returned by SetupAPI. The ones we are dealing with are either
	// in 0x0000xxxx or 0xE000xxxx and can be distinguished from standard error codes.
	// See http://msdn.microsoft.com/en-us/library/windows/hardware/ff545011.aspx
	switch (error_code & 0xE0000000) {
	case 0:
		error_code = HRESULT_FROM_WIN32(error_code);	// Still leaves ERROR_SUCCESS unmodified
		break;
	case 0xE0000000:
		error_code =  0x80000000 | (FACILITY_SETUPAPI << 16) | (error_code & 0x0000FFFF);
		break;
	default:
		break;
	}

	size = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, error_code,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), &err_string[safe_strlen(err_string)],
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
		for (i=safe_strlen(err_string)-1; (i>=0) && ((err_string[i]==0x0A) || (err_string[i]==0x0D)); i--) {
			err_string[i] = 0;
		}
	}
	return err_string;
}
#endif

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

	// Microsoft indiscriminately uses '\\?\', '\\.\', '##?#" or "##.#" for root prefixes.
	if (!((size > 3) && (((path[0] == '\\') && (path[1] == '\\') && (path[3] == '\\')) ||
		((path[0] == '#') && (path[1] == '#') && (path[3] == '#'))))) {
		add_root = root_size;
		size += add_root;
	}

	if ((ret_path = (char*) calloc(size, 1)) == NULL)
		return NULL;

	safe_strcpy(&ret_path[add_root], size-add_root, path);

	// Ensure consistency with root prefix
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
	// Prefixed to avoid conflict with header files
	DLL_LOAD_PREFIXED(OLE32.dll, p, CLSIDFromString, TRUE);
	DLL_LOAD_PREFIXED(SetupAPI.dll, p, SetupDiGetClassDevsA, TRUE);
	DLL_LOAD_PREFIXED(SetupAPI.dll, p, SetupDiEnumDeviceInfo, TRUE);
	DLL_LOAD_PREFIXED(SetupAPI.dll, p, SetupDiEnumDeviceInterfaces, TRUE);
	DLL_LOAD_PREFIXED(SetupAPI.dll, p, SetupDiGetDeviceInterfaceDetailA, TRUE);
	DLL_LOAD_PREFIXED(SetupAPI.dll, p, SetupDiDestroyDeviceInfoList, TRUE);
	DLL_LOAD_PREFIXED(SetupAPI.dll, p, SetupDiOpenDevRegKey, TRUE);
	DLL_LOAD_PREFIXED(SetupAPI.dll, p, SetupDiGetDeviceRegistryPropertyA, TRUE);
	DLL_LOAD_PREFIXED(SetupAPI.dll, p, SetupDiOpenDeviceInterfaceRegKey, TRUE);
	DLL_LOAD_PREFIXED(AdvAPI32.dll, p, RegQueryValueExW, TRUE);
	DLL_LOAD_PREFIXED(AdvAPI32.dll, p, RegCloseKey, TRUE);
	DLL_LOAD_PREFIXED(User32.dll, p, GetMessageA, TRUE);
	DLL_LOAD_PREFIXED(User32.dll, p, PeekMessageA, TRUE);
	DLL_LOAD_PREFIXED(User32.dll, p, PostThreadMessageA, TRUE);
	return LIBUSB_SUCCESS;
}

/*
 * enumerate interfaces for the whole USB class
 *
 * Parameters:
 * dev_info: a pointer to a dev_info list
 * dev_info_data: a pointer to an SP_DEVINFO_DATA to be filled (or NULL if not needed)
 * usb_class: the generic USB class for which to retrieve interface details
 * index: zero based index of the interface in the device info list
 *
 * Note: it is the responsibility of the caller to free the DEVICE_INTERFACE_DETAIL_DATA
 * structure returned and call this function repeatedly using the same guid (with an
 * incremented index starting at zero) until all interfaces have been returned.
 */
static bool get_devinfo_data(struct libusb_context *ctx,
	HDEVINFO *dev_info, SP_DEVINFO_DATA *dev_info_data, const char* usb_class, unsigned _index)
{
	if (_index <= 0) {
		*dev_info = pSetupDiGetClassDevsA(NULL, usb_class, NULL, DIGCF_PRESENT|DIGCF_ALLCLASSES);
		if (*dev_info == INVALID_HANDLE_VALUE) {
			return false;
		}
	}

	dev_info_data->cbSize = sizeof(SP_DEVINFO_DATA);
	if (!pSetupDiEnumDeviceInfo(*dev_info, _index, dev_info_data)) {
		if (GetLastError() != ERROR_NO_MORE_ITEMS) {
			usbi_err(ctx, "Could not obtain device info data for index %u: %s",
				_index, windows_error_str(0));
		}
		pSetupDiDestroyDeviceInfoList(*dev_info);
		*dev_info = INVALID_HANDLE_VALUE;
		return false;
	}
	return true;
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
static SP_DEVICE_INTERFACE_DETAIL_DATA_A *get_interface_details(struct libusb_context *ctx,
	HDEVINFO *dev_info, SP_DEVINFO_DATA *dev_info_data, const GUID* guid, unsigned _index)
{
	SP_DEVICE_INTERFACE_DATA dev_interface_data;
	SP_DEVICE_INTERFACE_DETAIL_DATA_A *dev_interface_details = NULL;
	DWORD size;

	if (_index <= 0) {
		*dev_info = pSetupDiGetClassDevsA(guid, NULL, NULL, DIGCF_PRESENT|DIGCF_DEVICEINTERFACE);
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
	if (!pSetupDiEnumDeviceInterfaces(*dev_info, NULL, guid, _index, &dev_interface_data)) {
		if (GetLastError() != ERROR_NO_MORE_ITEMS) {
			usbi_err(ctx, "Could not obtain interface data for index %u: %s",
				_index, windows_error_str(0));
		}
		pSetupDiDestroyDeviceInfoList(*dev_info);
		*dev_info = INVALID_HANDLE_VALUE;
		return NULL;
	}

	// Read interface data (dummy + actual) to access the device path
	if (!pSetupDiGetDeviceInterfaceDetailA(*dev_info, &dev_interface_data, NULL, 0, &size, NULL)) {
		// The dummy call should fail with ERROR_INSUFFICIENT_BUFFER
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			usbi_err(ctx, "could not access interface data (dummy) for index %u: %s",
				_index, windows_error_str(0));
			goto err_exit;
		}
	} else {
		usbi_err(ctx, "program assertion failed - http://msdn.microsoft.com/en-us/library/ms792901.aspx is wrong.");
		goto err_exit;
	}

	if ((dev_interface_details = (SP_DEVICE_INTERFACE_DETAIL_DATA_A*) calloc(size, 1)) == NULL) {
		usbi_err(ctx, "could not allocate interface data for index %u.", _index);
		goto err_exit;
	}

	dev_interface_details->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_A);
	if (!pSetupDiGetDeviceInterfaceDetailA(*dev_info, &dev_interface_data,
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

/* For libusb0 filter */
static SP_DEVICE_INTERFACE_DETAIL_DATA_A *get_interface_details_filter(struct libusb_context *ctx,
	HDEVINFO *dev_info, SP_DEVINFO_DATA *dev_info_data, const GUID* guid, unsigned _index, char* filter_path){
	SP_DEVICE_INTERFACE_DATA dev_interface_data;
	SP_DEVICE_INTERFACE_DETAIL_DATA_A *dev_interface_details = NULL;
	DWORD size;
	if (_index <= 0) {
		*dev_info = pSetupDiGetClassDevsA(guid, NULL, NULL, DIGCF_PRESENT|DIGCF_DEVICEINTERFACE);
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
	if (!pSetupDiEnumDeviceInterfaces(*dev_info, NULL, guid, _index, &dev_interface_data)) {
		if (GetLastError() != ERROR_NO_MORE_ITEMS) {
			usbi_err(ctx, "Could not obtain interface data for index %u: %s",
				_index, windows_error_str(0));
		}
		pSetupDiDestroyDeviceInfoList(*dev_info);
		*dev_info = INVALID_HANDLE_VALUE;
		return NULL;
	}
	// Read interface data (dummy + actual) to access the device path
	if (!pSetupDiGetDeviceInterfaceDetailA(*dev_info, &dev_interface_data, NULL, 0, &size, NULL)) {
		// The dummy call should fail with ERROR_INSUFFICIENT_BUFFER
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			usbi_err(ctx, "could not access interface data (dummy) for index %u: %s",
				_index, windows_error_str(0));
			goto err_exit;
		}
	} else {
		usbi_err(ctx, "program assertion failed - http://msdn.microsoft.com/en-us/library/ms792901.aspx is wrong.");
		goto err_exit;
	}
	if ((dev_interface_details = malloc(size)) == NULL) {
		usbi_err(ctx, "could not allocate interface data for index %u.", _index);
		goto err_exit;
	}
	dev_interface_details->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_A);
	if (!pSetupDiGetDeviceInterfaceDetailA(*dev_info, &dev_interface_data,
		dev_interface_details, size, &size, NULL)) {
		usbi_err(ctx, "could not access interface data (actual) for index %u: %s",
			_index, windows_error_str(0));
	}
	// [trobinso] lookup the libusb0 symbolic index.
	if (dev_interface_details) {
		HKEY hkey_device_interface=pSetupDiOpenDeviceInterfaceRegKey(*dev_info,&dev_interface_data,0,KEY_READ);
		if (hkey_device_interface != INVALID_HANDLE_VALUE) {
			DWORD libusb0_symboliclink_index=0;
			DWORD value_length=sizeof(DWORD);
			DWORD value_type=0;
			LONG status;
			status = pRegQueryValueExW(hkey_device_interface, L"LUsb0", NULL, &value_type,
				(LPBYTE) &libusb0_symboliclink_index, &value_length);
			if (status == ERROR_SUCCESS) {
				if (libusb0_symboliclink_index < 256) {
					// libusb0.sys is connected to this device instance.
					// If the the device interface guid is {F9F3FF14-AE21-48A0-8A25-8011A7A931D9} then it's a filter.
					safe_sprintf(filter_path, sizeof("\\\\.\\libusb0-0000"), "\\\\.\\libusb0-%04d", libusb0_symboliclink_index);
					usbi_dbg("assigned libusb0 symbolic link %s", filter_path);
				} else {
					// libusb0.sys was connected to this device instance at one time; but not anymore.
				}
			}
			pRegCloseKey(hkey_device_interface);
		}
	}
	return dev_interface_details;
err_exit:
	pSetupDiDestroyDeviceInfoList(*dev_info);
	*dev_info = INVALID_HANDLE_VALUE;
	return NULL;}

/* Hash table functions - modified From glibc 2.3.2:
   [Aho,Sethi,Ullman] Compilers: Principles, Techniques and Tools, 1986
   [Knuth]            The Art of Computer Programming, part 3 (6.4)  */
typedef struct htab_entry {
	unsigned long used;
	char* str;
} htab_entry;
htab_entry* htab_table = NULL;
usbi_mutex_t htab_write_mutex = NULL;
unsigned long htab_size, htab_filled;

/* For the used double hash method the table size has to be a prime. To
   correct the user given table size we need a prime test.  This trivial
   algorithm is adequate because the code is called only during init and
   the number is likely to be small  */
static int isprime(unsigned long number)
{
	// no even number will be passed
	unsigned int divider = 3;

	while((divider * divider < number) && (number % divider != 0))
		divider += 2;

	return (number % divider != 0);
}

/* Before using the hash table we must allocate memory for it.
   We allocate one element more as the found prime number says.
   This is done for more effective indexing as explained in the
   comment for the hash function.  */
static int htab_create(struct libusb_context *ctx, unsigned long nel)
{
	if (htab_table != NULL) {
		usbi_err(ctx, "hash table already allocated");
	}

	// Create a mutex
	usbi_mutex_init(&htab_write_mutex, NULL);

	// Change nel to the first prime number not smaller as nel.
	nel |= 1;
	while(!isprime(nel))
		nel += 2;

	htab_size = nel;
	usbi_dbg("using %d entries hash table", nel);
	htab_filled = 0;

	// allocate memory and zero out.
	htab_table = (htab_entry*) calloc(htab_size + 1, sizeof(htab_entry));
	if (htab_table == NULL) {
		usbi_err(ctx, "could not allocate space for hash table");
		return 0;
	}

	return 1;
}

/* After using the hash table it has to be destroyed.  */
static void htab_destroy(void)
{
	size_t i;
	if (htab_table == NULL) {
		return;
	}

	for (i=0; i<htab_size; i++) {
		if (htab_table[i].used) {
			safe_free(htab_table[i].str);
		}
	}
	usbi_mutex_destroy(&htab_write_mutex);
	safe_free(htab_table);
}

/* This is the search function. It uses double hashing with open addressing.
   We use an trick to speed up the lookup. The table is created with one
   more element available. This enables us to use the index zero special.
   This index will never be used because we store the first hash index in
   the field used where zero means not used. Every other value means used.
   The used field can be used as a first fast comparison for equality of
   the stored and the parameter value. This helps to prevent unnecessary
   expensive calls of strcmp.  */
static unsigned long htab_hash(char* str)
{
	unsigned long hval, hval2;
	unsigned long idx;
	unsigned long r = 5381;
	int c;
	char* sz = str;

	if (str == NULL)
		return 0;

	// Compute main hash value (algorithm suggested by Nokia)
	while ((c = *sz++) != 0)
		r = ((r << 5) + r) + c;
	if (r == 0)
		++r;

	// compute table hash: simply take the modulus
	hval = r % htab_size;
	if (hval == 0)
		++hval;

	// Try the first index
	idx = hval;

	if (htab_table[idx].used) {
		if ( (htab_table[idx].used == hval)
		  && (safe_strcmp(str, htab_table[idx].str) == 0) ) {
			// existing hash
			return idx;
		}
		usbi_dbg("hash collision ('%s' vs '%s')", str, htab_table[idx].str);

		// Second hash function, as suggested in [Knuth]
		hval2 = 1 + hval % (htab_size - 2);

		do {
			// Because size is prime this guarantees to step through all available indexes
			if (idx <= hval2) {
				idx = htab_size + idx - hval2;
			} else {
				idx -= hval2;
			}

			// If we visited all entries leave the loop unsuccessfully
			if (idx == hval) {
				break;
			}

			// If entry is found use it.
			if ( (htab_table[idx].used == hval)
			  && (safe_strcmp(str, htab_table[idx].str) == 0) ) {
				return idx;
			}
		}
		while (htab_table[idx].used);
	}

	// Not found => New entry

	// If the table is full return an error
	if (htab_filled >= htab_size) {
		usbi_err(NULL, "hash table is full (%d entries)", htab_size);
		return 0;
	}

	// Concurrent threads might be storing the same entry at the same time
	// (eg. "simultaneous" enums from different threads) => use a mutex
	usbi_mutex_lock(&htab_write_mutex);
	// Just free any previously allocated string (which should be the same as
	// new one). The possibility of concurrent threads storing a collision
	// string (same hash, different string) at the same time is extremely low
	safe_free(htab_table[idx].str);
	htab_table[idx].used = hval;
	htab_table[idx].str = (char*) malloc(safe_strlen(str)+1);
	if (htab_table[idx].str == NULL) {
		usbi_err(NULL, "could not duplicate string for hash table");
		usbi_mutex_unlock(&htab_write_mutex);
		return 0;
	}
	memcpy(htab_table[idx].str, str, safe_strlen(str)+1);
	++htab_filled;
	usbi_mutex_unlock(&htab_write_mutex);

	return idx;
}

/*
 * Returns the session ID of a device's nth level ancestor
 * If there's no device at the nth level, return 0
 */
static unsigned long get_ancestor_session_id(DWORD devinst, unsigned level)
{
	DWORD parent_devinst;
	unsigned long session_id = 0;
	char* sanitized_path = NULL;
	char path[MAX_PATH_LENGTH];
	unsigned i;

	if (level < 1) return 0;
	for (i = 0; i<level; i++) {
		if (CM_Get_Parent(&parent_devinst, devinst, 0) != CR_SUCCESS) {
			return 0;
		}
		devinst = parent_devinst;
	}
	if (CM_Get_Device_IDA(devinst, path, MAX_PATH_LENGTH, 0) != CR_SUCCESS) {
		return 0;
	}
	// TODO: (post hotplug): try without sanitizing
	sanitized_path = sanitize_path(path);
	if (sanitized_path == NULL) {
		return 0;
	}
	session_id = htab_hash(sanitized_path);
	safe_free(sanitized_path);
	return session_id;
}

/*
 * Determine which interface the given endpoint address belongs to
 */
static int get_interface_by_endpoint(struct libusb_config_descriptor *conf_desc, uint8_t ep)
{
	const struct libusb_interface *intf;
	const struct libusb_interface_descriptor *intf_desc;
	int i, j, k;

	for (i = 0; i < conf_desc->bNumInterfaces; i++) {
		intf = &conf_desc->interface[i];
		for (j = 0; j < intf->num_altsetting; j++) {
			intf_desc = &intf->altsetting[j];
			for (k = 0; k < intf_desc->bNumEndpoints; k++) {
				if (intf_desc->endpoint[k].bEndpointAddress == ep) {
					usbi_dbg("found endpoint %02X on interface %d", intf_desc->bInterfaceNumber);
					return intf_desc->bInterfaceNumber;
				}
			}
		}
	}

	usbi_dbg("endpoint %02X not found on any interface", ep);
	return LIBUSB_ERROR_NOT_FOUND;
}

/*
 * Populate the endpoints addresses of the device_priv interface helper structs
 */
static int windows_assign_endpoints(struct libusb_device_handle *dev_handle, int iface, int altsetting)
{
	int i, r;
	struct windows_device_priv *priv = _device_priv(dev_handle->dev);
	struct libusb_config_descriptor *conf_desc;
	const struct libusb_interface_descriptor *if_desc;
	struct libusb_context *ctx = DEVICE_CTX(dev_handle->dev);

	r = libusb_get_config_descriptor(dev_handle->dev, (uint8_t)(priv->active_config-1), &conf_desc);
	if (r != LIBUSB_SUCCESS) {
		usbi_warn(ctx, "could not read config descriptor: error %d", r);
		return r;
	}

	if_desc = &conf_desc->interface[iface].altsetting[altsetting];
	safe_free(priv->usb_interface[iface].endpoint);

	if (if_desc->bNumEndpoints == 0) {
		usbi_dbg("no endpoints found for interface %d", iface);
		libusb_free_config_descriptor(conf_desc);
		return LIBUSB_SUCCESS;
	}

	priv->usb_interface[iface].endpoint = (uint8_t*) malloc(if_desc->bNumEndpoints);
	if (priv->usb_interface[iface].endpoint == NULL) {
		libusb_free_config_descriptor(conf_desc);
		return LIBUSB_ERROR_NO_MEM;
	}

	priv->usb_interface[iface].nb_endpoints = if_desc->bNumEndpoints;
	for (i=0; i<if_desc->bNumEndpoints; i++) {
		priv->usb_interface[iface].endpoint[i] = if_desc->endpoint[i].bEndpointAddress;
		usbi_dbg("(re)assigned endpoint %02X to interface %d", priv->usb_interface[iface].endpoint[i], iface);
	}
	libusb_free_config_descriptor(conf_desc);

	// Extra init may be required to configure endpoints
	return priv->apib->configure_endpoints(SUB_API_NOTSET, dev_handle, iface);
}

// Lookup for a match in the list of API driver names
// return -1 if not found, driver match number otherwise
static int get_sub_api(char* driver, int api){
	int i;
	const char sep_str[2] = {LIST_SEPARATOR, 0};
	char *tok, *tmp_str;
	size_t len = safe_strlen(driver);

	if (len == 0) return SUB_API_NOTSET;
	tmp_str = (char*) calloc(len+1, 1);
	if (tmp_str == NULL) return SUB_API_NOTSET;
	memcpy(tmp_str, driver, len+1);
	tok = strtok(tmp_str, sep_str);
	while (tok != NULL) {
		for (i=0; i<usb_api_backend[api].nb_driver_names; i++) {
			if (safe_stricmp(tok, usb_api_backend[api].driver_name_list[i]) == 0) {
				free(tmp_str);
				return i;
			}
		}
		tok = strtok(NULL, sep_str);
	}
	free (tmp_str);
	return SUB_API_NOTSET;
}

/*
 * auto-claiming and auto-release helper functions
 */
static int auto_claim(struct libusb_transfer *transfer, int *interface_number, int api_type)
{
	struct libusb_context *ctx = DEVICE_CTX(transfer->dev_handle->dev);
	struct windows_device_handle_priv *handle_priv = _device_handle_priv(
		transfer->dev_handle);
	struct windows_device_priv *priv = _device_priv(transfer->dev_handle->dev);
	int current_interface = *interface_number;
	int r = LIBUSB_SUCCESS;

	switch(api_type) {
	case USB_API_WINUSBX:
	case USB_API_HID:
		break;
	default:
		return LIBUSB_ERROR_INVALID_PARAM;
	}

	usbi_mutex_lock(&autoclaim_lock);
	if (current_interface < 0)	// No serviceable interface was found
	{
		for (current_interface=0; current_interface<USB_MAXINTERFACES; current_interface++) {
			// Must claim an interface of the same API type
			if ( (priv->usb_interface[current_interface].apib->id == api_type)
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
	struct windows_transfer_priv *transfer_priv = (struct windows_transfer_priv*)usbi_transfer_get_os_priv(itransfer);
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	libusb_device_handle *dev_handle = transfer->dev_handle;
	struct windows_device_handle_priv* handle_priv = _device_handle_priv(dev_handle);
	int r;

	usbi_mutex_lock(&autoclaim_lock);
	if (handle_priv->autoclaim_count[transfer_priv->interface_number] > 0) {
		handle_priv->autoclaim_count[transfer_priv->interface_number]--;
		if (handle_priv->autoclaim_count[transfer_priv->interface_number] == 0) {
			r = libusb_release_interface(dev_handle, transfer_priv->interface_number);
			if (r == LIBUSB_SUCCESS) {
				usbi_dbg("auto-released interface %d", transfer_priv->interface_number);
			} else {
				usbi_dbg("failed to auto-release interface %d (%s)",
					transfer_priv->interface_number, libusb_error_name((enum libusb_error)r));
			}
		}
	}
	usbi_mutex_unlock(&autoclaim_lock);
}

/* Windows version dtection */
static BOOL is_x64(void)
{
	BOOL ret = FALSE;
	// Detect if we're running a 32 or 64 bit system
	if (sizeof(uintptr_t) < 8) {
		DLL_LOAD_PREFIXED(Kernel32.dll, p, IsWow64Process, FALSE);
		if (pIsWow64Process != NULL) {
			(*pIsWow64Process)(GetCurrentProcess(), &ret);
		}
	} else {
		ret = TRUE;
	}
	return ret;
}

static void get_windows_version(void)
{
	OSVERSIONINFOEXA vi, vi2;
	const char* w = 0;
	const char* w64 = "32 bit";
	char* vptr;
	size_t vlen;
	unsigned major, minor;
	ULONGLONG major_equal, minor_equal;
	BOOL ws;

	memset(&vi, 0, sizeof(vi));
	vi.dwOSVersionInfoSize = sizeof(vi);
	if (!GetVersionExA((OSVERSIONINFOA *)&vi)) {
		memset(&vi, 0, sizeof(vi));
		vi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
		if (!GetVersionExA((OSVERSIONINFOA *)&vi))
			return;
	}

	if (vi.dwPlatformId == VER_PLATFORM_WIN32_NT) {

		if (vi.dwMajorVersion > 6 || (vi.dwMajorVersion == 6 && vi.dwMinorVersion >= 2)) {
			// Starting with Windows 8.1 Preview, GetVersionEx() does no longer report the actual OS version
			// See: http://msdn.microsoft.com/en-us/library/windows/desktop/dn302074.aspx

			major_equal = VerSetConditionMask(0, VER_MAJORVERSION, VER_EQUAL);
			for (major = vi.dwMajorVersion; major <= 9; major++) {
				memset(&vi2, 0, sizeof(vi2));
				vi2.dwOSVersionInfoSize = sizeof(vi2); vi2.dwMajorVersion = major;
				if (!VerifyVersionInfoA(&vi2, VER_MAJORVERSION, major_equal))
					continue;
				if (vi.dwMajorVersion < major) {
					vi.dwMajorVersion = major; vi.dwMinorVersion = 0;
				}

				minor_equal = VerSetConditionMask(0, VER_MINORVERSION, VER_EQUAL);
				for (minor = vi.dwMinorVersion; minor <= 9; minor++) {
					memset(&vi2, 0, sizeof(vi2)); vi2.dwOSVersionInfoSize = sizeof(vi2);
					vi2.dwMinorVersion = minor;
					if (!VerifyVersionInfoA(&vi2, VER_MINORVERSION, minor_equal))
						continue;
					vi.dwMinorVersion = minor;
					break;
				}

				break;
			}
		}

		if (vi.dwMajorVersion <= 0xf && vi.dwMinorVersion <= 0xf) {
			ws = (vi.wProductType <= VER_NT_WORKSTATION);
			windows_version = vi.dwMajorVersion << 4 | vi.dwMinorVersion;
			switch (windows_version) {
			case 0x50: w = "2000";
				break;
			case 0x51: w = "XP";
				break;
			case 0x52: w = ("2003");
				break;
			case 0x60: w = (ws?"Vista":"2008");
				break;
			case 0x61: w = (ws?"7":"2008_R2");
				break;
			case 0x62: w = (ws?"8":"2012");
				break;
			case 0x63: w = (ws?"8.1":"2012_R2");
				break;
			case 0x64: w = (ws?"10":"2015");
				break;
			default:
				if (windows_version < 0x50)
					windows_version = WINDOWS_UNSUPPORTED;
				else
					w = "11 or later";
				break;
			}
		}
	}

	if (is_x64())
		w64 = "64-bit";

	vptr = &windows_version_str[sizeof("Windows ") - 1];
	vlen = sizeof(windows_version_str) - sizeof("Windows ") - 1;
	if (!w)
		safe_sprintf(vptr, vlen, "%s %u.%u %s", (vi.dwPlatformId==VER_PLATFORM_WIN32_NT?"NT":"??"),
			(unsigned)vi.dwMajorVersion, (unsigned)vi.dwMinorVersion, w64);
	else if (vi.wServicePackMinor)
		safe_sprintf(vptr, vlen, "%s SP%u.%u %s", w, vi.wServicePackMajor, vi.wServicePackMinor, w64);
	else if (vi.wServicePackMajor)
		safe_sprintf(vptr, vlen, "%s SP%u %s", w, vi.wServicePackMajor, w64);
	else
		safe_sprintf(vptr, vlen, "%s %s", w, w64);
}

/*
 * init: libusb backend init function
 *
 * This function enumerates the HCDs (Host Controller Drivers) and populates our private HCD list
 * In our implementation, we equate Windows' "HCD" to libusb's "bus". Note that bus is zero indexed.
 * HCDs are not expected to change after init (might not hold true for hot pluggable USB PCI card?)
 */
static int windows_init(struct libusb_context *ctx)
{
	int i, r = LIBUSB_ERROR_OTHER;
	DWORD_PTR affinity, dummy;
	HANDLE event = NULL;
	HANDLE semaphore;
	LARGE_INTEGER li_frequency;
	char sem_name[11+1+8]; // strlen(libusb_init)+'\0'+(32-bit hex PID)

	sprintf(sem_name, "libusb_init%08X", (unsigned int)GetCurrentProcessId()&0xFFFFFFFF);
	semaphore = CreateSemaphoreA(NULL, 1, 1, sem_name);
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
		get_windows_version();
		usbi_dbg(windows_version_str);
		if (windows_version == WINDOWS_UNSUPPORTED) {
			usbi_err(ctx, "This version of Windows is NOT supported");
			r = LIBUSB_ERROR_NOT_SUPPORTED;
			goto init_exit;
		}

		// We need a lock for proper auto-release
		usbi_mutex_init(&autoclaim_lock, NULL);

		// Initialize pollable file descriptors
		init_polling();

		// Load DLL imports
		if (init_dlls() != LIBUSB_SUCCESS) {
			usbi_err(ctx, "could not resolve DLL functions");
			goto init_exit;
		}

		// Initialize the low level APIs (we don't care about errors at this stage)
		for (i=0; i<USB_API_MAX; i++) {
			usb_api_backend[i].init(SUB_API_NOTSET, ctx);
		}

		if (QueryPerformanceFrequency(&li_frequency)) {
			// The hires frequency can go as high as 4 GHz, so we'll use a conversion
			// to picoseconds to compute the tv_nsecs part in clock_gettime
			hires_frequency = li_frequency.QuadPart;
			hires_ticks_to_ps = UINT64_C(1000000000000) / hires_frequency;
			usbi_dbg("hires timer available (Frequency: %"PRIu64" Hz)", hires_frequency);

			// Because QueryPerformanceCounter might report different values when
			// running on different cores, we create a separate thread for the timer
			// calls, which we glue to the first available core always to prevent timing discrepancies.
			if (!GetProcessAffinityMask(GetCurrentProcess(), &affinity, &dummy) || (affinity == 0)) {
				usbi_err(ctx, "could not get process affinity: %s", windows_error_str(0));
				goto init_exit;
			}
			// The process affinity mask is a bitmask where each set bit represents a core on
			// which this process is allowed to run, so we find the first set bit
			for (i = 0; !(affinity & (DWORD_PTR)(1 << i)); i++);
			affinity = (DWORD_PTR)(1 << i);

			usbi_dbg("timer thread will run on core #%d", i);

			r = LIBUSB_ERROR_NO_MEM;
			event = CreateEvent(NULL, FALSE, FALSE, NULL);
			if (event == NULL) {
				usbi_err(ctx, "could not create event: %s", windows_error_str(0));
				goto init_exit;
			}
			timer_thread = (HANDLE)_beginthreadex(NULL, 0, windows_clock_gettime_threaded, (void *)event,
				0, (unsigned int *)&timer_thread_id);
			if (timer_thread == NULL) {
				usbi_err(ctx, "unable to create timer thread - aborting");
				goto init_exit;
			}
			if (!SetThreadAffinityMask(timer_thread, affinity)) {
				usbi_warn(ctx, "unable to set timer thread affinity, timer discrepancies may arise");
			}

			// Wait for timer thread to init before continuing.
			if (WaitForSingleObject(event, INFINITE) != WAIT_OBJECT_0) {
				usbi_err(ctx, "failed to wait for timer thread to become ready - aborting");
				goto init_exit;
			}
		}
		else {
			usbi_dbg("no hires timer available on this platform");
			hires_frequency = 0;
			hires_ticks_to_ps = UINT64_C(0);
		}

		// Create a hash table to store session ids. Second parameter is better if prime
		htab_create(ctx, HTAB_SIZE);
	}
	// At this stage, either we went through full init successfully, or didn't need to
	r = LIBUSB_SUCCESS;

init_exit: // Holds semaphore here.
	if (!concurrent_usage && r != LIBUSB_SUCCESS) { // First init failed?
		if (timer_thread) {
			// actually the signal to quit the thread.
			if (!pPostThreadMessageA(timer_thread_id, WM_TIMER_EXIT, 0, 0) ||
				(WaitForSingleObject(timer_thread, INFINITE) != WAIT_OBJECT_0)) {
				usbi_warn(ctx, "could not wait for timer thread to quit");
				TerminateThread(timer_thread, 1);
				// shouldn't happen, but we're destroying
				// all objects it might have held anyway.
			}
			CloseHandle(timer_thread);
			timer_thread = NULL;
			timer_thread_id = 0;
		}
		htab_destroy();
		usbi_mutex_destroy(&autoclaim_lock);
	}

	if (r != LIBUSB_SUCCESS)
		--concurrent_usage; // Not expected to call libusb_exit if we failed.

	if (event)
		CloseHandle(event);
	ReleaseSemaphore(semaphore, 1, NULL);	// increase count back to 1
	CloseHandle(semaphore);
	return r;
}

/*
 * HCD (root) hubs need to have their device descriptor manually populated
 *
 * Note that, like Microsoft does in the device manager, we populate the
 * Vendor and Device ID for HCD hubs with the ones from the PCI HCD device.
 */
static int force_hcd_device_descriptor(struct libusb_device *dev)
{
	struct windows_device_priv *parent_priv, *priv = _device_priv(dev);
	struct libusb_context *ctx = DEVICE_CTX(dev);
	int vid, pid;

	dev->num_configurations = 1;
	priv->dev_descriptor.bLength = sizeof(USB_DEVICE_DESCRIPTOR);
	priv->dev_descriptor.bDescriptorType = USB_DEVICE_DESCRIPTOR_TYPE;
	priv->dev_descriptor.bNumConfigurations = 1;
	priv->active_config = 1;

	if (priv->parent_dev == NULL) {
		usbi_err(ctx, "program assertion failed - HCD hub has no parent");
		return LIBUSB_ERROR_NO_DEVICE;
	}
	parent_priv = _device_priv(priv->parent_dev);
	if (sscanf(parent_priv->path, "\\\\.\\PCI#VEN_%04x&DEV_%04x%*s", &vid, &pid) == 2) {
		priv->dev_descriptor.idVendor = (uint16_t)vid;
		priv->dev_descriptor.idProduct = (uint16_t)pid;
	} else {
		usbi_warn(ctx, "could not infer VID/PID of HCD hub from '%s'", parent_priv->path);
		priv->dev_descriptor.idVendor = 0x1d6b;		// Linux Foundation root hub
		priv->dev_descriptor.idProduct = 1;
	}
	return LIBUSB_SUCCESS;
}

/*
 * fetch and cache all the config descriptors through I/O
 */
static int cache_config_descriptors(struct libusb_device *dev, HANDLE hub_handle, char* device_id)
{
	DWORD size, ret_size;
	struct libusb_context *ctx = DEVICE_CTX(dev);
	struct windows_device_priv *priv = _device_priv(dev);
	int r;
	uint8_t i;

	USB_CONFIGURATION_DESCRIPTOR_SHORT cd_buf_short;    // dummy request
	PUSB_DESCRIPTOR_REQUEST cd_buf_actual = NULL;       // actual request
	PUSB_CONFIGURATION_DESCRIPTOR cd_data = NULL;

	if (dev->num_configurations == 0)
		return LIBUSB_ERROR_INVALID_PARAM;

	priv->config_descriptor = (unsigned char**) calloc(dev->num_configurations, sizeof(unsigned char*));
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

		cd_buf_short.req.ConnectionIndex = (ULONG)priv->port;
		cd_buf_short.req.SetupPacket.bmRequest = LIBUSB_ENDPOINT_IN;
		cd_buf_short.req.SetupPacket.bRequest = USB_REQUEST_GET_DESCRIPTOR;
		cd_buf_short.req.SetupPacket.wValue = (USB_CONFIGURATION_DESCRIPTOR_TYPE << 8) | i;
		cd_buf_short.req.SetupPacket.wIndex = 0;
		cd_buf_short.req.SetupPacket.wLength = (USHORT)(size - sizeof(USB_DESCRIPTOR_REQUEST));

		// Dummy call to get the required data size. Initial failures are reported as info rather
		// than error as they can occur for non-penalizing situations, such as with some hubs.
		// coverity[tainted_data_argument]
		if (!DeviceIoControl(hub_handle, IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION, &cd_buf_short, size,
			&cd_buf_short, size, &ret_size, NULL)) {
			usbi_info(ctx, "could not access configuration descriptor (dummy) for '%s': %s", device_id, windows_error_str(0));
			LOOP_BREAK(LIBUSB_ERROR_IO);
		}

		if ((ret_size != size) || (cd_buf_short.data.wTotalLength < sizeof(USB_CONFIGURATION_DESCRIPTOR))) {
			usbi_info(ctx, "unexpected configuration descriptor size (dummy) for '%s'.", device_id);
			LOOP_BREAK(LIBUSB_ERROR_IO);
		}

		size = sizeof(USB_DESCRIPTOR_REQUEST) + cd_buf_short.data.wTotalLength;
		if ((cd_buf_actual = (PUSB_DESCRIPTOR_REQUEST) calloc(1, size)) == NULL) {
			usbi_err(ctx, "could not allocate configuration descriptor buffer for '%s'.", device_id);
			LOOP_BREAK(LIBUSB_ERROR_NO_MEM);
		}
		memset(cd_buf_actual, 0, size);

		// Actual call
		cd_buf_actual->ConnectionIndex = (ULONG)priv->port;
		cd_buf_actual->SetupPacket.bmRequest = LIBUSB_ENDPOINT_IN;
		cd_buf_actual->SetupPacket.bRequest = USB_REQUEST_GET_DESCRIPTOR;
		cd_buf_actual->SetupPacket.wValue = (USB_CONFIGURATION_DESCRIPTOR_TYPE << 8) | i;
		cd_buf_actual->SetupPacket.wIndex = 0;
		cd_buf_actual->SetupPacket.wLength = (USHORT)(size - sizeof(USB_DESCRIPTOR_REQUEST));

		if (!DeviceIoControl(hub_handle, IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION, cd_buf_actual, size,
			cd_buf_actual, size, &ret_size, NULL)) {
			usbi_err(ctx, "could not access configuration descriptor (actual) for '%s': %s", device_id, windows_error_str(0));
			LOOP_BREAK(LIBUSB_ERROR_IO);
		}

		cd_data = (PUSB_CONFIGURATION_DESCRIPTOR)((UCHAR*)cd_buf_actual+sizeof(USB_DESCRIPTOR_REQUEST));

		if ((size != ret_size) || (cd_data->wTotalLength != cd_buf_short.data.wTotalLength)) {
			usbi_err(ctx, "unexpected configuration descriptor size (actual) for '%s'.", device_id);
			LOOP_BREAK(LIBUSB_ERROR_IO);
		}

		if (cd_data->bDescriptorType != USB_CONFIGURATION_DESCRIPTOR_TYPE) {
			usbi_err(ctx, "not a configuration descriptor for '%s'", device_id);
			LOOP_BREAK(LIBUSB_ERROR_IO);
		}

		usbi_dbg("cached config descriptor %d (bConfigurationValue=%d, %d bytes)",
			i, cd_data->bConfigurationValue, cd_data->wTotalLength);

		// Cache the descriptor
		priv->config_descriptor[i] = (unsigned char*) malloc(cd_data->wTotalLength);
		if (priv->config_descriptor[i] == NULL)
			LOOP_BREAK(LIBUSB_ERROR_NO_MEM);
		memcpy(priv->config_descriptor[i], cd_data, cd_data->wTotalLength);
	}
	return LIBUSB_SUCCESS;
}

/*
 * Populate a libusb device structure
 */
static int init_device(struct libusb_device* dev, struct libusb_device* parent_dev,
					   uint8_t port_number, char* device_id, DWORD devinst)
{
	HANDLE handle;
	DWORD size;
	USB_NODE_CONNECTION_INFORMATION_EX conn_info;
	USB_NODE_CONNECTION_INFORMATION_EX_V2 conn_info_v2;
	struct windows_device_priv *priv, *parent_priv;
	struct libusb_context *ctx;
	struct libusb_device* tmp_dev;
	unsigned long tmp_id;
	unsigned i;

	if ((dev == NULL) || (parent_dev == NULL)) {
		return LIBUSB_ERROR_NOT_FOUND;
	}
	ctx = DEVICE_CTX(dev);
	priv = _device_priv(dev);
	parent_priv = _device_priv(parent_dev);
	if (parent_priv->apib->id != USB_API_HUB) {
		usbi_warn(ctx, "parent for device '%s' is not a hub", device_id);
		return LIBUSB_ERROR_NOT_FOUND;
	}

	// It is possible for the parent hub not to have been initialized yet
	// If that's the case, lookup the ancestors to set the bus number
	if (parent_dev->bus_number == 0) {
		for (i=2; ; i++) {
			tmp_id = get_ancestor_session_id(devinst, i);
			if (tmp_id == 0) break;
			tmp_dev = usbi_get_device_by_session_id(ctx, tmp_id);
			if (tmp_dev == NULL) continue;
			if (tmp_dev->bus_number != 0) {
				usbi_dbg("got bus number from ancestor #%d", i);
				parent_dev->bus_number = tmp_dev->bus_number;
				libusb_unref_device(tmp_dev);
				break;
			}
			libusb_unref_device(tmp_dev);
		}
	}
	if (parent_dev->bus_number == 0) {
		usbi_err(ctx, "program assertion failed: unable to find ancestor bus number for '%s'", device_id);
		return LIBUSB_ERROR_NOT_FOUND;
	}
	dev->bus_number = parent_dev->bus_number;
	priv->port = port_number;
	dev->port_number = port_number;
	priv->depth = parent_priv->depth + 1;
	priv->parent_dev = parent_dev;
	dev->parent_dev = parent_dev;

	// If the device address is already set, we can stop here
	if (dev->device_address != 0) {
		return LIBUSB_SUCCESS;
	}
	memset(&conn_info, 0, sizeof(conn_info));
	if (priv->depth != 0) {	// Not a HCD hub
		handle = CreateFileA(parent_priv->path, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
			FILE_FLAG_OVERLAPPED, NULL);
		if (handle == INVALID_HANDLE_VALUE) {
			usbi_warn(ctx, "could not open hub %s: %s", parent_priv->path, windows_error_str(0));
			return LIBUSB_ERROR_ACCESS;
		}
		size = sizeof(conn_info);
		conn_info.ConnectionIndex = (ULONG)port_number;
		// coverity[tainted_data_argument]
		if (!DeviceIoControl(handle, IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX, &conn_info, size,
			&conn_info, size, &size, NULL)) {
			usbi_warn(ctx, "could not get node connection information for device '%s': %s",
				device_id, windows_error_str(0));
			safe_closehandle(handle);
			return LIBUSB_ERROR_NO_DEVICE;
		}
		if (conn_info.ConnectionStatus == NoDeviceConnected) {
			usbi_err(ctx, "device '%s' is no longer connected!", device_id);
			safe_closehandle(handle);
			return LIBUSB_ERROR_NO_DEVICE;
		}
		memcpy(&priv->dev_descriptor, &(conn_info.DeviceDescriptor), sizeof(USB_DEVICE_DESCRIPTOR));
		dev->num_configurations = priv->dev_descriptor.bNumConfigurations;
		priv->active_config = conn_info.CurrentConfigurationValue;
		usbi_dbg("found %d configurations (active conf: %d)", dev->num_configurations, priv->active_config);
		// If we can't read the config descriptors, just set the number of confs to zero
		if (cache_config_descriptors(dev, handle, device_id) != LIBUSB_SUCCESS) {
			dev->num_configurations = 0;
			priv->dev_descriptor.bNumConfigurations = 0;
		}

		// In their great wisdom, Microsoft decided to BREAK the USB speed report between Windows 7 and Windows 8
		if (windows_version >= WINDOWS_8) {
			memset(&conn_info_v2, 0, sizeof(conn_info_v2));
			size = sizeof(conn_info_v2);
			conn_info_v2.ConnectionIndex = (ULONG)port_number;
			conn_info_v2.Length = size;
			conn_info_v2.SupportedUsbProtocols.Usb300 = 1;
			if (!DeviceIoControl(handle, IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX_V2,
				&conn_info_v2, size, &conn_info_v2, size, &size, NULL)) {
				usbi_warn(ctx, "could not get node connection information (V2) for device '%s': %s",
					device_id,  windows_error_str(0));
			} else if (conn_info_v2.Flags.DeviceIsOperatingAtSuperSpeedOrHigher) {
				conn_info.Speed = 3;
			}
		}

		safe_closehandle(handle);

		if (conn_info.DeviceAddress > UINT8_MAX) {
			usbi_err(ctx, "program assertion failed: device address overflow");
		}
		dev->device_address = (uint8_t)conn_info.DeviceAddress + 1;
		if (dev->device_address == 1) {
			usbi_err(ctx, "program assertion failed: device address collision with root hub");
		}
		switch (conn_info.Speed) {
		case 0: dev->speed = LIBUSB_SPEED_LOW; break;
		case 1: dev->speed = LIBUSB_SPEED_FULL; break;
		case 2: dev->speed = LIBUSB_SPEED_HIGH; break;
		case 3: dev->speed = LIBUSB_SPEED_SUPER; break;
		default:
			usbi_warn(ctx, "Got unknown device speed %d", conn_info.Speed);
			break;
		}
	} else {
		dev->device_address = 1;	// root hubs are set to use device number 1
		force_hcd_device_descriptor(dev);
	}

	usbi_sanitize_device(dev);

	usbi_dbg("(bus: %d, addr: %d, depth: %d, port: %d): '%s'",
		dev->bus_number, dev->device_address, priv->depth, priv->port, device_id);

	return LIBUSB_SUCCESS;
}

// Returns the api type, or 0 if not found/unsupported
static void get_api_type(struct libusb_context *ctx, HDEVINFO *dev_info,
	SP_DEVINFO_DATA *dev_info_data, int *api, int *sub_api)
{
	// Precedence for filter drivers vs driver is in the order of this array
	struct driver_lookup lookup[3] = {
		{"\0\0", SPDRP_SERVICE, "driver"},
		{"\0\0", SPDRP_UPPERFILTERS, "upper filter driver"},
		{"\0\0", SPDRP_LOWERFILTERS, "lower filter driver"}
	};
	DWORD size, reg_type;
	unsigned k, l;
	int i, j;

	*api = USB_API_UNSUPPORTED;
	*sub_api = SUB_API_NOTSET;
	// Check the service & filter names to know the API we should use
	for (k=0; k<3; k++) {
		if (pSetupDiGetDeviceRegistryPropertyA(*dev_info, dev_info_data, lookup[k].reg_prop,
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
			usbi_dbg("%s(s): %s", lookup[k].designation, lookup[k].list);
		} else {
			if (GetLastError() != ERROR_INVALID_DATA) {
				usbi_dbg("could not access %s: %s", lookup[k].designation, windows_error_str(0));
			}
			lookup[k].list[0] = 0;
		}
	}

	for (i=1; i<USB_API_MAX; i++) {
		for (k=0; k<3; k++) {
			j = get_sub_api(lookup[k].list, i);
			if (j >= 0) {
				usbi_dbg("matched %s name against %s",
					lookup[k].designation, (i!=USB_API_WINUSBX)?usb_api_backend[i].designation:sub_api_name[j]);
				*api = i;
				*sub_api = j;
				return;
			}
		}
	}
}

static int set_composite_interface(struct libusb_context* ctx, struct libusb_device* dev,
							char* dev_interface_path, char* device_id, int api, int sub_api)
{
	unsigned i;
	struct windows_device_priv *priv = _device_priv(dev);
	int interface_number;

	if (priv->apib->id != USB_API_COMPOSITE) {
		usbi_err(ctx, "program assertion failed: '%s' is not composite", device_id);
		return LIBUSB_ERROR_NO_DEVICE;
	}

	// Because MI_## are not necessarily in sequential order (some composite
	// devices will have only MI_00 & MI_03 for instance), we retrieve the actual
	// interface number from the path's MI value
	interface_number = 0;
	for (i=0; device_id[i] != 0; ) {
		if ( (device_id[i++] == 'M') && (device_id[i++] == 'I')
		  && (device_id[i++] == '_') ) {
			interface_number = (device_id[i++] - '0')*10;
			interface_number += device_id[i] - '0';
			break;
		}
	}

	if (device_id[i] == 0) {
		usbi_warn(ctx, "failure to read interface number for %s. Using default value %d",
			device_id, interface_number);
	}

	if (priv->usb_interface[interface_number].path != NULL) {
		if (api == USB_API_HID) {
			// HID devices can have multiple collections (COL##) for each MI_## interface
			usbi_dbg("interface[%d] already set - ignoring HID collection: %s",
				interface_number, device_id);
			return LIBUSB_ERROR_ACCESS;
		}
		// In other cases, just use the latest data
		safe_free(priv->usb_interface[interface_number].path);
	}

	usbi_dbg("interface[%d] = %s", interface_number, dev_interface_path);
	priv->usb_interface[interface_number].path = dev_interface_path;
	priv->usb_interface[interface_number].apib = &usb_api_backend[api];
	priv->usb_interface[interface_number].sub_api = sub_api;
	if ((api == USB_API_HID) && (priv->hid == NULL)) {
		priv->hid = (struct hid_device_priv*) calloc(1, sizeof(struct hid_device_priv));
		if (priv->hid == NULL)
			return LIBUSB_ERROR_NO_MEM;
	}

	return LIBUSB_SUCCESS;
}

static int set_hid_interface(struct libusb_context* ctx, struct libusb_device* dev,
							char* dev_interface_path)
{
	int i;
	struct windows_device_priv *priv = _device_priv(dev);

	if (priv->hid == NULL) {
		usbi_err(ctx, "program assertion failed: parent is not HID");
		return LIBUSB_ERROR_NO_DEVICE;
	}
	if (priv->hid->nb_interfaces == USB_MAXINTERFACES) {
		usbi_err(ctx, "program assertion failed: max USB interfaces reached for HID device");
		return LIBUSB_ERROR_NO_DEVICE;
	}
	for (i=0; i<priv->hid->nb_interfaces; i++) {
		if (safe_strcmp(priv->usb_interface[i].path, dev_interface_path) == 0) {
			usbi_dbg("interface[%d] already set to %s", i, dev_interface_path);
			return LIBUSB_SUCCESS;
		}
	}

	priv->usb_interface[priv->hid->nb_interfaces].path = dev_interface_path;
	priv->usb_interface[priv->hid->nb_interfaces].apib = &usb_api_backend[USB_API_HID];
	usbi_dbg("interface[%d] = %s", priv->hid->nb_interfaces, dev_interface_path);
	priv->hid->nb_interfaces++;
	return LIBUSB_SUCCESS;
}

/*
 * get_device_list: libusb backend device enumeration function
 */
static int windows_get_device_list(struct libusb_context *ctx, struct discovered_devs **_discdevs)
{
	struct discovered_devs *discdevs;
	HDEVINFO dev_info = { 0 };
	const char* usb_class[] = {"USB", "NUSB3", "IUSB3"};
	SP_DEVINFO_DATA dev_info_data = { 0 };
	SP_DEVICE_INTERFACE_DETAIL_DATA_A *dev_interface_details = NULL;
	GUID hid_guid;
#define MAX_ENUM_GUIDS 64
	const GUID* guid[MAX_ENUM_GUIDS];
#define HCD_PASS 0
#define HUB_PASS 1
#define GEN_PASS 2
#define DEV_PASS 3
#define HID_PASS 4
	int r = LIBUSB_SUCCESS;
	int api, sub_api;
	size_t class_index = 0;
	unsigned int nb_guids, pass, i, j, ancestor;
	char path[MAX_PATH_LENGTH];
	char strbuf[MAX_PATH_LENGTH];
	struct libusb_device *dev, *parent_dev;
	struct windows_device_priv *priv, *parent_priv;
	char* dev_interface_path = NULL;
	char* dev_id_path = NULL;
	unsigned long session_id;
	DWORD size, reg_type, port_nr, install_state;
	HKEY key;
	WCHAR guid_string_w[MAX_GUID_STRING_LENGTH];
	GUID* if_guid;
	LONG s;
	// Keep a list of newly allocated devs to unref
	libusb_device** unref_list;
	unsigned int unref_size = 64;
	unsigned int unref_cur = 0;

	// PASS 1 : (re)enumerate HCDs (allows for HCD hotplug)
	// PASS 2 : (re)enumerate HUBS
	// PASS 3 : (re)enumerate generic USB devices (including driverless)
	//           and list additional USB device interface GUIDs to explore
	// PASS 4 : (re)enumerate master USB devices that have a device interface
	// PASS 5+: (re)enumerate device interfaced GUIDs (including HID) and
	//           set the device interfaces.

	// Init the GUID table
	guid[HCD_PASS] = &GUID_DEVINTERFACE_USB_HOST_CONTROLLER;
	guid[HUB_PASS] = &GUID_DEVINTERFACE_USB_HUB;
	guid[GEN_PASS] = NULL;
	guid[DEV_PASS] = &GUID_DEVINTERFACE_USB_DEVICE;
	HidD_GetHidGuid(&hid_guid);
	guid[HID_PASS] = &hid_guid;
	nb_guids = HID_PASS+1;

	unref_list = (libusb_device**) calloc(unref_size, sizeof(libusb_device*));
	if (unref_list == NULL) {
		return LIBUSB_ERROR_NO_MEM;
	}

	for (pass = 0; ((pass < nb_guids) && (r == LIBUSB_SUCCESS)); pass++) {
//#define ENUM_DEBUG
#ifdef ENUM_DEBUG
		const char *passname[] = { "HCD", "HUB", "GEN", "DEV", "HID", "EXT" };
		usbi_dbg("#### PROCESSING %ss %s", passname[(pass<=HID_PASS)?pass:HID_PASS+1],
			(pass!=GEN_PASS)?guid_to_string(guid[pass]):"");
#endif
		for (i = 0; ; i++) {
			// safe loop: free up any (unprotected) dynamic resource
			// NB: this is always executed before breaking the loop
			safe_free(dev_interface_details);
			safe_free(dev_interface_path);
			safe_free(dev_id_path);
			priv = parent_priv = NULL;
			dev = parent_dev = NULL;

			// Safe loop: end of loop conditions
			if (r != LIBUSB_SUCCESS) {
				break;
			}
			if ((pass == HCD_PASS) && (i == UINT8_MAX)) {
				usbi_warn(ctx, "program assertion failed - found more than %d buses, skipping the rest.", UINT8_MAX);
				break;
			}
			if (pass != GEN_PASS) {
				// Except for GEN, all passes deal with device interfaces
				dev_interface_details = get_interface_details(ctx, &dev_info, &dev_info_data, guid[pass], i);
				if (dev_interface_details == NULL) {
					break;
				} else {
					dev_interface_path = sanitize_path(dev_interface_details->DevicePath);
					if (dev_interface_path == NULL) {
						usbi_warn(ctx, "could not sanitize device interface path for '%s'", dev_interface_details->DevicePath);
						continue;
					}
				}
			} else {
				// Workaround for a Nec/Renesas USB 3.0 driver bug where root hubs are
				// being listed under the "NUSB3" PnP Symbolic Name rather than "USB".
				// The Intel USB 3.0 driver behaves similar, but uses "IUSB3"
				for (; class_index < ARRAYSIZE(usb_class); class_index++) {
					if (get_devinfo_data(ctx, &dev_info, &dev_info_data, usb_class[class_index], i))
						break;
					i = 0;
				}
				if (class_index >= ARRAYSIZE(usb_class))
					break;
			}

			// Read the Device ID path. This is what we'll use as UID
			// Note that if the device is plugged in a different port or hub, the Device ID changes
			if (CM_Get_Device_IDA(dev_info_data.DevInst, path, sizeof(path), 0) != CR_SUCCESS) {
				usbi_warn(ctx, "could not read the device id path for devinst %X, skipping",
					dev_info_data.DevInst);
				continue;
			}
			dev_id_path = sanitize_path(path);
			if (dev_id_path == NULL) {
				usbi_warn(ctx, "could not sanitize device id path for devinst %X, skipping",
					dev_info_data.DevInst);
				continue;
			}
#ifdef ENUM_DEBUG
			usbi_dbg("PRO: %s", dev_id_path);
#endif

			// The SPDRP_ADDRESS for USB devices is the device port number on the hub
			port_nr = 0;
			if ((pass >= HUB_PASS) && (pass <= GEN_PASS)) {
				if ( (!pSetupDiGetDeviceRegistryPropertyA(dev_info, &dev_info_data, SPDRP_ADDRESS,
					&reg_type, (BYTE*)&port_nr, 4, &size))
				  || (size != 4) ) {
					usbi_warn(ctx, "could not retrieve port number for device '%s', skipping: %s",
						dev_id_path, windows_error_str(0));
					continue;
				}
			}

			// Set API to use or get additional data from generic pass
			api = USB_API_UNSUPPORTED;
			sub_api = SUB_API_NOTSET;
			switch (pass) {
			case HCD_PASS:
				break;
			case GEN_PASS:
				// We use the GEN pass to detect driverless devices...
				size = sizeof(strbuf);
				if (!pSetupDiGetDeviceRegistryPropertyA(dev_info, &dev_info_data, SPDRP_DRIVER,
					&reg_type, (BYTE*)strbuf, size, &size)) {
						usbi_info(ctx, "The following device has no driver: '%s'", dev_id_path);
						usbi_info(ctx, "libusb will not be able to access it.");
				}
				// ...and to add the additional device interface GUIDs
				key = pSetupDiOpenDevRegKey(dev_info, &dev_info_data, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_READ);
				if (key != INVALID_HANDLE_VALUE) {
					size = sizeof(guid_string_w);
					s = pRegQueryValueExW(key, L"DeviceInterfaceGUIDs", NULL, &reg_type,
						(BYTE*)guid_string_w, &size);
					pRegCloseKey(key);
					if (s == ERROR_SUCCESS) {
						if (nb_guids >= MAX_ENUM_GUIDS) {
							// If this assert is ever reported, grow a GUID table dynamically
							usbi_err(ctx, "program assertion failed: too many GUIDs");
							LOOP_BREAK(LIBUSB_ERROR_OVERFLOW);
						}
						if_guid = (GUID*) calloc(1, sizeof(GUID));
						if (if_guid == NULL) {
							usbi_err(ctx, "could not calloc for if_guid: not enough memory");
							LOOP_BREAK(LIBUSB_ERROR_NO_MEM);
						}
						pCLSIDFromString(guid_string_w, if_guid);
						guid[nb_guids++] = if_guid;
						usbi_dbg("extra GUID: %s", guid_to_string(if_guid));
					}
				}
				break;
			case HID_PASS:
				api = USB_API_HID;
				break;
			default:
				// Get the API type (after checking that the driver installation is OK)
				if ( (!pSetupDiGetDeviceRegistryPropertyA(dev_info, &dev_info_data, SPDRP_INSTALL_STATE,
					&reg_type, (BYTE*)&install_state, 4, &size))
				  || (size != 4) ){
					usbi_warn(ctx, "could not detect installation state of driver for '%s': %s",
						dev_id_path, windows_error_str(0));
				} else if (install_state != 0) {
					usbi_warn(ctx, "driver for device '%s' is reporting an issue (code: %d) - skipping",
						dev_id_path, install_state);
					continue;
				}
				get_api_type(ctx, &dev_info, &dev_info_data, &api, &sub_api);
				break;
			}

			// Find parent device (for the passes that need it)
			switch (pass) {
			case HCD_PASS:
			case DEV_PASS:
			case HUB_PASS:
				break;
			default:
				// Go through the ancestors until we see a face we recognize
				parent_dev = NULL;
				for (ancestor = 1; parent_dev == NULL; ancestor++) {
					session_id = get_ancestor_session_id(dev_info_data.DevInst, ancestor);
					if (session_id == 0) {
						break;
					}
					parent_dev = usbi_get_device_by_session_id(ctx, session_id);
				}
				if (parent_dev == NULL) {
					usbi_dbg("unlisted ancestor for '%s' (non USB HID, newly connected, etc.) - ignoring", dev_id_path);
					continue;
				}
				parent_priv = _device_priv(parent_dev);
				// virtual USB devices are also listed during GEN - don't process these yet
				if ( (pass == GEN_PASS) && (parent_priv->apib->id != USB_API_HUB) ) {
					libusb_unref_device(parent_dev);
					continue;
				}
				break;
			}

			// Create new or match existing device, using the (hashed) device_id as session id
			if (pass <= DEV_PASS) {	// For subsequent passes, we'll lookup the parent
				// These are the passes that create "new" devices
				session_id = htab_hash(dev_id_path);
				dev = usbi_get_device_by_session_id(ctx, session_id);
				if (dev == NULL) {
					if (pass == DEV_PASS) {
						// This can occur if the OS only reports a newly plugged device after we started enum
						usbi_warn(ctx, "'%s' was only detected in late pass (newly connected device?)"
							" - ignoring", dev_id_path);
						continue;
					}
					usbi_dbg("allocating new device for session [%X]", session_id);
					if ((dev = usbi_alloc_device(ctx, session_id)) == NULL) {
						LOOP_BREAK(LIBUSB_ERROR_NO_MEM);
					}
					windows_device_priv_init(dev);
				} else {
					usbi_dbg("found existing device for session [%X] (%d.%d)",
						session_id, dev->bus_number, dev->device_address);
				}
				// Keep track of devices that need unref
				unref_list[unref_cur++] = dev;
				if (unref_cur >= unref_size) {
					unref_size += 64;
					unref_list = usbi_reallocf(unref_list, unref_size*sizeof(libusb_device*));
					if (unref_list == NULL) {
						usbi_err(ctx, "could not realloc list for unref - aborting.");
						LOOP_BREAK(LIBUSB_ERROR_NO_MEM);
					}
				}
				priv = _device_priv(dev);
			}

			// Setup device
			switch (pass) {
			case HCD_PASS:
				dev->bus_number = (uint8_t)(i + 1);	// bus 0 is reserved for disconnected
				dev->device_address = 0;
				dev->num_configurations = 0;
				priv->apib = &usb_api_backend[USB_API_HUB];
				priv->sub_api = SUB_API_NOTSET;
				priv->depth = UINT8_MAX;	// Overflow to 0 for HCD Hubs
				priv->path = dev_interface_path; dev_interface_path = NULL;
				break;
			case HUB_PASS:
			case DEV_PASS:
				// If the device has already been setup, don't do it again
				if (priv->path != NULL)
					break;
				// Take care of API initialization
				priv->path = dev_interface_path; dev_interface_path = NULL;
				priv->apib = &usb_api_backend[api];
				priv->sub_api = sub_api;
				switch(api) {
				case USB_API_COMPOSITE:
				case USB_API_HUB:
					break;
				case USB_API_HID:
					priv->hid = calloc(1, sizeof(struct hid_device_priv));
					if (priv->hid == NULL) {
						LOOP_BREAK(LIBUSB_ERROR_NO_MEM);
					}
					priv->hid->nb_interfaces = 0;
					break;
				default:
					// For other devices, the first interface is the same as the device
					priv->usb_interface[0].path = (char*) calloc(safe_strlen(priv->path)+1, 1);
					if (priv->usb_interface[0].path != NULL) {
						safe_strcpy(priv->usb_interface[0].path, safe_strlen(priv->path)+1, priv->path);
					} else {
						usbi_warn(ctx, "could not duplicate interface path '%s'", priv->path);
					}
					// The following is needed if we want API calls to work for both simple
					// and composite devices.
					for(j=0; j<USB_MAXINTERFACES; j++) {
						priv->usb_interface[j].apib = &usb_api_backend[api];
					}
					break;
				}
				break;
			case GEN_PASS:
				r = init_device(dev, parent_dev, (uint8_t)port_nr, dev_id_path, dev_info_data.DevInst);
				if (r == LIBUSB_SUCCESS) {
					// Append device to the list of discovered devices
					discdevs = discovered_devs_append(*_discdevs, dev);
					if (!discdevs) {
						LOOP_BREAK(LIBUSB_ERROR_NO_MEM);
					}
					*_discdevs = discdevs;
				} else if (r == LIBUSB_ERROR_NO_DEVICE) {
					// This can occur if the device was disconnected but Windows hasn't
					// refreshed its enumeration yet - in that case, we ignore the device
					r = LIBUSB_SUCCESS;
				}
				break;
			default:	// HID_PASS and later
				if (parent_priv->apib->id == USB_API_HID) {
					usbi_dbg("setting HID interface for [%lX]:", parent_dev->session_data);
					r = set_hid_interface(ctx, parent_dev, dev_interface_path);
					if (r != LIBUSB_SUCCESS) LOOP_BREAK(r);
					dev_interface_path = NULL;
				} else if (parent_priv->apib->id == USB_API_COMPOSITE) {
					usbi_dbg("setting composite interface for [%lX]:", parent_dev->session_data);
					switch (set_composite_interface(ctx, parent_dev, dev_interface_path, dev_id_path, api, sub_api)) {
					case LIBUSB_SUCCESS:
						dev_interface_path = NULL;
						break;
					case LIBUSB_ERROR_ACCESS:
						// interface has already been set => make sure dev_interface_path is freed then
						break;
					default:
						LOOP_BREAK(r);
						break;
					}
				}
				libusb_unref_device(parent_dev);
				break;
			}
		}
	}

	// Free any additional GUIDs
	for (pass = HID_PASS+1; pass < nb_guids; pass++) {
		safe_free(guid[pass]);
	}

	// Unref newly allocated devs
	if (unref_list != NULL) {
		for (i=0; i<unref_cur; i++) {
			safe_unref_device(unref_list[i]);
		}
		free(unref_list);
	}

	return r;
}

/*
 * exit: libusb backend deinitialization function
 */
static void windows_exit(void)
{
	int i;
	HANDLE semaphore;
	char sem_name[11+1+8]; // strlen(libusb_init)+'\0'+(32-bit hex PID)

	sprintf(sem_name, "libusb_init%08X", (unsigned int)GetCurrentProcessId()&0xFFFFFFFF);
	semaphore = CreateSemaphoreA(NULL, 1, 1, sem_name);
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
		for (i=0; i<USB_API_MAX; i++) {
			usb_api_backend[i].exit(SUB_API_NOTSET);
		}
		exit_polling();

		if (timer_thread) {
			// actually the signal to quit the thread.
			if (!pPostThreadMessageA(timer_thread_id, WM_TIMER_EXIT, 0, 0) ||
				(WaitForSingleObject(timer_thread, INFINITE) != WAIT_OBJECT_0)) {
				usbi_dbg("could not wait for timer thread to quit");
				TerminateThread(timer_thread, 1);
			}
			CloseHandle(timer_thread);
			timer_thread = NULL;
			timer_thread_id = 0;
		}
		htab_destroy();
		usbi_mutex_destroy(&autoclaim_lock);
	}

	ReleaseSemaphore(semaphore, 1, NULL);	// increase count back to 1
	CloseHandle(semaphore);
}

static int windows_get_device_descriptor(struct libusb_device *dev, unsigned char *buffer, int *host_endian)
{
	struct windows_device_priv *priv = _device_priv(dev);

	memcpy(buffer, &(priv->dev_descriptor), DEVICE_DESC_LENGTH);
	*host_endian = 0;

	return LIBUSB_SUCCESS;
}

static int windows_get_config_descriptor(struct libusb_device *dev, uint8_t config_index, unsigned char *buffer, size_t len, int *host_endian)
{
	struct windows_device_priv *priv = _device_priv(dev);
	PUSB_CONFIGURATION_DESCRIPTOR config_header;
	size_t size;

	// config index is zero based
	if (config_index >= dev->num_configurations)
		return LIBUSB_ERROR_INVALID_PARAM;

	if ((priv->config_descriptor == NULL) || (priv->config_descriptor[config_index] == NULL))
		return LIBUSB_ERROR_NOT_FOUND;

	config_header = (PUSB_CONFIGURATION_DESCRIPTOR)priv->config_descriptor[config_index];

	size = MIN(config_header->wTotalLength, len);
	memcpy(buffer, priv->config_descriptor[config_index], size);
	*host_endian = 0;

	return (int)size;
}

/*
 * return the cached copy of the active config descriptor
 */
static int windows_get_active_config_descriptor(struct libusb_device *dev, unsigned char *buffer, size_t len, int *host_endian)
{
	struct windows_device_priv *priv = _device_priv(dev);

	if (priv->active_config == 0)
		return LIBUSB_ERROR_NOT_FOUND;

	// config index is zero based
	return windows_get_config_descriptor(dev, (uint8_t)(priv->active_config-1), buffer, len, host_endian);
}

static int windows_open(struct libusb_device_handle *dev_handle)
{
	struct windows_device_priv *priv = _device_priv(dev_handle->dev);
	struct libusb_context *ctx = DEVICE_CTX(dev_handle->dev);

	if (priv->apib == NULL) {
		usbi_err(ctx, "program assertion failed - device is not initialized");
		return LIBUSB_ERROR_NO_DEVICE;
	}

	return priv->apib->open(SUB_API_NOTSET, dev_handle);
}

static void windows_close(struct libusb_device_handle *dev_handle)
{
	struct windows_device_priv *priv = _device_priv(dev_handle->dev);

	priv->apib->close(SUB_API_NOTSET, dev_handle);
}

static int windows_get_configuration(struct libusb_device_handle *dev_handle, int *config)
{
	struct windows_device_priv *priv = _device_priv(dev_handle->dev);

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
	struct windows_device_priv *priv = _device_priv(dev_handle->dev);
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
	struct windows_device_priv *priv = _device_priv(dev_handle->dev);

	safe_free(priv->usb_interface[iface].endpoint);
	priv->usb_interface[iface].nb_endpoints= 0;

	r = priv->apib->claim_interface(SUB_API_NOTSET, dev_handle, iface);

	if (r == LIBUSB_SUCCESS) {
		r = windows_assign_endpoints(dev_handle, iface, 0);
	}

	return r;
}

static int windows_set_interface_altsetting(struct libusb_device_handle *dev_handle, int iface, int altsetting)
{
	int r = LIBUSB_SUCCESS;
	struct windows_device_priv *priv = _device_priv(dev_handle->dev);

	safe_free(priv->usb_interface[iface].endpoint);
	priv->usb_interface[iface].nb_endpoints= 0;

	r = priv->apib->set_interface_altsetting(SUB_API_NOTSET, dev_handle, iface, altsetting);

	if (r == LIBUSB_SUCCESS) {
		r = windows_assign_endpoints(dev_handle, iface, altsetting);
	}

	return r;
}

static int windows_release_interface(struct libusb_device_handle *dev_handle, int iface)
{
	struct windows_device_priv *priv = _device_priv(dev_handle->dev);

	return priv->apib->release_interface(SUB_API_NOTSET, dev_handle, iface);
}

static int windows_clear_halt(struct libusb_device_handle *dev_handle, unsigned char endpoint)
{
	struct windows_device_priv *priv = _device_priv(dev_handle->dev);
	return priv->apib->clear_halt(SUB_API_NOTSET, dev_handle, endpoint);
}

static int windows_reset_device(struct libusb_device_handle *dev_handle)
{
	struct windows_device_priv *priv = _device_priv(dev_handle->dev);
	return priv->apib->reset_device(SUB_API_NOTSET, dev_handle);
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
	windows_device_priv_release(dev);
}

static void windows_clear_transfer_priv(struct usbi_transfer *itransfer)
{
	struct windows_transfer_priv *transfer_priv = (struct windows_transfer_priv*)usbi_transfer_get_os_priv(itransfer);

	usbi_free_fd(&transfer_priv->pollable_fd);
	safe_free(transfer_priv->hid_buffer);
	// When auto claim is in use, attempt to release the auto-claimed interface
	auto_release(itransfer);
}

static int submit_bulk_transfer(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct libusb_context *ctx = DEVICE_CTX(transfer->dev_handle->dev);
	struct windows_transfer_priv *transfer_priv = (struct windows_transfer_priv*)usbi_transfer_get_os_priv(itransfer);
	struct windows_device_priv *priv = _device_priv(transfer->dev_handle->dev);
	int r;

	r = priv->apib->submit_bulk_transfer(SUB_API_NOTSET, itransfer);
	if (r != LIBUSB_SUCCESS) {
		return r;
	}

	usbi_add_pollfd(ctx, transfer_priv->pollable_fd.fd,
		(short)(IS_XFERIN(transfer) ? POLLIN : POLLOUT));

	return LIBUSB_SUCCESS;
}

static int submit_iso_transfer(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct libusb_context *ctx = DEVICE_CTX(transfer->dev_handle->dev);
	struct windows_transfer_priv *transfer_priv = (struct windows_transfer_priv*)usbi_transfer_get_os_priv(itransfer);
	struct windows_device_priv *priv = _device_priv(transfer->dev_handle->dev);
	int r;

	r = priv->apib->submit_iso_transfer(SUB_API_NOTSET, itransfer);
	if (r != LIBUSB_SUCCESS) {
		return r;
	}

	usbi_add_pollfd(ctx, transfer_priv->pollable_fd.fd,
		(short)(IS_XFERIN(transfer) ? POLLIN : POLLOUT));

	return LIBUSB_SUCCESS;
}

static int submit_control_transfer(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct libusb_context *ctx = DEVICE_CTX(transfer->dev_handle->dev);
	struct windows_transfer_priv *transfer_priv = (struct windows_transfer_priv*)usbi_transfer_get_os_priv(itransfer);
	struct windows_device_priv *priv = _device_priv(transfer->dev_handle->dev);
	int r;

	r = priv->apib->submit_control_transfer(SUB_API_NOTSET, itransfer);
	if (r != LIBUSB_SUCCESS) {
		return r;
	}

	usbi_add_pollfd(ctx, transfer_priv->pollable_fd.fd, POLLIN);

	return LIBUSB_SUCCESS;

}

static int windows_submit_transfer(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);

	switch (transfer->type) {
	case LIBUSB_TRANSFER_TYPE_CONTROL:
		return submit_control_transfer(itransfer);
	case LIBUSB_TRANSFER_TYPE_BULK:
	case LIBUSB_TRANSFER_TYPE_INTERRUPT:
		if (IS_XFEROUT(transfer) &&
		    transfer->flags & LIBUSB_TRANSFER_ADD_ZERO_PACKET)
			return LIBUSB_ERROR_NOT_SUPPORTED;
		return submit_bulk_transfer(itransfer);
	case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS:
		return submit_iso_transfer(itransfer);
	case LIBUSB_TRANSFER_TYPE_BULK_STREAM:
		return LIBUSB_ERROR_NOT_SUPPORTED;
	default:
		usbi_err(TRANSFER_CTX(transfer), "unknown endpoint type %d", transfer->type);
		return LIBUSB_ERROR_INVALID_PARAM;
	}
}

static int windows_abort_control(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct windows_device_priv *priv = _device_priv(transfer->dev_handle->dev);

	return priv->apib->abort_control(SUB_API_NOTSET, itransfer);
}

static int windows_abort_transfers(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct windows_device_priv *priv = _device_priv(transfer->dev_handle->dev);

	return priv->apib->abort_transfers(SUB_API_NOTSET, itransfer);
}

static int windows_cancel_transfer(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);

	switch (transfer->type) {
	case LIBUSB_TRANSFER_TYPE_CONTROL:
		return windows_abort_control(itransfer);
	case LIBUSB_TRANSFER_TYPE_BULK:
	case LIBUSB_TRANSFER_TYPE_INTERRUPT:
	case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS:
		return windows_abort_transfers(itransfer);
	case LIBUSB_TRANSFER_TYPE_BULK_STREAM:
		return LIBUSB_ERROR_NOT_SUPPORTED;
	default:
		usbi_err(ITRANSFER_CTX(itransfer), "unknown endpoint type %d", transfer->type);
		return LIBUSB_ERROR_INVALID_PARAM;
	}
}

static void windows_transfer_callback(struct usbi_transfer *itransfer, uint32_t io_result, uint32_t io_size)
{
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct windows_device_priv *priv = _device_priv(transfer->dev_handle->dev);
	int status, istatus;

	usbi_dbg("handling I/O completion with errcode %d, size %d", io_result, io_size);

	switch(io_result) {
	case NO_ERROR:
		status = priv->apib->copy_transfer_data(SUB_API_NOTSET, itransfer, io_size);
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
		istatus = priv->apib->copy_transfer_data(SUB_API_NOTSET, itransfer, io_size);
		if (istatus != LIBUSB_TRANSFER_COMPLETED) {
			usbi_dbg("Failed to copy partial data in aborted operation: %d", istatus);
		}
		if (itransfer->flags & USBI_TRANSFER_TIMED_OUT) {
			usbi_dbg("detected timeout");
			status = LIBUSB_TRANSFER_TIMED_OUT;
		} else {
			usbi_dbg("detected operation aborted");
			status = LIBUSB_TRANSFER_CANCELLED;
		}
		break;
	default:
		usbi_err(ITRANSFER_CTX(itransfer), "detected I/O error %d: %s", io_result, windows_error_str(io_result));
		status = LIBUSB_TRANSFER_ERROR;
		break;
	}
	windows_clear_transfer_priv(itransfer);	// Cancel polling
	usbi_handle_transfer_completion(itransfer, (enum libusb_transfer_status)status);
}

static void windows_handle_callback (struct usbi_transfer *itransfer, uint32_t io_result, uint32_t io_size)
{
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);

	switch (transfer->type) {
	case LIBUSB_TRANSFER_TYPE_CONTROL:
	case LIBUSB_TRANSFER_TYPE_BULK:
	case LIBUSB_TRANSFER_TYPE_INTERRUPT:
	case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS:
		windows_transfer_callback (itransfer, io_result, io_size);
		break;
	case LIBUSB_TRANSFER_TYPE_BULK_STREAM:
		usbi_warn(ITRANSFER_CTX(itransfer), "bulk stream transfers are not yet supported on this platform");
		break;
	default:
		usbi_err(ITRANSFER_CTX(itransfer), "unknown endpoint type %d", transfer->type);
	}
}

static int windows_handle_events(struct libusb_context *ctx, struct pollfd *fds, POLL_NFDS_TYPE nfds, int num_ready)
{
	struct windows_transfer_priv* transfer_priv = NULL;
	POLL_NFDS_TYPE i = 0;
	bool found;
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
		found = false;
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
			usbi_mutex_unlock(&ctx->open_devs_lock);
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
	struct timer_request *request;
	LARGE_INTEGER hires_counter;
	MSG msg;

	// The following call will create this thread's message queue
	// See https://msdn.microsoft.com/en-us/library/windows/desktop/ms644946.aspx
	pPeekMessageA(&msg, NULL, WM_USER, WM_USER, PM_NOREMOVE);

	// Signal windows_init() that we're ready to service requests
	if (!SetEvent((HANDLE)param)) {
		usbi_dbg("SetEvent failed for timer init event: %s", windows_error_str(0));
	}
	param = NULL;

	// Main loop - wait for requests
	while (1) {
		if (pGetMessageA(&msg, NULL, WM_TIMER_REQUEST, WM_TIMER_EXIT) == -1) {
			usbi_err(NULL, "GetMessage failed for timer thread: %s", windows_error_str(0));
			return 1;
		}

		switch (msg.message) {
		case WM_TIMER_REQUEST:
			// Requests to this thread are for hires always
			// Microsoft says that this function always succeeds on XP and later
			// See https://msdn.microsoft.com/en-us/library/windows/desktop/ms644904.aspx
			request = (struct timer_request *)msg.lParam;
			QueryPerformanceCounter(&hires_counter);
			request->tp->tv_sec = (long)(hires_counter.QuadPart / hires_frequency);
			request->tp->tv_nsec = (long)(((hires_counter.QuadPart % hires_frequency) / 1000) * hires_ticks_to_ps);
			if (!SetEvent(request->event)) {
				usbi_err(NULL, "SetEvent failed for timer request: %s", windows_error_str(0));
			}
			break;

		case WM_TIMER_EXIT:
			usbi_dbg("timer thread quitting");
			return 0;
		}
	}
}

static int windows_clock_gettime(int clk_id, struct timespec *tp)
{
	struct timer_request request;
	FILETIME filetime;
	ULARGE_INTEGER rtime;
	DWORD r;
	switch(clk_id) {
	case USBI_CLOCK_MONOTONIC:
		if (timer_thread) {
			request.tp = tp;
			request.event = CreateEvent(NULL, FALSE, FALSE, NULL);
			if (request.event == NULL) {
				return LIBUSB_ERROR_NO_MEM;
			}

			if (!pPostThreadMessageA(timer_thread_id, WM_TIMER_REQUEST, 0, (LPARAM)&request)) {
				usbi_err(NULL, "PostThreadMessage failed for timer thread: %s", windows_error_str(0));
				CloseHandle(request.event);
				return LIBUSB_ERROR_OTHER;
			}

			do {
				r = WaitForSingleObject(request.event, TIMER_REQUEST_RETRY_MS);
				if (r == WAIT_TIMEOUT) {
					usbi_dbg("could not obtain a timer value within reasonable timeframe - too much load?");
				}
				else if (r == WAIT_FAILED) {
					usbi_err(NULL, "WaitForSingleObject failed: %s", windows_error_str(0));
				}
			} while (r == WAIT_TIMEOUT);
			CloseHandle(request.event);

			if (r == WAIT_OBJECT_0) {
				return LIBUSB_SUCCESS;
			}
			else {
				return LIBUSB_ERROR_OTHER;
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
	USBI_CAP_HAS_HID_ACCESS,
	windows_init,
	windows_exit,

	windows_get_device_list,
	NULL,				/* hotplug_poll */
	windows_open,
	windows_close,

	windows_get_device_descriptor,
	windows_get_active_config_descriptor,
	windows_get_config_descriptor,
	NULL,				/* get_config_descriptor_by_value() */

	windows_get_configuration,
	windows_set_configuration,
	windows_claim_interface,
	windows_release_interface,

	windows_set_interface_altsetting,
	windows_clear_halt,
	windows_reset_device,

	NULL,				/* alloc_streams */
	NULL,				/* free_streams */

	windows_kernel_driver_active,
	windows_detach_kernel_driver,
	windows_attach_kernel_driver,

	windows_destroy_device,

	windows_submit_transfer,
	windows_cancel_transfer,
	windows_clear_transfer_priv,

	windows_handle_events,
	NULL,				/* handle_transfer_completion() */

	windows_clock_gettime,
#if defined(USBI_TIMERFD_AVAILABLE)
	NULL,
#endif
	sizeof(struct windows_device_priv),
	sizeof(struct windows_device_handle_priv),
	sizeof(struct windows_transfer_priv),
};


/*
 * USB API backends
 */
static int unsupported_init(int sub_api, struct libusb_context *ctx) {
	return LIBUSB_SUCCESS;
}
static int unsupported_exit(int sub_api) {
	return LIBUSB_SUCCESS;
}
static int unsupported_open(int sub_api, struct libusb_device_handle *dev_handle) {
	PRINT_UNSUPPORTED_API(open);
}
static void unsupported_close(int sub_api, struct libusb_device_handle *dev_handle) {
	usbi_dbg("unsupported API call for 'close'");
}
static int unsupported_configure_endpoints(int sub_api, struct libusb_device_handle *dev_handle, int iface) {
	PRINT_UNSUPPORTED_API(configure_endpoints);
}
static int unsupported_claim_interface(int sub_api, struct libusb_device_handle *dev_handle, int iface) {
	PRINT_UNSUPPORTED_API(claim_interface);
}
static int unsupported_set_interface_altsetting(int sub_api, struct libusb_device_handle *dev_handle, int iface, int altsetting) {
	PRINT_UNSUPPORTED_API(set_interface_altsetting);
}
static int unsupported_release_interface(int sub_api, struct libusb_device_handle *dev_handle, int iface) {
	PRINT_UNSUPPORTED_API(release_interface);
}
static int unsupported_clear_halt(int sub_api, struct libusb_device_handle *dev_handle, unsigned char endpoint) {
	PRINT_UNSUPPORTED_API(clear_halt);
}
static int unsupported_reset_device(int sub_api, struct libusb_device_handle *dev_handle) {
	PRINT_UNSUPPORTED_API(reset_device);
}
static int unsupported_submit_bulk_transfer(int sub_api, struct usbi_transfer *itransfer) {
	PRINT_UNSUPPORTED_API(submit_bulk_transfer);
}
static int unsupported_submit_iso_transfer(int sub_api, struct usbi_transfer *itransfer) {
	PRINT_UNSUPPORTED_API(submit_iso_transfer);
}
static int unsupported_submit_control_transfer(int sub_api, struct usbi_transfer *itransfer) {
	PRINT_UNSUPPORTED_API(submit_control_transfer);
}
static int unsupported_abort_control(int sub_api, struct usbi_transfer *itransfer) {
	PRINT_UNSUPPORTED_API(abort_control);
}
static int unsupported_abort_transfers(int sub_api, struct usbi_transfer *itransfer) {
	PRINT_UNSUPPORTED_API(abort_transfers);
}
static int unsupported_copy_transfer_data(int sub_api, struct usbi_transfer *itransfer, uint32_t io_size) {
	PRINT_UNSUPPORTED_API(copy_transfer_data);
}
static int common_configure_endpoints(int sub_api, struct libusb_device_handle *dev_handle, int iface) {
	return LIBUSB_SUCCESS;
}
// These names must be uppercase
const char* hub_driver_names[] = {"USBHUB", "USBHUB3", "USB3HUB", "NUSB3HUB", "RUSB3HUB", "FLXHCIH", "TIHUB3", "ETRONHUB3", "VIAHUB3", "ASMTHUB3", "IUSB3HUB", "VUSB3HUB", "AMDHUB30"};
const char* composite_driver_names[] = {"USBCCGP"};
const char* winusbx_driver_names[] = WINUSBX_DRV_NAMES;
const char* hid_driver_names[] = {"HIDUSB", "MOUHID", "KBDHID"};
const struct windows_usb_api_backend usb_api_backend[USB_API_MAX] = {
	{
		USB_API_UNSUPPORTED,
		"Unsupported API",
		NULL,
		0,
		unsupported_init,
		unsupported_exit,
		unsupported_open,
		unsupported_close,
		unsupported_configure_endpoints,
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
		USB_API_HUB,
		"HUB API",
		hub_driver_names,
		ARRAYSIZE(hub_driver_names),
		unsupported_init,
		unsupported_exit,
		unsupported_open,
		unsupported_close,
		unsupported_configure_endpoints,
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
		composite_driver_names,
		ARRAYSIZE(composite_driver_names),
		composite_init,
		composite_exit,
		composite_open,
		composite_close,
		common_configure_endpoints,
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
		USB_API_WINUSBX,
		"WinUSB-like APIs",
		winusbx_driver_names,
		ARRAYSIZE(winusbx_driver_names),
		winusbx_init,
		winusbx_exit,
		winusbx_open,
		winusbx_close,
		winusbx_configure_endpoints,
		winusbx_claim_interface,
		winusbx_set_interface_altsetting,
		winusbx_release_interface,
		winusbx_clear_halt,
		winusbx_reset_device,
		winusbx_submit_bulk_transfer,
		unsupported_submit_iso_transfer,
		winusbx_submit_control_transfer,
		winusbx_abort_control,
		winusbx_abort_transfers,
		winusbx_copy_transfer_data,
	}, {
		USB_API_HID,
		"HID API",
		hid_driver_names,
		ARRAYSIZE(hid_driver_names),
		hid_init,
		hid_exit,
		hid_open,
		hid_close,
		common_configure_endpoints,
		hid_claim_interface,
		hid_set_interface_altsetting,
		hid_release_interface,
		hid_clear_halt,
		hid_reset_device,
		hid_submit_bulk_transfer,
		unsupported_submit_iso_transfer,
		hid_submit_control_transfer,
		hid_abort_transfers,
		hid_abort_transfers,
		hid_copy_transfer_data,
	},
};


/*
 * WinUSB-like (WinUSB, libusb0/libusbK through libusbk DLL) API functions
 */
#define WinUSBX_Set(fn) do { if (native_winusb) WinUSBX[i].fn = (WinUsb_##fn##_t) GetProcAddress(h, "WinUsb_" #fn); \
	else pLibK_GetProcAddress((PVOID*)&WinUSBX[i].fn, i, KUSB_FNID_##fn); } while (0)

static int winusbx_init(int sub_api, struct libusb_context *ctx)
{
	HMODULE h = NULL;
	bool native_winusb = false;
	int i;
	KLIB_VERSION LibK_Version;
	LibK_GetProcAddress_t pLibK_GetProcAddress = NULL;
	LibK_GetVersion_t pLibK_GetVersion = NULL;

	h = GetModuleHandleA("libusbK");
	if (h == NULL) {
		h = LoadLibraryA("libusbK");
	}
	if (h == NULL) {
		usbi_info(ctx, "libusbK DLL is not available, will use native WinUSB");
		h = GetModuleHandleA("WinUSB");
		if (h == NULL) {
			h = LoadLibraryA("WinUSB");
		}		if (h == NULL) {
			usbi_warn(ctx, "WinUSB DLL is not available either, "
				"you will not be able to access devices outside of enumeration");
			return LIBUSB_ERROR_NOT_FOUND;
		}
	} else {
		usbi_dbg("using libusbK DLL for universal access");
		pLibK_GetVersion = (LibK_GetVersion_t) GetProcAddress(h, "LibK_GetVersion");
		if (pLibK_GetVersion != NULL) {
			pLibK_GetVersion(&LibK_Version);
			usbi_dbg("libusbK version: %d.%d.%d.%d", LibK_Version.Major, LibK_Version.Minor,
				LibK_Version.Micro, LibK_Version.Nano);
		}
		pLibK_GetProcAddress = (LibK_GetProcAddress_t) GetProcAddress(h, "LibK_GetProcAddress");
		if (pLibK_GetProcAddress == NULL) {
			usbi_err(ctx, "LibK_GetProcAddress() not found in libusbK DLL");
			return LIBUSB_ERROR_NOT_FOUND;
		}
	}
	native_winusb = (pLibK_GetProcAddress == NULL);
	for (i=SUB_API_LIBUSBK; i<SUB_API_MAX; i++) {
		WinUSBX_Set(AbortPipe);
		WinUSBX_Set(ControlTransfer);
		WinUSBX_Set(FlushPipe);
		WinUSBX_Set(Free);
		WinUSBX_Set(GetAssociatedInterface);
		WinUSBX_Set(GetCurrentAlternateSetting);
		WinUSBX_Set(GetDescriptor);
		WinUSBX_Set(GetOverlappedResult);
		WinUSBX_Set(GetPipePolicy);
		WinUSBX_Set(GetPowerPolicy);
		WinUSBX_Set(Initialize);
		WinUSBX_Set(QueryDeviceInformation);
		WinUSBX_Set(QueryInterfaceSettings);
		WinUSBX_Set(QueryPipe);
		WinUSBX_Set(ReadPipe);
		WinUSBX_Set(ResetPipe);
		WinUSBX_Set(SetCurrentAlternateSetting);
		WinUSBX_Set(SetPipePolicy);
		WinUSBX_Set(SetPowerPolicy);
		WinUSBX_Set(WritePipe);
		if (!native_winusb) {
			WinUSBX_Set(ResetDevice);
		}
		if (WinUSBX[i].Initialize != NULL) {
			WinUSBX[i].initialized = true;
			usbi_dbg("initalized sub API %s", sub_api_name[i]);
		} else {
			usbi_warn(ctx, "Failed to initalize sub API %s", sub_api_name[i]);
			WinUSBX[i].initialized = false;
		}
	}
	return LIBUSB_SUCCESS;
}

static int winusbx_exit(int sub_api)
{
	return LIBUSB_SUCCESS;
}

// NB: open and close must ensure that they only handle interface of
// the right API type, as these functions can be called wholesale from
// composite_open(), with interfaces belonging to different APIs
static int winusbx_open(int sub_api, struct libusb_device_handle *dev_handle)
{
	struct libusb_context *ctx = DEVICE_CTX(dev_handle->dev);
	struct windows_device_priv *priv = _device_priv(dev_handle->dev);
	struct windows_device_handle_priv *handle_priv = _device_handle_priv(dev_handle);

	HANDLE file_handle;
	int i;

	CHECK_WINUSBX_AVAILABLE(sub_api);

	// WinUSB requires a seperate handle for each interface
	for (i = 0; i < USB_MAXINTERFACES; i++) {
		if ( (priv->usb_interface[i].path != NULL)
		  && (priv->usb_interface[i].apib->id == USB_API_WINUSBX) ) {
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

static void winusbx_close(int sub_api, struct libusb_device_handle *dev_handle)
{
	struct windows_device_handle_priv *handle_priv = _device_handle_priv(dev_handle);
	struct windows_device_priv *priv = _device_priv(dev_handle->dev);
	HANDLE handle;
	int i;

	if (sub_api == SUB_API_NOTSET)
		sub_api = priv->sub_api;
	if (!WinUSBX[sub_api].initialized)
		return;

	if (priv->apib->id == USB_API_COMPOSITE) {
		// If this is a composite device, just free and close all WinUSB-like
		// interfaces directly (each is independent and not associated with another)
		for (i = 0; i < USB_MAXINTERFACES; i++) {
			if (priv->usb_interface[i].apib->id == USB_API_WINUSBX) {
				handle = handle_priv->interface_handle[i].api_handle;
				if ((handle != 0) && (handle != INVALID_HANDLE_VALUE)) {
					WinUSBX[sub_api].Free(handle);
				}
				handle = handle_priv->interface_handle[i].dev_handle;
				if ((handle != 0) && (handle != INVALID_HANDLE_VALUE)) {
					CloseHandle(handle);
				}
			}
		}
	}
	else {
		// If this is a WinUSB device, free all interfaces above interface 0,
		// then free and close interface 0 last
		for (i = 1; i < USB_MAXINTERFACES; i++) {
			handle = handle_priv->interface_handle[i].api_handle;
			if ((handle != 0) && (handle != INVALID_HANDLE_VALUE)) {
				WinUSBX[sub_api].Free(handle);
			}
		}
		handle = handle_priv->interface_handle[0].api_handle;
		if ((handle != 0) && (handle != INVALID_HANDLE_VALUE)) {
			WinUSBX[sub_api].Free(handle);
		}
		handle = handle_priv->interface_handle[0].dev_handle;
		if ((handle != 0) && (handle != INVALID_HANDLE_VALUE)) {
			CloseHandle(handle);
		}
	}
}

static int winusbx_configure_endpoints(int sub_api, struct libusb_device_handle *dev_handle, int iface)
{
	struct windows_device_handle_priv *handle_priv = _device_handle_priv(dev_handle);
	struct windows_device_priv *priv = _device_priv(dev_handle->dev);
	HANDLE winusb_handle = handle_priv->interface_handle[iface].api_handle;
	UCHAR policy;
	ULONG timeout = 0;
	uint8_t endpoint_address;
	int i;

	CHECK_WINUSBX_AVAILABLE(sub_api);

	// With handle and enpoints set (in parent), we can setup the default pipe properties
	// see http://download.microsoft.com/download/D/1/D/D1DD7745-426B-4CC3-A269-ABBBE427C0EF/DVC-T705_DDC08.pptx
	for (i=-1; i<priv->usb_interface[iface].nb_endpoints; i++) {
		endpoint_address =(i==-1)?0:priv->usb_interface[iface].endpoint[i];
		if (!WinUSBX[sub_api].SetPipePolicy(winusb_handle, endpoint_address,
			PIPE_TRANSFER_TIMEOUT, sizeof(ULONG), &timeout)) {
			usbi_dbg("failed to set PIPE_TRANSFER_TIMEOUT for control endpoint %02X", endpoint_address);
		}
		if ((i == -1) || (sub_api == SUB_API_LIBUSB0)) {
			continue;	// Other policies don't apply to control endpoint or libusb0
		}
		policy = false;
		if (!WinUSBX[sub_api].SetPipePolicy(winusb_handle, endpoint_address,
			SHORT_PACKET_TERMINATE, sizeof(UCHAR), &policy)) {
			usbi_dbg("failed to disable SHORT_PACKET_TERMINATE for endpoint %02X", endpoint_address);
		}
		if (!WinUSBX[sub_api].SetPipePolicy(winusb_handle, endpoint_address,
			IGNORE_SHORT_PACKETS, sizeof(UCHAR), &policy)) {
			usbi_dbg("failed to disable IGNORE_SHORT_PACKETS for endpoint %02X", endpoint_address);
		}
		policy = true;
		/* ALLOW_PARTIAL_READS must be enabled due to likely libusbK bug. See:
		   https://sourceforge.net/mailarchive/message.php?msg_id=29736015 */
		if (!WinUSBX[sub_api].SetPipePolicy(winusb_handle, endpoint_address,
			ALLOW_PARTIAL_READS, sizeof(UCHAR), &policy)) {
			usbi_dbg("failed to enable ALLOW_PARTIAL_READS for endpoint %02X", endpoint_address);
		}
		if (!WinUSBX[sub_api].SetPipePolicy(winusb_handle, endpoint_address,
			AUTO_CLEAR_STALL, sizeof(UCHAR), &policy)) {
			usbi_dbg("failed to enable AUTO_CLEAR_STALL for endpoint %02X", endpoint_address);
		}
	}

	return LIBUSB_SUCCESS;
}

static int winusbx_claim_interface(int sub_api, struct libusb_device_handle *dev_handle, int iface)
{
	struct libusb_context *ctx = DEVICE_CTX(dev_handle->dev);
	struct windows_device_handle_priv *handle_priv = _device_handle_priv(dev_handle);
	struct windows_device_priv *priv = _device_priv(dev_handle->dev);
	bool is_using_usbccgp = (priv->apib->id == USB_API_COMPOSITE);
	HANDLE file_handle, winusb_handle;
	DWORD err;
	int i;
	SP_DEVICE_INTERFACE_DETAIL_DATA_A *dev_interface_details = NULL;
	HDEVINFO dev_info = INVALID_HANDLE_VALUE;
	SP_DEVINFO_DATA dev_info_data;
	char* dev_path_no_guid = NULL;
	char filter_path[] = "\\\\.\\libusb0-0000";
	bool found_filter = false;

	CHECK_WINUSBX_AVAILABLE(sub_api);

	// If the device is composite, but using the default Windows composite parent driver (usbccgp)
	// or if it's the first WinUSB-like interface, we get a handle through Initialize().
	if ((is_using_usbccgp) || (iface == 0)) {
		// composite device (independent interfaces) or interface 0
		file_handle = handle_priv->interface_handle[iface].dev_handle;
		if ((file_handle == 0) || (file_handle == INVALID_HANDLE_VALUE)) {
			return LIBUSB_ERROR_NOT_FOUND;
		}

		if (!WinUSBX[sub_api].Initialize(file_handle, &winusb_handle)) {
			handle_priv->interface_handle[iface].api_handle = INVALID_HANDLE_VALUE;
			err = GetLastError();
			switch(err) {
			case ERROR_BAD_COMMAND:
				// The device was disconnected
				usbi_err(ctx, "could not access interface %d: %s", iface, windows_error_str(0));
				return LIBUSB_ERROR_NO_DEVICE;
			default:
				// it may be that we're using the libusb0 filter driver.
				// TODO: can we move this whole business into the K/0 DLL?
				for (i = 0; ; i++) {
					safe_free(dev_interface_details);
					safe_free(dev_path_no_guid);
					dev_interface_details = get_interface_details_filter(ctx, &dev_info, &dev_info_data, &GUID_DEVINTERFACE_LIBUSB0_FILTER, i, filter_path);
					if ((found_filter) || (dev_interface_details == NULL)) {
						break;
					}
					// ignore GUID part
					dev_path_no_guid = sanitize_path(strtok(dev_interface_details->DevicePath, "{"));
					if (safe_strncmp(dev_path_no_guid, priv->usb_interface[iface].path, safe_strlen(dev_path_no_guid)) == 0) {
						file_handle = CreateFileA(filter_path, GENERIC_WRITE | GENERIC_READ, FILE_SHARE_WRITE | FILE_SHARE_READ,
							NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
						if (file_handle == INVALID_HANDLE_VALUE) {
							usbi_err(ctx, "could not open device %s: %s", filter_path, windows_error_str(0));
						} else {
							WinUSBX[sub_api].Free(winusb_handle);
							if (WinUSBX[sub_api].Initialize(file_handle, &winusb_handle))
								found_filter = true;
							else
								usbi_err(ctx, "could not initialize filter driver for %s", filter_path);
						}
					}
				}
				if (!found_filter) {
					usbi_err(ctx, "could not access interface %d: %s", iface, windows_error_str(err));
					return LIBUSB_ERROR_ACCESS;
				}
			}
		}
		handle_priv->interface_handle[iface].api_handle = winusb_handle;
	} else {
		// For all other interfaces, use GetAssociatedInterface()
		winusb_handle = handle_priv->interface_handle[0].api_handle;
		// It is a requirement for multiple interface devices on Windows that, to you
		// must first claim the first interface before you claim the others
		if ((winusb_handle == 0) || (winusb_handle == INVALID_HANDLE_VALUE)) {
			file_handle = handle_priv->interface_handle[0].dev_handle;
			if (WinUSBX[sub_api].Initialize(file_handle, &winusb_handle)) {
				handle_priv->interface_handle[0].api_handle = winusb_handle;
				usbi_warn(ctx, "auto-claimed interface 0 (required to claim %d with WinUSB)", iface);
			} else {
				usbi_warn(ctx, "failed to auto-claim interface 0 (required to claim %d with WinUSB): %s", iface, windows_error_str(0));
				return LIBUSB_ERROR_ACCESS;
			}
		}
		if (!WinUSBX[sub_api].GetAssociatedInterface(winusb_handle, (UCHAR)(iface-1),
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

	return LIBUSB_SUCCESS;
}

static int winusbx_release_interface(int sub_api, struct libusb_device_handle *dev_handle, int iface)
{
	struct windows_device_handle_priv *handle_priv = _device_handle_priv(dev_handle);
	struct windows_device_priv *priv = _device_priv(dev_handle->dev);
	HANDLE winusb_handle;

	CHECK_WINUSBX_AVAILABLE(sub_api);

	winusb_handle = handle_priv->interface_handle[iface].api_handle;
	if ((winusb_handle == 0) || (winusb_handle == INVALID_HANDLE_VALUE)) {
		return LIBUSB_ERROR_NOT_FOUND;
	}

	WinUSBX[sub_api].Free(winusb_handle);
	handle_priv->interface_handle[iface].api_handle = INVALID_HANDLE_VALUE;

	return LIBUSB_SUCCESS;
}

/*
 * Return the first valid interface (of the same API type), for control transfers
 */
static int get_valid_interface(struct libusb_device_handle *dev_handle, int api_id)
{
	struct windows_device_handle_priv *handle_priv = _device_handle_priv(dev_handle);
	struct windows_device_priv *priv = _device_priv(dev_handle->dev);
	int i;

	if ((api_id < USB_API_WINUSBX) || (api_id > USB_API_HID)) {
		usbi_dbg("unsupported API ID");
		return -1;
	}

	for (i=0; i<USB_MAXINTERFACES; i++) {
		if ( (handle_priv->interface_handle[i].dev_handle != 0)
		  && (handle_priv->interface_handle[i].dev_handle != INVALID_HANDLE_VALUE)
		  && (handle_priv->interface_handle[i].api_handle != 0)
		  && (handle_priv->interface_handle[i].api_handle != INVALID_HANDLE_VALUE)
		  && (priv->usb_interface[i].apib->id == api_id) ) {
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

static int winusbx_submit_control_transfer(int sub_api, struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct libusb_context *ctx = DEVICE_CTX(transfer->dev_handle->dev);
	struct windows_device_priv *priv = _device_priv(transfer->dev_handle->dev);
	struct windows_transfer_priv *transfer_priv = (struct windows_transfer_priv*)usbi_transfer_get_os_priv(itransfer);
	struct windows_device_handle_priv *handle_priv = _device_handle_priv(
		transfer->dev_handle);
	WINUSB_SETUP_PACKET *setup = (WINUSB_SETUP_PACKET *) transfer->buffer;
	ULONG size;
	HANDLE winusb_handle;
	int current_interface;
	struct winfd wfd;

	CHECK_WINUSBX_AVAILABLE(sub_api);

	transfer_priv->pollable_fd = INVALID_WINFD;
	size = transfer->length - LIBUSB_CONTROL_SETUP_SIZE;

	if (size > MAX_CTRL_BUFFER_LENGTH)
		return LIBUSB_ERROR_INVALID_PARAM;

	current_interface = get_valid_interface(transfer->dev_handle, USB_API_WINUSBX);
	if (current_interface < 0) {
		if (auto_claim(transfer, &current_interface, USB_API_WINUSBX) != LIBUSB_SUCCESS) {
			return LIBUSB_ERROR_NOT_FOUND;
		}
	}

	usbi_dbg("will use interface %d", current_interface);
	winusb_handle = handle_priv->interface_handle[current_interface].api_handle;

	wfd = usbi_create_fd(winusb_handle, RW_READ, NULL, NULL);
	// Always use the handle returned from usbi_create_fd (wfd.handle)
	if (wfd.fd < 0) {
		return LIBUSB_ERROR_NO_MEM;
	}

	// Sending of set configuration control requests from WinUSB creates issues
	if ( ((setup->request_type & (0x03 << 5)) == LIBUSB_REQUEST_TYPE_STANDARD)
	  && (setup->request == LIBUSB_REQUEST_SET_CONFIGURATION) ) {
		if (setup->value != priv->active_config) {
			usbi_warn(ctx, "cannot set configuration other than the default one");
			usbi_free_fd(&wfd);
			return LIBUSB_ERROR_INVALID_PARAM;
		}
		wfd.overlapped->Internal = STATUS_COMPLETED_SYNCHRONOUSLY;
		wfd.overlapped->InternalHigh = 0;
	} else {
		if (!WinUSBX[sub_api].ControlTransfer(wfd.handle, *setup, transfer->buffer + LIBUSB_CONTROL_SETUP_SIZE, size, NULL, wfd.overlapped)) {
			if(GetLastError() != ERROR_IO_PENDING) {
				usbi_warn(ctx, "ControlTransfer failed: %s", windows_error_str(0));
				usbi_free_fd(&wfd);
				return LIBUSB_ERROR_IO;
			}
		} else {
			wfd.overlapped->Internal = STATUS_COMPLETED_SYNCHRONOUSLY;
			wfd.overlapped->InternalHigh = (DWORD)size;
		}
	}

	// Use priv_transfer to store data needed for async polling
	transfer_priv->pollable_fd = wfd;
	transfer_priv->interface_number = (uint8_t)current_interface;

	return LIBUSB_SUCCESS;
}

static int winusbx_set_interface_altsetting(int sub_api, struct libusb_device_handle *dev_handle, int iface, int altsetting)
{
	struct libusb_context *ctx = DEVICE_CTX(dev_handle->dev);
	struct windows_device_handle_priv *handle_priv = _device_handle_priv(dev_handle);
	struct windows_device_priv *priv = _device_priv(dev_handle->dev);
	HANDLE winusb_handle;

	CHECK_WINUSBX_AVAILABLE(sub_api);

	if (altsetting > 255) {
		return LIBUSB_ERROR_INVALID_PARAM;
	}

	winusb_handle = handle_priv->interface_handle[iface].api_handle;
	if ((winusb_handle == 0) || (winusb_handle == INVALID_HANDLE_VALUE)) {
		usbi_err(ctx, "interface must be claimed first");
		return LIBUSB_ERROR_NOT_FOUND;
	}

	if (!WinUSBX[sub_api].SetCurrentAlternateSetting(winusb_handle, (UCHAR)altsetting)) {
		usbi_err(ctx, "SetCurrentAlternateSetting failed: %s", windows_error_str(0));
		return LIBUSB_ERROR_IO;
	}

	return LIBUSB_SUCCESS;
}

static int winusbx_submit_bulk_transfer(int sub_api, struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct libusb_context *ctx = DEVICE_CTX(transfer->dev_handle->dev);
	struct windows_transfer_priv *transfer_priv = (struct windows_transfer_priv*)usbi_transfer_get_os_priv(itransfer);
	struct windows_device_handle_priv *handle_priv = _device_handle_priv(transfer->dev_handle);
	struct windows_device_priv *priv = _device_priv(transfer->dev_handle->dev);
	HANDLE winusb_handle;
	bool ret;
	int current_interface;
	struct winfd wfd;

	CHECK_WINUSBX_AVAILABLE(sub_api);

	transfer_priv->pollable_fd = INVALID_WINFD;

	current_interface = interface_by_endpoint(priv, handle_priv, transfer->endpoint);
	if (current_interface < 0) {
		usbi_err(ctx, "unable to match endpoint to an open interface - cancelling transfer");
		return LIBUSB_ERROR_NOT_FOUND;
	}

	usbi_dbg("matched endpoint %02X with interface %d", transfer->endpoint, current_interface);

	winusb_handle = handle_priv->interface_handle[current_interface].api_handle;

	wfd = usbi_create_fd(winusb_handle, IS_XFERIN(transfer) ? RW_READ : RW_WRITE, NULL, NULL);
	// Always use the handle returned from usbi_create_fd (wfd.handle)
	if (wfd.fd < 0) {
		return LIBUSB_ERROR_NO_MEM;
	}

	if (IS_XFERIN(transfer)) {
		usbi_dbg("reading %d bytes", transfer->length);
		ret = WinUSBX[sub_api].ReadPipe(wfd.handle, transfer->endpoint, transfer->buffer, transfer->length, NULL, wfd.overlapped);
	} else {
		usbi_dbg("writing %d bytes", transfer->length);
		ret = WinUSBX[sub_api].WritePipe(wfd.handle, transfer->endpoint, transfer->buffer, transfer->length, NULL, wfd.overlapped);
	}
	if (!ret) {
		if(GetLastError() != ERROR_IO_PENDING) {
			usbi_err(ctx, "ReadPipe/WritePipe failed: %s", windows_error_str(0));
			usbi_free_fd(&wfd);
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

static int winusbx_clear_halt(int sub_api, struct libusb_device_handle *dev_handle, unsigned char endpoint)
{
	struct libusb_context *ctx = DEVICE_CTX(dev_handle->dev);
	struct windows_device_handle_priv *handle_priv = _device_handle_priv(dev_handle);
	struct windows_device_priv *priv = _device_priv(dev_handle->dev);
	HANDLE winusb_handle;
	int current_interface;

	CHECK_WINUSBX_AVAILABLE(sub_api);

	current_interface = interface_by_endpoint(priv, handle_priv, endpoint);
	if (current_interface < 0) {
		usbi_err(ctx, "unable to match endpoint to an open interface - cannot clear");
		return LIBUSB_ERROR_NOT_FOUND;
	}

	usbi_dbg("matched endpoint %02X with interface %d", endpoint, current_interface);
	winusb_handle = handle_priv->interface_handle[current_interface].api_handle;

	if (!WinUSBX[sub_api].ResetPipe(winusb_handle, endpoint)) {
		usbi_err(ctx, "ResetPipe failed: %s", windows_error_str(0));
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
static int winusbx_abort_control(int sub_api, struct usbi_transfer *itransfer)
{
	// Cancelling of the I/O is done in the parent
	return LIBUSB_SUCCESS;
}

static int winusbx_abort_transfers(int sub_api, struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct libusb_context *ctx = DEVICE_CTX(transfer->dev_handle->dev);
	struct windows_device_handle_priv *handle_priv = _device_handle_priv(transfer->dev_handle);
	struct windows_transfer_priv *transfer_priv = (struct windows_transfer_priv*)usbi_transfer_get_os_priv(itransfer);
	struct windows_device_priv *priv = _device_priv(transfer->dev_handle->dev);
	HANDLE winusb_handle;
	int current_interface;

	CHECK_WINUSBX_AVAILABLE(sub_api);

	current_interface = transfer_priv->interface_number;
	if ((current_interface < 0) || (current_interface >= USB_MAXINTERFACES)) {
		usbi_err(ctx, "program assertion failed: invalid interface_number");
		return LIBUSB_ERROR_NOT_FOUND;
	}
	usbi_dbg("will use interface %d", current_interface);

	winusb_handle = handle_priv->interface_handle[current_interface].api_handle;

	if (!WinUSBX[sub_api].AbortPipe(winusb_handle, transfer->endpoint)) {
		usbi_err(ctx, "AbortPipe failed: %s", windows_error_str(0));
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
// TODO: (post hotplug): see if we can force eject the device and redetect it (reuse hotplug?)
static int winusbx_reset_device(int sub_api, struct libusb_device_handle *dev_handle)
{
	struct libusb_context *ctx = DEVICE_CTX(dev_handle->dev);
	struct windows_device_handle_priv *handle_priv = _device_handle_priv(dev_handle);
	struct windows_device_priv *priv = _device_priv(dev_handle->dev);
	struct winfd wfd;
	HANDLE winusb_handle;
	int i, j;

	CHECK_WINUSBX_AVAILABLE(sub_api);

	// Reset any available pipe (except control)
	for (i=0; i<USB_MAXINTERFACES; i++) {
		winusb_handle = handle_priv->interface_handle[i].api_handle;
		for (wfd = handle_to_winfd(winusb_handle); wfd.fd > 0;)
		{
			// Cancel any pollable I/O
			usbi_remove_pollfd(ctx, wfd.fd);
			usbi_free_fd(&wfd);
			wfd = handle_to_winfd(winusb_handle);
		}

		if ( (winusb_handle != 0) && (winusb_handle != INVALID_HANDLE_VALUE)) {
			for (j=0; j<priv->usb_interface[i].nb_endpoints; j++) {
				usbi_dbg("resetting ep %02X", priv->usb_interface[i].endpoint[j]);
				if (!WinUSBX[sub_api].AbortPipe(winusb_handle, priv->usb_interface[i].endpoint[j])) {
					usbi_err(ctx, "AbortPipe (pipe address %02X) failed: %s",
						priv->usb_interface[i].endpoint[j], windows_error_str(0));
				}
				// FlushPipe seems to fail on OUT pipes
				if (IS_EPIN(priv->usb_interface[i].endpoint[j])
				  && (!WinUSBX[sub_api].FlushPipe(winusb_handle, priv->usb_interface[i].endpoint[j])) ) {
					usbi_err(ctx, "FlushPipe (pipe address %02X) failed: %s",
						priv->usb_interface[i].endpoint[j], windows_error_str(0));
				}
				if (!WinUSBX[sub_api].ResetPipe(winusb_handle, priv->usb_interface[i].endpoint[j])) {
					usbi_err(ctx, "ResetPipe (pipe address %02X) failed: %s",
						priv->usb_interface[i].endpoint[j], windows_error_str(0));
				}
			}
		}
	}

	// libusbK & libusb0 have the ability to issue an actual device reset
	if (WinUSBX[sub_api].ResetDevice != NULL) {
		winusb_handle = handle_priv->interface_handle[0].api_handle;
		if ( (winusb_handle != 0) && (winusb_handle != INVALID_HANDLE_VALUE)) {
			WinUSBX[sub_api].ResetDevice(winusb_handle);
		}
	}
	return LIBUSB_SUCCESS;
}

static int winusbx_copy_transfer_data(int sub_api, struct usbi_transfer *itransfer, uint32_t io_size)
{
	itransfer->transferred += io_size;
	return LIBUSB_TRANSFER_COMPLETED;
}

/*
 * Internal HID Support functions (from libusb-win32)
 * Note that functions that complete data transfer synchronously must return
 * LIBUSB_COMPLETED instead of LIBUSB_SUCCESS
 */
static int _hid_get_hid_descriptor(struct hid_device_priv* dev, void *data, size_t *size);
static int _hid_get_report_descriptor(struct hid_device_priv* dev, void *data, size_t *size);

static int _hid_wcslen(WCHAR *str)
{
	int i = 0;
	while (str[i] && (str[i] != 0x409)) {
		i++;
	}
	return i;
}

static int _hid_get_device_descriptor(struct hid_device_priv* dev, void *data, size_t *size)
{
	struct libusb_device_descriptor d;

	d.bLength = LIBUSB_DT_DEVICE_SIZE;
	d.bDescriptorType = LIBUSB_DT_DEVICE;
	d.bcdUSB = 0x0200; /* 2.00 */
	d.bDeviceClass = 0;
	d.bDeviceSubClass = 0;
	d.bDeviceProtocol = 0;
	d.bMaxPacketSize0 = 64; /* fix this! */
	d.idVendor = (uint16_t)dev->vid;
	d.idProduct = (uint16_t)dev->pid;
	d.bcdDevice = 0x0100;
	d.iManufacturer = dev->string_index[0];
	d.iProduct = dev->string_index[1];
	d.iSerialNumber = dev->string_index[2];
	d.bNumConfigurations = 1;

	if (*size > LIBUSB_DT_DEVICE_SIZE)
		*size = LIBUSB_DT_DEVICE_SIZE;
	memcpy(data, &d, *size);
	return LIBUSB_COMPLETED;
}

static int _hid_get_config_descriptor(struct hid_device_priv* dev, void *data, size_t *size)
{
	char num_endpoints = 0;
	size_t config_total_len = 0;
	char tmp[HID_MAX_CONFIG_DESC_SIZE];
	struct libusb_config_descriptor *cd;
	struct libusb_interface_descriptor *id;
	struct libusb_hid_descriptor *hd;
	struct libusb_endpoint_descriptor *ed;
	size_t tmp_size;

	if (dev->input_report_size)
		num_endpoints++;
	if (dev->output_report_size)
		num_endpoints++;

	config_total_len = LIBUSB_DT_CONFIG_SIZE + LIBUSB_DT_INTERFACE_SIZE
		+ LIBUSB_DT_HID_SIZE + num_endpoints * LIBUSB_DT_ENDPOINT_SIZE;


	cd = (struct libusb_config_descriptor *)tmp;
	id = (struct libusb_interface_descriptor *)(tmp + LIBUSB_DT_CONFIG_SIZE);
	hd = (struct libusb_hid_descriptor *)(tmp + LIBUSB_DT_CONFIG_SIZE
		+ LIBUSB_DT_INTERFACE_SIZE);
	ed = (struct libusb_endpoint_descriptor *)(tmp + LIBUSB_DT_CONFIG_SIZE
		+ LIBUSB_DT_INTERFACE_SIZE
		+ LIBUSB_DT_HID_SIZE);

	cd->bLength = LIBUSB_DT_CONFIG_SIZE;
	cd->bDescriptorType = LIBUSB_DT_CONFIG;
	cd->wTotalLength = (uint16_t) config_total_len;
	cd->bNumInterfaces = 1;
	cd->bConfigurationValue = 1;
	cd->iConfiguration = 0;
	cd->bmAttributes = 1 << 7; /* bus powered */
	cd->MaxPower = 50;

	id->bLength = LIBUSB_DT_INTERFACE_SIZE;
	id->bDescriptorType = LIBUSB_DT_INTERFACE;
	id->bInterfaceNumber = 0;
	id->bAlternateSetting = 0;
	id->bNumEndpoints = num_endpoints;
	id->bInterfaceClass = 3;
	id->bInterfaceSubClass = 0;
	id->bInterfaceProtocol = 0;
	id->iInterface = 0;

	tmp_size = LIBUSB_DT_HID_SIZE;
	_hid_get_hid_descriptor(dev, hd, &tmp_size);

	if (dev->input_report_size) {
		ed->bLength = LIBUSB_DT_ENDPOINT_SIZE;
		ed->bDescriptorType = LIBUSB_DT_ENDPOINT;
		ed->bEndpointAddress = HID_IN_EP;
		ed->bmAttributes = 3;
		ed->wMaxPacketSize = dev->input_report_size - 1;
		ed->bInterval = 10;
		ed = (struct libusb_endpoint_descriptor *)((char*)ed + LIBUSB_DT_ENDPOINT_SIZE);
	}

	if (dev->output_report_size) {
		ed->bLength = LIBUSB_DT_ENDPOINT_SIZE;
		ed->bDescriptorType = LIBUSB_DT_ENDPOINT;
		ed->bEndpointAddress = HID_OUT_EP;
		ed->bmAttributes = 3;
		ed->wMaxPacketSize = dev->output_report_size - 1;
		ed->bInterval = 10;
	}

	if (*size > config_total_len)
		*size = config_total_len;
	memcpy(data, tmp, *size);
	return LIBUSB_COMPLETED;
}

static int _hid_get_string_descriptor(struct hid_device_priv* dev, int _index,
									  void *data, size_t *size)
{
	void *tmp = NULL;
	size_t tmp_size = 0;
	int i;

	/* language ID, EN-US */
	char string_langid[] = {
		0x09,
		0x04
	};

	if ((*size < 2) || (*size > 255)) {
		return LIBUSB_ERROR_OVERFLOW;
	}

	if (_index == 0) {
		tmp = string_langid;
		tmp_size = sizeof(string_langid)+2;
	} else {
		for (i=0; i<3; i++) {
			if (_index == (dev->string_index[i])) {
				tmp = dev->string[i];
				tmp_size = (_hid_wcslen(dev->string[i])+1) * sizeof(WCHAR);
				break;
			}
		}
		if (i == 3) {	// not found
			return LIBUSB_ERROR_INVALID_PARAM;
		}
	}

	if(!tmp_size) {
		return LIBUSB_ERROR_INVALID_PARAM;
	}

	if (tmp_size < *size) {
		*size = tmp_size;
	}
	// 2 byte header
	((uint8_t*)data)[0] = (uint8_t)*size;
	((uint8_t*)data)[1] = LIBUSB_DT_STRING;
	memcpy((uint8_t*)data+2, tmp, *size-2);
	return LIBUSB_COMPLETED;
}

static int _hid_get_hid_descriptor(struct hid_device_priv* dev, void *data, size_t *size)
{
	struct libusb_hid_descriptor d;
	uint8_t tmp[MAX_HID_DESCRIPTOR_SIZE];
	size_t report_len = MAX_HID_DESCRIPTOR_SIZE;

	_hid_get_report_descriptor(dev, tmp, &report_len);

	d.bLength = LIBUSB_DT_HID_SIZE;
	d.bDescriptorType = LIBUSB_DT_HID;
	d.bcdHID = 0x0110; /* 1.10 */
	d.bCountryCode = 0;
	d.bNumDescriptors = 1;
	d.bClassDescriptorType = LIBUSB_DT_REPORT;
	d.wClassDescriptorLength = (uint16_t)report_len;

	if (*size > LIBUSB_DT_HID_SIZE)
		*size = LIBUSB_DT_HID_SIZE;
	memcpy(data, &d, *size);
	return LIBUSB_COMPLETED;
}

static int _hid_get_report_descriptor(struct hid_device_priv* dev, void *data, size_t *size)
{
	uint8_t d[MAX_HID_DESCRIPTOR_SIZE];
	size_t i = 0;

	/* usage page (0xFFA0 == vendor defined) */
	d[i++] = 0x06; d[i++] = 0xA0; d[i++] = 0xFF;
	/* usage (vendor defined) */
	d[i++] = 0x09; d[i++] = 0x01;
	/* start collection (application) */
	d[i++] = 0xA1; d[i++] = 0x01;
	/* input report */
	if (dev->input_report_size) {
		/* usage (vendor defined) */
		d[i++] = 0x09; d[i++] = 0x01;
		/* logical minimum (0) */
		d[i++] = 0x15; d[i++] = 0x00;
		/* logical maximum (255) */
		d[i++] = 0x25; d[i++] = 0xFF;
		/* report size (8 bits) */
		d[i++] = 0x75; d[i++] = 0x08;
		/* report count */
		d[i++] = 0x95; d[i++] = (uint8_t)dev->input_report_size - 1;
		/* input (data, variable, absolute) */
		d[i++] = 0x81; d[i++] = 0x00;
	}
	/* output report */
	if (dev->output_report_size) {
		/* usage (vendor defined) */
		d[i++] = 0x09; d[i++] = 0x02;
		/* logical minimum (0) */
		d[i++] = 0x15; d[i++] = 0x00;
		/* logical maximum (255) */
		d[i++] = 0x25; d[i++] = 0xFF;
		/* report size (8 bits) */
		d[i++] = 0x75; d[i++] = 0x08;
		/* report count */
		d[i++] = 0x95; d[i++] = (uint8_t)dev->output_report_size - 1;
		/* output (data, variable, absolute) */
		d[i++] = 0x91; d[i++] = 0x00;
	}
	/* feature report */
	if (dev->feature_report_size) {
		/* usage (vendor defined) */
		d[i++] = 0x09; d[i++] = 0x03;
		/* logical minimum (0) */
		d[i++] = 0x15; d[i++] = 0x00;
		/* logical maximum (255) */
		d[i++] = 0x25; d[i++] = 0xFF;
		/* report size (8 bits) */
		d[i++] = 0x75; d[i++] = 0x08;
		/* report count */
		d[i++] = 0x95; d[i++] = (uint8_t)dev->feature_report_size - 1;
		/* feature (data, variable, absolute) */
		d[i++] = 0xb2; d[i++] = 0x02; d[i++] = 0x01;
	}

	/* end collection */
	d[i++] = 0xC0;

	if (*size > i)
		*size = i;
	memcpy(data, d, *size);
	return LIBUSB_COMPLETED;
}

static int _hid_get_descriptor(struct hid_device_priv* dev, HANDLE hid_handle, int recipient,
							   int type, int _index, void *data, size_t *size)
{
	switch(type) {
	case LIBUSB_DT_DEVICE:
		usbi_dbg("LIBUSB_DT_DEVICE");
		return _hid_get_device_descriptor(dev, data, size);
	case LIBUSB_DT_CONFIG:
		usbi_dbg("LIBUSB_DT_CONFIG");
		if (!_index)
			return _hid_get_config_descriptor(dev, data, size);
		return LIBUSB_ERROR_INVALID_PARAM;
	case LIBUSB_DT_STRING:
		usbi_dbg("LIBUSB_DT_STRING");
		return _hid_get_string_descriptor(dev, _index, data, size);
	case LIBUSB_DT_HID:
		usbi_dbg("LIBUSB_DT_HID");
		if (!_index)
			return _hid_get_hid_descriptor(dev, data, size);
		return LIBUSB_ERROR_INVALID_PARAM;
	case LIBUSB_DT_REPORT:
		usbi_dbg("LIBUSB_DT_REPORT");
		if (!_index)
			return _hid_get_report_descriptor(dev, data, size);
		return LIBUSB_ERROR_INVALID_PARAM;
	case LIBUSB_DT_PHYSICAL:
		usbi_dbg("LIBUSB_DT_PHYSICAL");
		if (HidD_GetPhysicalDescriptor(hid_handle, data, (ULONG)*size))
			return LIBUSB_COMPLETED;
		return LIBUSB_ERROR_OTHER;
	}
	usbi_dbg("unsupported");
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int _hid_get_report(struct hid_device_priv* dev, HANDLE hid_handle, int id, void *data,
						   struct windows_transfer_priv *tp, size_t *size, OVERLAPPED* overlapped,
						   int report_type)
{
	uint8_t *buf;
	DWORD ioctl_code, read_size, expected_size = (DWORD)*size;
	int r = LIBUSB_SUCCESS;

	if (tp->hid_buffer != NULL) {
		usbi_dbg("program assertion failed: hid_buffer is not NULL");
	}

	if ((*size == 0) || (*size > MAX_HID_REPORT_SIZE)) {
		usbi_dbg("invalid size (%d)", *size);
		return LIBUSB_ERROR_INVALID_PARAM;
	}

	switch (report_type) {
		case HID_REPORT_TYPE_INPUT:
			ioctl_code = IOCTL_HID_GET_INPUT_REPORT;
			break;
		case HID_REPORT_TYPE_FEATURE:
			ioctl_code = IOCTL_HID_GET_FEATURE;
			break;
		default:
			usbi_dbg("unknown HID report type %d", report_type);
			return LIBUSB_ERROR_INVALID_PARAM;
	}

	// Add a trailing byte to detect overflows
	buf = (uint8_t*)calloc(expected_size+1, 1);
	if (buf == NULL) {
		return LIBUSB_ERROR_NO_MEM;
	}
	buf[0] = (uint8_t)id;	// Must be set always
	usbi_dbg("report ID: 0x%02X", buf[0]);

	tp->hid_expected_size = expected_size;
	read_size = expected_size;

	// NB: The size returned by DeviceIoControl doesn't include report IDs when not in use (0)
	if (!DeviceIoControl(hid_handle, ioctl_code, buf, expected_size+1,
		buf, expected_size+1, &read_size, overlapped)) {
		if (GetLastError() != ERROR_IO_PENDING) {
			usbi_dbg("Failed to Read HID Report: %s", windows_error_str(0));
			safe_free(buf);
			return LIBUSB_ERROR_IO;
		}
		// Asynchronous wait
		tp->hid_buffer = buf;
		tp->hid_dest = (uint8_t*)data; // copy dest, as not necessarily the start of the transfer buffer
		return LIBUSB_SUCCESS;
	}

	// Transfer completed synchronously => copy and discard extra buffer
	if (read_size == 0) {
		usbi_warn(NULL, "program assertion failed - read completed synchronously, but no data was read");
		*size = 0;
	} else {
		if (buf[0] != id) {
			usbi_warn(NULL, "mismatched report ID (data is %02X, parameter is %02X)", buf[0], id);
		}
		if ((size_t)read_size > expected_size) {
			r = LIBUSB_ERROR_OVERFLOW;
			usbi_dbg("OVERFLOW!");
		} else {
			r = LIBUSB_COMPLETED;
		}

		*size = MIN((size_t)read_size, *size);
		if (id == 0) {
			// Discard report ID
			memcpy(data, buf+1, *size);
		} else {
			memcpy(data, buf, *size);
		}
	}
	safe_free(buf);
	return r;
}

static int _hid_set_report(struct hid_device_priv* dev, HANDLE hid_handle, int id, void *data,
						   struct windows_transfer_priv *tp, size_t *size, OVERLAPPED* overlapped,
						   int report_type)
{
	uint8_t *buf = NULL;
	DWORD ioctl_code, write_size= (DWORD)*size;

	if (tp->hid_buffer != NULL) {
		usbi_dbg("program assertion failed: hid_buffer is not NULL");
	}

	if ((*size == 0) || (*size > MAX_HID_REPORT_SIZE)) {
		usbi_dbg("invalid size (%d)", *size);
		return LIBUSB_ERROR_INVALID_PARAM;
	}

	switch (report_type) {
		case HID_REPORT_TYPE_OUTPUT:
			ioctl_code = IOCTL_HID_SET_OUTPUT_REPORT;
			break;
		case HID_REPORT_TYPE_FEATURE:
			ioctl_code = IOCTL_HID_SET_FEATURE;
			break;
		default:
			usbi_dbg("unknown HID report type %d", report_type);
			return LIBUSB_ERROR_INVALID_PARAM;
	}

	usbi_dbg("report ID: 0x%02X", id);
	// When report IDs are not used (i.e. when id == 0), we must add
	// a null report ID. Otherwise, we just use original data buffer
	if (id == 0) {
		write_size++;
	}
	buf = (uint8_t*) malloc(write_size);
	if (buf == NULL) {
		return LIBUSB_ERROR_NO_MEM;
	}
	if (id == 0) {
		buf[0] = 0;
		memcpy(buf + 1, data, *size);
	} else {
		// This seems like a waste, but if we don't duplicate the
		// data, we'll get issues when freeing hid_buffer
		memcpy(buf, data, *size);
		if (buf[0] != id) {
			usbi_warn(NULL, "mismatched report ID (data is %02X, parameter is %02X)", buf[0], id);
		}
	}

	// NB: The size returned by DeviceIoControl doesn't include report IDs when not in use (0)
	if (!DeviceIoControl(hid_handle, ioctl_code, buf, write_size,
		buf, write_size, &write_size, overlapped)) {
		if (GetLastError() != ERROR_IO_PENDING) {
			usbi_dbg("Failed to Write HID Output Report: %s", windows_error_str(0));
			safe_free(buf);
			return LIBUSB_ERROR_IO;
		}
		tp->hid_buffer = buf;
		tp->hid_dest = NULL;
		return LIBUSB_SUCCESS;
	}

	// Transfer completed synchronously
	*size = write_size;
	if (write_size == 0) {
		usbi_dbg("program assertion failed - write completed synchronously, but no data was written");
	}
	safe_free(buf);
	return LIBUSB_COMPLETED;
}

static int _hid_class_request(struct hid_device_priv* dev, HANDLE hid_handle, int request_type,
							  int request, int value, int _index, void *data, struct windows_transfer_priv *tp,
							  size_t *size, OVERLAPPED* overlapped)
{
	int report_type = (value >> 8) & 0xFF;
	int report_id = value & 0xFF;

	if ( (LIBUSB_REQ_RECIPIENT(request_type) != LIBUSB_RECIPIENT_INTERFACE)
	  && (LIBUSB_REQ_RECIPIENT(request_type) != LIBUSB_RECIPIENT_DEVICE) )
		return LIBUSB_ERROR_INVALID_PARAM;

	if (LIBUSB_REQ_OUT(request_type) && request == HID_REQ_SET_REPORT)
		return _hid_set_report(dev, hid_handle, report_id, data, tp, size, overlapped, report_type);

	if (LIBUSB_REQ_IN(request_type) && request == HID_REQ_GET_REPORT)
		return _hid_get_report(dev, hid_handle, report_id, data, tp, size, overlapped, report_type);

	return LIBUSB_ERROR_INVALID_PARAM;
}


/*
 * HID API functions
 */
static int hid_init(int sub_api, struct libusb_context *ctx)
{
	DLL_LOAD(hid.dll, HidD_GetAttributes, TRUE);
	DLL_LOAD(hid.dll, HidD_GetHidGuid, TRUE);
	DLL_LOAD(hid.dll, HidD_GetPreparsedData, TRUE);
	DLL_LOAD(hid.dll, HidD_FreePreparsedData, TRUE);
	DLL_LOAD(hid.dll, HidD_GetManufacturerString, TRUE);
	DLL_LOAD(hid.dll, HidD_GetProductString, TRUE);
	DLL_LOAD(hid.dll, HidD_GetSerialNumberString, TRUE);
	DLL_LOAD(hid.dll, HidP_GetCaps, TRUE);
	DLL_LOAD(hid.dll, HidD_SetNumInputBuffers, TRUE);
	DLL_LOAD(hid.dll, HidD_SetFeature, TRUE);
	DLL_LOAD(hid.dll, HidD_GetFeature, TRUE);
	DLL_LOAD(hid.dll, HidD_GetPhysicalDescriptor, TRUE);
	DLL_LOAD(hid.dll, HidD_GetInputReport, FALSE);
	DLL_LOAD(hid.dll, HidD_SetOutputReport, FALSE);
	DLL_LOAD(hid.dll, HidD_FlushQueue, TRUE);
	DLL_LOAD(hid.dll, HidP_GetValueCaps, TRUE);

	api_hid_available = true;
	return LIBUSB_SUCCESS;
}

static int hid_exit(int sub_api)
{
	return LIBUSB_SUCCESS;
}

// NB: open and close must ensure that they only handle interface of
// the right API type, as these functions can be called wholesale from
// composite_open(), with interfaces belonging to different APIs
static int hid_open(int sub_api, struct libusb_device_handle *dev_handle)
{
	struct libusb_context *ctx = DEVICE_CTX(dev_handle->dev);
	struct windows_device_priv *priv = _device_priv(dev_handle->dev);
	struct windows_device_handle_priv *handle_priv = _device_handle_priv(dev_handle);

	HIDD_ATTRIBUTES hid_attributes;
	PHIDP_PREPARSED_DATA preparsed_data = NULL;
	HIDP_CAPS capabilities;
	HIDP_VALUE_CAPS *value_caps;

	HANDLE hid_handle = INVALID_HANDLE_VALUE;
	int i, j;
	// report IDs handling
	ULONG size[3];
	const char* type[3] = {"input", "output", "feature"};
	int nb_ids[2];	// zero and nonzero report IDs

	CHECK_HID_AVAILABLE;
	if (priv->hid == NULL) {
		usbi_err(ctx, "program assertion failed - private HID structure is unitialized");
		return LIBUSB_ERROR_NOT_FOUND;
	}

	for (i = 0; i < USB_MAXINTERFACES; i++) {
		if ( (priv->usb_interface[i].path != NULL)
		  && (priv->usb_interface[i].apib->id == USB_API_HID) ) {
			hid_handle = CreateFileA(priv->usb_interface[i].path, GENERIC_WRITE | GENERIC_READ, FILE_SHARE_WRITE | FILE_SHARE_READ,
				NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
			/*
			 * http://www.lvr.com/hidfaq.htm: Why do I receive "Access denied" when attempting to access my HID?
			 * "Windows 2000 and later have exclusive read/write access to HIDs that are configured as a system
			 * keyboards or mice. An application can obtain a handle to a system keyboard or mouse by not
			 * requesting READ or WRITE access with CreateFile. Applications can then use HidD_SetFeature and
			 * HidD_GetFeature (if the device supports Feature reports)."
			 */
			if (hid_handle == INVALID_HANDLE_VALUE) {
				usbi_warn(ctx, "could not open HID device in R/W mode (keyboard or mouse?) - trying without");
				hid_handle = CreateFileA(priv->usb_interface[i].path, 0, FILE_SHARE_WRITE | FILE_SHARE_READ,
					NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
				if (hid_handle == INVALID_HANDLE_VALUE) {
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
				priv->usb_interface[i].restricted_functionality = true;
			}
			handle_priv->interface_handle[i].api_handle = hid_handle;
		}
	}

	hid_attributes.Size = sizeof(hid_attributes);
	do {
		if (!HidD_GetAttributes(hid_handle, &hid_attributes)) {
			usbi_err(ctx, "could not gain access to HID top collection (HidD_GetAttributes)");
			break;
		}

		priv->hid->vid = hid_attributes.VendorID;
		priv->hid->pid = hid_attributes.ProductID;

		// Set the maximum available input buffer size
		for (i=32; HidD_SetNumInputBuffers(hid_handle, i); i*=2);
		usbi_dbg("set maximum input buffer size to %d", i/2);

		// Get the maximum input and output report size
		if (!HidD_GetPreparsedData(hid_handle, &preparsed_data) || !preparsed_data) {
			usbi_err(ctx, "could not read HID preparsed data (HidD_GetPreparsedData)");
			break;
		}
		if (HidP_GetCaps(preparsed_data, &capabilities) != HIDP_STATUS_SUCCESS) {
			usbi_err(ctx, "could not parse HID capabilities (HidP_GetCaps)");
			break;
		}

		// Find out if interrupt will need report IDs
		size[0] = capabilities.NumberInputValueCaps;
		size[1] = capabilities.NumberOutputValueCaps;
		size[2] = capabilities.NumberFeatureValueCaps;
		for (j=HidP_Input; j<=HidP_Feature; j++) {
			usbi_dbg("%d HID %s report value(s) found", size[j], type[j]);
			priv->hid->uses_report_ids[j] = false;
			if (size[j] > 0) {
				value_caps = (HIDP_VALUE_CAPS*) calloc(size[j], sizeof(HIDP_VALUE_CAPS));
				if ( (value_caps != NULL)
				  && (HidP_GetValueCaps((HIDP_REPORT_TYPE)j, value_caps, &size[j], preparsed_data) == HIDP_STATUS_SUCCESS)
				  && (size[j] >= 1) ) {
					nb_ids[0] = 0;
					nb_ids[1] = 0;
					for (i=0; i<(int)size[j]; i++) {
						usbi_dbg("  Report ID: 0x%02X", value_caps[i].ReportID);
						if (value_caps[i].ReportID != 0) {
							nb_ids[1]++;
						} else {
							nb_ids[0]++;
						}
					}
					if (nb_ids[1] != 0) {
						if (nb_ids[0] != 0) {
							usbi_warn(ctx, "program assertion failed: zero and nonzero report IDs used for %s",
								type[j]);
						}
						priv->hid->uses_report_ids[j] = true;
					}
				} else {
					usbi_warn(ctx, "  could not process %s report IDs", type[j]);
				}
				safe_free(value_caps);
			}
		}

		// Set the report sizes
		priv->hid->input_report_size = capabilities.InputReportByteLength;
		priv->hid->output_report_size = capabilities.OutputReportByteLength;
		priv->hid->feature_report_size = capabilities.FeatureReportByteLength;

		// Fetch string descriptors
		priv->hid->string_index[0] = priv->dev_descriptor.iManufacturer;
		if (priv->hid->string_index[0] != 0) {
			HidD_GetManufacturerString(hid_handle, priv->hid->string[0],
				sizeof(priv->hid->string[0]));
		} else {
			priv->hid->string[0][0] = 0;
		}
		priv->hid->string_index[1] = priv->dev_descriptor.iProduct;
		if (priv->hid->string_index[1] != 0) {
			HidD_GetProductString(hid_handle, priv->hid->string[1],
				sizeof(priv->hid->string[1]));
		} else {
			priv->hid->string[1][0] = 0;
		}
		priv->hid->string_index[2] = priv->dev_descriptor.iSerialNumber;
		if (priv->hid->string_index[2] != 0) {
			HidD_GetSerialNumberString(hid_handle, priv->hid->string[2],
				sizeof(priv->hid->string[2]));
		} else {
			priv->hid->string[2][0] = 0;
		}
	} while(0);

	if (preparsed_data) {
		HidD_FreePreparsedData(preparsed_data);
	}

	return LIBUSB_SUCCESS;
}

static void hid_close(int sub_api, struct libusb_device_handle *dev_handle)
{
	struct windows_device_priv *priv = _device_priv(dev_handle->dev);
	struct windows_device_handle_priv *handle_priv = _device_handle_priv(dev_handle);
	HANDLE file_handle;
	int i;

	if (!api_hid_available)
		return;

	for (i = 0; i < USB_MAXINTERFACES; i++) {
		if (priv->usb_interface[i].apib->id == USB_API_HID) {
			file_handle = handle_priv->interface_handle[i].api_handle;
			if ( (file_handle != 0) && (file_handle != INVALID_HANDLE_VALUE)) {
				CloseHandle(file_handle);
			}
		}
	}
}

static int hid_claim_interface(int sub_api, struct libusb_device_handle *dev_handle, int iface)
{
	struct windows_device_handle_priv *handle_priv = _device_handle_priv(dev_handle);
	struct windows_device_priv *priv = _device_priv(dev_handle->dev);

	CHECK_HID_AVAILABLE;

	// NB: Disconnection detection is not possible in this function
	if (priv->usb_interface[iface].path == NULL) {
		return LIBUSB_ERROR_NOT_FOUND;	// invalid iface
	}

	// We use dev_handle as a flag for interface claimed
	if (handle_priv->interface_handle[iface].dev_handle == INTERFACE_CLAIMED) {
		return LIBUSB_ERROR_BUSY;	// already claimed
	}

	handle_priv->interface_handle[iface].dev_handle = INTERFACE_CLAIMED;

	usbi_dbg("claimed interface %d", iface);
	handle_priv->active_interface = iface;

	return LIBUSB_SUCCESS;
}

static int hid_release_interface(int sub_api, struct libusb_device_handle *dev_handle, int iface)
{
	struct windows_device_handle_priv *handle_priv = _device_handle_priv(dev_handle);
	struct windows_device_priv *priv = _device_priv(dev_handle->dev);

	CHECK_HID_AVAILABLE;

	if (priv->usb_interface[iface].path == NULL) {
		return LIBUSB_ERROR_NOT_FOUND;	// invalid iface
	}

	if (handle_priv->interface_handle[iface].dev_handle != INTERFACE_CLAIMED) {
		return LIBUSB_ERROR_NOT_FOUND;	// invalid iface
	}

	handle_priv->interface_handle[iface].dev_handle = INVALID_HANDLE_VALUE;

	return LIBUSB_SUCCESS;
}

static int hid_set_interface_altsetting(int sub_api, struct libusb_device_handle *dev_handle, int iface, int altsetting)
{
	struct libusb_context *ctx = DEVICE_CTX(dev_handle->dev);

	CHECK_HID_AVAILABLE;

	if (altsetting > 255) {
		return LIBUSB_ERROR_INVALID_PARAM;
	}

	if (altsetting != 0) {
		usbi_err(ctx, "set interface altsetting not supported for altsetting >0");
		return LIBUSB_ERROR_NOT_SUPPORTED;
	}

	return LIBUSB_SUCCESS;
}

static int hid_submit_control_transfer(int sub_api, struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct windows_transfer_priv *transfer_priv = (struct windows_transfer_priv*)usbi_transfer_get_os_priv(itransfer);
	struct windows_device_handle_priv *handle_priv = _device_handle_priv(transfer->dev_handle);
	struct windows_device_priv *priv = _device_priv(transfer->dev_handle->dev);
	struct libusb_context *ctx = DEVICE_CTX(transfer->dev_handle->dev);
	WINUSB_SETUP_PACKET *setup = (WINUSB_SETUP_PACKET *) transfer->buffer;
	HANDLE hid_handle;
	struct winfd wfd;
	int current_interface, config;
	size_t size;
	int r = LIBUSB_ERROR_INVALID_PARAM;

	CHECK_HID_AVAILABLE;

	transfer_priv->pollable_fd = INVALID_WINFD;
	safe_free(transfer_priv->hid_buffer);
	transfer_priv->hid_dest = NULL;
	size = transfer->length - LIBUSB_CONTROL_SETUP_SIZE;

	if (size > MAX_CTRL_BUFFER_LENGTH) {
		return LIBUSB_ERROR_INVALID_PARAM;
	}

	current_interface = get_valid_interface(transfer->dev_handle, USB_API_HID);
	if (current_interface < 0) {
		if (auto_claim(transfer, &current_interface, USB_API_HID) != LIBUSB_SUCCESS) {
			return LIBUSB_ERROR_NOT_FOUND;
		}
	}

	usbi_dbg("will use interface %d", current_interface);
	hid_handle = handle_priv->interface_handle[current_interface].api_handle;
	// Always use the handle returned from usbi_create_fd (wfd.handle)
	wfd = usbi_create_fd(hid_handle, RW_READ, NULL, NULL);
	if (wfd.fd < 0) {
		return LIBUSB_ERROR_NOT_FOUND;
	}

	switch(LIBUSB_REQ_TYPE(setup->request_type)) {
	case LIBUSB_REQUEST_TYPE_STANDARD:
		switch(setup->request) {
		case LIBUSB_REQUEST_GET_DESCRIPTOR:
			r = _hid_get_descriptor(priv->hid, wfd.handle, LIBUSB_REQ_RECIPIENT(setup->request_type),
				(setup->value >> 8) & 0xFF, setup->value & 0xFF, transfer->buffer + LIBUSB_CONTROL_SETUP_SIZE, &size);
			break;
		case LIBUSB_REQUEST_GET_CONFIGURATION:
			r = windows_get_configuration(transfer->dev_handle, &config);
			if (r == LIBUSB_SUCCESS) {
				size = 1;
				((uint8_t*)transfer->buffer)[LIBUSB_CONTROL_SETUP_SIZE] = (uint8_t)config;
				r = LIBUSB_COMPLETED;
			}
			break;
		case LIBUSB_REQUEST_SET_CONFIGURATION:
			if (setup->value == priv->active_config) {
				r = LIBUSB_COMPLETED;
			} else {
				usbi_warn(ctx, "cannot set configuration other than the default one");
				r = LIBUSB_ERROR_NOT_SUPPORTED;
			}
			break;
		case LIBUSB_REQUEST_GET_INTERFACE:
			size = 1;
			((uint8_t*)transfer->buffer)[LIBUSB_CONTROL_SETUP_SIZE] = 0;
			r = LIBUSB_COMPLETED;
			break;
		case LIBUSB_REQUEST_SET_INTERFACE:
			r = hid_set_interface_altsetting(0, transfer->dev_handle, setup->index, setup->value);
			if (r == LIBUSB_SUCCESS) {
				r = LIBUSB_COMPLETED;
			}
			break;
		default:
			usbi_warn(ctx, "unsupported HID control request");
			r = LIBUSB_ERROR_NOT_SUPPORTED;
			break;
		}
		break;
	case LIBUSB_REQUEST_TYPE_CLASS:
		r =_hid_class_request(priv->hid, wfd.handle, setup->request_type, setup->request, setup->value,
			setup->index, transfer->buffer + LIBUSB_CONTROL_SETUP_SIZE, transfer_priv,
			&size, wfd.overlapped);
		break;
	default:
		usbi_warn(ctx, "unsupported HID control request");
		r = LIBUSB_ERROR_NOT_SUPPORTED;
		break;
	}

	if (r == LIBUSB_COMPLETED) {
		// Force request to be completed synchronously. Transferred size has been set by previous call
		wfd.overlapped->Internal = STATUS_COMPLETED_SYNCHRONOUSLY;
		// http://msdn.microsoft.com/en-us/library/ms684342%28VS.85%29.aspx
		// set InternalHigh to the number of bytes transferred
		wfd.overlapped->InternalHigh = (DWORD)size;
		r = LIBUSB_SUCCESS;
	}

	if (r == LIBUSB_SUCCESS) {
		// Use priv_transfer to store data needed for async polling
		transfer_priv->pollable_fd = wfd;
		transfer_priv->interface_number = (uint8_t)current_interface;
	} else {
		usbi_free_fd(&wfd);
	}

	return r;
}

static int hid_submit_bulk_transfer(int sub_api, struct usbi_transfer *itransfer) {
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct windows_transfer_priv *transfer_priv = (struct windows_transfer_priv*)usbi_transfer_get_os_priv(itransfer);
	struct libusb_context *ctx = DEVICE_CTX(transfer->dev_handle->dev);
	struct windows_device_handle_priv *handle_priv = _device_handle_priv(transfer->dev_handle);
	struct windows_device_priv *priv = _device_priv(transfer->dev_handle->dev);
	struct winfd wfd;
	HANDLE hid_handle;
	bool direction_in, ret;
	int current_interface, length;
	DWORD size;
	int r = LIBUSB_SUCCESS;

	CHECK_HID_AVAILABLE;

	transfer_priv->pollable_fd = INVALID_WINFD;
	transfer_priv->hid_dest = NULL;
	safe_free(transfer_priv->hid_buffer);

	current_interface = interface_by_endpoint(priv, handle_priv, transfer->endpoint);
	if (current_interface < 0) {
		usbi_err(ctx, "unable to match endpoint to an open interface - cancelling transfer");
		return LIBUSB_ERROR_NOT_FOUND;
	}

	usbi_dbg("matched endpoint %02X with interface %d", transfer->endpoint, current_interface);

	hid_handle = handle_priv->interface_handle[current_interface].api_handle;
	direction_in = transfer->endpoint & LIBUSB_ENDPOINT_IN;

	wfd = usbi_create_fd(hid_handle, direction_in?RW_READ:RW_WRITE, NULL, NULL);
	// Always use the handle returned from usbi_create_fd (wfd.handle)
	if (wfd.fd < 0) {
		return LIBUSB_ERROR_NO_MEM;
	}

	// If report IDs are not in use, an extra prefix byte must be added
	if ( ((direction_in) && (!priv->hid->uses_report_ids[0]))
	  || ((!direction_in) && (!priv->hid->uses_report_ids[1])) ) {
		length = transfer->length+1;
	} else {
		length = transfer->length;
	}
	// Add a trailing byte to detect overflows on input
	transfer_priv->hid_buffer = (uint8_t*)calloc(length+1, 1);
	if (transfer_priv->hid_buffer == NULL) {
		return LIBUSB_ERROR_NO_MEM;
	}
	transfer_priv->hid_expected_size = length;

	if (direction_in) {
		transfer_priv->hid_dest = transfer->buffer;
		usbi_dbg("reading %d bytes (report ID: 0x00)", length);
		ret = ReadFile(wfd.handle, transfer_priv->hid_buffer, length+1, &size, wfd.overlapped);
	} else {
		if (!priv->hid->uses_report_ids[1]) {
			memcpy(transfer_priv->hid_buffer+1, transfer->buffer, transfer->length);
		} else {
			// We could actually do without the calloc and memcpy in this case
			memcpy(transfer_priv->hid_buffer, transfer->buffer, transfer->length);
		}
		usbi_dbg("writing %d bytes (report ID: 0x%02X)", length, transfer_priv->hid_buffer[0]);
		ret = WriteFile(wfd.handle, transfer_priv->hid_buffer, length, &size, wfd.overlapped);
	}
	if (!ret) {
		if (GetLastError() != ERROR_IO_PENDING) {
			usbi_err(ctx, "HID transfer failed: %s", windows_error_str(0));
			usbi_free_fd(&wfd);
			safe_free(transfer_priv->hid_buffer);
			return LIBUSB_ERROR_IO;
		}
	} else {
		// Only write operations that completed synchronously need to free up
		// hid_buffer. For reads, copy_transfer_data() handles that process.
		if (!direction_in) {
			safe_free(transfer_priv->hid_buffer);
		}
		if (size == 0) {
			usbi_err(ctx, "program assertion failed - no data was transferred");
			size = 1;
		}
		if (size > (size_t)length) {
			usbi_err(ctx, "OVERFLOW!");
			r = LIBUSB_ERROR_OVERFLOW;
		}
		wfd.overlapped->Internal = STATUS_COMPLETED_SYNCHRONOUSLY;
		wfd.overlapped->InternalHigh = size;
	}

	transfer_priv->pollable_fd = wfd;
	transfer_priv->interface_number = (uint8_t)current_interface;

	return r;
}

static int hid_abort_transfers(int sub_api, struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct windows_transfer_priv *transfer_priv = (struct windows_transfer_priv*)usbi_transfer_get_os_priv(itransfer);
	struct windows_device_handle_priv *handle_priv = _device_handle_priv(transfer->dev_handle);
	HANDLE hid_handle;
	int current_interface;

	CHECK_HID_AVAILABLE;

	current_interface = transfer_priv->interface_number;
	hid_handle = handle_priv->interface_handle[current_interface].api_handle;
	CancelIo(hid_handle);

	return LIBUSB_SUCCESS;
}

static int hid_reset_device(int sub_api, struct libusb_device_handle *dev_handle)
{
	struct windows_device_handle_priv *handle_priv = _device_handle_priv(dev_handle);
	HANDLE hid_handle;
	int current_interface;

	CHECK_HID_AVAILABLE;

	// Flushing the queues on all interfaces is the best we can achieve
	for (current_interface = 0; current_interface < USB_MAXINTERFACES; current_interface++) {
		hid_handle = handle_priv->interface_handle[current_interface].api_handle;
		if ((hid_handle != 0) && (hid_handle != INVALID_HANDLE_VALUE)) {
			HidD_FlushQueue(hid_handle);
		}
	}
	return LIBUSB_SUCCESS;
}

static int hid_clear_halt(int sub_api, struct libusb_device_handle *dev_handle, unsigned char endpoint)
{
	struct libusb_context *ctx = DEVICE_CTX(dev_handle->dev);
	struct windows_device_handle_priv *handle_priv = _device_handle_priv(dev_handle);
	struct windows_device_priv *priv = _device_priv(dev_handle->dev);
	HANDLE hid_handle;
	int current_interface;

	CHECK_HID_AVAILABLE;

	current_interface = interface_by_endpoint(priv, handle_priv, endpoint);
	if (current_interface < 0) {
		usbi_err(ctx, "unable to match endpoint to an open interface - cannot clear");
		return LIBUSB_ERROR_NOT_FOUND;
	}

	usbi_dbg("matched endpoint %02X with interface %d", endpoint, current_interface);
	hid_handle = handle_priv->interface_handle[current_interface].api_handle;

	// No endpoint selection with Microsoft's implementation, so we try to flush the
	// whole interface. Should be OK for most case scenarios
	if (!HidD_FlushQueue(hid_handle)) {
		usbi_err(ctx, "Flushing of HID queue failed: %s", windows_error_str(0));
		// Device was probably disconnected
		return LIBUSB_ERROR_NO_DEVICE;
	}

	return LIBUSB_SUCCESS;
}

// This extra function is only needed for HID
static int hid_copy_transfer_data(int sub_api, struct usbi_transfer *itransfer, uint32_t io_size) {
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct libusb_context *ctx = DEVICE_CTX(transfer->dev_handle->dev);
	struct windows_transfer_priv *transfer_priv = usbi_transfer_get_os_priv(itransfer);
	int r = LIBUSB_TRANSFER_COMPLETED;
	uint32_t corrected_size = io_size;

	if (transfer_priv->hid_buffer != NULL) {
		// If we have a valid hid_buffer, it means the transfer was async
		if (transfer_priv->hid_dest != NULL) {	// Data readout
			if (corrected_size > 0) {
				// First, check for overflow
				if (corrected_size > transfer_priv->hid_expected_size) {
					usbi_err(ctx, "OVERFLOW!");
					corrected_size = (uint32_t)transfer_priv->hid_expected_size;
					r = LIBUSB_TRANSFER_OVERFLOW;
				}

				if (transfer_priv->hid_buffer[0] == 0) {
					// Discard the 1 byte report ID prefix
					corrected_size--;
					memcpy(transfer_priv->hid_dest, transfer_priv->hid_buffer+1, corrected_size);
				} else {
					memcpy(transfer_priv->hid_dest, transfer_priv->hid_buffer, corrected_size);
				}
			}
			transfer_priv->hid_dest = NULL;
		}
		// For write, we just need to free the hid buffer
		safe_free(transfer_priv->hid_buffer);
	}
	itransfer->transferred += corrected_size;
	return r;
}


/*
 * Composite API functions
 */
static int composite_init(int sub_api, struct libusb_context *ctx)
{
	return LIBUSB_SUCCESS;
}

static int composite_exit(int sub_api)
{
	return LIBUSB_SUCCESS;
}

static int composite_open(int sub_api, struct libusb_device_handle *dev_handle)
{
	struct windows_device_priv *priv = _device_priv(dev_handle->dev);
	int r = LIBUSB_ERROR_NOT_FOUND;
	uint8_t i;
	// SUB_API_MAX+1 as the SUB_API_MAX pos is used to indicate availability of HID
	bool available[SUB_API_MAX+1] = {0};

	for (i=0; i<USB_MAXINTERFACES; i++) {
		switch (priv->usb_interface[i].apib->id) {
		case USB_API_WINUSBX:
			if (priv->usb_interface[i].sub_api != SUB_API_NOTSET)
				available[priv->usb_interface[i].sub_api] = true;
			break;
		case USB_API_HID:
			available[SUB_API_MAX] = true;
			break;
		default:
			break;
		}
	}

	for (i=0; i<SUB_API_MAX; i++) {	// WinUSB-like drivers
		if (available[i]) {
			r = usb_api_backend[USB_API_WINUSBX].open(i, dev_handle);
			if (r != LIBUSB_SUCCESS) {
				return r;
			}
		}
	}
	if (available[SUB_API_MAX]) {	// HID driver
		r = hid_open(SUB_API_NOTSET, dev_handle);
	}
	return r;
}

static void composite_close(int sub_api, struct libusb_device_handle *dev_handle)
{
	struct windows_device_priv *priv = _device_priv(dev_handle->dev);
	uint8_t i;
	// SUB_API_MAX+1 as the SUB_API_MAX pos is used to indicate availability of HID
	bool available[SUB_API_MAX+1] = {0};

	for (i=0; i<USB_MAXINTERFACES; i++) {
		switch (priv->usb_interface[i].apib->id) {
		case USB_API_WINUSBX:
			if (priv->usb_interface[i].sub_api != SUB_API_NOTSET)
				available[priv->usb_interface[i].sub_api] = true;
			break;
		case USB_API_HID:
			available[SUB_API_MAX] = true;
			break;
		default:
			break;
		}
	}

	for (i=0; i<SUB_API_MAX; i++) {	// WinUSB-like drivers
		if (available[i]) {
			usb_api_backend[USB_API_WINUSBX].close(i, dev_handle);
		}
	}
	if (available[SUB_API_MAX]) {	// HID driver
		hid_close(SUB_API_NOTSET, dev_handle);
	}
}

static int composite_claim_interface(int sub_api, struct libusb_device_handle *dev_handle, int iface)
{
	struct windows_device_priv *priv = _device_priv(dev_handle->dev);
	return priv->usb_interface[iface].apib->
		claim_interface(priv->usb_interface[iface].sub_api, dev_handle, iface);
}

static int composite_set_interface_altsetting(int sub_api, struct libusb_device_handle *dev_handle, int iface, int altsetting)
{
	struct windows_device_priv *priv = _device_priv(dev_handle->dev);
	return priv->usb_interface[iface].apib->
		set_interface_altsetting(priv->usb_interface[iface].sub_api, dev_handle, iface, altsetting);
}

static int composite_release_interface(int sub_api, struct libusb_device_handle *dev_handle, int iface)
{
	struct windows_device_priv *priv = _device_priv(dev_handle->dev);
	return priv->usb_interface[iface].apib->
		release_interface(priv->usb_interface[iface].sub_api, dev_handle, iface);
}

static int composite_submit_control_transfer(int sub_api, struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct libusb_context *ctx = DEVICE_CTX(transfer->dev_handle->dev);
	struct windows_device_priv *priv = _device_priv(transfer->dev_handle->dev);
	struct libusb_config_descriptor *conf_desc;
	WINUSB_SETUP_PACKET *setup = (WINUSB_SETUP_PACKET *) transfer->buffer;
	int iface, pass, r;

	// Interface shouldn't matter for control, but it does in practice, with Windows'
	// restrictions with regards to accessing HID keyboards and mice. Try to target
	// a specific interface first, if possible.
	switch (LIBUSB_REQ_RECIPIENT(setup->request_type)) {
	case LIBUSB_RECIPIENT_INTERFACE:
		iface = setup->index & 0xFF;
		break;
	case LIBUSB_RECIPIENT_ENDPOINT:
		r = libusb_get_config_descriptor(transfer->dev_handle->dev, (uint8_t)(priv->active_config-1), &conf_desc);
		if (r == LIBUSB_SUCCESS) {
			iface = get_interface_by_endpoint(conf_desc, (setup->index & 0xFF));
			libusb_free_config_descriptor(conf_desc);
			break;
		}
		// Fall through if not able to determine interface
	default:
		iface = -1;
		break;
	}

	// Try and target a specific interface if the control setup indicates such
	if ((iface >= 0) && (iface < USB_MAXINTERFACES)) {
		usbi_dbg("attempting control transfer targeted to interface %d", iface);
		if (priv->usb_interface[iface].path != NULL) {
			r = priv->usb_interface[iface].apib->submit_control_transfer(priv->usb_interface[iface].sub_api, itransfer);
			if (r == LIBUSB_SUCCESS) {
				return r;
			}
		}
	}

	// Either not targeted to a specific interface or no luck in doing so.
	// Try a 2 pass approach with all interfaces.
	for (pass = 0; pass < 2; pass++) {
		for (iface = 0; iface < USB_MAXINTERFACES; iface++) {
			if (priv->usb_interface[iface].path != NULL) {
				if ((pass == 0) && (priv->usb_interface[iface].restricted_functionality)) {
					usbi_dbg("trying to skip restricted interface #%d (HID keyboard or mouse?)", iface);
					continue;
				}
				usbi_dbg("using interface %d", iface);
				r = priv->usb_interface[iface].apib->submit_control_transfer(priv->usb_interface[iface].sub_api, itransfer);
				// If not supported on this API, it may be supported on another, so don't give up yet!!
				if (r == LIBUSB_ERROR_NOT_SUPPORTED) {
					continue;
				}
				return r;
			}
		}
	}

	usbi_err(ctx, "no libusb supported interfaces to complete request");
	return LIBUSB_ERROR_NOT_FOUND;
}

static int composite_submit_bulk_transfer(int sub_api, struct usbi_transfer *itransfer) {
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct libusb_context *ctx = DEVICE_CTX(transfer->dev_handle->dev);
	struct windows_device_handle_priv *handle_priv = _device_handle_priv(transfer->dev_handle);
	struct windows_device_priv *priv = _device_priv(transfer->dev_handle->dev);
	int current_interface;

	current_interface = interface_by_endpoint(priv, handle_priv, transfer->endpoint);
	if (current_interface < 0) {
		usbi_err(ctx, "unable to match endpoint to an open interface - cancelling transfer");
		return LIBUSB_ERROR_NOT_FOUND;
	}

	return priv->usb_interface[current_interface].apib->
		submit_bulk_transfer(priv->usb_interface[current_interface].sub_api, itransfer);}

static int composite_submit_iso_transfer(int sub_api, struct usbi_transfer *itransfer) {
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct libusb_context *ctx = DEVICE_CTX(transfer->dev_handle->dev);
	struct windows_device_handle_priv *handle_priv = _device_handle_priv(transfer->dev_handle);
	struct windows_device_priv *priv = _device_priv(transfer->dev_handle->dev);
	int current_interface;

	current_interface = interface_by_endpoint(priv, handle_priv, transfer->endpoint);
	if (current_interface < 0) {
		usbi_err(ctx, "unable to match endpoint to an open interface - cancelling transfer");
		return LIBUSB_ERROR_NOT_FOUND;
	}

	return priv->usb_interface[current_interface].apib->
		submit_iso_transfer(priv->usb_interface[current_interface].sub_api, itransfer);}

static int composite_clear_halt(int sub_api, struct libusb_device_handle *dev_handle, unsigned char endpoint)
{
	struct libusb_context *ctx = DEVICE_CTX(dev_handle->dev);
	struct windows_device_handle_priv *handle_priv = _device_handle_priv(dev_handle);
	struct windows_device_priv *priv = _device_priv(dev_handle->dev);
	int current_interface;

	current_interface = interface_by_endpoint(priv, handle_priv, endpoint);
	if (current_interface < 0) {
		usbi_err(ctx, "unable to match endpoint to an open interface - cannot clear");
		return LIBUSB_ERROR_NOT_FOUND;
	}

	return priv->usb_interface[current_interface].apib->
		clear_halt(priv->usb_interface[current_interface].sub_api, dev_handle, endpoint);}

static int composite_abort_control(int sub_api, struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct windows_transfer_priv *transfer_priv = usbi_transfer_get_os_priv(itransfer);
	struct windows_device_priv *priv = _device_priv(transfer->dev_handle->dev);

	return priv->usb_interface[transfer_priv->interface_number].apib->
		abort_control(priv->usb_interface[transfer_priv->interface_number].sub_api, itransfer);}

static int composite_abort_transfers(int sub_api, struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct windows_transfer_priv *transfer_priv = usbi_transfer_get_os_priv(itransfer);
	struct windows_device_priv *priv = _device_priv(transfer->dev_handle->dev);

	return priv->usb_interface[transfer_priv->interface_number].apib->
		abort_transfers(priv->usb_interface[transfer_priv->interface_number].sub_api, itransfer);}

static int composite_reset_device(int sub_api, struct libusb_device_handle *dev_handle)
{
	struct windows_device_priv *priv = _device_priv(dev_handle->dev);
	int r;
	uint8_t i; 
	bool available[SUB_API_MAX];
	for (i = 0; i<SUB_API_MAX; i++) {
		available[i] = false;
	}
	for (i=0; i<USB_MAXINTERFACES; i++) {
		if ( (priv->usb_interface[i].apib->id == USB_API_WINUSBX)
		  && (priv->usb_interface[i].sub_api != SUB_API_NOTSET) ) {
			available[priv->usb_interface[i].sub_api] = true;
		}
	}
	for (i=0; i<SUB_API_MAX; i++) {
		if (available[i]) {
			r = usb_api_backend[USB_API_WINUSBX].reset_device(i, dev_handle);
			if (r != LIBUSB_SUCCESS) {
				return r;
			}
		}
	}
	return LIBUSB_SUCCESS;
}

static int composite_copy_transfer_data(int sub_api, struct usbi_transfer *itransfer, uint32_t io_size)
{
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct windows_transfer_priv *transfer_priv = usbi_transfer_get_os_priv(itransfer);
	struct windows_device_priv *priv = _device_priv(transfer->dev_handle->dev);

	return priv->usb_interface[transfer_priv->interface_number].apib->
		copy_transfer_data(priv->usb_interface[transfer_priv->interface_number].sub_api, itransfer, io_size);
}
