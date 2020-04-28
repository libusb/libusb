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

#include <errno.h>
#include <inttypes.h>
#include <process.h>
#include <stdio.h>

#include "libusbi.h"
#include "windows_common.h"

#define EPOCH_TIME	UINT64_C(116444736000000000)	// 1970.01.01 00:00:000 in MS Filetime

#define STATUS_SUCCESS	((ULONG_PTR)0UL)

// Public
enum windows_version windows_version = WINDOWS_UNDEFINED;

 // Global variables for init/exit
static unsigned int init_count;
static bool usbdk_available;

#if !defined(HAVE_CLOCK_GETTIME)
// Global variables for clock_gettime mechanism
static uint64_t hires_ticks_to_ps;
static uint64_t hires_frequency;
#endif

/*
* Converts a windows error to human readable string
* uses retval as errorcode, or, if 0, use GetLastError()
*/
#if defined(ENABLE_LOGGING)
const char *windows_error_str(DWORD error_code)
{
	static char err_string[256];

	DWORD size;
	int len;

	if (error_code == 0)
		error_code = GetLastError();

	len = sprintf(err_string, "[%lu] ", ULONG_CAST(error_code));

	// Translate codes returned by SetupAPI. The ones we are dealing with are either
	// in 0x0000xxxx or 0xE000xxxx and can be distinguished from standard error codes.
	// See http://msdn.microsoft.com/en-us/library/windows/hardware/ff545011.aspx
	switch (error_code & 0xE0000000) {
	case 0:
		error_code = HRESULT_FROM_WIN32(error_code); // Still leaves ERROR_SUCCESS unmodified
		break;
	case 0xE0000000:
		error_code = 0x80000000 | (FACILITY_SETUPAPI << 16) | (error_code & 0x0000FFFF);
		break;
	default:
		break;
	}

	size = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			&err_string[len], sizeof(err_string) - len, NULL);
	if (size == 0) {
		DWORD format_error = GetLastError();
		if (format_error)
			snprintf(err_string, sizeof(err_string),
				"Windows error code %lu (FormatMessage error code %lu)",
				ULONG_CAST(error_code), ULONG_CAST(format_error));
		else
			snprintf(err_string, sizeof(err_string), "Unknown error code %lu",
				ULONG_CAST(error_code));
	} else {
		// Remove CRLF from end of message, if present
		size_t pos = len + size - 2;
		if (err_string[pos] == '\r')
			err_string[pos] = '\0';
	}

	return err_string;
}
#endif

/* Hash table functions - modified From glibc 2.3.2:
   [Aho,Sethi,Ullman] Compilers: Principles, Techniques and Tools, 1986
   [Knuth]            The Art of Computer Programming, part 3 (6.4)  */

#define HTAB_SIZE 1021UL	// *MUST* be a prime number!!

typedef struct htab_entry {
	unsigned long used;
	char *str;
} htab_entry;

static htab_entry *htab_table;
static usbi_mutex_t htab_mutex;
static unsigned long htab_filled;

/* Before using the hash table we must allocate memory for it.
   We allocate one element more as the found prime number says.
   This is done for more effective indexing as explained in the
   comment for the hash function.  */
static bool htab_create(struct libusb_context *ctx)
{
	if (htab_table != NULL) {
		usbi_err(ctx, "program assertion falied - hash table already allocated");
		return true;
	}

	// Create a mutex
	usbi_mutex_init(&htab_mutex);

	usbi_dbg("using %lu entries hash table", HTAB_SIZE);
	htab_filled = 0;

	// allocate memory and zero out.
	htab_table = calloc(HTAB_SIZE + 1, sizeof(htab_entry));
	if (htab_table == NULL) {
		usbi_err(ctx, "could not allocate space for hash table");
		return false;
	}

	return true;
}

/* After using the hash table it has to be destroyed.  */
static void htab_destroy(void)
{
	unsigned long i;

	if (htab_table == NULL)
		return;

	for (i = 0; i < HTAB_SIZE; i++)
		free(htab_table[i].str);

	safe_free(htab_table);

	usbi_mutex_destroy(&htab_mutex);
}

/* This is the search function. It uses double hashing with open addressing.
   We use a trick to speed up the lookup. The table is created with one
   more element available. This enables us to use the index zero special.
   This index will never be used because we store the first hash index in
   the field used where zero means not used. Every other value means used.
   The used field can be used as a first fast comparison for equality of
   the stored and the parameter value. This helps to prevent unnecessary
   expensive calls of strcmp.  */
unsigned long htab_hash(const char *str)
{
	unsigned long hval, hval2;
	unsigned long idx;
	unsigned long r = 5381UL;
	int c;
	const char *sz = str;

	if (str == NULL)
		return 0;

	// Compute main hash value (algorithm suggested by Nokia)
	while ((c = *sz++) != 0)
		r = ((r << 5) + r) + c;
	if (r == 0)
		++r;

	// compute table hash: simply take the modulus
	hval = r % HTAB_SIZE;
	if (hval == 0)
		++hval;

	// Try the first index
	idx = hval;

	// Mutually exclusive access (R/W lock would be better)
	usbi_mutex_lock(&htab_mutex);

	if (htab_table[idx].used) {
		if ((htab_table[idx].used == hval) && (strcmp(str, htab_table[idx].str) == 0))
			goto out_unlock; // existing hash

		usbi_dbg("hash collision ('%s' vs '%s')", str, htab_table[idx].str);

		// Second hash function, as suggested in [Knuth]
		hval2 = 1UL + hval % (HTAB_SIZE - 2);

		do {
			// Because size is prime this guarantees to step through all available indexes
			if (idx <= hval2)
				idx = HTAB_SIZE + idx - hval2;
			else
				idx -= hval2;

			// If we visited all entries leave the loop unsuccessfully
			if (idx == hval)
				break;

			// If entry is found use it.
			if ((htab_table[idx].used == hval) && (strcmp(str, htab_table[idx].str) == 0))
				goto out_unlock;
		} while (htab_table[idx].used);
	}

	// Not found => New entry

	// If the table is full return an error
	if (htab_filled >= HTAB_SIZE) {
		usbi_err(NULL, "hash table is full (%lu entries)", HTAB_SIZE);
		idx = 0UL;
		goto out_unlock;
	}

	htab_table[idx].str = _strdup(str);
	if (htab_table[idx].str == NULL) {
		usbi_err(NULL, "could not duplicate string for hash table");
		idx = 0UL;
		goto out_unlock;
	}

	htab_table[idx].used = hval;
	++htab_filled;

out_unlock:
	usbi_mutex_unlock(&htab_mutex);

	return idx;
}

enum libusb_transfer_status usbd_status_to_libusb_transfer_status(USBD_STATUS status)
{
	if (USBD_SUCCESS(status))
		return LIBUSB_TRANSFER_COMPLETED;

	switch (status) {
	case USBD_STATUS_TIMEOUT:
		return LIBUSB_TRANSFER_TIMED_OUT;
	case USBD_STATUS_CANCELED:
		return LIBUSB_TRANSFER_CANCELLED;
	case USBD_STATUS_ENDPOINT_HALTED:
		return LIBUSB_TRANSFER_STALL;
	case USBD_STATUS_DEVICE_GONE:
		return LIBUSB_TRANSFER_NO_DEVICE;
	default:
		usbi_dbg("USBD_STATUS 0x%08lx translated to LIBUSB_TRANSFER_ERROR", ULONG_CAST(status));
		return LIBUSB_TRANSFER_ERROR;
	}
}

/*
* Make a transfer complete synchronously
*/
void windows_force_sync_completion(OVERLAPPED *overlapped, ULONG size)
{
	overlapped->Internal = (ULONG_PTR)STATUS_SUCCESS;
	overlapped->InternalHigh = (ULONG_PTR)size;
	SetEvent(overlapped->hEvent);
}

static void windows_init_clock(void)
{
#if !defined(HAVE_CLOCK_GETTIME)
	LARGE_INTEGER li_frequency;

	// Microsoft says that the QueryPerformanceFrequency() and
	// QueryPerformanceCounter() functions always succeed on XP and later
	QueryPerformanceFrequency(&li_frequency);

	// The hires frequency can go as high as 4 GHz, so we'll use a conversion
	// to picoseconds to compute the tv_nsecs part in clock_gettime
	hires_frequency = li_frequency.QuadPart;
	hires_ticks_to_ps = UINT64_C(1000000000000) / hires_frequency;
	usbi_dbg("hires timer frequency: %"PRIu64" Hz", hires_frequency);
#endif
}

/* Windows version detection */
static BOOL is_x64(void)
{
	BOOL ret = FALSE;

	// Detect if we're running a 32 or 64 bit system
	if (sizeof(uintptr_t) < 8) {
		IsWow64Process(GetCurrentProcess(), &ret);
	} else {
		ret = TRUE;
	}

	return ret;
}

static void get_windows_version(void)
{
	OSVERSIONINFOEXA vi, vi2;
	const char *arch, *w = NULL;
	unsigned major, minor, version;
	ULONGLONG major_equal, minor_equal;
	bool ws;

	windows_version = WINDOWS_UNDEFINED;

	memset(&vi, 0, sizeof(vi));
	vi.dwOSVersionInfoSize = sizeof(vi);
	if (!GetVersionExA((OSVERSIONINFOA *)&vi)) {
		memset(&vi, 0, sizeof(vi));
		vi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
		if (!GetVersionExA((OSVERSIONINFOA *)&vi))
			return;
	}

	if (vi.dwPlatformId != VER_PLATFORM_WIN32_NT)
		return;

	if ((vi.dwMajorVersion > 6) || ((vi.dwMajorVersion == 6) && (vi.dwMinorVersion >= 2))) {
		// Starting with Windows 8.1 Preview, GetVersionEx() does no longer report the actual OS version
		// See: http://msdn.microsoft.com/en-us/library/windows/desktop/dn302074.aspx

		major_equal = VerSetConditionMask(0, VER_MAJORVERSION, VER_EQUAL);
		for (major = vi.dwMajorVersion; major <= 9; major++) {
			memset(&vi2, 0, sizeof(vi2));
			vi2.dwOSVersionInfoSize = sizeof(vi2);
			vi2.dwMajorVersion = major;
			if (!VerifyVersionInfoA(&vi2, VER_MAJORVERSION, major_equal))
				continue;

			if (vi.dwMajorVersion < major) {
				vi.dwMajorVersion = major;
				vi.dwMinorVersion = 0;
			}

			minor_equal = VerSetConditionMask(0, VER_MINORVERSION, VER_EQUAL);
			for (minor = vi.dwMinorVersion; minor <= 9; minor++) {
				memset(&vi2, 0, sizeof(vi2));
				vi2.dwOSVersionInfoSize = sizeof(vi2);
				vi2.dwMinorVersion = minor;
				if (!VerifyVersionInfoA(&vi2, VER_MINORVERSION, minor_equal))
					continue;

				vi.dwMinorVersion = minor;
				break;
			}

			break;
		}
	}

	if ((vi.dwMajorVersion > 0xf) || (vi.dwMinorVersion > 0xf))
		return;

	ws = (vi.wProductType <= VER_NT_WORKSTATION);
	version = vi.dwMajorVersion << 4 | vi.dwMinorVersion;
	switch (version) {
	case 0x50: windows_version = WINDOWS_2000;  w = "2000";	break;
	case 0x51: windows_version = WINDOWS_XP;    w = "XP";	break;
	case 0x52: windows_version = WINDOWS_2003;  w = "2003";	break;
	case 0x60: windows_version = WINDOWS_VISTA; w = (ws ? "Vista" : "2008");  break;
	case 0x61: windows_version = WINDOWS_7;	    w = (ws ? "7" : "2008_R2");	  break;
	case 0x62: windows_version = WINDOWS_8;	    w = (ws ? "8" : "2012");	  break;
	case 0x63: windows_version = WINDOWS_8_1;   w = (ws ? "8.1" : "2012_R2"); break;
	case 0x64: // Early Windows 10 Insider Previews and Windows Server 2017 Technical Preview 1 used version 6.4
	case 0xA0: windows_version = WINDOWS_10;    w = (ws ? "10" : "2016");	  break;
	default:
		if (version < 0x50) {
			return;
		} else {
			windows_version = WINDOWS_11_OR_LATER;
			w = "11 or later";
		}
	}

	arch = is_x64() ? "64-bit" : "32-bit";

	if (vi.wServicePackMinor)
		usbi_dbg("Windows %s SP%u.%u %s", w, vi.wServicePackMajor, vi.wServicePackMinor, arch);
	else if (vi.wServicePackMajor)
		usbi_dbg("Windows %s SP%u %s", w, vi.wServicePackMajor, arch);
	else
		usbi_dbg("Windows %s %s", w, arch);
}

static void windows_transfer_callback(const struct windows_backend *backend,
	struct usbi_transfer *itransfer, DWORD error, DWORD bytes_transferred)
{
	struct windows_transfer_priv *transfer_priv = usbi_get_transfer_priv(itransfer);
	enum libusb_transfer_status status, istatus;

	usbi_dbg("handling I/O completion with errcode %lu, length %lu",
		ULONG_CAST(error), ULONG_CAST(bytes_transferred));

	switch (error) {
	case NO_ERROR:
		status = backend->copy_transfer_data(itransfer, bytes_transferred);
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
		istatus = backend->copy_transfer_data(itransfer, bytes_transferred);
		if (istatus != LIBUSB_TRANSFER_COMPLETED)
			usbi_dbg("failed to copy partial data in aborted operation: %d", (int)istatus);

		usbi_dbg("detected operation aborted");
		status = LIBUSB_TRANSFER_CANCELLED;
		break;
	case ERROR_FILE_NOT_FOUND:
	case ERROR_DEVICE_NOT_CONNECTED:
	case ERROR_NO_SUCH_DEVICE:
		usbi_dbg("detected device removed");
		status = LIBUSB_TRANSFER_NO_DEVICE;
		break;
	default:
		usbi_err(ITRANSFER_CTX(itransfer), "detected I/O error %lu: %s",
			ULONG_CAST(error), windows_error_str(error));
		status = LIBUSB_TRANSFER_ERROR;
		break;
	}

	// Cancel polling
	usbi_close(transfer_priv->pollable_fd.fd);
	transfer_priv->pollable_fd = INVALID_WINFD;
	transfer_priv->handle = NULL;

	// Backend-specific cleanup
	backend->clear_transfer_priv(itransfer);

	if (status == LIBUSB_TRANSFER_CANCELLED)
		usbi_handle_transfer_cancellation(itransfer);
	else
		usbi_handle_transfer_completion(itransfer, status);
}

static int windows_init(struct libusb_context *ctx)
{
	struct windows_context_priv *priv = usbi_get_context_priv(ctx);
	char mutex_name[11 + 8 + 1]; // strlen("libusb_init") + (32-bit hex PID) + '\0'
	HANDLE mutex;
	int r = LIBUSB_ERROR_OTHER;
	bool winusb_backend_init = false;

	sprintf(mutex_name, "libusb_init%08lX", ULONG_CAST(GetCurrentProcessId() & 0xFFFFFFFFU));
	mutex = CreateMutexA(NULL, FALSE, mutex_name);
	if (mutex == NULL) {
		usbi_err(ctx, "could not create mutex: %s", windows_error_str(0));
		return LIBUSB_ERROR_NO_MEM;
	}

	// A successful wait gives this thread ownership of the mutex
	// => any concurent wait stalls until the mutex is released
	if (WaitForSingleObject(mutex, INFINITE) != WAIT_OBJECT_0) {
		usbi_err(ctx, "failure to access mutex: %s", windows_error_str(0));
		CloseHandle(mutex);
		return LIBUSB_ERROR_NO_MEM;
	}

	// NB: concurrent usage supposes that init calls are equally balanced with
	// exit calls. If init is called more than exit, we will not exit properly
	if (++init_count == 1) { // First init?
		get_windows_version();

		if (windows_version == WINDOWS_UNDEFINED) {
			usbi_err(ctx, "failed to detect Windows version");
			r = LIBUSB_ERROR_NOT_SUPPORTED;
			goto init_exit;
		}

		windows_init_clock();

		if (!htab_create(ctx))
			goto init_exit;

		r = winusb_backend.init(ctx);
		if (r != LIBUSB_SUCCESS)
			goto init_exit;
		winusb_backend_init = true;

		r = usbdk_backend.init(ctx);
		if (r == LIBUSB_SUCCESS) {
			usbi_dbg("UsbDk backend is available");
			usbdk_available = true;
		} else {
			usbi_info(ctx, "UsbDk backend is not available");
			// Do not report this as an error
			r = LIBUSB_SUCCESS;
		}
	}

	// By default, new contexts will use the WinUSB backend
	priv->backend = &winusb_backend;

	r = LIBUSB_SUCCESS;

init_exit: // Holds semaphore here
	if ((init_count == 1) && (r != LIBUSB_SUCCESS)) { // First init failed?
		if (winusb_backend_init)
			winusb_backend.exit(ctx);
		htab_destroy();
		--init_count;
	}

	ReleaseMutex(mutex);
	CloseHandle(mutex);
	return r;
}

static void windows_exit(struct libusb_context *ctx)
{
	char mutex_name[11 + 8 + 1]; // strlen("libusb_init") + (32-bit hex PID) + '\0'
	HANDLE mutex;

	sprintf(mutex_name, "libusb_init%08lX", ULONG_CAST(GetCurrentProcessId() & 0xFFFFFFFFU));
	mutex = CreateMutexA(NULL, FALSE, mutex_name);
	if (mutex == NULL)
		return;

	// A successful wait gives this thread ownership of the mutex
	// => any concurent wait stalls until the mutex is released
	if (WaitForSingleObject(mutex, INFINITE) != WAIT_OBJECT_0) {
		usbi_err(ctx, "failed to access mutex: %s", windows_error_str(0));
		CloseHandle(mutex);
		return;
	}

	// Only works if exits and inits are balanced exactly
	if (--init_count == 0) { // Last exit
		if (usbdk_available) {
			usbdk_backend.exit(ctx);
			usbdk_available = false;
		}
		winusb_backend.exit(ctx);
		htab_destroy();
	}

	ReleaseMutex(mutex);
	CloseHandle(mutex);
}

static int windows_set_option(struct libusb_context *ctx, enum libusb_option option, va_list ap)
{
	struct windows_context_priv *priv = usbi_get_context_priv(ctx);

	UNUSED(ap);

	switch ((int)option) {
	case LIBUSB_OPTION_USE_USBDK:
		if (usbdk_available) {
			usbi_dbg("switching context %p to use UsbDk backend", ctx);
			priv->backend = &usbdk_backend;
		} else {
			usbi_err(ctx, "UsbDk backend not available");
			return LIBUSB_ERROR_NOT_FOUND;
		}
		return LIBUSB_SUCCESS;
	default:
		return LIBUSB_ERROR_NOT_SUPPORTED;
	}
}

static int windows_get_device_list(struct libusb_context *ctx, struct discovered_devs **discdevs)
{
	struct windows_context_priv *priv = usbi_get_context_priv(ctx);
	return priv->backend->get_device_list(ctx, discdevs);
}

static int windows_open(struct libusb_device_handle *dev_handle)
{
	struct windows_context_priv *priv = usbi_get_context_priv(HANDLE_CTX(dev_handle));
	return priv->backend->open(dev_handle);
}

static void windows_close(struct libusb_device_handle *dev_handle)
{
	struct windows_context_priv *priv = usbi_get_context_priv(HANDLE_CTX(dev_handle));
	priv->backend->close(dev_handle);
}

static int windows_get_active_config_descriptor(struct libusb_device *dev,
	void *buffer, size_t len)
{
	struct windows_context_priv *priv = usbi_get_context_priv(DEVICE_CTX(dev));
	return priv->backend->get_active_config_descriptor(dev, buffer, len);
}

static int windows_get_config_descriptor(struct libusb_device *dev,
	uint8_t config_index, void *buffer, size_t len)
{
	struct windows_context_priv *priv = usbi_get_context_priv(DEVICE_CTX(dev));
	return priv->backend->get_config_descriptor(dev, config_index, buffer, len);
}

static int windows_get_config_descriptor_by_value(struct libusb_device *dev,
	uint8_t bConfigurationValue, void **buffer)
{
	struct windows_context_priv *priv = usbi_get_context_priv(DEVICE_CTX(dev));
	return priv->backend->get_config_descriptor_by_value(dev, bConfigurationValue, buffer);
}

static int windows_get_configuration(struct libusb_device_handle *dev_handle, uint8_t *config)
{
	struct windows_context_priv *priv = usbi_get_context_priv(HANDLE_CTX(dev_handle));
	return priv->backend->get_configuration(dev_handle, config);
}

static int windows_set_configuration(struct libusb_device_handle *dev_handle, int config)
{
	struct windows_context_priv *priv = usbi_get_context_priv(HANDLE_CTX(dev_handle));
	if (config == -1)
		config = 0;
	return priv->backend->set_configuration(dev_handle, (uint8_t)config);
}

static int windows_claim_interface(struct libusb_device_handle *dev_handle, uint8_t interface_number)
{
	struct windows_context_priv *priv = usbi_get_context_priv(HANDLE_CTX(dev_handle));
	return priv->backend->claim_interface(dev_handle, interface_number);
}

static int windows_release_interface(struct libusb_device_handle *dev_handle, uint8_t interface_number)
{
	struct windows_context_priv *priv = usbi_get_context_priv(HANDLE_CTX(dev_handle));
	return priv->backend->release_interface(dev_handle, interface_number);
}

static int windows_set_interface_altsetting(struct libusb_device_handle *dev_handle,
	uint8_t interface_number, uint8_t altsetting)
{
	struct windows_context_priv *priv = usbi_get_context_priv(HANDLE_CTX(dev_handle));
	return priv->backend->set_interface_altsetting(dev_handle, interface_number, altsetting);
}

static int windows_clear_halt(struct libusb_device_handle *dev_handle, unsigned char endpoint)
{
	struct windows_context_priv *priv = usbi_get_context_priv(HANDLE_CTX(dev_handle));
	return priv->backend->clear_halt(dev_handle, endpoint);
}

static int windows_reset_device(struct libusb_device_handle *dev_handle)
{
	struct windows_context_priv *priv = usbi_get_context_priv(HANDLE_CTX(dev_handle));
	return priv->backend->reset_device(dev_handle);
}

static void windows_destroy_device(struct libusb_device *dev)
{
	struct windows_context_priv *priv = usbi_get_context_priv(DEVICE_CTX(dev));
	priv->backend->destroy_device(dev);
}

static int windows_submit_transfer(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct libusb_context *ctx = TRANSFER_CTX(transfer);
	struct windows_context_priv *priv = usbi_get_context_priv(ctx);
	struct windows_transfer_priv *transfer_priv = usbi_get_transfer_priv(itransfer);
	short events;
	int r;

	switch (transfer->type) {
	case LIBUSB_TRANSFER_TYPE_CONTROL:
		events = (transfer->buffer[0] & LIBUSB_ENDPOINT_IN) ? POLLIN : POLLOUT;
		break;
	case LIBUSB_TRANSFER_TYPE_BULK:
	case LIBUSB_TRANSFER_TYPE_INTERRUPT:
	case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS:
		events = IS_XFERIN(transfer) ? POLLIN : POLLOUT;
		break;
	case LIBUSB_TRANSFER_TYPE_BULK_STREAM:
		usbi_warn(ctx, "bulk stream transfers are not yet supported on this platform");
		return LIBUSB_ERROR_NOT_SUPPORTED;
	default:
		usbi_err(ctx, "unknown endpoint type %d", transfer->type);
		return LIBUSB_ERROR_INVALID_PARAM;
	}

	// Because a Windows OVERLAPPED is used for poll emulation,
	// a pollable fd is created and stored with each transfer
	transfer_priv->pollable_fd = usbi_create_fd();
	if (transfer_priv->pollable_fd.fd < 0) {
		usbi_err(ctx, "failed to create pollable fd");
		return LIBUSB_ERROR_NO_MEM;
	}

	if (transfer_priv->handle != NULL) {
		usbi_err(ctx, "program assertion failed - transfer HANDLE is not NULL");
		transfer_priv->handle = NULL;
	}

	r = priv->backend->submit_transfer(itransfer);
	if (r != LIBUSB_SUCCESS) {
		// Always call the backend's clear_transfer_priv() function on failure
		priv->backend->clear_transfer_priv(itransfer);
		// Release the pollable fd since it won't be used
		usbi_close(transfer_priv->pollable_fd.fd);
		transfer_priv->pollable_fd = INVALID_WINFD;
		transfer_priv->handle = NULL;
		return r;
	}

	// The backend should set the HANDLE used for each submitted transfer
	// by calling set_transfer_priv_handle()
	if (transfer_priv->handle == NULL)
		usbi_err(ctx, "program assertion failed - transfer HANDLE is NULL after transfer was submitted");

	// We don't want to start monitoring the pollable fd before the transfer
	// has been submitted, so start monitoring it now.  Note that if the
	// usbi_add_pollfd() function fails, the user will never get notified
	// that the transfer has completed.  We don't attempt any cleanup if this
	// happens because the transfer is already in progress and could even have
	// completed
	if (usbi_add_pollfd(ctx, transfer_priv->pollable_fd.fd, events))
		usbi_err(ctx, "failed to add pollable fd %d for transfer %p",
			transfer_priv->pollable_fd.fd, transfer);

	return r;
}

static int windows_cancel_transfer(struct usbi_transfer *itransfer)
{
	struct windows_context_priv *priv = usbi_get_context_priv(ITRANSFER_CTX(itransfer));
	struct windows_transfer_priv *transfer_priv = usbi_get_transfer_priv(itransfer);

	// Try CancelIoEx() on the transfer
	// If that fails, fall back to the backend's cancel_transfer()
	// function if it is available
	if (CancelIoEx(transfer_priv->handle, transfer_priv->pollable_fd.overlapped))
		return LIBUSB_SUCCESS;
	else if (GetLastError() == ERROR_NOT_FOUND)
		return LIBUSB_ERROR_NOT_FOUND;

	if (priv->backend->cancel_transfer)
		return priv->backend->cancel_transfer(itransfer);

	usbi_warn(ITRANSFER_CTX(itransfer), "cancellation not supported for this transfer's driver");
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int windows_handle_events(struct libusb_context *ctx, struct pollfd *fds, usbi_nfds_t nfds, int num_ready)
{
	struct windows_context_priv *priv = usbi_get_context_priv(ctx);
	struct usbi_transfer *itransfer;
	struct windows_transfer_priv *transfer_priv;
	DWORD result, bytes_transferred;
	usbi_nfds_t i;
	int r = LIBUSB_SUCCESS;

	usbi_mutex_lock(&ctx->open_devs_lock);
	for (i = 0; i < nfds && num_ready > 0; i++) {
		usbi_dbg("checking fd %d with revents = %04x", fds[i].fd, fds[i].revents);

		if (!fds[i].revents)
			continue;

		num_ready--;

		transfer_priv = NULL;
		usbi_mutex_lock(&ctx->flying_transfers_lock);
		list_for_each_entry(itransfer, &ctx->flying_transfers, list, struct usbi_transfer) {
			transfer_priv = usbi_get_transfer_priv(itransfer);
			if (transfer_priv->pollable_fd.fd == fds[i].fd)
				break;
			transfer_priv = NULL;
		}
		usbi_mutex_unlock(&ctx->flying_transfers_lock);

		if (transfer_priv == NULL) {
			usbi_err(ctx, "could not find a matching transfer for fd %d", fds[i].fd);
			r = LIBUSB_ERROR_NOT_FOUND;
			break;
		}

		usbi_remove_pollfd(ctx, transfer_priv->pollable_fd.fd);

		if (GetOverlappedResult(transfer_priv->handle, transfer_priv->pollable_fd.overlapped, &bytes_transferred, FALSE))
			result = NO_ERROR;
		else
			result = GetLastError();

		windows_transfer_callback(priv->backend, itransfer, result, bytes_transferred);
	}
	usbi_mutex_unlock(&ctx->open_devs_lock);

	return r;
}

#if !defined(HAVE_CLOCK_GETTIME)
int usbi_clock_gettime(int clk_id, struct timespec *tp)
{
	LARGE_INTEGER hires_counter;
#if !defined(_MSC_VER) || (_MSC_VER < 1900)
	FILETIME filetime;
	ULARGE_INTEGER rtime;
#endif

	switch (clk_id) {
	case USBI_CLOCK_MONOTONIC:
		if (hires_frequency) {
			QueryPerformanceCounter(&hires_counter);
			tp->tv_sec = (long)(hires_counter.QuadPart / hires_frequency);
			tp->tv_nsec = (long)(((hires_counter.QuadPart % hires_frequency) * hires_ticks_to_ps) / UINT64_C(1000));
			return 0;
		}
		// Return real-time if monotonic was not detected @ timer init
		// Fall through
	case USBI_CLOCK_REALTIME:
#if defined(_MSC_VER) && (_MSC_VER >= 1900)
		if (!timespec_get(tp, TIME_UTC)) {
			errno = EIO;
			return -1;
		}
#else
		// We follow http://msdn.microsoft.com/en-us/library/ms724928%28VS.85%29.aspx
		// with a predef epoch time to have an epoch that starts at 1970.01.01 00:00
		// Note however that our resolution is bounded by the Windows system time
		// functions and is at best of the order of 1 ms (or, usually, worse)
		GetSystemTimeAsFileTime(&filetime);
		rtime.LowPart = filetime.dwLowDateTime;
		rtime.HighPart = filetime.dwHighDateTime;
		rtime.QuadPart -= EPOCH_TIME;
		tp->tv_sec = (long)(rtime.QuadPart / 10000000);
		tp->tv_nsec = (long)((rtime.QuadPart % 10000000) * 100);
#endif
		return 0;
	default:
		errno = EINVAL;
		return -1;
	}
}
#endif

// NB: MSVC6 does not support named initializers.
const struct usbi_os_backend usbi_backend = {
	"Windows",
	USBI_CAP_HAS_HID_ACCESS,
	windows_init,
	windows_exit,
	windows_set_option,
	windows_get_device_list,
	NULL,	/* hotplug_poll */
	NULL,	/* wrap_sys_device */
	windows_open,
	windows_close,
	windows_get_active_config_descriptor,
	windows_get_config_descriptor,
	windows_get_config_descriptor_by_value,
	windows_get_configuration,
	windows_set_configuration,
	windows_claim_interface,
	windows_release_interface,
	windows_set_interface_altsetting,
	windows_clear_halt,
	windows_reset_device,
	NULL,	/* alloc_streams */
	NULL,	/* free_streams */
	NULL,	/* dev_mem_alloc */
	NULL,	/* dev_mem_free */
	NULL,	/* kernel_driver_active */
	NULL,	/* detach_kernel_driver */
	NULL,	/* attach_kernel_driver */
	windows_destroy_device,
	windows_submit_transfer,
	windows_cancel_transfer,
	NULL,	/* clear_transfer_priv */
	windows_handle_events,
	NULL,	/* handle_transfer_completion */
	sizeof(struct windows_context_priv),
	sizeof(union windows_device_priv),
	sizeof(union windows_device_handle_priv),
	sizeof(struct windows_transfer_priv),
};
