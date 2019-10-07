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
#include <tchar.h>
#include <inttypes.h>
#include <process.h>
#include <stdio.h>
#include <dbt.h>

#include "libusbi.h"
#include "windows_common.h"
#include "windows_nt_common.h"

// Public
BOOL (WINAPI *pCancelIoEx)(HANDLE, LPOVERLAPPED);
enum windows_version windows_version = WINDOWS_UNDEFINED;

 // Global variables for init/exit
static unsigned int init_count = 0;
static bool usbdk_available = false;

// Global variables for clock_gettime mechanism
static uint64_t hires_ticks_to_ps;
static uint64_t hires_frequency;

#define TIMER_REQUEST_RETRY_MS	100
#define WM_TIMER_REQUEST	(WM_USER + 1)
#define WM_TIMER_EXIT		(WM_USER + 2)

// used for monotonic clock_gettime()
struct timer_request {
	struct timespec *tp;
	HANDLE event;
};

// Event thread
static HANDLE event_thread = NULL;
static DWORD event_thread_id = 0;
static HWND event_window = NULL;
usbi_mutex_t event_lock;

// Timer thread
static HANDLE timer_thread = NULL;
static DWORD timer_thread_id = 0;

/* Kernel32 dependencies */
DLL_DECLARE_HANDLE(Kernel32);
/* This call is only available from XP SP2 */
DLL_DECLARE_FUNC_PREFIXED(WINAPI, BOOL, p, IsWow64Process, (HANDLE, PBOOL));

/* User32 dependencies */
DLL_DECLARE_HANDLE(User32);
DLL_DECLARE_FUNC_PREFIXED(WINAPI, BOOL, p, GetMessageA, (LPMSG, HWND, UINT, UINT));
DLL_DECLARE_FUNC_PREFIXED(WINAPI, BOOL, p, PeekMessageA, (LPMSG, HWND, UINT, UINT, UINT));
DLL_DECLARE_FUNC_PREFIXED(WINAPI, BOOL, p, PostThreadMessageA, (DWORD, UINT, WPARAM, LPARAM));


// http://msdn.microsoft.com/en-us/library/ff545978.aspx
// http://msdn.microsoft.com/en-us/library/ff545972.aspx
// http://msdn.microsoft.com/en-us/library/ff545982.aspx
#ifndef GUID_DEVINTERFACE_USB_HOST_CONTROLLER
GUID const GUID_DEVINTERFACE_USB_HOST_CONTROLLER = {0x3ABF6F2D, 0x71C4, 0x462A, {0x8A, 0x92, 0x1E, 0x68, 0x61, 0xE6, 0xAF, 0x27}};
#endif
#ifndef GUID_DEVINTERFACE_USB_DEVICE
GUID const GUID_DEVINTERFACE_USB_DEVICE = {0xA5DCBF10, 0x6530, 0x11D2, {0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED}};
#endif
#ifndef GUID_DEVINTERFACE_USB_HUB
GUID const GUID_DEVINTERFACE_USB_HUB = {0xF18A0E88, 0xC30C, 0x11D0, {0x88, 0x15, 0x00, 0xA0, 0xC9, 0x06, 0xBE, 0xD8}};
#endif
#ifndef GUID_DEVINTERFACE_LIBUSB0_FILTER
GUID const GUID_DEVINTERFACE_LIBUSB0_FILTER = {0xF9F3FF14, 0xAE21, 0x48A0, {0x8A, 0x25, 0x80, 0x11, 0xA7, 0xA9, 0x31, 0xD9}};
#endif


static unsigned __stdcall windows_clock_gettime_threaded(void *param);

/*
* Converts a windows error to human readable string
* uses retval as errorcode, or, if 0, use GetLastError()
*/
#if defined(ENABLE_LOGGING)
const char *windows_error_str(DWORD error_code)
{
	static char err_string[ERR_BUFFER_SIZE];

	DWORD size;
	int len;

	if (error_code == 0)
		error_code = GetLastError();

	len = sprintf(err_string, "[%u] ", (unsigned int)error_code);

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
			&err_string[len], ERR_BUFFER_SIZE - len, NULL);
	if (size == 0) {
		DWORD format_error = GetLastError();
		if (format_error)
			snprintf(err_string, ERR_BUFFER_SIZE,
				"Windows error code %u (FormatMessage error code %u)",
				(unsigned int)error_code, (unsigned int)format_error);
		else
			snprintf(err_string, ERR_BUFFER_SIZE, "Unknown error code %u", (unsigned int)error_code);
	} else {
		// Remove CRLF from end of message, if present
		size_t pos = len + size - 2;
		if (err_string[pos] == '\r')
			err_string[pos] = '\0';
	}

	return err_string;
}
#endif

static inline struct windows_context_priv *_context_priv(struct libusb_context *ctx)
{
	return (struct windows_context_priv *)ctx->os_priv;
}

/* Hash table functions - modified From glibc 2.3.2:
   [Aho,Sethi,Ullman] Compilers: Principles, Techniques and Tools, 1986
   [Knuth]            The Art of Computer Programming, part 3 (6.4)  */

#define HTAB_SIZE 1021UL	// *MUST* be a prime number!!

typedef struct htab_entry {
	unsigned long used;
	char *str;
} htab_entry;

static htab_entry *htab_table = NULL;
static usbi_mutex_t htab_mutex;
static unsigned long htab_filled;

/* Before using the hash table we must allocate memory for it.
   We allocate one element more as the found prime number says.
   This is done for more effective indexing as explained in the
   comment for the hash function.  */
static bool htab_create(struct libusb_context *ctx)
{
	if (htab_table != NULL) {
		usbi_err(ctx, "hash table already allocated");
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
	unsigned long r = 5381;
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
		hval2 = 1 + hval % (HTAB_SIZE - 2);

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
		idx = 0;
		goto out_unlock;
	}

	htab_table[idx].str = _strdup(str);
	if (htab_table[idx].str == NULL) {
		usbi_err(NULL, "could not duplicate string for hash table");
		idx = 0;
		goto out_unlock;
	}

	htab_table[idx].used = hval;
	++htab_filled;

out_unlock:
	usbi_mutex_unlock(&htab_mutex);

	return idx;
}

/*
* Make a transfer complete synchronously
*/
void windows_force_sync_completion(OVERLAPPED *overlapped, ULONG size)
{
	overlapped->Internal = STATUS_COMPLETED_SYNCHRONOUSLY;
	overlapped->InternalHigh = size;
	SetEvent(overlapped->hEvent);
}

static BOOL windows_init_dlls(void)
{
	DLL_GET_HANDLE(Kernel32);
	DLL_LOAD_FUNC_PREFIXED(Kernel32, p, IsWow64Process, FALSE);
	pCancelIoEx = (BOOL (WINAPI *)(HANDLE, LPOVERLAPPED))
		GetProcAddress(DLL_HANDLE_NAME(Kernel32), "CancelIoEx");
	usbi_dbg("Will use CancelIo%s for I/O cancellation", pCancelIoEx ? "Ex" : "");

	DLL_GET_HANDLE(User32);
	DLL_LOAD_FUNC_PREFIXED(User32, p, GetMessageA, TRUE);
	DLL_LOAD_FUNC_PREFIXED(User32, p, PeekMessageA, TRUE);
	DLL_LOAD_FUNC_PREFIXED(User32, p, PostThreadMessageA, TRUE);

	return TRUE;
}

static void windows_exit_dlls(void)
{
	DLL_FREE_HANDLE(Kernel32);
	DLL_FREE_HANDLE(User32);
}

static bool windows_init_clock(struct libusb_context *ctx)
{
	DWORD_PTR affinity, dummy;
	HANDLE event;
	LARGE_INTEGER li_frequency;
	int i;

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
			return false;
		}

		// The process affinity mask is a bitmask where each set bit represents a core on
		// which this process is allowed to run, so we find the first set bit
		for (i = 0; !(affinity & (DWORD_PTR)(1 << i)); i++);
		affinity = (DWORD_PTR)(1 << i);

		usbi_dbg("timer thread will run on core #%d", i);

		event = CreateEvent(NULL, FALSE, FALSE, NULL);
		if (event == NULL) {
			usbi_err(ctx, "could not create event: %s", windows_error_str(0));
			return false;
		}

		timer_thread = (HANDLE)_beginthreadex(NULL, 0, windows_clock_gettime_threaded, (void *)event,
				0, (unsigned int *)&timer_thread_id);
		if (timer_thread == NULL) {
			usbi_err(ctx, "unable to create timer thread - aborting");
			CloseHandle(event);
			return false;
		}

		if (!SetThreadAffinityMask(timer_thread, affinity))
			usbi_warn(ctx, "unable to set timer thread affinity, timer discrepancies may arise");

		// Wait for timer thread to init before continuing.
		if (WaitForSingleObject(event, INFINITE) != WAIT_OBJECT_0) {
			usbi_err(ctx, "failed to wait for timer thread to become ready - aborting");
			CloseHandle(event);
			return false;
		}

		CloseHandle(event);
	} else {
		usbi_dbg("no hires timer available on this platform");
		hires_frequency = 0;
		hires_ticks_to_ps = UINT64_C(0);
	}

	return true;
}

static void windows_destroy_clock(void)
{
	if (timer_thread) {
		// actually the signal to quit the thread.
		if (!pPostThreadMessageA(timer_thread_id, WM_TIMER_EXIT, 0, 0)
				|| (WaitForSingleObject(timer_thread, INFINITE) != WAIT_OBJECT_0)) {
			usbi_dbg("could not wait for timer thread to quit");
			TerminateThread(timer_thread, 1);
			// shouldn't happen, but we're destroying
			// all objects it might have held anyway.
		}
		CloseHandle(timer_thread);
		timer_thread = NULL;
		timer_thread_id = 0;
	}
}

/* Windows version detection */
static BOOL is_x64(void)
{
	BOOL ret = FALSE;

	// Detect if we're running a 32 or 64 bit system
	if (sizeof(uintptr_t) < 8) {
		if (pIsWow64Process != NULL)
			pIsWow64Process(GetCurrentProcess(), &ret);
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
	BOOL ws;

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

/*
* Monotonic and real time functions
*/
static unsigned __stdcall windows_clock_gettime_threaded(void *param)
{
	struct timer_request *request;
	LARGE_INTEGER hires_counter;
	MSG msg;

	// The following call will create this thread's message queue
	// See https://msdn.microsoft.com/en-us/library/windows/desktop/ms644946.aspx
	pPeekMessageA(&msg, NULL, WM_USER, WM_USER, PM_NOREMOVE);

	// Signal windows_init_clock() that we're ready to service requests
	if (!SetEvent((HANDLE)param))
		usbi_dbg("SetEvent failed for timer init event: %s", windows_error_str(0));
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
			if (!SetEvent(request->event))
				usbi_err(NULL, "SetEvent failed for timer request: %s", windows_error_str(0));
			break;
		case WM_TIMER_EXIT:
			usbi_dbg("timer thread quitting");
			return 0;
		}
	}
}

static void windows_transfer_callback(const struct windows_backend *backend,
	struct usbi_transfer *itransfer, DWORD io_result, DWORD io_size)
{
	int status, istatus;

	usbi_dbg("handling I/O completion with errcode %u, size %u", (unsigned int)io_result, (unsigned int)io_size);

	switch (io_result) {
	case NO_ERROR:
		status = backend->copy_transfer_data(itransfer, (uint32_t)io_size);
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
		istatus = backend->copy_transfer_data(itransfer, (uint32_t)io_size);
		if (istatus != LIBUSB_TRANSFER_COMPLETED)
			usbi_dbg("Failed to copy partial data in aborted operation: %d", istatus);

		usbi_dbg("detected operation aborted");
		status = LIBUSB_TRANSFER_CANCELLED;
		break;
	case ERROR_FILE_NOT_FOUND:
		usbi_dbg("detected device removed");
		status = LIBUSB_TRANSFER_NO_DEVICE;
		break;
	default:
		usbi_err(ITRANSFER_CTX(itransfer), "detected I/O error %u: %s", (unsigned int)io_result, windows_error_str(io_result));
		status = LIBUSB_TRANSFER_ERROR;
		break;
	}
	backend->clear_transfer_priv(itransfer);	// Cancel polling
	if (status == LIBUSB_TRANSFER_CANCELLED)
		usbi_handle_transfer_cancellation(itransfer);
	else
		usbi_handle_transfer_completion(itransfer, (enum libusb_transfer_status)status);
}

static void windows_handle_callback(const struct windows_backend *backend,
	struct usbi_transfer *itransfer, DWORD io_result, DWORD io_size)
{
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);

	switch (transfer->type) {
	case LIBUSB_TRANSFER_TYPE_CONTROL:
	case LIBUSB_TRANSFER_TYPE_BULK:
	case LIBUSB_TRANSFER_TYPE_INTERRUPT:
	case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS:
		windows_transfer_callback(backend, itransfer, io_result, io_size);
		break;
	case LIBUSB_TRANSFER_TYPE_BULK_STREAM:
		usbi_warn(ITRANSFER_CTX(itransfer), "bulk stream transfers are not yet supported on this platform");
		break;
	default:
		usbi_err(ITRANSFER_CTX(itransfer), "unknown endpoint type %d", transfer->type);
	}
}

static void windows_hotplug_enumerate(TCHAR const *device_path)
{
	struct libusb_context *ctx;

	usbi_mutex_static_lock(&active_contexts_lock);
	list_for_each_entry (ctx, &active_contexts_list, list,
											 struct libusb_context) {
		_context_priv(ctx)->backend->enumerate_device(ctx, device_path);
	}
	usbi_mutex_static_unlock(&active_contexts_lock);
}

static void windows_device_disconnected(TCHAR const *device_path)
{
	struct libusb_context *ctx;

	usbi_mutex_static_lock(&active_contexts_lock);
	list_for_each_entry (ctx, &active_contexts_list, list,
											 struct libusb_context) {
		_context_priv(ctx)->backend->disconnect_device(ctx, device_path);
	}
	usbi_mutex_static_unlock(&active_contexts_lock);
}

static bool windows_setup_event_filter(HWND window, GUID const guid, unsigned i)
{
	HDEVNOTIFY devNotify;
	DEV_BROADCAST_DEVICEINTERFACE filter;
	ZeroMemory(&filter, sizeof(filter));

	filter.dbcc_size = sizeof(DEV_BROADCAST_DEVICEINTERFACE);
	filter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
	filter.dbcc_classguid = guid;

	devNotify = RegisterDeviceNotification(window, &filter, DEVICE_NOTIFY_WINDOW_HANDLE);
	if (NULL == devNotify) {
		usbi_err(NULL, "Failed to create filter");
		return false;
	}
	SetWindowLongPtr(window, i * sizeof(LONG_PTR), (LONG_PTR)devNotify);
	return true;
}

static bool windows_create_event_filter(HWND window)
{
	// NOTE adjust space in windows_event_window_setup if new filter are added
	// Setup filter for the events we want to get notified about

	if (!windows_setup_event_filter(window, GUID_DEVINTERFACE_USB_HOST_CONTROLLER, 0)) {
		return false;
	}
	if (!windows_setup_event_filter(window, GUID_DEVINTERFACE_USB_HUB, 1)) {
		return false;
	}
	if (!windows_setup_event_filter(window, GUID_DEVINTERFACE_USB_DEVICE, 2)) {
		return false;
	}
	if (!windows_setup_event_filter(window, GUID_DEVINTERFACE_LIBUSB0_FILTER, 3)) {
		return false;
	}
	return true;
}

static LRESULT
windows_event_message_handler(HWND hWnd, UINT uMsg, WPARAM wParam,
															LPARAM lParam)
{
	PDEV_BROADCAST_DEVICEINTERFACE lpdbv;

	switch (uMsg) {
	case WM_NCCREATE:
		// NOTE before window creation
		return true;
	case WM_CREATE:
		// NOTE the actual creation of the window
		if (!windows_create_event_filter(hWnd)) {
			return -1;
		}
		break;
	case WM_DEVICECHANGE: {
		lpdbv = (PDEV_BROADCAST_DEVICEINTERFACE)lParam;

		if (lpdbv->dbcc_devicetype == DBT_DEVTYP_DEVICEINTERFACE) {
			usbi_mutex_lock(&event_lock);
			switch (wParam) {
			case DBT_DEVICEARRIVAL: {
				usbi_dbg("Device arrived %s", lpdbv->dbcc_name);
				windows_hotplug_enumerate(lpdbv->dbcc_name);
				break;
			}
			case DBT_DEVICEREMOVECOMPLETE: {
				usbi_dbg("Device removed %s", lpdbv->dbcc_name);
				windows_device_disconnected(lpdbv->dbcc_name);
				break;
			}
			default:
				break;
			}
			usbi_mutex_unlock(&event_lock);
		}
		return true;
	}
	default:
		// NOTE don't care ...
		break;
	}
	return 0L;
}

// Window class name for the non-visible window for windows events
#define LIBUSB_EVENT_CLASS "LIBUSB_EVENT_CLASS"

static int windows_event_window_setup(void)
{
	WNDCLASSEX wx;
	ZeroMemory(&wx, sizeof(wx));

	wx.cbSize = sizeof(WNDCLASSEX);
	wx.lpfnWndProc = (WNDPROC)windows_event_message_handler;
	wx.hInstance = (HINSTANCE)GetModuleHandle(NULL);
	wx.style = CS_HREDRAW | CS_VREDRAW;
	wx.hInstance = GetModuleHandle(NULL);
	wx.hbrBackground = (HBRUSH)(COLOR_WINDOW);
	wx.lpszClassName = _T(LIBUSB_EVENT_CLASS);
	wx.cbWndExtra = 4 * sizeof(LONG_PTR); // NOTE adjust if new filter are added

	if (!RegisterClassEx(&wx)) {
		usbi_err(NULL, "Failed to register event window class");
		return LIBUSB_ERROR_NO_MEM;
	}
	if (NULL == (event_window =
								 CreateWindow(_T(LIBUSB_EVENT_CLASS), _T("DeviceNotificationWindow"),
															WS_ICONIC, 0, 0, CW_USEDEFAULT, 0, HWND_MESSAGE,
															NULL, GetModuleHandle(NULL), NULL))) {
		usbi_err(NULL, "Failed to create event window");
		return LIBUSB_ERROR_NO_MEM;
	}
	SetWindowLongPtr(event_window, 0 * sizeof(LONG_PTR), (LONG_PTR)NULL);
	SetWindowLongPtr(event_window, 1 * sizeof(LONG_PTR), (LONG_PTR)NULL);
	SetWindowLongPtr(event_window, 2 * sizeof(LONG_PTR), (LONG_PTR)NULL);
	SetWindowLongPtr(event_window, 3 * sizeof(LONG_PTR), (LONG_PTR)NULL);

	return LIBUSB_SUCCESS;
}

static void windows_destroy_event_window(void)
{
	UnregisterDeviceNotification((HDEVNOTIFY)GetWindowLongPtr(event_window, sizeof(LONG_PTR)));
	DestroyWindow(event_window);
	event_window = NULL;
	UnregisterClass(_T(LIBUSB_EVENT_CLASS), (HINSTANCE)GetModuleHandle(NULL));
}

static unsigned __stdcall windows_event_thread_main(void *param)
{
	int r;
	int msg_ret = 0;
	MSG msg;

	if (LIBUSB_SUCCESS != (r = windows_event_window_setup())) {
		return r;
	}

	// Signal windows_start_event_monitor() that we're ready to service requests
	if (!SetEvent((HANDLE)param))
		usbi_dbg("SetEvent failed for timer init event: %s", windows_error_str(0));

	while ((msg_ret = pGetMessageA(&msg, event_window, 0, 0)) != 0) {
		if (msg_ret == -1) {
			r = LIBUSB_ERROR_OTHER;
			goto cleanup;
		} else {
			switch (msg.message) {
			case WM_TIMER_REQUEST:
				TranslateMessage(&msg);
				DispatchMessage(&msg);
				break;
			case WM_TIMER_EXIT:
				goto cleanup;
			}
		}
	}

cleanup:
	UnregisterDeviceNotification((HDEVNOTIFY *)GetWindowLongPtr(event_window, sizeof(LONG_PTR)));
	windows_destroy_event_window();
	return r;
}

static int windows_start_event_monitor(void)
{
	HANDLE event;

	event = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (event == NULL) {
		usbi_err(NULL, "could not create event: %s", windows_error_str(0));
		return LIBUSB_ERROR_NO_MEM;
	}

	event_thread =
		(HANDLE)_beginthreadex(NULL, 0, windows_event_thread_main, (void *)event, 0,
													 (unsigned int *)&event_thread_id);
	if (event_thread == NULL) {
		usbi_err(NULL, "unable to create event thread - aborting");
		return LIBUSB_ERROR_NO_MEM;
	}
	// Wait for timer thread to init before continuing.
	if (WaitForSingleObject(event, INFINITE) != WAIT_OBJECT_0) {
		usbi_err(NULL, "failed to wait for event thread to become ready - aborting");
		CloseHandle(event);
		return LIBUSB_ERROR_OTHER;
	}
	CloseHandle(event);
	return LIBUSB_SUCCESS;
}

static void windows_destroy_event_monitor(void)
{
	if (event_thread) {
		// actually the signal to quit the thread.
		if (!PostMessageA(event_window, WM_TIMER_EXIT, 0, 0) ||
				(WaitForSingleObject(event_thread, INFINITE) != WAIT_OBJECT_0)) {
			usbi_dbg("could not wait for timer thread to quit");
			TerminateThread(event_thread, 1);
			// shouldn't happen, but we're destroying
			// all objects it might have held anyway.
		}
		CloseHandle(event_thread);
		event_thread = NULL;
		event_thread_id = 0;
	}
}

static int windows_scan_devices(struct libusb_context *ctx)
{
	int found;
	ssize_t i, len;
	struct libusb_device *dev = NULL;

	struct discovered_devs *disc_devs = usbi_discovered_devs_alloc();
	if (NULL == disc_devs) {
		return LIBUSB_ERROR_NO_MEM;
	}

	usbi_mutex_lock(&event_lock);
	usbi_mutex_lock(&ctx->usb_devs_lock);
	if (LIBUSB_SUCCESS == _context_priv(ctx)->backend->get_device_list(ctx, &disc_devs)) {
		len = disc_devs->len;
		for (i = 0; i < len; i++) {
			found = 0;
			list_for_each_entry (dev, &ctx->usb_devs, list, struct libusb_device)
				if (dev->session_data == disc_devs->devices[i]->session_data) {
					found = 1;
					break;
				}
			if(!found) {
				dev = disc_devs->devices[i];
				libusb_ref_device(dev);
				usbi_connect_device(dev);
			}
		}
	}
	usbi_mutex_unlock(&ctx->usb_devs_lock);
	usbi_mutex_unlock(&event_lock);
	usbi_discovered_devs_free(disc_devs);

	return LIBUSB_SUCCESS;
}

static int windows_init(struct libusb_context *ctx)
{
	struct windows_context_priv *priv = _context_priv(ctx);
	HANDLE semaphore;
	char sem_name[11 + 8 + 1]; // strlen("libusb_init") + (32-bit hex PID) + '\0'
	int r = LIBUSB_ERROR_OTHER;
	bool winusb_backend_init = false;
	bool usbdk_backend_init = false;

	sprintf(sem_name, "libusb_init%08X", (unsigned int)(GetCurrentProcessId() & 0xFFFFFFFF));
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
	if (++init_count == 1) { // First init?
		// Load DLL imports
		if (!windows_init_dlls()) {
			usbi_err(ctx, "could not resolve DLL functions");
			goto init_exit;
		}

		get_windows_version();

		if (windows_version == WINDOWS_UNDEFINED) {
			usbi_err(ctx, "failed to detect Windows version");
			r = LIBUSB_ERROR_NOT_SUPPORTED;
			goto init_exit;
		}

		if (!windows_init_clock(ctx))
			goto init_exit;

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
			usbdk_backend_init = true;
		} else {
			usbi_info(ctx, "UsbDk backend is not available");
			// Do not report this as an error
			r = LIBUSB_SUCCESS;
		}

		r = usbi_mutex_init(&event_lock);
		if (LIBUSB_SUCCESS != r) {
			goto init_exit;
		}

		r = windows_start_event_monitor();
		if (LIBUSB_SUCCESS != r) {
			goto init_exit;
		}
	} else if (!event_thread) {
		r = LIBUSB_ERROR_OTHER;
		goto init_exit;
	}

	// By default, new contexts will use the WinUSB backend
	priv->backend = &winusb_backend;

	r = windows_scan_devices(ctx);
	if (LIBUSB_SUCCESS != r) {
		goto init_exit;
	}

init_exit: // Holds semaphore here
	if ((init_count == 1) && (r != LIBUSB_SUCCESS)) { // First init failed?
		if (winusb_backend_init)
			winusb_backend.exit(ctx);
		if (usbdk_backend_init)
			usbdk_backend.exit(ctx);
		htab_destroy();
		windows_destroy_clock();
		windows_exit_dlls();
		usbi_mutex_destroy(&event_lock);
		--init_count;
	}

	ReleaseSemaphore(semaphore, 1, NULL); // increase count back to 1
	CloseHandle(semaphore);
	return r;
}

static void windows_exit(struct libusb_context *ctx)
{
	HANDLE semaphore;
	char sem_name[11 + 8 + 1]; // strlen("libusb_init") + (32-bit hex PID) + '\0'
	UNUSED(ctx);

	sprintf(sem_name, "libusb_init%08X", (unsigned int)(GetCurrentProcessId() & 0xFFFFFFFF));
	semaphore = CreateSemaphoreA(NULL, 1, 1, sem_name);
	if (semaphore == NULL)
		return;

	// A successful wait brings our semaphore count to 0 (unsignaled)
	// => any concurent wait stalls until the semaphore release
	if (WaitForSingleObject(semaphore, INFINITE) != WAIT_OBJECT_0) {
		CloseHandle(semaphore);
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
		windows_destroy_event_monitor();
		usbi_mutex_destroy(&event_lock);
		windows_destroy_clock();
		windows_exit_dlls();
	}

	ReleaseSemaphore(semaphore, 1, NULL); // increase count back to 1
	CloseHandle(semaphore);
}

static int windows_set_option(struct libusb_context *ctx,
															enum libusb_option option, va_list ap)
{
	struct windows_context_priv *priv = _context_priv(ctx);
	struct libusb_device *dev = NULL;
	struct libusb_device *n = NULL;
	unsigned nums = 0;
	int r = LIBUSB_SUCCESS;

	UNUSED(ap);

	switch (option) {
	case LIBUSB_OPTION_USE_USBDK:
		if (usbdk_available) {
			usbi_mutex_lock(&ctx->events_lock);
			usbi_mutex_lock(&ctx->usb_devs_lock);

			usbi_mutex_lock(&ctx->open_devs_lock);
			list_for_each_entry (dev, &ctx->open_devs, list, struct libusb_device) {
				++nums;
			}
			usbi_mutex_unlock(&ctx->open_devs_lock);
			
			if (0 != nums) {
				usbi_err(ctx, "Tried to switch the backend while using devices!");
				r = LIBUSB_ERROR_OTHER;
				goto backend_exit;
			}
			list_for_each_entry (dev, &ctx->hotplug_msgs, list,
													 struct libusb_device) {
				++nums;
			}
			if (0 != nums) {
				usbi_err(ctx, "Tried to switch the backend while there are events for it!");
				r = LIBUSB_ERROR_OTHER;
				goto backend_exit;
			}
			usbi_dbg("switching context %p to use UsbDk backend", ctx);

			// FIXME This is horrible, but these events may not be sent to the user
			ctx->hotplug_msgs.next = NULL;
			ctx->hotplug_msgs.prev = NULL;

			list_for_each_entry_safe (dev, n, &ctx->usb_devs, list,
																struct libusb_device) {
				libusb_ref_device(dev);
				usbi_disconnect_device(dev);
				libusb_unref_device(dev);
			}
			priv->backend = &usbdk_backend;
			windows_scan_devices(ctx);

			list_init(&ctx->hotplug_msgs);

		backend_exit:
			usbi_mutex_unlock(&ctx->usb_devs_lock);
			usbi_mutex_unlock(&ctx->events_lock);
			return r;
		} else {
			usbi_err(ctx, "UsbDk backend not available");
			return LIBUSB_ERROR_NOT_FOUND;
		}
	default:
		return LIBUSB_ERROR_NOT_SUPPORTED;
	}
}

static void windows_hotplug_poll(void)
{
	Sleep(10); // Wait 10ms - this is by no means good but similar to darwin
	usbi_mutex_lock(&event_lock);
	usbi_mutex_unlock(&event_lock);
}

static int windows_open(struct libusb_device_handle *dev_handle)
{
	struct windows_context_priv *priv = _context_priv(HANDLE_CTX(dev_handle));
	return priv->backend->open(dev_handle);
}

static void windows_close(struct libusb_device_handle *dev_handle)
{
	struct windows_context_priv *priv = _context_priv(HANDLE_CTX(dev_handle));
	priv->backend->close(dev_handle);
}

static int windows_get_device_descriptor(struct libusb_device *dev,
	unsigned char *buffer, int *host_endian)
{
	struct windows_context_priv *priv = _context_priv(DEVICE_CTX(dev));
	*host_endian = 0;
	return priv->backend->get_device_descriptor(dev, buffer);
}

static int windows_get_active_config_descriptor(struct libusb_device *dev,
	unsigned char *buffer, size_t len, int *host_endian)
{
	struct windows_context_priv *priv = _context_priv(DEVICE_CTX(dev));
	*host_endian = 0;
	return priv->backend->get_active_config_descriptor(dev, buffer, len);
}

static int windows_get_config_descriptor(struct libusb_device *dev,
	uint8_t config_index, unsigned char *buffer, size_t len, int *host_endian)
{
	struct windows_context_priv *priv = _context_priv(DEVICE_CTX(dev));
	*host_endian = 0;
	return priv->backend->get_config_descriptor(dev, config_index, buffer, len);
}

static int windows_get_config_descriptor_by_value(struct libusb_device *dev,
	uint8_t bConfigurationValue, unsigned char **buffer, int *host_endian)
{
	struct windows_context_priv *priv = _context_priv(DEVICE_CTX(dev));
	*host_endian = 0;
	return priv->backend->get_config_descriptor_by_value(dev, bConfigurationValue, buffer);
}

static int windows_get_configuration(struct libusb_device_handle *dev_handle, int *config)
{
	struct windows_context_priv *priv = _context_priv(HANDLE_CTX(dev_handle));
	return priv->backend->get_configuration(dev_handle, config);
}

static int windows_set_configuration(struct libusb_device_handle *dev_handle, int config)
{
	struct windows_context_priv *priv = _context_priv(HANDLE_CTX(dev_handle));
	return priv->backend->set_configuration(dev_handle, config);
}

static int windows_claim_interface(struct libusb_device_handle *dev_handle, int interface_number)
{
	struct windows_context_priv *priv = _context_priv(HANDLE_CTX(dev_handle));
	return priv->backend->claim_interface(dev_handle, interface_number);
}

static int windows_release_interface(struct libusb_device_handle *dev_handle, int interface_number)
{
	struct windows_context_priv *priv = _context_priv(HANDLE_CTX(dev_handle));
	return priv->backend->release_interface(dev_handle, interface_number);
}

static int windows_set_interface_altsetting(struct libusb_device_handle *dev_handle,
	int interface_number, int altsetting)
{
	struct windows_context_priv *priv = _context_priv(HANDLE_CTX(dev_handle));
	return priv->backend->set_interface_altsetting(dev_handle, interface_number, altsetting);
}

static int windows_clear_halt(struct libusb_device_handle *dev_handle, unsigned char endpoint)
{
	struct windows_context_priv *priv = _context_priv(HANDLE_CTX(dev_handle));
	return priv->backend->clear_halt(dev_handle, endpoint);
}

static int windows_reset_device(struct libusb_device_handle *dev_handle)
{
	struct windows_context_priv *priv = _context_priv(HANDLE_CTX(dev_handle));
	return priv->backend->reset_device(dev_handle);
}

static void windows_destroy_device(struct libusb_device *dev)
{
	struct windows_context_priv *priv = _context_priv(DEVICE_CTX(dev));
	priv->backend->destroy_device(dev);
}

static int windows_submit_transfer(struct usbi_transfer *itransfer)
{
	struct windows_context_priv *priv = _context_priv(ITRANSFER_CTX(itransfer));
	return priv->backend->submit_transfer(itransfer);
}

static int windows_cancel_transfer(struct usbi_transfer *itransfer)
{
	struct windows_context_priv *priv = _context_priv(ITRANSFER_CTX(itransfer));
	return priv->backend->cancel_transfer(itransfer);
}

static void windows_clear_transfer_priv(struct usbi_transfer *itransfer)
{
	struct windows_context_priv *priv = _context_priv(ITRANSFER_CTX(itransfer));
	priv->backend->clear_transfer_priv(itransfer);
}

static int windows_handle_events(struct libusb_context *ctx, struct pollfd *fds, POLL_NFDS_TYPE nfds, int num_ready)
{
	struct windows_context_priv *priv = _context_priv(ctx);
	struct usbi_transfer *itransfer;
	DWORD io_size, io_result;
	POLL_NFDS_TYPE i;
	bool found;
	int transfer_fd;
	int r = LIBUSB_SUCCESS;

	usbi_mutex_lock(&ctx->open_devs_lock);
	for (i = 0; i < nfds && num_ready > 0; i++) {

		usbi_dbg("checking fd %d with revents = %04x", fds[i].fd, fds[i].revents);

		if (!fds[i].revents)
			continue;

		num_ready--;

		// Because a Windows OVERLAPPED is used for poll emulation,
		// a pollable fd is created and stored with each transfer
		found = false;
		transfer_fd = -1;
		usbi_mutex_lock(&ctx->flying_transfers_lock);
		list_for_each_entry(itransfer, &ctx->flying_transfers, list, struct usbi_transfer) {
			transfer_fd = priv->backend->get_transfer_fd(itransfer);
			if (transfer_fd == fds[i].fd) {
				found = true;
				break;
			}
		}
		usbi_mutex_unlock(&ctx->flying_transfers_lock);

		if (found) {
			priv->backend->get_overlapped_result(itransfer, &io_result, &io_size);

			usbi_remove_pollfd(ctx, transfer_fd);

			// let handle_callback free the event using the transfer wfd
			// If you don't use the transfer wfd, you run a risk of trying to free a
			// newly allocated wfd that took the place of the one from the transfer.
			windows_handle_callback(priv->backend, itransfer, io_result, io_size);
		} else {
			usbi_err(ctx, "could not find a matching transfer for fd %d", fds[i].fd);
			r = LIBUSB_ERROR_NOT_FOUND;
			break;
		}
	}
	usbi_mutex_unlock(&ctx->open_devs_lock);

	return r;
}

static int windows_clock_gettime(int clk_id, struct timespec *tp)
{
	struct timer_request request;
#if !defined(_MSC_VER) || (_MSC_VER < 1900)
	FILETIME filetime;
	ULARGE_INTEGER rtime;
#endif
	DWORD r;

	switch (clk_id) {
	case USBI_CLOCK_MONOTONIC:
		if (timer_thread) {
			request.tp = tp;
			request.event = CreateEvent(NULL, FALSE, FALSE, NULL);
			if (request.event == NULL)
				return LIBUSB_ERROR_NO_MEM;

			if (!pPostThreadMessageA(timer_thread_id, WM_TIMER_REQUEST, 0, (LPARAM)&request)) {
				usbi_err(NULL, "PostThreadMessage failed for timer thread: %s", windows_error_str(0));
				CloseHandle(request.event);
				return LIBUSB_ERROR_OTHER;
			}

			do {
				r = WaitForSingleObject(request.event, TIMER_REQUEST_RETRY_MS);
				if (r == WAIT_TIMEOUT)
					usbi_dbg("could not obtain a timer value within reasonable timeframe - too much load?");
				else if (r == WAIT_FAILED)
					usbi_err(NULL, "WaitForSingleObject failed: %s", windows_error_str(0));
			} while (r == WAIT_TIMEOUT);
			CloseHandle(request.event);

			if (r == WAIT_OBJECT_0)
				return LIBUSB_SUCCESS;
			else
				return LIBUSB_ERROR_OTHER;
		}
		// Fall through and return real-time if monotonic was not detected @ timer init
	case USBI_CLOCK_REALTIME:
#if defined(_MSC_VER) && (_MSC_VER >= 1900)
		timespec_get(tp, TIME_UTC);
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
		return LIBUSB_SUCCESS;
	default:
		return LIBUSB_ERROR_INVALID_PARAM;
	}
}

static int windows_get_device_driver(struct libusb_device *const device,
																		 char *driver, int size)
{
	struct windows_context_priv const *const priv = _context_priv(device->ctx);
	return priv->backend->get_device_driver(device, driver, size);
}

// NB: MSVC6 does not support named initializers.
const struct usbi_os_backend usbi_backend = {
	"Windows",
	USBI_CAP_HAS_HID_ACCESS,
	windows_init,
	windows_exit,
	windows_set_option,
	NULL,	/* get_device_list */
	windows_hotplug_poll,
	NULL,	/* wrap_sys_device */
	windows_open,
	windows_close,
	windows_get_device_driver,
	windows_get_device_descriptor,
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
	windows_clear_transfer_priv,
	windows_handle_events,
	NULL,	/* handle_transfer_completion */
	windows_clock_gettime,
	sizeof(struct windows_context_priv),
	sizeof(union windows_device_priv),
	sizeof(union windows_device_handle_priv),
	sizeof(union windows_transfer_priv),
};
