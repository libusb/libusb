/*
 * windows hotplug backend for libusb 1.0
 * Copyright © 2024 Sylvain Fasel <sylvain@sonatique.net>
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

#include "libusbi.h"
#include "threads_windows.h"

#include "windows_common.h"
#include "windows_hotplug.h"

#include <stdio.h>
#include <dbt.h>

/* The Windows Hotplug system is a two steps process.
 * 1. We create a hidden window and listen for DBT_DEVNODES_CHANGED, which Windows
 *    broadcasts to all top-level windows whenever the device tree changes (no
 *    registration required). Multiple rapid events (e.g. a hub with many children)
 *    are coalesced via a short debounce timer so we only scan once the burst settles.
 *    A maximum delay ceiling guarantees a scan fires within a bounded time even
 *    during sustained bursts, preventing unbounded latency.
 * 2. Upon timer expiry, we snapshot the current device list, run a full re-enumeration
 *    via the Windows backend, then diff the result: newly found devices that have been
 *    successfully initialized generate DEVICE_ARRIVED events; devices that were not
 *    encountered by the re-enumeration (physically removed) generate DEVICE_LEFT events.
 */

#define HOTPLUG_DEBOUNCE_TIMER_ID		1
#define HOTPLUG_DEBOUNCE_MS				10
#define HOTPLUG_DEBOUNCE_MAX_DELAY_MS	100

static ULONGLONG first_debounce_tick;
static HWND windows_event_hwnd;
static HANDLE windows_event_thread_handle;
static DWORD WINAPI windows_event_thread_main(LPVOID lpParam);
static LRESULT CALLBACK windows_proc_callback(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);

#define log_error(operation) do { \
	usbi_err(NULL, "%s failed with error: %s", operation, windows_error_str(0)); \
} while (0)

int windows_start_event_monitor(void)
{
	windows_event_thread_handle = CreateThread(
		NULL, // Default security descriptor
		0, // Default stack size
		windows_event_thread_main,
		NULL, // No parameters to pass to the thread
		0, // Start immediately
		NULL // No need to keep track of thread ID
	);

	if (windows_event_thread_handle == NULL)
	{
		log_error("CreateThread");
		return LIBUSB_ERROR_OTHER;
	}

	return LIBUSB_SUCCESS;
}

int windows_stop_event_monitor(void)
{
	if (windows_event_hwnd == NULL)
	{
		return LIBUSB_SUCCESS;
	}

	if (!SUCCEEDED(SendMessage(windows_event_hwnd, WM_CLOSE, 0, 0)))
	{
		log_error("SendMessage");
		return LIBUSB_ERROR_OTHER;
	}

	if (WaitForSingleObject(windows_event_thread_handle, INFINITE) != WAIT_OBJECT_0)
	{
		log_error("WaitForSingleObject");
		return LIBUSB_ERROR_OTHER;
	}

	if (!CloseHandle(windows_event_thread_handle))
	{
		log_error("CloseHandle");
		return LIBUSB_ERROR_OTHER;
	}

	return LIBUSB_SUCCESS;
}

static int windows_get_device_list(struct libusb_context *ctx)
{
	// note: context device list is protected by active_contexts_lock
	return ((struct windows_context_priv *)usbi_get_context_priv(ctx))->backend->get_device_list(ctx, NULL);
}

void windows_initial_scan_devices(struct libusb_context *ctx)
{
	usbi_mutex_static_lock(&active_contexts_lock);

	const int ret =  windows_get_device_list(ctx);
	if (ret != LIBUSB_SUCCESS)
	{
		usbi_err(ctx, "hotplug failed to retrieve initial list with error: %s", libusb_error_name(ret));
	}
	usbi_mutex_static_unlock(&active_contexts_lock);
}

static void windows_refresh_device_list(struct libusb_context *ctx)
{
	struct libusb_device *dev, *next_dev;

	// Step 1: clear seen_during_scan so the scan can mark which devices are still
	// physically present, and set seen_before_scan so we can distinguish newly
	// created devices (which start with seen_before_scan=false via calloc).
	for_each_device_safe(ctx, dev, next_dev)
	{
		struct winusb_device_priv *priv = (struct winusb_device_priv *)usbi_get_device_priv(dev);
		priv->seen_during_scan = false;
		priv->seen_before_scan = true;
	}

	// Step 2: re-enumerate — winusb_get_device_list attaches newly-arrived devices
	// and sets seen_during_scan=true for every device it physically encounters.
	// seen_before_scan is untouched and will be left in default state (false) for newly created devices, allowing us to identify them in the next step.
	const int ret = windows_get_device_list(ctx);
	if (ret != LIBUSB_SUCCESS)
	{
		usbi_err(ctx, "hotplug failed to retrieve current list with error: %s", libusb_error_name(ret));
		return;
	}

	// Step 3: diff old vs new.
	for_each_device_safe(ctx, dev, next_dev)
	{
		struct winusb_device_priv *priv = (struct winusb_device_priv *)usbi_get_device_priv(dev);

		if (!priv->seen_during_scan)
		{
			// Not encountered by the scan: device was physically removed.
			if (priv->initialized)
			{
				usbi_disconnect_device(dev); // fires DEVICE_LEFT
			}
			else
			{
				usbi_detach_device(dev);
			}
		}
		else if (!priv->seen_before_scan)
		{
			if (priv->initialized)
			{
				usbi_hotplug_notification(ctx, dev, LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED);
			}
		}
	}
}

static void windows_refresh_device_list_for_all_ctx(void)
{
	usbi_mutex_static_lock(&active_contexts_lock);

	struct libusb_context *ctx;
	for_each_context(ctx)
	{
		windows_refresh_device_list(ctx);
	}

	usbi_mutex_static_unlock(&active_contexts_lock);
}

#define WND_CLASS_NAME TEXT("libusb-1.0-windows-hotplug")

static bool init_wnd_class(void)
{
	WNDCLASS wndClass = { 0 };
	wndClass.lpfnWndProc = windows_proc_callback;
	wndClass.hInstance = GetModuleHandle(NULL);
	wndClass.lpszClassName = WND_CLASS_NAME;

	if (!RegisterClass(&wndClass))
	{
		log_error("event thread: RegisterClass");
		return false;
	}

	return true;
}

static DWORD WINAPI windows_event_thread_main(LPVOID lpParam)
{
	UNUSED(lpParam);

	usbi_dbg(NULL, "windows event thread entering");

	if (!init_wnd_class())
	{
		return (DWORD)-1;
	}

	windows_event_hwnd = CreateWindow(
		WND_CLASS_NAME,
		TEXT(""),
		0,
		0, 0, 0, 0,
		NULL, NULL,
		GetModuleHandle(NULL),
		NULL);

	if (windows_event_hwnd == NULL)
	{
		log_error("event thread: CreateWindow");
		return (DWORD)-1;
	}

	MSG msg;
	BOOL ret_val;

	while ((ret_val = GetMessage(&msg, windows_event_hwnd, 0, 0)) != 0)
	{
		if (ret_val == -1)
		{
			log_error("event thread: GetMessage");
			break;
		}

		if (!SUCCEEDED(TranslateMessage(&msg)))
		{
			log_error("event thread: TranslateMessage");
		}

		if (!SUCCEEDED(DispatchMessage(&msg)))
		{
			log_error("event thread: DispatchMessage");
		}
	}

	usbi_dbg(NULL, "windows event thread exiting");

	return 0;
}

static LRESULT CALLBACK windows_proc_callback(
	HWND hwnd,
	UINT message,
	WPARAM wParam,
	LPARAM lParam)
{
	switch (message)
	{
	case WM_DEVICECHANGE:
		if (wParam == DBT_DEVNODES_CHANGED)
		{
			if (first_debounce_tick == 0)
			{
				// First event in a new burst — record the time and start the debounce timer.
				first_debounce_tick = GetTickCount64();
				SetTimer(hwnd, HOTPLUG_DEBOUNCE_TIMER_ID, HOTPLUG_DEBOUNCE_MS, NULL);
			}
			else if (GetTickCount64() - first_debounce_tick >= HOTPLUG_DEBOUNCE_MAX_DELAY_MS)
			{
				// Maximum delay reached — force an immediate scan so devices
				// are not invisible for the entire duration of a sustained burst.
				KillTimer(hwnd, HOTPLUG_DEBOUNCE_TIMER_ID);
				first_debounce_tick = 0;
				windows_refresh_device_list_for_all_ctx();
			}
			else
			{
				// Still within the max-delay window — reset the debounce timer.
				SetTimer(hwnd, HOTPLUG_DEBOUNCE_TIMER_ID, HOTPLUG_DEBOUNCE_MS, NULL);
			}
			return TRUE;
		}
		return DefWindowProc(hwnd, message, wParam, lParam);

	case WM_TIMER:
		if (wParam == HOTPLUG_DEBOUNCE_TIMER_ID)
		{
			KillTimer(hwnd, HOTPLUG_DEBOUNCE_TIMER_ID);
			first_debounce_tick = 0;
			windows_refresh_device_list_for_all_ctx();
			return 0;
		}
		return DefWindowProc(hwnd, message, wParam, lParam);

	case WM_CLOSE:
		KillTimer(hwnd, HOTPLUG_DEBOUNCE_TIMER_ID);
		first_debounce_tick = 0;
		if (!DestroyWindow(hwnd))
		{
			log_error("DestroyWindow");
		}
		return 0;

	case WM_DESTROY:
		PostQuitMessage(0);
		return 0;

	default:
		return DefWindowProc(hwnd, message, wParam, lParam);
	}
}
