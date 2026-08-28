/* -*- Mode: C; indent-tabs-mode:t ; c-basic-offset:4 -*- */
/*
 * windows hotplug backend for libusb 1.0
 * Copyright © 2024 Sylvain Fasel <sylvain@sonatique.net>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
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
 * 1. A hidden window listens for DBT_DEVNODES_CHANGED, which Windows
 *    broadcasts to all top-level windows whenever the device tree changes.
 *    Rapid bursts are coalesced by a short debounce timer, with a maximum
 *    delay ceiling bounding the latency during sustained bursts.
 * 2. Each expiry runs a full re-enumeration via the Windows backend, then
 *    diffs the result: devices no longer present generate DEVICE_LEFT,
 *    newly present devices generate DEVICE_ARRIVED - but only once a scan
 *    has proven them usable, or proven that they never will be, because
 *    Windows makes devices visible before their driver stack is up (see
 *    windows_resolve_pending_announcements). A retry timer re-examines
 *    still-pending devices, and a device withheld for more than
 *    HOTPLUG_SETTLE_MAX_WAIT_MS is announced as-is, so nothing stays
 *    unannounced forever.
 *
 * All of this bookkeeping lives in struct winusb_device_priv, so it only runs
 * for contexts served by the WinUSB backend: a context that selected UsbDk
 * stores a different structure in the same memory (see #1920, item 4).
 */

#define HOTPLUG_DEBOUNCE_TIMER_ID       1
#define HOTPLUG_DEBOUNCE_MS             10
#define HOTPLUG_DEBOUNCE_MAX_DELAY_MS   100

#define HOTPLUG_SETTLE_TIMER_ID         2
#define HOTPLUG_SETTLE_RETRY_MS         500
#define HOTPLUG_SETTLE_MAX_WAIT_MS      5000

// libusb_init must not return while a device is still withheld: the
// application enumerates the device list right after, and a device announced
// later would be reported twice. Devices present at startup are settled long
// ago, so this only bounds the rare case of one arriving at the same moment.
#define HOTPLUG_INITIAL_SETTLE_MAX_MS   500
#define HOTPLUG_INITIAL_SETTLE_POLL_MS  100

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
	// Signaled by the event thread once its notification window exists, so
	// that a failure to bring up the monitor is reported to the caller.
	// Owned by this function; the thread only receives it to signal it,
	// and must not use it after this function returns.
	HANDLE window_ready = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (window_ready == NULL)
	{
		log_error("CreateEvent");
		return LIBUSB_ERROR_OTHER;
	}

	DWORD thread_id;

	windows_event_thread_handle = CreateThread(
		NULL, // Default security descriptor
		0, // Default stack size
		windows_event_thread_main,
		window_ready, // The event the thread signals once its window exists
		0, // Start immediately
		&thread_id // Used to reap the thread if waiting for readiness fails
	);

	if (windows_event_thread_handle == NULL)
	{
		log_error("CreateThread");
		CloseHandle(window_ready);
		return LIBUSB_ERROR_OTHER;
	}

	// Wait until the notification window exists or the thread failed and exited
	HANDLE handles[2] = { window_ready, windows_event_thread_handle };
	int r = LIBUSB_ERROR_OTHER;

	switch (WaitForMultipleObjects(2, handles, FALSE, INFINITE))
	{
	case WAIT_OBJECT_0:
		r = LIBUSB_SUCCESS;
		break;
	case WAIT_OBJECT_0 + 1:
		usbi_err(NULL, "event thread exited before its notification window was created");
		break;
	default:
		log_error("WaitForMultipleObjects");
		// Should not happen with two valid handles, but do not abandon a
		// live thread: a queued WM_QUIT ends its message loop even if it
		// is posted before the loop starts. PostThreadMessage fails until
		// the thread has a message queue, so retry while it is running.
		while (!PostThreadMessage(thread_id, WM_QUIT, 0, 0))
		{
			if (WaitForSingleObject(windows_event_thread_handle, 10) != WAIT_TIMEOUT)
			{
				break; // The thread exited on its own
			}
		}
		WaitForSingleObject(windows_event_thread_handle, INFINITE);
		break;
	}

	if (r != LIBUSB_SUCCESS)
	{
		CloseHandle(windows_event_thread_handle);
		windows_event_thread_handle = NULL;
		windows_event_hwnd = NULL; // May have been set before the thread was reaped
	}

	CloseHandle(window_ready);

	return r;
}

int windows_stop_event_monitor(void)
{
	if (windows_event_thread_handle == NULL)
	{
		// The event monitor is not running, there is nothing to stop
		return LIBUSB_SUCCESS;
	}

	// The WM_CLOSE handler destroys the notification window, which in turn
	// posts WM_QUIT and thereby ends the event thread's message loop.
	SendMessage(windows_event_hwnd, WM_CLOSE, 0, 0);

	int r = LIBUSB_SUCCESS;
	if (WaitForSingleObject(windows_event_thread_handle, INFINITE) != WAIT_OBJECT_0)
	{
		log_error("WaitForSingleObject");
		r = LIBUSB_ERROR_OTHER;
	}

	if (!CloseHandle(windows_event_thread_handle))
	{
		log_error("CloseHandle");
		r = LIBUSB_ERROR_OTHER;
	}

	windows_event_thread_handle = NULL;
	windows_event_hwnd = NULL;

	return r;
}

static int windows_get_device_list(struct libusb_context *ctx)
{
	// note: context device list is protected by active_contexts_lock
	return ((struct windows_context_priv *)usbi_get_context_priv(ctx))->backend->get_device_list(ctx, NULL);
}

// Whether this context is served by the WinUSB backend, i.e. whether its
// devices carry the struct winusb_device_priv this file reads and writes.
// A UsbDk context stores struct usbdk_device_priv in the same memory, where
// these fields would land in the middle of a device ID.
static bool ctx_uses_winusb(struct libusb_context *ctx)
{
	return ((struct windows_context_priv *)usbi_get_context_priv(ctx))->backend == &winusb_backend;
}

// Resolve withheld announcements once a scan has run all of its passes.
//
// A withheld device stays attached, so libusb_get_device_list still lists it:
// that is what lets its child devnodes resolve to it while the driver stack
// comes up. libusb_init therefore completes this decision before returning
// (see windows_initial_scan_devices), so that the enumeration performed by
// LIBUSB_HOTPLUG_ENUMERATE never races it.
static void windows_resolve_pending_announcements(struct libusb_context *ctx)
{
	struct libusb_device *dev;

	for_each_device(ctx, dev)
	{
		struct winusb_device_priv *priv = (struct winusb_device_priv *)usbi_get_device_priv(dev);

		if (!priv->initialized || !priv->announce_pending)
		{
			continue;
		}

		if (windows_hotplug_device_usable(dev))
		{
			priv->announce_pending = false;
		}
		else if (priv->settled_observed)
		{
			// Was already settled before this scan and still yields nothing
			// usable: nothing is coming, announce the device as-is
			usbi_dbg(ctx, "device '%s' settled without becoming usable, announcing it as-is", priv->dev_id);
			priv->announce_pending = false;
		}
		else if (GetTickCount64() - priv->pending_since >= HOTPLUG_SETTLE_MAX_WAIT_MS)
		{
			// Counted per device: a device that just started waiting must not
			// inherit the deadline of one that has been waiting for seconds.
			usbi_warn(ctx, "device '%s' did not become usable within %d ms, announcing it as-is",
				priv->dev_id, HOTPLUG_SETTLE_MAX_WAIT_MS);
			priv->announce_pending = false;
		}
		else
		{
			if (windows_hotplug_device_settled(dev))
			{
				// Settled per live PnP state, which the scan's device
				// interface snapshot may predate: let one more scan, whose
				// snapshot postdates this observation, decide usability
				priv->settled_observed = true;
			}
			usbi_dbg(ctx, "deferring arrival of device '%s' until its driver stack has settled", priv->dev_id);
		}
	}
}

static bool ctx_has_pending_announcement(struct libusb_context *ctx)
{
	struct libusb_device *dev;

	for_each_device(ctx, dev)
	{
		const struct winusb_device_priv *priv = (const struct winusb_device_priv *)usbi_get_device_priv(dev);

		if (priv->initialized && priv->announce_pending)
		{
			return true;
		}
	}

	return false;
}

void windows_initial_scan_devices(struct libusb_context *ctx)
{
	struct libusb_device *dev;

	usbi_mutex_static_lock(&active_contexts_lock);

	int ret = windows_get_device_list(ctx);
	if (ret != LIBUSB_SUCCESS)
	{
		usbi_err(ctx, "hotplug failed to retrieve initial list with error: %s", libusb_error_name(ret));
	}

	if (ctx_uses_winusb(ctx))
	{
		// These devices reach the application through LIBUSB_HOTPLUG_ENUMERATE,
		// which simply lists what is attached. The announcement decision must
		// therefore be complete before returning: a device left pending would
		// be enumerated while still unusable, then announced a second time by
		// the scan that releases it.
		const ULONGLONG deadline = GetTickCount64() + HOTPLUG_INITIAL_SETTLE_MAX_MS;

		for (;;)
		{
			// Devices present at startup settled long ago, so the second pass
			// releases them at once, acting on what the first observed.
			windows_resolve_pending_announcements(ctx);
			windows_resolve_pending_announcements(ctx);

			if (!ctx_has_pending_announcement(ctx))
			{
				break;
			}

			if (GetTickCount64() >= deadline)
			{
				usbi_dbg(ctx, "some devices were still coming up after %d ms, listing them as they are",
					HOTPLUG_INITIAL_SETTLE_MAX_MS);
				break;
			}

			// Give the driver stack time to progress, then look again: the
			// interface paths of a device being brought up appear in a later
			// scan, not in the snapshot this one has already taken. This is
			// the only place that waits while holding active_contexts_lock,
			// and only for a device that is arriving as libusb starts.
			Sleep(HOTPLUG_INITIAL_SETTLE_POLL_MS);

			ret = windows_get_device_list(ctx);
			if (ret != LIBUSB_SUCCESS)
			{
				usbi_err(ctx, "hotplug failed to refresh the initial list with error: %s", libusb_error_name(ret));
				break;
			}
		}

		for_each_device(ctx, dev)
		{
			struct winusb_device_priv *priv = (struct winusb_device_priv *)usbi_get_device_priv(dev);

			if (priv->initialized)
			{
				// Part of the list the application enumerates, whether or not
				// it settled in time: no DEVICE_ARRIVED for it later.
				priv->announce_pending = false;
				priv->announced = true;
			}
		}
	}

	usbi_mutex_static_unlock(&active_contexts_lock);
}

static void windows_refresh_device_list(struct libusb_context *ctx)
{
	struct libusb_device *dev, *next_dev;

	if (!ctx_uses_winusb(ctx))
	{
		// Every field used below belongs to struct winusb_device_priv, and a
		// UsbDk context stores something else there: reading them would
		// interpret a device ID as flags and pointers, and writing them would
		// corrupt that ID. Keep the device list current (the UsbDk backend
		// announces its own arrivals through usbi_connect_device) and leave
		// hotplug support for that backend to #1920, item 4.
		const int usbdk_ret = windows_get_device_list(ctx);
		if (usbdk_ret != LIBUSB_SUCCESS)
		{
			usbi_err(ctx, "hotplug failed to retrieve current list with error: %s", libusb_error_name(usbdk_ret));
		}
		return;
	}

	// Step 1: clear seen_during_scan so the scan can mark which devices are
	// still physically present.
	for_each_device_safe(ctx, dev, next_dev)
	{
		struct winusb_device_priv *priv = (struct winusb_device_priv *)usbi_get_device_priv(dev);
		priv->seen_during_scan = false;
	}

	// Step 2: re-enumerate — winusb_get_device_list attaches newly-arrived
	// devices (announce-pending) and sets seen_during_scan=true for every
	// device it physically encounters.
	const int ret = windows_get_device_list(ctx);
	if (ret != LIBUSB_SUCCESS)
	{
		usbi_err(ctx, "hotplug failed to retrieve current list with error: %s", libusb_error_name(ret));
		return;
	}

	// Step 2.5: decide which withheld announcements can be released
	windows_resolve_pending_announcements(ctx);

	// Step 3: diff old vs new.
	for_each_device_safe(ctx, dev, next_dev)
	{
		struct winusb_device_priv *priv = (struct winusb_device_priv *)usbi_get_device_priv(dev);

		if (!priv->seen_during_scan)
		{
			// Not encountered by the scan: device was physically removed.
			if (priv->announced)
			{
				usbi_disconnect_device(dev); // fires DEVICE_LEFT
			}
			else
			{
				// Never announced: no DEVICE_LEFT message will drop the
				// initial ref, drop it here to avoid a leak
				usbi_detach_device(dev);
				libusb_unref_device(dev);
			}
		}
		else if (priv->initialized && !priv->announce_pending && !priv->announced)
		{
			priv->announced = true;
			usbi_hotplug_notification(ctx, dev, LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED);
		}
	}
}

// Returns true when at least one device is still waiting to be announced.
static bool windows_refresh_device_list_for_all_ctx(void)
{
	bool pending = false;

	usbi_mutex_static_lock(&active_contexts_lock);

	struct libusb_context *ctx;
	for_each_context(ctx)
	{
		windows_refresh_device_list(ctx);

		if (ctx_uses_winusb(ctx) && ctx_has_pending_announcement(ctx))
		{
			pending = true;
		}
	}

	usbi_mutex_static_unlock(&active_contexts_lock);

	return pending;
}

// Run a scan and keep the retry timer in step with it. Event thread only.
static void windows_scan_for_hotplug_events(HWND hwnd)
{
	// Whether to retry is decided by the device list itself, not by what this
	// scan did: a scan that failed leaves its devices pending and therefore
	// keeps the timer armed, instead of silently dropping the retry.
	if (windows_refresh_device_list_for_all_ctx())
	{
		SetTimer(hwnd, HOTPLUG_SETTLE_TIMER_ID, HOTPLUG_SETTLE_RETRY_MS, NULL);
	}
	else
	{
		KillTimer(hwnd, HOTPLUG_SETTLE_TIMER_ID);
	}
}

#define WND_CLASS_NAME TEXT("libusb-1.0-windows-hotplug")

// Window classes are keyed by the (name, hInstance) pair. Use this libusb
// copy's own module handle rather than the executable's, so that independent
// copies of libusb within one process (e.g. one linked statically into the
// application and one bundled as a DLL by a plugin) each register their own
// class instead of colliding on ERROR_CLASS_ALREADY_EXISTS.
static HINSTANCE get_hotplug_instance(void)
{
	// Cached so that RegisterClass, CreateWindow and UnregisterClass are
	// guaranteed to use the same handle. No synchronization needed: all
	// callers run on the event thread, and successive event threads are
	// serialized by the join in windows_stop_event_monitor.
	static HINSTANCE hotplug_instance;

	if (hotplug_instance == NULL)
	{
		// Resolve the module containing this libusb copy from the address of
		// one of its statics (works for both the DLL and static-linked cases).
		if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
			GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			(LPCTSTR)&windows_event_hwnd, &hotplug_instance))
		{
			log_error("GetModuleHandleEx");
		}
	}

	return hotplug_instance;
}

static bool init_wnd_class(void)
{
	WNDCLASS wndClass = { 0 };
	wndClass.lpfnWndProc = windows_proc_callback;
	wndClass.hInstance = get_hotplug_instance();
	wndClass.lpszClassName = WND_CLASS_NAME;

	if (!RegisterClass(&wndClass))
	{
		if (GetLastError() == ERROR_CLASS_ALREADY_EXISTS)
		{
			// A registration left behind by an abnormally terminated event
			// thread of this same libusb copy (the class is keyed to this
			// module, and orderly shutdowns unregister it). It is still
			// backed by this module's windows_proc_callback, so reuse it.
			usbi_warn(NULL, "hotplug window class was already registered");
			return true;
		}

		log_error("event thread: RegisterClass");
		return false;
	}

	return true;
}

static DWORD WINAPI windows_event_thread_main(LPVOID lpParam)
{
	HANDLE window_ready = (HANDLE)lpParam;

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
		get_hotplug_instance(),
		NULL);

	if (windows_event_hwnd == NULL)
	{
		log_error("event thread: CreateWindow");
		UnregisterClass(WND_CLASS_NAME, get_hotplug_instance());
		return (DWORD)-1;
	}

	// Unblock windows_start_event_monitor: the monitor is now operational.
	// The event handle is owned by windows_start_event_monitor and must not
	// be used after this point.
	SetEvent(window_ready);

	MSG msg;
	BOOL ret_val;

	// Note: no window handle filter here. The documentation only guarantees
	// that WM_QUIT is retrieved regardless of the message-range filter; with
	// a window handle filter, clean termination would instead depend on
	// GetMessage failing with -1 once the notification window (the filter)
	// has been destroyed. With a NULL filter the loop simply ends on WM_QUIT.
	while ((ret_val = GetMessage(&msg, NULL, 0, 0)) != 0)
	{
		if (ret_val == -1)
		{
			log_error("event thread: GetMessage");
			break;
		}

		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	// Window classes are process-global and survive both the destruction of
	// the window and the end of this thread. If the class were left behind,
	// restarting the event monitor (libusb_exit followed by libusb_init)
	// would fail RegisterClass with ERROR_CLASS_ALREADY_EXISTS and hotplug
	// events would never be delivered again. See issue #1862.
	if (!UnregisterClass(WND_CLASS_NAME, get_hotplug_instance()))
	{
		log_error("event thread: UnregisterClass");
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
				windows_scan_for_hotplug_events(hwnd);
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
			windows_scan_for_hotplug_events(hwnd);
			return 0;
		}
		if (wParam == HOTPLUG_SETTLE_TIMER_ID)
		{
			KillTimer(hwnd, HOTPLUG_SETTLE_TIMER_ID);
			windows_scan_for_hotplug_events(hwnd);
			return 0;
		}
		return DefWindowProc(hwnd, message, wParam, lParam);

	case WM_CLOSE:
		KillTimer(hwnd, HOTPLUG_DEBOUNCE_TIMER_ID);
		KillTimer(hwnd, HOTPLUG_SETTLE_TIMER_ID);
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
