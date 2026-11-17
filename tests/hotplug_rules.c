/* -*- Mode: C; indent-tabs-mode:t ; c-basic-offset:8 -*- */
/*
 * libusb test: the rules deciding when a withheld hotplug announcement is
 * released on Windows
 *
 * Copyright © 2026 Sylvain Fasel <sylvain@sonatique.net>
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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>

#include "libusb_testlib.h"

#if defined(LIBUSB_WINDOWS_HOTPLUG)

#include <string.h>
#include <windows.h>
#include <setupapi.h>

#include "libusbi.h"
/* The backend headers, in the order the backend includes them. This test
 * does not use the DLL entry points windows_winusb.h declares as statics. */
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#endif
#include "os/windows_winusb.h"
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
#include "os/windows_hotplug.h"

/* Windows makes a device visible before its driver stack is up, so libusb
 * withholds DEVICE_ARRIVED until a scan proves the device usable, or proves
 * that nothing usable is coming. Those rules live in windows_hotplug_decide()
 * so that they can be checked here: every case below is a state a real device
 * goes through, and none of them needs hardware, a driver installation, or
 * the five seconds the ceiling describes. */

static unsigned int failures;

static const char *action_name(enum windows_hotplug_action action)
{
	switch (action) {
	case WINDOWS_HOTPLUG_WITHHOLD:			return "withhold";
	case WINDOWS_HOTPLUG_ANNOUNCE_USABLE:		return "announce usable";
	case WINDOWS_HOTPLUG_ANNOUNCE_NOTHING_COMING:	return "announce, nothing coming";
	case WINDOWS_HOTPLUG_ANNOUNCE_TIMED_OUT:	return "announce, timed out";
	default:					return "unknown";
	}
}

static struct windows_hotplug_state state_of(enum windows_hotplug_usability usability,
	bool settled_before_scan, bool settled_now, DWORD waited_ms)
{
	struct windows_hotplug_state state;

	state.usability = usability;
	state.settled_before_scan = settled_before_scan;
	state.settled_now = settled_now;
	state.waited_ms = waited_ms;

	return state;
}

static void check(const char *what, const struct windows_hotplug_state *state,
	enum windows_hotplug_action expected_action, bool expected_observe)
{
	bool observe = !expected_observe;	/* the callee must write it */
	enum windows_hotplug_action action = windows_hotplug_decide(state, &observe);

	if (action != expected_action || observe != expected_observe) {
		libusb_testlib_logf("%s: got '%s' (observe %d), expected '%s' (observe %d)",
			what, action_name(action), (int)observe,
			action_name(expected_action), (int)expected_observe);
		failures++;
	}
}

/* A device the scan could open is announced, whatever its driver stack is
 * doing at this instant. */
static libusb_testlib_result test_usable_is_announced(void)
{
	struct windows_hotplug_state state;

	failures = 0;

	state = state_of(WINDOWS_HOTPLUG_DEVICE_USABLE, false, false, 0);
	check("usable, nothing else known", &state, WINDOWS_HOTPLUG_ANNOUNCE_USABLE, false);

	state = state_of(WINDOWS_HOTPLUG_DEVICE_USABLE, true, true, HOTPLUG_SETTLE_MAX_WAIT_MS * 2);
	check("usable, everything else set", &state, WINDOWS_HOTPLUG_ANNOUNCE_USABLE, false);

	return failures ? TEST_STATUS_FAILURE : TEST_STATUS_SUCCESS;
}

/* A hub, or a device with no matching libusb API, has no interface path to
 * wait for, so it must not be held back by the settle wait. */
static libusb_testlib_result test_never_usable_is_not_waited_for(void)
{
	struct windows_hotplug_state state;

	failures = 0;

	state = state_of(WINDOWS_HOTPLUG_DEVICE_NEVER_USABLE, false, false, 0);
	check("never usable, just withheld", &state, WINDOWS_HOTPLUG_ANNOUNCE_NOTHING_COMING, false);

	state = state_of(WINDOWS_HOTPLUG_DEVICE_NEVER_USABLE, false, true, 10);
	check("never usable, settled now", &state, WINDOWS_HOTPLUG_ANNOUNCE_NOTHING_COMING, false);

	return failures ? TEST_STATUS_FAILURE : TEST_STATUS_SUCCESS;
}

/* What the usability helper concludes from the state a scan left in the
 * backend private data, which libusb places right after struct libusb_device. */
static enum windows_hotplug_usability usability_of(uint8_t api, bool device_path, bool interface_path)
{
	static union {
		struct libusb_device dev;
		unsigned char bytes[PTR_ALIGN(sizeof(struct libusb_device)) + sizeof(struct winusb_device_priv)];
	} fake;
	static char path[] = "fake";
	struct winusb_device_priv *priv;

	memset(&fake, 0, sizeof(fake));
	priv = (struct winusb_device_priv *)usbi_get_device_priv(&fake.dev);
	priv->apib = &usb_api_backend[api];
	priv->path = device_path ? path : NULL;
	priv->usb_interface[0].path = interface_path ? path : NULL;

	return windows_hotplug_device_usability(&fake.dev);
}

/* The backend only learns a device's driver once a scan has found its device
 * interface, which Windows registers when that driver starts. Before that, as
 * on a first plug while Windows still installs the driver, the device must
 * count as not yet usable, never as one libusb has no API for. */
static libusb_testlib_result test_usability_needs_a_known_driver(void)
{
	static const struct {
		const char *what;
		uint8_t api;
		bool device_path, interface_path;
		enum windows_hotplug_usability expected;
	} cases[] = {
		{ "driver not started yet", USB_API_UNSUPPORTED, false, false, WINDOWS_HOTPLUG_DEVICE_NOT_YET },
		{ "driver libusb has no API for", USB_API_UNSUPPORTED, true, false, WINDOWS_HOTPLUG_DEVICE_NEVER_USABLE },
		{ "composite, functions coming up", USB_API_COMPOSITE, true, false, WINDOWS_HOTPLUG_DEVICE_NOT_YET },
		{ "composite, a function is up", USB_API_COMPOSITE, true, true, WINDOWS_HOTPLUG_DEVICE_USABLE },
		{ "WinUSB", USB_API_WINUSBX, true, false, WINDOWS_HOTPLUG_DEVICE_USABLE },
	};
	size_t i;

	failures = 0;

	for (i = 0; i < ARRAYSIZE(cases); i++) {
		enum windows_hotplug_usability got =
			usability_of(cases[i].api, cases[i].device_path, cases[i].interface_path);

		if (got != cases[i].expected) {
			libusb_testlib_logf("%s: got usability %d, expected %d",
				cases[i].what, (int)got, (int)cases[i].expected);
			failures++;
		}
	}

	return failures ? TEST_STATUS_FAILURE : TEST_STATUS_SUCCESS;
}

/* The ordering rule: a device seen settled by a live query cannot be declared
 * hopeless on the strength of that query, because the scan that just ran took
 * its interface snapshot before it. Only the next scan can conclude. */
static libusb_testlib_result test_settled_needs_a_newer_scan(void)
{
	struct windows_hotplug_state state;

	failures = 0;

	/* this scan could not have seen an interface registered while it ran */
	state = state_of(WINDOWS_HOTPLUG_DEVICE_NOT_YET, false, true, 20);
	check("settled now, first time", &state, WINDOWS_HOTPLUG_WITHHOLD, true);

	/* the next scan, started after that observation, still found nothing */
	state = state_of(WINDOWS_HOTPLUG_DEVICE_NOT_YET, true, true, 40);
	check("settled before this scan", &state, WINDOWS_HOTPLUG_ANNOUNCE_NOTHING_COMING, false);

	/* unless an interface did appear in the meantime */
	state = state_of(WINDOWS_HOTPLUG_DEVICE_USABLE, true, true, 40);
	check("interface appeared after all", &state, WINDOWS_HOTPLUG_ANNOUNCE_USABLE, false);

	return failures ? TEST_STATUS_FAILURE : TEST_STATUS_SUCCESS;
}

/* A device that is still coming up keeps its announcement withheld, and a
 * scan that brought no news, which is what a failed scan looks like, must not
 * change that. */
static libusb_testlib_result test_still_coming_up_stays_withheld(void)
{
	struct windows_hotplug_state state;
	unsigned int scan;

	failures = 0;

	for (scan = 0; scan < 5; scan++) {
		state = state_of(WINDOWS_HOTPLUG_DEVICE_NOT_YET, false, false, 100 * scan);
		check("still coming up", &state, WINDOWS_HOTPLUG_WITHHOLD, false);
	}

	return failures ? TEST_STATUS_FAILURE : TEST_STATUS_SUCCESS;
}

/* The give-up ceiling belongs to each device: one that has been waiting for
 * seconds must not drag with it a device that just started waiting. */
static libusb_testlib_result test_ceiling_is_per_device(void)
{
	struct windows_hotplug_state waiting_long, waiting_briefly;

	failures = 0;

	waiting_long = state_of(WINDOWS_HOTPLUG_DEVICE_NOT_YET, false, false, HOTPLUG_SETTLE_MAX_WAIT_MS);
	waiting_briefly = state_of(WINDOWS_HOTPLUG_DEVICE_NOT_YET, false, false, 100);

	check("device at the ceiling", &waiting_long, WINDOWS_HOTPLUG_ANNOUNCE_TIMED_OUT, false);
	check("device that just arrived", &waiting_briefly, WINDOWS_HOTPLUG_WITHHOLD, false);

	/* just below the ceiling is still a wait */
	waiting_long.waited_ms = HOTPLUG_SETTLE_MAX_WAIT_MS - 1;
	check("one millisecond short", &waiting_long, WINDOWS_HOTPLUG_WITHHOLD, false);

	return failures ? TEST_STATUS_FAILURE : TEST_STATUS_SUCCESS;
}

/* The wait is measured with a 32-bit tick, which wraps every 49.7 days: the
 * unsigned difference the caller computes has to keep working across it. */
static libusb_testlib_result test_wait_survives_the_tick_wrap(void)
{
	struct windows_hotplug_state state;
	DWORD pending_since = 0xFFFFFF00u;	/* shortly before the wrap */
	DWORD now = 0x00000064u;		/* 356 ms later */

	failures = 0;

	state = state_of(WINDOWS_HOTPLUG_DEVICE_NOT_YET, false, false, (DWORD)(now - pending_since));
	check("356 ms across the wrap", &state, WINDOWS_HOTPLUG_WITHHOLD, false);

	now = (DWORD)(pending_since + HOTPLUG_SETTLE_MAX_WAIT_MS);
	state = state_of(WINDOWS_HOTPLUG_DEVICE_NOT_YET, false, false, (DWORD)(now - pending_since));
	check("ceiling reached across the wrap", &state, WINDOWS_HOTPLUG_ANNOUNCE_TIMED_OUT, false);

	return failures ? TEST_STATUS_FAILURE : TEST_STATUS_SUCCESS;
}

/* A composite device arriving while libusb runs: withheld while usbccgp
 * brings up its functions, then announced exactly once. */
static libusb_testlib_result test_composite_arrival_is_announced_once(void)
{
	struct windows_hotplug_state state;
	bool settled_observed = false;
	bool observe = false;
	enum windows_hotplug_action action;
	DWORD waited = 0;
	unsigned int announcements = 0;
	unsigned int scan;

	failures = 0;

	for (scan = 0; scan < 4; scan++) {
		/* the function devnodes appear during the fourth scan */
		state = state_of(scan < 3 ? WINDOWS_HOTPLUG_DEVICE_NOT_YET : WINDOWS_HOTPLUG_DEVICE_USABLE,
			settled_observed, false, waited);

		action = windows_hotplug_decide(&state, &observe);
		if (observe)
			settled_observed = true;
		if (action != WINDOWS_HOTPLUG_WITHHOLD)
			announcements++;

		waited += 120;
	}

	if (announcements != 1) {
		libusb_testlib_logf("composite arrival: %u announcements, expected exactly 1", announcements);
		failures++;
	}

	return failures ? TEST_STATUS_FAILURE : TEST_STATUS_SUCCESS;
}

static const libusb_testlib_test tests[] = {
	{ "usable_is_announced", &test_usable_is_announced },
	{ "never_usable_is_not_waited_for", &test_never_usable_is_not_waited_for },
	{ "usability_needs_a_known_driver", &test_usability_needs_a_known_driver },
	{ "settled_needs_a_newer_scan", &test_settled_needs_a_newer_scan },
	{ "still_coming_up_stays_withheld", &test_still_coming_up_stays_withheld },
	{ "ceiling_is_per_device", &test_ceiling_is_per_device },
	{ "wait_survives_the_tick_wrap", &test_wait_survives_the_tick_wrap },
	{ "composite_arrival_is_announced_once", &test_composite_arrival_is_announced_once },
	LIBUSB_NULL_TEST
};

#else

static libusb_testlib_result test_not_applicable(void)
{
	libusb_testlib_logf("built without Windows hotplug support");
	return TEST_STATUS_SKIP;
}

static const libusb_testlib_test tests[] = {
	{ "not_applicable", &test_not_applicable },
	LIBUSB_NULL_TEST
};

#endif

int main(int argc, const char *argv[])
{
	return libusb_testlib_run_tests(argc, argv, tests);
}
