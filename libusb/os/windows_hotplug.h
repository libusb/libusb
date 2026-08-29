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

#ifndef WINDOWS_HOTPLUG_H
#define WINDOWS_HOTPLUG_H

int windows_start_event_monitor(void);
int windows_stop_event_monitor(void);

void windows_initial_scan_devices(struct libusb_context *ctx);

// What the last scan produced for a device, as judged from the state the
// interface passes filled in, not from live PnP state: the scan works on a
// device interface snapshot taken when it started, so a live query can be
// ahead of what the scan could see.
enum windows_hotplug_usability {
	WINDOWS_HOTPLUG_DEVICE_USABLE,		// libusb_open has what it needs
	WINDOWS_HOTPLUG_DEVICE_NEVER_USABLE,	// no interface path can ever appear
	WINDOWS_HOTPLUG_DEVICE_NOT_YET		// none yet, the driver stack may add one
};

// Implemented by the WinUSB backend
enum windows_hotplug_usability windows_hotplug_device_usability(struct libusb_device *dev);
bool windows_hotplug_device_settled(struct libusb_device *dev);

#endif
