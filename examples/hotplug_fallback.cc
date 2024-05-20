/* -*- Mode: C; indent-tabs-mode:t ; c-basic-offset:8 -*- */
/*
 * libusb example program for hotplug API
 * Copyright © 2012-2013 Nathan Hjelm <hjelmn@mac.com>
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

#include <stdlib.h>

#include <algorithm>
#include <chrono>
#include <iostream>
#include <thread>
#include <unordered_map>
#include <vector>

#include "libusb.h"

// This is a code sample demonstrating how to fallback on system without support for hotplug.
// Three threads are involved. 
//     - One main thread would be your application thread.
//     - One thread pumps libusb_handle_events forever.
//     - One thread runs libusb_get_device_list periodically.

// On Windows, address changes everytimes a device is connected. Even if it is the same
// device on the same port. We use these properties to build an unique key for a connected
// device.
uint64_t get_key_for(uint64_t vendor, uint64_t product, uint64_t port, uint64_t address) {
	return vendor << 32 | product << 16 | port << 8 | address;
}

int main() {	
	int rc = libusb_init_context(nullptr, nullptr, 0);
	if (LIBUSB_SUCCESS != rc) {
	   std::cout << "failed to initialise libusb:" << libusb_strerror((enum libusb_error)rc) << std::endl;
		return EXIT_FAILURE;
	}

	if (libusb_has_capability (LIBUSB_CAP_HAS_HOTPLUG)) {
		std::cout << "Hotplug capabilities is supported on this platform. No need for fallback!" << std::endl;
		libusb_exit (nullptr);
		return EXIT_FAILURE;
	}

	std::cout << "Hotplug capabilities is NOT supported on this platform. Using fallback!" << std::endl;
	
	// This thread calls libusb_get_device_list every two seconds.
	auto hotplug_thread = std::thread([]() {
	    std::unordered_map<uint64_t, libusb_device*> known_devices;
		while (true) {

			// First retrieve all connected devices and detect new devices.
			libusb_device** devs = nullptr;
			libusb_get_device_list(nullptr, &devs);
			std::unordered_map<uint64_t, libusb_device*> current_devices;
			for (size_t i = 0; devs[i] != nullptr; ++i) {
				libusb_device* dev = devs[i];
				libusb_device_descriptor desc;
				auto result = libusb_get_device_descriptor(dev, &desc);
				if (result != LIBUSB_SUCCESS) {
					continue;
				}
				uint8_t port = libusb_get_port_number(dev);
				uint8_t address = libusb_get_device_address(dev);
				uint64_t key = get_key_for(desc.idVendor, desc.idProduct, port, address);
				current_devices[key] = dev;

				// Handle new devices
				if (known_devices.count(key) == 0) {
					std::cout << "Device added vendor:" << desc.idVendor << " product:" << desc.idProduct << std::endl;
				}
			}

			// Handle disconnected devices
			for (const auto& it : known_devices) {
				auto key = it.first;
				if (current_devices.count(key) == 0) {
				
					libusb_device_descriptor desc;
					auto result = libusb_get_device_descriptor(it.second, &desc);
					if (result != LIBUSB_SUCCESS) {
						continue;
					}
					std::cout << "Device removed vendor:" << desc.idVendor << " product:" << desc.idProduct << std::endl;

					libusb_unref_device(it.second);
							
				}
			}
			known_devices = std::move(current_devices);
			
			using namespace std::chrono_literals;
			std::this_thread::sleep_for(2s);
		}
		
	});
	hotplug_thread.detach();

	// That the thread to run libusb events system.
	auto event_thread = std::thread([] () {
		while (true) {
		  int rc = libusb_handle_events(nullptr);
		  if (LIBUSB_SUCCESS != rc)
			  std::cout << "libusb_handle_events() failed:" << libusb_strerror((enum libusb_error)rc) << std::endl;
		}
	});

	event_thread.join();
	libusb_exit (nullptr);
	return EXIT_SUCCESS;
}
