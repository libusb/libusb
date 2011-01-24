/*
 * Super Mega USB Challenge: libusb hotplug and topology demo
 * Copyright (c) 2011 Pete Batard <pbatard@gmail.com>
 *
 * This test program highlights the use of the new hotplug and
 * topology calls from the point of view of game controller setup.
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
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "libusb.h"

// Global variables
FILE *config_fd = NULL;
int nb_controllers = 0;
struct libusb_device* controller_list[16];
uint8_t config_bus[16];
uint8_t config_data[16][7];
uint8_t config_len[16];
uint8_t bus_number[16];
uint8_t nb_bus_used = 0;

void connected(struct libusb_device *dev, void *data) {
	struct libusb_device_descriptor dev_desc;
	struct libusb_device_topology topology;
	uint8_t i;

	controller_list[nb_controllers++] = dev;

	if (libusb_get_device_descriptor(dev, &dev_desc) == LIBUSB_SUCCESS) {
		printf("\nController #%d: VID:PID %04X:%04X [ignored, as assumed identical]\n",
			nb_controllers, dev_desc.idVendor, dev_desc.idProduct);
	}
	if (libusb_get_device_topology(dev, &topology) == LIBUSB_SUCCESS) {
		printf("bus: %d, port: %d, depth: %d\n", topology.bus, topology.port, topology.depth);
	}
	// To minimize data, each bus is handled separately
	for (i=0; i<nb_bus_used; i++) {
		if (bus_number[i] == topology.bus) {
			return;
		}
	}
	bus_number[nb_bus_used++] = topology.bus;
}

void init_controllers(void) {
	int i, j, r;
	struct libusb_device *last_parent, *current_parent;
	struct libusb_device_topology topology;
	uint8_t b, current_depth;
	uint8_t minimal_depth = 0;

	libusb_register_hotplug_listeners(NULL, connected, NULL, NULL);

	printf("Controller initialization: please plug each controller in the order\n");
	printf("you want them assigned to players (first plugged => player 1, etc.)\n");
	printf("When done, press Enter (would be \"a button on any controller\" for actual app)\n");

	while(getchar() != 0x0A);

	// Ideally, to avoid separate bus number processing, we could treat the bus# as a port# for a depth 0 "hub"
	for (b=0; b<nb_bus_used; b++) {
		last_parent = NULL;
		for (i=0; i<nb_controllers; i++) {
			if (libusb_get_device_topology(controller_list[i], &topology) != LIBUSB_SUCCESS) {
				fprintf(stderr, "failed to read topology 1\n");
				return;
			}

			if (topology.bus != bus_number[b]) {
				continue;
			}
			config_len[i] = 0;

			// First controller for this bus
			if (last_parent == NULL) {
				minimal_depth = topology.depth;
				last_parent = topology.parent_dev;
			}

			// At the very least, we need the leaf port (and bus number)
			config_data[i][config_len[i]++] = topology.port;
			config_bus[i] = topology.bus;

			// If our depth is higher, get to the same depth as current minimal
			while (topology.depth > minimal_depth) {
				if (libusb_get_device_topology(topology.parent_dev, &topology) != LIBUSB_SUCCESS) {
					fprintf(stderr, "failed to read topology\n");
					return;
				}
				config_data[i][config_len[i]++] = topology.port;
			};

			// Keep a copy of our current depth, in case it is lower than last
			current_depth = topology.depth;
			current_parent = topology.parent_dev;

			// Lower everyone before us until we get to the common ancestor
			while (current_parent != last_parent) {
				minimal_depth--;
				// All ancestors up to i-1 are the same as this stage, so just pick up the port from last common parent
				if (libusb_get_device_topology(last_parent, &topology)) {
					fprintf(stderr, "failed to read topology\n");
					return;
				}
				last_parent = topology.parent_dev;
				for (j=0; j<i; j++) {
					config_data[j][config_len[j]++] = topology.port;
				}
				if (current_depth <= topology.depth) {
					// If the depths are different, we are just lowering existing data to our
					// current depth => don't go further until we can compare parents on the same footing
					continue;
				}
				if ((r = libusb_get_device_topology(current_parent, &topology)) != LIBUSB_SUCCESS) {
					fprintf(stderr, "failed to read topology\n");
					return;
				}
				current_parent = topology.parent_dev;
			}
		}
		printf("Minimum distance to root, to uniquely identify all controllers on bus %d: %d\n", bus_number[b], minimal_depth);
	}

	// Display config data
	printf("\nConfig data:\n");
	for (i=0; i<nb_controllers; i++) {
		printf("Controller #%d: Len:%02X, Bus:%02X, Port(s):", i+1, ++config_len[i], config_bus[i]);
		fwrite(&config_len[i], 1, 1, config_fd);
		fwrite(&config_bus[i], 1, 1, config_fd);
		for (j=0; j<config_len[i]-1; j++) {
			printf(" %02X", config_data[i][j]);
			fwrite(&config_data[i][j], 1, 1, config_fd);
		}
		printf("\n");
	}
}

void check_controllers(void) {
	printf("Confirming controller setup...\n\n");
	printf("(This is the part where we would scan all devices with our controllers VID:PID\n");
	printf("and check that they match the config, using the same code as in init_controllers)\n");
}


int main(int argc, char** argv)
{
	int show_help = 0;
	int debug_mode = 0;
	int controller_setup = 0;
	int j, r;
	size_t len;

	// Default to HID, expecting VID:PID
	if (argc >= 2) {
		for (j = 1; j<argc; j++) {
			len = strlen(argv[j]);
			if ( ((argv[j][0] == '-') || (argv[j][0] == '/')) && (len >= 2) ) {
				switch(argv[j][1]) {
				case 'd':
					debug_mode = -1;
					break;
				default:
					show_help = -1;
					break;
				}
			} else {
				show_help = -1;
			}
		}
	}

	if ((show_help) || (argc > 2)) {
		printf("usage: %s [-d] [-h]\n", argv[0]);
		printf("   -h: display usage\n");
		printf("   -d: enable debug output (if library was compiled with debug enabled)\n");
		return 0;
	}

	printf("\nSuper Mega USB Challenge! (c) 2011 MomCo\n\n");

	config_fd = fopen("smuc.cfg", "rb");
	if (config_fd == NULL) {
		config_fd = fopen("smuc.cfg", "wb");
		if (config_fd == NULL) {
			fprintf(stderr, "unable to create config file\n");
			exit(1);
		}
		controller_setup = -1;
		len = 0;
	} else {
		fseek(config_fd, 0, SEEK_END);
		len = (size_t)ftell(config_fd);
		fseek(config_fd, 0, SEEK_SET);
		if (len == 0) {
			controller_setup = -1;
		}
	}

	r = libusb_init(NULL);
	if (r < 0) {
		fclose(config_fd);
		return r;
	}

	// Warnings = 2, Debug = 4
	libusb_set_debug(NULL, debug_mode?4:2);

	if (controller_setup) {
		init_controllers();
	} else {
		check_controllers();
	}

	fclose(config_fd);
	libusb_exit(NULL);

	return 0;
}
