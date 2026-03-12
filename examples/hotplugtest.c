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

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <inttypes.h>

#if defined(PLATFORM_WINDOWS)
#include <conio.h>
#elif defined(PLATFORM_POSIX)
#include <errno.h>
#include <unistd.h>
#include <termios.h>
#include <sys/select.h>
#endif

#include "libusb.h"

struct hotplug_state {
	uint64_t arrived;
	uint64_t departed;
	volatile sig_atomic_t quit;
};

static volatile sig_atomic_t signal_exit_requested = 0;

#if defined(PLATFORM_POSIX)
static int terminal_configured = 0;
static struct termios terminal_saved;
#endif

static void handle_signal(int signum)
{
	(void)signum;
	signal_exit_requested = 1;
}

static const char *speed_name(int speed)
{
	switch (speed) {
	case LIBUSB_SPEED_LOW:
		return "1.5M";
	case LIBUSB_SPEED_FULL:
		return "12M";
	case LIBUSB_SPEED_HIGH:
		return "480M";
	case LIBUSB_SPEED_SUPER:
		return "5G";
	case LIBUSB_SPEED_SUPER_PLUS:
		return "10G";
	case LIBUSB_SPEED_SUPER_PLUS_X2:
		return "20G";
	case LIBUSB_SPEED_UNKNOWN:
	default:
		return "unknown";
	}
}

static void print_counters(const struct hotplug_state *state)
{
	int64_t difference = (int64_t)state->arrived - (int64_t)state->departed;
	printf("[arrived=%" PRIu64 " departed=%" PRIu64 " delta=%" PRId64"]\n",
		state->arrived, state->departed, difference);
}

static void print_device_event(const char *event_name, libusb_device *dev, struct hotplug_state *state)
{
	struct libusb_device_descriptor desc;
	char string_buffer[LIBUSB_DEVICE_STRING_BYTES_MAX];
	uint8_t path[8];
	int rc;
	int i;

	rc = libusb_get_device_descriptor(dev, &desc);
	if (LIBUSB_SUCCESS == rc) {
		printf("%s: %04x:%04x (bus %d, device %d)",
			event_name, desc.idVendor, desc.idProduct,
			libusb_get_bus_number(dev), libusb_get_device_address(dev));

		rc = libusb_get_port_numbers(dev, path, sizeof(path));
		if (rc > 0) {
			printf(" path: %d", path[0]);
			for (i = 1; i < rc; i++)
				printf(".%d", path[i]);
		}

		printf("\n    speed = %s", speed_name(libusb_get_device_speed(dev)));

		rc = libusb_get_device_string(dev, LIBUSB_DEVICE_STRING_SERIAL_NUMBER,
			string_buffer, sizeof(string_buffer));
		if (rc >= 0)
			printf("\n    serial_number = %s", string_buffer);

		printf("\n");
	} else {
		printf("%s\n", event_name);
		fprintf(stderr, "Error getting device descriptor: %s\n",
			libusb_strerror((enum libusb_error)rc));
	}

	print_counters(state);
}

static int check_for_quit_key(void)
{
#if defined(PLATFORM_WINDOWS)
	if (_kbhit()) {
		int c = _getch();
		return c == 'q' || c == 'Q';
	}
	return 0;
#elif defined(PLATFORM_POSIX)
	fd_set read_fds;
	struct timeval timeout = { 0, 0 };
	char c;
	int rc;

	FD_ZERO(&read_fds);
	FD_SET(STDIN_FILENO, &read_fds);

	rc = select(STDIN_FILENO + 1, &read_fds, NULL, NULL, &timeout);
	if (rc < 0) {
		if (errno == EINTR)
			return 0;
		return 0;
	}
	if (rc > 0 && FD_ISSET(STDIN_FILENO, &read_fds) && read(STDIN_FILENO, &c, 1) == 1)
		return c == 'q' || c == 'Q';

	return 0;
#else
	return 0;
#endif
}

#if defined(PLATFORM_POSIX)
static int setup_terminal(void)
{
	struct termios new_termios;

	if (!isatty(STDIN_FILENO))
		return 0;

	if (tcgetattr(STDIN_FILENO, &terminal_saved) != 0)
		return -1;

	new_termios = terminal_saved;
	new_termios.c_lflag &= (tcflag_t)~(ICANON | ECHO);
	new_termios.c_cc[VMIN] = 0;
	new_termios.c_cc[VTIME] = 0;
	if (tcsetattr(STDIN_FILENO, TCSANOW, &new_termios) != 0)
		return -1;

	terminal_configured = 1;
	return 0;
}

static void restore_terminal(void)
{
	if (terminal_configured) {
		(void)tcsetattr(STDIN_FILENO, TCSANOW, &terminal_saved);
		terminal_configured = 0;
	}
}
#else
static int setup_terminal(void)
{
	return 0;
}

static void restore_terminal(void)
{
}
#endif

static int ask_hotplug_enumerate_flag(void)
{
	char line[16];

	for (;;) {
		printf("Use LIBUSB_HOTPLUG_ENUMERATE for already-connected devices? [Y/n]: ");
		fflush(stdout);

		if (NULL == fgets(line, sizeof(line), stdin)) {
			printf("\nNo input received; defaulting to yes.\n");
			return LIBUSB_HOTPLUG_ENUMERATE;
		}

		if ('\n' == line[0] || 'y' == line[0] || 'Y' == line[0])
			return LIBUSB_HOTPLUG_ENUMERATE;

		if ('n' == line[0] || 'N' == line[0])
			return 0;

		printf("Please answer y or n.\n");
	}
}

static int LIBUSB_CALL hotplug_callback(libusb_context *ctx, libusb_device *dev, libusb_hotplug_event event, void *user_data)
{
	struct hotplug_state *state = (struct hotplug_state *)user_data;

	(void)ctx;
	(void)event;

	state->arrived++;
	print_device_event("\nDevice attached", dev, state);

	return 0;
}

static int LIBUSB_CALL hotplug_callback_detach(libusb_context *ctx, libusb_device *dev, libusb_hotplug_event event, void *user_data)
{
	struct hotplug_state *state = (struct hotplug_state *)user_data;

	(void)ctx;
	(void)event;

	state->departed++;
	print_device_event("\nDevice detached", dev, state);

	return 0;
}

int main(int argc, char *argv[])
{
	libusb_context *ctx = NULL;
	struct hotplug_state state = { 0, 0, 0 };
	libusb_hotplug_callback_handle hp[2];
	int callback_registered[2] = { 0, 0 };
	int product_id, vendor_id, class_id;
	int arrival_flags;
	int rc;

	vendor_id  = (argc > 1) ? (int)strtol (argv[1], NULL, 0) : LIBUSB_HOTPLUG_MATCH_ANY;
	product_id = (argc > 2) ? (int)strtol (argv[2], NULL, 0) : LIBUSB_HOTPLUG_MATCH_ANY;
	class_id   = (argc > 3) ? (int)strtol (argv[3], NULL, 0) : LIBUSB_HOTPLUG_MATCH_ANY;

	rc = libusb_init_context(&ctx, /*options=*/NULL, /*num_options=*/0);
	if (LIBUSB_SUCCESS != rc)
	{
		printf ("failed to initialise libusb: %s\n",
			libusb_strerror((enum libusb_error)rc));
		return EXIT_FAILURE;
	}

	if (!libusb_has_capability (LIBUSB_CAP_HAS_HOTPLUG)) {
		printf ("Hotplug capabilities are not supported on this platform\n");
		libusb_exit (ctx);
		return EXIT_FAILURE;
	}

	arrival_flags = ask_hotplug_enumerate_flag();

	if (setup_terminal() != 0)
		fprintf(stderr, "Warning: failed to setup terminal for q/Q input\n");

	(void)signal(SIGINT, handle_signal);

	printf("Monitoring hotplug events. Press q or Q to quit, or Ctrl-C.\n");

	rc = libusb_hotplug_register_callback (ctx, LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED,
		arrival_flags, vendor_id, product_id, class_id,
		hotplug_callback, &state, &hp[0]);
	if (LIBUSB_SUCCESS != rc) {
		fprintf (stderr, "Error registering callback 0\n");
		restore_terminal();
		libusb_exit (ctx);
		return EXIT_FAILURE;
	}
	callback_registered[0] = 1;

	rc = libusb_hotplug_register_callback (ctx, LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT, 0, vendor_id,
		product_id,class_id, hotplug_callback_detach, &state, &hp[1]);
	if (LIBUSB_SUCCESS != rc) {
		fprintf (stderr, "Error registering callback 1\n");
		libusb_hotplug_deregister_callback(ctx, hp[0]);
		restore_terminal();
		libusb_exit (ctx);
		return EXIT_FAILURE;
	}
	callback_registered[1] = 1;

	while (!state.quit) {
		struct timeval tv = { 0, 50000 };

		rc = libusb_handle_events_timeout_completed(ctx, &tv, NULL);
		if (LIBUSB_SUCCESS != rc && LIBUSB_ERROR_INTERRUPTED != rc)
			printf ("libusb_handle_events_timeout_completed() failed: %s\n",
				libusb_strerror((enum libusb_error)rc));

		if (signal_exit_requested || check_for_quit_key())
			state.quit = 1;
	}

	if (callback_registered[1])
		libusb_hotplug_deregister_callback(ctx, hp[1]);
	if (callback_registered[0])
		libusb_hotplug_deregister_callback(ctx, hp[0]);

	restore_terminal();
	libusb_exit (ctx);

	return EXIT_SUCCESS;
}
