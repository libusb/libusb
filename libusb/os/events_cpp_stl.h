/*
 * C++ STL event handling backend for libusb 1.0
 * Copyright © 2025 James Smith <jmsmith86@gmail.com>
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

#ifndef LIBUSB_EVENTS_CPP_STL_H
#define LIBUSB_EVENTS_CPP_STL_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HAVE_CLOCK_GETTIME
void usbi_get_monotonic_time(struct timespec *tp);
#endif

typedef void** usbi_os_handle_t;
#define USBI_OS_HANDLE_FORMAT_STRING	"HANDLE %p"

typedef struct cpp_stl_usbi_event* usbi_event_t;
#define USBI_EVENT_OS_HANDLE(e)	(e)
#define USBI_EVENT_POLL_EVENTS	0
#define USBI_INVALID_EVENT	{ INVALID_HANDLE_VALUE }

int usbi_create_event(usbi_event_t *event);
void usbi_destroy_event(usbi_event_t *event);
void usbi_signal_event(usbi_event_t *event);
void usbi_clear_event(usbi_event_t *event);

#define HAVE_OS_TIMER 1
typedef struct cpp_stl_usbi_timer* usbi_timer_t;
#define USBI_TIMER_OS_HANDLE(t)	(t)
#define USBI_TIMER_POLL_EVENTS	0

int usbi_timer_valid(usbi_timer_t *timer);
int usbi_create_timer(usbi_timer_t *timer);
void usbi_destroy_timer(usbi_timer_t *timer);
int usbi_arm_timer(usbi_timer_t *timer, const struct timespec *timeout);
int usbi_disarm_timer(usbi_timer_t *timer);

#ifdef __cplusplus
}
#endif

#endif // LIBUSB_EVENTS_CPP_STL_H
