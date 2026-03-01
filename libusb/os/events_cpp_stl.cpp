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

#include "libusbi.h"

#include <cstdlib>
#include <chrono>
#include <mutex>
#include <condition_variable>

//! Enumerates the type of an event data from a raw pointer
enum cpp_stl_event_type : int
{
    //! Initialization value - invalid event type
    CPP_STL_EVENT_TYPE_UNKNOWN = 0,
    //! Event event type
    CPP_STL_EVENT_TYPE_EVENT = 1,
    //! Timer event type
    CPP_STL_EVENT_TYPE_TIMER = 2
};

#ifndef HAVE_CLOCK_GETTIME
void usbi_get_monotonic_time(struct timespec *tp)
{
    std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
    std::chrono::steady_clock::duration duration = now.time_since_epoch();
    std::chrono::seconds seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
    std::chrono::nanoseconds nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(duration - seconds);
    tp->tv_sec = seconds.count();
    tp->tv_nsec = static_cast<long>(nanoseconds.count());
}
#endif

//! All event access is serialized using this mutex
static std::mutex event_mutex;
//! All events are signaled using this condition variable
static std::condition_variable event_cv;

struct cpp_stl_usbi_event
{
    //! Enumerates the type of this event data from a raw pointer
    const int type = CPP_STL_EVENT_TYPE_EVENT;
    //! 1 when event signaled or 0 if event is cleared
    int event_occurred = 0;
};

int usbi_create_event(usbi_event_t *event)
{
    (*event) = new cpp_stl_usbi_event();
    return 0;
}

void usbi_destroy_event(usbi_event_t *event)
{
    delete (*event);
    (*event) = nullptr;
}

void usbi_signal_event(usbi_event_t *event)
{
    std::unique_lock<std::mutex> lock(event_mutex);
    (*event)->event_occurred = 1;
    event_cv.notify_all();
}

void usbi_clear_event(usbi_event_t *event)
{
    std::unique_lock<std::mutex> lock(event_mutex);
    (*event)->event_occurred = 0;
}

#ifdef HAVE_OS_TIMER
struct cpp_stl_usbi_timer
{
    //! Enumerates the type of this event data from a raw pointer
    const int type = CPP_STL_EVENT_TYPE_TIMER;
    //! true when time is set and timer is waiting for expiration
    bool armed = false;
    //! The time point of this timer using monotonic clock
    std::chrono::steady_clock::time_point time;
};

int usbi_timer_valid(usbi_timer_t *timer)
{
	return (*timer) != nullptr;
}

int usbi_create_timer(usbi_timer_t *timer)
{
	(*timer) = new cpp_stl_usbi_timer();
	return 0;
}

void usbi_destroy_timer(usbi_timer_t *timer)
{
	delete (*timer);
    (*timer) = nullptr;
}

int usbi_arm_timer(usbi_timer_t *timer, const struct timespec *timeout)
{
    (*timer)->time =
        std::chrono::steady_clock::now() +
        std::chrono::seconds(timeout->tv_sec) +
        std::chrono::nanoseconds(timeout->tv_nsec);
    (*timer)->armed = true;
    return 0;
}

int usbi_disarm_timer(usbi_timer_t *timer)
{
	(*timer)->armed = false;
	return 0;
}
#endif // HAVE_OS_TIMER

int usbi_alloc_event_data(struct libusb_context *ctx)
{
	struct usbi_event_source *ievent_source;
	void **handles;
	size_t i = 0;

	/* Event sources are only added during usbi_io_init(). We should not
	 * be running this function again if the event data has already been
	 * allocated. */
	if (ctx->event_data)
    {
		usbi_warn(ctx, "program assertion failed - event data already allocated");
		return LIBUSB_ERROR_OTHER;
	}

	ctx->event_data_cnt = 0;
	for_each_event_source(ctx, ievent_source)
    {
		ctx->event_data_cnt++;
    }

    // Note: free(ctx->event_data) is called in io.c
	handles = static_cast<void**>(calloc(ctx->event_data_cnt, sizeof(void*)));
	if (!handles)
    {
		return LIBUSB_ERROR_NO_MEM;
    }

	for_each_event_source(ctx, ievent_source)
    {
        // This isn't needed, but it cleans up a silly compiler warning
        if (i >= ctx->event_data_cnt)
        {
            break;
        }

        // ievent_source->data.os_handle holds pointers to allocated pointers to event and timer
        handles[i] = *(ievent_source->data.os_handle);
        i++;
	}

	ctx->event_data = handles;
	return 0;
}

int usbi_wait_for_events(struct libusb_context *ctx, struct usbi_reported_events *reported_events, int timeout_ms)
{
	void **handles = static_cast<void**>(ctx->event_data);
	int num_handles = ctx->event_data_cnt;

	usbi_dbg(ctx, "wait for %lu HANDLEs with timeout in %dms", static_cast<unsigned long>(num_handles), timeout_ms);

    std::chrono::steady_clock::time_point expiration = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);

    // This value will remain 0 because events don't need to be handled by back-end using this platform
    reported_events->num_ready = 0;

    reported_events->event_triggered = 0;

#ifdef HAVE_OS_TIMER
    reported_events->timer_triggered = 0;
    bool timerElapsedOnTimeout = false;
    if (usbi_using_timer(ctx))
    {
        for (int i = 0; i < num_handles; ++i)
        {
            cpp_stl_usbi_timer *tmr = static_cast<cpp_stl_usbi_timer*>(handles[i]);
            if (tmr->type == CPP_STL_EVENT_TYPE_TIMER && tmr->armed)
            {
                std::chrono::milliseconds tmrTimeoutMs(0);
                if (tmr->time < expiration)
                {
                    // Change expiration to timer's time
                    expiration = tmr->time;
                    timerElapsedOnTimeout = true;
                    break;
                }
            }
        }
    }
#endif

    if (num_handles > 0)
    {
        std::unique_lock<std::mutex> lock(event_mutex);
        bool status = event_cv.wait_until(
            lock,
            expiration,
            [&handles, &num_handles, &reported_events]()
            {
                bool trigger = false;

                for (int i = 0; i < num_handles; ++i)
                {
                    cpp_stl_usbi_event *ev = static_cast<cpp_stl_usbi_event*>(handles[0]);

                    if (ev->type == CPP_STL_EVENT_TYPE_EVENT && ev->event_occurred)
                    {
                        trigger = true;
                        reported_events->event_triggered = 1;
                        break;
                    }
                }

                return trigger;
            }
        );

#if HAVE_OS_TIMER
        if (!status && timerElapsedOnTimeout)
        {
            reported_events->timer_triggered = 1;
            status = true;
        }
#endif

        if (!status)
        {
            return LIBUSB_ERROR_TIMEOUT;
        }
    }

	return LIBUSB_SUCCESS;
}
