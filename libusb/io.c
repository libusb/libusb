/*
 * I/O functions for libusb
 * Copyright (C) 2007-2008 Daniel Drake <dsd@gentoo.org>
 * Copyright (c) 2001 Johannes Erdfelt <johannes@erdfelt.com>
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
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "libusbi.h"

/* this is a list of in-flight transfer handles, sorted by timeout expiration.
 * URBs to timeout the soonest are placed at the beginning of the list, URBs
 * that will time out later are placed after, and urbs with infinite timeout
 * are always placed at the very end. */
static struct list_head flying_transfers;
static pthread_mutex_t flying_transfers_lock = PTHREAD_MUTEX_INITIALIZER;

/* list of poll fd's */
static struct list_head pollfds;
static pthread_mutex_t pollfds_lock = PTHREAD_MUTEX_INITIALIZER;

/* user callbacks for pollfd changes */
static libusb_pollfd_added_cb fd_added_cb = NULL;
static libusb_pollfd_removed_cb fd_removed_cb = NULL;

/**
 * \page io Synchronous and asynchronous device I/O
 *
 * \section intro Introduction
 *
 * If you're using libusb in your application, you're probably wanting to
 * perform I/O with devices - you want to perform USB data transfers.
 *
 * libusb offers two separate interfaces for device I/O. This page aims to
 * introduce the two in order to help you decide which one is more suitable
 * for your application. You can also choose to use both interfaces in your
 * application by considering each transfer on a case-by-case basis.
 *
 * Once you have read through the following discussion, you should consult the
 * detailed API documentation pages for the details:
 * - \ref syncio
 * - \ref asyncio
 *
 * \section theory Transfers at a logical level
 *
 * At a logical level, USB transfers typically happen in two parts. For
 * example, when reading data from a endpoint:
 * -# A request for data is sent to the device
 * -# Some time later, the incoming data is received by the host
 *
 * or when writing data to an endpoint:
 *
 * -# The data is sent to the device
 * -# Some time later, the host receives acknowledgement from the device that
 *    the data has been transferred.
 *
 * There may be an indefinite delay between the two steps. Consider a
 * fictional USB input device with a button that the user can press. In order
 * to determine when the button is pressed, you would likely submit a request
 * to read data on a bulk or interrupt endpoint and wait for data to arrive.
 * Data will arrive when the button is pressed by the user, which is
 * potentially hours later.
 *
 * libusb offers both a synchronous and an asynchronous interface to performing
 * USB transfers. The main difference is that the synchronous interface
 * combines both steps indicated above into a single function call, whereas
 * the asynchronous interface separates them.
 *
 * \section sync The synchronous interface
 *
 * The synchronous I/O interface allows you to perform a USB transfer with
 * a single function call. When the function call returns, the transfer has
 * completed and you can parse the results.
 *
 * If you have used the libusb-0.1 before, this I/O style will seem familar to
 * you. libusb-0.1 only offered a synchronous interface.
 *
 * In our input device example, to read button presses you might write code
 * in the following style:
\code
unsigned char data[4];
int actual_length,
int r = libusb_bulk_transfer(handle, EP_IN, data, sizeof(data), &actual_length, 0);
if (r == 0 && actual_length == sizeof(data)) {
	// results of the transaction can now be found in the data buffer
	// parse them here and report button press
} else {
	error();
}
\endcode
 *
 * The main advantage of this model is simplicity: you did everything with
 * a single simple function call.
 *
 * However, this interface has its limitations. Your application will sleep
 * inside libusb_bulk_transfer() until the transaction has completed. If it
 * takes the user 3 hours to press the button, your application will be
 * sleeping for that long. Execution will be tied up inside the library -
 * the entire thread will be useless for that duration.
 *
 * Another issue is that by tieing up the thread with that single transaction
 * there is no possibility of performing I/O with multiple endpoints and/or
 * multiple devices simultaneously, unless you resort to creating one thread
 * per transaction.
 *
 * Additionally, there is no opportunity to cancel the transfer after the
 * request has been submitted.
 *
 * For details on how to use the synchronous API, see the
 * \ref syncio "synchronous I/O API documentation" pages.
 * 
 * \section async The asynchronous interface
 *
 * Asynchronous I/O is the most significant new feature in libusb-1.0.
 * Although it is a more complex interface, it solves all the issues detailed
 * above.
 *
 * Instead of providing which functions that block until the I/O has complete,
 * libusb's asynchronous interface presents non-blocking functions which
 * begin a transfer and then return immediately. Your application passes a
 * callback function pointer to this non-blocking function, which libusb will
 * call with the results of the transaction when it has completed.
 *
 * Transfers which have been submitted through the non-blocking functions
 * can be cancelled with a separate function call.
 *
 * The non-blocking nature of this interface allows you to be simultaneously
 * performing I/O to multiple endpoints on multiple devices, without having
 * to use threads.
 *
 * This added flexibility does come with some complications though:
 * - In the interest of being a lightweight library, libusb does not create
 * threads and can only operate when your application is calling into it. Your
 * application must call into libusb from it's main loop when events are ready
 * to be handled, or you must use some other scheme to allow libusb to
 * undertake whatever work needs to be done.
 * - libusb also needs to be called into at certain fixed points in time in
 * order to accurately handle transfer timeouts.
 * - Memory handling becomes more complex. You cannot use stack memory unless
 * the function with that stack is guaranteed not to return until the transfer
 * callback has finished executing.
 * - You generally lose some linearity from your code flow because submitting
 * the transfer request is done in a separate function from where the transfer
 * results are handled. This becomes particularly obvious when you want to
 * submit a second transfer based on the results of an earlier transfer.
 *
 * Internally, libusb's synchronous interface is expressed in terms of function
 * calls to the asynchronous interface.
 *
 * For details on how to use the asynchronous API, see the
 * \ref asyncio "asynchronous I/O API" documentation pages.
 */

/**
 * @defgroup asyncio Asynchronous device I/O
 *
 * This page details libusb's asynchronous (non-blocking) API for USB device
 * I/O. This interface is very powerful but is also quite complex - you will
 * need to read this page carefully to understand the necessary considerations
 * and issues surrounding use of this interface. Simplistic applications
 * may wish to consider the \ref syncio "synchronous I/O API" instead.
 *
 * The asynchronous interface is built around the idea of separating transfer
 * submission and handling of transfer completion (the synchronous model
 * combines both of these into one). There may be a long delay between
 * submission and completion, however the asynchronous submission function
 * is non-blocking so will return control to your application during that
 * potentially long delay.
 *
 * \section asyncabstraction Transfer abstraction
 *
 * For the asynchronous I/O, libusb implements the concept of a generic
 * transfer entity for all types of I/O (control, bulk, interrupt,
 * isochronous). The generic transfer object must be treated slightly
 * differently depending on which type of I/O you are performing with it.
 *
 * This is represented by the public libusb_transfer structure type.
 *
 * \section asynctrf Asynchronous transfers
 *
 * We can view asynchronous I/O as a 5 step process:
 * -# Allocation
 * -# Filling
 * -# Submission
 * -# Completion handling
 * -# Deallocation
 *
 * \subsection asyncalloc Allocation
 *
 * This step involves allocating memory for a USB transfer. This is the
 * generic transfer object mentioned above. At this stage, the transfer
 * is "blank" with no details about what type of I/O it will be used for.
 *
 * Allocation is done with the libusb_alloc_transfer() function. You must use
 * this function rather than allocating your own transfers.
 *
 * \subsection asyncfill Filling
 *
 * This step is where you take a previously allocated transfer and fill it
 * with information to determine the message type and direction, data buffer,
 * callback function, etc.
 *
 * You can either fill the required fields yourself or you can use the
 * helper functions: libusb_fill_control_transfer(), libusb_fill_bulk_transfer()
 * and libusb_fill_interrupt_transfer().
 *
 * \subsection asyncsubmit Submission
 *
 * When you have allocated a transfer and filled it, you can submit it using
 * libusb_submit_transfer(). This function returns immediately but can be
 * regarded as firing off the I/O request in the background.
 *
 * \subsection asynccomplete Completion handling
 *
 * After a transfer has been submitted, one of four things can happen to it:
 *
 * - The transfer completes (i.e. some data was transferred)
 * - The transfer has a timeout and the timeout expires before all data is
 * transferred
 * - The transfer fails due to an error
 * - The transfer is cancelled
 *
 * Each of these will cause the user-specified transfer callback function to
 * be invoked. It is up to the callback function to determine which of the
 * above actually happened and to act accordingly.
 *
 * \subsection Deallocation
 *
 * When a transfer has completed (i.e. the callback function has been invoked),
 * you are advised to free the transfer (unless you wish to resubmit it, see
 * below). Transfers are deallocated with libusb_free_transfer().
 *
 * It is undefined behaviour to free a transfer which has not completed.
 *
 * \section asyncresubmit Resubmission
 *
 * You may be wondering why allocation, filling, and submission are all
 * separated above where they could reasonably be combined into a single
 * operation.
 *
 * The reason for separation is to allow you to resubmit transfers without
 * having to allocate new ones every time. This is especially useful for
 * common situations dealing with interrupt endpoints - you allocate one
 * transfer, fill and submit it, and when it returns with results you just
 * resubmit it for the next interrupt.
 *
 * \section asynccancel Cancellation
 *
 * Another advantage of using the asynchronous interface is that you have
 * the ability to cancel transfers which have not yet completed. This is
 * done by calling the libusb_cancel_transfer() function.
 *
 * libusb_cancel_transfer() is asynchronous/non-blocking in itself. When the
 * cancellation actually completes, the transfer's callback function will
 * be invoked, and the callback function should check the transfer status to
 * determine that it was cancelled.
 *
 * Freeing the transfer after it has been cancelled but before cancellation
 * has completed will result in undefined behaviour.
 *
 * \section asyncctrl Considerations for control transfers
 *
 * The <tt>libusb_transfer</tt> structure is generic and hence does not
 * include specific fields for the control-specific setup packet structure.
 *
 * In order to perform a control transfer, you must place the 8-byte setup
 * packet at the start of the data buffer. To simplify this, you could
 * cast the buffer pointer to type struct libusb_control_setup, or you can
 * use the helper function libusb_fill_control_setup().
 *
 * The wLength field placed in the setup packet must be the length you would
 * expect to be sent in the setup packet: the length of the payload that
 * follows (or the expected maximum number of bytes to receive). However,
 * the length field of the libusb_transfer object must be the length of
 * the data buffer - i.e. it should be wLength <em>plus</em> the size of
 * the setup packet (LIBUSB_CONTROL_SETUP_SIZE).
 *
 * If you use the helper functions, this is simplified for you:
 * -# Allocate a buffer of size LIBUSB_CONTROL_SETUP_SIZE plus the size of the
 * data you are sending/requesting.
 * -# Call libusb_fill_control_setup() on the data buffer, using the transfer
 * request size as the wLength value (i.e. do not include the extra space you
 * allocated for the control setup).
 * -# If this is a host-to-device transfer, place the data to be transferred
 * in the data buffer, starting at offset LIBUSB_CONTROL_SETUP_SIZE.
 * -# Call libusb_fill_control_transfer() to associate the data buffer with
 * the transfer (and to set the remaining details such as callback and timeout).
 *   - Note that there is no parameter to set the length field of the transfer.
 *     The length is automatically inferred from the wLength field of the setup
 *     packet.
 * -# Submit the transfer.
 *
 * Further considerations are needed when handling transfer completion in
 * your callback function:
 * - As you might expect, the setup packet will still be sitting at the start
 * of the data buffer.
 * - If this was a device-to-host transfer, the received data will be sitting
 * at offset LIBUSB_CONTROL_SETUP_SIZE into the buffer.
 * - The actual_length field of the transfer structure is relative to the
 * wLength of the setup packet, rather than the size of the data buffer. So,
 * if your wLength was 4, your transfer's <tt>length</tt> was 12, then you
 * should expect an <tt>actual_length</tt> of 4 to indicate that the data was
 * transferred in entirity.
 *
 * To simplify parsing of setup packets and obtaining the data from the
 * correct offset, you may wish to use the libusb_control_transfer_get_data()
 * and libusb_control_transfer_get_setup() functions within your transfer
 * callback.
 *
 * \section asyncintr Considerations for interrupt transfers
 * 
 * All interrupt transfers are performed using the polling interval presented
 * by the bInterval value of the endpoint descriptor.
 *
 * \section asynciso Considerations for isochronous transfers
 *
 * As isochronous transfers are more complicated than transfers to
 * non-isochronous endpoints.
 *
 * To perform I/O to an isochronous endpoint, allocate the transfer by calling
 * libusb_alloc_transfer() with an appropriate number of isochronous packets.
 *
 * During filling, set \ref libusb_transfer::endpoint_type "endpoint_type" to
 * \ref libusb_endpoint_type::LIBUSB_ENDPOINT_TYPE_ISOCHRONOUS
 * "LIBUSB_ENDPOINT_TYPE_ISOCHRONOUS", and set
 * \ref libusb_transfer::num_iso_packets "num_iso_packets" to a value less than
 * or equal to the number of packets you requested during allocation.
 * libusb_alloc_transfer() does not set either of these fields for you, given
 * that you might not even use the transfer on an isochronous endpoint.
 *
 * Next, populate the length field for the first num_iso_packets entries in
 * the \ref libusb_transfer::iso_packet_desc "iso_packet_desc" array. Section
 * 5.6.3 of the USB2 specifications describe how the maximum isochronous
 * packet length is determined by the endpoint descriptor. FIXME need a helper
 * function to find this.
 * FIXME, write a helper function to set the length for all iso packets in an
 * array
 *
 * For outgoing transfers, you'll obviously fill the buffer and populate the
 * packet descriptors in hope that all the data gets transferred. For incoming
 * transfers, you must ensure the buffer has sufficient capacity for
 * the situation where all packets transfer the full amount of requested data.
 *
 * Completion handling requires some extra consideration. The
 * \ref libusb_transfer::actual_length "actual_length" field of the transfer
 * is meaningless and should not be examined; instead you must refer to the
 * \ref libusb_iso_packet_descriptor::actual_length "actual_length" field of
 * each individual packet.
 *
 * The \ref libusb_transfer::status "status" field of the transfer is also a
 * little misleading:
 *  - If the packets were submitted and the isochronous data microframes
 *    completed normally, status will have value
 *    \ref libusb_transfer_status::LIBUSB_TRANSFER_COMPLETED
 *    "LIBUSB_TRANSFER_COMPLETED". Note that bus errors and software-incurred
 *    delays are not counted as transfer errors; the transfer.status field may
 *    indicate COMPLETED even if some or all of the packets failed. Refer to
 *    the \ref libusb_iso_packet_descriptor::status "status" field of each
 *    individual packet to determine packet failures.
 *  - The status field will have value
 *    \ref libusb_transfer_status::LIBUSB_TRANSFER_ERROR
 *    "LIBUSB_TRANSFER_ERROR" only when serious errors were encountered.
 *  - Other transfer status codes occur with normal behaviour.
 *
 * The data for each packet will be found at an offset into the buffer that
 * can be calculated as if each prior packet completed in full. FIXME write
 * a helper function to determine this, and flesh this description out a bit
 * more.
 *
 * \section asyncmem Memory caveats
 *
 * In most circumstances, it is not safe to use stack memory for transfer
 * buffers. This is because the function that fired off the asynchronous
 * transfer may return before libusb has finished using the buffer, and when
 * the function returns it's stack gets destroyed. This is true for both
 * host-to-device and device-to-host transfers.
 *
 * The only case in which it is safe to use stack memory is where you can
 * guarantee that the function owning the stack space for the buffer does not
 * return until after the transfer's callback function has completed. In every
 * other case, you need to use heap memory instead.
 *
 * \section asyncflags Fine control
 *
 * Through using this asynchronous interface, you may find yourself repeating
 * a few simple operations many times. You can apply a bitwise OR of certain
 * flags to a transfer to simplify certain things:
 * - \ref libusb_transfer_flags::LIBUSB_TRANSFER_SHORT_NOT_OK
 *   "LIBUSB_TRANSFER_SHORT_NOT_OK" results in transfers which transferred
 *   less than the requested amount of data being marked with status
 *   \ref libusb_transfer_status::LIBUSB_TRANSFER_ERROR "LIBUSB_TRANSFER_ERROR"
 *   (they would normally be regarded as COMPLETED)
 * - \ref libusb_transfer_flags::LIBUSB_TRANSFER_FREE_BUFFER
 *   "LIBUSB_TRANSFER_FREE_BUFFER" allows you to ask libusb to free the transfer
 *   buffer when freeing the transfer.
 * - \ref libusb_transfer_flags::LIBUSB_TRANSFER_FREE_TRANSFER
 *   "LIBUSB_TRANSFER_FREE_TRANSFER" causes libusb to automatically free the
 *   transfer after the transfer callback returns.
 *
 * \section asyncevent Event handling
 *
 * In accordance of the aim of being a lightweight library, libusb does not
 * create threads internally. This means that libusb code does not execute
 * at any time other than when your application is calling a libusb function.
 * However, an asynchronous model requires that libusb perform work at various
 * points in time - namely processing the results of previously-submitted
 * transfers and invoking the user-supplied callback function.
 *
 * This gives rise to the libusb_handle_events() function which your
 * application must call into when libusb has work do to. This gives libusb
 * the opportunity to reap pending transfers, invoke callbacks, etc.
 *
 * The first issue to discuss here is how your application can figure out
 * when libusb has work to do. In fact, there are two naive options which
 * do not actually require your application to know this:
 * -# Periodically call libusb_handle_events() in non-blocking mode at fixed
 *    short intervals from your main loop
 * -# Repeatedly call libusb_handle_events() in blocking mode from a dedicated
 *    thread.
 *
 * The first option is plainly not very nice, and will cause unnecessary 
 * CPU wakeups leading to increased power usage and decreased battery life.
 * The second option is not very nice either, but may be the nicest option
 * available to you if the "proper" approach can not be applied to your
 * application (read on...).
 * 
 * The recommended option is to integrate libusb with your application main
 * event loop. libusb exposes a set of file descriptors which allow you to do
 * this. Your main loop is probably already calling poll() or select() or a
 * variant on a set of file descriptors for other event sources (e.g. keyboard
 * button presses, mouse movements, network sockets, etc). You then add
 * libusb's file descriptors to your poll()/select() calls, and when activity
 * is detected on such descriptors you know it is time to call
 * libusb_handle_events().
 *
 * There is one final event handling complication. libusb supports
 * asynchronous transfers which time out after a specified time period, and
 * this requires that libusb is called into at or after the timeout so that
 * the timeout can be handled. So, in addition to considering libusb's file
 * descriptors in your main event loop, you must also consider that libusb
 * sometimes needs to be called into at fixed points in time even when there
 * is no file descriptor activity.
 *
 * For the details on retrieving the set of file descriptors and determining
 * the next timeout, see the \ref poll "polling and timing" API documentation.
 */

/**
 * @defgroup poll Polling and timing
 *
 * This page documents libusb's functions for polling events and timing.
 * These functions are only necessary for users of the
 * \ref asyncio "asynchronous API". If you are only using the simpler
 * \ref syncio "synchronous API" then you do not need to ever call these
 * functions.
 *
 * The justification for the functionality described here has already been
 * discussed in the \ref asyncevent "event handling" section of the
 * asynchronous API documentation. In summary, libusb does not create internal
 * threads for event processing and hence relies on your application calling
 * into libusb at certain points in time so that pending events can be handled.
 * In order to know precisely when libusb needs to be called into, libusb
 * offers you a set of pollable file descriptors and information about when
 * the next timeout expires.
 *
 * If you are using the asynchronous I/O API, you must take one of the two
 * following options, otherwise your I/O will not complete.
 *
 * \section pollsimple The simple option
 *
 * If your application revolves solely around libusb and does not need to
 * handle other event sources, you can have a program structure as follows:
\code
// initialize libusb
// find and open device
// maybe fire off some initial async I/O

while (user_has_not_requested_exit)
	libusb_handle_events();

// clean up and exit
\endcode
 *
 * With such a simple main loop, you do not have to worry about managing
 * sets of file descriptors or handling timeouts. libusb_handle_events() will
 * handle those details internally.
 *
 * \section pollmain The more advanced option
 *
 * In more advanced applications, you will already have a main loop which
 * is monitoring other event sources: network sockets, X11 events, mouse
 * movements, etc. Through exposing a set of file descriptors, libusb is
 * designed to cleanly integrate into such main loops.
 *
 * In addition to polling file descriptors for the other event sources, you
 * take a set of file descriptors from libusb and monitor those too. When you
 * detect activity on libusb's file descriptors, you call
 * libusb_handle_events_timeout() in non-blocking mode.
 *
 * You must also consider the fact that libusb sometimes has to handle events
 * at certain known times which do not generate activity on file descriptors.
 * Your main loop must also consider these times, modify it's poll()/select()
 * timeout accordingly, and track time so that libusb_handle_events_timeout()
 * is called in non-blocking mode when timeouts expire.
 *
 * In pseudo-code, you want something that looks like:
\code
// initialise libusb

libusb_get_pollfds()
while (user has not requested application exit) {
	libusb_get_next_timeout();
	select(on libusb file descriptors plus any other event sources of interest,
		using a timeout no larger than the value libusb just suggested)
	if (select() indicated activity on libusb file descriptors)
		libusb_handle_events_timeout(0);
	if (time has elapsed to or beyond the libusb timeout)
		libusb_handle_events_timeout(0);
}

// clean up and exit
\endcode
 *
 * The set of file descriptors that libusb uses as event sources may change
 * during the life of your application. Rather than having to repeatedly
 * call libusb_get_pollfds(), you can set up notification functions for when
 * the file descriptor set changes using libusb_set_pollfd_notifiers().
 *
 */

void usbi_io_init()
{
	list_init(&flying_transfers);
	list_init(&pollfds);
	fd_added_cb = NULL;
	fd_removed_cb = NULL;
}

static int calculate_timeout(struct usbi_transfer *transfer)
{
	int r;
	struct timespec current_time;
	unsigned int timeout =
		__USBI_TRANSFER_TO_LIBUSB_TRANSFER(transfer)->timeout;

	if (!timeout)
		return 0;

	r = clock_gettime(CLOCK_MONOTONIC, &current_time);
	if (r < 0) {
		usbi_err("failed to read monotonic clock, errno=%d", errno);
		return r;
	}

	current_time.tv_sec += timeout / 1000;
	current_time.tv_nsec += (timeout % 1000) * 1000000;

	if (current_time.tv_nsec > 1000000000) {
		current_time.tv_nsec -= 1000000000;
		current_time.tv_sec++;
	}

	TIMESPEC_TO_TIMEVAL(&transfer->timeout, &current_time);
	return 0;
}

static void add_to_flying_list(struct usbi_transfer *transfer)
{
	struct usbi_transfer *cur;
	struct timeval *timeout = &transfer->timeout;
	
	pthread_mutex_lock(&flying_transfers_lock);

	/* if we have no other flying transfers, start the list with this one */
	if (list_empty(&flying_transfers)) {
		list_add(&transfer->list, &flying_transfers);
		goto out;
	}

	/* if we have infinite timeout, append to end of list */
	if (!timerisset(timeout)) {
		list_add_tail(&transfer->list, &flying_transfers);
		goto out;
	}

	/* otherwise, find appropriate place in list */
	list_for_each_entry(cur, &flying_transfers, list) {
		/* find first timeout that occurs after the transfer in question */
		struct timeval *cur_tv = &cur->timeout;

		if (!timerisset(cur_tv) || (cur_tv->tv_sec > timeout->tv_sec) ||
				(cur_tv->tv_sec == timeout->tv_sec &&
					cur_tv->tv_usec > timeout->tv_usec)) {
			list_add_tail(&transfer->list, &cur->list);
			goto out;
		}
	}

	/* otherwise we need to be inserted at the end */
	list_add_tail(&transfer->list, &flying_transfers);
out:
	pthread_mutex_unlock(&flying_transfers_lock);
}

static int submit_transfer(struct usbi_transfer *itransfer)
{
	int r;
	
	add_to_flying_list(itransfer);
	r = usbi_backend->submit_transfer(itransfer);
	if (r < 0) {
		pthread_mutex_lock(&flying_transfers_lock);
		list_del(&itransfer->list);
		pthread_mutex_unlock(&flying_transfers_lock);
	}

	return r;
}

/** \ingroup asyncio
 * Allocate a libusb transfer with a specified number of isochronous packet
 * descriptors. The returned transfer is pre-initialized for you. When the new
 * transfer is no longer needed, it should be freed with
 * libusb_free_transfer().
 *
 * Transfers intended for non-isochronous endpoints (e.g. control, bulk,
 * interrupt) should specify an iso_packets count of zero.
 *
 * For transfers intended for isochronous endpoints, specify an appropriate
 * number of packet descriptors to be allocated as part of the transfer.
 * The returned transfer is not specially initialized for isochronous I/O;
 * you are still required to set the
 * \ref libusb_transfer::num_iso_packets "num_iso_packets" and
 * \ref libusb_transfer::endpoint_type "endpoint_type" fields accordingly.
 *
 * It is safe to allocate a transfer with some isochronous packets and then
 * use it on a non-isochronous endpoint. If you do this, ensure that at time
 * of submission, num_iso_packets is 0 and that endpoint_type is set
 * appropriately.
 *
 * \param iso_packets number of isochronous packet descriptors to allocate
 * \returns a newly allocated transfer, or NULL on error
 */
API_EXPORTED struct libusb_transfer *libusb_alloc_transfer(int iso_packets)
{
	size_t os_alloc_size = usbi_backend->transfer_priv_size
		+ (usbi_backend->add_iso_packet_size * iso_packets);
	int alloc_size = sizeof(struct usbi_transfer)
		+ sizeof(struct libusb_transfer)
		+ (sizeof(struct libusb_iso_packet_descriptor) * iso_packets)
		+ os_alloc_size;
	struct usbi_transfer *itransfer = malloc(alloc_size);
	if (!itransfer)
		return NULL;

	memset(itransfer, 0, alloc_size);
	itransfer->num_iso_packets = iso_packets;
	return __USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
}

/** \ingroup asyncio
 * Free a transfer structure. This should be called for all transfers
 * allocated with libusb_alloc_transfer().
 *
 * If the \ref libusb_transfer_flags::LIBUSB_TRANSFER_FREE_BUFFER
 * "LIBUSB_TRANSFER_FREE_BUFFER" flag is set and the transfer buffer is
 * non-NULL, this function will also free the transfer buffer using the
 * standard system memory allocator (e.g. free()).
 *
 * It is legal to call this function with a NULL transfer. In this case,
 * the function will simply return safely.
 *
 * \param transfer the transfer to free
 */
API_EXPORTED void libusb_free_transfer(struct libusb_transfer *transfer)
{
	struct usbi_transfer *itransfer;
	if (!transfer)
		return;

	if (transfer->flags & LIBUSB_TRANSFER_FREE_BUFFER && transfer->buffer)
		free(transfer->buffer);

	itransfer = __LIBUSB_TRANSFER_TO_USBI_TRANSFER(transfer);
	free(itransfer);
}

/** \ingroup asyncio
 * Submit a transfer. This function will fire off the USB transfer and then
 * return immediately.
 *
 * It is undefined behaviour to submit a transfer that has already been
 * submitted but has not yet completed.
 *
 * \param transfer the transfer to submit
 * \returns 0 on success
 * \returns negative on error
 */
API_EXPORTED int libusb_submit_transfer(struct libusb_transfer *transfer)
{
	struct usbi_transfer *itransfer =
		__LIBUSB_TRANSFER_TO_USBI_TRANSFER(transfer);
	int r;

	itransfer->transferred = 0;
	r = calculate_timeout(itransfer);
	if (r < 0)
		return r;

	if (transfer->endpoint_type == LIBUSB_ENDPOINT_TYPE_CONTROL) {
		struct libusb_control_setup *setup =
			(struct libusb_control_setup *) transfer->buffer;
	
		usbi_dbg("RQT=%02x RQ=%02x VAL=%04x IDX=%04x length=%d",
			setup->bmRequestType, setup->bRequest, setup->wValue, setup->wIndex,
			setup->wLength);

		setup->wValue = cpu_to_le16(setup->wValue);
		setup->wIndex = cpu_to_le16(setup->wIndex);
		setup->wLength = cpu_to_le16(setup->wLength);
	}

	return submit_transfer(itransfer);
}

/** \ingroup asyncio
 * Asynchronously cancel a previously submitted transfer.
 * It is undefined behaviour to call this function on a transfer that is
 * already being cancelled or has already completed.
 * This function returns immediately, but this does not indicate cancellation
 * is complete. Your callback function will be invoked at some later time
 * with a transfer status of
 * \ref libusb_transfer_status::LIBUSB_TRANSFER_CANCELLED
 * "LIBUSB_TRANSFER_CANCELLED."
 *
 * \param transfer the transfer to cancel
 * \returns 0 on success
 * \returns non-zero on error
 */
API_EXPORTED int libusb_cancel_transfer(struct libusb_transfer *transfer)
{
	struct usbi_transfer *itransfer =
		__LIBUSB_TRANSFER_TO_USBI_TRANSFER(transfer);
	int r;

	usbi_dbg("");
	r = usbi_backend->cancel_transfer(itransfer);
	if (r < 0)
		usbi_err("cancel transfer failed error %d", r);
	return r;
}

void usbi_handle_transfer_completion(struct usbi_transfer *itransfer,
	enum libusb_transfer_status status)
{
	struct libusb_transfer *transfer =
		__USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	uint8_t flags;

	pthread_mutex_lock(&flying_transfers_lock);
	list_del(&itransfer->list);
	pthread_mutex_unlock(&flying_transfers_lock);

	if (status == LIBUSB_TRANSFER_COMPLETED
			&& transfer->flags & LIBUSB_TRANSFER_SHORT_NOT_OK) {
		int rqlen = transfer->length;
		if (transfer->endpoint_type == LIBUSB_ENDPOINT_TYPE_CONTROL)
			rqlen -= LIBUSB_CONTROL_SETUP_SIZE;
		if (rqlen != itransfer->transferred) {
			usbi_dbg("interpreting short transfer as error");
			status = LIBUSB_TRANSFER_ERROR;
		}
	}

	flags = transfer->flags;
	transfer->status = status;
	transfer->actual_length = itransfer->transferred;
	if (transfer->callback)
		transfer->callback(transfer);
	/* transfer might have been freed by the above call, do not use from
	 * this point. */
	if (flags & LIBUSB_TRANSFER_FREE_TRANSFER)
		libusb_free_transfer(transfer);
}

void usbi_handle_transfer_cancellation(struct usbi_transfer *transfer)
{
	/* if the URB was cancelled due to timeout, report timeout to the user */
	if (transfer->flags & USBI_TRANSFER_TIMED_OUT) {
		usbi_dbg("detected timeout cancellation");
		usbi_handle_transfer_completion(transfer, LIBUSB_TRANSFER_TIMED_OUT);
		return;
	}

	/* otherwise its a normal async cancel */
	usbi_handle_transfer_completion(transfer, LIBUSB_TRANSFER_CANCELLED);
}

static void handle_timeout(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer =
		__USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	int r;

	itransfer->flags |= USBI_TRANSFER_TIMED_OUT;
	r = libusb_cancel_transfer(transfer);
	if (r < 0)
		usbi_warn("async cancel failed %d errno=%d", r, errno);
}

static int handle_timeouts(void)
{
	struct timespec systime_ts;
	struct timeval systime;
	struct usbi_transfer *transfer;
	int r = 0;

	pthread_mutex_lock(&flying_transfers_lock);
	if (list_empty(&flying_transfers))
		goto out;

	/* get current time */
	r = clock_gettime(CLOCK_MONOTONIC, &systime_ts);
	if (r < 0)
		goto out;

	TIMESPEC_TO_TIMEVAL(&systime, &systime_ts);

	/* iterate through flying transfers list, finding all transfers that
	 * have expired timeouts */
	list_for_each_entry(transfer, &flying_transfers, list) {
		struct timeval *cur_tv = &transfer->timeout;

		/* if we've reached transfers of infinite timeout, we're all done */
		if (!timerisset(cur_tv))
			goto out;

		/* ignore timeouts we've already handled */
		if (transfer->flags & USBI_TRANSFER_TIMED_OUT)
			continue;

		/* if transfer has non-expired timeout, nothing more to do */
		if ((cur_tv->tv_sec > systime.tv_sec) ||
				(cur_tv->tv_sec == systime.tv_sec &&
					cur_tv->tv_usec > systime.tv_usec))
			goto out;
	
		/* otherwise, we've got an expired timeout to handle */
		handle_timeout(transfer);
	}

out:
	pthread_mutex_unlock(&flying_transfers_lock);
	return r;
}

static int handle_events(struct timeval *tv)
{
	int r;
	int maxfd = 0;
	fd_set readfds, writefds;
	fd_set *_readfds = NULL;
	fd_set *_writefds = NULL;
	struct usbi_pollfd *ipollfd;
	int have_readfds = 0;
	int have_writefds = 0;
	struct timeval select_timeout;
	struct timeval timeout;

	r = libusb_get_next_timeout(&timeout);
	if (r) {
		/* timeout already expired? */
		if (!timerisset(&timeout))
			return handle_timeouts();

		/* choose the smallest of next URB timeout or user specified timeout */
		if (timercmp(&timeout, tv, <))
			select_timeout = timeout;
		else
			select_timeout = *tv;
	} else {
		select_timeout = *tv;
	}

	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	pthread_mutex_lock(&pollfds_lock);
	list_for_each_entry(ipollfd, &pollfds, list) {
		struct libusb_pollfd *pollfd = &ipollfd->pollfd;
		int fd = pollfd->fd;
		if (pollfd->events & POLLIN) {
			have_readfds = 1;
			FD_SET(fd, &readfds);
		}
		if (pollfd->events & POLLOUT) {
			have_writefds = 1;
			FD_SET(fd, &writefds);
		}
		if (fd > maxfd)
			maxfd = fd;
	}
	pthread_mutex_unlock(&pollfds_lock);

	if (have_readfds)
		_readfds = &readfds;
	if (have_writefds)
		_writefds = &writefds;

	usbi_dbg("select() with timeout in %d.%06ds", select_timeout.tv_sec,
		select_timeout.tv_usec);
	r = select(maxfd + 1, _readfds, _writefds, NULL, &select_timeout);
	usbi_dbg("select() returned %d with %d.%06ds remaining",
		r, select_timeout.tv_sec, select_timeout.tv_usec);
	if (r == 0) {
		*tv = select_timeout;
		return handle_timeouts();
	} else if (r == -1 && errno == EINTR) {
		return 0;
	} else if (r < 0) {
		usbi_err("select failed %d err=%d\n", r, errno);
		return r;
	}

	r = usbi_backend->handle_events(_readfds, _writefds);
	if (r)
		usbi_err("backend handle_events failed with error %d", r);

	return r;
}

/** \ingroup poll
 * Handle any pending events.
 *
 * libusb determines "pending events" by checking if any timeouts have expired
 * and by checking the set of file descriptors for activity.
 *
 * If a zero timeval is passed, this function will handle any already-pending
 * events and then immediately return in non-blocking style.
 *
 * If a non-zero timeval is passed and no events are currently pending, this
 * function will block waiting for events to handle up until the specified
 * timeout. If an event arrives or a signal is raised, this function will
 * return early.
 *
 * \param tv the maximum time to block waiting for events, or zero for
 * non-blocking mode
 * \returns 0 on success
 * \returns non-zero on error
 */
API_EXPORTED int libusb_handle_events_timeout(struct timeval *tv)
{
	return handle_events(tv);
}

/** \ingroup poll
 * Handle any pending events in blocking mode with a sensible timeout. This
 * timeout is currently hardcoded at 2 seconds but we may change this if we
 * decide other values are more sensible. For finer control over whether this
 * function is blocking or non-blocking, or the maximum timeout, use
 * libusb_handle_events_timeout() instead.
 *
 * \returns 0 on success
 * \returns non-zero on error
 */
API_EXPORTED int libusb_handle_events(void)
{
	struct timeval tv;
	tv.tv_sec = 2;
	tv.tv_usec = 0;
	return handle_events(&tv);
}

/** \ingroup poll
 * Determine the next internal timeout that libusb needs to handle. You only
 * need to use this function if you are calling poll() or select() or similar
 * on libusb's file descriptors yourself - you do not need to use it if you
 * are calling libusb_handle_events() or a variant directly.
 * 
 * You should call this function in your main loop in order to determine how
 * long to wait for select() or poll() to return results. libusb needs to be
 * called into at this timeout, so you should use it as an upper bound on
 * your select() or poll() call.
 *
 * When the timeout has expired, call into libusb_handle_events_timeout()
 * (perhaps in non-blocking mode) so that libusb can handle the timeout.
 *
 * This function may return 0 (success) and an all-zero timeval. If this is
 * the case, it indicates that libusb has a timeout that has already expired
 * so you should call libusb_handle_events_timeout() or similar immediately.
 *
 * \param tv output location for a relative time against the current
 * clock in which libusb must be called into in order to process timeout events
 * \returns 0 on success
 * \returns non-zero on error
 */
API_EXPORTED int libusb_get_next_timeout(struct timeval *tv)
{
	struct usbi_transfer *transfer;
	struct timespec cur_ts;
	struct timeval cur_tv;
	struct timeval *next_timeout;
	int r;
	int found = 0;

	pthread_mutex_lock(&flying_transfers_lock);
	if (list_empty(&flying_transfers)) {
		pthread_mutex_unlock(&flying_transfers_lock);
		usbi_dbg("no URBs, no timeout!");
		return 0;
	}

	/* find next transfer which hasn't already been processed as timed out */
	list_for_each_entry(transfer, &flying_transfers, list) {
		if (!(transfer->flags & USBI_TRANSFER_TIMED_OUT)) {
			found = 1;
			break;
		}
	}
	pthread_mutex_unlock(&flying_transfers_lock);

	if (!found) {
		usbi_dbg("all URBs have already been processed for timeouts");
		return 0;
	}

	next_timeout = &transfer->timeout;

	/* no timeout for next transfer */
	if (!timerisset(next_timeout)) {
		usbi_dbg("no URBs with timeouts, no timeout!");
		return 0;
	}

	r = clock_gettime(CLOCK_MONOTONIC, &cur_ts);
	if (r < 0) {
		usbi_err("failed to read monotonic clock, errno=%d", errno);
		return r;
	}
	TIMESPEC_TO_TIMEVAL(&cur_tv, &cur_ts);

	if (timercmp(&cur_tv, next_timeout, >=)) {
		usbi_dbg("first timeout already expired");
		timerclear(tv);
	} else {
		timersub(next_timeout, &cur_tv, tv);
		usbi_dbg("next timeout in %d.%06ds", tv->tv_sec, tv->tv_usec);
	}

	return 1;
}

/** \ingroup poll
 * Register notification functions for file descriptor additions/removals.
 * These functions will be invoked for every new or removed file descriptor
 * that libusb uses as an event source.
 *
 * To remove notifiers, pass NULL values for the function pointers.
 *
 * \param added_cb pointer to function for addition notifications
 * \param removed_cb pointer to function for removal notifications
 */
API_EXPORTED void libusb_set_pollfd_notifiers(libusb_pollfd_added_cb added_cb,
	libusb_pollfd_removed_cb removed_cb)
{
	fd_added_cb = added_cb;
	fd_removed_cb = removed_cb;
}

int usbi_add_pollfd(int fd, short events)
{
	struct usbi_pollfd *ipollfd = malloc(sizeof(*ipollfd));
	if (!ipollfd)
		return -ENOMEM;

	usbi_dbg("add fd %d events %d", fd, events);
	ipollfd->pollfd.fd = fd;
	ipollfd->pollfd.events = events;
	pthread_mutex_lock(&pollfds_lock);
	list_add(&ipollfd->list, &pollfds);
	pthread_mutex_unlock(&pollfds_lock);

	if (fd_added_cb)
		fd_added_cb(fd, events);
	return 0;
}

void usbi_remove_pollfd(int fd)
{
	struct usbi_pollfd *ipollfd;
	int found = 0;

	usbi_dbg("remove fd %d", fd);
	pthread_mutex_lock(&pollfds_lock);
	list_for_each_entry(ipollfd, &pollfds, list)
		if (ipollfd->pollfd.fd == fd) {
			found = 1;
			break;
		}

	if (!found) {
		usbi_err("couldn't find fd %d to remove", fd);
		pthread_mutex_unlock(&pollfds_lock);
		return;
	}

	list_del(&ipollfd->list);
	pthread_mutex_unlock(&pollfds_lock);
	free(ipollfd);
	if (fd_removed_cb)
		fd_removed_cb(fd);
}

/** \ingroup poll
 * Retrieve a list of file descriptors that should be polled by your main loop
 * as libusb event sources.
 *
 * The returned list is NULL-terminated and should be freed with free() when
 * done. The actual list contents must not be touched.
 *
 * \returns a NULL-terminated list of libusb_pollfd structures, or NULL on
 * error
 */
API_EXPORTED const struct libusb_pollfd **libusb_get_pollfds(void)
{
	struct libusb_pollfd **ret = NULL;
	struct usbi_pollfd *ipollfd;
	size_t i = 0;
	size_t cnt = 0;

	pthread_mutex_lock(&pollfds_lock);
	list_for_each_entry(ipollfd, &pollfds, list)
		cnt++;

	ret = calloc(cnt + 1, sizeof(struct libusb_pollfd *));
	if (!ret)
		goto out;

	list_for_each_entry(ipollfd, &pollfds, list)
		ret[i++] = (struct libusb_pollfd *) ipollfd;
	ret[cnt] = NULL;

out:
	pthread_mutex_unlock(&pollfds_lock);
	return (const struct libusb_pollfd **) ret;
}

