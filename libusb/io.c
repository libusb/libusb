/*
 * I/O functions for libusb
 * Copyright (C) 2007 Daniel Drake <dsd@gentoo.org>
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
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "libusbi.h"

/* this is a list of in-flight rb_handles, sorted by timeout expiration.
 * URBs to timeout the soonest are placed at the beginning of the list, URBs
 * that will time out later are placed after, and urbs with infinite timeout
 * are always placed at the very end. */
static struct list_head flying_urbs;

void usbi_io_init()
{
	list_init(&flying_urbs);
}

static int calculate_timeout(struct libusb_urb_handle *urbh,
	unsigned int timeout)
{
	int r;
	struct timespec current_time;

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

	TIMESPEC_TO_TIMEVAL(&urbh->timeout, &current_time);
	return 0;
}

static void add_to_flying_list(struct libusb_urb_handle *urbh)
{
	struct libusb_urb_handle *cur;
	struct timeval *timeout = &urbh->timeout;

	/* if we have no other flying urbs, start the list with this one */
	if (list_empty(&flying_urbs)) {
		list_add(&urbh->list, &flying_urbs);
		return;
	}

	/* if we have infinite timeout, append to end of list */
	if (!timerisset(timeout)) {
		list_add_tail(&urbh->list, &flying_urbs);
		return;
	}

	/* otherwise, find appropriate place in list */
	list_for_each_entry(cur, &flying_urbs, list) {
		/* find first timeout that occurs after the urbh in question */
		struct timeval *cur_tv = &cur->timeout;

		if (!timerisset(cur_tv) || (cur_tv->tv_sec > timeout->tv_sec) ||
				(cur_tv->tv_sec == timeout->tv_sec &&
					cur_tv->tv_usec > timeout->tv_usec)) {
			list_add_tail(&urbh->list, &cur->list);
			return;
		}
	}

	/* otherwise we need to be inserted at the end */
	list_add_tail(&urbh->list, &flying_urbs);
}

static int submit_urb(struct libusb_dev_handle *devh,
	struct libusb_urb_handle *urbh)
{
	int r;
	struct usb_urb *urb = &urbh->urb;
	int to_be_transferred = urbh->transfer_len - urbh->transferred;

	urb->type = urbh->urb_type;
	urb->endpoint = urbh->endpoint;
	urb->buffer = urbh->buffer + urbh->transferred;
	urb->buffer_length = MIN(to_be_transferred, MAX_URB_BUFFER_LENGTH);

	/* FIXME: for requests that we have to split into multiple URBs, we should
	 * submit all the URBs instantly: submit, submit, submit, reap, reap, reap
	 * rather than: submit, reap, submit, reap, submit, reap
	 * this will improve performance and fix bugs concerning behaviour when
	 * the user submits two similar multiple-urb requests */
	usbi_dbg("transferring %d from %d bytes", urb->buffer_length,
		to_be_transferred);

	r = ioctl(devh->fd, IOCTL_USB_SUBMITURB, &urbh->urb);
	if (r < 0) {
		usbi_err("submiturb failed error %d errno=%d", r, errno);
		return r;
	}

	add_to_flying_list(urbh);
	return 0;
}

API_EXPORTED struct libusb_urb_handle *libusb_async_control_transfer(
	struct libusb_dev_handle *devh, struct libusb_control_transfer *transfer,
	libusb_ctrl_cb_fn callback, void *user_data, unsigned int timeout)
{
	struct libusb_urb_handle *urbh = malloc(sizeof(*urbh));
	struct libusb_ctrl_setup *setup;
	unsigned char *urbdata;
	int urbdata_length = sizeof(struct libusb_ctrl_setup) + transfer->length;
	int r;

	if (!urbh)
		return NULL;
	memset(urbh, 0, sizeof(*urbh));
	urbh->devh = devh;
	urbh->callback = callback;
	urbh->user_data = user_data;
	r = calculate_timeout(urbh, timeout);
	if (r < 0) {
		free(urbh);
		return NULL;
	}

	urbdata = malloc(urbdata_length);
	if (!urbdata) {
		free(urbh);
		return NULL;
	}

	usbi_dbg("RQT=%02x RQ=%02x VAL=%04x IDX=%04x length=%d",
		transfer->requesttype, transfer->request, transfer->value,
		transfer->index, transfer->length);

	setup = (struct libusb_ctrl_setup *) urbdata;
	setup->bRequestType = transfer->requesttype;
	setup->bRequest = transfer->request;
	setup->wValue = cpu_to_le16(transfer->value);
	setup->wIndex = cpu_to_le16(transfer->index);
	setup->wLength = cpu_to_le16(transfer->length);

	if ((transfer->requesttype & 0x80) == LIBUSB_ENDPOINT_OUT)
		memcpy(urbdata + sizeof(struct libusb_ctrl_setup), transfer->data,
		transfer->length);

	urbh->urb_type = USB_URB_TYPE_CONTROL;
	urbh->buffer = urbdata;
	urbh->transfer_len = urbdata_length;

	r = submit_urb(devh, urbh);
	if (r < 0) {
		free(urbh);
		free(urbdata);
		return NULL;
	}

	return urbh;
}

static struct libusb_urb_handle *submit_bulk_transfer(
	struct libusb_dev_handle *devh, struct libusb_bulk_transfer *transfer,
	libusb_bulk_cb_fn callback, void *user_data, unsigned int timeout,
	unsigned char urbtype)
{
	struct libusb_urb_handle *urbh = malloc(sizeof(*urbh));
	int r;

	usbi_dbg("length %d timeout %d", transfer->length, timeout);

	if (!urbh)
		return NULL;
	memset(urbh, 0, sizeof(*urbh));
	r = calculate_timeout(urbh, timeout);
	if (r < 0) {
		free(urbh);
		return NULL;
	}
	urbh->devh = devh;
	urbh->callback = callback;
	urbh->user_data = user_data;
	urbh->flags |= LIBUSB_URBH_DATA_BELONGS_TO_USER;
	urbh->endpoint = transfer->endpoint;
	urbh->urb_type = urbtype;
	urbh->buffer = transfer->data;
	urbh->transfer_len = transfer->length;

	r = submit_urb(devh, urbh);
	if (r < 0) {
		free(urbh);
		return NULL;
	}

	return urbh;
}

API_EXPORTED struct libusb_urb_handle *libusb_async_bulk_transfer(
	struct libusb_dev_handle *devh, struct libusb_bulk_transfer *transfer,
	libusb_bulk_cb_fn callback, void *user_data, unsigned int timeout)
{
	return submit_bulk_transfer(devh, transfer, callback, user_data, timeout,
		USB_URB_TYPE_BULK);
}

API_EXPORTED struct libusb_urb_handle *libusb_async_interrupt_transfer(
	struct libusb_dev_handle *devh, struct libusb_bulk_transfer *transfer,
	libusb_bulk_cb_fn callback, void *user_data, unsigned int timeout)
{
	return submit_bulk_transfer(devh, transfer, callback, user_data, timeout,
		USB_URB_TYPE_INTERRUPT);
}

API_EXPORTED int libusb_urb_handle_cancel(struct libusb_dev_handle *devh,
	struct libusb_urb_handle *urbh)
{
	int r;
	usbi_dbg("");
	r = ioctl(devh->fd, IOCTL_USB_DISCARDURB, &urbh->urb);
	if (r < 0)
		usbi_err("cancel urb failed error %d", r);
	return r;
}

API_EXPORTED int libusb_urb_handle_cancel_sync(struct libusb_dev_handle *devh,
	struct libusb_urb_handle *urbh)
{
	int r;
	usbi_dbg("");
	r = ioctl(devh->fd, IOCTL_USB_DISCARDURB, &urbh->urb);
	if (r < 0) {
		usbi_err("cancel urb failed error %d", r);
		return r;
	}

	urbh->flags |= LIBUSB_URBH_SYNC_CANCELLED;
	while (urbh->flags & LIBUSB_URBH_SYNC_CANCELLED) {
		r = libusb_poll();
		if (r < 0)
			return r;
	}

	return 0;
}

int handle_transfer_completion(struct libusb_dev_handle *devh,
	struct libusb_urb_handle *urbh, enum libusb_urb_cb_status status)
{
	struct usb_urb *urb = &urbh->urb;

	if (status == FP_URB_SILENT_COMPLETION)
		return 0;

	if (urb->type == USB_URB_TYPE_CONTROL) {
		libusb_ctrl_cb_fn callback = urbh->callback;
		if (callback)
			callback(devh, urbh, status, urb->buffer,
				urb->buffer + sizeof(struct libusb_ctrl_setup), urbh->transferred,
				urbh->user_data);
	} else if (urb->type == USB_URB_TYPE_BULK ||
			urb->type == USB_URB_TYPE_INTERRUPT) {
		libusb_bulk_cb_fn callback = urbh->callback;
		if (callback)
			callback(devh, urbh, status, urbh->endpoint, urbh->transfer_len,
				urbh->buffer, urbh->transferred, urbh->user_data);
	}
	return 0;
}

static int handle_transfer_cancellation(struct libusb_dev_handle *devh,
	struct libusb_urb_handle *urbh)
{
	/* if the URB is being cancelled synchronously, raise cancellation
	 * completion event by unsetting flag, and ensure that user callback does
	 * not get called.
	 */
	if (urbh->flags & LIBUSB_URBH_SYNC_CANCELLED) {
		urbh->flags &= ~LIBUSB_URBH_SYNC_CANCELLED;
		usbi_dbg("detected sync. cancel");
		return handle_transfer_completion(devh, urbh, FP_URB_SILENT_COMPLETION);
	}

	/* if the URB was cancelled due to timeout, report timeout to the user */
	if (urbh->flags & LIBUSB_URBH_TIMED_OUT) {
		usbi_dbg("detected timeout cancellation");
		return handle_transfer_completion(devh, urbh, FP_URB_TIMEOUT);
	}

	/* otherwise its a normal async cancel */
	return handle_transfer_completion(devh, urbh, FP_URB_CANCELLED);
}

static int reap_for_devh(struct libusb_dev_handle *devh)
{
	int r;
	struct usb_urb *urb;
	struct libusb_urb_handle *urbh;
	int trf_requested;

	r = ioctl(devh->fd, IOCTL_USB_REAPURBNDELAY, &urb);
	if (r == -1 && errno == EAGAIN)
		return r;
	if (r < 0) {
		usbi_err("reap failed error %d errno=%d", r, errno);
		return r;
	}

	urbh = container_of(urb, struct libusb_urb_handle, urb);

	usbi_dbg("urb type=%d status=%d transferred=%d", urb->type, urb->status,
		urb->actual_length);
	list_del(&urbh->list);

	if (urb->status == -2)
		return handle_transfer_cancellation(devh, urbh);
	/* FIXME: research what other status codes may exist */
	if (urb->status != 0)
		usbi_warn("unrecognised urb status %d", urb->status);

	/* determine how much data was asked for */
	trf_requested = MIN(urbh->transfer_len - urbh->transferred,
		MAX_URB_BUFFER_LENGTH);

	urbh->transferred += urb->actual_length;	

	/* if we were provided less data than requested, then our transfer is
	 * done */
	if (urb->actual_length < trf_requested) {
		usbi_dbg("less data than requested (%d/%d) --> all done",
			urb->actual_length, trf_requested);
		return handle_transfer_completion(devh, urbh, FP_URB_COMPLETED);
	}

	/* if we've transferred all data, we're done */
	if (urbh->transferred == urbh->transfer_len) {
		usbi_dbg("transfer complete --> all done");
		return handle_transfer_completion(devh, urbh, FP_URB_COMPLETED);
	}

	/* otherwise, we have more data to transfer */
	usbi_dbg("more data to transfer...");
	memset(urb, 0, sizeof(*urb));
	return submit_urb(devh, urbh);
}

static void handle_timeout(struct libusb_urb_handle *urbh)
{
	/* handling timeouts is tricky, as we may race with the kernel: we may
	 * detect a timeout racing with the condition that the urb has actually
	 * completed. we asynchronously cancel the URB and report timeout
	 * to the user when the URB cancellation completes (or not at all if the
	 * URB actually gets delivered as per this race) */
	int r;


	urbh->flags |= LIBUSB_URBH_TIMED_OUT;
	r = libusb_urb_handle_cancel(urbh->devh, urbh);
	if (r < 0)
		usbi_warn("async cancel failed %d errno=%d", r, errno);
}

static int handle_timeouts(void)
{
	struct timespec systime_ts;
	struct timeval systime;
	struct libusb_urb_handle *urbh;
	int r;

	if (list_empty(&flying_urbs))
		return 0;

	/* get current time */
	r = clock_gettime(CLOCK_MONOTONIC, &systime_ts);
	if (r < 0)
		return r;

	TIMESPEC_TO_TIMEVAL(&systime, &systime_ts);

	/* iterate through flying urbs list, finding all urbs that have expired
	 * timeouts */
	list_for_each_entry(urbh, &flying_urbs, list) {
		struct timeval *cur_tv = &urbh->timeout;

		/* if we've reached urbs of infinite timeout, we're all done */
		if (!timerisset(cur_tv))
			return 0;

		/* ignore timeouts we've already handled */
		if (urbh->flags & LIBUSB_URBH_TIMED_OUT)
			continue;

		/* if urb has non-expired timeout, nothing more to do */
		if ((cur_tv->tv_sec > systime.tv_sec) ||
				(cur_tv->tv_sec == systime.tv_sec &&
					cur_tv->tv_usec > systime.tv_usec))
			return 0;
	
		/* otherwise, we've got an expired timeout to handle */
		handle_timeout(urbh);
	}

	return 0;
}

static int poll_io(struct timeval *tv)
{
	struct libusb_dev_handle *devh;
	int r;
	int maxfd = 0;
	fd_set writefds;
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

	FD_ZERO(&writefds);
	list_for_each_entry(devh, &open_devs, list) {
		int fd = devh->fd;
		FD_SET(fd, &writefds);
		if (fd > maxfd)
			maxfd = fd;
	}

	usbi_dbg("select() with timeout in %d.%06ds", select_timeout.tv_sec,
		select_timeout.tv_usec);
	r = select(maxfd + 1, NULL, &writefds, NULL, &select_timeout);
	usbi_dbg("select() returned %d with %d.%06ds remaining", r, select_timeout.tv_sec,
		select_timeout.tv_usec);
	if (r == 0) {
		*tv = select_timeout;
		return handle_timeouts();
	} else if (r == -1 && errno == EINTR) {
		return 0;
	} else if (r < 0) {
		usbi_err("select failed %d err=%d\n", r, errno);
		return r;
	}

	list_for_each_entry(devh, &open_devs, list) {
		if (!FD_ISSET(devh->fd, &writefds))
			continue;
		r = reap_for_devh(devh);
		if (r == -1 && errno == EAGAIN)
			continue;
		if (r < 0)
			return r;
	}

	/* FIXME check return value? */
	return handle_timeouts();
}

API_EXPORTED int libusb_poll_timeout(struct timeval *tv)
{
	return poll_io(tv);
}

API_EXPORTED int libusb_poll(void)
{
	struct timeval tv;
	tv.tv_sec = 2;
	tv.tv_usec = 0;
	return poll_io(&tv);
}

API_EXPORTED int libusb_get_next_timeout(struct timeval *tv)
{
	struct libusb_urb_handle *urbh;
	struct timespec cur_ts;
	struct timeval cur_tv;
	struct timeval *next_timeout;
	int r;
	int found = 0;

	if (list_empty(&flying_urbs)) {
		usbi_dbg("no URBs, no timeout!");
		return 0;
	}

	/* find next urb which hasn't already been processed as timed out */
	list_for_each_entry(urbh, &flying_urbs, list) {
		if (!(urbh->flags & LIBUSB_URBH_TIMED_OUT)) {
			found = 1;
			break;
		}
	}

	if (!found) {
		usbi_dbg("all URBs have already been processed for timeouts");
		return 0;
	}

	next_timeout = &urbh->timeout;

	/* no timeout for next urb */
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

struct sync_ctrl_handle {
	enum libusb_urb_cb_status status;
	unsigned char *data;
	int actual_length;
};

static void ctrl_transfer_cb(struct libusb_dev_handle *devh,
	struct libusb_urb_handle *urbh, enum libusb_urb_cb_status status,
	struct libusb_ctrl_setup *setup, unsigned char *data, int actual_length,
	void *user_data)
{
	struct sync_ctrl_handle *ctrlh = (struct sync_ctrl_handle *) user_data;
	usbi_dbg("actual_length=%d", actual_length);

	if (status == FP_URB_COMPLETED) {
		/* copy results into user-defined buffer */
		if (setup->bRequestType & LIBUSB_ENDPOINT_IN)
			memcpy(ctrlh->data, data, actual_length);
	}

	ctrlh->status = status;
	ctrlh->actual_length = actual_length;
	/* caller frees urbh */
}

API_EXPORTED int libusb_control_transfer(struct libusb_dev_handle *devh,
	struct libusb_control_transfer *transfer, unsigned int timeout)
{
	struct libusb_urb_handle *urbh;
	struct sync_ctrl_handle ctrlh;

	memset(&ctrlh, 0, sizeof(ctrlh));
	ctrlh.data = transfer->data;

	urbh = libusb_async_control_transfer(devh, transfer, ctrl_transfer_cb,
		&ctrlh, timeout);
	if (!urbh)
		return -1;

	while (!ctrlh.status) {
		int r = libusb_poll();
		if (r < 0) {
			libusb_urb_handle_cancel_sync(devh, urbh);
			libusb_urb_handle_free(urbh);
			return r;
		}
	}

	libusb_urb_handle_free(urbh);
	switch (ctrlh.status) {
	case FP_URB_COMPLETED:
		return ctrlh.actual_length;
	case FP_URB_TIMEOUT:
		return -ETIMEDOUT;
	default:
		usbi_warn("unrecognised status code %d", ctrlh.status);
		return -1;
	}
}

struct sync_bulk_handle {
	enum libusb_urb_cb_status status;
	int actual_length;
};

static void bulk_transfer_cb(struct libusb_dev_handle *devh,
	struct libusb_urb_handle *urbh, enum libusb_urb_cb_status status,
	unsigned char endpoint, int rqlength, unsigned char *data,
	int actual_length, void *user_data)
{
	struct sync_bulk_handle *bulkh = (struct sync_bulk_handle *) user_data;
	usbi_dbg("");
	bulkh->status = status;
	bulkh->actual_length = actual_length;
	/* caller frees urbh */
}

static int do_sync_bulk_transfer(struct libusb_dev_handle *devh,
	struct libusb_bulk_transfer *transfer, int *transferred,
	unsigned int timeout, unsigned char urbtype)
{
	struct libusb_urb_handle *urbh;
	struct sync_bulk_handle bulkh;

	memset(&bulkh, 0, sizeof(bulkh));

	urbh = submit_bulk_transfer(devh, transfer, bulk_transfer_cb, &bulkh,
		timeout, urbtype);
	if (!urbh)
		return -1;

	while (!bulkh.status) {
		int r = libusb_poll();
		if (r < 0) {
			libusb_urb_handle_cancel_sync(devh, urbh);
			libusb_urb_handle_free(urbh);
			return r;
		}
	}

	*transferred = bulkh.actual_length;
	libusb_urb_handle_free(urbh);

	switch (bulkh.status) {
	case FP_URB_COMPLETED:
		return 0;
	case FP_URB_TIMEOUT:
		return -ETIMEDOUT;
	default:
		usbi_warn("unrecognised status code %d", bulkh.status);
		return -1;
	}
}

API_EXPORTED int libusb_interrupt_transfer(struct libusb_dev_handle *devh,
	struct libusb_bulk_transfer *transfer, int *transferred,
	unsigned int timeout)
{
	return do_sync_bulk_transfer(devh, transfer, transferred, timeout,
		USB_URB_TYPE_INTERRUPT);
}

API_EXPORTED int libusb_bulk_transfer(struct libusb_dev_handle *devh,
	struct libusb_bulk_transfer *transfer, int *transferred,
	unsigned int timeout)
{
	return do_sync_bulk_transfer(devh, transfer, transferred, timeout,
		USB_URB_TYPE_BULK);
}

API_EXPORTED void libusb_urb_handle_free(struct libusb_urb_handle *urbh)
{
	if (!urbh)
		return;

	if (!(urbh->flags & LIBUSB_URBH_DATA_BELONGS_TO_USER))
		free(urbh->urb.buffer);
	free(urbh);
}

