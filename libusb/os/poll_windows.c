/*
 * poll_windows: poll compatibility wrapper for Windows
 * Copyright © 2017 Chris Dickens <christopher.a.dickens@gmail.com>
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
 *
 */

/*
 * poll() and pipe() Windows compatibility layer for libusb 1.0
 *
 * The way this layer works is by using OVERLAPPED with async I/O transfers, as
 * OVERLAPPED have an associated event which is flagged for I/O completion.
 *
 * For USB pollable async I/O, you would typically:
 * - obtain a Windows HANDLE to a file or device that has been opened in
 *   OVERLAPPED mode
 * - call usbi_create_fd with this handle to obtain a custom fd.
 * - leave the core functions call the poll routine and flag POLLIN/POLLOUT
 *
 * The pipe pollable synchronous I/O works using the overlapped event associated
 * with a fake pipe. The read/write functions are only meant to be used in that
 * context.
 */

#include "libusbi.h"
#include "windows_common.h"

#include <errno.h>
#include <intrin.h>
#include <malloc.h>
#include <stdbool.h>
#include <stdlib.h>

// public fd data
const struct winfd INVALID_WINFD = { -1, NULL };

// private data
struct file_descriptor {
	enum fd_type { FD_TYPE_PIPE, FD_TYPE_TRANSFER } type;
	LONG refcount;
	OVERLAPPED overlapped;
};

static usbi_mutex_static_t fd_table_lock = USBI_MUTEX_INITIALIZER;

#define BITS_PER_BYTE			8
#define BITMAP_BITS_PER_WORD		(sizeof(unsigned long) * BITS_PER_BYTE)
#define FD_TABLE_INCR_SIZE		64

static struct file_descriptor **fd_table;
static unsigned long *fd_table_bitmap;
static unsigned int fd_table_size;
static unsigned int fd_count;

#define return_with_errno(err)		\
	do {				\
		errno = (err);		\
		return -1;		\
	} while (0)

static struct file_descriptor *alloc_fd(enum fd_type type, LONG refcount)
{
	struct file_descriptor *fd = calloc(1, sizeof(*fd));

	if (fd == NULL)
		return NULL;
	fd->overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (fd->overlapped.hEvent == NULL) {
		free(fd);
		return NULL;
	}
	fd->type = type;
	fd->refcount = refcount;
	return fd;
}

static struct file_descriptor *get_fd(unsigned int _fd, bool ref)
{
	struct file_descriptor *fd = NULL;

	if (_fd < fd_table_size)
		fd = fd_table[_fd];
	if (fd != NULL && ref)
		InterlockedIncrement(&fd->refcount);

	return fd;
}

static void put_fd(struct file_descriptor *fd)
{
	if (InterlockedDecrement(&fd->refcount) == 0L) {
		CloseHandle(fd->overlapped.hEvent);
		free(fd);
	}
}

static int install_fd(struct file_descriptor *fd)
{
	unsigned int n;

	if (fd_count == fd_table_size) {
		struct file_descriptor **new_table;
		unsigned long *new_bitmap;

		// Need to expand the fd table and bitmap
		new_table = realloc(fd_table, (fd_table_size + FD_TABLE_INCR_SIZE) * sizeof(*new_table));
		if (new_table == NULL)
			return -ENOMEM;
		memset(new_table + fd_table_size, 0, FD_TABLE_INCR_SIZE * sizeof(*new_table));
		fd_table = new_table;

		new_bitmap = realloc(fd_table_bitmap, (fd_table_size + FD_TABLE_INCR_SIZE) / BITS_PER_BYTE);
		if (new_bitmap == NULL)
			return -ENOMEM;
		memset(new_bitmap + (fd_table_size / BITMAP_BITS_PER_WORD), 0, FD_TABLE_INCR_SIZE / BITS_PER_BYTE);
		fd_table_bitmap = new_bitmap;

		fd_table_size += FD_TABLE_INCR_SIZE;
		assert(fd_table_size < (unsigned int)INT_MAX);
	}

	for (n = 0; n < fd_table_size; n += BITMAP_BITS_PER_WORD) {
		unsigned int idx = n / BITMAP_BITS_PER_WORD;
		ULONG mask, pos = 0U;
		unsigned char nonzero;

		mask = ~fd_table_bitmap[idx];
		if (mask == 0U)
			continue;

		nonzero = _BitScanForward(&pos, mask);
		assert(nonzero);
		fd_table_bitmap[idx] |= 1U << pos;
		n += pos;
		break;
	}

	assert(n < fd_table_size);
	assert(fd_table[n] == NULL);
	fd_table[n] = fd;
	fd_count++;

	return n;
}

static void remove_fd(unsigned int pos)
{
	assert(fd_table[pos] != NULL);
	fd_table[pos] = NULL;
	fd_table_bitmap[pos / BITMAP_BITS_PER_WORD] &= ~(1U << (pos % BITMAP_BITS_PER_WORD));
	fd_count--;
	if (fd_count == 0) {
		free(fd_table);
		free(fd_table_bitmap);
		fd_table = NULL;
		fd_table_bitmap = NULL;
		fd_table_size = 0;
	}
}

/*
 * Create both an fd and an OVERLAPPED, so that it can be used with our
 * polling function
 * The handle MUST support overlapped transfers (usually requires CreateFile
 * with FILE_FLAG_OVERLAPPED)
 * Return a pollable file descriptor struct, or INVALID_WINFD on error
 *
 * Note that the fd returned by this function is a per-transfer fd, rather
 * than a per-session fd and cannot be used for anything else but our
 * custom functions.
 * if you plan to do R/W on the same handle, you MUST create 2 fds: one for
 * read and one for write. Using a single R/W fd is unsupported and will
 * produce unexpected results
 */
struct winfd usbi_create_fd(void)
{
	struct file_descriptor *fd;
	struct winfd wfd;

	fd = alloc_fd(FD_TYPE_TRANSFER, 1);
	if (fd == NULL)
		return INVALID_WINFD;

	usbi_mutex_static_lock(&fd_table_lock);
	wfd.fd = install_fd(fd);
	usbi_mutex_static_unlock(&fd_table_lock);

	if (wfd.fd < 0) {
		put_fd(fd);
		return INVALID_WINFD;
	}

	wfd.overlapped = &fd->overlapped;

	return wfd;
}

struct wait_thread_data {
	HANDLE thread;
	HANDLE handles[MAXIMUM_WAIT_OBJECTS];
	DWORD num_handles;
	DWORD error;
};

static DWORD WINAPI WaitThread(LPVOID lpParam)
{
	struct wait_thread_data *thread_data = lpParam;
	HANDLE notify_event = thread_data->handles[0];
	DWORD status;

	status = WaitForMultipleObjects(thread_data->num_handles, thread_data->handles, FALSE, INFINITE);
	if (status < (WAIT_OBJECT_0 + thread_data->num_handles)) {
		if (status > WAIT_OBJECT_0) {
			// This will wake up all the other waiting threads
			SetEvent(notify_event);
		}
		thread_data->error = 0;
	} else {
		assert(status == WAIT_FAILED);
		thread_data->error = (status == WAIT_FAILED) ? GetLastError() : ERROR_CAN_NOT_COMPLETE;
	}

	return 0;
}

static DWORD poll_wait(const HANDLE *wait_handles, DWORD num_wait_handles, DWORD timeout)
{
	struct wait_thread_data *thread_data;
	HANDLE notify_event;
	HANDLE *handles;
	int n, num_threads;
	DWORD error, status;

	if (num_wait_handles <= MAXIMUM_WAIT_OBJECTS)
		return WaitForMultipleObjects(num_wait_handles, wait_handles, FALSE, timeout);

	// To wait on more than MAXIMUM_WAIT_OBJECTS, each thread (including the
	// current thread) will wait on an event and (MAXIMUM_WAIT_OBJECTS - 1)
	// HANDLEs.  The event is shared amongst all threads so that any thread
	// that returns from a WaitForMultipleObjects() call will set the event
	// and wake up all the other threads.
	notify_event = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (notify_event == NULL)
		return WAIT_FAILED;

	num_threads = 1 + (num_wait_handles - MAXIMUM_WAIT_OBJECTS - 1) / (MAXIMUM_WAIT_OBJECTS - 1);
	thread_data = malloc(num_threads * sizeof(*thread_data));
	if (thread_data == NULL) {
		CloseHandle(notify_event);
		SetLastError(ERROR_OUTOFMEMORY);
		return WAIT_FAILED;
	}

	handles = _alloca(MAXIMUM_WAIT_OBJECTS * sizeof(HANDLE));
	handles[0] = notify_event;
	memcpy(handles + 1, wait_handles, (MAXIMUM_WAIT_OBJECTS - 1) * sizeof(HANDLE));
	wait_handles += MAXIMUM_WAIT_OBJECTS - 1;
	num_wait_handles -= MAXIMUM_WAIT_OBJECTS - 1;

	for (n = 0; n < num_threads; n++) {
		DWORD copy_size = MIN(num_wait_handles, MAXIMUM_WAIT_OBJECTS - 1);

		thread_data[n].handles[0] = notify_event;
		memcpy(thread_data[n].handles + 1, wait_handles, copy_size * sizeof(HANDLE));
		thread_data[n].num_handles = copy_size + 1;

		// Create the thread that will wait on these HANDLEs
		thread_data[n].thread = CreateThread(NULL, 0, WaitThread, &thread_data[n], 0, NULL);
		if (thread_data[n].thread == NULL) {
			thread_data[n].error = GetLastError();
			SetEvent(notify_event);
			num_threads = n + 1;
			break;
		}

		wait_handles += copy_size;
		num_wait_handles -= copy_size;
	}

	status = WaitForMultipleObjects(MAXIMUM_WAIT_OBJECTS, handles, FALSE, timeout);
	if (status < (WAIT_OBJECT_0 + MAXIMUM_WAIT_OBJECTS)) {
		if (status > WAIT_OBJECT_0) {
			// Wake up all the waiting threads
			SetEvent(notify_event);
			status = WAIT_OBJECT_0;
		}
		error = 0;
	} else if (status == WAIT_TIMEOUT) {
		// Wake up all the waiting threads
		SetEvent(notify_event);
		error = 0;
	} else {
		assert(status == WAIT_FAILED);
		error = (status == WAIT_FAILED) ? GetLastError() : ERROR_CAN_NOT_COMPLETE;
	}

	for (n = 0; n < num_threads; n++) {
		if (thread_data[n].thread != NULL) {
			if (WaitForSingleObject(thread_data[n].thread, INFINITE) != WAIT_OBJECT_0)
				usbi_err(NULL, "WaitForSingleObject() failed: %lu", ULONG_CAST(GetLastError()));
			CloseHandle(thread_data[n].thread);
		}
		if (thread_data[n].error) {
			usbi_err(NULL, "wait thread %d had error %lu\n", n, ULONG_CAST(thread_data[n].error));
			error = thread_data[n].error;
			status = WAIT_FAILED;
		}
	}

	free(thread_data);

	CloseHandle(notify_event);

	if (status == WAIT_FAILED)
		SetLastError(error);

	return status;
}

/*
 * POSIX poll equivalent, using Windows OVERLAPPED
 * Currently, this function only accepts one of POLLIN or POLLOUT per fd
 * (but you can create multiple fds from the same handle for read and write)
 */
int usbi_poll(struct pollfd *fds, usbi_nfds_t nfds, int timeout)
{
	struct file_descriptor **fds_array;
	HANDLE *handles_array;
	struct file_descriptor *fd;
	usbi_nfds_t n;
	int nready;

	if (nfds <= MAXIMUM_WAIT_OBJECTS) {
		fds_array = _alloca(nfds * sizeof(*fds_array));
		handles_array = _alloca(nfds * sizeof(*handles_array));
	} else {
		fds_array = malloc(nfds * sizeof(*fds_array));
		if (fds_array == NULL)
			return_with_errno(ENOMEM);
		handles_array = malloc(nfds * sizeof(*handles_array));
		if (handles_array == NULL) {
			free(fds_array);
			return_with_errno(ENOMEM);
		}
	}

	usbi_mutex_static_lock(&fd_table_lock);
	for (n = 0; n < nfds; n++) {
		struct pollfd *pfd = &fds[n];

		// Keep it simple - only allow either POLLIN *or* POLLOUT
		assert((pfd->events == POLLIN) || (pfd->events == POLLOUT));
		if ((pfd->events != POLLIN) && (pfd->events != POLLOUT)) {
			fds_array[n] = NULL;
			continue;
		}

		// All file descriptors must be valid
		fd = get_fd(pfd->fd, true);
		assert(fd != NULL);
		if (fd == NULL) {
			fds_array[n] = NULL;
			continue;
		}

		// We hold a reference to fd for the duration of usbi_poll()
		fds_array[n] = fd;
		handles_array[n] = fd->overlapped.hEvent;
	}
	usbi_mutex_static_unlock(&fd_table_lock);

	nready = 0;
	while (nready == 0) {
		DWORD ret;

		// Check all fds for events
		for (n = 0; n < nfds; n++) {
			fd = fds_array[n];
			if (fd == NULL) {
				fds[n].revents = POLLNVAL;
				nready++;
			} else if (HasOverlappedIoCompleted(&fd->overlapped)) {
				fds[n].revents = fds[n].events;
				nready++;
			} else {
				fds[n].revents = 0;
			}
		}

		if ((nready != 0) || (timeout == 0))
			break;

		// Wait for any of the events to trigger
		ret = poll_wait(handles_array, nfds, (timeout < 0) ? INFINITE : (DWORD)timeout);
		if (ret == WAIT_TIMEOUT) {
			assert(timeout > 0);
			timeout = 0;
		} else if (ret == WAIT_FAILED) {
			usbi_err(NULL, "WaitForMultipleObjects failed: %lu", ULONG_CAST(GetLastError()));
			errno = EIO;
			nready = -1;
		}
	}

	for (n = 0; n < nfds; n++) {
		if (fds_array[n] != NULL)
			put_fd(fds_array[n]);
	}

	if (nfds > MAXIMUM_WAIT_OBJECTS) {
		free(handles_array);
		free(fds_array);
	}

	return nready;
}

/*
 * close a fake file descriptor
 */
int usbi_close(int _fd)
{
	struct file_descriptor *fd;

	usbi_mutex_static_lock(&fd_table_lock);
	fd = get_fd(_fd, false);
	if (fd != NULL)
		remove_fd(_fd);
	usbi_mutex_static_unlock(&fd_table_lock);

	if (fd == NULL)
		return_with_errno(EBADF);

	put_fd(fd);

	return 0;
}

/*
* Create a fake pipe.
* As libusb only uses pipes for signaling, all we need from a pipe is an
* event. To that extent, we create a single wfd and overlapped as a means
* to access that event.
*/
int usbi_pipe(int filedes[2])
{
	struct file_descriptor *fd;
	int r_fd, w_fd;
	int error = 0;

	fd = alloc_fd(FD_TYPE_PIPE, 2);
	if (fd == NULL)
		return_with_errno(ENOMEM);

	fd->overlapped.Internal = STATUS_PENDING;

	usbi_mutex_static_lock(&fd_table_lock);
	r_fd = install_fd(fd);
	if (r_fd >= 0) {
		w_fd = install_fd(fd);
		if (w_fd < 0) {
			remove_fd(r_fd);
			error = w_fd;
		}
	} else {
		error = r_fd;
		w_fd = -1; // Keep compiler happy
	}
	usbi_mutex_static_unlock(&fd_table_lock);

	if (error) {
		CloseHandle(fd->overlapped.hEvent);
		free(fd);
		return_with_errno(error);
	}

	filedes[0] = r_fd;
	filedes[1] = w_fd;

	return 0;
}

/*
 * synchronous write for fake "pipe" signaling
 */
ssize_t usbi_write(int _fd, const void *buf, size_t count)
{
	struct file_descriptor *fd;

	UNUSED(buf);

	if (count != sizeof(unsigned char)) {
		usbi_err(NULL, "this function should only used for signaling");
		return_with_errno(EINVAL);
	}

	usbi_mutex_static_lock(&fd_table_lock);
	fd = get_fd(_fd, false);
	if (fd && fd->type == FD_TYPE_PIPE) {
		assert(fd->overlapped.Internal == STATUS_PENDING);
		fd->overlapped.Internal = STATUS_WAIT_0;
		SetEvent(fd->overlapped.hEvent);
	} else {
		fd = NULL;
	}
	usbi_mutex_static_unlock(&fd_table_lock);

	if (fd == NULL)
		return_with_errno(EBADF);

	return sizeof(unsigned char);
}

/*
 * synchronous read for fake "pipe" signaling
 */
ssize_t usbi_read(int _fd, void *buf, size_t count)
{
	struct file_descriptor *fd;

	UNUSED(buf);

	if (count != sizeof(unsigned char)) {
		usbi_err(NULL, "this function should only used for signaling");
		return_with_errno(EINVAL);
	}

	usbi_mutex_static_lock(&fd_table_lock);
	fd = get_fd(_fd, false);
	if (fd && fd->type == FD_TYPE_PIPE) {
		assert(fd->overlapped.Internal == STATUS_WAIT_0);
		fd->overlapped.Internal = STATUS_PENDING;
		ResetEvent(fd->overlapped.hEvent);
	} else {
		fd = NULL;
	}
	usbi_mutex_static_unlock(&fd_table_lock);

	if (fd == NULL)
		return_with_errno(EBADF);

	return sizeof(unsigned char);
}
