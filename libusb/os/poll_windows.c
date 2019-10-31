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
#include <config.h>

#include <assert.h>
#include <errno.h>
#include <stdlib.h>

#include "libusbi.h"
#include "windows_common.h"

// public fd data
const struct winfd INVALID_WINFD = { -1, NULL };

// private data
struct file_descriptor {
	enum fd_type { FD_TYPE_PIPE, FD_TYPE_TRANSFER } type;
	OVERLAPPED overlapped;
	int refcount;
};

static usbi_mutex_static_t fd_table_lock = USBI_MUTEX_INITIALIZER;

static struct file_descriptor **fd_table;
static size_t fd_count;
static size_t fd_size;
#define INC_FDS_EACH 256

static void usbi_dec_fd_table()
{
	fd_count--;
	if (fd_count == 0) {
		free(fd_table);
		fd_size = 0;
		fd_table = NULL;
	}
}

static void smart_realloc_fd_table_space(int inc)
{
	if (fd_table == NULL || fd_count + inc > fd_size) {
		struct file_descriptor **p = (struct file_descriptor **)realloc(fd_table, (fd_size + INC_FDS_EACH) * sizeof(struct file_descriptor *));
		if (p != NULL) {
			memset(p + fd_size, 0, INC_FDS_EACH * sizeof(struct file_descriptor *));
			fd_size += INC_FDS_EACH;
			fd_table = p;
		}
	}
}

static struct file_descriptor *create_fd(enum fd_type type)
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
	fd->refcount = 1;
	return fd;
}

static void free_fd(struct file_descriptor *fd)
{
	CloseHandle(fd->overlapped.hEvent);
	free(fd);
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

	fd = create_fd(FD_TYPE_TRANSFER);
	if (fd == NULL)
		return INVALID_WINFD;

	usbi_mutex_static_lock(&fd_table_lock);

	smart_realloc_fd_table_space(1);

	for (wfd.fd = 0; wfd.fd < fd_size; wfd.fd++) {
		if (fd_table[wfd.fd] != NULL)
			continue;
		fd_table[wfd.fd] = fd;
		fd_count++;
		break;
	}
	usbi_mutex_static_unlock(&fd_table_lock);

	if (wfd.fd == fd_size) {
		free_fd(fd);
		return INVALID_WINFD;
	}

	wfd.overlapped = &fd->overlapped;

	return wfd;
}

void usbi_inc_fds_ref(struct pollfd *fds, unsigned int nfds)
{
	int n;
	usbi_mutex_static_lock(&fd_table_lock);
	for (n = 0; n < nfds; ++n) {
		fd_table[fds[n].fd]->refcount++;
	}
	usbi_mutex_static_unlock(&fd_table_lock);
}

void usbi_dec_fds_ref(struct pollfd *fds, unsigned int nfds)
{
	int n;
	struct file_descriptor *fd;

	usbi_mutex_static_lock(&fd_table_lock);
	for (n = 0; n < nfds; ++n) {
		fd = fd_table[fds[n].fd];
		fd->refcount--;
		//FD_TYPE_PIPE map fd to two _fd
		if (fd->refcount == 0 || (fd->refcount == 1 && fd->type == FD_TYPE_PIPE))
		{
			if (fd->type == FD_TYPE_PIPE) {
				// InternalHigh is our reference count
				fd->overlapped.InternalHigh--;
				if (fd->overlapped.InternalHigh == 0)
					free_fd(fd);
			}
			else {
				free_fd(fd);
			}
			fd_table[fds[n].fd] = NULL;
			usbi_dec_fd_table();
		}
	}
	usbi_mutex_static_unlock(&fd_table_lock);
}


static int check_pollfds(struct pollfd *fds, unsigned int nfds,
	HANDLE *wait_handles, DWORD *nb_wait_handles)
{
	struct file_descriptor *fd;
	unsigned int n;
	int nready = 0;

	usbi_mutex_static_lock(&fd_table_lock);

	for (n = 0; n < nfds; ++n) {
		fds[n].revents = 0;

		// Keep it simple - only allow either POLLIN *or* POLLOUT
		assert((fds[n].events == POLLIN) || (fds[n].events == POLLOUT));
		if ((fds[n].events != POLLIN) && (fds[n].events != POLLOUT)) {
			fds[n].revents = POLLNVAL;
			nready++;
			continue;
		}

		if ((fds[n].fd >= 0) && (fds[n].fd < fd_size))
			fd = fd_table[fds[n].fd];
		else
			fd = NULL;

		assert(fd != NULL);
		if (fd == NULL) {
			fds[n].revents = POLLNVAL;
			nready++;
			continue;
		}

		if (HasOverlappedIoCompleted(&fd->overlapped)
				&& (WaitForSingleObject(fd->overlapped.hEvent, 0) == WAIT_OBJECT_0)) {
			fds[n].revents = fds[n].events;
			nready++;
		} else if (wait_handles != NULL) {
			wait_handles[*nb_wait_handles] = fd->overlapped.hEvent;
			(*nb_wait_handles)++;
		}
	}

	usbi_mutex_static_unlock(&fd_table_lock);

	return nready;
}

#define EXT_TIMEOUT WAIT_OBJECT_0

struct ExThreadData
{
	HANDLE notifyevents;

	HANDLE thread;
	HANDLE wait_event[MAXIMUM_WAIT_OBJECTS];
	int nEvents;
	DWORD ret_wait;
	volatile int bexit;
};

static DWORD __stdcall WaitThread(LPVOID lpThreadParameter)
{
	struct ExThreadData *p = (struct ExThreadData *)lpThreadParameter;
	int ret = WaitForMultipleObjects(p->nEvents, p->wait_event, FALSE, INFINITE);
	p->ret_wait = ret;
	p->bexit = true;
	SetEvent(p->notifyevents);
	return 0;
}

static DWORD ExtendWaitForMultipleObjects(
	DWORD        nCount,
	const HANDLE *lpHandles,
	BOOL         bWaitAll,
	DWORD        dwMilliseconds
)
{
	DWORD ret;
	int i = 0;
	int nThreads = 0;
	struct ExThreadData *pThread;
	int size;
	HANDLE notify_event;

	if (nCount <= MAXIMUM_WAIT_OBJECTS) {
		ret = WaitForMultipleObjects(nCount, lpHandles, bWaitAll, dwMilliseconds);
		if (ret == WAIT_TIMEOUT)
			return EXT_TIMEOUT;

		if (ret < WAIT_OBJECT_0 + nCount)
			return ret + 1;

		return ret;
	}

	nThreads = (nCount + MAXIMUM_WAIT_OBJECTS - 2) / (MAXIMUM_WAIT_OBJECTS - 1);

	notify_event = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (notify_event == NULL) {
		usbi_err(NULL, "Create Event failure");
		return WAIT_FAILED;
	}

	pThread = malloc(sizeof(struct ExThreadData) * nThreads);

	if (pThread == NULL) {
		usbi_err(NULL, "Out of memory");
		CloseHandle(notify_event);
		return WAIT_FAILED;
	}

	for (i = 0; i < nThreads; i++)
	{
		pThread[i].wait_event[0] = CreateEvent(NULL, TRUE, FALSE, NULL);
		pThread[i].notifyevents = notify_event;

		size = nCount - i * (MAXIMUM_WAIT_OBJECTS - 1);
		if (size >= (MAXIMUM_WAIT_OBJECTS - 1))
			size = (MAXIMUM_WAIT_OBJECTS - 1);

		memcpy(pThread[i].wait_event + 1, lpHandles + i * (MAXIMUM_WAIT_OBJECTS - 1), size * sizeof(HANDLE));

		pThread[i].nEvents = size + 1;

		pThread[i].bexit = 0;

		pThread[i].thread = CreateThread(NULL, 0, WaitThread, pThread+i, 0, NULL);
	}

	ret = WaitForSingleObject(notify_event, INFINITE);

	for (i = 0; i < nThreads; i++)
	{
		SetEvent(pThread[i].wait_event[0]);
		while (pThread[i].bexit == 0); //wait for thread exist;

		if (pThread[i].ret_wait != WAIT_OBJECT_0)
			ret = pThread[i].ret_wait + i * (MAXIMUM_WAIT_OBJECTS - 1);

		CloseHandle(pThread[i].wait_event[0]);
	}

	CloseHandle(notify_event);
	free(pThread);

	return ret ;
}

/*
 * POSIX poll equivalent, using Windows OVERLAPPED
 * Currently, this function only accepts one of POLLIN or POLLOUT per fd
 * (but you can create multiple fds from the same handle for read and write)
 */
int usbi_poll(struct pollfd *fds, unsigned int nfds, int timeout)
{
	HANDLE *wait_handles;
	DWORD nb_wait_handles = 0;
	DWORD ret;
	int nready;

	wait_handles = malloc(nfds * sizeof(HANDLE));
	if (!wait_handles)
	{
		usbi_err(NULL, "Out of memory");
		return -1;
	}

	nready = check_pollfds(fds, nfds, wait_handles, &nb_wait_handles);

	// If nothing was triggered, wait on all fds that require it
	if ((nready == 0) && (nb_wait_handles != 0) && (timeout != 0)) {
		ret = ExtendWaitForMultipleObjects(nb_wait_handles, wait_handles,
			FALSE, (timeout < 0) ? INFINITE : (DWORD)timeout);
		if (ret != EXT_TIMEOUT && ret <= (WAIT_OBJECT_0 + nb_wait_handles)) {
			nready = check_pollfds(fds, nfds, NULL, NULL);
		} else if (ret != EXT_TIMEOUT) {
			if (ret == WAIT_FAILED)
				usbi_err(NULL, "WaitForMultipleObjects failed: %u", (unsigned int)GetLastError());
			nready = -1;
		}
	}

	free(wait_handles);
	return nready;
}

/*
 * close a fake file descriptor
 */
int usbi_close(int _fd)
{
	struct file_descriptor *fd;

	if (_fd < 0 || _fd >= fd_size)
		goto err_badfd;

	usbi_mutex_static_lock(&fd_table_lock);
	fd = fd_table[_fd];
	fd->refcount--;
	//FD_TYPE_PIPE map fd to two _fd
	if(fd->refcount==0 || (fd->refcount == 1 && fd->type == FD_TYPE_PIPE))
	{	fd_table[_fd] = NULL;
		usbi_dec_fd_table();

		if (fd->type == FD_TYPE_PIPE) {
			// InternalHigh is our reference count
			fd->overlapped.InternalHigh--;
			if (fd->overlapped.InternalHigh == 0)
				free_fd(fd);
		}
		else {
			free_fd(fd);
		}
	}
	usbi_mutex_static_unlock(&fd_table_lock);

	if (fd == NULL)
		goto err_badfd;

	return 0;

err_badfd:
	errno = EBADF;
	return -1;
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
	int r_fd = -1, w_fd = -1;
	int i;

	fd = create_fd(FD_TYPE_PIPE);
	if (fd == NULL) {
		errno = ENOMEM;
		return -1;
	}

	// Use InternalHigh as a reference count
	fd->overlapped.Internal = STATUS_PENDING;
	fd->overlapped.InternalHigh = 2;

	usbi_mutex_static_lock(&fd_table_lock);
	do {
		smart_realloc_fd_table_space(2);

		for (i = 0; i < fd_size; i++) {
			if (fd_table[i] != NULL)
				continue;
			if (r_fd == -1) {
				r_fd = i;
			} else if (w_fd == -1) {
				w_fd = i;
				break;
			}
		}

		if (i == fd_size)
			break;

		fd_table[r_fd] = fd;
		fd_table[w_fd] = fd;

		fd->refcount++; //this fd reference twice for r and w.

		fd_count += 2;

	} while (0);
	usbi_mutex_static_unlock(&fd_table_lock);

	if (i == fd_size) {
		free_fd(fd);
		errno = EMFILE;
		return -1;
	}

	filedes[0] = r_fd;
	filedes[1] = w_fd;

	return 0;
}

/*
 * synchronous write for fake "pipe" signaling
 */
ssize_t usbi_write(int fd, const void *buf, size_t count)
{
	int error = EBADF;

	UNUSED(buf);

	if (fd < 0 || fd >= fd_size)
		goto err_out;

	if (count != sizeof(unsigned char)) {
		usbi_err(NULL, "this function should only used for signaling");
		error = EINVAL;
		goto err_out;
	}

	usbi_mutex_static_lock(&fd_table_lock);
	if ((fd_table[fd] != NULL) && (fd_table[fd]->type == FD_TYPE_PIPE)) {
		assert(fd_table[fd]->overlapped.Internal == STATUS_PENDING);
		assert(fd_table[fd]->overlapped.InternalHigh == 2);
		fd_table[fd]->overlapped.Internal = STATUS_WAIT_0;
		SetEvent(fd_table[fd]->overlapped.hEvent);
		error = 0;
	}
	usbi_mutex_static_unlock(&fd_table_lock);

	if (error)
		goto err_out;

	return sizeof(unsigned char);

err_out:
	errno = error;
	return -1;
}

/*
 * synchronous read for fake "pipe" signaling
 */
ssize_t usbi_read(int fd, void *buf, size_t count)
{
	int error = EBADF;

	UNUSED(buf);

	if (fd < 0 || fd >= fd_size)
		goto err_out;

	if (count != sizeof(unsigned char)) {
		usbi_err(NULL, "this function should only used for signaling");
		error = EINVAL;
		goto err_out;
	}

	usbi_mutex_static_lock(&fd_table_lock);
	if ((fd_table[fd] != NULL) && (fd_table[fd]->type == FD_TYPE_PIPE)) {
		assert(fd_table[fd]->overlapped.Internal == STATUS_WAIT_0);
		assert(fd_table[fd]->overlapped.InternalHigh == 2);
		fd_table[fd]->overlapped.Internal = STATUS_PENDING;
		ResetEvent(fd_table[fd]->overlapped.hEvent);
		error = 0;
	}
	usbi_mutex_static_unlock(&fd_table_lock);

	if (error)
		goto err_out;

	return sizeof(unsigned char);

err_out:
	errno = error;
	return -1;
}
