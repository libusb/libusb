/*
 * Windows compat: POSIX compatibility wrapper
 * Copyright (C) 2009 Pete Batard <pbatard@gmail.com>
 *
 * Parts of poll implementation from libusb-win32, by Stephan Meyer et al.
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
 * Posix poll() and pipe() Windows compatibility layer for libusb 1.0
 *
 * The way this layer works is by using OVERLAPPED with async I/O transfers, as
 * OVERLAPPED have an associated event which is flagged for I/O completion.
 * 
 * For USB pollable async I/O, you would typically:
 * - obtain a Windows HANDLE to a file or device that has been opened in
 *   OVERLAPPED mode
 * - call _libusb_create_fd with this handle to obtain a custom fd.
 *   Note that if you need simultaneous R/W access, you need to call create_fd
 *   twice, once in _O_RDONLY and once in _O_WRONLY mode to obtain 2 separate
 *   pollable fds
 * - leave the core functions call the poll routine and flag POLLIN/POLLOUT
 * 
 * For pipe pollable synchronous I/O (read end polling only), you would:
 * - create an anonymous pipe with _libusb_pipe to obtain 2 fds (r & w)
 * - use _libusb_write / _libusb_read to write to either end of the pipe
 * - use poll to check for data to read
 * Note that the _libusb_read/_libusb_write function actually perform 
 * asynchronous I/O internally, and could potentially be modified to support
 * O_NON_BLOCK
 *
 * The way the polling on _libusb_read works is by splitting all read I/O
 * into a dual 1 byte/n-1 bytes asynchronous read operation.
 * The 1 byte data (called the marker), is always armed for asynchronous
 * readout, so that as soon as data becomes available, an OVERLAPPED event
 * will be flagged, which poll can report.
 * Then during the _libusb_read routine itself, this 1 byte marker is copied
 * to the buffer, along with the rest of the data.
 *
 * Note that, since most I/O is buffered, being notified when only the first
 * byte of data is available is unlikely to delay read operations, since the
 * rest of the data should be available in system buffers by the time read
 * is called.
 *
 * Also note that if you don't use _libusb_read to read inbound data, but
 * use the OVERLAPPED directly (which is what we do in the USB async I/O 
 * functions), the marker is not used at all.
 */

/*
 * TODO: Once MinGW supports it (or for other compilation platforms) use
 * CancelIoEx instead of CancelIo for Vista and later platforms
 */
#include <windows.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <io.h>

#include "windows_compat.h"

// Uncomment to debug the polling layer
//#define DEBUG_WINDOWS_COMPAT
#if defined(DEBUG_WINDOWS_COMPAT)
#define printb printf
#else
// MSVC6 cannot use a variadic argument and non MSVC
// compilers produce warnings if parenthesis are ommitted.
#if defined(_MSC_VER)
#define printb
#else
#define printb(...)
#endif
#endif

#if defined(_PREFAST_)
#pragma warning(disable:28719)
#endif

#if defined(__CYGWIN__ )
// cygwin produces a warning unless these prototypes are defined
extern int _close(int fd);
extern int _snprintf(char *buffer, size_t count, const char *format, ...);
extern int cygwin_attach_handle_to_fd(char *name, int fd, HANDLE handle, int bin, int access); 
// _open_osfhandle() is not available on cygwin, but we can emulate
// it for our needs with cygwin_attach_handle_to_fd()
static inline int _open_osfhandle(intptr_t osfhandle, int flags)
{
	int access;
	switch (flags) {
	case _O_RDONLY:
		access = GENERIC_READ;
		break;
	case _O_WRONLY:
		access = GENERIC_WRITE;
		break;
	case _O_RDWR:
		access = GENERIC_READ|GENERIC_WRITE;
		break;
	default:
		printb("_open_osfhandle (emulated): unuspported access mode\n");
		return -1;
	}
	return cygwin_attach_handle_to_fd("/dev/null", -1, (HANDLE)osfhandle, -1, access);
}
#endif

#define CHECK_INIT_POLLING do {if(!is_polling_set) init_polling();} while(0)

// public fd data
const struct winfd INVALID_WINFD = {-1, NULL, NULL, RW_NONE, FALSE};
struct winfd poll_fd[MAX_FDS];
// internal fd data
struct {
	CRITICAL_SECTION mutex; // lock for fds
	BYTE marker;            // 1st byte of a _libusb_read operation gets stored here

} _poll_fd[MAX_FDS];

// globals
BOOLEAN is_polling_set = FALSE;
LONG pipe_number = 0;
static volatile LONG compat_spinlock = 0;

// Init
void init_polling(void)
{
	int i;

	while (InterlockedExchange((LONG *)&compat_spinlock, 1) == 1) {
		SleepEx(0, TRUE);
	}
	if (!is_polling_set) {
		for (i=0; i<MAX_FDS; i++) {
			poll_fd[i] = INVALID_WINFD;
			_poll_fd[i].marker = 0;
			InitializeCriticalSection(&_poll_fd[i].mutex);
		}
		is_polling_set = TRUE;
	}
	compat_spinlock = 0;
}

// Internal function to retrieve the table index (and lock the fd mutex)
int _fd_to_index_and_lock(int fd)
{
	int i;

	if (fd <= 0)
		return -1;

	for (i=0; i<MAX_FDS; i++) {
		if (poll_fd[i].fd == fd) {
			EnterCriticalSection(&_poll_fd[i].mutex);
			// fd might have changed before we got to critical
			if (poll_fd[i].fd != fd) {
				LeaveCriticalSection(&_poll_fd[i].mutex);
				continue;
			}
			return i;
		}
	}
	return -1;
}

OVERLAPPED *create_overlapped(void) 
{
	OVERLAPPED *overlapped = calloc(1, sizeof(OVERLAPPED));
	if (overlapped == NULL) {
		return NULL;
	}
	overlapped->hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if(overlapped->hEvent == NULL) {
		free (overlapped);
		return NULL;
	}
	return overlapped;
}

void free_overlapped(OVERLAPPED *overlapped)
{
	if (overlapped == NULL)
		return;

	if ( (overlapped->hEvent != 0) 
	  && (overlapped->hEvent != INVALID_HANDLE_VALUE) ) {
		CloseHandle(overlapped->hEvent);
	}
	free(overlapped);
}

void reset_overlapped(OVERLAPPED *overlapped)
{
	HANDLE event_handle;
	if (overlapped == NULL)
		return;

	event_handle = overlapped->hEvent;
	if (event_handle != NULL) {
		ResetEvent(event_handle);
	}
	memset(overlapped, 0, sizeof(OVERLAPPED));
	overlapped->hEvent = event_handle;
}

void exit_polling(void)
{
	int i;

	while (InterlockedExchange((LONG *)&compat_spinlock, 1) == 1) {
		SleepEx(0, TRUE);
	}
	if (is_polling_set) {
		is_polling_set = FALSE;

		for (i=0; i<MAX_FDS; i++) {
			// Cancel any async I/O (handle can be invalid)
			CancelIo(poll_fd[i].handle);
			// If anything was pending on that I/O, it should be
			// terminating, and we should be able to access the fd
			// mutex lock before too long
			EnterCriticalSection(&_poll_fd[i].mutex);
			if ( (poll_fd[i].fd > 0) && (poll_fd[i].handle != INVALID_HANDLE_VALUE) && (poll_fd[i].handle != 0)
			  && (GetFileType(poll_fd[i].handle) == FILE_TYPE_UNKNOWN) ) {
				_close(poll_fd[i].fd);
			}
			free_overlapped(poll_fd[i].overlapped);
			poll_fd[i] = INVALID_WINFD;
			LeaveCriticalSection(&_poll_fd[i].mutex);
			DeleteCriticalSection(&_poll_fd[i].mutex);
		}
	}
	compat_spinlock = 0;
}

/*
 * sets the async I/O read on our 1 byte marker
 *
 * requires a valid index
 */
__inline void _init_read_marker(int index) 
{
	// Cancel any read operation in progress
	CancelIo(poll_fd[index].handle);
	// Setup a new async read on our marker
	reset_overlapped(poll_fd[index].overlapped);
	if (!ReadFile(poll_fd[index].handle, &_poll_fd[index].marker, 1, NULL, poll_fd[index].overlapped)) {
		if(GetLastError() != ERROR_IO_PENDING) {
			printb("_init_read_marker: didn't get IO_PENDING!\n");
			reset_overlapped(poll_fd[index].overlapped);
		}
	} else {
		// We got some sync I/O. We'll pretend it's async and set overlapped manually
		printb("_init_read_marker: marker readout completed before exit!\n");
		// TODO: check IO_PENDING cleared?
		SetEvent(poll_fd[index].overlapped->hEvent);
		poll_fd[index].overlapped->InternalHigh = 1;
	}
}

/*
 * Create an async I/O anonymous pipe (that can be used for sync as well)
 */
int _libusb_pipe(int filedes[2])
{
	int i, j;
	HANDLE handle[2];
	OVERLAPPED *overlapped0, *overlapped1;
	char pipe_name[] = "\\\\.\\pipe\\libusb000000000000";
	LONG our_pipe_number;

	CHECK_INIT_POLLING;

	overlapped0 = calloc(1, sizeof(OVERLAPPED));
	if (overlapped0 == NULL) {
		return -1;
	}

	overlapped1 = calloc(1, sizeof(OVERLAPPED));
	if (overlapped1 == NULL) {
		free(overlapped0);
		return -1;
	}

	our_pipe_number  = InterlockedIncrement(&pipe_number) - 1; // - 1 to mirror postfix operation inside _snprintf
	our_pipe_number &= 0xFFFF; // Could warn if this was necessary (ToDo)
	_snprintf(pipe_name, sizeof(pipe_name), "\\\\.\\pipe\\libusb%08x%04x", (unsigned)GetCurrentProcessId(), our_pipe_number);

	// Read end of the pipe
	handle[0] = CreateNamedPipeA(pipe_name, PIPE_ACCESS_INBOUND|FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE, 1, 4096, 4096, 0, NULL);
	if (handle[0] == INVALID_HANDLE_VALUE) {
		printb("Could not create pipe (read end): errcode %d\n", (int)GetLastError());
		goto out1;
	}
	filedes[0] = _open_osfhandle((intptr_t)handle[0], _O_RDONLY);
	printb("filedes[0] = %d\n", filedes[0]);

	// Write end of the pipe
	handle[1] = CreateFileA(pipe_name, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OVERLAPPED, NULL);
	if (handle[1] == INVALID_HANDLE_VALUE) {
		printb("Could not create pipe (write end): errcode %d\n", (int)GetLastError());
		goto out2;
	}
	filedes[1] = _open_osfhandle((intptr_t)handle[1], _O_WRONLY);
	printb("filedes[1] = %d\n", filedes[1]);

	// Create an OVERLAPPED for each end
	overlapped0->hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if(!overlapped0->hEvent) {
		goto out3;
	}
	overlapped1->hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if(!overlapped1->hEvent) {
		goto out4;
	}

	for (i=0, j=0; i<MAX_FDS; i++) {
		if (poll_fd[i].fd < 0) {
			EnterCriticalSection(&_poll_fd[i].mutex);
			// fd might have been allocated before we got to critical
			if (poll_fd[i].fd >= 0) {
				LeaveCriticalSection(&_poll_fd[i].mutex);
				continue;
			}

			poll_fd[i].fd = filedes[j];
			poll_fd[i].handle = handle[j];
			poll_fd[i].overlapped = (j==0)?overlapped0:overlapped1;
			poll_fd[i].rw = RW_READ+j;
			poll_fd[i].completed_synchronously = FALSE;
			j++;
			if (j==1) {
				// Start a 1 byte nonblocking read operation
				// so that we get read event notifications
				_init_read_marker(i);
			}
			LeaveCriticalSection(&_poll_fd[i].mutex);
			if (j>=2) {
				return 0;
			}
		}
	}

	CloseHandle(overlapped1->hEvent);
out4:
	CloseHandle(overlapped0->hEvent);
out3:
	CloseHandle(handle[1]);
out2:
	CloseHandle(handle[0]);
out1:
	free(overlapped1);
	free(overlapped0);
	return -1;
}

/*
 * Create both an fd and an OVERLAPPED from an open Windows handle, so that 
 * it can be used with our polling function
 * The handle MUST support overlapped transfers (usually requires CreateFile
 * with FILE_FLAG_OVERLAPPED)
 * Return a pollable file descriptor struct, or INVALID_WINFD on error
 *
 * Note that the fd returned by this function is a per-transfer fd, rather
 * than a per-session fd and cannot be used for anything else but our 
 * custom functions (the fd itself points to the NUL: device)
 * if you plan to do R/W on the same handle, you MUST create 2 fds: one for
 * read and one for write. Using a single R/W fd is unsupported and will
 * produce unexpected results
 */
struct winfd _libusb_create_fd(HANDLE handle, int access_mode)
{
	int i, fd;
	struct winfd wfd = INVALID_WINFD;
	OVERLAPPED* overlapped = NULL;

	CHECK_INIT_POLLING;

	if ((handle == 0) || (handle == INVALID_HANDLE_VALUE)) {
		return INVALID_WINFD;
	}

	if ((access_mode != _O_RDONLY) && (access_mode != _O_WRONLY)) {
		printb("_libusb_create_fd: only one of _O_RDONLY or _O_WRONLY are supported.\n"
			"If you want to poll for R/W simultaneously, create multiple fds from the same handle.\n");
		return INVALID_WINFD;
	}
	if (access_mode == _O_RDONLY) {
		wfd.rw = RW_READ;
	} else {
		wfd.rw = RW_WRITE;
	}

	// Ensure that we get a non system conflicting unique fd
	fd = _open_osfhandle((intptr_t)CreateFileA("NUL", 0, 0,
		NULL, OPEN_EXISTING, 0, NULL), _O_RDWR);
	if (fd < 0) {
		return INVALID_WINFD;
	}

	overlapped = create_overlapped();
	if(overlapped == NULL) {
		_close(fd);
		return INVALID_WINFD;
	}

	for (i=0; i<MAX_FDS; i++) {
		if (poll_fd[i].fd < 0) {
			EnterCriticalSection(&_poll_fd[i].mutex);
			// fd might have been removed before we got to critical
			if (poll_fd[i].fd >= 0) {
				LeaveCriticalSection(&_poll_fd[i].mutex);
				continue;
			}
			wfd.fd = fd;
			wfd.handle = handle;
			wfd.overlapped = overlapped;
			memcpy(&poll_fd[i], &wfd, sizeof(struct winfd));
			LeaveCriticalSection(&_poll_fd[i].mutex);
			return wfd;
		}
	}
	free_overlapped(overlapped);
	_close(fd);
	return INVALID_WINFD;
}

void _free_index(int index)
{
	// Cancel any async IO (Don't care about the validity of our handles for this)
	CancelIo(poll_fd[index].handle);
	// close fake handle for devices
	if ( (poll_fd[index].handle != INVALID_HANDLE_VALUE) && (poll_fd[index].handle != 0)
	  && (GetFileType(poll_fd[index].handle) == FILE_TYPE_UNKNOWN) ) {
		_close(poll_fd[index].fd);
	}
	free_overlapped(poll_fd[index].overlapped);
	poll_fd[index] = INVALID_WINFD;
}

/*
 * Release a pollable file descriptor. 
 *
 * Note that the associated Windows handle is not closed by this call
 */
void _libusb_free_fd(int fd)
{
	int index;

	CHECK_INIT_POLLING;

	index = _fd_to_index_and_lock(fd);
	if (index < 0) {
		return;
	}
	_free_index(index);
	LeaveCriticalSection(&_poll_fd[index].mutex);
}

/*
 * The functions below perform various conversions between fd, handle and OVERLAPPED
 */
struct winfd fd_to_winfd(int fd)
{
	int i;
	struct winfd wfd;

	CHECK_INIT_POLLING;

	if (fd <= 0)
		return INVALID_WINFD;

	for (i=0; i<MAX_FDS; i++) {
		if (poll_fd[i].fd == fd) {
			EnterCriticalSection(&_poll_fd[i].mutex);
			// fd might have been deleted before we got to critical
			if (poll_fd[i].fd != fd) {
				LeaveCriticalSection(&_poll_fd[i].mutex);
				continue;
			}
			memcpy(&wfd, &poll_fd[i], sizeof(struct winfd));
			LeaveCriticalSection(&_poll_fd[i].mutex);
			return wfd;
		}
	}
	return INVALID_WINFD;
}

struct winfd handle_to_winfd(HANDLE handle)
{
	int i;
	struct winfd wfd;

	CHECK_INIT_POLLING;

	if ((handle == 0) || (handle == INVALID_HANDLE_VALUE))
		return INVALID_WINFD;

	for (i=0; i<MAX_FDS; i++) {
		if (poll_fd[i].handle == handle) {
			EnterCriticalSection(&_poll_fd[i].mutex);
			// fd might have been deleted before we got to critical
			if (poll_fd[i].handle != handle) {
				LeaveCriticalSection(&_poll_fd[i].mutex);
				continue;
			}
			memcpy(&wfd, &poll_fd[i], sizeof(struct winfd));
			LeaveCriticalSection(&_poll_fd[i].mutex);
			return wfd;
		}
	}
	return INVALID_WINFD;
}

struct winfd overlapped_to_winfd(OVERLAPPED* overlapped)
{
	int i;
	struct winfd wfd;

	CHECK_INIT_POLLING;

	if (overlapped == NULL)
		return INVALID_WINFD;

	for (i=0; i<MAX_FDS; i++) {
		if (poll_fd[i].overlapped == overlapped) {
			EnterCriticalSection(&_poll_fd[i].mutex);
			// fd might have been deleted before we got to critical
			if (poll_fd[i].overlapped != overlapped) {
				LeaveCriticalSection(&_poll_fd[i].mutex);
				continue;
			}
			memcpy(&wfd, &poll_fd[i], sizeof(struct winfd));
			LeaveCriticalSection(&_poll_fd[i].mutex);
			return wfd;
		}
	}
	return INVALID_WINFD;
}

/*
 * POSIX poll equivalent, using Windows OVERLAPPED
 * Currently, this function only accepts one of POLLIN or POLLOUT per fd
 * (but you can create multiple fds from the same handle for read and write)
 */
int _libusb_poll(struct pollfd *fds, unsigned int nfds, int timeout)
{
	unsigned i, triggered = 0;
	int index, object_index;
	HANDLE *handles_to_wait_on = malloc(nfds*sizeof(HANDLE));
	int *handle_to_index = malloc(nfds*sizeof(int));
	DWORD nb_handles_to_wait_on = 0;
	DWORD ret;

	CHECK_INIT_POLLING;

	if ((handles_to_wait_on == NULL) || (handle_to_index == NULL)) {
		errno = ENOMEM;
		return -1;
	}

	for (i = 0; i < nfds; ++i) {
		fds[i].revents = 0;

		// Only one of POLLIN or POLLOUT can be selected with this version of poll (not both)
		if ((fds[i].events & ~POLLIN) && (!(fds[i].events & POLLOUT))) {
			fds[i].revents |= POLLERR;
			errno = EACCES;
			printb("_libusb_poll: unsupported set of events\n");
			return -1;
		}

		index = _fd_to_index_and_lock(fds[i].fd);
		if ( (index < 0) || (poll_fd[index].handle == INVALID_HANDLE_VALUE)
		  || (poll_fd[index].handle == 0) || (poll_fd[index].overlapped == NULL)) {
			fds[i].revents |= POLLNVAL | POLLERR;
			errno = EBADF;
			if (index >= 0) {
				LeaveCriticalSection(&_poll_fd[index].mutex);
			}
			printb("_libusb_poll: invalid fd\n");
			return -1;
		}

		// IN or OUT must match our fd direction
		if ((fds[i].events & POLLIN) && (poll_fd[index].rw != RW_READ)) {
			fds[i].revents |= POLLNVAL | POLLERR;
			errno = EBADF;
			printb("_libusb_poll: attempted POLLIN on fd[%d] without READ access\n", i);
			LeaveCriticalSection(&_poll_fd[index].mutex);
			return -1;
		}

		if ((fds[i].events & POLLOUT) && (poll_fd[index].rw != RW_WRITE)) {
			fds[i].revents |= POLLNVAL | POLLERR;
			errno = EBADF;
			printb("_libusb_poll: attempted POLLOUT on fd[%d] without WRITE access\n", i);
			LeaveCriticalSection(&_poll_fd[index].mutex);
			return -1;
		}
		
		printb("_libusb_poll: fd[%d]=%d (overlapped = %p) got events %04X\n", i, poll_fd[index].fd, poll_fd[index].overlapped, fds[i].events);

		// The following macro only works if overlapped I/O was reported pending
		if ( (HasOverlappedIoCompleted(poll_fd[index].overlapped))
		  || (poll_fd[index].completed_synchronously) ) {
			printb("  completed\n");
			// checks above should ensure this works:
			fds[i].revents = fds[i].events;
			triggered++;
		} else {
			handles_to_wait_on[nb_handles_to_wait_on] = poll_fd[index].overlapped->hEvent;
			handle_to_index[nb_handles_to_wait_on] = i;
			nb_handles_to_wait_on++;
		}
		LeaveCriticalSection(&_poll_fd[index].mutex);
	}

	if (triggered != 0)
		return triggered;

	// If nothing was triggered, wait on all fds that require it
	if (nb_handles_to_wait_on != 0)	{
		printb("_libusb_poll: starting %d ms wait for %d handles...\n", timeout, (int)nb_handles_to_wait_on);
		ret = WaitForMultipleObjects(nb_handles_to_wait_on, handles_to_wait_on, 
			FALSE, (timeout==-1)?INFINITE:(DWORD)timeout);

		object_index = ret-WAIT_OBJECT_0;
		if ((object_index >= 0) && ((DWORD)object_index < nb_handles_to_wait_on)) {
			printb("  completed after wait\n");
			i = handle_to_index[object_index];
			index = _fd_to_index_and_lock(fds[i].fd);
			fds[i].revents = fds[i].events;
			triggered++;
			if (index >= 0) {
				LeaveCriticalSection(&_poll_fd[index].mutex);
			}
		} else if (ret == WAIT_TIMEOUT) {
			printb("  timed out\n");
			return 0;	// 0 = timeout
		} else {
			errno = EIO;
			return -1;	// error
		}
	}

	return triggered;
}

/*
 * close a pollable fd
 *
 * Note that this function will also close the associated handle
 */
int _libusb_close(int fd)
{
	int index;
	HANDLE handle;
	int r = -1;

	CHECK_INIT_POLLING;

	index = _fd_to_index_and_lock(fd);

	if (index < 0) {
		errno = EBADF;
	} else {
		handle = poll_fd[index].handle;
		_free_index(index);
		if (CloseHandle(handle) == 0) {
			errno = EIO;
		} else {
			r     = 0;
		}
		LeaveCriticalSection(&_poll_fd[index].mutex);
	}
	return r;
}

/*
 * synchronous write for custom poll (works on Windows file handles that
 * have been opened with the FILE_FLAG_OVERLAPPED flag)
 *
 * Current restrictions: 
 * - binary mode only
 * - no append mode
 */
ssize_t _libusb_write(int fd, const void *buf, size_t count)
{
	int index;
	DWORD wr_count;
	int r = -1;

	CHECK_INIT_POLLING;

	index = _fd_to_index_and_lock(fd);

	if (count == 0) {
		return 0;
	}

	if ( (index < 0) || (poll_fd[index].overlapped == NULL) 
	  || (poll_fd[index].rw != RW_WRITE) ) {
		errno = EBADF;
		if (index >= 0) {
			LeaveCriticalSection(&_poll_fd[index].mutex);
		}
		return -1;
	}

	// For sync mode, we shouldn't get pending async write I/O
	if (!HasOverlappedIoCompleted(poll_fd[index].overlapped)) {
		printb("_libusb_write: previous write I/O was flagged pending!\n");
		CancelIo(poll_fd[index].handle);
	}

	printb("_libusb_write: writing %d bytes to fd=%d\n", count, poll_fd[index].fd);

	reset_overlapped(poll_fd[index].overlapped);
	if (!WriteFile(poll_fd[index].handle, buf, (DWORD)count, &wr_count, poll_fd[index].overlapped)) {
		if(GetLastError() == ERROR_IO_PENDING) {
			// I/O started but is not completed => wait till completion
			switch(WaitForSingleObject(poll_fd[index].overlapped->hEvent, INFINITE)) 
			{
			case WAIT_OBJECT_0:
				if (GetOverlappedResult(poll_fd[index].handle, 
					poll_fd[index].overlapped, &wr_count, FALSE)) {
					r     = 0;
					goto out;
				} else {
					printb("_libusb_write: GetOverlappedResult failed with error %d\n", (int)GetLastError());
					errno = EIO;
					goto out;
				}
			default:
				errno = EIO;
				goto out;
			}
		} else {
			// I/O started and failed
			printb("_libusb_write: WriteFile failed with error %d\n", (int)GetLastError());
			errno = EIO;
			goto out;
		}
	}

	// I/O started and completed synchronously
	r     = 0;

out:
	if (r) {
		reset_overlapped(poll_fd[index].overlapped);
		LeaveCriticalSection(&_poll_fd[index].mutex);
		return -1;
	} else {
		LeaveCriticalSection(&_poll_fd[index].mutex);
		return (ssize_t)wr_count;
	}
}

/*
 * synchronous read for custom poll (works on Windows file handles that
 * have been opened with the FILE_FLAG_OVERLAPPED flag)
 */
ssize_t _libusb_read(int fd, void *buf, size_t count)
{
	int index;
	DWORD rd_count;
	int r = -1;

	CHECK_INIT_POLLING;

	if (count == 0) {
		return 0;
	}

	index = _fd_to_index_and_lock(fd);

	if (index < 0) {
		errno = EBADF;
		return -1;
	}

	if (poll_fd[index].rw != RW_READ) {
		errno = EBADF;
		goto out;
	}


	// still waiting for completion => force completion
	if (!HasOverlappedIoCompleted(poll_fd[index].overlapped)) {
		if (WaitForSingleObject(poll_fd[index].overlapped->hEvent, INFINITE) != WAIT_OBJECT_0) {
			printb("_libusb_read: waiting for marker failed: %d\n", (int)GetLastError());
			errno = EIO;
			goto out;
		}
	}

	// Find out if we've read the first byte
	if (!GetOverlappedResult(poll_fd[index].handle,	poll_fd[index].overlapped, &rd_count, FALSE)) {
		if (GetLastError() != ERROR_MORE_DATA) {
			printb("_libusb_read: readout of marker failed: %d\n", (int)GetLastError());
			errno = EIO;
			goto out;
		} else {
			printb("_libusb_read: readout of marker reported more data\n");
		}
	}

	printb("_libusb_read: count = %d, rd_count(marker) = %d\n", count, (int)rd_count);

	// We should have our marker by now
	if (rd_count != 1) {
		printb("_libusb_read: unexpected number of bytes for marker (%d)\n", (int)rd_count);
		errno = EIO;
		goto out;
	}

	((BYTE*)buf)[0] = _poll_fd[index].marker;

	// Read supplementary bytes if needed (blocking)
	if (count > 1) {
		reset_overlapped(poll_fd[index].overlapped);
		if (!ReadFile(poll_fd[index].handle, (char*)buf+1, (DWORD)(count-1), &rd_count, poll_fd[index].overlapped)) {
			if(GetLastError() == ERROR_IO_PENDING) {
				if (!GetOverlappedResult(poll_fd[index].handle,	poll_fd[index].overlapped, &rd_count, TRUE)) {
					// TODO: handle more data!
					printb("_libusb_read: readout of supplementary data failed: %d\n", (int)GetLastError());
					errno = EIO;
					goto out;
				}
			} else {
				printb("_libusb_read: could not start blocking read of supplementary: %d\n", (int)GetLastError());
				errno = EIO;
				goto out;
			}
		}
		// If ReadFile completed synchronously, we're fine too

		printb("_libusb_read: rd_count(supplementary ) = %d\n", (int)rd_count);

		if ((rd_count+1) != count) {
			printb("_libusb_read: wanted %d-1, got %d\n", count, (int)rd_count);
			errno = EIO;
			goto out;
		}
	}

	r = 0;

out:
	// Setup pending read I/O for the marker
	_init_read_marker(index);
	LeaveCriticalSection(&_poll_fd[index].mutex);
	if (r)
		return -1;
	else
		return count;
}
