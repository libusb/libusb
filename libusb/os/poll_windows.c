/*
 * poll_windows: poll compatibility wrapper for Windows
 * Copyright (C) 2009-2010 Pete Batard <pbatard@gmail.com>
 * With contributions from Michael Plante, Orin Eman et al.
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
 * poll() and pipe() Windows compatibility layer for libusb 1.0
 *
 * The way this layer works is by using OVERLAPPED with async I/O transfers, as
 * OVERLAPPED have an associated event which is flagged for I/O completion.
 *
 * For USB pollable async I/O, you would typically:
 * - obtain a Windows HANDLE to a file or device that has been opened in
 *   OVERLAPPED mode
 * - call usbi_create_fd with this handle to obtain a custom fd.
 *   Note that if you need simultaneous R/W access, you need to call create_fd
 *   twice, once in _O_RDONLY and once in _O_WRONLY mode to obtain 2 separate
 *   pollable fds
 * - leave the core functions call the poll routine and flag POLLIN/POLLOUT
 *
 * The pipe pollable synchronous I/O works using the overlapped event associated
 * with a fake pipe. The read/write functions are only meant to be used in that
 * context.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <io.h>

#include <libusbi.h>

// Uncomment to debug the polling layer
//#define DEBUG_POLL_WINDOWS
#if defined(DEBUG_POLL_WINDOWS)
#define poll_dbg usbi_dbg
#else
// MSVC6 cannot use a variadic argument and non MSVC
// compilers produce warnings if parenthesis are ommitted.
#if defined(_MSC_VER)
#define poll_dbg
#else
#define poll_dbg(...)
#endif
#endif

#if defined(_PREFAST_)
#pragma warning(disable:28719)
#endif

#if defined(__CYGWIN__)
// cygwin produces a warning unless these prototypes are defined
extern int _close(int fd);
extern int _snprintf(char *buffer, size_t count, const char *format, ...);
extern int cygwin_attach_handle_to_fd(char *name, int fd, HANDLE handle, int bin, int access_mode);
// _open_osfhandle() is not available on cygwin, but we can emulate
// it for our needs with cygwin_attach_handle_to_fd()
static inline int _open_osfhandle(intptr_t osfhandle, int flags)
{
	int access_mode;
	switch (flags) {
	case _O_RDONLY:
		access_mode = GENERIC_READ;
		break;
	case _O_WRONLY:
		access_mode = GENERIC_WRITE;
		break;
	case _O_RDWR:
		access_mode = GENERIC_READ|GENERIC_WRITE;
		break;
	default:
		usbi_err(NULL, "unsupported access mode");
		return -1;
	}
	return cygwin_attach_handle_to_fd("/dev/null", -1, (HANDLE)osfhandle, -1, access_mode);
}
#endif

#define CHECK_INIT_POLLING do {if(!is_polling_set) init_polling();} while(0)

// public fd data
const struct winfd INVALID_WINFD = {-1, INVALID_HANDLE_VALUE, NULL, RW_NONE};
struct winfd poll_fd[MAX_FDS];
// internal fd data
struct {
	CRITICAL_SECTION mutex; // lock for fds
	// Additional variables for XP CancelIoEx partial emulation
	HANDLE original_handle;
	DWORD thread_id;
} _poll_fd[MAX_FDS];

// globals
BOOLEAN is_polling_set = FALSE;
#if defined(DYNAMIC_FDS)
HANDLE fd_update = INVALID_HANDLE_VALUE;	// event to notify poll of fd update
HANDLE new_fd[MAX_FDS];		// overlapped event handles for fds created since last poll
unsigned nb_new_fds = 0;	// nb new fds created since last poll
usbi_mutex_t new_fd_mutex;	// mutex required for the above
#endif
LONG pipe_number = 0;
static volatile LONG compat_spinlock = 0;

// CancelIoEx, available on Vista and later only, provides the ability to cancel
// a single transfer (OVERLAPPED) when used. As it may not be part of any of the
// platform headers, we hook into the Kernel32 system DLL directly to seek it.
static BOOL (__stdcall *pCancelIoEx)(HANDLE, LPOVERLAPPED) = NULL;
#define CancelIoEx_Available (pCancelIoEx != NULL)
__inline BOOL cancel_io(int index)
{
	if ((index < 0) || (index >= MAX_FDS)) {
		return FALSE;
	}

	if ( (poll_fd[index].fd < 0) || (poll_fd[index].handle == INVALID_HANDLE_VALUE)
	  || (poll_fd[index].handle == 0) || (poll_fd[index].overlapped == NULL) ) {
		return TRUE;
	}
	if (CancelIoEx_Available) {
		return (*pCancelIoEx)(poll_fd[index].handle, poll_fd[index].overlapped);
	}
	if (_poll_fd[index].thread_id == GetCurrentThreadId()) {
		return CancelIo(poll_fd[index].handle);
	}
	usbi_warn(NULL, "Unable to cancel I/O that was started from another thread");
	return FALSE;
}

// Init
void init_polling(void)
{
	int i;

	while (InterlockedExchange((LONG *)&compat_spinlock, 1) == 1) {
		SleepEx(0, TRUE);
	}
	if (!is_polling_set) {
		pCancelIoEx = (BOOL (__stdcall *)(HANDLE,LPOVERLAPPED))
			GetProcAddress(GetModuleHandle("KERNEL32"), "CancelIoEx");
		usbi_dbg("Will use CancelIo%s for I/O cancellation",
			CancelIoEx_Available?"Ex":"");
		for (i=0; i<MAX_FDS; i++) {
			poll_fd[i] = INVALID_WINFD;
			_poll_fd[i].original_handle = INVALID_HANDLE_VALUE;
			_poll_fd[i].thread_id = 0;
			InitializeCriticalSection(&_poll_fd[i].mutex);
		}
#if defined(DYNAMIC_FDS)
		// We need to create an update event so that poll is warned when there
		// are new/deleted fds during a timeout wait operation
		fd_update = CreateEvent(NULL, TRUE, FALSE, NULL);
		if (fd_update == NULL) {
			usbi_err(NULL, "unable to create update event");
		}
		usbi_mutex_init(&new_fd_mutex, NULL);
		nb_new_fds = 0;
#endif
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
			cancel_io(i);
			// If anything was pending on that I/O, it should be
			// terminating, and we should be able to access the fd
			// mutex lock before too long
			EnterCriticalSection(&_poll_fd[i].mutex);
			if ( (poll_fd[i].fd > 0) && (poll_fd[i].handle != INVALID_HANDLE_VALUE) && (poll_fd[i].handle != 0)
			  && (GetFileType(poll_fd[i].handle) == FILE_TYPE_UNKNOWN) ) {
				_close(poll_fd[i].fd);
			}
			free_overlapped(poll_fd[i].overlapped);
			if (!CancelIoEx_Available) {
				// Close duplicate handle
				if (_poll_fd[i].original_handle != INVALID_HANDLE_VALUE) {
					CloseHandle(poll_fd[i].handle);
				}
			}
			poll_fd[i] = INVALID_WINFD;
#if defined(DYNAMIC_FDS)
			usbi_mutex_destroy(&new_fd_mutex);
			CloseHandle(fd_update);
			fd_update = INVALID_HANDLE_VALUE;
#endif
			LeaveCriticalSection(&_poll_fd[i].mutex);
			DeleteCriticalSection(&_poll_fd[i].mutex);
		}
	}
	compat_spinlock = 0;
}

/*
 * Create a fake pipe.
 * As libusb only uses pipes for signaling, all we need from a pipe is an
 * event. To that extent, we create a single wfd and overlapped as a means
 * to access that event.
 */
int usbi_pipe(int filedes[2])
{
	int i;
	HANDLE handle;
	OVERLAPPED* overlapped;

	CHECK_INIT_POLLING;

	overlapped = calloc(1, sizeof(OVERLAPPED));
	if (overlapped == NULL) {
		return -1;
	}
	// The overlapped must have status pending for signaling to work in poll
	overlapped->Internal = STATUS_PENDING;
	overlapped->InternalHigh = 0;

	// Read end of the "pipe"
	handle = CreateFileA("NUL", 0, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (handle == INVALID_HANDLE_VALUE) {
		usbi_err(NULL, "could not create pipe: errcode %d", (int)GetLastError());
		goto out1;
	}
	filedes[0] = _open_osfhandle((intptr_t)handle, _O_RDONLY);
	// We can use the same handle for both ends
	filedes[1] = filedes[0];
	poll_dbg("pipe filedes = %d", filedes[0]);

	// Note: manual reset must be true (second param) as the reset occurs in read
	overlapped->hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if(!overlapped->hEvent) {
		goto out2;
	}

	for (i=0; i<MAX_FDS; i++) {
		if (poll_fd[i].fd < 0) {
			EnterCriticalSection(&_poll_fd[i].mutex);
			// fd might have been allocated before we got to critical
			if (poll_fd[i].fd >= 0) {
				LeaveCriticalSection(&_poll_fd[i].mutex);
				continue;
			}

			poll_fd[i].fd = filedes[0];
			poll_fd[i].handle = handle;
			poll_fd[i].overlapped = overlapped;
			// There's no polling on the write end, so we just use READ for our needs
			poll_fd[i].rw = RW_READ;
			_poll_fd[i].original_handle = INVALID_HANDLE_VALUE;
			LeaveCriticalSection(&_poll_fd[i].mutex);
			return 0;
		}
	}

	CloseHandle(overlapped->hEvent);
out2:
	CloseHandle(handle);
out1:
	free(overlapped);
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
struct winfd usbi_create_fd(HANDLE handle, int access_mode)
{
	int i, fd;
	struct winfd wfd = INVALID_WINFD;
	OVERLAPPED* overlapped = NULL;

	CHECK_INIT_POLLING;

	if ((handle == 0) || (handle == INVALID_HANDLE_VALUE)) {
		return INVALID_WINFD;
	}

	if ((access_mode != _O_RDONLY) && (access_mode != _O_WRONLY)) {
		usbi_warn(NULL, "only one of _O_RDONLY or _O_WRONLY are supported.\n"
			"If you want to poll for R/W simultaneously, create multiple fds from the same handle.");
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
			// Attempt to emulate some of the CancelIoEx behaviour on platforms
			// that don't have it
			if (!CancelIoEx_Available) {
				_poll_fd[i].thread_id = GetCurrentThreadId();
				if (!DuplicateHandle(GetCurrentProcess(), handle, GetCurrentProcess(),
					&wfd.handle, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
					usbi_dbg("could not duplicate handle for CancelIo - using original one");
					wfd.handle = handle;
					// Make sure we won't close the original handle on fd deletion then
					_poll_fd[i].original_handle = INVALID_HANDLE_VALUE;
				} else {
					_poll_fd[i].original_handle = handle;
				}
			} else {
				wfd.handle = handle;
			}
			wfd.overlapped = overlapped;
			memcpy(&poll_fd[i], &wfd, sizeof(struct winfd));
			LeaveCriticalSection(&_poll_fd[i].mutex);
#if defined(DYNAMIC_FDS)
			usbi_mutex_lock(&new_fd_mutex);
			new_fd[nb_new_fds++] = overlapped->hEvent;
			usbi_mutex_unlock(&new_fd_mutex);
			// Notify poll that fds have been updated
			SetEvent(fd_update);
#endif
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
	cancel_io(index);
	// close fake handle for devices
	if ( (poll_fd[index].handle != INVALID_HANDLE_VALUE) && (poll_fd[index].handle != 0)
	  && (GetFileType(poll_fd[index].handle) == FILE_TYPE_UNKNOWN) ) {
		_close(poll_fd[index].fd);
	}
	// close the duplicate handle (if we have an actual duplicate)
	if (!CancelIoEx_Available) {
		if (_poll_fd[index].original_handle != INVALID_HANDLE_VALUE) {
			CloseHandle(poll_fd[index].handle);
		}
		_poll_fd[index].original_handle = INVALID_HANDLE_VALUE;
		_poll_fd[index].thread_id = 0;
	}
	free_overlapped(poll_fd[index].overlapped);
	poll_fd[index] = INVALID_WINFD;
}

/*
 * Release a pollable file descriptor.
 *
 * Note that the associated Windows handle is not closed by this call
 */
void usbi_free_fd(int fd)
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
int usbi_poll(struct pollfd *fds, unsigned int nfds, int timeout)
{
	unsigned i;
	int index, object_index, triggered;
	HANDLE *handles_to_wait_on;
	int *handle_to_index;
	DWORD nb_handles_to_wait_on = 0;
	DWORD ret;

#if defined(DYNAMIC_FDS)
	DWORD nb_extra_handles = 0;
	unsigned j;

	// To address the possibility of missing new fds between the time the new
	// pollable fd set is assembled, and the ResetEvent() call below, an
	// additional new_fd[] HANDLE table is used for any new fd that was created
	// since the last call to poll (see below)
	ResetEvent(fd_update);

	// At this stage, any new fd creation will be detected through the fd_update
	// event notification, and any previous creation that we may have missed
	// will be picked up through the existing new_fd[] table.
#endif

	CHECK_INIT_POLLING;

	triggered = 0;
	handles_to_wait_on = malloc((nfds+1)*sizeof(HANDLE));	// +1 for fd_update
	handle_to_index = malloc(nfds*sizeof(int));
	if ((handles_to_wait_on == NULL) || (handle_to_index == NULL)) {
		errno = ENOMEM;
		triggered = -1;
		goto poll_exit;
	}

	for (i = 0; i < nfds; ++i) {
		fds[i].revents = 0;

		// Only one of POLLIN or POLLOUT can be selected with this version of poll (not both)
		if ((fds[i].events & ~POLLIN) && (!(fds[i].events & POLLOUT))) {
			fds[i].revents |= POLLERR;
			errno = EACCES;
			usbi_warn(NULL, "unsupported set of events");
			triggered = -1;
			goto poll_exit;
		}

		index = _fd_to_index_and_lock(fds[i].fd);
		poll_dbg("fd[%d]=%d: (overlapped=%p) got events %04X", i, poll_fd[index].fd, poll_fd[index].overlapped, fds[i].events);

		if ( (index < 0) || (poll_fd[index].handle == INVALID_HANDLE_VALUE)
		  || (poll_fd[index].handle == 0) || (poll_fd[index].overlapped == NULL)) {
			fds[i].revents |= POLLNVAL | POLLERR;
			errno = EBADF;
			if (index >= 0) {
				LeaveCriticalSection(&_poll_fd[index].mutex);
			}
			usbi_warn(NULL, "invalid fd");
			triggered = -1;
			goto poll_exit;
		}

		// IN or OUT must match our fd direction
		if ((fds[i].events & POLLIN) && (poll_fd[index].rw != RW_READ)) {
			fds[i].revents |= POLLNVAL | POLLERR;
			errno = EBADF;
			usbi_warn(NULL, "attempted POLLIN on fd without READ access");
			LeaveCriticalSection(&_poll_fd[index].mutex);
			triggered = -1;
			goto poll_exit;
		}

		if ((fds[i].events & POLLOUT) && (poll_fd[index].rw != RW_WRITE)) {
			fds[i].revents |= POLLNVAL | POLLERR;
			errno = EBADF;
			usbi_warn(NULL, "attempted POLLOUT on fd without WRITE access");
			LeaveCriticalSection(&_poll_fd[index].mutex);
			triggered = -1;
			goto poll_exit;
		}

		// The following macro only works if overlapped I/O was reported pending
		if ( (HasOverlappedIoCompleted(poll_fd[index].overlapped))
		  || (HasOverlappedIoCompletedSync(poll_fd[index].overlapped)) ) {
			poll_dbg("  completed");
			// checks above should ensure this works:
			fds[i].revents = fds[i].events;
			triggered++;
		} else {
			handles_to_wait_on[nb_handles_to_wait_on] = poll_fd[index].overlapped->hEvent;
			handle_to_index[nb_handles_to_wait_on] = i;
#if defined(DYNAMIC_FDS)
			// If this fd from the poll set is also part of the new_fd event handle table, remove it
			usbi_mutex_lock(&new_fd_mutex);
			for (j=0; j<nb_new_fds; j++) {
				if (handles_to_wait_on[nb_handles_to_wait_on] == new_fd[j]) {
					new_fd[j] = INVALID_HANDLE_VALUE;
					break;
				}
			}
			usbi_mutex_unlock(&new_fd_mutex);
#endif
			nb_handles_to_wait_on++;
		}
		LeaveCriticalSection(&_poll_fd[index].mutex);
	}
#if defined(DYNAMIC_FDS)
	// At this stage, new_fd[] should only contain events from fds that
	// have been added since the last call to poll, but are not (yet) part
	// of the pollable fd set. Typically, these would be from fds that have
	// been created between the construction of the fd set and the calling
	// of poll.
	// Event if we won't be able to return usable poll data on these events,
	// make sure we monitor them to return an EINTR code
	usbi_mutex_lock(&new_fd_mutex); // We could probably do without
	for (i=0; i<nb_new_fds; i++) {
		if (new_fd[i] != INVALID_HANDLE_VALUE) {
			handles_to_wait_on[nb_handles_to_wait_on++] = new_fd[i];
			nb_extra_handles++;
		}
	}
	usbi_mutex_unlock(&new_fd_mutex);
	poll_dbg("dynamic_fds: added %d extra handles", nb_extra_handles);
#endif

	// If nothing was triggered, wait on all fds that require it
	if ((timeout != 0) && (triggered == 0) && (nb_handles_to_wait_on != 0)) {
#if defined(DYNAMIC_FDS)
		// Register for fd update notifications
		handles_to_wait_on[nb_handles_to_wait_on++] = fd_update;
		nb_extra_handles++;
#endif
		if (timeout < 0) {
			poll_dbg("starting infinite wait for %d handles...", (int)nb_handles_to_wait_on);
		} else {
			poll_dbg("starting %d ms wait for %d handles...", timeout, (int)nb_handles_to_wait_on);
		}
		ret = WaitForMultipleObjects(nb_handles_to_wait_on, handles_to_wait_on,
			FALSE, (timeout<0)?INFINITE:(DWORD)timeout);
		object_index = ret-WAIT_OBJECT_0;
		if ((object_index >= 0) && ((DWORD)object_index < nb_handles_to_wait_on)) {
#if defined(DYNAMIC_FDS)
			if ((DWORD)object_index >= (nb_handles_to_wait_on-nb_extra_handles)) {
				// Detected fd update => flag a poll interruption
				if ((DWORD)object_index == (nb_handles_to_wait_on-1))
					poll_dbg("  dynamic_fds: fd_update event");
				else
					poll_dbg("  dynamic_fds: new fd I/O event");
				errno = EINTR;
				triggered = -1;
				goto poll_exit;
			}
#endif
			poll_dbg("  completed after wait");
			i = handle_to_index[object_index];
			index = _fd_to_index_and_lock(fds[i].fd);
			fds[i].revents = fds[i].events;
			triggered++;
			if (index >= 0) {
				LeaveCriticalSection(&_poll_fd[index].mutex);
			}
		} else if (ret == WAIT_TIMEOUT) {
			poll_dbg("  timed out");
			triggered = 0;	// 0 = timeout
		} else {
			errno = EIO;
			triggered = -1;	// error
		}
	}

poll_exit:
	if (handles_to_wait_on != NULL) {
		free(handles_to_wait_on);
	}
	if (handle_to_index != NULL) {
		free(handle_to_index);
	}
#if defined(DYNAMIC_FDS)
	usbi_mutex_lock(&new_fd_mutex);
	nb_new_fds = 0;
	usbi_mutex_unlock(&new_fd_mutex);
#endif
	return triggered;
}

/*
 * close a fake pipe fd
 */
int usbi_close(int fd)
{
	int index;
	int r = -1;

	CHECK_INIT_POLLING;

	index = _fd_to_index_and_lock(fd);

	if (index < 0) {
		errno = EBADF;
	} else {
		if (poll_fd[index].overlapped != NULL) {
			// Must be a different event for each end of the pipe
			CloseHandle(poll_fd[index].overlapped->hEvent);
			free(poll_fd[index].overlapped);
		}
		if (CloseHandle(poll_fd[index].handle) == 0) {
			errno = EIO;
		} else {
			r = 0;
		}
		poll_fd[index] = INVALID_WINFD;
		LeaveCriticalSection(&_poll_fd[index].mutex);
	}
	return r;
}

/*
 * synchronous write for fake "pipe" signaling
 */
ssize_t usbi_write(int fd, const void *buf, size_t count)
{
	int index;

	CHECK_INIT_POLLING;

	if (count != sizeof(unsigned char)) {
		usbi_err(NULL, "this function should only used for signaling");
		return -1;
	}

	index = _fd_to_index_and_lock(fd);

	if ( (index < 0) || (poll_fd[index].overlapped == NULL) ) {
		errno = EBADF;
		if (index >= 0) {
			LeaveCriticalSection(&_poll_fd[index].mutex);
		}
		return -1;
	}

	poll_dbg("set pipe event (fd = %d, thread = %08X)", index, GetCurrentThreadId());
	SetEvent(poll_fd[index].overlapped->hEvent);
	poll_fd[index].overlapped->Internal = STATUS_WAIT_0;
	// If two threads write on the pipe at the same time, we need to
	// process two separate reads => use the overlapped as a counter
	poll_fd[index].overlapped->InternalHigh++;

	LeaveCriticalSection(&_poll_fd[index].mutex);
	return sizeof(unsigned char);
}

/*
 * synchronous read for fake "pipe" signaling
 */
ssize_t usbi_read(int fd, void *buf, size_t count)
{
	int index;
	ssize_t r = -1;

	CHECK_INIT_POLLING;

	if (count != sizeof(unsigned char)) {
		usbi_err(NULL, "this function should only used for signaling");
		return -1;
	}

	index = _fd_to_index_and_lock(fd);

	if (index < 0) {
		errno = EBADF;
		return -1;
	}

	if (WaitForSingleObject(poll_fd[index].overlapped->hEvent, INFINITE) != WAIT_OBJECT_0) {
		usbi_warn(NULL, "waiting for event failed: %d", (int)GetLastError());
		errno = EIO;
		goto out;
	}

	poll_dbg("clr pipe event (fd = %d, thread = %08X)", index, GetCurrentThreadId());
	poll_fd[index].overlapped->InternalHigh--;
	// Don't reset unless we don't have any more events to process
	if (poll_fd[index].overlapped->InternalHigh <= 0) {
		ResetEvent(poll_fd[index].overlapped->hEvent);
		poll_fd[index].overlapped->Internal = STATUS_PENDING;
	}

	r = sizeof(unsigned char);

out:
	LeaveCriticalSection(&_poll_fd[index].mutex);
	return r;
}
