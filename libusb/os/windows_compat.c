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
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <windows.h>
#include <pthread.h>

#include "windows_compat.h"

#ifndef FILE_FLAG_FIRST_PIPE_INSTANCE
#define FILE_FLAG_FIRST_PIPE_INSTANCE 524288
#endif

#define CHECK_INIT_OVERLAPPED do {if(!is_overlapped_set) init_overlapped();} while(0)

struct pseudo_fd {
	int fd;
	OVERLAPPED* overlapped;
};

int is_overlapped_set = 0;
unsigned short pipe_number = 0;
struct pseudo_fd overlapped_fd[MAX_FDS];

int libusb_pipe(int filedes[2])
{
	int i, j;
	OVERLAPPED *overlapped = calloc(2, sizeof(OVERLAPPED));
	char pipe_name[] = "\\\\.\\pipe\\libusb000000000000";

	CHECK_INIT_OVERLAPPED;

	if (overlapped == NULL) {
		return -1;
	}

	sprintf(pipe_name, "\\\\.\\pipe\\libusb%08x%04x", (unsigned)GetCurrentProcessId(), pipe_number++);

	filedes[0] = _open_osfhandle((intptr_t)CreateNamedPipeA(pipe_name, PIPE_ACCESS_INBOUND|FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE, 1, 4096, 4096, 0, NULL), _O_RDONLY);
	if (filedes[0] < 0) {
		printf("Could not create read pipe: errcode %d\n", (int)GetLastError());
		goto out1;
	}

    filedes[1] = _open_osfhandle((intptr_t)CreateFileA(pipe_name, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OVERLAPPED, NULL), _O_WRONLY);
	if (filedes[1] < 0) {
		printf("Could not create write pipe: errcode %d\n", (int)GetLastError());
		goto out2;
	}

	// Now let's set ourselves some overlapped
	overlapped[0].hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if(!overlapped[0].hEvent) {
		goto out3;
	}
	overlapped[1].hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if(!overlapped[1].hEvent) {
		goto out4;
	}

	// ideally, you'd need a mutex lock here. However, we don't have 
	// access to the context locks through the pipe call..
	// TODO: create our own mutex?
	for (i=0, j=0; i<MAX_FDS; i++) {
		if (overlapped_fd[i].overlapped == NULL) {
			overlapped_fd[i].fd = filedes[j];
			overlapped_fd[i].overlapped = &overlapped[j++];
			if (j == 2)
				return 0;
		}
	}

	CloseHandle(overlapped[1].hEvent);
out4:
	CloseHandle(overlapped[0].hEvent);
out3:
	_close(filedes[1]);
out2:
	_close(filedes[0]);
out1:
	free(overlapped);
	return -1;
}

// TODO: better (faster!) fd <-> overlapped handling in all these functions
int create_overlapped(void* pollfds_lock)
{
	int i, fd;
	OVERLAPPED* overlapped = calloc(1, sizeof(OVERLAPPED));
	pthread_mutex_t *mutex_lock = (pthread_mutex_t*)pollfds_lock;

	CHECK_INIT_OVERLAPPED;

	if(overlapped == NULL)
		return -1;

	// We need a fd that's assigned by the system to avoid conflict with any
	// fd that was generated for pipes (can't use a homemade fd system here)
	// Don't care about the file, so just use NUL: to get an fd
	fd = _open_osfhandle((intptr_t)CreateFileA("NUL", GENERIC_WRITE, FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, 0, NULL), _O_WRONLY);
	if (fd < 0) {
		free(overlapped);
		return -1;
	}

	overlapped->hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if(!overlapped->hEvent) {
		free(overlapped);
		_close(fd);
		return -1;
	}
	// Bad things might happen if we don't protect this loop
	pthread_mutex_lock(mutex_lock);
	for (i=0; i<MAX_FDS; i++) {
		if (overlapped_fd[i].overlapped == NULL) {
			overlapped_fd[i].fd = fd;
			overlapped_fd[i].overlapped = overlapped;
			pthread_mutex_unlock(mutex_lock);
			return fd;
		}
	}
	pthread_mutex_unlock(mutex_lock);
	CloseHandle(overlapped->hEvent);
	_close(fd);
	free(overlapped);
	return -1;
}

void free_overlapped(int fd)
{
	int i;

	CHECK_INIT_OVERLAPPED;

	for (i=0; i<MAX_FDS; i++) {
		if ( (overlapped_fd[i].fd == fd)
		  && (overlapped_fd[i].overlapped != NULL) )
		{
			_close(overlapped_fd[i].fd);
			CloseHandle(overlapped_fd[i].overlapped->hEvent);
			free(overlapped_fd[i].overlapped);
			overlapped_fd[i].fd = -1;
			overlapped_fd[i].overlapped = NULL;
			return;
		}
	}
}

void init_overlapped(void)
{
	int i;
	if (is_overlapped_set)
		return;
	is_overlapped_set = -1;
	for (i=0; i<MAX_FDS; i++) {
		overlapped_fd[i].fd = -1;
		overlapped_fd[i].overlapped = NULL;
	}
}

void* fd_to_overlapped(int fd)
{
	int i;

	CHECK_INIT_OVERLAPPED;

	for (i=0; i<MAX_FDS; i++) {
		if (overlapped_fd[i].fd == fd)
			return overlapped_fd[i].overlapped;
	}
	return NULL;
}

int overlapped_to_fd(void* overlapped)
{
	int i;

	CHECK_INIT_OVERLAPPED;

	if (overlapped == NULL)
		return -1;
	for (i=0; i<MAX_FDS; i++) {
		if (overlapped_fd[i].overlapped == overlapped)
			return overlapped_fd[i].fd;
	}
	return -1;
}

// Rudimentary poll using OVERLAPPED
int libusb_poll(struct pollfd *fds, unsigned int nfds, int timeout)
{
	int i, triggered = 0;
	OVERLAPPED* overlapped;

	CHECK_INIT_OVERLAPPED;

	for (i = 0; i < nfds; ++i) {
		fds[i].revents = 0;

		/* form io.c:
		 * -# During initialization, libusb opens an internal pipe, and it adds the read
		 *    end of this pipe to the set of file descriptors to be polled.
		 * -# During libusb_close(), libusb writes some dummy data on this control pipe.
		 *    This immediately interrupts the event handler. libusb also records
		 *    internally that it is trying to interrupt event handlers for this
		 *    high-priority event.
		 */
		// TODO: for now, we just ignore the control pipe
//		if (i==0)
//			continue;

		overlapped = fd_to_overlapped(fds[i].fd);
		printf("windows_poll: fd[%d] (overlapped = %p) got events %04X\n", i, overlapped, fds[i].events);

		if (overlapped == NULL) {
			fds[i].revents |= POLLERR;
			return -1;
		}

		if (HasOverlappedIoCompleted(overlapped)) {
			printf("  completed\n");
			fds[i].revents |= POLLIN;
			triggered++;
		} else {
			switch(WaitForSingleObject(overlapped->hEvent, (timeout==-1)?INFINITE:timeout)) 
			{
			case WAIT_OBJECT_0:
				printf("  completed after wait\n");
				fds[i].revents |= POLLIN;
				triggered++;
				break;
			case WAIT_TIMEOUT:
				printf("  timed out\n");
				return 0;	// 0 = timeout
			default:
				fds[i].revents |= POLLERR;
				return -1;	// error
				break;
			}
		}
	}

	return triggered;
}
