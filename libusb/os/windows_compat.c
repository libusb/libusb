/*
 * Windows compat: POSIX compatibility wrapper
 *
 * pipe implementation from mlton (http://www.mlton.org - runtime/platform/mingw.c):
 * -----------------------------------------------------------------------------
 * This is the license for MLton, a whole-program optimizing compiler for
 * the Standard ML programming language.  Send comments and questions to
 * MLton@mlton.org.
 *
 * MLton COPYRIGHT NOTICE, LICENSE AND DISCLAIMER.
 *
 * Copyright (C) 1999-2009 Henry Cejtin, Matthew Fluet, Suresh
 *    Jagannathan, and Stephen Weeks.
 * Copyright (C) 1997-2000 by the NEC Research Institute
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted,
 * provided that the above copyright notice appear in all copies and that
 * both the copyright notice and this permission notice and warranty
 * disclaimer appear in supporting documentation, and that the name of
 * the above copyright holders, or their entities, not be used in
 * advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission.

 * The above copyright holders disclaim all warranties with regard to
 * this software, including all implied warranties of merchantability and
 * fitness. In no event shall the above copyright holders be liable for
 * any special, indirect or consequential damages or any damages
 * whatsoever resulting from loss of use, data or profits, whether in an
 * action of contract, negligence or other tortious action, arising out
 * of or in connection with the use or performance of this software.
 * -----------------------------------------------------------------------------
 *
 *
 * parts of poll implementation from libusb-win32 v1, by Stephan Meyer et al.
 *
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <windows.h>

#include "windows_compat.h"

int pipe (int filedes[2]) {
        HANDLE read_h;
        HANDLE write_h;

        /* We pass no security attributes (0), so the current policy gets
         * inherited. The pipe is set to NOT stay open in child processes.
         * This will be corrected using DuplicateHandle in create()
         * The 4k buffersize is choosen b/c that's what linux uses.
         */
        if (!CreatePipe(&read_h, &write_h, 0, 4096)) {
                errno = ENOMEM; /* fake errno: out of resources */
                return -1;
        }
        /* This requires Win98+
         * Choosing text/binary mode is defered till a later setbin/text call
         */
        filedes[0] = _open_osfhandle((intptr_t)read_h,  _O_RDONLY);
        filedes[1] = _open_osfhandle((intptr_t)write_h, _O_WRONLY);
        if ((filedes[0] == -1) || (filedes[1] == -1)) {
                if (filedes[0] == -1)
                        CloseHandle(read_h);
                else    close(filedes[0]);
                if (filedes[1] == -1)
                        CloseHandle(write_h);
                else    close(filedes[1]);

                errno = ENFILE;
                return -1;
        }
        return 0;
}

// Rudimentary poll using OVERLAPPED
int windows_poll(struct pollfd *fds, unsigned int nfds, int timeout)
{
	int i, triggered = 0;
	OVERLAPPED* io;

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
		if (i==0)
			continue;

		// All the fds above 1 are actually OVERLAPPED pointers converted to int
		io = (OVERLAPPED*)fds[i].fd;

		printf("windows_poll: fd[%d] (fd = %p) got events %04X\n", i, io, fds[i].events);

		if (HasOverlappedIoCompleted(io)) {
			printf("  completed\n");
			fds[i].revents |= POLLIN;
			triggered++;
		} else {
			switch(WaitForSingleObject(io->hEvent, (timeout==-1)?INFINITE:timeout)) 
			{
			case WAIT_OBJECT_0:
				printf("  completed after wait\n");
				fds[i].revents |= POLLIN;
				triggered++;
				break;
			case WAIT_TIMEOUT:
				printf("  timed out\n");
				break;
			default:
				fds[i].revents |= POLLERR;
				break;
			}
		}
	}

	return triggered;
}
