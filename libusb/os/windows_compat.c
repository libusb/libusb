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
 * poll implementation from polipo (http://www.pps.jussieu.fr/~jch/software/polipo/):
 * -----------------------------------------------------------------------------
 * Copyright (c) 2006 by Dan Kennedy.
 * Copyright (c) 2006 by Juliusz Chroboczek.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 * -----------------------------------------------------------------------------
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

// NB: because this implementation of poll uses select(), executables
// need to be linked against the winsock library (-lws2_32)
int mingw_poll(struct pollfd *fds, unsigned int nfds, int timo)
{
    struct timeval timeout, *toptr;
    fd_set ifds, ofds, efds, *ip, *op;
    int i, rc;

    /* Set up the file-descriptor sets in ifds, ofds and efds. */
    FD_ZERO(&ifds);
    FD_ZERO(&ofds);
    FD_ZERO(&efds);
    for (i = 0, op = ip = 0; i < nfds; ++i) {
	fds[i].revents = 0;
	if(fds[i].events & (POLLIN|POLLPRI)) {
		ip = &ifds;
		FD_SET(fds[i].fd, ip);
	}
	if(fds[i].events & POLLOUT) {
		op = &ofds;
		FD_SET(fds[i].fd, op);
	}
	FD_SET(fds[i].fd, &efds);
    }

    /* Set up the timeval structure for the timeout parameter */
    if(timo < 0) {
	toptr = 0;
    } else {
	toptr = &timeout;
	timeout.tv_sec = timo / 1000;
	timeout.tv_usec = (timo - timeout.tv_sec * 1000) * 1000;
    }

#ifdef DEBUG_POLL
    printf("Entering select() sec=%ld usec=%ld ip=%lx op=%lx\n",
           (long)timeout.tv_sec, (long)timeout.tv_usec, (long)ip, (long)op);
#endif
    rc = select(0, ip, op, &efds, toptr);
#ifdef DEBUG_POLL
    printf("Exiting select rc=%d\n", rc);
#endif

    if(rc <= 0)
	return rc;

    if(rc > 0) {
        for (i = 0; i < nfds; ++i) {
            int fd = fds[i].fd;
    	if(fds[i].events & (POLLIN|POLLPRI) && FD_ISSET(fd, &ifds))
    		fds[i].revents |= POLLIN;
    	if(fds[i].events & POLLOUT && FD_ISSET(fd, &ofds))
    		fds[i].revents |= POLLOUT;
    	if(FD_ISSET(fd, &efds))
    		/* Some error was detected ... should be some way to know. */
    		fds[i].revents |= POLLHUP;
#ifdef DEBUG_POLL
        printf("%d %d %d revent = %x\n",
                FD_ISSET(fd, &ifds), FD_ISSET(fd, &ofds), FD_ISSET(fd, &efds),
                fds[i].revents
        );
#endif
        }
    }
    return rc;
}
