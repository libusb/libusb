#ifndef LIBUSB_POLL_POSIX_H
#define LIBUSB_POLL_POSIX_H

#include <poll.h>
#include <unistd.h>

#ifdef HAVE_NFDS_T
typedef nfds_t usbi_nfds_t;
#else
typedef unsigned int usbi_nfds_t;
#endif

#define usbi_write	write
#define usbi_read	read
#define usbi_close	close
#define usbi_poll	poll

int usbi_pipe(int pipefd[2]);

#endif /* LIBUSB_POLL_POSIX_H */
