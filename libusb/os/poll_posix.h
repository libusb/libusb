#ifndef LIBUSB_POLL_POSIX_H
#define LIBUSB_POLL_POSIX_H

#define usbi_write write
#define usbi_read read
#define usbi_close close
#define usbi_pipe pipe
#define usbi_poll poll

#endif /* LIBUSB_POLL_POSIX_H */
