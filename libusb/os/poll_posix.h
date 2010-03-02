#ifndef __LIBUSB_UNISTD_POSIX_H__
#define __LIBUSB_UNISTD_POSIX_H__

#include <unistd.h>
#include <poll.h>
#define usbi_write write
#define usbi_read read
#define usbi_close close
#define usbi_pipe pipe
#define usbi_poll poll

#endif /* __LIBUSB_UNISTD_POSIX_H__ */
