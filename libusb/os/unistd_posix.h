#ifndef __LIBUSB_UNISTD_POSIX_H__
#define __LIBUSB_UNISTD_POSIX_H__

#include <unistd.h>
#include <poll.h>
#define _libusb_write write
#define _libusb_read read
#define _libusb_close close
#define _libusb_pipe pipe
#define _libusb_poll poll

#endif /* __LIBUSB_UNISTD_POSIX_H__ */
