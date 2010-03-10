lib_LTLIBRARIES = libusb-1.0.la

if POSIX_THREADS
THREADS_SRC = os/threads_posix.h
else
THREADS_SRC = os/threads_windows.h os/threads_windows.c
endif

LINUX_USBFS_SRC = $(THREADS_SRC) os/poll_posix.h os/linux_usbfs.h os/linux_usbfs.c
DARWIN_USB_SRC = $(THREADS_SRC) os/poll_posix.h os/darwin_usb.h os/darwin_usb.c
WINDOWS_USB_SRC = $(THREADS_SRC) os/poll_windows.h os/poll_windows.c os/windows_usb.h os/windows_usb.c libusb-1.0.rc

EXTRA_DIST = $(LINUX_USBFS_SRC) $(DARWIN_USB_SRC) $(WINDOWS_USB_SRC)

if OS_LINUX
OS_SRC = $(LINUX_USBFS_SRC)
endif

if OS_DARWIN
OS_SRC = $(DARWIN_USB_SRC)
AM_CFLAGS_EXT = -no-cpp-precomp
endif

if OS_WINDOWS
OS_SRC = $(WINDOWS_USB_SRC)
.rc.lo:
	$(LIBTOOL) $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=compile $(RC) $(RCFLAGS) -i $< -o $@
endif

libusb_1_0_la_CFLAGS = $(VISIBILITY_CFLAGS) $(AM_CFLAGS)
libusb_1_0_la_SOURCES = libusbi.h core.c descriptor.c io.c sync.c $(OS_SRC)

hdrdir = $(includedir)/libusb-1.0
hdr_HEADERS = libusb.h
