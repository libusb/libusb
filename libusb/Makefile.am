lib_LTLIBRARIES = libusb-1.0.la

LINUX_USBFS_SRC = os/linux_usbfs.h os/linux_usbfs.c

EXTRA_DIST = $(LINUX_USBFS_SRC)

if OS_LINUX
OS_SRC = $(LINUX_USBFS_SRC)
endif

libusb_1_0_la_CFLAGS = -fvisibility=hidden $(AM_CFLAGS)
libusb_1_0_la_SOURCES = libusbi.h core.c descriptor.c io.c sync.c $(OS_SRC)
libusb_1_0_la_LIBADD = -lrt

hdrdir = $(includedir)/libusb-1.0
hdr_HEADERS = libusb.h
