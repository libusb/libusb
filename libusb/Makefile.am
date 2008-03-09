lib_LTLIBRARIES = libusb-1.0.la

libusb_1_0_la_CFLAGS = -fvisibility=hidden $(AM_CFLAGS)
libusb_1_0_la_SOURCES = libusbi.h usbfs.h core.c descriptor.c io.c sync.c
libusb_1_0_la_LIBADD = -lrt

hdrdir = $(includedir)/libusb-1.0
hdr_HEADERS = libusb.h
