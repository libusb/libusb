lib_LTLIBRARIES = libusb-1.0.la

libusb_1_0_la_CFLAGS = -fvisibility=hidden $(AM_CFLAGS)
libusb_1_0_la_SOURCES = signalfd.h libusbi.h usbfs.h core.c descriptor.c io.c
libusb_1_0_la_LIBADD = -lrt

pkginclude_HEADERS = libusb.h
