lib_LTLIBRARIES = libfpusb.la

libfpusb_la_CFLAGS = -fvisibility=hidden $(AM_CFLAGS)
libfpusb_la_SOURCES = signalfd.h fpusbi.h usbfs.h core.c descriptor.c io.c
libfpusb_la_LIBADD = -lrt

pkginclude_HEADERS = fpusb.h
