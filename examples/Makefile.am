INCLUDES = -I$(top_srcdir)
noinst_PROGRAMS = lsusb dpfp

lsusb_SOURCES = lsusb.c
lsusb_LDADD = ../libusb/libusb-1.0.la -lusb-1.0

dpfp_SOURCES = dpfp.c
dpfp_LDADD = ../libusb/libusb-1.0.la -lusb-1.0

if THREADS_POSIX
dpfp_threaded_SOURCES = dpfp_threaded.c
dpfp_threaded_CFLAGS = $(THREAD_CFLAGS) $(AM_CFLAGS)
dpfp_threaded_LDADD = ../libusb/libusb-1.0.la -lusb-1.0
noinst_PROGRAMS += dpfp_threaded
endif

