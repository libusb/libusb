INCLUDES = -I$(top_srcdir)
noinst_PROGRAMS = xusb lsusb

lsusb_SOURCES = lsusb.c
lsusb_LDADD = ../libusb/libusb-1.0.la -lusb-1.0

xusb_SOURCES = xusb.c
xusb_LDADD = ../libusb/libusb-1.0.la -lusb-1.0

if HAVE_SIGACTION
dpfp_SOURCES = dpfp.c
dpfp_LDADD = ../libusb/libusb-1.0.la -lusb-1.0
noinst_PROGRAMS += dpfp
endif

if THREADS_POSIX
if HAVE_SIGACTION
dpfp_threaded_SOURCES = dpfp_threaded.c
dpfp_threaded_CFLAGS = $(THREAD_CFLAGS) $(AM_CFLAGS)
dpfp_threaded_LDADD = ../libusb/libusb-1.0.la -lusb-1.0
noinst_PROGRAMS += dpfp_threaded
endif
endif
