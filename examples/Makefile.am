INCLUDES = -I$(top_srcdir)/libusb
noinst_PROGRAMS = listdevs xusb

listdevs_SOURCES = listdevs.c
listdevs_LDADD = ../libusb/libusb-1.0.la

xusb_SOURCES = xusb.c
xusb_LDADD = ../libusb/libusb-1.0.la

if HAVE_SIGACTION
dpfp_SOURCES = dpfp.c
dpfp_LDADD = ../libusb/libusb-1.0.la
noinst_PROGRAMS += dpfp
endif

if THREADS_POSIX
if HAVE_SIGACTION
dpfp_threaded_SOURCES = dpfp_threaded.c
dpfp_threaded_CFLAGS = $(THREAD_CFLAGS) $(AM_CFLAGS)
dpfp_threaded_LDADD = ../libusb/libusb-1.0.la
noinst_PROGRAMS += dpfp_threaded
endif
endif
