INCLUDES = -I$(top_srcdir)/libusb
LDADD = ../libusb/libusb-1.0.la

noinst_PROGRAMS = listdevs xusb

listdevs_SOURCES = listdevs.c

xusb_SOURCES = xusb.c

if HAVE_SIGACTION
dpfp_SOURCES = dpfp.c
noinst_PROGRAMS += dpfp
endif

if THREADS_POSIX
if HAVE_SIGACTION
dpfp_threaded_SOURCES = dpfp_threaded.c
dpfp_threaded_CFLAGS = $(THREAD_CFLAGS) $(AM_CFLAGS)
noinst_PROGRAMS += dpfp_threaded
endif
endif
