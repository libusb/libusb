AM_CPPFLAGS = -I$(top_srcdir)/libusb
LDADD = ../libusb/libusb-1.0.la
LIBS =

noinst_PROGRAMS = fxload hotplugtest listdevs testlibusb xusb

fxload_SOURCES = ezusb.c ezusb.h fxload.c

if HAVE_SIGACTION
noinst_PROGRAMS += dpfp
if PLATFORM_POSIX
noinst_PROGRAMS += dpfp_threaded
dpfp_threaded_CFLAGS = $(AM_CFLAGS) $(THREAD_CFLAGS)
dpfp_threaded_LDADD = $(LDADD) $(THREAD_LIBS)
endif

noinst_PROGRAMS += sam3u_benchmark
endif
