AM_CPPFLAGS = -I$(top_srcdir)/libusb
LDADD = ../libusb/libusb-1.0.la
LIBS =

noinst_PROGRAMS = dpfp dpfp_threaded fxload hotplugtest listdevs sam3u_benchmark testlibusb xusb

dpfp_threaded_CPPFLAGS = $(AM_CPPFLAGS) -DDPFP_THREADED
dpfp_threaded_CFLAGS = $(AM_CFLAGS) $(THREAD_CFLAGS)
dpfp_threaded_LDADD = $(LDADD) $(THREAD_LIBS)
dpfp_threaded_SOURCES = dpfp.c

fxload_SOURCES = ezusb.c ezusb.h fxload.c
