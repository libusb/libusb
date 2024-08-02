AM_CPPFLAGS = -I$(top_srcdir)/libusb
AM_CXXFLAGS += -std=c++14
LDADD = ../libusb/libusb-1.0.la
LIBS =

noinst_PROGRAMS = dpfp dpfp_threaded fxload hotplugtest listdevs sam3u_benchmark testlibusb xusb hotplug_fallback

hotplug_fallback_SOURCES = hotplug_fallback.cc

dpfp_threaded_CPPFLAGS = $(AM_CPPFLAGS) -DDPFP_THREADED
dpfp_threaded_CFLAGS = $(AM_CFLAGS) $(THREAD_CFLAGS)
dpfp_threaded_LDADD = $(LDADD) $(THREAD_LIBS)
dpfp_threaded_SOURCES = dpfp.c

fxload_SOURCES = ezusb.c ezusb.h fxload.c
