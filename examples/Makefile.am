INCLUDES = -I$(top_srcdir)

if POSIX_THREADS
DPFP_SRC = dpfp dpfp_threaded
else
DPFP_SRC = dpfp
endif

noinst_PROGRAMS = xusb lsusb $(DPFP_SRC)

lsusb_SOURCES = lsusb.c
lsusb_LDADD = ../libusb/libusb-1.0.la -lusb-1.0

xusb_SOURCES = xusb.c
xusb_LDADD = ../libusb/libusb-1.0.la -lusb-1.0

dpfp_SOURCES = dpfp.c
dpfp_LDADD = ../libusb/libusb-1.0.la -lusb-1.0

dpfp_threaded_SOURCES = dpfp_threaded.c
dpfp_threaded_CFLAGS = $(AM_CFLAGS)
dpfp_threaded_LDADD = ../libusb/libusb-1.0.la -lusb-1.0

