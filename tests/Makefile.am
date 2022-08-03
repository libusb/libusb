AM_CPPFLAGS = -I$(top_srcdir)/libusb
LDADD = ../libusb/libusb-1.0.la
LIBS =

stress_SOURCES = stress.c libusb_testlib.h testlib.c

noinst_PROGRAMS = stress

if PLATFORM_POSIX
stress_mt_SOURCES = stress_mt.c

noinst_PROGRAMS += stress_mt
endif

if BUILD_UMOCKDEV_TEST
# NOTE: We add libumockdev-preload.so so that we can run tests in-process
#       We also use -Wl,-lxxx as the compiler doesn't need it and libtool
#       would reorder the flags otherwise.
umockdev_CPPFLAGS = ${UMOCKDEV_CFLAGS} -I$(top_srcdir)/libusb
umockdev_LDFLAGS = -Wl,--push-state,--no-as-needed -Wl,-lumockdev-preload -Wl,--pop-state ${UMOCKDEV_LIBS}
umockdev_SOURCES = umockdev.c

noinst_PROGRAMS += umockdev
endif
