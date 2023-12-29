AM_CPPFLAGS = -I$(top_srcdir)/libusb
LDADD = ../libusb/libusb-1.0.la
AM_LDFLAGS = -static

stress_SOURCES = stress.c testlib.c
stress_mt_SOURCES = stress_mt.c
set_option_SOURCES = set_option.c testlib.c
init_context_SOURCES = init_context.c testlib.c
macos_SOURCES = macos.c testlib.c

stress_mt_CFLAGS = $(AM_CFLAGS) $(THREAD_CFLAGS)
stress_mt_LDADD = $(LDADD) $(THREAD_LIBS)
stress_mt_LDFLAGS = $(AM_LDFLAGS)

if OS_EMSCRIPTEN
# On the Web you can't block the main thread as this blocks the event loop itself,
# causing deadlocks when trying to use async APIs like WebUSB.
# We use the PROXY_TO_PTHREAD Emscripten's feature to move the main app to a separate thread
# where it can block safely.
stress_mt_LDFLAGS += ${AM_LDFLAGS} -s PROXY_TO_PTHREAD -s EXIT_RUNTIME
endif

noinst_HEADERS = libusb_testlib.h
noinst_PROGRAMS = stress stress_mt set_option init_context
if OS_DARWIN
noinst_PROGRAMS += macos
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

TESTS=$(noinst_PROGRAMS)
