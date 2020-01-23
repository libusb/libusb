all: libusb-1.0.la libusb-1.0.dll

AUTOMAKE_OPTIONS = subdir-objects

lib_LTLIBRARIES = libusb-1.0.la

POSIX_POLL_SRC = os/poll_posix.h os/poll_posix.c
WINDOWS_POLL_SRC = os/poll_windows.h os/poll_windows.c

if POLL_POSIX
POLL_SRC = $(POSIX_POLL_SRC)
else
POLL_SRC = $(WINDOWS_POLL_SRC)
endif

POSIX_THREADS_SRC = os/threads_posix.h os/threads_posix.c
WINDOWS_THREADS_SRC = os/threads_windows.h os/threads_windows.c

if THREADS_POSIX
THREADS_SRC = $(POSIX_THREADS_SRC)
else
THREADS_SRC = $(WINDOWS_THREADS_SRC)
endif

OS_DARWIN_SRC = os/darwin_usb.h os/darwin_usb.c
OS_HAIKU_SRC = os/haiku_usb.h os/haiku_usb_backend.cpp \
	       os/haiku_pollfs.cpp os/haiku_usb_raw.h os/haiku_usb_raw.cpp
OS_LINUX_SRC = os/linux_usbfs.h os/linux_usbfs.c
OS_NETBSD_SRC = os/netbsd_usb.c
OS_NULL_SRC = os/null_usb.c
OS_OPENBSD_SRC = os/openbsd_usb.c
OS_SUNOS_SRC = os/sunos_usb.h os/sunos_usb.c
OS_WINDOWS_SRC = libusb-1.0.def libusb-1.0.rc \
		 os/windows_common.h ps/windows_common.c \
		 os/windows_usbdk.h os/windows_usbdk.c \
		 os/windows_winusb.h os/windows_winusb.c

EXTRA_DIST = $(POSIX_POLL_SRC) $(POSIX_THREADS_SRC) \
	$(WINDOWS_POLL_SRC) $(WINDOWS_THREADS_SRC) \
	$(OS_DARWIN_SRC) \
	$(OS_HAIKU_SRC) \
	$(OS_LINUX_SRC) \
	$(OS_NETBSD_SRC) \
	$(OS_NULL_SRC) \
	$(OS_OPENBSD_SRC) \
	$(OS_SUNOS_SRC) \
	$(OS_WINDOWS_SRC) \
	os/linux_netlink.c os/linux_udev.c

if OS_DARWIN
OS_SRC = $(OS_DARWIN_SRC)
AM_CFLAGS_EXT = -no-cpp-precomp
endif

if OS_HAIKU
noinst_LTLIBRARIES = libusb_haiku.la
libusb_haiku_la_SOURCES = $(OS_HAIKU_SRC)
libusb_1_0_la_LIBADD = libusb_haiku.la
endif

if OS_LINUX
OS_SRC = $(OS_LINUX_SRC)
if USE_UDEV
OS_SRC += os/linux_udev.c
else
OS_SRC += os/linux_netlink.c
endif
endif

if OS_NETBSD
OS_SRC = $(OS_NETBSD_SRC)
endif

if OS_NULL
OS_SRC = $(OS_NULL_SRC)
endif

if OS_OPENBSD
OS_SRC = $(OS_OPENBSD_SRC)
endif

if OS_SUNOS
OS_SRC = $(OS_SUNOS_SRC)
endif

if OS_WINDOWS
OS_SRC = $(OS_WINDOWS_SRC)

.rc.lo:
	$(AM_V_GEN)$(LIBTOOL) $(AM_V_lt) $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --tag=RC --mode=compile $(RC) $(RCFLAGS) -i $< -o $@

libusb-1.0.rc: version.h version_nano.h
endif

libusb-1.0.dll: libusb-1.0.def libusb-1.0.la
if CREATE_IMPORT_LIB
# Rebuild the import lib from the .def so that MS and MinGW DLLs can be interchanged
	$(AM_V_GEN)$(DLLTOOL) $(DLLTOOLFLAGS) --kill-at --input-def $(srcdir)/libusb-1.0.def --dllname $@ --output-lib .libs/$@.a
endif

libusb_1_0_la_CFLAGS = $(AM_CFLAGS)
libusb_1_0_la_LDFLAGS = $(LTLDFLAGS)
libusb_1_0_la_SOURCES = libusbi.h libusb.h version.h version_nano.h \
	core.c descriptor.c hotplug.h hotplug.c io.c strerror.c sync.c \
	$(POLL_SRC) $(THREADS_SRC) $(OS_SRC)

hdrdir = $(includedir)/libusb-1.0
hdr_HEADERS = libusb.h
