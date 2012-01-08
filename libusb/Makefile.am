all: libusb-1.0.la
if CREATE_IMPORT_LIB
# Rebuild the import lib from the .def so that MS and MinGW DLLs can be interchanged
	$(DLLTOOL) $(DLLTOOLFLAGS) --kill-at --input-def $(srcdir)/libusb-1.0.def --dllname libusb-1.0.dll --output-lib .libs/libusb-1.0.dll.a
endif

lib_LTLIBRARIES = libusb-1.0.la

LINUX_USBFS_SRC = os/linux_usbfs.c
DARWIN_USB_SRC = os/darwin_usb.c
WINDOWS_USB_SRC = os/poll_windows.c os/windows_usb.c libusb-1.0.rc

EXTRA_DIST = $(LINUX_USBFS_SRC) $(DARWIN_USB_SRC) $(WINDOWS_USB_SRC) \
	os/threads_posix.c os/threads_windows.c

if OS_LINUX
OS_SRC = $(LINUX_USBFS_SRC)
endif

if OS_DARWIN
OS_SRC = $(DARWIN_USB_SRC)
AM_CFLAGS_EXT = -no-cpp-precomp
endif

if OS_WINDOWS
OS_SRC = $(WINDOWS_USB_SRC)

pkg_v_rc = $(pkg_v_rc_$(V))
pkg_v_rc_ = $(pkg_v_rc_$(AM_DEFAULT_VERBOSITY))
pkg_v_rc_0 = @echo "  RC     $@";

.rc.lo:
	$(pkg_v_rc)$(LIBTOOL) $(AM_V_lt) $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --tag=RC --mode=compile $(RC) $(RCFLAGS) -i $< -o $@

libusb-1.0.rc: version.h
endif

if THREADS_POSIX
THREADS_SRC = os/threads_posix.h os/threads_posix.c
else
THREADS_SRC = os/threads_windows.h os/threads_windows.c
endif

libusb_1_0_la_CFLAGS = $(VISIBILITY_CFLAGS) $(AM_CFLAGS) $(THREAD_CFLAGS)
libusb_1_0_la_LDFLAGS = $(LTLDFLAGS)
libusb_1_0_la_SOURCES = libusbi.h core.c descriptor.c io.c sync.c $(OS_SRC) \
	os/linux_usbfs.h os/darwin_usb.h os/windows_usb.h \
	$(THREADS_SRC) \
	os/poll_posix.h os/poll_windows.h

hdrdir = $(includedir)/libusb-1.0
hdr_HEADERS = libusb.h
