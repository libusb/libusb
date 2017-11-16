/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Default visibility */
#define DEFAULT_VISIBILITY __attribute__((visibility("default")))

/* Start with debug message logging enabled */
/* #undef ENABLE_DEBUG_LOGGING */

/* Message logging */
#define ENABLE_LOGGING 1

/* Define to 1 if you have the <asm/types.h> header file. */
/* #undef HAVE_ASM_TYPES_H */

/* Define to 1 if you have the declaration of `TFD_CLOEXEC', and to 0 if you
   don't. */
#define HAVE_DECL_TFD_CLOEXEC 1

/* Define to 1 if you have the declaration of `TFD_NONBLOCK', and to 0 if you
   don't. */
#define HAVE_DECL_TFD_NONBLOCK 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the `udev' library (-ludev). */
#define HAVE_LIBUDEV 1

/* Define to 1 if you have the <libudev.h> header file. */
#define HAVE_LIBUDEV_H 1

/* Define to 1 if you have the <linux/netlink.h> header file. */
/* #undef HAVE_LINUX_NETLINK_H */

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `pipe2' function. */
#define HAVE_PIPE2 1

/* Define to 1 if you have the <poll.h> header file. */
#define HAVE_POLL_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if the system has the type `struct timespec'. */
#define HAVE_STRUCT_TIMESPEC 1

/* syslog() function available */
/* #undef HAVE_SYSLOG_FUNC */

/* Define to 1 if you have the <syslog.h> header file. */
/* #undef HAVE_SYSLOG_H */

/* Define to 1 if you have the <sys/socket.h> header file. */
/* #undef HAVE_SYS_SOCKET_H */

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#define LT_OBJDIR ".libs/"

/* Darwin backend */
/* #undef OS_DARWIN */

/* Haiku backend */
/* #undef OS_HAIKU */

/* Linux backend */
#define OS_LINUX 1

/* NetBSD backend */
/* #undef OS_NETBSD */

/* OpenBSD backend */
/* #undef OS_OPENBSD */

/* SunOS backend */
/* #undef OS_SUNOS */

/* Windows backend */
/* #undef OS_WINDOWS */

/* Name of package */
#define PACKAGE "libusb"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "libusb-devel@lists.sourceforge.net"

/* Define to the full name of this package. */
#define PACKAGE_NAME "libusb"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "libusb 1.0.21"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "libusb"

/* Define to the home page for this package. */
#define PACKAGE_URL "http://libusb.info"

/* Define to the version of this package. */
#define PACKAGE_VERSION "1.0.21"

/* type of second poll() argument */
#define POLL_NFDS_TYPE nfds_t

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Use POSIX Threads */
#define THREADS_POSIX 1

/* timerfd headers available */
#define USBI_TIMERFD_AVAILABLE 1

/* Enable output to system log */
/* #undef USE_SYSTEM_LOGGING_FACILITY */

/* Use udev for device enumeration/hotplug */
#define USE_UDEV 1

/* Use UsbDk Windows backend */
/* #undef USE_USBDK */

/* Version number of package */
#define VERSION "1.0.21"

/* Oldest Windows version supported */
/* #undef WINVER */

/* Use GNU extensions */
#define _GNU_SOURCE 1

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
/* #undef inline */
#endif
