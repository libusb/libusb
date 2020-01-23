dnl These m4 macros are whitespace sensitive and break if moved around much.
m4_define([LU_VERSION_H], m4_include([libusb/version.h]))
m4_define([LU_DEFINE_VERSION_ATOM],
	[m4_define([$1], m4_bregexp(LU_VERSION_H,
	[^#define\s*$1\s*\([0-9]*\).*], [\1]))])
m4_define([LU_DEFINE_VERSION_RC_ATOM],
	[m4_define([$1], m4_bregexp(LU_VERSION_H,
	[^#define\s*$1\s*"\(-rc[0-9]*\)".*], [\1]))])
dnl The m4_bregexp() returns (only) the numbers following the #define named
dnl in the first macro parameter. m4_define() then defines the name for use
dnl in AC_INIT.

LU_DEFINE_VERSION_ATOM([LIBUSB_MAJOR])
LU_DEFINE_VERSION_ATOM([LIBUSB_MINOR])
LU_DEFINE_VERSION_ATOM([LIBUSB_MICRO])
LU_DEFINE_VERSION_RC_ATOM([LIBUSB_RC])

AC_INIT([libusb],[LIBUSB_MAJOR[.]LIBUSB_MINOR[.]LIBUSB_MICRO[]LIBUSB_RC],[libusb-devel@lists.sourceforge.net],[libusb],[http://libusb.info])

dnl Library versioning
dnl These numbers should be tweaked on every release. Read carefully:
dnl http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
dnl http://sourceware.org/autobook/autobook/autobook_91.html
lt_current=2
lt_revision=0
lt_age=2
LTLDFLAGS="-version-info ${lt_current}:${lt_revision}:${lt_age}"

AM_INIT_AUTOMAKE

AC_CONFIG_SRCDIR([libusb/core.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

AC_PREREQ([2.69])
AC_PROG_CC
AC_PROG_CXX
LT_INIT
LT_LANG([Windows Resource])
AC_C_INLINE
AM_PROG_CC_C_O
AC_DEFINE([_GNU_SOURCE], [1], [Use GNU extensions])

LTLDFLAGS="${LTLDFLAGS} -no-undefined"

AC_MSG_CHECKING([operating system])
case $host in
*-darwin*)
	AC_MSG_RESULT([Darwin/Mac OS X])
	backend=darwin
	poll=posix
	threads=posix
	;;
*-haiku*)
	AC_MSG_RESULT([Haiku])
	backend=haiku
	poll=posix
	threads=posix
	;;
*-linux* | *-uclinux*)
	dnl on linux-android platform, some functions are in different places
	case $host in
	*-linux-android*)
		AC_MSG_RESULT([Linux (Android system)])
		is_backend_android=yes
		;;
	*)
		AC_MSG_RESULT([Linux])
		is_backend_android=no
		;;
	esac
	backend=linux
	poll=posix
	threads=posix
	;;
*-netbsd*)
	AC_MSG_RESULT([NetBSD])
	backend=netbsd
	poll=posix
	threads=posix
	;;
*-openbsd*)
	AC_MSG_RESULT([OpenBSD])
	backend=openbsd
	poll=posix
	threads=posix
	;;
*-solaris*)
	AC_MSG_RESULT([SunOS])
	backend=sunos
	poll=posix
	threads=posix
	;;
*-cygwin*)
	AC_MSG_RESULT([Windows (using Cygwin)])
	backend=windows
	poll=windows
	threads=posix
	;;
*-mingw* | *msys*)
	AC_MSG_RESULT([Windows])
	backend=windows
	poll=windows
	threads=windows
	create_import_lib=yes
	AM_CFLAGS="${AM_CFLAGS} -fno-omit-frame-pointer"
	;;
*)
	AC_MSG_RESULT([Null])
	backend="null"
	poll=posix
	threads="posix"
	;;
esac

case $backend in
darwin)
	AC_DEFINE([OS_DARWIN], [1], [Darwin backend])
	LIBS="-lobjc -Wl,-framework,IOKit -Wl,-framework,CoreFoundation"
	LTLDFLAGS="${LTLDFLAGS} -Wl,-prebind"
	;;
haiku)
	AC_DEFINE([OS_HAIKU], [1], [Haiku backend])
	LIBS="-lbe"
	;;
linux)
	AC_DEFINE([OS_LINUX], [1], [Linux backend])
	AC_SEARCH_LIBS([clock_gettime], [rt], [], [], [-pthread])
	AC_ARG_ENABLE([udev],
		[AC_HELP_STRING([--enable-udev], [use udev for device enumeration and hotplug support (recommended) [default=yes]])],
		[], [enable_udev=yes])
	if test "x$enable_udev" = xyes ; then
		dnl system has udev. use it or fail!
		AC_CHECK_HEADER([libudev.h], [], [AC_MSG_ERROR([udev support requested but libudev header not installed])])
		AC_CHECK_LIB([udev], [udev_new], [], [AC_MSG_ERROR([udev support requested but libudev not installed])])
	else
		AC_CHECK_HEADERS([asm/types.h])
		AC_CHECK_HEADER([linux/netlink.h], [], [AC_MSG_ERROR([Linux netlink header not found])])
		AC_CHECK_HEADER([sys/socket.h], [], [AC_MSG_ERROR([Linux socket header not found])])
	fi
	if test "x$is_backend_android" != xyes; then
		THREAD_CFLAGS="-pthread"
		LIBS="${LIBS} -pthread"
	fi
	;;
netbsd)
	AC_DEFINE([OS_NETBSD], [1], [NetBSD backend])
	THREAD_CFLAGS="-pthread"
	LIBS="-pthread"
	;;
null)
	AC_DEFINE([OS_NULL], [1], [Null backend])
	THREAD_CFLAGS="-pthread"
	LIBS="-pthread"
	;;
openbsd)
	AC_DEFINE([OS_OPENBSD], [1], [OpenBSD backend])
	THREAD_CFLAGS="-pthread"
	LIBS="-pthread"
	;;
sunos)
	AC_DEFINE([OS_SUNOS], [1], [SunOS backend])
	THREAD_CFLAGS="-pthread"
	LIBS="-pthread -ldevinfo"
	;;
windows)
	AC_DEFINE([OS_WINDOWS], [1], [Windows backend])
	AC_CHECK_TYPES([struct timespec], [], [], [[#include <time.h>]])
	LIBS=""
	LTLDFLAGS="${LTLDFLAGS} -avoid-version -Wl,--add-stdcall-alias"
	AC_DEFINE([_WIN32_WINNT], [_WIN32_WINNT_VISTA], [Oldest Windows version supported (Vista)])
	;;
*)
	AC_MSG_ERROR([Unknown backend])
	;;
esac

AC_SUBST(LIBS)

AM_CONDITIONAL([OS_DARWIN], [test "x$backend" = xdarwin])
AM_CONDITIONAL([OS_HAIKU], [test "x$backend" = xhaiku])
AM_CONDITIONAL([OS_LINUX], [test "x$backend" = xlinux])
AM_CONDITIONAL([OS_NETBSD], [test "x$backend" = xnetbsd])
AM_CONDITIONAL([OS_NULL], [test "x$backend" = xnull])
AM_CONDITIONAL([OS_OPENBSD], [test "x$backend" = xopenbsd])
AM_CONDITIONAL([OS_SUNOS], [test "x$backend" = xsunos])
AM_CONDITIONAL([OS_WINDOWS], [test "x$backend" = xwindows])
AM_CONDITIONAL([POLL_POSIX], [test "x$threads" = xposix])
AM_CONDITIONAL([POLL_WINDOWS], [test "x$threads" = xwindows])
AM_CONDITIONAL([THREADS_POSIX], [test "x$threads" = xposix])
AM_CONDITIONAL([THREADS_WINDOWS], [test "x$threads" = xwindows])
AM_CONDITIONAL([CREATE_IMPORT_LIB], [test "x$create_import_lib" = xyes])
AM_CONDITIONAL([USE_UDEV], [test "x$enable_udev" = xyes])

if test "x$poll" = xposix; then
	AC_DEFINE([POLL_POSIX], [1], [Use POSIX poll() implementation])
	AC_CHECK_TYPES([nfds_t], [], [], [[#include <poll.h>]])
	AC_CHECK_FUNCS([pipe2])
elif test "x$poll" = xwindows; then
	AC_DEFINE([POLL_WINDOWS], [1], [Use Windows poll() implementation])
else
	AC_MSG_ERROR([Unknown poll implementation])
fi

if test "x$threads" = xposix; then
	AC_DEFINE([THREADS_POSIX], [1], [Use POSIX Threads])
elif test "x$threads" = xwindows; then
	AC_DEFINE([THREADS_WINDOWS], [1], [Use Windows Threads])
else
	AC_MSG_ERROR([Unknown threads implementation])
fi

dnl headers not available on all platforms but required on others
AC_CHECK_HEADERS([sys/time.h])

dnl timerfd support
if test "x$backend" = xlinux || test "x$backend" = xsunos; then
	AC_ARG_ENABLE([timerfd],
		[AS_HELP_STRING([--enable-timerfd], [use timerfd for timing [default=auto]])],
		[use_timerfd=$enableval],
		[use_timerfd=auto])
	if test "x$use_timerfd" != xno; then
		AC_CHECK_HEADER([sys/timerfd.h], [timerfd_h=yes], [timerfd_h=no])
		if test "x$timerfd_h" = xyes; then
			AC_CHECK_DECLS([TFD_NONBLOCK, TFD_CLOEXEC], [timerfd_h_ok=yes], [timerfd_h_ok=no], [[#include <sys/timerfd.h>]])
			if test "x$timerfd_h_ok" = xyes; then
				AC_CHECK_FUNC([timerfd_create], [timerfd_ok=yes], [timerfd_ok=no])
				if test "x$timerfd_ok" = xyes; then
					AC_DEFINE([HAVE_TIMERFD], [1], [Define if the system has timerfd functionality])
				elif test "x$use_timerfd" = xyes; then
					AC_MSG_ERROR([timerfd_create() function not found; glibc 2.9+ required])
				fi
			elif test "x$use_timerfd" = xyes; then
				AC_MSG_ERROR([timerfd header not usable; glibc 2.9+ required])
			fi
		elif test "x$use_timerfd" = xyes; then
			AC_MSG_ERROR([timerfd header not available; glibc 2.9+ required])
		fi
	fi
	AC_MSG_CHECKING([whether to use timerfd for timing])
	if test "x$use_timerfd" = xno; then
		AC_MSG_RESULT([no (disabled by user)])
	elif test "x$timerfd_h" = xno; then
		AC_MSG_RESULT([no (header not usable)])
	elif test "x$timerfd_h_ok" = xno; then
		AC_MSG_RESULT([no (header not available)])
	elif test "x$timerfd_ok" = xno; then
		AC_MSG_RESULT([no (functions not available)])
	else
		AC_MSG_RESULT([yes])
	fi
fi

dnl Message logging
AC_ARG_ENABLE([log],
	[AS_HELP_STRING([--disable-log], [disable all logging])],
	[log_enabled=$enableval],
	[log_enabled=yes])
if test "x$log_enabled" != xno; then
	AC_DEFINE([ENABLE_LOGGING], [1], [Message logging])
fi

AC_ARG_ENABLE([debug-log],
	[AS_HELP_STRING([--enable-debug-log], [start with debug message logging enabled [default=no]])],
	[debug_log_enabled=$enableval],
	[debug_log_enabled=no])
if test "x$debug_log_enabled" != xno; then
	AC_DEFINE([ENABLE_DEBUG_LOGGING], [1], [Start with debug message logging enabled])
fi

AC_ARG_ENABLE([system-log],
	[AS_HELP_STRING([--enable-system-log], [output logging messages to system wide log, if supported by the OS [default=no]])],
	[system_log_enabled=$enableval],
	[system_log_enabled=no])
if test "x$system_log_enabled" != xno; then
	AC_DEFINE([USE_SYSTEM_LOGGING_FACILITY], [1], [Enable output to system log])
	if test "x$backend" != xwindows && test "x$is_backend_android" != xyes; then
		dnl Check if syslog is available in standard C library
		AC_CHECK_HEADER([syslog.h], [syslog_h=yes], [syslog_h=no])
		if test "x$syslog_h" = xyes; then
			AC_CHECK_FUNCS([syslog])
		fi
	fi
fi

dnl Examples build
AC_ARG_ENABLE([examples-build],
	[AS_HELP_STRING([--enable-examples-build], [build example applications [default=no]])],
	[build_examples=$enableval],
	[build_examples=no])
AM_CONDITIONAL([BUILD_EXAMPLES], [test "x$build_examples" != xno])

dnl Tests build
AC_ARG_ENABLE([tests-build],
	[AS_HELP_STRING([--enable-tests-build], [build test applications [default=no]])],
	[build_tests=$enableval],
	[build_tests=no])
AM_CONDITIONAL([BUILD_TESTS], [test "x$build_tests" != xno])

dnl sigaction needed for some example programs
if test "x$build_examples" != xno; then
	AC_CHECK_FUNC([sigaction], [have_sigaction=yes], [have_sigaction=no])
fi
AM_CONDITIONAL([HAVE_SIGACTION], [test "x$have_sigaction" = xyes])

dnl check for -fvisibility=hidden compiler support (GCC >= 3.4)
saved_CFLAGS="${CFLAGS}"
dnl -Werror required for cygwin
CFLAGS="${CFLAGS} -Werror -fvisibility=hidden"
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
	[VISIBILITY_CFLAGS="-fvisibility=hidden"
	 AC_DEFINE([DEFAULT_VISIBILITY], [__attribute__((visibility("default")))], [Default visibility])],
	[VISIBILITY_CFLAGS=""
	 AC_DEFINE([DEFAULT_VISIBILITY], [], [Default visibility])],
	])
CFLAGS="${saved_CFLAGS}"

dnl check for -Wno-pointer-sign compiler support (GCC >= 4)
saved_CFLAGS="${CFLAGS}"
CFLAGS="${CFLAGS} -Wno-pointer-sign"
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
	nopointersign_cflags="-Wno-pointer-sign", nopointersign_cflags="")
CFLAGS="${saved_CFLAGS}"

dnl check for -std=gnu99 compiler support
saved_CFLAGS="${CFLAGS}"
CFLAGS="-std=gnu99"
AC_MSG_CHECKING([whether CC supports -std=gnu99])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
	[AC_MSG_RESULT([yes])
	 AM_CFLAGS="${AM_CFLAGS} -std=gnu99"],
	[AC_MSG_RESULT([no])]
)
CFLAGS="${saved_CFLAGS}"

AM_CFLAGS="${AM_CFLAGS} -Wall -Wundef -Wunused -Wstrict-prototypes -Werror-implicit-function-declaration ${nopointersign_cflags} -Wshadow ${THREAD_CFLAGS} ${VISIBILITY_CFLAGS}"

AC_SUBST(AM_CFLAGS)
AC_SUBST(LTLDFLAGS)

AC_CONFIG_FILES([libusb-1.0.pc])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([libusb/Makefile])
AC_CONFIG_FILES([examples/Makefile])
AC_CONFIG_FILES([tests/Makefile])
AC_CONFIG_FILES([doc/Makefile])
AC_CONFIG_FILES([doc/doxygen.cfg])
AC_OUTPUT
