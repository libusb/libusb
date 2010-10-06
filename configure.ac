m4_define(LIBUSB_MAJOR, [1])
m4_define(LIBUSB_MINOR, [0])
m4_define(LIBUSB_MICRO, [8])

AC_INIT([libusb], LIBUSB_MAJOR.LIBUSB_MINOR.LIBUSB_MICRO, [libusb-devel@lists.sourceforge.net], [libusb], [http://www.libusb.org/])

AC_SUBST([LIBUSB_VERSION_MAJOR], [LIBUSB_MAJOR])
AC_SUBST([LIBUSB_VERSION_MINOR], [LIBUSB_MINOR])
AC_SUBST([LIBUSB_VERSION_MICRO], [LIBUSB_MICRO])

# Library versioning
# These numbers should be tweaked on every release. Read carefully:
# http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
# http://sourceware.org/autobook/autobook/autobook_91.html
lt_current="1"
lt_revision="0"
lt_age="1"
AC_SUBST(lt_current)
AC_SUBST(lt_revision)
AC_SUBST(lt_age)

AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([libusb/core.c])
AC_CONFIG_MACRO_DIR([m4])
AM_CONFIG_HEADER([config.h])
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

AC_PREREQ([2.50])
AC_PROG_CC
AC_PROG_LIBTOOL
AC_C_INLINE
AM_PROG_CC_C_O
AC_DEFINE([_GNU_SOURCE], [], [Use GNU extensions])

AM_MAINTAINER_MODE

AC_MSG_CHECKING([operating system])
PC_LIBS_PRIVATE=
case $host in
*-linux*)
	AC_DEFINE(OS_LINUX, [], [Linux backend])
	AC_SUBST(OS_LINUX)
	AC_DEFINE([THREADS_POSIX], [], [Use Posix Threads])
	AC_MSG_RESULT([Linux])
	backend="linux"
	AC_CHECK_LIB(rt, clock_gettime, PC_LIBS_PRIVATE="-lrt")
	LIBS="${LIBS} ${PC_LIBS_PRIVATE}"
	threads="posix"
	THREAD_CFLAGS="-pthread"
	PC_LIBS_PRIVATE="${PC_LIBS_PRIVATE} -pthread"
	AM_LDFLAGS=""
	;;
*-darwin*)
	AC_DEFINE(OS_DARWIN, [], [Darwin backend])
	AC_SUBST(OS_DARWIN)
	AC_DEFINE([THREADS_POSIX], [], [Use Posix Threads])
	AC_MSG_RESULT([Darwin/MacOS X])
	backend="darwin"
	threads="posix"
	THREAD_CFLAGS="-pthread"
	PC_LIBS_PRIVATE="-Wl,-framework,IOKit -Wl,-framework,CoreFoundation -Wl,-prebind -no-undefined -pthread"
	AM_LDFLAGS=${PC_LIBS_PRIVATE}
;;
*-mingw*)
	AC_DEFINE(OS_WINDOWS, [], [Windows backend])
	AC_SUBST(OS_WINDOWS)
	AC_MSG_RESULT([Windows])
	backend="windows"
	threads="windows"
	PC_LIBS_PRIVATE="-lsetupapi -lole32 -ladvapi32"
	LIBS="${LIBS} ${PC_LIBS_PRIVATE}"
	# -avoid-version to avoid a naming scheme such as libusb-0.dll
	AM_LDFLAGS="-no-undefined -avoid-version --add-stdcall-alias"
	AC_CHECK_TOOL(RC, windres, no)
	;;
*-cygwin*)
	AC_DEFINE(OS_WINDOWS, [], [Windows backend])
	AC_SUBST(OS_WINDOWS)
	AC_DEFINE([THREADS_POSIX], [], [Use Posix Threads])
	AC_MSG_RESULT([Windows])
	backend="windows"
	threads="posix"
	PC_LIBS_PRIVATE="-lsetupapi -lole32 -ladvapi32"
	LIBS="${LIBS} ${PC_LIBS_PRIVATE}"
	AM_LDFLAGS="-no-undefined -avoid-version"
	AC_CHECK_TOOL(RC, windres, no)
	;;
*)
	AC_MSG_ERROR([unsupported operating system])
esac
AC_SUBST(PC_LIBS_PRIVATE)

AM_CONDITIONAL([OS_LINUX], [test "x$backend" = "xlinux"])
AM_CONDITIONAL([OS_DARWIN], [test "x$backend" = "xdarwin"])
AM_CONDITIONAL([OS_WINDOWS], [test "x$backend" = "xwindows"])
AM_CONDITIONAL([THREADS_POSIX], [test "x$threads" = "xposix"])

# timerfd
AC_CHECK_HEADER([sys/timerfd.h], [timerfd_h=1], [timerfd_h=0])
AC_ARG_ENABLE([timerfd],
	[AS_HELP_STRING([--enable-timerfd],
		[use timerfd for timing (default auto)])],
	[use_timerfd=$enableval], [use_timerfd='auto'])

if test "x$use_timerfd" = "xyes" -a "x$timerfd_h" = "x0"; then
	AC_MSG_ERROR([timerfd header not available; glibc 2.9+ required])
fi

AC_CHECK_DECL([TFD_NONBLOCK], [tfd_hdr_ok=yes], [tfd_hdr_ok=no], [#include <sys/timerfd.h>])
if test "x$use_timerfd" = "xyes" -a "x$tfd_hdr_ok" = "xno"; then
	AC_MSG_ERROR([timerfd header not usable; glibc 2.9+ required])
fi

AC_MSG_CHECKING([whether to use timerfd for timing])
if test "x$use_timerfd" = "xno"; then
	AC_MSG_RESULT([no (disabled by user)])
else
	if test "x$timerfd_h" = "x1" -a "x$tfd_hdr_ok" = "xyes"; then
		AC_MSG_RESULT([yes])
		AC_DEFINE(USBI_TIMERFD_AVAILABLE, [], [timerfd headers available])
	else
		AC_MSG_RESULT([no (header not available)])
	fi
fi

AC_CHECK_TYPES(struct timespec)

# Message logging
AC_ARG_ENABLE([log], [AS_HELP_STRING([--disable-log], [disable all logging])],
	[log_enabled=$enableval],
	[log_enabled='yes'])
if test "x$log_enabled" != "xno"; then
	AC_DEFINE([ENABLE_LOGGING], 1, [Message logging])
fi

AC_ARG_ENABLE([debug-log], [AS_HELP_STRING([--enable-debug-log],
	[enable debug logging (default n)])],
	[debug_log_enabled=$enableval],
	[debug_log_enabled='no'])
if test "x$debug_log_enabled" != "xno"; then
	AC_DEFINE([ENABLE_DEBUG_LOGGING], 1, [Debug message logging])
fi

# Examples build
AC_ARG_ENABLE([examples-build], [AS_HELP_STRING([--enable-examples-build],
	[build example applications (default n)])],
	[build_examples=$enableval],
	[build_examples='no'])
AM_CONDITIONAL([BUILD_EXAMPLES], [test "x$build_examples" != "xno"])

# Restore gnu89 inline semantics on gcc 4.3 and newer
saved_cflags="$CFLAGS"
CFLAGS="$CFLAGS -fgnu89-inline"
AC_COMPILE_IFELSE(AC_LANG_PROGRAM([]), inline_cflags="-fgnu89-inline", inline_cflags="")
CFLAGS="$saved_cflags"

# check for -fvisibility=hidden compiler support (GCC >= 3.4)
saved_cflags="$CFLAGS"
# -Werror required for cygwin
CFLAGS="$CFLAGS -Werror -fvisibility=hidden"
AC_COMPILE_IFELSE(AC_LANG_PROGRAM([]),
	[VISIBILITY_CFLAGS="-fvisibility=hidden"
	 AC_DEFINE([DEFAULT_VISIBILITY], [__attribute__((visibility("default")))], [Default visibility]) ],
	[ VISIBILITY_CFLAGS=""
	 AC_DEFINE([DEFAULT_VISIBILITY], [], [Default visibility]) ],
	])
CFLAGS="$saved_cflags"

# check for -Wno-pointer-sign compiler support (GCC >= 4)
saved_cflags="$CFLAGS"
CFLAGS="$CFLAGS -Wno-pointer-sign"
AC_COMPILE_IFELSE(AC_LANG_PROGRAM([]),
	nopointersign_cflags="-Wno-pointer-sign", nopointersign_cflags="")
CFLAGS="$saved_cflags"

# sigaction not available on MinGW
AC_CHECK_FUNC([sigaction], [have_sigaction=yes], [have_sigaction=no])
AM_CONDITIONAL([HAVE_SIGACTION], [test "x$have_sigaction" = "xyes"])

# headers not available on all platforms but required on others
AC_CHECK_HEADERS([sys/time.h])

AC_SUBST([THREAD_CFLAGS])

AM_CFLAGS="-std=gnu99 $inline_cflags -Wall -Wundef -Wunused -Wstrict-prototypes -Werror-implicit-function-declaration $nopointersign_cflags -Wshadow"

AC_SUBST(VISIBILITY_CFLAGS)
AC_SUBST(AM_CFLAGS)
AC_SUBST(AM_LDFLAGS)

AC_CONFIG_FILES([libusb-1.0.pc] [Makefile] [libusb/Makefile] [libusb/libusb-1.0.rc] [examples/Makefile] [doc/Makefile] [doc/doxygen.cfg])
AC_OUTPUT

