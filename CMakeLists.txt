cmake_minimum_required(VERSION 3.18) # find_library()/find_package() REQUIRED keyword

# libusb/version.h is the single source of truth for the release version;
# configure.ac parses it with m4 and the .rc/.def build paths include it
# directly, so re-derive the same numbers here instead of duplicating them.
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/libusb/version.h" _libusb_version_h)
foreach(_atom MAJOR MINOR MICRO)
  string(REGEX MATCH "#define[ \t]+LIBUSB_${_atom}[ \t]+([0-9]+)" _match "${_libusb_version_h}")
  if(NOT _match)
    message(FATAL_ERROR "Could not parse LIBUSB_${_atom} from libusb/version.h")
  endif()
  set(_libusb_version_${_atom} "${CMAKE_MATCH_1}")
endforeach()
unset(_match)
unset(_libusb_version_h)

project(libusb
  VERSION "${_libusb_version_MAJOR}.${_libusb_version_MINOR}.${_libusb_version_MICRO}"
  DESCRIPTION "C API for USB device access from Linux, Mac OS X, Windows, OpenBSD/NetBSD and Solaris userspace"
  HOMEPAGE_URL "https://libusb.info"
  LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON) # gnu11: libusbi.h needs _Thread_local, as checked by configure.ac

include(GNUInstallDirs)
include(CheckIncludeFile)
include(CheckSymbolExists)
include(CheckCSourceCompiles)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
  set(_libusb_default_install ON)
else()
  set(_libusb_default_install OFF)
endif()

option(BUILD_SHARED_LIBS "Build libusb as a shared library" OFF)
option(LIBUSB_ENABLE_LOGGING "Enable all libusb logging" ON)
option(LIBUSB_ENABLE_DEBUG_LOGGING "Start with debug message logging enabled" OFF)
option(LIBUSB_ENABLE_SYSTEM_LOGGING "Send log messages to the systemwide log" OFF)
option(LIBUSB_ENABLE_UDEV "Use udev for device enumeration/hotplug on Linux (netlink is used otherwise)" ON)
option(LIBUSB_ENABLE_WINDOWS_HOTPLUG "Enable hotplug support on Windows" OFF)
option(LIBUSB_INSTALL "Generate install rules for libusb" ${_libusb_default_install})
option(LIBUSB_BUILD_EXAMPLES "Build the libusb example programs (examples/)" OFF)
option(LIBUSB_BUILD_TESTS "Build the libusb test suite (tests/) and register it with ctest" OFF)
option(LIBUSB_ENABLE_TESTCORE "Register the long-running testcore stress test with ctest" OFF)

# ---------------------------------------------------------------------------
# Backend selection - mirrors the `case $host in` block in configure.ac.
# ---------------------------------------------------------------------------
set(LIBUSB_PLATFORM_POSIX OFF)
set(LIBUSB_PLATFORM_WINDOWS OFF)

if(APPLE)
  set(LIBUSB_BACKEND "darwin")
  set(LIBUSB_PLATFORM_POSIX ON)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Haiku")
  set(LIBUSB_BACKEND "haiku")
  set(LIBUSB_PLATFORM_POSIX ON)
elseif(EMSCRIPTEN OR CMAKE_SYSTEM_NAME STREQUAL "Emscripten")
  set(LIBUSB_BACKEND "emscripten")
  set(LIBUSB_PLATFORM_POSIX ON)
elseif(CMAKE_SYSTEM_NAME MATCHES "^(Linux|Android)$")
  set(LIBUSB_BACKEND "linux")
  set(LIBUSB_PLATFORM_POSIX ON)
elseif(CMAKE_SYSTEM_NAME STREQUAL "NetBSD")
  set(LIBUSB_BACKEND "netbsd")
  set(LIBUSB_PLATFORM_POSIX ON)
elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
  set(LIBUSB_BACKEND "openbsd")
  set(LIBUSB_PLATFORM_POSIX ON)
elseif(CMAKE_SYSTEM_NAME MATCHES "SunOS")
  set(LIBUSB_BACKEND "sunos")
  set(LIBUSB_PLATFORM_POSIX ON)
elseif(WIN32)
  set(LIBUSB_BACKEND "windows")
  set(LIBUSB_PLATFORM_WINDOWS ON)
else()
  set(LIBUSB_BACKEND "null")
  set(LIBUSB_PLATFORM_POSIX ON)
  message(WARNING "libusb: unrecognized target OS '${CMAKE_SYSTEM_NAME}'; "
    "building the null backend, which cannot access any USB device.")
endif()

set(LIBUSB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/libusb")

set(LIBUSB_SOURCES
  ${LIBUSB_DIR}/core.c
  ${LIBUSB_DIR}/descriptor.c
  ${LIBUSB_DIR}/hotplug.c
  ${LIBUSB_DIR}/io.c
  ${LIBUSB_DIR}/strerror.c
  ${LIBUSB_DIR}/sync.c
)
set(LIBUSB_PRIVATE_LIBRARIES "")

if(LIBUSB_PLATFORM_POSIX)
  list(APPEND LIBUSB_SOURCES
    ${LIBUSB_DIR}/os/events_posix.c
    ${LIBUSB_DIR}/os/threads_posix.c
  )
  set(THREADS_PREFER_PTHREAD_FLAG ON)
  find_package(Threads REQUIRED)
  list(APPEND LIBUSB_PRIVATE_LIBRARIES Threads::Threads)

  # config.h below always defines _GNU_SOURCE for POSIX builds, and several
  # of the functions checked here (pipe2, pthread_setname_np, ...) are GNU
  # extensions that glibc hides unless it is defined, so the checks need to
  # see the same feature-test macro the real compile will use. Likewise
  # link against pthreads for the pthread_* symbol checks below.
  set(CMAKE_REQUIRED_DEFINITIONS "-D_GNU_SOURCE")
  set(CMAKE_REQUIRED_LIBRARIES Threads::Threads)

  # These checks apply to every POSIX backend (configure.ac's outer
  # `platform = posix` block); pipe2 is skipped on Emscripten there because
  # it is detected but never actually functional. See build-aux history.
  check_c_source_compiles("#include <poll.h>
    int main(void) { nfds_t n = 0; (void)n; return 0; }" LIBUSB_HAVE_NFDS_T)
  if(NOT LIBUSB_BACKEND STREQUAL "emscripten")
    check_symbol_exists(pipe2 "unistd.h" LIBUSB_HAVE_PIPE2)
  endif()
  check_include_file("sys/time.h" LIBUSB_HAVE_SYS_TIME_H)

  # clock_gettime() is required everywhere except Darwin, which never uses it.
  if(NOT LIBUSB_BACKEND STREQUAL "darwin")
    if(LIBUSB_BACKEND STREQUAL "linux")
      # Only glibc < 2.17 needs -lrt for clock_gettime(); search for it like
      # configure.ac's linux-specific AC_SEARCH_LIBS does.
      check_symbol_exists(clock_gettime "time.h" LIBUSB_HAVE_CLOCK_GETTIME_LIBC)
      if(LIBUSB_HAVE_CLOCK_GETTIME_LIBC)
        set(LIBUSB_HAVE_CLOCK_GETTIME ON)
      else()
        find_library(LIBUSB_RT_LIBRARY rt)
        if(LIBUSB_RT_LIBRARY)
          list(APPEND LIBUSB_PRIVATE_LIBRARIES ${LIBUSB_RT_LIBRARY})
          set(LIBUSB_HAVE_CLOCK_GETTIME ON)
        endif()
      endif()
    else()
      check_symbol_exists(clock_gettime "time.h" LIBUSB_HAVE_CLOCK_GETTIME)
    endif()
    if(NOT LIBUSB_HAVE_CLOCK_GETTIME)
      message(FATAL_ERROR "libusb: clock_gettime() is required on this platform")
    endif()
    # Use the monotonic clock for condition variable timed waits when possible.
    check_symbol_exists(pthread_condattr_setclock "pthread.h" LIBUSB_HAVE_PTHREAD_CONDATTR_SETCLOCK)
  endif()
endif()

if(LIBUSB_BACKEND STREQUAL "darwin")
  list(APPEND LIBUSB_SOURCES ${LIBUSB_DIR}/os/darwin_usb.c)
  check_symbol_exists(pthread_threadid_np "pthread.h" LIBUSB_HAVE_PTHREAD_THREADID_NP)
  check_include_file("IOKit/usb/IOUSBHostFamilyDefinitions.h" LIBUSB_HAVE_IOKIT_USB_IOUSBHOSTFAMILYDEFINITIONS_H)
  find_library(LIBUSB_IOKIT_FRAMEWORK IOKit REQUIRED)
  find_library(LIBUSB_COREFOUNDATION_FRAMEWORK CoreFoundation REQUIRED)
  find_library(LIBUSB_SECURITY_FRAMEWORK Security REQUIRED)
  find_library(LIBUSB_OBJC_LIBRARY objc REQUIRED)
  list(APPEND LIBUSB_PRIVATE_LIBRARIES
    ${LIBUSB_IOKIT_FRAMEWORK} ${LIBUSB_COREFOUNDATION_FRAMEWORK}
    ${LIBUSB_SECURITY_FRAMEWORK} ${LIBUSB_OBJC_LIBRARY})

elseif(LIBUSB_BACKEND STREQUAL "linux")
  list(APPEND LIBUSB_SOURCES ${LIBUSB_DIR}/os/linux_usbfs.c)
  check_symbol_exists(pthread_setname_np "pthread.h" LIBUSB_HAVE_PTHREAD_SETNAME_NP)

  if(LIBUSB_ENABLE_UDEV)
    find_package(PkgConfig)
    pkg_check_modules(LIBUDEV IMPORTED_TARGET libudev)
    if(NOT LIBUDEV_FOUND)
      message(FATAL_ERROR "libusb: LIBUSB_ENABLE_UDEV is ON but libudev "
        "(libudev-dev / systemd-devel) was not found. Install it, or "
        "configure with -DLIBUSB_ENABLE_UDEV=OFF to use the netlink backend.")
    endif()
    set(LIBUSB_HAVE_LIBUDEV ON)
    list(APPEND LIBUSB_SOURCES ${LIBUSB_DIR}/os/linux_udev.c)
    list(APPEND LIBUSB_PRIVATE_LIBRARIES PkgConfig::LIBUDEV)
  else()
    list(APPEND LIBUSB_SOURCES ${LIBUSB_DIR}/os/linux_netlink.c)
    check_include_file("asm/types.h" LIBUSB_HAVE_ASM_TYPES_H)
    check_include_file("linux/netlink.h" _libusb_have_netlink_h)
    check_include_file("sys/socket.h" _libusb_have_sys_socket_h)
    if(NOT _libusb_have_netlink_h)
      message(FATAL_ERROR "libusb: linux/netlink.h not found (required for the non-udev Linux backend)")
    endif()
    if(NOT _libusb_have_sys_socket_h)
      message(FATAL_ERROR "libusb: sys/socket.h not found (required for the non-udev Linux backend)")
    endif()
  endif()

elseif(LIBUSB_BACKEND STREQUAL "netbsd")
  list(APPEND LIBUSB_SOURCES ${LIBUSB_DIR}/os/netbsd_usb.c)

elseif(LIBUSB_BACKEND STREQUAL "openbsd")
  list(APPEND LIBUSB_SOURCES ${LIBUSB_DIR}/os/openbsd_usb.c)

elseif(LIBUSB_BACKEND STREQUAL "sunos")
  list(APPEND LIBUSB_SOURCES ${LIBUSB_DIR}/os/sunos_usb.c)
  # sunos_usb.c calls libnvpair; a static link needs -ldevinfo explicitly too.
  list(APPEND LIBUSB_PRIVATE_LIBRARIES devinfo nvpair)

elseif(LIBUSB_BACKEND STREQUAL "haiku")
  enable_language(CXX)
  list(APPEND LIBUSB_SOURCES
    ${LIBUSB_DIR}/os/haiku_usb_backend.cpp
    ${LIBUSB_DIR}/os/haiku_pollfs.cpp
    ${LIBUSB_DIR}/os/haiku_usb_raw.cpp
  )
  list(APPEND LIBUSB_PRIVATE_LIBRARIES be)

elseif(LIBUSB_BACKEND STREQUAL "emscripten")
  enable_language(CXX)
  list(APPEND LIBUSB_SOURCES ${LIBUSB_DIR}/os/emscripten_webusb.cpp)
  set_source_files_properties(${LIBUSB_DIR}/os/emscripten_webusb.cpp PROPERTIES
    COMPILE_OPTIONS "-std=c++20")
  # DEFAULT_TO_CXX: emcc 6.0.6+ needs it so C-only downstream links (this
  # library's C sources, and C consumers) still pull in the C++ runtime that
  # the WebUSB backend requires. See the comment in configure.ac. Applied as
  # PUBLIC link options below (target doesn't exist yet at this point) so
  # consumers linking against libusb::libusb inherit them too.
  set(LIBUSB_EMSCRIPTEN_LINK_OPTIONS "--bind" "-sASYNCIFY" "-sDEFAULT_TO_CXX" "-sASSERTIONS" "-sALLOW_MEMORY_GROWTH")

elseif(LIBUSB_BACKEND STREQUAL "windows")
  enable_language(RC)
  list(APPEND LIBUSB_SOURCES
    ${LIBUSB_DIR}/os/windows_common.c
    ${LIBUSB_DIR}/os/windows_usbdk.c
    ${LIBUSB_DIR}/os/windows_winusb.c
  )
  if(LIBUSB_ENABLE_WINDOWS_HOTPLUG)
    list(APPEND LIBUSB_SOURCES ${LIBUSB_DIR}/os/windows_hotplug.c)
  endif()
  list(APPEND LIBUSB_SOURCES
    ${LIBUSB_DIR}/os/events_windows.c
    ${LIBUSB_DIR}/os/threads_windows.c
  )
endif()

unset(CMAKE_REQUIRED_DEFINITIONS)
unset(CMAKE_REQUIRED_LIBRARIES)

# ---------------------------------------------------------------------------
# libusb/version_describe.h - regenerated on every build, like the autotools
# BUILT_SOURCES / msvc PreBuildEvent equivalents (see gen-describe.sh).
# ---------------------------------------------------------------------------
set(LIBUSB_VERSION_DESCRIBE_HEADER "${CMAKE_CURRENT_BINARY_DIR}/libusb/version_describe.h")
add_custom_target(libusb_version_describe
  COMMAND "${CMAKE_COMMAND}"
          "-DSRC_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
          "-DOUT_FILE=${LIBUSB_VERSION_DESCRIBE_HEADER}"
          -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/GenerateVersionDescribe.cmake"
  BYPRODUCTS "${LIBUSB_VERSION_DESCRIBE_HEADER}"
  COMMENT "Generating libusb/version_describe.h"
  VERBATIM)

# ---------------------------------------------------------------------------
# libusb/config.h - the private, per-platform feature header every source
# file pulls in via `#include <config.h>`. examples/ and tests/ need this
# directory too: several of their sources (testlib.c, umockdev.c, ezusb.c,
# ...) include <config.h> directly, matching their AM_CPPFLAGS in Makefile.am.
# ---------------------------------------------------------------------------
set(LIBUSB_CONFIG_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/libusb_config")
if(MSVC)
  set(LIBUSB_DEFAULT_VISIBILITY_ATTR "/**/")
  set(LIBUSB_PRINTF_FORMAT_ATTR "/**/")
else()
  set(LIBUSB_DEFAULT_VISIBILITY_ATTR "__attribute__ ((visibility (\"default\")))")
  set(LIBUSB_PRINTF_FORMAT_ATTR "__attribute__ ((__format__ (__printf__, a, b)))")
endif()
if(LIBUSB_PLATFORM_POSIX)
  set(_GNU_SOURCE ON)
endif()
set(ENABLE_LOGGING ${LIBUSB_ENABLE_LOGGING})
set(ENABLE_DEBUG_LOGGING ${LIBUSB_ENABLE_DEBUG_LOGGING})
set(USE_SYSTEM_LOGGING_FACILITY ${LIBUSB_ENABLE_SYSTEM_LOGGING})
set(HAVE_LIBUDEV ${LIBUSB_HAVE_LIBUDEV})
set(LIBUSB_WINDOWS_HOTPLUG ${LIBUSB_ENABLE_WINDOWS_HOTPLUG})
set(PLATFORM_POSIX ${LIBUSB_PLATFORM_POSIX})
set(PLATFORM_WINDOWS ${LIBUSB_PLATFORM_WINDOWS})
# config.h.in's #cmakedefine directives look up these exact (unprefixed)
# names; bridge in the LIBUSB_HAVE_* results from the checks above.
set(HAVE_NFDS_T ${LIBUSB_HAVE_NFDS_T})
set(HAVE_PIPE2 ${LIBUSB_HAVE_PIPE2})
set(HAVE_SYS_TIME_H ${LIBUSB_HAVE_SYS_TIME_H})
set(HAVE_CLOCK_GETTIME ${LIBUSB_HAVE_CLOCK_GETTIME})
set(HAVE_PTHREAD_CONDATTR_SETCLOCK ${LIBUSB_HAVE_PTHREAD_CONDATTR_SETCLOCK})
set(HAVE_PTHREAD_SETNAME_NP ${LIBUSB_HAVE_PTHREAD_SETNAME_NP})
set(HAVE_PTHREAD_THREADID_NP ${LIBUSB_HAVE_PTHREAD_THREADID_NP})
set(HAVE_ASM_TYPES_H ${LIBUSB_HAVE_ASM_TYPES_H})
set(HAVE_IOKIT_USB_IOUSBHOSTFAMILYDEFINITIONS_H ${LIBUSB_HAVE_IOKIT_USB_IOUSBHOSTFAMILYDEFINITIONS_H})

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/cmake/config.h.in"
                "${LIBUSB_CONFIG_INCLUDE_DIR}/config.h" @ONLY)

# eventfd/timerfd signalling: only wired up for the linux and sunos backends
# (configure.ac guards these the same way), each independently optional.
if(LIBUSB_BACKEND STREQUAL "linux" OR LIBUSB_BACKEND STREQUAL "sunos")
  check_include_file("sys/eventfd.h" _libusb_have_eventfd_h)
  if(_libusb_have_eventfd_h)
    check_symbol_exists(EFD_NONBLOCK "sys/eventfd.h" _libusb_have_efd_nonblock)
    check_symbol_exists(EFD_CLOEXEC "sys/eventfd.h" _libusb_have_efd_cloexec)
    check_symbol_exists(eventfd "sys/eventfd.h" _libusb_have_eventfd_fn)
    if(_libusb_have_efd_nonblock AND _libusb_have_efd_cloexec AND _libusb_have_eventfd_fn)
      set(LIBUSB_HAVE_EVENTFD ON)
    endif()
  endif()
  check_include_file("sys/timerfd.h" _libusb_have_timerfd_h)
  if(_libusb_have_timerfd_h)
    check_symbol_exists(TFD_NONBLOCK "sys/timerfd.h" _libusb_have_tfd_nonblock)
    check_symbol_exists(TFD_CLOEXEC "sys/timerfd.h" _libusb_have_tfd_cloexec)
    check_symbol_exists(timerfd_create "sys/timerfd.h" _libusb_have_timerfd_create)
    if(_libusb_have_tfd_nonblock AND _libusb_have_tfd_cloexec AND _libusb_have_timerfd_create)
      set(LIBUSB_HAVE_TIMERFD ON)
    endif()
  endif()
  # Regenerate config.h now that these two are known too.
  set(HAVE_EVENTFD ${LIBUSB_HAVE_EVENTFD})
  set(HAVE_TIMERFD ${LIBUSB_HAVE_TIMERFD})
  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/cmake/config.h.in"
                  "${CMAKE_CURRENT_BINARY_DIR}/libusb_config/config.h" @ONLY)
endif()

# ---------------------------------------------------------------------------
# The libusb-1.0 target
# ---------------------------------------------------------------------------
add_library(libusb ${LIBUSB_SOURCES})
add_library(libusb::libusb ALIAS libusb)
add_dependencies(libusb libusb_version_describe)

if(LIBUSB_BACKEND STREQUAL "windows")
  target_sources(libusb PRIVATE ${LIBUSB_DIR}/libusb-1.0.rc)
  if(BUILD_SHARED_LIBS)
    # Only the DLL build needs the .def; CMake passes it to the linker
    # (/DEF: for MSVC, -Wl,<file> for MinGW) when it sees a target_sources
    # entry with a .def extension on a SHARED library.
    target_sources(libusb PRIVATE ${LIBUSB_DIR}/libusb-1.0.def)
  endif()
endif()

target_link_libraries(libusb PRIVATE ${LIBUSB_PRIVATE_LIBRARIES})
target_include_directories(libusb PRIVATE
  "${LIBUSB_CONFIG_INCLUDE_DIR}"
  "${CMAKE_CURRENT_BINARY_DIR}/libusb"
)
target_include_directories(libusb PUBLIC
  $<BUILD_INTERFACE:${LIBUSB_DIR}>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/libusb-1.0>
)
set_target_properties(libusb PROPERTIES
  C_VISIBILITY_PRESET hidden
  POSITION_INDEPENDENT_CODE ON
  PUBLIC_HEADER "${LIBUSB_DIR}/libusb.h"
)

if(LIBUSB_BACKEND STREQUAL "windows")
  # MSVC and MinGW both name every configuration "libusb-1.0.{lib,dll,a}",
  # matching msvc/libusb_dll.vcxproj and msvc/libusb_static.vcxproj.
  set_target_properties(libusb PROPERTIES
    PREFIX ""
    OUTPUT_NAME "libusb-1.0"
  )
else()
  # SOVERSION/VERSION mirror configure.ac's libtool `-version-info
  # current:revision:age` (lt_current:lt_revision:lt_age), which encodes
  # ABI compatibility as (current - age).age.revision. Keep in sync with
  # configure.ac when that triple changes.
  set(_lt_current 6)
  set(_lt_revision 0)
  set(_lt_age 6)
  math(EXPR _lt_soversion "${_lt_current} - ${_lt_age}")
  set_target_properties(libusb PROPERTIES
    OUTPUT_NAME "usb-1.0"
    VERSION "${_lt_soversion}.${_lt_age}.${_lt_revision}"
    SOVERSION "${_lt_soversion}"
  )
endif()

if(LIBUSB_BACKEND STREQUAL "emscripten")
  set_target_properties(libusb PROPERTIES LINKER_LANGUAGE CXX)
  target_link_options(libusb PUBLIC ${LIBUSB_EMSCRIPTEN_LINK_OPTIONS})
endif()

# ---------------------------------------------------------------------------
# Install rules - opt out via -DLIBUSB_INSTALL=OFF (the default when this
# is pulled in with FetchContent/add_subdirectory rather than built standalone).
# ---------------------------------------------------------------------------
if(LIBUSB_INSTALL)
  include(CMakePackageConfigHelpers)

  install(TARGETS libusb
    EXPORT libusbTargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/libusb-1.0
  )

  # libusb-1.0.pc.in uses autoconf @var@ placeholders for these four, and
  # shell-style ${libdir}/${includedir} (left untouched by @ONLY) for the
  # rest, so pkg-config re-expands them relative to a relocated prefix.
  set(prefix "${CMAKE_INSTALL_PREFIX}")
  set(exec_prefix "\${prefix}")
  set(libdir "\${exec_prefix}/${CMAKE_INSTALL_LIBDIR}")
  set(includedir "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}")
  set(VERSION "${PROJECT_VERSION}")
  set(LIBS "") # static-link dependency flags aren't tracked by this build
  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/libusb-1.0.pc.in"
                  "${CMAKE_CURRENT_BINARY_DIR}/libusb-1.0.pc" @ONLY)
  install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libusb-1.0.pc"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

  install(EXPORT libusbTargets
    FILE libusbTargets.cmake
    NAMESPACE libusb::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libusb)

  write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/libusbConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion)
  # libusbConfig.cmake.in re-resolves libusb::libusb's private imported
  # dependencies (Threads, libudev) via find_dependency() before including
  # the exported targets file; #cmakedefine-style truthiness needs literal
  # 0/1, not an unset variable expanding to nothing.
  if(LIBUSB_PLATFORM_POSIX)
    set(LIBUSB_PLATFORM_POSIX 1)
  else()
    set(LIBUSB_PLATFORM_POSIX 0)
  endif()
  if(LIBUSB_HAVE_LIBUDEV)
    set(LIBUSB_HAVE_LIBUDEV 1)
  else()
    set(LIBUSB_HAVE_LIBUDEV 0)
  endif()
  configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/libusbConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/libusbConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libusb)
  install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/libusbConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/libusbConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libusb)
endif()

# ---------------------------------------------------------------------------
# examples/ and tests/ - both off by default (matching configure.ac's
# --enable-examples-build/--enable-tests-build, also both no by default).
# Neither directory's programs are installed (noinst_PROGRAMS upstream).
# ---------------------------------------------------------------------------
if(LIBUSB_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

if(LIBUSB_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
