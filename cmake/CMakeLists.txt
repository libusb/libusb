project(usb-1.0)
cmake_minimum_required(VERSION 3.10)
set(CMAKE_C_USE_RESPONSE_FILE_FOR_INCLUDES   OFF)
set(CMAKE_CXX_USE_RESPONSE_FILE_FOR_INCLUDES OFF)

include(CheckIncludeFiles)
include(CheckFunctionExists)
include(CheckSymbolExists)
include(CheckStructHasMember)
include(CheckCCompilerFlag)
include(CTest)

check_function_exists(clock_gettime             HAVE_CLOCK_GETTIME)
check_function_exists(pthread_condattr_setclock HAVE_PTHREAD_CONDATTR_SETCLOCK)
check_function_exists(pthread_setname_np        HAVE_PTHREAD_SETNAME_NP)
check_function_exists(pthread_threadid_np       HAVE_PTHREAD_THREADID_NP)
check_function_exists(eventfd                   HAVE_EVENTFD)
check_function_exists(pipe2                     HAVE_PIPE2)
check_function_exists(syslog                    HAVE_SYSLOG)

check_include_files(asm/types.h      HAVE_ASM_TYPES_H) 
check_include_files(sys/eventfd.h    HAVE_EVENTFD) 
check_include_files(dlfcn.h          HAVE_DLFCN_H)
check_include_files(inttypes.h       HAVE_INTTYPES_H)
check_include_files(stdint.h         HAVE_STDINT_H)
check_include_files(stdio.h          HAVE_STDIO_H)
check_include_files(stdlib.h         HAVE_STDLIB_H)
check_include_files(string.h         HAVE_STRING_H)
check_include_files(strings.h        HAVE_STRINGS_H)
check_include_files(sys/stat.h       HAVE_SYS_STAT_H)
check_include_files(sys/time.h       HAVE_SYS_TIME_H)
check_include_files(sys/types.h      HAVE_SYS_TYPES_H)
check_include_files(unistd.h         HAVE_UNISTD_H)
check_include_files("stdlib.h;stdarg.h;string.h;float.h" STDC_HEADERS)

check_symbol_exists(EFD_CLOEXEC     "sys/eventfd.h" HAVE_DECL_EFD_CLOEXEC)
check_symbol_exists(EFD_NONBLOCK    "sys/eventfd.h" HAVE_DECL_EFD_NONBLOCK)
check_symbol_exists(TFD_CLOEXEC     "sys/eventfd.h" HAVE_DECL_TFD_CLOEXEC)
check_symbol_exists(timerfd_create  "sys/timerfd.h" HAVE_TIMERFD) 

check_struct_has_member("struct timespec" tv_sec time.h HAVE_STRUCT_TIMESPEC)

if (BUILD_SHARED_LIBS)
  set(libusb_BUILD_SHARED_LIBS_DEFAULT ON)
else (BUILD_SHARED_LIBS)
  set(libusb_BUILD_SHARED_LIBS_DEFAULT OFF)
endif (BUILD_SHARED_LIBS)

option(libusb_BUILD_SHARED_LIBS "Build Shared Libraries for libusb" ${libusb_BUILD_SHARED_LIBS_DEFAULT})
option(libusb_BUILD_TESTING "Build Tests" ON)
option(ENABLE_LOGGING "Enable Logging" ON)

if (WIN32)
    set(PLATFORM_WINDOWS 1 CACHE INTERNAL "")
endif()
if (UNIX)
    set(PLATFORM_POSIX 1  CACHE INTERNAL "")
endif()

if(("${CMAKE_CXX_COMPILER_ID}" STREQUAL Clang) OR ("${CMAKE_CXX_COMPILER_ID}" STREQUAL GNU))
    check_c_compiler_flag("-fvisibility=hidden" HAVE_VISIBILITY)
endif()

if (HAVE_VISIBILITY)
    set(DEFAULT_VISIBILITY "__attribute__((visibility(\"default\")))"  CACHE INTERNAL "")
else()
    set(DEFAULT_VISIBILITY ""  CACHE INTERNAL "")
endif()

configure_file(config.h.in config.h @ONLY)

set(libusb_ROOT ../libusb)

add_library(usb-1.0
    "${libusb_ROOT}/core.c"
    "${libusb_ROOT}/descriptor.c"
    "${libusb_ROOT}/hotplug.c"
    "${libusb_ROOT}/io.c"
    "${libusb_ROOT}/sync.c"
    "${libusb_ROOT}/strerror.c"

    "${libusb_ROOT}/libusb.h"
    "${libusb_ROOT}/libusbi.h"
    "${libusb_ROOT}/version_nano.h"
    "${libusb_ROOT}/version.h"

    "${CMAKE_CURRENT_BINARY_DIR}/config.h"
)

target_include_directories(usb-1.0 PUBLIC "${libusb_ROOT}")
target_include_directories(usb-1.0 PUBLIC "${CMAKE_CURRENT_BINARY_DIR}")
target_include_directories(usb-1.0 PRIVATE "${libusb_ROOT}/os")

if(WIN32)
    target_sources(usb-1.0 PRIVATE
        "${libusb_ROOT}/os/windows_common.c"
        "${libusb_ROOT}/os/windows_usbdk.c"
        "${libusb_ROOT}/os/windows_winusb.c"
        "${libusb_ROOT}/os/events_windows.c"
        "${libusb_ROOT}/os/threads_windows.c"

        "${libusb_ROOT}/os/events_windows.h"
        "${libusb_ROOT}/os/threads_windows.h"
        "${libusb_ROOT}/os/windows_common.h"
        "${libusb_ROOT}/os/windows_usbdk.h"
        "${libusb_ROOT}/os/windows_winusb.h"

        "${libusb_ROOT}/libusb-1.0.def"
    )
    if(MSVC)
        target_sources(usb-1.0 PRIVATE "${libusb_ROOT}/libusb-1.0.rc")
        target_compile_options(usb-1.0 PRIVATE /await /Zc:twoPhase- /permissive)
    endif()
    target_link_libraries(usb-1.0 PRIVATE windowsapp)
endif()

if(UNIX AND NOT ANDROID)
    target_sources(usb-1.0 PRIVATE
        "${libusb_ROOT}/os/events_posix.c"
        "${libusb_ROOT}/os/threads_posix.c"
        "${libusb_ROOT}/os/linux_usbfs.c"
        "${libusb_ROOT}/os/linux_udev.c"

        "${libusb_ROOT}/os/events_posix.h"
        "${libusb_ROOT}/os/threads_posix.h"
        "${libusb_ROOT}/os/linux_usbfs.h"
    )
    target_link_libraries(usb-1.0 PUBLIC udev)
    target_compile_definitions(usb-1.0 PRIVATE HAVE_LIBUDEV=1)
endif()

if(ANDROID)
    target_sources(usb-1.0 PRIVATE
        "${libusb_ROOT}/os/events_posix.c"
        "${libusb_ROOT}/os/threads_posix.c"
        "${libusb_ROOT}/os/linux_usbfs.c"
        "${libusb_ROOT}/os/linux_netlink.c"
        "${libusb_ROOT}/os/linux_android_jni.c"

        "${libusb_ROOT}/os/events_posix.h"
        "${libusb_ROOT}/os/threads_posix.h"
        "${libusb_ROOT}/os/linux_usbfs.h"
    )
    target_include_directories(usb-1.0 PUBLIC android)
endif()

if (libusb_BUILD_TESTING AND BUILD_TESTING)
    add_executable(testlibusb ../tests/testlib.c ../tests/stress.c)
    target_link_libraries(testlibusb PRIVATE usb-1.0)
    add_test(testlibusb COMMAND testlibusb)
endif()

install(TARGETS usb-1.0)
install(FILES ${libusb_ROOT}/libusb.h DESTINATION include/libusb-1.0)
