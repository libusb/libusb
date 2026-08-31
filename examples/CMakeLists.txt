# Example programs - noinst_PROGRAMS in Makefile.am, so none of these
# are installed.
set(LIBUSB_EXAMPLE_TARGETS "")

foreach(_name IN ITEMS dpfp hotplugtest listdevs sam3u_benchmark testlibusb xusb)
  add_executable(${_name} ${_name}.c)
  list(APPEND LIBUSB_EXAMPLE_TARGETS ${_name})
endforeach()

add_executable(fxload ezusb.c ezusb.h fxload.c)
list(APPEND LIBUSB_EXAMPLE_TARGETS fxload)

# dpfp_threaded reuses dpfp.c compiled with -DDPFP_THREADED (see
# dpfp_threaded_SOURCES in the old Makefile.am). It, and stress_mt/testcore
# under ../tests, include <pthread.h> directly with no Windows fallback, so
# only build them where a pthread implementation is actually available:
# always true on POSIX and MinGW-w64, not on stock MSVC.
check_include_file(pthread.h LIBUSB_EXAMPLES_HAVE_PTHREAD_H)
if(LIBUSB_EXAMPLES_HAVE_PTHREAD_H)
  set(THREADS_PREFER_PTHREAD_FLAG ON)
  find_package(Threads REQUIRED)
  add_executable(dpfp_threaded dpfp.c)
  target_compile_definitions(dpfp_threaded PRIVATE DPFP_THREADED)
  target_link_libraries(dpfp_threaded PRIVATE Threads::Threads)
  list(APPEND LIBUSB_EXAMPLE_TARGETS dpfp_threaded)
endif()

foreach(_t IN LISTS LIBUSB_EXAMPLE_TARGETS)
  target_link_libraries(${_t} PRIVATE libusb::libusb)
  # Several examples (ezusb.c, hotplugtest.c, sam3u_benchmark.c, dpfp.c, ...)
  # include <config.h> directly, matching AM_CPPFLAGS in the old Makefile.am.
  target_include_directories(${_t} PRIVATE "${LIBUSB_CONFIG_INCLUDE_DIR}")
endforeach()
