# Test programs - noinst_PROGRAMS in Makefile.am, so none of these are
# installed. LIBUSB_TEST_TARGETS gets a target_link_libraries()/include-dir
# pass; LIBUSB_CTEST_TARGETS is the subset registered with ctest (mirrors
# the old Makefile.am's TESTS list, a strict subset of noinst_PROGRAMS).
add_executable(stress stress.c testlib.c)
add_executable(set_option set_option.c testlib.c)
add_executable(init_context init_context.c testlib.c)
set(LIBUSB_TEST_TARGETS stress set_option init_context)
set(LIBUSB_CTEST_TARGETS stress set_option init_context)

if(APPLE)
  add_executable(macos macos.c testlib.c)
  list(APPEND LIBUSB_TEST_TARGETS macos)
  list(APPEND LIBUSB_CTEST_TARGETS macos)
endif()

# stress_mt and testcore include <pthread.h> directly with no Windows
# fallback; only build them where a pthread implementation is actually
# available (see ../examples/CMakeLists.txt for the same reasoning).
check_include_file(pthread.h LIBUSB_TESTS_HAVE_PTHREAD_H)
if(LIBUSB_TESTS_HAVE_PTHREAD_H)
  set(THREADS_PREFER_PTHREAD_FLAG ON)
  find_package(Threads REQUIRED)

  add_executable(stress_mt stress_mt.c)
  target_link_libraries(stress_mt PRIVATE Threads::Threads)
  list(APPEND LIBUSB_TEST_TARGETS stress_mt)
  list(APPEND LIBUSB_CTEST_TARGETS stress_mt)

  # testcore is an intentionally long-running stress test. Upstream CI only
  # enables it (--enable-testcore) on master / explicitly labelled PRs, so
  # it's always built but only registered with ctest when requested.
  add_executable(testcore testcore.c)
  target_link_libraries(testcore PRIVATE Threads::Threads)
  list(APPEND LIBUSB_TEST_TARGETS testcore)
  if(LIBUSB_ENABLE_TESTCORE)
    list(APPEND LIBUSB_CTEST_TARGETS testcore)
  endif()
endif()

foreach(_t IN LISTS LIBUSB_TEST_TARGETS)
  target_link_libraries(${_t} PRIVATE libusb::libusb)
  # testlib.c/libusb_testlib.h/testcore.c/stress_mt.c include <config.h>
  # directly, matching AM_CPPFLAGS in the old Makefile.am.
  target_include_directories(${_t} PRIVATE "${LIBUSB_CONFIG_INCLUDE_DIR}")
endforeach()

foreach(_t IN LISTS LIBUSB_CTEST_TARGETS)
  add_test(NAME ${_t} COMMAND ${_t})
endforeach()

# umockdev: an optional Linux-only test that mocks USB devices via
# libumockdev-preload, so it can run in CI without real hardware. Silently
# skipped when the umockdev-1.0 pkg-config package isn't found, matching
# configure.ac's BUILD_UMOCKDEV_TEST (also gated there on logging being
# enabled and debug logging being off, since the test asserts on libusb's
# regular log output).
if(LIBUSB_BACKEND STREQUAL "linux" AND LIBUSB_ENABLE_LOGGING AND NOT LIBUSB_ENABLE_DEBUG_LOGGING)
  find_package(PkgConfig)
  pkg_check_modules(UMOCKDEV IMPORTED_TARGET "umockdev-1.0>=0.16.0")
  if(UMOCKDEV_FOUND)
    add_executable(umockdev umockdev.c)
    target_link_libraries(umockdev PRIVATE libusb::libusb PkgConfig::UMOCKDEV)
    target_include_directories(umockdev PRIVATE "${LIBUSB_CONFIG_INCLUDE_DIR}")
    # UMOCKDEV_HOTPLUG marks that umockdev's hotplug support isn't racy
    # (see the #ifdef UMOCKDEV_HOTPLUG guards in umockdev.c).
    pkg_check_modules(UMOCKDEV_HOTPLUG "umockdev-1.0>=0.17.7")
    if(UMOCKDEV_HOTPLUG_FOUND)
      target_compile_definitions(umockdev PRIVATE UMOCKDEV_HOTPLUG)
    endif()
    # Preload the umockdev shim so umockdev.c can run against mocked
    # devices in-process. --no-as-needed keeps the linker from dropping it,
    # since nothing else references its symbols directly.
    target_link_options(umockdev PRIVATE
      "-Wl,--push-state,--no-as-needed,-lumockdev-preload,--pop-state")
    add_test(NAME umockdev COMMAND umockdev)
  endif()
endif()
