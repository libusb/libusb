cmake_minimum_required(VERSION 2.6)

# Can be removed once CMake >= 2.8.4 is required
# this has to be set before the project directive
set(CMAKE_LEGACY_CYGWIN_WIN32 0)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")

project(libusb)

option(WITHOUT_EXPERIMENTAL_WARNING "Disable the warning that CMake build is experimental whenever CMake is run" OFF)
if (NOT WITHOUT_EXPERIMENTAL_WARNING)
	message(WARNING "The CMake build system is not officially endorsed.  Support may or may not be provided on the libusb-devel@sourceforge.net mailing list")
endif()

option(WITH_SHARED "Build a shared library" ON)
option(WITH_STATIC "Build a static library" OFF)
option(WITH_DOCS "Build the documentation" OFF)

option(WITH_DEBUG_LOG "enable debug logging" OFF)

# if debug logging is enabled, by default enable logging
option(WITH_LOGGING "if false, disable all logging" ON)

# enable examples by default if building with maintainer mode
option(WITH_EXAMPLES "build example applications" ${WITH_MAINTAINER_MODE})

option(WITHOUT_PTHREADS "force pthreads to not be used.  if on, then they are used based on detection logic" OFF)

set(LIBUSB_MAJOR 1)
set(LIBUSB_MINOR 0)
set(LIBUSB_MICRO 8)

macro(append_compiler_flags)
	foreach(FLAG IN ITEMS ${ARGN})
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${FLAG}")
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${FLAG}")
	endforeach()
endmacro()

if (WITH_DOCS)
	add_subdirectory(docs)
endif ()

if (WITH_EXAMPLES)
	add_subdirectory(examples)
endif()

add_subdirectory(libusb)
