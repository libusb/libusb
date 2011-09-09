include(CheckFunctionExists)
include(FindThreads)

check_function_exists(sigaction HAVE_SIGACTION)

if (WITH_SHARED)
	set(LIBUSB_LIBRARY usb-1.0)
else()
	set(LIBUSB_LIBRARY usb-1.0-static)
endif()

include_directories(../libusb)

add_executable(lsusb lsusb.c)
target_link_libraries(lsusb ${LIBUSB_LIBRARY})
add_executable(xusb xusb.c)
target_link_libraries(xusb ${LIBUSB_LIBRARY})

if (HAVE_SIGACTION)
	add_executable(dpfp dpfp.c)
	target_link_libraries(dpfp ${LIBUSB_LIBRARY})

	if (CMAKE_USE_PTHREADS_INIT)
		add_executable(dpfp_threaded dpfp_threaded.c)
		target_link_libraries(dpfp_threaded ${LIBUSB_LIBRARY})
	endif()
endif()
