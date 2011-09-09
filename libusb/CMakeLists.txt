add_subdirectory(os)

include(config.cmake)
include(FindThreads)

set (LIBUSB_COMMON
	core.c
	descriptor.c
	io.c
	sync.c
	libusb-1.0.rc
	libusb-1.0.def
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/os)

if (CMAKE_THREAD_LIBS_INIT)
	list(APPEND LIBUSB_LIBRARIES ${CMAKE_THREAD_LIBS_INIT})
endif()

# The CLEAN_DIRECT_OUTPUT property setting can be removed once CMake >= 2.8.4
if (WITH_SHARED)
	add_library(usb-1.0
		SHARED
		${LIBUSB_COMMON}
		${LIBUSB_PLATFORM}
	)

	if (MSVC)
		set_target_properties(usb-1.0 PROPERTIES PREFIX "lib")
		set_target_properties(usb-1.0 PROPERTIES IMPORT_PREFIX "lib")
		set_target_properties(usb-1.0 PROPERTIES IMPORT_SUFFIX ".dll.lib")
	endif()

	set_target_properties(usb-1.0 PROPERTIES
		CLEAN_DIRECT_OUTPUT 1
		PUBLIC_HEADER libusb.h
		VERSION "${LIBUSB_MAJOR}.${LIBUSB_MINOR}.${LIBUSB_MICRO}"
		SOVERSION "${LIBUSB_MAJOR}.${LIBUSB_MINOR}.${LIBUSB_MICRO}"
	)

	if (DEFINED LIBUSB_LIBRARIES)
		message("Linking shared library against ${LIBUSB_LIBRARIES}")
		target_link_libraries(usb-1.0
			${LIBUSB_LIBRARIES}
		)
	endif()

	list(APPEND LIBUSB_LIBTARGETS usb-1.0)
endif()

if (WITH_STATIC)
	add_library(usb-1.0-static
		STATIC
		${LIBUSB_COMMON}
		${LIBUSB_PLATFORM}
	)

	set_target_properties(usb-1.0-static PROPERTIES
		PREFIX "lib"
		OUTPUT_NAME "usb-1.0"
		CLEAN_DIRECT_OUTPUT 1
		PUBLIC_HEADER libusb.h
		VERSION "${LIBUSB_MAJOR}.${LIBUSB_MINOR}.${LIBUSB_MICRO}"
		SOVERSION "${LIBUSB_MAJOR}.${LIBUSB_MINOR}.${LIBUSB_MICRO}"
	)

	if (DEFINED LIBUSB_LIBRARIES)
		target_link_libraries(usb-1.0-static
			${LIBUSB_LIBRARIES}
		)
	endif()

	list(APPEND LIBUSB_LIBTARGETS usb-1.0-static)
endif()

install(TARGETS ${LIBUSB_LIBTARGETS} EXPORT libusb-1
	PUBLIC_HEADER DESTINATION include/libusb-1.0
	ARCHIVE DESTINATION lib
	LIBRARY DESTINATION lib
	RUNTIME DESTINATION lib
)
install(EXPORT libusb-1 DESTINATION lib/libusb)

foreach(LIB IN LISTS LIBUSB_LIBRARIES)
	if (LIB MATCHES .framework$)
		get_filename_component(LIB "${LIB}" NAME)
		set(LIB "-Wl,-framework,${LIB}")
	elseif (LIB MATCHES .dylib$)
		get_filename_component(LIBDIR "${LIB}" PATH)
		get_filename_component(LIB "${LIB}" NAME)
		string(REGEX REPLACE "lib(.*).dylib$" "\\1" LIB "${LIB}")
		set(LIB "-L${LIBDIR} -l${LIB}")
	endif()
	set(LIBUSB_LIB_DEPENDS "${LIBUSB_LIB_DEPENDS} ${LIB}")
endforeach()

configure_file(libusb-1.0.pc.cmake "${CMAKE_CURRENT_BINARY_DIR}/libusb-1.0.pc" @ONLY)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libusb-1.0.pc" DESTINATION lib/pkgconfig)
