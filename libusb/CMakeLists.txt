set(TARGET_NAME LibUsb)

set(${TARGET_NAME}_SOURCES
    core.c
    descriptor.c
    hotplug.c
    io.c
    strerror.c
    sync.c
)

set(${TARGET_NAME}_PUBLIC_HEADERS
    libusb.h
)

set(${TARGET_NAME}_PRIVATE_HEADERS
    hotplug.h
    libusbi.h
    version.h
    version_nano.h
)

# Windows
if(WIN32)
    list(APPEND ${TARGET_NAME}_PRIVATE_HEADERS
        os/poll_windows.h
        os/threads_windows.h
        os/windows_common.h
        os/windows_nt_common.h
        os/windows_nt_shared_types.h
        os/windows_usbdk.h
        os/windows_winusb.h
    )
    list(APPEND ${TARGET_NAME}_SOURCES
        os/poll_windows.c
        os/threads_windows.c
        os/windows_nt_common.c
        os/windows_usbdk.c
        os/windows_winusb.c
        libusb-1.0.rc
        libusb-1.0.def
    )
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Darwin") # Mac
    list(APPEND ${TARGET_NAME}_PRIVATE_HEADERS
        os/darwin_usb.h
        os/poll_posix.h
        os/threads_posix.h
    )
    list(APPEND ${TARGET_NAME}_SOURCES
        os/darwin_usb.c
        os/poll_posix.c
        os/threads_posix.c
    )
else(WIN32) # Linux
    list(APPEND ${TARGET_NAME}_PRIVATE_HEADERS
        os/linux_usbfs.h
        os/poll_posix.h
        os/threads_posix.h
    )
    list(APPEND ${TARGET_NAME}_SOURCES
        os/linux_udev.c
        os/linux_netlink.c
        os/linux_usbfs.c
        os/poll_posix.c
        os/threads_posix.c
    )
    add_definitions(-D_GNU_SOURCE)
endif(WIN32)


add_library(${TARGET_NAME} SHARED
    ${${TARGET_NAME}_SOURCES}
)

if(WIN32)
    target_include_directories(${TARGET_NAME} PRIVATE "../msvc")
    set(TARGET_OUTPUT_NAME "libusb")
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    target_include_directories(${TARGET_NAME} PRIVATE "../xcode")
    target_link_libraries(${TARGET_NAME} "objc")
    target_link_libraries(${TARGET_NAME} "-framework IOKit")
    target_link_libraries(${TARGET_NAME} "-framework CoreFoundation")
    set(TARGET_OUTPUT_NAME "usb")  # Linux and mac likes to prefix lib to libraries
else(WIN32)
    target_include_directories(${TARGET_NAME} PRIVATE "../android")
    target_link_libraries(${TARGET_NAME} "udev")
    target_link_libraries(${TARGET_NAME} "pthread")
    set(TARGET_OUTPUT_NAME "usb") # Linux and mac likes to prefix lib to libraries
endif(WIN32)


set_target_properties(${TARGET_NAME}
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    OUTPUT_NAME "${TARGET_OUTPUT_NAME}-1.0"
    PUBLIC_HEADER ${${TARGET_NAME}_PUBLIC_HEADERS}
)

target_include_directories(${TARGET_NAME} PRIVATE ".")

# Installing and exporting
include(CMakePackageConfigHelpers)
configure_package_config_file(
  ${CMAKE_CURRENT_LIST_DIR}/LibUsbConfig.cmake.in
  ${CMAKE_BINARY_DIR}/LibUsbConfig.cmake
  INSTALL_DESTINATION lib/cmake/${TARGET_NAME}
  PATH_VARS
)

write_basic_package_version_file(
  ${CMAKE_BINARY_DIR}/LibUsbConfigVersion.cmake
  VERSION 1.0.22.0
  COMPATIBILITY SameMajorVersion
)

install(FILES ${CMAKE_BINARY_DIR}/LibUsbConfig.cmake
              ${CMAKE_BINARY_DIR}/LibUsbConfigVersion.cmake
        DESTINATION lib/cmake/${TARGET_NAME}
)

install(TARGETS ${TARGET_NAME}
        EXPORT LibUsbTargets
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin
        PUBLIC_HEADER DESTINATION include
)

install(EXPORT LibUsbTargets
  FILE LibUsbTargets.cmake
  NAMESPACE ${TARGET_NAME}::
  DESTINATION lib/cmake/${TARGET_NAME}
)

