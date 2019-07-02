set(TARGET_NAME libusb-1.0)

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
# Linux/MacOS
else()
list(APPEND ${TARGET_NAME}_PRIVATE_HEADERS
)
list(APPEND ${TARGET_NAME}_SOURCES
)
endif(WIN32)

add_library(${TARGET_NAME} SHARED
    ${${TARGET_NAME}_SOURCES}
    ${${TARGET_NAME}_PUBLIC_HEADERS}
    ${${TARGET_NAME}_PRIVATE_HEADERS}
)
set_target_properties(${TARGET_NAME}
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

target_include_directories(${TARGET_NAME} PRIVATE "../msvc")
target_include_directories(${TARGET_NAME} PRIVATE ".")

install(TARGETS ${TARGET_NAME}
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin
)
install(FILES ${${TARGET_NAME}_PUBLIC_HEADERS} DESTINATION inlcude)