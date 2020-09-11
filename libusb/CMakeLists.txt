add_library (libusb)

target_sources( libusb PRIVATE
        core.c
        hotplug.c
        sync.c
        io.c
        descriptor.c
        strerror.c
        )

if (UNIX)
    target_sources(libusb PRIVATE
            os/threads_posix.c
            os/linux_usbfs.c
            os/linux_netlink.c
            os/events_posix.c
            )

    target_link_libraries(libusb pthread)
endif (UNIX)

include_directories(../android ../ )

target_include_directories (libusb PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
