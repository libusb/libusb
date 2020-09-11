add_library (usb-1.0 SHARED )

target_sources( usb-1.0 PRIVATE
        core.c
        hotplug.c
        sync.c
        io.c
        descriptor.c
        strerror.c
        )

if (UNIX)
    target_sources(usb-1.0 PRIVATE
            os/threads_posix.c
            os/linux_usbfs.c
            os/linux_netlink.c
            os/events_posix.c
            )

    target_link_libraries(usb-1.0 android log)
endif (UNIX)

include_directories(../android ../ )

target_include_directories (usb-1.0 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
