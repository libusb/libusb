# Copyright 2013 (C) Butterfly Network, Inc.

SRC_DIR = $${PWD}/libusb

INCLUDEPATH += $$PWD $$SRC_DIR

SOURCES += \
    $${SRC_DIR}/core.c \
    $${SRC_DIR}/descriptor.c \
    $${SRC_DIR}/io.c \
    $${SRC_DIR}/strerror.c \
    $${SRC_DIR}/sync.c \
    $${SRC_DIR}/hotplug.c \

HEADERS += \
    $${SRC_DIR}/libusbi.h \
    $${SRC_DIR}/hotplug.h

unix {
    SOURCES += \
        $${SRC_DIR}/os/poll_posix.c \
        $${SRC_DIR}/os/threads_posix.c

    HEADERS += \
        $${SRC_DIR}/os/poll_posix.h \
        $${SRC_DIR}/os/threads_posix.h
}

win32 {
    INCLUDEPATH += $${PWD}/msvc

    SOURCES += \
        $${SRC_DIR}/os/threads_windows.c \
        $${SRC_DIR}/os/poll_windows.c \
        $${SRC_DIR}/os/threads_windows.c \
        $${SRC_DIR}/os/windows_usb.c
        #libusb-1.0.rc libusb-1.0.def

    HEADERS += \
        $${SRC_DIR}/os/windows_common.h \
        $${SRC_DIR}/os/poll_windows.h \
        $${SRC_DIR}/os/threads_windows.h
}

linux {
    SOURCES += \
        $${SRC_DIR}/os/linux_usbfs.c \
        $${SRC_DIR}/os/linux_udev.c

    HEADERS += \
        $${SRC_DIR}/os/linux_usbfs.h
}

macx {
    INCLUDEPATH += $${PWD}/Xcode
    LIBS += -framework CoreFoundation -framework IOKit -lobjc

    SOURCES += \
        $${SRC_DIR}/os/darwin_usb.c

    HEADERS += \
        $${SRC_DIR}/os/darwin_usb.h
}
