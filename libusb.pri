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
    DEFINES += _CRT_SECURE_NO_WARNINGS
    INCLUDEPATH += $${PWD}/msvc

    SOURCES += \
        $${SRC_DIR}/os/threads_windows.c \
        $${SRC_DIR}/os/poll_windows.c \
        $${SRC_DIR}/os/windows_usb.c
        #libusb-1.0.rc libusb-1.0.def

    HEADERS += \
        $${SRC_DIR}/os/windows_common.h \
        $${SRC_DIR}/os/poll_windows.h \
        $${SRC_DIR}/os/threads_windows.h
}

linux {
    LIBS += -ludev

    SOURCES += \
        $${SRC_DIR}/os/linux_usbfs.c \
        $${SRC_DIR}/os/linux_udev.c

    HEADERS += \
        $${SRC_DIR}/os/linux_usbfs.h

    # Make all source files depend on config.h to ensure that it exists
    libusb_sources.target = $(SOURCES)
    libusb_sources.depends = config_header
    QMAKE_EXTRA_TARGETS += libusb_sources

    # Add a target to generate the config.h file using configure
    config_header.target = $${PWD}/config.h
    config_header.depends = bootstrap
    config_header.commands = cd $${PWD} && ./configure
    QMAKE_EXTRA_TARGETS += config_header

    # Add a target for map the relative path to config.h to the absolute path to config.h
    config_header_rel.target = $$relative_path($${PWD}/config.h, $${OUT_PWD})
    config_header_rel.depends = config_header
    QMAKE_EXTRA_TARGETS += config_header_rel

    # Add a target to generate the configure command using bootstrap.sh
    bootstrap.target = $${PWD}/configure
    bootstrap.depends = $${PWD}/bootstrap.sh $${PWD}/configure.ac
    bootstrap.commands = cd $${PWD} && ./bootstrap.sh
    QMAKE_EXTRA_TARGETS += bootstrap
}

macx {
    INCLUDEPATH += $${PWD}/Xcode
    LIBS += -framework CoreFoundation -framework IOKit -lobjc

    SOURCES += \
        $${SRC_DIR}/os/darwin_usb.c

    HEADERS += \
        $${SRC_DIR}/os/darwin_usb.h
}
