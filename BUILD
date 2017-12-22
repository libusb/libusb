config_setting(
    name = "darwin",
    values = {
        "cpu": "darwin",
    },
)

config_setting(
    name = "linux",
    values = {
        "cpu": "k8",
    },
)

cc_library(
    name = "libusb",
    srcs = glob([
        "libusb/*.c",
        "libusb/*.h",
    ]) + [
        "libusb/os/poll_posix.c",
        "libusb/os/poll_posix.h",
        "libusb/os/threads_posix.c",
        "libusb/os/threads_posix.h",
    ] + select({
        ":darwin": [
            "libusb/os/darwin_usb.c",
            "libusb/os/darwin_usb.h",
            "Xcode/config.h",
        ],
        ":linux": [
            "libusb/os/linux_usbfs.c",
            "libusb/os/linux_usbfs.h",
            "libusb/os/linux_udev.c",
            "linux/config.h",
        ],
        "//conditions:default": [],
    }),
    hdrs = [
        "libusb/libusb.h",
    ],
    includes = ["."],
    copts = [
        "-I" + PACKAGE_NAME + "/libusb",
    ] + select({
        ":darwin": [
            "-I" + PACKAGE_NAME + "/Xcode",
            "-mmacosx-version-min=10.12",
        ],
        ":linux": [
            "-I" + PACKAGE_NAME + "/linux",
        ],
        "//conditions:default": [],
    }),
    linkopts = select({
        ":darwin": [
            "-framework CoreFoundation",
            "-framework IOKit",
        ],
        ":linux": [
            "-ludev",
        ],
        "//conditions:default": [],
    }),
    visibility = ["//visibility:public"],
)
