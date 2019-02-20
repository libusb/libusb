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

config_setting(
    name = "android_arm64-v8a",
    values = {
        "cpu": "arm64-v8a",
    },
)

config_setting(
    name = "android_x86_64",
    values = {
        "cpu": "x86_64",
    },
)

_android_srcs = [
    "android/config.h",
    "libusb/os/linux_netlink.c",
    "libusb/os/linux_usbfs.c",
    "libusb/os/linux_usbfs.h",
]

_android_copts = [
    "-I" + native.package_name() + "/android",
]

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
        ":android_arm64-v8a": _android_srcs,
        ":android_x86_64": _android_srcs,
        ":darwin": [
            "libusb/os/darwin_usb.c",
            "libusb/os/darwin_usb.h",
            "Xcode/config.h",
        ],
        ":linux": [
            "libusb/os/linux_udev.c",
            "libusb/os/linux_usbfs.c",
            "libusb/os/linux_usbfs.h",
            "linux/config.h",
        ],
        "//conditions:default": [],
    }),
    hdrs = [
        "libusb/libusb.h",
    ],
    copts = [
        "-I" + native.package_name() + "/libusb",
    ] + select({
        ":android_arm64-v8a": _android_copts,
        ":android_x86_64": _android_copts,
        ":darwin": [
            "-I" + native.package_name() + "/Xcode",
            "-mmacosx-version-min=10.12",
        ],
        ":linux": [
            "-I" + native.package_name() + "/linux",
        ],
        "//conditions:default": [],
    }),
    includes = ["."],
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
