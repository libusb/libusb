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

sh_binary(
    name = "bootstrap",
    srcs = ["bazel_bootstrap.sh"],
)

genrule(
    name = "config_hdr",
    srcs = ["configure.ac"],
    tools = [
        "doc/Makefile.am",
        "doc/doxygen.cfg.in",
        "examples/Makefile.am",
        "libusb/Makefile.am",
        "libusb/core.c",
        "libusb/version.h",
        "tests/Makefile.am",
        "AUTHORS",
        "ChangeLog",
        "COPYING",
        "NEWS",
        "README",
        "Makefile.am",
        "bootstrap.sh",
        "libusb-1.0.pc.in",
        ":bootstrap",
    ],
    outs = ["config.h"],
    cmd = "$(location :bootstrap) $< $@",
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
        ],
        ":linux": [
            "libusb/os/linux_usbfs.c",
            "libusb/os/linux_usbfs.h",
            "libusb/os/linux_udev.c",
            ":config_hdr",
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
