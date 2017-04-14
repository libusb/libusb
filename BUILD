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
        # Unix common
        "libusb/os/poll_posix.c",
        "libusb/os/poll_posix.h",
        "libusb/os/threads_posix.c",
        "libusb/os/threads_posix.h",

        # macOS specific
        "libusb/os/darwin_usb.c",
        "libusb/os/darwin_usb.h",

        # Linux specific
        # ":config_hdr",
    ],
    hdrs = [
        "libusb/libusb.h",
    ],
    includes = ["."],
    copts = [
        "-I" + PACKAGE_NAME + "/libusb",

        # macOS specific
        "-I" + PACKAGE_NAME + "/Xcode",
    ],
    linkopts = [
        "-framework CoreFoundation",
        "-framework IOKit",
    ],
    visibility = ["//visibility:public"],
)
