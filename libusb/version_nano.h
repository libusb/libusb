/* LIBUSB_NANO is deprecated since libusb 1.0.31 and is no longer
 * updated. The macro is kept at its last value to preserve the ABI of
 * the `nano` field in struct libusb_version and to avoid breaking
 * downstream users that currently #ifdef LIBUSB_NANO.
 *
 * Use libusb_version::describe (the LIBUSB_DESCRIBE string; see
 * libusb.h) for a unique-per-build identifier. It is generated at
 * build time from `git describe --tags --always --dirty` and is the
 * intended replacement. */
#define LIBUSB_NANO 12037
