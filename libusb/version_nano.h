/* Deprecated: LIBUSB_NANO is frozen since 1.0.30. Use the LIBUSB_DESCRIBE
 * string exposed via struct libusb_version::describe for a unique-per-build
 * identifier. The macro is kept at its last value to preserve the ABI of the
 * `nano` field in struct libusb_version and to avoid breaking downstream
 * users that currently #ifdef LIBUSB_NANO. */
#define LIBUSB_NANO 12029
