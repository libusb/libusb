/* Used by source archives without Git or release metadata. */
#ifndef LIBUSB_DESCRIBE
#include "version.h"
#define LIBUSB_DESCRIBE_STRINGIFY_(value) #value
#define LIBUSB_DESCRIBE_STRINGIFY(value) LIBUSB_DESCRIBE_STRINGIFY_(value)
#define LIBUSB_DESCRIBE "Unknown source (v" \
	LIBUSB_DESCRIBE_STRINGIFY(LIBUSB_MAJOR) "." \
	LIBUSB_DESCRIBE_STRINGIFY(LIBUSB_MINOR) "." \
	LIBUSB_DESCRIBE_STRINGIFY(LIBUSB_MICRO) LIBUSB_RC ")"
#endif
