/*
 * Compile-only check of the libusb.h include contract on Windows.
 *
 * CI compiles this file twice, with and without WIN32_LEAN_AND_MEAN. The
 * define stops windows.h from pulling in winsock.h, which is how an
 * application can end up with neither winsock version in scope.
 *
 * References #1937 and #1509.
 */

#include "libusb.h"

/* #1937: struct timeval must be complete with libusb.h as the only include. */
int win32_header_check_timeval(libusb_context *ctx);
int win32_header_check_timeval(libusb_context *ctx)
{
	struct timeval tv = { 1, 0 };

	return libusb_handle_events_timeout_completed(ctx, &tv, NULL);
}

/* #1509: deliberately included last. Winsock v2 after libusb.h must not
 * collide with a winsock v1 that libusb.h let windows.h pull in. */
#include <winsock2.h>
