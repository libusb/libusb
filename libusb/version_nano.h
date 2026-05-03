/* LIBUSB_NANO is the per-commit version counter, bumped by the
 * maintainer pre-commit hook (.private/pre-commit.sh). It is a
 * candidate to be frozen and eventually deprecated once the
 * LIBUSB_DESCRIBE identifier (see struct libusb_version::describe)
 * has been through at least one release and developers agree to
 * retire it. Until then it remains active and downstream users that
 * currently #ifdef LIBUSB_NANO continue to work as before. */
#define LIBUSB_NANO 12029
