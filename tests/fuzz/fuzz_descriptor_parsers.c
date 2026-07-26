/* Fuzz the static descriptor parsers in libusb/descriptor.c.
 *
 * The relevant entry points (parse_configuration, parse_interface,
 * parse_endpoint, parse_iad_array) all have file-local linkage, so we
 * compile them into this fuzzer's translation unit by including the source
 * file directly. The libusb_get_*() public APIs that wrap them require a
 * libusb_device with a backend, which is more setup than a fuzz target
 * needs. The unity-include keeps the fuzzer focused on parser logic only.
 *
 * Three small symbol stubs satisfy references that descriptor.c makes into
 * other libusb translation units; none of those code paths are reachable
 * from the parsers we exercise here.
 *
 * Built as part of the OSS-Fuzz integration; not exercised by the autotools
 * test suite.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* ENABLE_LOGGING affects only printf-like macros we don't care about. */
#define ENABLE_LOGGING 0

#include "config.h"
#include "libusbi.h"
#include "../../libusb/descriptor.c"

/* Stubs for symbols that descriptor.c references but the parsers we fuzz
 * never reach (logging sink, backend dispatch, control-transfer wrapper). */
const struct usbi_os_backend usbi_backend = {0};
void usbi_log(struct libusb_context *ctx, enum libusb_log_level level,
              const char *function, const char *format, ...) {
    (void)ctx; (void)level; (void)function; (void)format;
}
int libusb_control_transfer(libusb_device_handle *dev_handle,
                            uint8_t bmRequestType, uint8_t bRequest,
                            uint16_t wValue, uint16_t wIndex,
                            unsigned char *data, uint16_t wLength,
                            unsigned int timeout) {
    (void)dev_handle; (void)bmRequestType; (void)bRequest; (void)wValue;
    (void)wIndex; (void)data; (void)wLength; (void)timeout;
    return LIBUSB_ERROR_NOT_SUPPORTED;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* The limit of 8192 is comfortably above practical cases and
     * still keeping libFuzzer iterations fast and the corpus small */
    if (size < LIBUSB_DT_CONFIG_SIZE || size > 8192)
        return 0;

    /* Every call gets a fresh exact-size copy so any byte read past the
     * end is caught by ASan. The fuzzer must not observe state between
     * iterations. */
    uint8_t *buf;

    /* (1) parse_configuration -> parse_interface -> parse_endpoint */
    buf = malloc(size);
    if (!buf) return 0;
    memcpy(buf, data, size);
    {
        struct libusb_config_descriptor cfg;
        memset(&cfg, 0, sizeof(cfg));
        if (parse_configuration(NULL, &cfg, buf, (int)size) >= 0)
            clear_configuration(&cfg);
    }
    free(buf);

    /* (2) parse_iad_array */
    buf = malloc(size);
    if (!buf) return 0;
    memcpy(buf, data, size);
    {
        struct libusb_interface_association_descriptor_array iad;
        memset(&iad, 0, sizeof(iad));
        if (parse_iad_array(NULL, &iad, buf, (int)size) == LIBUSB_SUCCESS)
            free((void *)iad.iad);
    }
    free(buf);

    return 0;
}
