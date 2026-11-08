/* -*- Mode: C; indent-tabs-mode:nil -*- */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "libusbi.h"

/* Fuzz libusb_fill_control_setup() and the transfer allocator.
   The setup packet occupies the first LIBUSB_CONTROL_SETUP_SIZE bytes of a
   transfer buffer, so the buffer has to be at least that large.
   The reach here is small, because the function parses nothing.

   libusb_free_transfer() is not usable: no callback has run, so it would
   report a false positive. The allocation is released the way the library
   does it instead. */

/* libusb builds with -Werror=missing-prototypes, so the entry point
 * needs a declaration of its own. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct libusb_transfer *transfer;
    struct usbi_transfer *itransfer;
    unsigned char *buffer;
    unsigned char *ptr;
    uint8_t bmRequestType, bRequest;
    uint16_t wValue, wIndex, wLength;
    size_t payload_len, priv_size;

    /* The first 8 bytes become the setup fields, the rest is payload. */
    if (size < 8)
        return 0;

    bmRequestType = data[0];
    bRequest = data[1];
    wValue = (uint16_t)(data[2] | (data[3] << 8));
    wIndex = (uint16_t)(data[4] | (data[5] << 8));
    wLength = (uint16_t)(data[6] | (data[7] << 8));
    payload_len = size - 8;

    buffer = malloc(LIBUSB_CONTROL_SETUP_SIZE + payload_len);
    if (!buffer)
        return 0;
    memset(buffer, 0, LIBUSB_CONTROL_SETUP_SIZE);
    if (payload_len)
        memcpy(buffer + LIBUSB_CONTROL_SETUP_SIZE, data + 8, payload_len);

    transfer = libusb_alloc_transfer(0);
    if (!transfer) {
        free(buffer);
        return 0;
    }

    libusb_fill_control_setup(buffer, bmRequestType, bRequest, wValue, wIndex,
                              wLength);

    itransfer = LIBUSB_TRANSFER_TO_USBI_TRANSFER(transfer);
    usbi_mutex_destroy(&itransfer->lock);
    priv_size = PTR_ALIGN(usbi_backend.transfer_priv_size);
    ptr = (unsigned char *)itransfer - priv_size;
    free(ptr);
    free(buffer);

    return 0;
}
