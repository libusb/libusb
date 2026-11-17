/* -*- Mode: C; indent-tabs-mode:nil -*- */
/*
 * Darwin transfer timeout byte accounting
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#ifndef LIBUSB_DARWIN_TIMEOUT_H
#define LIBUSB_DARWIN_TIMEOUT_H

#include <stdbool.h>
#include <stdint.h>

#include "libusb.h"

/*
 * Apple documents the async read/write callback's arg0 as the number of
 * bytes actually transferred, including when the transfer times out, so
 * preserve that count.
 *
 * macOS 15 on Apple Silicon was observed reporting the full requested
 * length with stale data on a timed-out bulk IN transfer (the MT7961
 * reproduction). A full-length bulk IN transfer should complete as
 * success, not timeout, so treat only that anomalous case as zero.
 * Partial timeouts and all OUT, control and interrupt transfers keep the
 * reported size.
 */
static inline uint32_t darwin_timeout_transferred(bool timed_out,
                                                  int transfer_type,
                                                  uint8_t endpoint,
                                                  uint32_t reported,
                                                  uint32_t length)
{
  if (timed_out &&
      (transfer_type == LIBUSB_TRANSFER_TYPE_BULK ||
       transfer_type == LIBUSB_TRANSFER_TYPE_BULK_STREAM) &&
      (endpoint & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_IN &&
      reported == length)
    return 0;
  return reported;
}

#endif /* LIBUSB_DARWIN_TIMEOUT_H */
