/* -*- Mode: C; indent-tabs-mode:nil -*- */
/*
 * Regression tests for Darwin timeout byte accounting
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

#include "config.h"

#include <stdint.h>

#include "libusb.h"
#include "libusb_testlib.h"
#include "os/darwin_timeout.h"

libusb_testlib_result test_darwin_timeout(void);

static unsigned failures;

static void check(const char *what, uint32_t got, uint32_t want)
{
  if (got != want) {
    libusb_testlib_logf("FAIL %s: got %u, want %u", what, got, want);
    failures++;
  }
}

libusb_testlib_result test_darwin_timeout(void)
{
  const uint32_t len = 512;
  const uint32_t partial = 64;

  failures = 0;

  /* Success and underrun preserve the reported count. */
  check("success bulk IN partial",
        darwin_timeout_transferred(false, LIBUSB_TRANSFER_TYPE_BULK, 0x81, partial, len), partial);
  check("success bulk IN full",
        darwin_timeout_transferred(false, LIBUSB_TRANSFER_TYPE_BULK, 0x81, len, len), len);
  check("underrun bulk IN partial",
        darwin_timeout_transferred(false, LIBUSB_TRANSFER_TYPE_BULK, 0x81, partial, len), partial);

  /* Every partial timeout keeps its valid partial data. */
  check("timeout bulk IN partial",
        darwin_timeout_transferred(true, LIBUSB_TRANSFER_TYPE_BULK, 0x81, partial, len), partial);
  check("timeout bulk OUT partial",
        darwin_timeout_transferred(true, LIBUSB_TRANSFER_TYPE_BULK, 0x01, partial, len), partial);
  check("timeout control IN partial",
        darwin_timeout_transferred(true, LIBUSB_TRANSFER_TYPE_CONTROL, 0x80, partial, len), partial);
  check("timeout control OUT partial",
        darwin_timeout_transferred(true, LIBUSB_TRANSFER_TYPE_CONTROL, 0x00, partial, len), partial);
  check("timeout bulk-stream IN partial",
        darwin_timeout_transferred(true, LIBUSB_TRANSFER_TYPE_BULK_STREAM, 0x81, partial, len), partial);
  check("timeout bulk-stream OUT partial",
        darwin_timeout_transferred(true, LIBUSB_TRANSFER_TYPE_BULK_STREAM, 0x01, partial, len), partial);
  check("timeout interrupt IN partial",
        darwin_timeout_transferred(true, LIBUSB_TRANSFER_TYPE_INTERRUPT, 0x82, partial, len), partial);

  /* The observed stale-buffer case: a full-length bulk IN timeout is zero. */
  check("timeout bulk IN full",
        darwin_timeout_transferred(true, LIBUSB_TRANSFER_TYPE_BULK, 0x81, len, len), 0);
  check("timeout bulk-stream IN full",
        darwin_timeout_transferred(true, LIBUSB_TRANSFER_TYPE_BULK_STREAM, 0x81, len, len), 0);

  /* A full-length timeout in every other direction/type is preserved. */
  check("timeout bulk OUT full",
        darwin_timeout_transferred(true, LIBUSB_TRANSFER_TYPE_BULK, 0x01, len, len), len);
  check("timeout bulk-stream OUT full",
        darwin_timeout_transferred(true, LIBUSB_TRANSFER_TYPE_BULK_STREAM, 0x01, len, len), len);
  check("timeout control IN full",
        darwin_timeout_transferred(true, LIBUSB_TRANSFER_TYPE_CONTROL, 0x80, len, len), len);
  check("timeout control OUT full",
        darwin_timeout_transferred(true, LIBUSB_TRANSFER_TYPE_CONTROL, 0x00, len, len), len);
  check("timeout interrupt IN full",
        darwin_timeout_transferred(true, LIBUSB_TRANSFER_TYPE_INTERRUPT, 0x82, len, len), len);

  return failures ? TEST_STATUS_FAILURE : TEST_STATUS_SUCCESS;
}
