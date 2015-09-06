// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBUSB_INTERRUPT_H
#define LIBUSB_INTERRUPT_H

#include "libusb.h"

#ifdef __cplusplus
extern "C" {
#endif

int LIBUSB_CALL libusb_interrupt_handle_event(struct libusb_context* ctx);

#ifdef __cplusplus
}
#endif

#endif  // LIBUSB_INTERRUPT_H
