/* -*- Mode: C; indent-tabs-mode:nil -*- */
/*
 * Unit tests for libusb_set_option
 * Copyright © 2023 Nathan Hjelm <hjelmn@cs.unm.edu>
 * Copyright © 2023 Google, LLC. All rights reserved.
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
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "config.h"

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include "libusbi.h"
#include "libusb_testlib.h"

#define LIBUSB_TEST_CLEAN_EXIT(code) \
  do {                               \
    if (test_ctx != NULL) {          \
      libusb_exit(test_ctx);         \
    }                                \
    unsetenv("LIBUSB_DEBUG");        \
    return (code);                   \
  } while (0)

/**
 * Fail the test if the expression does not evaluate to LIBUSB_SUCCESS.
 */
#define LIBUSB_TEST_RETURN_ON_ERROR(expr)                       \
  do {                                                          \
    int _result = (expr);                                       \
    if (LIBUSB_SUCCESS != _result) {                            \
      libusb_testlib_logf("Not success (%s) at %s:%d", #expr,   \
                          __FILE__, __LINE__);                  \
      LIBUSB_TEST_CLEAN_EXIT(TEST_STATUS_FAILURE);              \
    }                                                           \
  } while (0)

/**
 * Use relational operator to compare two values and fail the test if the
 * comparison is false. Intended to compare integer or pointer types.
 *
 * Example: LIBUSB_EXPECT(==, 0, 1) -> fail, LIBUSB_EXPECT(==, 0, 0) -> ok.
 */
#define LIBUSB_EXPECT(operator, lhs, rhs)                               \
  do {                                                                  \
    int64_t _lhs = (lhs), _rhs = (rhs);                                 \
    if (!(_lhs operator _rhs)) {                                        \
      libusb_testlib_logf("Expected %s (%" PRId64 ") " #operator        \
                          " %s (%" PRId64 ") at %s:%d", #lhs,           \
                          (int64_t)(intptr_t)_lhs, #rhs,                \
                          (int64_t)(intptr_t)_rhs, __FILE__,            \
                          __LINE__);                                    \
      LIBUSB_TEST_CLEAN_EXIT(TEST_STATUS_FAILURE);                      \
    }                                                                   \
  } while (0)


extern uint32_t libusb_testonly_fake_running_version;
extern int libusb_testonly_using_running_interface_version;
extern int libusb_testonly_using_running_device_version;
extern bool libusb_testonly_clear_running_version_cache;

static libusb_testlib_result test_macos_version_fallback(void) {
  libusb_context *test_ctx = NULL;
  libusb_testonly_fake_running_version = 100001;
  libusb_testonly_clear_running_version_cache = true;

  LIBUSB_TEST_RETURN_ON_ERROR(libusb_init_context(&test_ctx, /*options=*/NULL,
                                                  /*num_options=*/0));
  LIBUSB_EXPECT(==, libusb_testonly_using_running_interface_version, 220);
  LIBUSB_EXPECT(==, libusb_testonly_using_running_device_version, 197);

  libusb_exit(test_ctx);
  test_ctx = NULL;

  libusb_testonly_fake_running_version = 100900;

  LIBUSB_TEST_RETURN_ON_ERROR(libusb_init_context(&test_ctx, /*options=*/NULL,
                                                  /*num_options=*/0));
  LIBUSB_EXPECT(==, libusb_testonly_using_running_interface_version, 650);
  LIBUSB_EXPECT(==, libusb_testonly_using_running_device_version, 650);

  libusb_exit(test_ctx);
  test_ctx = NULL;

  libusb_testonly_fake_running_version = 101200;

  LIBUSB_TEST_RETURN_ON_ERROR(libusb_init_context(&test_ctx, /*options=*/NULL,
                                                  /*num_options=*/0));
  LIBUSB_EXPECT(==, libusb_testonly_using_running_interface_version, 800);
  LIBUSB_EXPECT(==, libusb_testonly_using_running_device_version, 650);

  libusb_exit(test_ctx);
  test_ctx = NULL;

  // Test a version smaller than 10.0. Initialization should fail.
  libusb_testonly_fake_running_version = 99999;

  int error = libusb_init_context(&test_ctx, /*options=*/NULL,
                                  /*num_options=*/0);
  LIBUSB_EXPECT(!=, error, LIBUSB_SUCCESS);


  LIBUSB_TEST_CLEAN_EXIT(TEST_STATUS_SUCCESS);
}

static const libusb_testlib_test tests[] = {
  { "test_macos_version_fallback", &test_macos_version_fallback },
  LIBUSB_NULL_TEST
};

int main(int argc, char *argv[])
{
  return libusb_testlib_run_tests(argc, argv, tests);
}
