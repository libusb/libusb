# Android build config for libftdi tests and examples to be run by test_app
# Copyright © 2016 Eugene Hutorny <eugnene@hutorny.in.ua>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

LOCAL_PATH:= $(call my-dir)
LIBUSB_ROOT_REL:= ../../..
LIBUSB_ROOT_ABS:= $(abspath $(LOCAL_PATH)/$(LIBUSB_ROOT_REL))

#LIBFTDI_ROOT must be specified by the caller
LIBFTDI_ROOT_SET := $(if $(LIBFTDI_ROOT),yes,$(error LIBFTDI_ROOT is not set))

# libftdi

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
  $(LIBFTDI_ROOT)/src/ftdi.c												\
  $(LIBFTDI_ROOT)/src/ftdi_stream.c

LOCAL_C_INCLUDES += \
  $(LIBFTDI_ROOT)/src

LOCAL_SHARED_LIBRARIES += libusb1.0

LOCAL_MODULE:= libftdi

include $(BUILD_SHARED_LIBRARY)
