# Android build config for libftdi examples to be run by test_app
# Copyright © 2016 Eugene Hutorny <eugene@hutorny.in.ua>
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


LOCAL_PATH := $(or $(call my-dir),$(shell pwd))
TARGET_ARCH_ABI := $(or $(TARGET_ARCH_ABI),armeabi-v7a)
LIBUSB_ROOT_REL:= ../../..
LIBUSB_ROOT_ABS:= $(abspath $(LOCAL_PATH)/$(LIBUSB_ROOT_REL))


#==============================================================================
# ch34x

include $(CLEAR_VARS)


LOCAL_SRC_FILES := ch340.c

LOCAL_CFLAGS := -std=c11 --include jaemon.h

LOCAL_SHARED_LIBRARIES += usb-1.0 jaemon

LOCAL_MODULE:= libch340

include $(BUILD_SHARED_LIBRARY)

