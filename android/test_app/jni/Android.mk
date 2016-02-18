# Android build config for libusb, examples and tests
# Copyright © 2016 Eugene Hutorny <eugene@hutorny.in.ua>
# Copyright © 2012-2013 RealVNC Ltd. <toby.gray@realvnc.com>
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
#

LOCAL_PATH    := $(call my-dir)

# libftd2xx 1.3.6 is not usable on android due to missing DT_HASH
# it should have been build with -Wl,--hash-style=both
# perhaps, it will be fixed some day
# libftd2xx-arm64-v8-hf-1.3.6.tgz is not available
# libftd2xx-mips-eglibc-hf-1.3.6.tgz is big endian (Android is little endian)
# libftd2xx-mips64-eglibc-hf-1.3.6.tgz is not available

LIBFTD2XX_ABI := armeabi armeabi-v7a x86 x86_64
LIBFTD2XX_OK  := $(and LIBFTD2XX, $(strip									\
				 $(filter $(LIBFTD2XX_ABI), $(TARGET_ARCH_ABI))))
include $(LOCAL_PATH)/jaemon.mk
include $(LOCAL_PATH)/libusb.mk
include $(LOCAL_PATH)/examples.mk
include $(LOCAL_PATH)/tests.mk
include $(if $(LIBFTDI_ROOT),$(LOCAL_PATH)/libftdi.mk,)
include $(if $(LIBFTDI_ROOT),$(LOCAL_PATH)/libftdi_tests.mk,)
include $(if $(LIBFTD2XX_OK),$(LOCAL_PATH)/D2XX_tests.mk,)
include $(LOCAL_PATH)/ch34x_tests.mk
