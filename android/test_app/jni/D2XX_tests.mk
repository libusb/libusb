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
D2XX_VER ?= 1.3.6

LIBUSB_ROOT_REL:= ../../..
LIBUSB_ROOT_ABS:= $(abspath $(LOCAL_PATH)/$(LIBUSB_ROOT_REL))
D2XX_LINUX_URL ?= http://www.ftdichip.com/Drivers/D2XX/Linux/

TARGET_D2XX := $(strip 		 												\
  $(subst arm64-v8a,arm64-v8-hf,											\
  $(subst armeabi,arm-v5-sf,												\
  $(subst armeabi-v7a,arm-v5-sf,											\
  $(subst mips-eglibc-hf64,mips-eglibc-hf,									\
  $(subst mips,mips-eglibc-hf,												\
  $(subst i368_64,x86_64,													\
  $(subst x86,i368,															\
    $(TARGET_ARCH_ABI)))))))))

D2XX_PATH := $(LOCAL_PATH)/deps/$(TARGET_ARCH_ABI)/D2XX
D2XX_TAR  := libftd2xx-$(TARGET_D2XX)-$(D2XX_VER).tgz

DOWNLOAD:=$(and $(shell make -f $(LOCAL_PATH)/D2XX_download.mk				\
		LOCAL_PATH=$(LOCAL_PATH)											\
		D2XX_PATH=$(D2XX_PATH)												\
		D2XX_TAR=$(D2XX_TAR)												\
		D2XX_VER=$(D2XX_VER)												\
	),)

#==============================================================================
# libftd2xx

include $(CLEAR_VARS)
LOCAL_MODULE := ftd2xx
LOCAL_SRC_FILES := $(D2XX_PATH)/build/libftd2xx.so
include $(or $(call DOWNLOAD),$(PREBUILT_SHARED_LIBRARY))

#==============================================================================
# simple

include $(CLEAR_VARS)

$(D2XX_PATH)/examples/Simple/main.c: | $(D2XX_PATH)/ftd2xx.h

LOCAL_SRC_FILES := \
  $(D2XX_PATH)/examples/Simple/main.c

LOCAL_C_INCLUDES += \
  $(LOCAL_PATH)																\
  $(D2XX_PATH)/src

LOCAL_CFLAGS := --include jaemon.h

LOCAL_SHARED_LIBRARIES += usb-1.0 jaemon ftd2xx

#LOCAL_LDLIBS += -L$(D2XX_PATH)/build -lftd2xx

LOCAL_MODULE:= libftd2xx_simple

include $(BUILD_SHARED_LIBRARY)

