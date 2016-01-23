# Android build config for libftdi examples to be run by test_app
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

$(LOCAL_PATH)/examples:
	mkdir -p $@

$(LOCAL_PATH)/examples/0001-ftdi-examples.status: $(LOCAL_PATH)/examples
	$(call host-echo-build-step,$(TARGET_ARCH_ABI),FTDI examples) Patching 	        
	$(hide) cp $(LIBFTDI_ROOT)/examples/serial_test.c $(LOCAL_PATH)/examples/
	$(hide) cp $(LIBFTDI_ROOT)/examples/simple.c $(LOCAL_PATH)/examples/
	$(hide) cp $(LIBFTDI_ROOT)/examples/stream_test.c $(LOCAL_PATH)/examples/
	$(hide) patch -p1 <  patches/0001-ftdi-examples.patch >  $@


#==============================================================================
# find_all

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
  $(LIBFTDI_ROOT)/examples/find_all.c
  
LOCAL_C_INCLUDES += \
  $(LOCAL_PATH)																\
  $(LIBFTDI_ROOT)/src

LOCAL_CFLAGS := \
  --include jaemon.h

LOCAL_SHARED_LIBRARIES += libusb1.0 libftdi

LOCAL_MODULE:= libftdi_find_all

include $(BUILD_SHARED_LIBRARY)

#==============================================================================
# serial_test

include $(CLEAR_VARS)

$(LOCAL_PATH)/examples/serial_test.c: 										\
   $(LOCAL_PATH)/examples/0001-ftdi-examples.status							\
   $(LIBFTDI_ROOT)/examples/serial_test.c

LOCAL_SRC_FILES := \
  $(LOCAL_PATH)/examples/serial_test.c
#  $(LIBFTDI_ROOT)/examples/serial_test.c
  
LOCAL_C_INCLUDES += \
  $(LOCAL_PATH)																\
  $(LIBFTDI_ROOT)/src

LOCAL_CFLAGS := --include jaemon.h

LOCAL_SHARED_LIBRARIES += libusb1.0 libftdi libjaemon

LOCAL_MODULE:= libftdi_serial_test

include $(BUILD_SHARED_LIBRARY)

#==============================================================================
# simple

include $(CLEAR_VARS)

$(LOCAL_PATH)/examples/simple.c: 											\
  $(LOCAL_PATH)/examples/0001-ftdi-examples.status						\
  $(LIBFTDI_ROOT)/examples/simple.c

LOCAL_SRC_FILES := \
  $(LOCAL_PATH)/examples/simple.c
  
LOCAL_C_INCLUDES += \
  $(LOCAL_PATH)																\
  $(LIBFTDI_ROOT)/src

LOCAL_CFLAGS := --include jaemon.h

LOCAL_SHARED_LIBRARIES += libusb1.0 libftdi libjaemon

LOCAL_MODULE:= libftdi_simple

include $(BUILD_SHARED_LIBRARY)

#==============================================================================
# simple

include $(CLEAR_VARS)

$(LOCAL_PATH)/examples/stream_test.c:										\
  $(LOCAL_PATH)/examples/0001-ftdi-examples.status							\
  $(LIBFTDI_ROOT)/examples/simple.c
  

LOCAL_SRC_FILES := \
  $(LOCAL_PATH)/examples/stream_test.c
  
LOCAL_C_INCLUDES += \
  $(LOCAL_PATH)																\
  $(LIBFTDI_ROOT)/src

LOCAL_CFLAGS := --include jaemon.h

LOCAL_SHARED_LIBRARIES += libusb1.0 libftdi libjaemon

LOCAL_MODULE:= libftdi_stream_test

include $(BUILD_SHARED_LIBRARY)
