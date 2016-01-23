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


D2XX_LINUX_URL ?= http://www.ftdichip.com/Drivers/D2XX/Linux/

download:: $(D2XX_PATH)/ftd2xx.h

.PHONY: download

$(LOCAL_PATH)/.dl:
	mkdir -p $@

$(LOCAL_PATH)/.dl/$(D2XX_TAR): | $(LOCAL_PATH)/.dl 
	$(hide) wget -q -O $@ $(D2XX_LINUX_URL)$(notdir $@)

D2XX_download.mk::;

$(D2XX_PATH)/ftd2xx.h: $(LOCAL_PATH)/.dl/$(D2XX_TAR)
	$(hide) mkdir -p $(dir $@)
	$(hide) tar --strip-components 1 --exclude=libusb -xf $< -C $(dir $@)
	$(hide) ln -fs $(D2XX_PATH)/build/libftd2xx.so.$(D2XX_VER)				\
			$(D2XX_PATH)/build/libftd2xx.so
