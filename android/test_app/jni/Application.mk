# Android application build config for libusb test_app
# Copyright © 2016 Eugene Hutorny <eugnene@hutorny.in.ua>
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

APP_ABI := $(or $(APP_ABI),all)

#If no platform specified, using the most recent one
APP_PLATFORM := $(strip $(or $(APP_PLATFORM),								\
	$(shell echo `for i in ${NDK}/platforms/*-?? ; do basename $${i}; done 	\
		| tail -1`)))
#If no toolchain version specified, using the most recent one
NDK_TOOLCHAIN_VERSION := $(or $(NDK_TOOLCHAIN_VERSION),						\
	$(strip $(subst arm-linux-androideabi-,,								\
	$(shell echo `for i in ${NDK}/toolchains/arm-linux-androideabi-?.? ; 	\
		do basename $${i}; done | tail -1`))))

# Workaround for MIPS toolchain linker being unable to find liblog dependency
# of shared object in NDK versions at least up to r9.
#

APP_LDFLAGS := -llog
APP_PIE := 1
