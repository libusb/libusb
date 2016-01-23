#!/bin/sh
# This file is originated from https://gist.github.com/nddrylliog/4688209

if [ "$NDK" = "" ]; then
	echo "NDK environment variable is not set, unable to contrinue"
	exit 1
fi

if [ "$APP_PLATFORM" = "" ]; then
	export APP_PLATFORM=`for i in $NDK/platforms/*-?? ; do basename ${i%%}; done | tail -1`
	echo "APP_PLATFORM not specified, assuming $APP_PLATFORM"
fi

SELF=$(readlink -m $0)
BASE_DIR=`dirname $SELF`
export LIBUSB_DIR=$(readlink -m $BASE_DIR/..)
export LIBUSB_INCLUDE_DIR=${LIBUSB_DIR}/libusb
export LIBUSB_LIBRARIES=$BASE_DIR/libs/armeabi/libusb.1.0.so
export PREFIX=`pwd`/out
export CROSS_COMPILE=arm-linux-androideabi
export ANDROID_PREFIX=${NDK}/toolchains/${CROSS_COMPILE}-4.9/prebuilt/linux-x86/
export SYSROOT=${NDK}/platforms/${APP_PLATFORM}/arch-arm
export CROSS_PATH=${ANDROID_PREFIX}/bin/${CROSS_COMPILE}

# Non-exhaustive lists of compiler + binutils
# Depending on what you compile, you might need more binutils than that
export CPP=${CROSS_PATH}-cpp
export AR=${CROSS_PATH}-ar
export AS=${CROSS_PATH}-as
export NM=${CROSS_PATH}-nm
export CC=${CROSS_PATH}-gcc
export CXX=${CROSS_PATH}-g++
export LD=${CROSS_PATH}-ld
export RANLIB=${CROSS_PATH}-ranlib

# Don't mix up .pc files from your host and build target
export PKG_CONFIG_PATH=${PREFIX}/lib/pkgconfig
export CFLAGS="${CFLAGS} -fPIC --sysroot=${SYSROOT} -I${SYSROOT}/usr/include -I${ANDROID_PREFIX}/include"
export CPPFLAGS="${CFLAGS}"
export CXXFLAGS="${CFLAGS}"
export LDFLAGS="${LDFLAGS} -fPIE -L${SYSROOT}/usr/lib -L${ANDROID_PREFIX}/lib"
if [ -f ./autogen.sh ]; then
	./autogen.sh --host=${CROSS_COMPILE} --with-sysroot=${SYSROOT} --prefix=${PREFIX}/lib "$@"
elif [ -f ./configure ]; then
	./configure --host=${CROSS_COMPILE} --with-sysroot=${SYSROOT} --prefix=${PREFIX}/lib "$@"
elif [ -f ./CMakeLists.txt ]; then
	cmake \
		-D LIBC_HAS_DGETTEXT=0												\
		-D CMAKE_C_FLAGS="${CFLAGS}"										\
		-D CMAKE_CXX_FLAGS="${CXXFLAGS}"									\
		-D CMAKE_SYSROOT="${SYSROOT}" 										\
		-D LIBUSB_INCLUDE_DIR="${LIBUSB_INCLUDE_DIR}"						\
		-D LIBUSB_LIBRARIES="${LIBUSB_LIBRARIES}"							\
		"$@"-Bbuild/ .
fi
