#!/bin/sh
date=`date +%Y.%m.%d`

#
# 32 bit binaries
#
target=e:/dailies/$date/MinGW32
git clean -f -d -x
# Not using debug (-g) in CFLAGS DRAMATICALLY reduces the size of the binaries
export CFLAGS="-O2 -m32"
export RCFLAGS="--target=pe-i386"
echo `pwd`
(glibtoolize --version) < /dev/null > /dev/null 2>&1 && LIBTOOLIZE=glibtoolize || LIBTOOLIZE=libtoolize
$LIBTOOLIZE --copy --force || exit 1
aclocal || exit 1
autoheader || exit 1
autoconf || exit 1
automake -a -c || exit 1
./configure --enable-examples-build --enable-toggable-debug
make
mkdir -p $target/examples
mkdir -p $target/lib
mkdir -p $target/dll
cp -v examples/.libs/lsusb.exe $target/examples
cp -v examples/.libs/xusb.exe $target/examples
cp -v libusb/.libs/libusb-1.0.a $target/lib
cp -v libusb/.libs/libusb-1.0.dll $target/dll
cp -v libusb/.libs/libusb-1.0.dll.a $target/dll
make clean

#
# 64 bit binaries
#
target=e:/dailies/$date/MinGW64
export CFLAGS="-O2 -m64"
export RCFLAGS=""
./configure --enable-examples-build --enable-toggable-debug
make
mkdir -p $target/examples
mkdir -p $target/lib
mkdir -p $target/dll
cp -v examples/.libs/lsusb.exe $target/examples
cp -v examples/.libs/xusb.exe $target/examples
cp -v libusb/.libs/libusb-1.0.a $target/lib
cp -v libusb/.libs/libusb-1.0.dll $target/dll
cp -v libusb/.libs/libusb-1.0.dll.a $target/dll