#!/bin/sh
date=`date +%Y.%m.%d`
git clean -f -d -x
# Not using debug (-g) in CFLAGS DRAMATICALLY reduces the size of the binaries
export CFLAGS="-O2"
echo `pwd`
./autogen.sh
make
cp examples/.libs/lsusb.exe e:/dailies/$date/MinGW32/examples
cp examples/.libs/xusb.exe e:/dailies/$date/MinGW32/examples
cp libusb/.libs/libusb-1.0.a e:/dailies/$date/MinGW32/lib
cp libusb/.libs/libusb-1.0.dll e:/dailies/$date/MinGW32/dll
cp libusb/.libs/libusb-1.0.dll.a e:/dailies/$date/MinGW32/dll
