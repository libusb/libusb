#!/bin/sh
date=`date +%Y.%m.%d`
git clean -f -d -x
# Not using debug (-g) in CFLAGS DRAMATICALLY reduces the size of the binaries
export CFLAGS="-O2"
echo `pwd`
(glibtoolize --version) < /dev/null > /dev/null 2>&1 && LIBTOOLIZE=glibtoolize || LIBTOOLIZE=libtoolize
$LIBTOOLIZE --copy --force || exit 1
aclocal || exit 1
autoheader || exit 1
autoconf || exit 1
automake -a -c || exit 1
./configure --enable-examples-build $*
make
cp examples/.libs/lsusb.exe e:/dailies/$date/MinGW32/examples
cp examples/.libs/xusb.exe e:/dailies/$date/MinGW32/examples
cp libusb/.libs/libusb-1.0.a e:/dailies/$date/MinGW32/lib
cp libusb/.libs/libusb-1.0.dll e:/dailies/$date/MinGW32/dll
cp libusb/.libs/libusb-1.0.dll.a e:/dailies/$date/MinGW32/dll
