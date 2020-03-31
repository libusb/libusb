#!/bin/bash

set -eu

buildsys="${1}-${Platform}"

if [ "${buildsys}" == "MinGW-Win32" ]; then
	export PATH="/c/mingw-w64/i686-6.3.0-posix-dwarf-rt_v5-rev1/mingw32/bin:${PATH}"
elif [ "${buildsys}" == "MinGW-x64" ]; then
	export PATH="/c/mingw-w64/x86_64-8.1.0-posix-seh-rt_v6-rev0/mingw64/bin:${PATH}"
fi

builddir="build-${buildsys}"
installdir="${PWD}/libusb-${buildsys}"

cd libusb

echo "Bootstrapping ..."
./bootstrap.sh
echo ""

exec .private/ci-build.sh --build-dir "${builddir}" --install -- "--prefix=${installdir}"
