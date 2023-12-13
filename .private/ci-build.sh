#!/bin/bash

set -e

builddir=
scriptdir=$(dirname $(readlink -f "$0"))
install=no
test=yes
asan=yes

while [ $# -gt 0 ]; do
	case "$1" in
	--build-dir)
		if [ $# -lt 2 ]; then
			echo "ERROR: missing argument for --build-dir option" >&2
			exit 1
		fi
		builddir=$2
		shift 2
		;;
	--install)
		install=yes
		shift
		;;
	--no-test)
		test=no
		shift
		;;
	--no-asan)
		asan=no
		shift
		;;
	--)
		shift
		break;
		;;
	*)
		echo "ERROR: Unexpected argument: $1" >&2
		exit 1
	esac
done

if [ -z "${builddir}" ]; then
	echo "ERROR: --build-dir option not specified" >&2
	exit 1
fi

if [ -e "${builddir}" ]; then
	echo "ERROR: directory entry named '${builddir}' already exists" >&2
	exit 1
fi

mkdir "${builddir}"
cd "${builddir}"

cflags="-O2"

# enable extra warnings
cflags+=" -Winline"
cflags+=" -Wmissing-include-dirs"
cflags+=" -Wnested-externs"
cflags+=" -Wpointer-arith"
cflags+=" -Wredundant-decls"
cflags+=" -Wswitch-enum"

# enable address sanitizer
if [ "${asan}" = "yes" ]; then
	cflags+=" -fsanitize=address"
fi

echo ""
echo "Configuring ..."
CFLAGS="${cflags}" CXXFLAGS="${cflags}" ../configure --enable-examples-build --enable-tests-build "$@"

echo ""
echo "Building ..."
make -j4 -k

if [ "${test}" = "yes" ]; then
	# Load custom shim for WebUSB tests that simulates Web environment.
	export NODE_OPTIONS="--require ${scriptdir}/../tests/webusb-test-shim/"
	if ! make check ; then
	    cat tests/test-suite.log
	    exit 1
	fi
fi

if [ "${install}" = "yes" ]; then
	echo ""
	echo "Installing ..."
	make install
fi
