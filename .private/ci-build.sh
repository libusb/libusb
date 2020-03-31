#!/bin/bash

set -e

builddir=
install=no

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

echo ""
echo "Configuring ..."
CFLAGS="${cflags}" ../configure --enable-examples-build --enable-tests-build "$@"

echo ""
echo "Building ..."
make -j4 -k

if [ "${install}" = "yes" ]; then
	echo ""
	echo "Installing ..."
	make install
fi
