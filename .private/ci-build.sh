#!/bin/bash

set -e

builddir=
scriptdir=$(dirname $(readlink -f "$0"))
install=no
test=yes
asan=yes
tidy=no

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
	--clang-tidy)
		tidy=yes
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

gitdir=$(git rev-parse --show-toplevel)

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
if [ "${tidy}" = "yes" ]; then
	# Clang-Tidy needs to be run with Clang compiler
	CFLAGS="${cflags}" CXXFLAGS="${cflags}" CC="clang" CXX="clang++" ../configure \
		--enable-examples-build --enable-tests-build "$@"
else
	CFLAGS="${cflags}" CXXFLAGS="${cflags}" ../configure --enable-examples-build \
		--enable-tests-build "$@"
fi

echo ""
echo "Building ..."

if [ "${tidy}" = "yes" ]; then
	# $(@D) and $(<F) are GNU Make automatic variables.
	# $(@D): '$(@D)' is equivalent to '$(dirname $@)'.
	# $(<F): '$(<F)' is equivalent to '$(notdir $<)'.
	# example: 'src/foo.c' -> 'builddir/src/foo.c.compdb.json'
	# More info: https://www.gnu.org/software/make/manual/html_node/Automatic-Variables.html
	# add CFLAGS here as automake escapes them
	cflags+=" -MJ \$(@D)/\$(<F).compdb.json"
	make -j4 -k CFLAGS="${cflags}" CXXFLAGS="${cflags}"

	# Create compile_commands.json from all the .compdb.json files.
	echo "[" > compile_commands.json
	find . -name "*compdb.json" -exec cat {} \; >> compile_commands.json
	echo "]" >> compile_commands.json

	built_files=$(find . -name "*.compdb.json" -printf "${gitdir}/%P " | \
		sed 's/.compdb.json//g')
	reldr=$(realpath --relative-to="$(pwd)" "${gitdir}")

	# Get llvmorg-21.1.0-rc3 clang-tidy-diff.py script from LLVM project.
	wget https://raw.githubusercontent.com/llvm/llvm-project/refs/tags/llvmorg-21.1.0-rc3/clang-tools-extra/clang-tidy/tool/clang-tidy-diff.py

	# Use clang-tidy-diff to check only the files that were built.
	# clang-tidy-diff expects the files to be relative to the git root.
	# shellcheck disable=SC2086, SC2154
	git diff -U0 "${current_sha}^..${current_sha}" --dst-prefix="b/${reldr}/" \
		--src-prefix="a/${reldr}/" -- $built_files | \
		python3 clang-tidy-diff.py -p1 -warnings-as-errors="*" \
		-config-file="${gitdir}/.clang-tidy"

	exit $?
fi

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
