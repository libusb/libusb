#!/bin/bash

set -eu

# keep container around if $DEBUG is set
[ -n "${DEBUG:-}" ] || OPTS="--rm"

if type podman >/dev/null 2>&1; then
    RUNC=podman
else
    RUNC="sudo docker"
fi

MOUNT_MODE=":ro"

$RUNC run --interactive ${RUNC_OPTIONS:-} ${OPTS:-} --volume `pwd`:/source${MOUNT_MODE:-} ${1:-docker.io/amd64/ubuntu:rolling} /bin/bash << EOF
set -ex

# avoid meson exit code 125; https://github.com/containers/podman/issues/11540
trap '[ \$? -eq 0 ] || exit 1' EXIT

# go-faster apt
echo  'Acquire::Languages "none";' > /etc/apt/apt.conf.d/90nolanguages

# upgrade
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y eatmydata
eatmydata apt-get -y --purge dist-upgrade

# install build and test dependencies
# 'git' is required by build-aux/gen-describe.sh to populate the
# LIBUSB_DESCRIBE string at configure/build time when .git is present.
# (NOTE: this comment intentionally avoids backticks around 'git' because
# the surrounding heredoc is unquoted; backticks would trigger command
# substitution by the outer shell and splat git's output into the body.)
eatmydata apt-get install -y make libtool libudev-dev pkg-config umockdev libumockdev-dev git

# run build as user
useradd build
su -s /bin/bash - build << 'EOG'
set -ex

mkdir "/tmp/builddir"
cd "/tmp/builddir"

CFLAGS="-O2"

# enable extra warnings
CFLAGS+=" -Winline"
CFLAGS+=" -Wmissing-include-dirs"
CFLAGS+=" -Wnested-externs"
CFLAGS+=" -Wpointer-arith"
CFLAGS+=" -Wredundant-decls"
CFLAGS+=" -Wswitch-enum"

export CXXFLAGS="\${CFLAGS}"
CFLAGS+=" -std=c23"
export CFLAGS

echo ""
echo "Configuring ..."
/source/configure --enable-examples-build --enable-tests-build

echo ""
echo "Checking C23 headers ..."
printf '%s\n' \
	'#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L' \
	'#error compiler does not report final C23 mode' \
	'#endif' \
	'#include <assert.h>' \
	'#ifdef static_assert' \
	'#define SYSTEM_STATIC_ASSERT_IS_MACRO 1' \
	'#endif' \
	'#include "libusbi.h"' \
	'#if !defined(SYSTEM_STATIC_ASSERT_IS_MACRO) && defined(static_assert)' \
	'#error libusbi.h must not define static_assert in C23' \
	'#endif' | \
	gcc -std=c23 -I. -I/source/libusb -E -x c -o /dev/null -

gcc -std=c23 -I/source/libusb -dM -E -include libusb.h -x c /dev/null | \
	grep -F '#define LIBUSB_DEPRECATED_FOR(f) [[deprecated("Use " #f " instead")]]'

echo ""
echo "Building ..."
make -j4 -k

echo ""
echo "Running umockdev tests ..."
tests/umockdev
EOG
EOF
