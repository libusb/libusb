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
eatmydata apt-get install -y make libtool libudev-dev pkg-config umockdev libumockdev-dev

# run build as user
useradd build
su -s /bin/bash - build << EOG
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
export CFLAGS

echo ""
echo "Configuring ..."
/source/configure --enable-examples-build --enable-tests-build

echo ""
echo "Building ..."
make -j4 -k

echo ""
echo "Running umockdev tests ..."
tests/umockdev

echo "Running stress tests ..."
tests/stress
tests/stress_mt
EOG
EOF


