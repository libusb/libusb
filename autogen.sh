#!/bin/sh

set -e

./bootstrap.sh
if test -z "$NOCONFIGURE"; then
    exec ./configure --enable-maintainer-mode --enable-examples-build --enable-tests-build "$@"
fi
