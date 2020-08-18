#!/bin/sh

set -e

./bootstrap.sh
if [ -z "$NOCONFIGURE" ]; then
    exec ./configure --enable-examples-build --enable-tests-build "$@"
fi
