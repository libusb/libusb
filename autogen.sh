#!/bin/sh

set -e

./bootstrap.sh
./configure --enable-maintainer-mode --enable-examples-build --enable-tests-build "$@"
