#!/usr/bin/env bash

set -euo pipefail

SANDBOX_DIR=$(dirname $1)

pushd $SANDBOX_DIR > /dev/null

./bootstrap.sh > /dev/null 2>&1
./configure --silent

CONFIG_HDR=$PWD/config.h
popd > /dev/null

cp $CONFIG_HDR $2
