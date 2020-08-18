#!/bin/sh

set -e

if [ ! -d m4 ]; then
    mkdir m4
fi
exec autoreconf -ivf
