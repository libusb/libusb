#!/bin/bash

CFLAGS="-O2"

CFLAGS+=" -Wbad-function-cast"
#CFLAGS+=" -Wcast-align"
CFLAGS+=" -Wformat-security"
CFLAGS+=" -Winit-self"
CFLAGS+=" -Winline"
CFLAGS+=" -Wmissing-include-dirs"
CFLAGS+=" -Wnested-externs"
CFLAGS+=" -Wold-style-definition"
CFLAGS+=" -Wpointer-arith"
CFLAGS+=" -Wredundant-decls"
CFLAGS+=" -Wswitch-enum"

# warnings disabled on purpose
CFLAGS+=" -Wno-deprecated-declarations"

export CFLAGS

exec ./autogen.sh "$@"
