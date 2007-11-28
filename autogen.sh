#!/bin/sh
libtoolize --copy --force || exit 1
aclocal || exit 1
autoheader || exit 1
autoconf || exit 1
automake -a -c || exit 1
./configure --enable-maintainer-mode --enable-debug-log \
	--enable-examples-build $*
