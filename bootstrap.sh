#!/bin/sh

set -e

# use libtoolize if available, otherwise look for glibtoolize (darwin)
if (libtoolize --version) < /dev/null > /dev/null 2>&1; then
  LIBTOOLIZE=libtoolize
elif (glibtoolize --version) < /dev/null > /dev/null 2>&1; then
  LIBTOOLIZE=glibtoolize
else
  echo "libtoolize or glibtoolize was not found! Please install libtool." 1>&2
  exit 1
fi

$LIBTOOLIZE --copy --force || exit 1
aclocal || exit 1
autoheader || exit 1
autoconf || exit 1
automake -a -c || exit 1
