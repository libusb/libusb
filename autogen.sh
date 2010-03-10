#!/bin/sh

# use glibtoolize if it is available (darwin)
(glibtoolize --version) < /dev/null > /dev/null 2>&1 && LIBTOOLIZE=glibtoolize || LIBTOOLIZE=libtoolize

$LIBTOOLIZE --copy --force || exit 1
# Force ltmain's NLS test to set locale to C always. Prevents an
# issue when compiling shared libs with MinGW on Chinese locale.
type -P sed &>/dev/null || { echo "sed command not found. Aborting." >&2; exit 1; }
sed -e s/\\\\\${\$lt_var+set}/set/g ltmain.sh > lttmp.sh
mv lttmp.sh ltmain.sh
#
aclocal || exit 1
autoheader || exit 1
autoconf || exit 1
automake -a -c || exit 1
./configure --enable-debug-log --enable-examples-build $*
