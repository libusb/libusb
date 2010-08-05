#!/bin/sh

# rebuilds the Windows def file by parsing the core and exporting all API_EXPORTED call
create_def()
{
  echo "rebuidling libusb-1.0.def file"
  echo "LIBRARY" > libusb/libusb-1.0.def
  echo "EXPORTS" >> libusb/libusb-1.0.def
  sed -n -e "s/.*API_EXPORTED.*\([[:blank:]]\)\(.*\)(.*/  \2/p" libusb/*.c >> libusb/libusb-1.0.def
  # We need to manually define a whole set of DLL aliases if we want the MS
  # DLLs to be usable with dynamically linked MinGW executables. This is
  # because it is not possible to avoid the @ decoration from import WINAPI
  # calls in MinGW generated objects, and .def based MS generated DLLs don't
  # have such a decoration => linking to MS DLL will fail without aliases.
  # Currently, the maximum size is 32 and all sizes are multiples of 4
  for i in 4 8 12 16 20 24 28 32
  do
    sed -n -e "s/.*API_EXPORTED.*\([[:blank:]]\)\(.*\)(.*/  \2@$i = \2/p" libusb/*.c >> libusb/libusb-1.0.def
  done
}

# use glibtoolize if it is available (darwin)
(glibtoolize --version) < /dev/null > /dev/null 2>&1 && LIBTOOLIZE=glibtoolize || LIBTOOLIZE=libtoolize

$LIBTOOLIZE --copy --force || exit 1
# If available, apply libtool's NLS patch to set locale to C always.
# Prevents an issue when compiling shared libs with MinGW on Chinese locale.
# see: http://lists.gnu.org/archive/html/bug-libtool/2010-03/msg00012.html
type -P patch &>/dev/null && { if [ -e "libtool-nls.diff" ]; then patch -p1 -Nl -i libtool-nls.diff &>/dev/null; fi; }
#
aclocal || exit 1
autoheader || exit 1
autoconf || exit 1
automake -a -c || exit 1
./configure --enable-maintainer-mode --enable-debug-log \
	--enable-examples-build $*
# rebuild .def, if sed is available
type -P sed &>/dev/null && create_def