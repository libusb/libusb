#!/bin/sh

# This script bumps the version and updates the git tree accordingly, with tag

type -P sed &>/dev/null || { echo "sed command not found. Aborting." >&2; exit 1; }
type -P git &>/dev/null || { echo "git command not found. Aborting." >&2; exit 1; }

if [ ! -n "$1" ]; then
  TAG=$(git describe --tags --abbrev=0 2>/dev/null)
  if [ ! -n "$TAG" ]; then
    echo Unable to read tag - aborting.
    exit 1
  fi
else
  TAG=$1
fi
if [ ! ${TAG:0:3} = 'pbh' ]; then
  echo Tag "$TAG" does not start with 'pbh' - aborting
  exit 1
fi
TAGVER=${TAG:3}
OFFSET=9000
# increment - ideally, we'd check that tagver is really numeric here
TAGVER=`expr $TAGVER + 1`
TAGVER_OFF=`expr $TAGVER + $OFFSET`
echo "Bumping version to pbr$TAGVER (nano: $TAGVER_OFF)"
sed -e "s/\(^m4_define(LIBUSB_NANO.*\)/m4_define(LIBUSB_NANO, [$TAGVER_OFF])/" configure.ac >> configure.ac~
mv configure.ac~ configure.ac
# we're duplicating libusb_version.h generation here, but that avoids having to run configure
sed -e "s/\(^#define LIBUSB_VERSION_NANO.*\)/#define LIBUSB_VERSION_NANO    $TAGVER_OFF/" libusb/libusb_version.h > libusb/libusb_version.h~
mv libusb/libusb_version.h~ libusb/libusb_version.h
git commit -a -m "bumped internal version"
git tag "pbh$TAGVER"