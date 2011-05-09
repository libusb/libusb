#!/bin/sh
# bump the version and update the git tree accordingly
# !!!THIS SCRIPT IS FOR INTERNAL DEVELOPER USE ONLY!!!

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
if [ ! ${TAG:0:3} = 'pbr' ]; then
  echo Tag "$TAG" does not start with 'pbr' - aborting
  exit 1
fi
TAGVER=${TAG:3}
case $TAGVER in *[!0-9]*) 
  echo "$TAGVER is not a number"
  exit 1
esac
OFFSET=10000
TAGVER=`expr $TAGVER + 1`
TAGVER_OFF=`expr $TAGVER + $OFFSET`
echo "Bumping version to pbr$TAGVER (nano: $TAGVER_OFF)"
# we're duplicating libusb_version.h generation here, but that avoids having to run configure
sed -e "s/\(^#define\s*LIBUSB_NANO.*\)/#define LIBUSB_NANO $TAGVER_OFF/" libusb/version.h > libusb/version.h~
mv libusb/version.h~ libusb/version.h
git commit -a -m "[internal] bumped internal version" -e
git tag "pbr$TAGVER"