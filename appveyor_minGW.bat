echo on
SetLocal EnableDelayedExpansion

if [%Configuration%] NEQ [Debug] goto releasex64

:releasex64
if [%Platform%] NEQ [x64] goto releaseWin32
if [%Configuration%] NEQ [Release] exit 0
C:\msys64\usr\bin\bash -e -l -c "mkdir build-x64"
C:\msys64\usr\bin\bash -e -l -c ./autogen.sh
C:\msys64\usr\bin\bash -e -l -c "cd build-x64"
C:\msys64\usr\bin\bash -e -l -c "build-x64/../configure --prefix=/mingw64 --build=--build= --host=x86_64-w64-mingw32"
C:\msys64\usr\bin\bash -e -l -c "make -j4"
C:\msys64\usr\bin\bash -e -l -c "make install"

:releaseWin32
if [%Platform%] NEQ [Win32] exit 0
if [%Configuration%] NEQ [Release] exit 0
C:\msys64\usr\bin\bash -e -l -c "mkdir build-Win32"
C:\msys64\usr\bin\bash -e -l -c ./autogen.sh
C:\msys64\usr\bin\bash -e -l -c "cd build-Win32"
C:\msys64\usr\bin\bash -e -l -c "build-Win32/../configure --prefix=/mingw32 --build=i686-w64-mingw32 --host=i686-w64-mingw32"
C:\msys64\usr\bin\bash -e -l -c "make -j4"
C:\msys64\usr\bin\bash -e -l -c "make install"