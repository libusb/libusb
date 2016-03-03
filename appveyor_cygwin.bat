echo on
SetLocal EnableDelayedExpansion

if [%Configuration%] NEQ [Debug] goto releaseWin32

:releaseWin32
if [%Platform%] NEQ [Win32] exit 0
if [%Configuration%] NEQ [Release] exit 0
C:\cygwin\bin\bash -e -l -c "mkdir build-Win32-cygwin"
C:\cygwin\bin\bash -e -l -c ./autogen.sh
C:\cygwin\bin\bash -e -l -c "cd build-Win32-cygwin"
C:\cygwin\bin\bash -e -l -c "build-Win32-cygwin/../configure"
C:\cygwin\bin\bash -e -l -c "make -j4"
C:\cygwin\bin\bash -e -l -c "make install"