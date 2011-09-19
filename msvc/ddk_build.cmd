@rem default builds static library.
@rem you can pass the following arguments (case insensitive):
@rem - "DLL" to build a DLL instead of a static library
@rem - "/MT" to build a static library compatible with MSVC's /MT option (LIBCMT vs MSVCRT)
@echo off

if Test%BUILD_ALT_DIR%==Test goto usage

rem process commandline parameters
set TARGET=LIBRARY
set STATIC_LIBC=
set version=1.0

if "%1" == "" goto no_more_args
rem /I for case insensitive
if /I Test%1==TestDLL set TARGET=DYNLINK
if /I Test%1==Test/MT set STATIC_LIBC=1
:no_more_args

cd ..\libusb\os
echo TARGETTYPE=%TARGET% > target
copy target+..\..\msvc\libusb_sources sources >NUL 2>&1
del target
@echo on
build -cwgZ
@echo off
if errorlevel 1 goto builderror
cd ..\..

set cpudir=i386
set destType=Win32
if %_BUILDARCH%==x86 goto isI386
set cpudir=amd64
set destType=x64
:isI386

set srcPath=libusb\os\obj%BUILD_ALT_DIR%\%cpudir%

set dstPath=%destType%\Debug
if %DDKBUILDENV%==chk goto isDebug
set dstPath=%destType%\Release
:isDebug

if exist %destType% goto md2
mkdir %destType%
:md2
if exist %dstPath% goto md3
mkdir %dstPath%
:md3
if exist %dstPath%\dll goto md4
mkdir %dstPath%\dll
:md4
if exist %dstPath%\lib goto md5
md %dstPath%\lib
:md5
if exist %dstPath%\examples goto md6
md %dstPath%\examples
:md6
@echo on

@if /I NOT Test%1==TestDLL goto copylib
copy %srcPath%\libusb-%version%.dll %dstPath%\dll
copy %srcPath%\libusb-%version%.pdb %dstPath%\dll
:copylib
copy %srcPath%\libusb-%version%.lib %dstPath%\lib

@echo off

if exist examples\lsusb_ddkbuild goto md7
md examples\lsusb_ddkbuild
:md7

cd examples\lsusb_ddkbuild
copy ..\..\msvc\lsusb_sources sources >NUL 2>&1
@echo on
build -cwgZ
@echo off
if errorlevel 1 goto buildlsusberror
cd ..\..

set srcPath=examples\lsusb_ddkbuild\obj%BUILD_ALT_DIR%\%cpudir%
@echo on

copy %srcPath%\lsusb.exe %dstPath%\examples
copy %srcPath%\lsusb.pdb %dstPath%\examples

cd msvc
goto done


:builderror
cd ..\..\msvc
echo Build failed
goto done

:buildlsusberror
cd ..\..\msvc
echo lsusb build failed
goto done

:usage
echo ddk_build must be run in a WDK build environment
pause
goto done

:done
