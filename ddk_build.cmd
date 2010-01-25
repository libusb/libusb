@echo off
if Test%BUILD_ALT_DIR%==Test goto usage

set version=1.0

cd libusb\os
copy /y ..\..\msvc\libusb-%version%.rc .
@echo on
build -cZ
@echo off
if errorlevel 1 goto builderror
del libusb-%version%.rc
cd ..\..

set cpudir=i386
set destType=Win32
if %_BUILDARCH%==x86 goto isI386
set cpudir=amd64
set destType=x64
:isI386

set srcPath=libusb\os\obj%BUILD_ALT_DIR%\%cpudir%

set dstPath=%destType%\Debug
if %_BuildType%==chk goto isDebug
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
@echo on

copy %srcPath%\libusb-%version%.dll %dstPath%\dll
copy %srcPath%\libusb-%version%.pdb %dstPath%\dll
copy %srcPath%\libusb-%version%.lib %dstPath%\lib

@echo off
goto done


:builderror
del libusb-%version%.rc
cd ..\..
echo Build failed
goto done

:usage
echo ddk_build must be run in a WDK build environment
goto done

:done