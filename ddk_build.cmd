@echo off

@rem ==================== setup ======================

@rem Compatibility with older DDK environments:
if defined DDKBUILDENV set _BuildType=%DDKBUILDENV%

if Test%BUILD_ALT_DIR%==Test goto usage

set cpudir=i386
set destType=Win32
if %_BUILDARCH%==x86 goto isI386
set cpudir=amd64
set destType=x64
:isI386

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
if exist %dstPath%\sys goto md6
md %dstPath%\sys
:md6
if exist %dstPath%\examples goto md7
md %dstPath%\examples
:md7

@rem ==================== libusb ======================
set version=1.0

cd libusb\os
copy /y ..\..\msvc\libusb-%version%.rc .
copy /y ..\libusb-%version%.def .
copy /y makefile.ddk makefile
@echo on
build -cZ
@echo off
if errorlevel 1 goto builderror
del libusb-%version%.rc
cd ..\..

set srcPath=libusb\os\obj%BUILD_ALT_DIR%\%cpudir%
@echo on

copy %srcPath%\libusb-%version%.dll %dstPath%\dll
copy %srcPath%\libusb-%version%.pdb %dstPath%\dll
copy %srcPath%\libusb-%version%.lib %dstPath%\lib

@echo off

@rem ==================== libusb0.sys ======================
cd libusb\os\driver
copy /y makefile.ddk makefile
@echo on
build -cZ
@echo off
if errorlevel 1 goto buildlsusberror
cd ..\..\..

set srcPath=libusb\os\driver\obj%BUILD_ALT_DIR%\%cpudir%
@echo on

copy %srcPath%\libusb0.sys %dstPath%\sys

@echo off

@rem ==================== example lsusb ======================
if exist examples\lsusb_ddkbuild goto md8
md examples\lsusb_ddkbuild
:md8

cd examples\lsusb_ddkbuild
copy ..\lsusb_sources sources
copy ..\makefile.ddk makefile
@echo on
build -cZ
@echo off
if errorlevel 1 goto buildlsusberror
cd ..\..

set srcPath=examples\lsusb_ddkbuild\obj%BUILD_ALT_DIR%\%cpudir%
@echo on

copy %srcPath%\lsusb.exe %dstPath%\examples
copy %srcPath%\lsusb.pdb %dstPath%\examples

@echo off

@rem ==================== example xusb ======================
if exist examples\xusb_ddkbuild goto md9
md examples\xusb_ddkbuild
:md9

cd examples\xusb_ddkbuild
copy ..\xusb_sources sources
copy ..\makefile.ddk makefile
@echo on
build -cZ
@echo off
if errorlevel 1 goto buildxusberror
cd ..\..

set srcPath=examples\xusb_ddkbuild\obj%BUILD_ALT_DIR%\%cpudir%
@echo on

copy %srcPath%\xusb.exe %dstPath%\examples
copy %srcPath%\xusb.pdb %dstPath%\examples

@echo off

@rem ==================== cleanup ======================
goto done

:builderror
del libusb-%version%.rc
cd ..\..
echo Build failed
goto done

:buildlsusberror
cd ..\..
echo lsusb build failed
goto done

:buildxusberror
cd ..\..
echo xusb build failed
goto done

:usage
echo ddk_build must be run in a WDK build environment
goto done

:done
