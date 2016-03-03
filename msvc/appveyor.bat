echo on
SetLocal EnableDelayedExpansion

if [%Configuration%] NEQ [Debug] goto releasex64
if [%Configuration%] NEQ [Release] goto debugx64

:debugx64
call "C:\Program Files\Microsoft SDKs\Windows\v7.1\Bin\SetEnv.cmd" /Debug /x64
msbuild libusb_2010.sln /p:Configuration=Debug,Platform=x64 /logger:"C:\Program Files\AppVeyor\BuildAgent\Appveyor.MSBuildLogger.dll"

:releasex64
call "C:\Program Files\Microsoft SDKs\Windows\v7.1\Bin\SetEnv.cmd" /Release /x64
msbuild libusb_2010.sln /p:Configuration=Release,Platform=x64 /logger:"C:\Program Files\AppVeyor\BuildAgent\Appveyor.MSBuildLogger.dll"