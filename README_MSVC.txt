To compile libusb 1.0 using MSVC 9:

- download the pthread.h and sched.h headers from 
  ftp://sourceware.org/pub/pthreads-win32/prebuilt-dll-2-8-0-release/include/
  into the msvc directory
- (Win32) download pthreadVC2.lib from:
  ftp://sourceware.org/pub/pthreads-win32/prebuilt-dll-2-8-0-release/lib/ 
  into the msvc directory
- (Win32) download pthreadVC2.dll from the same link either into your executable
  destination or copy it into C:\Window\System32 or C:\Window\SysWOW64
- (x64) follow the "Direct access to the CVS code repository" details on
  http://sourceware.org/pthreads-win32/ and create both a pthreadVC2_x64.lib
  and pthreadVC2_x64.dll from the latest pthread-win32 source. Then copy 
  pthreadVC2_x64.lib into the msvc directory and the DLL where relevant.
- edit config_msvc.h according to your needs (you might want to comment out
  ENABLE_DEBUG_LOGGING)
- If you don't have it already, download and install the latest Windows DDK 
  (http://www.microsoft.com/downloads/details.aspx?FamilyID=2105564e-1a9a-4bf4-8d74-ec5b52da3d00)
- In Visual Studio, go to Tools -> Options -> Projects and Solutions ->
  VC++ directories and change the "Include files" and "Library files" 
  references to point to the correct DDK paths.
