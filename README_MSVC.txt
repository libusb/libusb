To compile libusb 1.0 using MSVC 8 or later:

- download the pthread.h and sched.h headers from 
  ftp://sourceware.org/pub/pthreads-win32/prebuilt-dll-2-8-0-release/include/
  into the msvc directory
- download pthreadVC2.lib from:
  ftp://sourceware.org/pub/pthreads-win32/prebuilt-dll-2-8-0-release/lib/ 
  into the msvc directory
- download pthreadVC2.dll from the same link into your executable destination
- edit config_msvc.h according to your needs (you might want to comment out
  ENABLE_DEBUG_LOGGING) 
- edit the Linker's "Additional Library Directory" properties to point to your 
  Windows DDK (you must have the Windows DDK installed). For instance, to build
  against the Windows 7 x86 libraries, you could use:
  E:\WinDDK\7600.16385.0\lib\win7\i386
